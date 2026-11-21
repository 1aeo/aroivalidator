#!/usr/bin/env python3
"""Tests for atomic result persistence and quiet batch mode."""
import contextlib
import errno
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app
import aroi_cli
from aroi_validator import _atomic_write_text, save_results


class TestAtomicSaveResults(unittest.TestCase):
    """Verify save_results writes atomically and leaves no partial files."""

    def test_save_results_permissions_format_and_no_leftover_tmp(self):
        """save_results writes indented JSON honoring umask with no .tmp files."""
        results = [
            {'nickname': 'Relay1', 'valid': True, 'proof_type': 'dns-rsa', 'ciissversion': '2'},
        ]
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            old_umask = os.umask(0o022)
            try:
                with patch('aroi_validator.get_code_commit', return_value=None):
                    out_path = save_results(results, 'aroi_validation_20261121_090000.json')

                self.assertTrue(out_path.exists())
                latest_path = out_path.parent / 'latest.json'
                self.assertTrue(latest_path.exists())

                # Verify indent=2 preserved and valid JSON
                raw = out_path.read_text(encoding='utf-8')
                self.assertIn('\n  "metadata": {', raw)
                self.assertEqual(json.loads(raw)['metadata']['total_relays'], 1)
                self.assertEqual(raw, latest_path.read_text(encoding='utf-8'))

                # Default 0o644 mode when umask is 0o022
                self.assertEqual(stat.S_IMODE(out_path.stat().st_mode), 0o644)
                self.assertEqual(stat.S_IMODE(latest_path.stat().st_mode), 0o644)

                # No lingering temp files
                entries = sorted(p.name for p in out_path.parent.iterdir())
                self.assertEqual(entries, ['aroi_validation_20261121_090000.json', 'latest.json'])
            finally:
                os.umask(old_umask)
                os.chdir(cwd)

    def test_atomic_write_preserves_existing_mode_and_honors_restrictive_umask(self):
        """Existing restrictive mode (0600) is preserved; temp inode is never broader."""
        with tempfile.TemporaryDirectory() as tmp:
            dest_existing = Path(tmp) / 'latest.json'
            dest_existing.write_text('{"old": true}', encoding='utf-8')
            os.chmod(dest_existing, 0o600)

            old_umask = os.umask(0o022)
            seen_pre_fchmod_modes = []
            real_fchmod = os.fchmod

            def spy_fchmod(fd, mode):
                seen_pre_fchmod_modes.append(stat.S_IMODE(os.fstat(fd).st_mode))
                return real_fchmod(fd, mode)

            try:
                with patch('aroi_validator.os.fchmod', side_effect=spy_fchmod):
                    _atomic_write_text(dest_existing, '{"new": true}')
                self.assertEqual(seen_pre_fchmod_modes, [0o600])
                self.assertEqual(stat.S_IMODE(dest_existing.stat().st_mode), 0o600)

                os.umask(0o077)
                dest_new = Path(tmp) / 'restricted.json'
                _atomic_write_text(dest_new, '{"restricted": true}')
                self.assertEqual(stat.S_IMODE(dest_new.stat().st_mode), 0o600)
            finally:
                os.umask(old_umask)

    def test_atomic_write_without_os_fchmod_updates_existing_file(self):
        """When os.fchmod is unavailable (e.g. Windows), replacing still succeeds."""
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'latest.json'
            dest.write_text('{"old": true}', encoding='utf-8')

            orig_fchmod = getattr(os, 'fchmod', None)
            if orig_fchmod is not None:
                delattr(os, 'fchmod')
            try:
                _atomic_write_text(dest, '{"new": true}')
            finally:
                if orig_fchmod is not None:
                    setattr(os, 'fchmod', orig_fchmod)

            self.assertEqual(dest.read_text(encoding='utf-8'), '{"new": true}')
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ['latest.json'])

    def test_atomic_write_fsyncs_parent_directory_and_closes_fd(self):
        """Parent directory is synced strictly after replace and its fd is closed."""
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'latest.json'
            events = []
            dir_fds = []
            real_open = os.open
            real_fsync = os.fsync
            real_replace = os.replace
            real_close = os.close

            def spy_open(path, flags, *args, **kwargs):
                fd = real_open(path, flags, *args, **kwargs)
                if Path(path) == dest.parent:
                    dir_fds.append(fd)
                    events.append(('dir_open', fd))
                return fd

            def spy_replace(src, dst):
                events.append(('replace', Path(dst)))
                return real_replace(src, dst)

            def spy_fsync(fd):
                events.append(('dir_fsync' if fd in dir_fds else 'file_fsync', fd))
                return real_fsync(fd)

            def spy_close(fd):
                if fd in dir_fds:
                    events.append(('dir_close', fd))
                return real_close(fd)

            with patch('aroi_validator.os.open', side_effect=spy_open), \
                 patch('aroi_validator.os.replace', side_effect=spy_replace), \
                 patch('aroi_validator.os.fsync', side_effect=spy_fsync), \
                 patch('aroi_validator.os.close', side_effect=spy_close):
                _atomic_write_text(dest, '{"ok": true}')

            self.assertEqual(len(dir_fds), 1)
            dir_fd = dir_fds[0]
            op_names = [e[0] for e in events]
            self.assertEqual(
                op_names,
                ['file_fsync', 'replace', 'dir_open', 'dir_fsync', 'dir_close'],
            )
            self.assertIn(('dir_fsync', dir_fd), events)
            self.assertIn(('dir_close', dir_fd), events)

            # Unsupported directory fsync errnos (EINVAL, ENOSYS) are ignored and fd closes.
            for err_no in (errno.EINVAL, errno.ENOSYS):
                events.clear()
                dir_fds.clear()

                def unsupported_dir_fsync(fd, _err=err_no):
                    if fd in dir_fds:
                        events.append(('dir_fsync', fd))
                        raise OSError(_err, 'Unsupported')
                    events.append(('file_fsync', fd))
                    return real_fsync(fd)

                with patch('aroi_validator.os.open', side_effect=spy_open), \
                     patch('aroi_validator.os.replace', side_effect=spy_replace), \
                     patch('aroi_validator.os.fsync', side_effect=unsupported_dir_fsync), \
                     patch('aroi_validator.os.close', side_effect=spy_close):
                    _atomic_write_text(dest, '{"ok": 2}')

                self.assertEqual(dest.read_text(encoding='utf-8'), '{"ok": 2}')
                self.assertEqual([e[0] for e in events], ['file_fsync', 'replace', 'dir_open', 'dir_fsync', 'dir_close'])

    def test_save_results_propagates_operational_error_on_dir_open(self):
        """Operational os.open errors (e.g. ENOMEM) on parent dir must propagate."""
        results = [{'nickname': 'Relay1', 'valid': True, 'proof_type': 'dns-rsa', 'ciissversion': '2'}]
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                real_open = os.open

                def enomem_on_dir_open(path, flags, *args, **kwargs):
                    if Path(path) == Path(tmp, 'validation_results').resolve():
                        raise OSError(errno.ENOMEM, 'Out of memory')
                    return real_open(path, flags, *args, **kwargs)

                with patch('aroi_validator.get_code_commit', return_value=None), \
                     patch('aroi_validator.os.open', side_effect=enomem_on_dir_open):
                    with self.assertRaises(OSError) as cm:
                        save_results(results, 'aroi_validation_20261121_090000.json')
                self.assertEqual(cm.exception.errno, errno.ENOMEM)
            finally:
                os.chdir(cwd)

    def test_atomic_write_preserves_existing_file_on_write_error(self):
        """A simulated ENOSPC during write cleans up tmp file and keeps target intact."""
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'latest.json'
            dest.write_text('{"previous": true}', encoding='utf-8')

            real_fdopen = os.fdopen

            def failing_fdopen(fd, *args, **kwargs):
                real_f = real_fdopen(fd, *args, **kwargs)
                real_f.close()
                fake_cm = MagicMock()
                fake_cm.__enter__.return_value = fake_cm
                fake_cm.__exit__.return_value = False
                fake_cm.write.side_effect = OSError(errno.ENOSPC, 'No space left on device')
                return fake_cm

            with patch('aroi_validator.os.fdopen', side_effect=failing_fdopen):
                with self.assertRaises(OSError):
                    _atomic_write_text(dest, '{"new": true}')

            self.assertEqual(dest.read_text(encoding='utf-8'), '{"previous": true}')
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ['latest.json'])

    def test_atomic_write_cleans_tmp_on_replace_error(self):
        """If os.replace fails, the temporary file is removed and target preserved."""
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'latest.json'
            dest.write_text('{"previous": true}', encoding='utf-8')

            with patch('aroi_validator.os.replace', side_effect=OSError(errno.EIO, 'I/O error')):
                with self.assertRaises(OSError):
                    _atomic_write_text(dest, '{"new": true}')

            self.assertEqual(dest.read_text(encoding='utf-8'), '{"previous": true}')
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ['latest.json'])

    def test_save_results_named_latest_writes_once(self):
        """Saving explicitly as latest.json does not fail or perform a duplicate write."""
        results = [{'nickname': 'Relay1', 'valid': True, 'proof_type': 'dns-rsa', 'ciissversion': '2'}]
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                with patch('aroi_validator.get_code_commit', return_value=None), \
                     patch('aroi_validator._atomic_write_text', wraps=_atomic_write_text) as mock_write:
                    path = save_results(results, 'latest.json')
                self.assertEqual(path.name, 'latest.json')
                self.assertEqual(mock_write.call_count, 1)
            finally:
                os.chdir(cwd)

    def test_save_results_supports_long_filenames_near_name_max(self):
        """Filenames near the 255-byte filesystem limit succeed without ENAMETOOLONG."""
        long_name = ('a' * 245) + '.json'  # 250 bytes, accepted by _sanitize_filename
        results = [{'nickname': 'Relay1', 'valid': True, 'proof_type': 'dns-rsa', 'ciissversion': '2'}]
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                with patch('aroi_validator.get_code_commit', return_value=None):
                    out_path = save_results(results, long_name)
                self.assertTrue(out_path.exists())
                self.assertEqual(out_path.name, long_name)
                self.assertEqual(json.loads(out_path.read_text(encoding='utf-8'))['metadata']['total_relays'], 1)
            finally:
                os.chdir(cwd)


class TestQuietBatchMode(unittest.TestCase):
    """Verify --quiet and BATCH_QUIET behavior in aroi_cli and app."""

    def test_cli_forwards_quiet_for_batch(self):
        """aroi_cli batch --quiet forwards --quiet to app.py."""
        proc = MagicMock(returncode=0)
        with patch.object(sys, 'argv', ['aroi_cli.py', 'batch', '--quiet']), \
             patch('aroi_cli.subprocess.run', return_value=proc) as mock_run:
            with self.assertRaises(SystemExit) as cm:
                aroi_cli.main()
        self.assertEqual(cm.exception.code, 0)
        cmd = mock_run.call_args.args[0]
        self.assertIn('--quiet', cmd)
        self.assertIn('batch', cmd)

    def test_cli_rejects_quiet_for_non_batch_modes(self):
        """aroi_cli rejects --quiet on modes other than batch."""
        for mode in ('interactive', 'viewer', 'insights'):
            with patch.object(sys, 'argv', ['aroi_cli.py', mode, '--quiet']), \
                 contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    aroi_cli.main()
                self.assertEqual(cm.exception.code, 2)

    def test_is_batch_quiet_precedence(self):
        """Explicit flag beats BATCH_QUIET env var; env var accepts truthy values."""
        with patch.dict(os.environ, {'BATCH_QUIET': 'false'}):
            self.assertTrue(app._is_batch_quiet(True))
            self.assertFalse(app._is_batch_quiet(None))

        with patch.dict(os.environ, {'BATCH_QUIET': 'true'}):
            self.assertFalse(app._is_batch_quiet(False))
            self.assertTrue(app._is_batch_quiet(None))

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('BATCH_QUIET', None)
            self.assertFalse(app._is_batch_quiet(None))

    def test_batch_mode_suppresses_progress_callback_when_quiet(self):
        """batch_mode passes progress_callback=None when quiet, keeps summary JSON."""
        sample_results = [
            {'nickname': 'TestRelay', 'valid': True, 'proof_type': 'dns-rsa', 'ciissversion': '2'},
        ]

        def fake_run_validation(**kwargs):
            cb = kwargs.get('progress_callback')
            if cb is not None:
                cb(1, 1, sample_results[0])
            return sample_results

        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                stdout = io.StringIO()
                with patch.dict(os.environ, {'BATCH_QUIET': 'true'}), \
                     patch('aroi_validator.run_validation', side_effect=fake_run_validation) as mock_rv, \
                     patch('aroi_validator.get_code_commit', return_value=None), \
                     contextlib.redirect_stdout(stdout):
                    app.batch_mode()

                self.assertIsNone(mock_rv.call_args.kwargs['progress_callback'])
                out_text = stdout.getvalue()
                self.assertNotIn('[1/1]', out_text)
                self.assertIn('VALIDATION COMPLETE', out_text)
                self.assertIn('"total_relays": 1', out_text)

                # Non-quiet mode still emits per-relay progress lines
                stdout_verbose = io.StringIO()
                with patch.dict(os.environ, {'BATCH_QUIET': 'false'}), \
                     patch('aroi_validator.run_validation', side_effect=fake_run_validation) as mock_rv2, \
                     patch('aroi_validator.get_code_commit', return_value=None), \
                     contextlib.redirect_stdout(stdout_verbose):
                    app.batch_mode()

                self.assertIsNotNone(mock_rv2.call_args.kwargs['progress_callback'])
                self.assertIn('[1/1] ✓ TestRelay', stdout_verbose.getvalue())
            finally:
                os.chdir(cwd)


if __name__ == '__main__':
    unittest.main()
