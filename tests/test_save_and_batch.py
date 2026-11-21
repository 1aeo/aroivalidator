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
        """save_results writes indented JSON with 0644 mode and no .tmp files."""
        results = [
            {'nickname': 'Relay1', 'valid': True, 'proof_type': 'dns-rsa', 'ciissversion': '2'},
        ]
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
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

                # Verify world-readable 0644 mode (not mkstemp default 0600)
                self.assertEqual(stat.S_IMODE(out_path.stat().st_mode), 0o644)
                self.assertEqual(stat.S_IMODE(latest_path.stat().st_mode), 0o644)

                # No lingering temp files
                entries = sorted(p.name for p in out_path.parent.iterdir())
                self.assertEqual(entries, ['aroi_validation_20261121_090000.json', 'latest.json'])
            finally:
                os.chdir(cwd)

    def test_atomic_write_preserves_existing_file_on_write_error(self):
        """A simulated ENOSPC during write cleans up tmp file and keeps target intact."""
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'latest.json'
            dest.write_text('{"previous": true}', encoding='utf-8')

            fake_tmp = MagicMock()
            fake_tmp.name = str(Path(tmp) / '.latest.json.fail.tmp')
            Path(fake_tmp.name).write_text('', encoding='utf-8')
            fake_tmp.write.side_effect = OSError(errno.ENOSPC, 'No space left on device')

            cm = MagicMock()
            cm.__enter__.return_value = fake_tmp
            cm.__exit__.return_value = False

            with patch('aroi_validator.tempfile.NamedTemporaryFile', return_value=cm):
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
