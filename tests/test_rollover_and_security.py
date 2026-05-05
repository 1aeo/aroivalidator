#!/usr/bin/env python3
"""ciissversion:3 mocked-input tests (no network required).

Discoverable by pytest (`pytest tests/test_rollover_and_security.py`) and
also runnable as a standalone script (`python3 tests/test_rollover_and_security.py`).

Covers:
  - Rollover simulation (shared DNS cache, per-relay match)
  - Secret-key-leak detection (DNS and URI paths)
  - Case-mismatch diagnostic
  - SSRF protections (IP literals, private/loopback ranges, redirects)
"""
import socket
import sys
import os.path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aroi_validator import (
    ParallelAROIValidator,
    is_safe_public_host,
    _ip_is_safe,
    _clear_host_safety_cache,
    _safe_create_connection,
    SSRFBlockedError,
)


def test_rollover():
    """Two relays, same url, disjoint family_ids, one shared TXT response."""
    v = ParallelAROIValidator(max_workers=1)

    # The published TXT contains family_id "A1"; relay_a has it, relay_b
    # has only "B1" so will fail.
    family_id_a = "A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A"  # 45-char filler
    family_id_b = "B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B1B"

    relay_a = {
        'nickname': 'RelayA',
        'fingerprint': 'A' * 40,
        'family_ids': [family_id_a],
        'contact': 'url:example.invalid proof:dns-familyid-ed25519 ciissversion:3',
    }
    relay_b = {
        'nickname': 'RelayB',
        'fingerprint': 'B' * 40,
        'family_ids': [family_id_b],
        'contact': 'url:example.invalid proof:dns-familyid-ed25519 ciissversion:3',
    }

    # Mock the DNS resolver: every call returns one rdata whose .strings
    # contains the family_id_a value.
    mock_rdata = MagicMock()
    mock_rdata.strings = (family_id_a.encode(),)
    fake_answers = [mock_rdata]

    call_count = {'n': 0}

    def fake_resolve(qname, qtype):
        call_count['n'] += 1
        return fake_answers

    with patch('aroi_validator.dns.resolver.resolve', side_effect=fake_resolve):
        out_a = v.validate_relay(relay_a)
        out_b = v.validate_relay(relay_b)

    assert call_count['n'] == 1, (
        f"dns.resolver.resolve was called {call_count['n']} times, expected 1 "
        "(rollover/shared-cache test failed)"
    )
    assert out_a['valid'] is True, f"RelayA should validate: {out_a}"
    assert out_b['valid'] is False, f"RelayB should NOT validate: {out_b}"
    assert out_b['error_category'] == 'dns_content_mismatch', out_b
    print("  ✓ rollover/shared-cache: 1 DNS call serves both relays; per-relay match correct")


def test_secret_key_leak_dns():
    """Synthetic TXT with leaked .secret_family_key content → security alert."""
    v = ParallelAROIValidator(max_workers=1)
    relay = {
        'nickname': 'LeakyRelay',
        'fingerprint': 'C' * 40,
        'family_ids': ['legitimate_family_id_1234567890abcdef____'],
        'contact': 'url:leaky.invalid proof:dns-familyid-ed25519 ciissversion:3',
    }
    leaked = '== ed25519v1-secret-type0 ==' + ('A' * 700)
    mock_rdata = MagicMock()
    mock_rdata.strings = (leaked.encode(),)

    with patch('aroi_validator.dns.resolver.resolve', return_value=[mock_rdata]):
        out = v.validate_relay(relay)

    assert out['valid'] is False, f"leaked secret should NOT validate: {out}"
    assert out['error_category'] == 'secret_key_leaked', out
    assert 'SECURITY' in out['error'], out
    assert 'rotate' in out.get('hint', '').lower(), out
    print("  ✓ secret-key leak: detected, valid=False, category=secret_key_leaked, SECURITY hint")


def test_secret_key_leak_uri():
    """Synthetic URI response with leaked .secret_family_key content."""
    v = ParallelAROIValidator(max_workers=1)
    relay = {
        'nickname': 'LeakyURIRelay',
        'fingerprint': 'D' * 40,
        'family_ids': ['legitimate_family_id_1234567890abcdef____'],
        'contact': 'url:leakyuri.invalid proof:uri-familyid-ed25519 ciissversion:3',
    }

    leaked_response = MagicMock()
    leaked_response.text = '== ed25519v1-secret-type0 ==\n' + ('A' * 700)

    # _fetch_with_retry returns (response, error_msg, error_category, attempts)
    with patch.object(
        v, '_fetch_with_retry',
        return_value=(leaked_response, "", None, 1),
    ):
        out = v.validate_relay(relay)

    assert out['valid'] is False, out
    assert out['error_category'] == 'secret_key_leaked', out
    assert 'SECURITY' in out['error'], out
    print("  ✓ secret-key leak (URI): detected on response.text, security category attached")


def test_case_mismatch_diagnostic():
    """v3 content-mismatch where content matches family_ids only by case."""
    v = ParallelAROIValidator(max_workers=1)
    relay = {
        'nickname': 'CaseRelay',
        'fingerprint': 'E' * 40,
        'family_ids': ['ABCdef1234567890abcdef1234567890abcdef1234X'],  # mixed case
        'contact': 'url:case.invalid proof:dns-familyid-ed25519 ciissversion:3',
    }
    # Published TXT has same value, ALL LOWERCASE
    lowercased = relay['family_ids'][0].lower()
    mock_rdata = MagicMock()
    mock_rdata.strings = (lowercased.encode(),)

    with patch('aroi_validator.dns.resolver.resolve', return_value=[mock_rdata]):
        out = v.validate_relay(relay)

    assert out['valid'] is False, out
    assert 'case mismatch detected' in out['error'], out
    assert out['error_category'] == 'dns_content_mismatch', out
    print("  ✓ case-mismatch diagnostic: case-only mismatch tagged in error message")


def test_ip_safety_classification():
    """_ip_is_safe must reject every non-globally-routable address.

    Uses ip.is_global semantics (deny-by-default), so it covers gaps that
    enumerated is_private/is_reserved would miss — notably CGN/shared
    address space (100.64.0.0/10) and benchmarking ranges.
    """
    UNSAFE = [
        # Loopback
        '127.0.0.1', '127.255.255.254', '::1',
        # Unspecified
        '0.0.0.0', '::',
        # Link-local
        '169.254.169.254',  # cloud metadata (AWS/GCP/Azure)
        'fe80::1',
        # RFC1918 / RFC4193
        '10.0.0.1', '10.255.255.255',
        '172.16.0.1', '172.31.255.254',
        '192.168.1.1',
        'fc00::1', 'fd00::1',
        # Multicast / reserved
        '224.0.0.1',
        '255.255.255.255',
        'ff02::1',
        # Carrier-Grade NAT / shared address space (RFC6598)
        # — NOT covered by is_private; only is_global catches this.
        '100.64.0.1', '100.127.255.254',
        # IETF protocol assignments / TEST-NET / benchmarking
        '192.0.0.1',     # IETF Protocol Assignments
        '192.0.2.1',     # TEST-NET-1 (RFC5737)
        '198.51.100.1',  # TEST-NET-2
        '203.0.113.1',   # TEST-NET-3
        '198.18.0.1',    # benchmarking (RFC2544)
        '198.19.255.254',
    ]
    for ip in UNSAFE:
        assert not _ip_is_safe(ip), f"{ip!r} should be classified unsafe (non-global)"
    SAFE = [
        '8.8.8.8', '1.1.1.1', '93.184.216.34',
        '2606:2800:220:1::6',  # example.com IPv6
    ]
    for ip in SAFE:
        assert _ip_is_safe(ip), f"{ip!r} should be classified safe (globally routable)"
    print("  ✓ _ip_is_safe rejects all non-global ranges incl. CGN, TEST-NET, benchmarking")


def test_is_safe_public_host_rejects_ip_literals():
    """Hostname check must reject IP-literal hostnames outright (no DNS)."""
    _clear_host_safety_cache()
    for ip in ('127.0.0.1', '169.254.169.254', '10.0.0.1', '::1', 'fe80::1'):
        safe, reason = is_safe_public_host(ip)
        assert not safe, f"{ip!r} should be rejected; got {(safe, reason)}"
        assert 'IP literal' in reason, reason
    print("  ✓ is_safe_public_host rejects IP-literal hostnames outright")


def test_is_safe_public_host_rejects_private_resolution():
    """Hostname resolving to a private/loopback address must be rejected.
    Hermetic: socket.getaddrinfo is mocked so the test does no real DNS."""
    _clear_host_safety_cache()
    # Synthetic getaddrinfo output: IPv4 loopback + IPv6 loopback.
    # Format matches socket.getaddrinfo: (family, type, proto, canonname, sockaddr).
    fake_infos = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 0, '', ('::1', 0, 0, 0)),
    ]
    with patch('aroi_validator.socket.getaddrinfo', return_value=fake_infos):
        safe, reason = is_safe_public_host('mocked-loopback.invalid')
    assert not safe, f"mocked loopback resolution should be rejected: ({safe}, {reason})"
    assert 'non-public' in reason, reason
    print("  ✓ is_safe_public_host rejects hostnames resolving to private/loopback (mocked DNS)")


def test_uri_validation_blocked_for_ip_literal():
    """End-to-end: a relay with url:127.0.0.1 must be SSRF-blocked before any HTTP."""
    _clear_host_safety_cache()
    v = ParallelAROIValidator(max_workers=1)
    relay = {
        'nickname': 'AttackerRelay',
        'fingerprint': 'F' * 40,
        'family_ids': ['fid'],
        'contact': 'url:127.0.0.1 proof:uri-familyid-ed25519 ciissversion:3',
    }
    # If the SSRF gate works, _fetch_with_retry must NEVER be invoked.
    with patch.object(v, '_fetch_with_retry') as mock_fetch:
        out = v.validate_relay(relay)
    assert mock_fetch.call_count == 0, (
        f"SSRF gate failed — _fetch_with_retry was invoked {mock_fetch.call_count} time(s)"
    )
    assert out['valid'] is False
    assert out['error_category'] == 'unsafe_target', out
    assert 'SSRF-blocked' in out['error'], out
    print("  ✓ SSRF gate: url:127.0.0.1 blocks fetch entirely; error_category=unsafe_target")


def test_uri_validation_blocked_for_private_resolution():
    """End-to-end: a relay with url:localhost (resolves private) must be blocked."""
    _clear_host_safety_cache()
    v = ParallelAROIValidator(max_workers=1)
    relay = {
        'nickname': 'AttackerRelay2',
        'fingerprint': 'G' * 40,
        'family_ids': ['fid'],
        'contact': 'url:localhost proof:uri-familyid-ed25519 ciissversion:3',
    }
    # localhost might fail _extract_domain (no '.'); pre-validate that.
    out = v.validate_relay(relay)
    # Either SSRF-blocked OR rejected as invalid_url (no '.' in 'localhost').
    # Both outcomes prevent SSRF; assert one of them.
    assert out['valid'] is False, out
    assert out['error_category'] in ('unsafe_target', 'invalid_url'), out
    print(f"  ✓ url:localhost rejected with error_category={out['error_category']}")


def test_dns_rebinding_blocked_at_connect():
    """DNS-rebinding attack: an attacker's DNS server returns a public IP
    for the pre-flight is_safe_public_host() check, then a private IP
    when urllib3 resolves the same hostname for the actual fetch.

    The pre-flight is informational; the SECURITY guarantee comes from
    _safe_create_connection (the function urllib3 uses to open every
    socket on the relay-fetch session). This test:

      1. Primes the host-safety cache as if pre-flight passed (host is
         marked safe with a public IP).
      2. Mocks getaddrinfo to return a private IP — simulating the
         attacker's DNS flipping its answer between the safety lookup
         and the actual connect.
      3. Calls _safe_create_connection directly. It must raise
         SSRFBlockedError BEFORE opening a TCP socket. We patch
         socket.socket as a tripwire to confirm no socket is ever
         constructed.
    """
    _clear_host_safety_cache()

    # Step 1: simulate successful pre-flight by force-priming the cache.
    from aroi_validator import _HOST_SAFETY_CACHE, _HOST_SAFETY_LOCK
    with _HOST_SAFETY_LOCK:
        _HOST_SAFETY_CACHE['attacker.invalid'] = (True, '93.184.216.34')

    # Step 2 + 3: connect-time getaddrinfo returns a private IP (rebinding).
    # No socket should ever be created — the gate must reject before
    # constructing the AF_INET socket.
    private_info = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 0)),
    ]
    socket_constructed = {'count': 0}

    real_socket = socket.socket
    def tripwire_socket(*args, **kwargs):
        socket_constructed['count'] += 1
        return real_socket(*args, **kwargs)

    raised = None
    with patch('aroi_validator.socket.getaddrinfo', return_value=private_info), \
         patch('aroi_validator.socket.socket', side_effect=tripwire_socket):
        try:
            sock = _safe_create_connection(('attacker.invalid', 443), timeout=2)
            sock.close()  # safety; should not be reached
        except SSRFBlockedError as e:
            raised = e
        except OSError as e:
            # If a different OSError subclass leaks out, only acceptable if
            # the message clearly tags this as an SSRF block.
            if 'SSRF' not in str(e) and 'non-public' not in str(e):
                raise AssertionError(
                    f"DNS rebinding NOT blocked: got non-SSRF OSError {e!r}"
                )
            raised = e

    assert raised is not None, (
        "DNS rebinding NOT blocked: _safe_create_connection returned a "
        "socket to the rebound private IP"
    )
    assert socket_constructed['count'] == 0, (
        f"socket() was called {socket_constructed['count']} time(s); "
        f"connect-time gate must reject BEFORE constructing a socket"
    )
    msg = str(raised)
    assert 'SSRF' in msg or 'non-public' in msg, (
        f"SSRFBlockedError message should mention the rejection: {msg!r}"
    )
    print("  ✓ DNS rebinding blocked at connect: SSRFBlockedError raised, no socket opened")


def test_redirect_both_primary_and_www_fail():
    """When BOTH primary and www-fallback return 3xx redirects, the relay
    fails with category=redirect_disallowed. allow_redirects=False asserted."""
    _clear_host_safety_cache()
    v = ParallelAROIValidator(max_workers=1)
    relay = {
        'nickname': 'RedirectRelay',
        'fingerprint': 'H' * 40,
        'family_ids': ['fid'],
        'contact': 'url:public.invalid proof:uri-familyid-ed25519 ciissversion:3',
    }
    fake_3xx = MagicMock()
    fake_3xx.status_code = 301
    fake_3xx.headers = {'Location': 'https://attacker.invalid/somewhere'}

    with patch.object(v.session, 'get', return_value=fake_3xx) as mock_get:
        out = v.validate_relay(relay)

    # SSRF defense: allow_redirects=False on every call.
    assert mock_get.call_count >= 1
    for call in mock_get.call_args_list:
        assert call.kwargs.get('allow_redirects') is False, (
            f"allow_redirects must be False for SSRF defense; got {call.kwargs}"
        )

    # Both primary and www-fallback are tried (3xx is not a fast-fail).
    assert mock_get.call_count == 2, (
        f"both primary + www-fallback should be attempted on 3xx; "
        f"session.get was called {mock_get.call_count} times"
    )

    assert out['valid'] is False
    assert out['error_category'] == 'redirect_disallowed', out
    # Error must include status code AND the Location header for diagnostics
    assert '301' in out['error'], out
    assert 'https://attacker.invalid/somewhere' in out['error'], out
    print("  ✓ both primary + www 3xx: relay fails, category=redirect_disallowed, Location captured")


def test_redirect_primary_recovered_via_www():
    """When primary returns 3xx but www-fallback succeeds, the relay
    VALIDATES (not a failure) and a validation_steps note records the
    ignored primary error for diagnostic visibility."""
    _clear_host_safety_cache()
    v = ParallelAROIValidator(max_workers=1)
    relay = {
        'nickname': 'RecoveredRelay',
        'fingerprint': 'I' * 40,
        'family_ids': ['the_legitimate_public_family_id_value___'],
        'contact': 'url:public.invalid proof:uri-familyid-ed25519 ciissversion:3',
    }

    # Primary returns 301 → www-fallback is tried → www returns 200 with
    # the legitimate family id.
    primary_3xx = MagicMock()
    primary_3xx.status_code = 301
    primary_3xx.headers = {'Location': 'https://www.public.invalid/.well-known/tor-relay/ed25519-family-id.txt'}
    www_ok = MagicMock()
    www_ok.status_code = 200
    www_ok.headers = {}
    www_ok.text = relay['family_ids'][0] + '\n'
    # raise_for_status is a no-op for 200; we just need it not to throw.
    www_ok.raise_for_status = MagicMock(return_value=None)

    with patch.object(v.session, 'get', side_effect=[primary_3xx, www_ok]) as mock_get:
        out = v.validate_relay(relay)

    assert mock_get.call_count == 2
    assert out['valid'] is True, out
    # validation_steps should contain TWO entries: the ignored-primary note
    # and the successful match.
    steps = out.get('validation_steps') or []
    note = next((s for s in steps if 'primary fetch failed' in s.get('step', '')), None)
    assert note is not None, f"missing primary-error note in validation_steps: {steps}"
    assert note['success'] is False
    assert 'redirect_disallowed' in note['details'], note
    print("  ✓ primary 3xx + www 200: relay validates, primary error recorded as ignored note")


def main():
    print("Running ciissversion:3 mocked-input tests...")
    test_rollover()
    test_secret_key_leak_dns()
    test_secret_key_leak_uri()
    test_case_mismatch_diagnostic()
    test_ip_safety_classification()
    test_is_safe_public_host_rejects_ip_literals()
    test_is_safe_public_host_rejects_private_resolution()
    test_uri_validation_blocked_for_ip_literal()
    test_uri_validation_blocked_for_private_resolution()
    test_dns_rebinding_blocked_at_connect()
    test_redirect_both_primary_and_www_fail()
    test_redirect_primary_recovered_via_www()
    print("\nAll mocked-input tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
