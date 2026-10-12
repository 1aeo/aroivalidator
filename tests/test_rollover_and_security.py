#!/usr/bin/env python3
"""ciissversion:3 mocked-input tests (no network required).

Discoverable by pytest (`pytest tests/test_rollover_and_security.py`) and
also runnable as a standalone script (`python3 tests/test_rollover_and_security.py`).

Covers:
  - Rollover simulation (shared DNS cache, per-relay match)
  - Secret-key-leak detection (DNS and URI paths)
  - Case-mismatch diagnostic
  - SSRF protections (IP literals, private/loopback ranges, redirects)
  - Operator hostnames resolved as absolute names (no search-domain leak)
  - Hostnames ending in a Unicode full stop, or with an empty label, fail cleanly
  - Hosts longer than a DNS name rejected before any IDNA encoding
  - IPv4 shorthand (127.1, 0x7f.1) treated as IP literals; hosts-file-only names
  - TLS failures reported by their ssl error, not as connection errors
  - TLS SNI and the HTTP Host header keep the plain hostname
  - Results metadata records the code commit
"""
import io
import json
import socket
import ssl
import subprocess
import sys
import os.path
import tempfile
from unittest.mock import patch, MagicMock

import requests
from urllib3.exceptions import MaxRetryError, NewConnectionError, SSLError as Urllib3SSLError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aroi_validator import (
    ParallelAROIValidator,
    is_safe_public_host,
    _absolute_dns_name,
    _ip_is_safe,
    _is_ip_literal,
    _clear_host_safety_cache,
    _safe_create_connection,
    SSRFBlockedError,
    get_code_commit,
    save_results,
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


def test_absolute_dns_name():
    """Names get exactly one trailing dot. IP literals are left alone:
    '192.0.2.1.' or '::1.' no longer parses as an address and fails to resolve."""
    assert _absolute_dns_name('example.org') == 'example.org.'
    assert _absolute_dns_name('www.example.org') == 'www.example.org.'
    assert _absolute_dns_name('example.org.') == 'example.org.'
    for literal in ('192.0.2.1', '2001:db8::1', '::1'):
        assert _absolute_dns_name(literal) == literal
    assert _absolute_dns_name('') == ''
    print("  ✓ _absolute_dns_name: one trailing dot on names; IP literals and absolute names unchanged")


def test_operator_hosts_resolved_without_search_domain():
    """Every resolver call for an operator hostname must pass the absolute
    name. Otherwise, when the name fails to resolve, the system resolver
    retries it with the validator host's search domain appended
    (www.<domain> -> www.<domain>.<search-domain>), leaking it to that zone.

    Drives the www-fallback flow through the real requests/urllib3 stack.
    Hermetic: getaddrinfo is mocked to fail every lookup.
    """
    _clear_host_safety_cache()
    v = ParallelAROIValidator(max_workers=1)
    # Environment proxies would route the fetch around _safe_create_connection.
    v.session.trust_env = False
    relay = {
        'nickname': 'SearchDomainRelay',
        'fingerprint': 'J' * 40,
        'family_ids': ['fid'],
        'contact': 'url:operator.invalid proof:uri-familyid-ed25519 ciissversion:3',
    }
    looked_up = []

    def failing_getaddrinfo(host, *args, **kwargs):
        looked_up.append(host)
        raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')

    with patch('aroi_validator.socket.getaddrinfo', side_effect=failing_getaddrinfo):
        out = v.validate_relay(relay)

    assert set(looked_up) == {'operator.invalid.', 'www.operator.invalid.'}, (
        f"resolver must only see absolute names; got {looked_up}"
    )
    # The fetch URLs and error messages keep the plain hostname.
    assert out['valid'] is False, out
    assert 'https://www.operator.invalid/.well-known/' in out['error'], out
    assert 'operator.invalid.' not in out['error'], out
    print("  ✓ safety check and connect lookups use absolute names; messages keep plain names")


UNICODE_FULL_STOPS = ('\u3002', '\uff0e', '\uff61')


def _idna_then_fail_getaddrinfo(looked_up):
    """getaddrinfo stand-in that encodes the name with the idna codec, as the
    real one does before any query (raising UnicodeError for an empty or
    over-long label), records the encoded name, then fails the lookup."""
    def fake_getaddrinfo(host, *args, **kwargs):
        looked_up.append(host.encode('idna'))
        raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')
    return fake_getaddrinfo


def test_absolute_dns_name_unicode_full_stops():
    """The idna codec reads U+3002, U+FF0E and U+FF61 as '.', so a name
    ending in one is already absolute. Adding a root dot would make an empty
    label, which getaddrinfo rejects with UnicodeError."""
    for stop in UNICODE_FULL_STOPS:
        name = 'example.org' + stop
        assert _absolute_dns_name(name) == name, repr(stop)
        assert _absolute_dns_name(name).encode('idna') == b'example.org.', repr(stop)
        # A Unicode full stop inside the name is a separator, not the root.
        inner = 'example' + stop + 'org'
        assert _absolute_dns_name(inner).encode('idna') == b'example.org.', repr(stop)
    print("  ✓ _absolute_dns_name: names ending in a Unicode full stop stay absolute and encodable")


def test_malformed_hostnames_fail_cleanly():
    """Names the idna codec rejects (empty or over-long label) must not raise
    UnicodeError out of the safety check or the connect."""
    _clear_host_safety_cache()
    names = [
        'operator..invalid', '.operator.invalid', 'operator.invalid..',
        'a' * 64 + '.invalid',
    ] + ['operator.invalid' + stop + '.' for stop in UNICODE_FULL_STOPS]
    for name in names:
        with patch('aroi_validator.socket.getaddrinfo',
                   side_effect=_idna_then_fail_getaddrinfo([])):
            safe, reason = is_safe_public_host(name)
            assert safe is True and reason.startswith('unresolved'), (name, safe, reason)
            try:
                _safe_create_connection((name, 443), timeout=2)
                raise AssertionError(f"{name!r}: connect should fail")
            except socket.gaierror:
                pass  # urllib3 reports it as a NameResolutionError
    print("  ✓ empty/over-long labels: safety check and connect fail without UnicodeError")


def test_relay_with_malformed_hostname_fails_cleanly():
    """validate_relay must return a categorized failure, and resolve the
    domain-cache entry, for a url ending in a Unicode full stop or holding an
    empty label. An escaped exception left the entry 'pending', so every other
    relay sharing the domain waited for the cache timeout."""
    names = ['operator.invalid' + stop for stop in UNICODE_FULL_STOPS]
    names.append('operator..invalid')
    for name in names:
        _clear_host_safety_cache()
        v = ParallelAROIValidator(max_workers=1)
        v.session.trust_env = False
        relay = {
            'nickname': 'MalformedHostRelay',
            'fingerprint': 'K' * 40,
            'family_ids': ['fid'],
            'contact': f'url:https://{name} proof:uri-familyid-ed25519 ciissversion:3',
        }
        looked_up = []
        with patch('aroi_validator.socket.getaddrinfo',
                   side_effect=_idna_then_fail_getaddrinfo(looked_up)):
            out = v.validate_relay(relay)

        assert out['valid'] is False, out
        assert out['error_category'] == 'transport_error', (name, out)
        entry = v._domain_cache[(out['domain'], 'uri-familyid-ed25519')]
        assert entry['status'] != 'pending', (name, entry)
        if name[-1] in UNICODE_FULL_STOPS:
            # The safety check resolves both hosts as absolute names; urllib3
            # then rejects the URL itself, so no connect-time lookup follows.
            assert set(looked_up) == {b'operator.invalid.', b'www.operator.invalid.'}, (name, looked_up)
        else:
            assert looked_up == [], (name, looked_up)
            assert 'name resolution failed' in out['error'], (name, out)
    print("  ✓ url ending in a Unicode full stop or with an empty label: transport_error, cache entry resolved")


def test_overlong_hostname_rejected_before_lookup():
    """A url host longer than a DNS name (253 characters) is invalid_url,
    before the safety check, any lookup or fetch. Each of those IDNA-encodes
    the host, and the codec's punycode step is quadratic in label length: a
    5,000-character CJK host took seconds per encode, holding the GIL."""
    v = ParallelAROIValidator(max_workers=1)
    longest = '.'.join(['a' * 63, 'b' * 63, 'c' * 63, 'd' * 57, 'org'])
    assert len(longest) == 253
    assert v._extract_domain(f'https://{longest}/') == longest
    assert v._extract_domain(f'https://e{longest}/') is None

    overlong = ''.join(chr(0x4e00 + i) for i in range(5000)) + '.com'
    for proof in ('uri-familyid-ed25519', 'dns-familyid-ed25519'):
        _clear_host_safety_cache()
        relay = {
            'nickname': 'OverlongHostRelay',
            'fingerprint': 'L' * 40,
            'family_ids': ['fid'],
            'contact': f'url:https://{overlong} proof:{proof} ciissversion:3',
        }
        with patch('aroi_validator.socket.getaddrinfo') as mock_gai, \
             patch('aroi_validator.dns.resolver.resolve') as mock_resolve, \
             patch.object(v, '_fetch_with_retry') as mock_fetch:
            out = v.validate_relay(relay)
        assert out['valid'] is False, proof
        assert out['error_category'] == 'invalid_url', (proof, out['error_category'], out['error'][:80])
        assert mock_gai.call_count == mock_resolve.call_count == mock_fetch.call_count == 0, proof
    print("  ✓ url host over 253 characters: invalid_url with no lookup or fetch (uri and dns proofs)")


def test_numeric_shorthand_is_ip_literal():
    """glibc's getaddrinfo parses every IPv4 form inet_aton accepts as an
    address: 127.1 and 0x7f.1 are 127.0.0.1, 010.0.0.1 is 8.0.0.1. They must
    be rejected like 127.0.0.1, with no lookup, and keep no trailing dot
    ('127.1.' is a name and would be sent to DNS)."""
    literals = ('127.1', '127.0.1', '127.000.000.001', '0x7f.1', '0177.0.0.1',
                '010.0.0.1', '2130706433', '0x7f000001', '1.2.3', '4294967295',
                '\uff11\uff12\uff17.0.0.1')  # fullwidth digits; IDNA maps them to ASCII
    names = ('123.example', 'xn--1.com', '1.com', '0x7f.com', '127.1.', '127..1',
             '127.1 x', '127.1\t', '256.1', '1.2.3.256', '08.0.0.1', '1e2',
             '1.2.3.4.5')
    for host in literals:
        assert _is_ip_literal(host), host
        assert _absolute_dns_name(host) == host, host
    for host in names:
        assert not _is_ip_literal(host), host

    _clear_host_safety_cache()
    v = ParallelAROIValidator(max_workers=1)
    relay = {
        'nickname': 'ShorthandRelay',
        'fingerprint': 'K' * 40,
        'family_ids': ['fid'],
        'contact': 'url:https://0x7f.1 proof:uri-familyid-ed25519 ciissversion:3',
    }
    looked_up = []

    def failing_getaddrinfo(host, *args, **kwargs):
        looked_up.append(host)
        raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')

    with patch('aroi_validator.socket.getaddrinfo', side_effect=failing_getaddrinfo), \
         patch.object(v, '_fetch_with_retry') as mock_fetch:
        for host in literals:
            safe, reason = is_safe_public_host(host)
            assert not safe and 'IP literal' in reason, (host, safe, reason)
        out = v.validate_relay(relay)

    assert looked_up == [], f"IP literals must not be resolved; got {looked_up}"
    assert mock_fetch.call_count == 0, mock_fetch.call_count
    assert out['error_category'] == 'unsafe_target', out
    print("  ✓ IPv4 shorthand (127.1, 0x7f.1, 010.0.0.1) rejected as IP literal with no lookup; names unaffected")


def test_hosts_file_only_name_not_consulted():
    """Operator hostnames are resolved by DNS, not by the validator host's
    /etc/hosts: glibc's hosts-file backend doesn't match the absolute name
    the validator passes. A name only the hosts file knows must fail to
    resolve, and nothing may connect to the address the hosts file gives.

    Hermetic: getaddrinfo is mocked to answer like glibc with a hosts entry
    for the relative names only; socket.socket is a tripwire.
    """
    _clear_host_safety_cache()
    v = ParallelAROIValidator(max_workers=1)
    # Environment proxies would route the fetch around _safe_create_connection.
    v.session.trust_env = False
    relay = {
        'nickname': 'HostsFileRelay',
        'fingerprint': 'L' * 40,
        'family_ids': ['fid'],
        'contact': 'url:hostsonly.invalid proof:uri-familyid-ed25519 ciissversion:3',
    }
    hosts_file = {'hostsonly.invalid': '93.184.216.34',
                  'www.hostsonly.invalid': '93.184.216.34'}
    looked_up = []
    sockets = []

    def hosts_file_getaddrinfo(host, port=None, *args, **kwargs):
        looked_up.append(host)
        if host in hosts_file:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (hosts_file[host], port or 0))]
        raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')

    def tripwire_socket(*args, **kwargs):
        sockets.append(args)
        raise OSError("tripwire: socket() called")

    with patch('aroi_validator.socket.getaddrinfo', side_effect=hosts_file_getaddrinfo), \
         patch('aroi_validator.socket.socket', side_effect=tripwire_socket):
        out = v.validate_relay(relay)

    assert looked_up and all(h.endswith('.') for h in looked_up), (
        f"resolver must only see absolute names; got {looked_up}"
    )
    assert sockets == [], f"socket() was called {len(sockets)} time(s)"
    assert out['valid'] is False, out
    assert out['error_category'] == 'transport_error', out
    print("  ✓ hosts-file-only name: not consulted, fails closed as transport_error, no connection")


def _requests_error(exc_cls, cause):
    """Wrap cause the way requests raises a failed connect/handshake:
    requests error -> MaxRetryError -> urllib3 error -> cause."""
    if isinstance(cause, ssl.SSLError):
        cause = Urllib3SSLError(cause)
    return exc_cls(MaxRetryError(None, '/.well-known/tor-relay/rsa-fingerprint.txt', cause))


def _ssl_error(cls, reason, text, verify_code=None, verify_message=None):
    """ssl exception with the attributes _ssl sets on a real one."""
    e = cls(1, f"[SSL: {reason}] {text} (_ssl.c:1029)")
    e.reason, e.library = reason, 'SSL'
    if verify_code is not None:
        e.verify_code, e.verify_message = verify_code, verify_message
    return e


def _cert_error(verify_code, verify_message):
    return _ssl_error(
        ssl.SSLCertVerificationError, 'CERTIFICATE_VERIFY_FAILED',
        f"certificate verify failed: {verify_message}", verify_code, verify_message)


def _fetch_failure(exc):
    """validate_relay for a uri-rsa relay whose every fetch raises exc.
    Returns (result, session.get call count). The pre-flight resolves to a
    public address; socket.create_connection is a tripwire for any second
    connection opened to describe the failure."""
    _clear_host_safety_cache()
    v = ParallelAROIValidator(max_workers=1)
    relay = {
        'nickname': 'TLSRelay',
        'fingerprint': 'K' * 40,
        'contact': 'url:tls.invalid proof:uri-rsa ciissversion:2',
    }
    public = [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 0))]
    with patch('aroi_validator.socket.getaddrinfo', return_value=public), \
         patch('aroi_validator.socket.create_connection') as tripwire, \
         patch.object(v.session, 'get', side_effect=exc) as mock_get:
        out = v.validate_relay(relay)
    assert tripwire.call_count == 0, "TLS failure must not open a second connection"
    return out, mock_get.call_count


def test_tls_failures_report_cause():
    """requests.SSLError subclasses ConnectionError, so it must be caught
    first; otherwise every TLS failure reads 'connection max retries
    exceeded'. The message comes from the wrapped ssl error. The category
    stays transport_error and the www-fallback is still tried, as before."""
    url = 'https://tls.invalid/.well-known/tor-relay/rsa-fingerprint.txt'
    cases = [
        (_cert_error(10, 'certificate has expired'),
         "HTTP SSL certificate expired for tls.invalid at URL: " + url),
        (_cert_error(18, 'self-signed certificate'),
         "HTTP SSL certificate is self-signed for tls.invalid at URL: " + url),
        (_cert_error(62, "Hostname mismatch, certificate is not valid for 'tls.invalid'."),
         "HTTP SSL hostname mismatch, certificate is not valid for tls.invalid at URL: " + url),
        (_cert_error(20, 'unable to get local issuer certificate'),
         "HTTP SSL certificate chain incomplete or issued by an untrusted CA for tls.invalid"),
        (_cert_error(19, 'self-signed certificate in certificate chain'),
         "HTTP SSL certificate chain ends in an untrusted root CA for tls.invalid"),
        (_cert_error(9, 'certificate is not yet valid'),
         "HTTP SSL certificate verification failed (certificate is not yet valid) for tls.invalid"),
        (_ssl_error(ssl.SSLError, 'SSLV3_ALERT_HANDSHAKE_FAILURE', 'ssl/tls alert handshake failure'),
         "HTTP SSL handshake failure (server sent handshake_failure alert) for tls.invalid"),
        (_ssl_error(ssl.SSLError, 'UNSUPPORTED_PROTOCOL', 'unsupported protocol'),
         "HTTP SSL handshake failure (server does not support TLS 1.2 or newer) for tls.invalid"),
        (_ssl_error(ssl.SSLEOFError, 'UNEXPECTED_EOF_WHILE_READING', 'EOF occurred in violation of protocol'),
         "HTTP SSL error unexpected EOF for tls.invalid"),
        (_ssl_error(ssl.SSLError, 'BAD_DH_VALUE', 'bad dh value'),
         "HTTP SSL error bad dh value for tls.invalid at URL: " + url),
    ]
    for cause, expected in cases:
        out, calls = _fetch_failure(_requests_error(requests.exceptions.SSLError, cause))
        assert out['valid'] is False, out
        assert out['error_category'] == 'transport_error', out
        assert out['error'].startswith('URI-RSA: ' + expected), (expected, out['error'])
        assert calls == 2, f"www-fallback should still be tried after a TLS failure ({calls} fetches)"
        assert 'www.tls.invalid at URL' in out['error'], out['error']
        assert 'max retries' not in out['error'] and '_ssl.c' not in out['error'], out['error']
    print(f"  ✓ TLS failures: {len(cases)} ssl error variants reported by cause, transport_error, www-fallback kept, no second connection")


def test_non_tls_connection_errors_unchanged():
    """Connection errors that are not TLS failures keep their messages and
    the connectivity rule for skipping the www-fallback."""
    url = 'https://tls.invalid/.well-known/tor-relay/rsa-fingerprint.txt'
    refused = NewConnectionError(None, 'Failed to establish a new connection: [Errno 111] Connection refused')
    out, calls = _fetch_failure(_requests_error(requests.exceptions.ConnectionError, refused))
    assert out['error'] == f"URI-RSA: HTTP error connection refused for URL: {url}", out['error']
    assert out['error_category'] == 'transport_error' and calls == 1, (out, calls)

    unreachable = NewConnectionError(None, 'Failed to establish a new connection: [Errno 101] Network is unreachable')
    out, calls = _fetch_failure(_requests_error(requests.exceptions.ConnectionError, unreachable))
    assert out['error'].startswith(f"URI-RSA: HTTP error connection max retries exceeded for URL: {url}; "), out['error']
    assert out['error_category'] == 'transport_error' and calls == 2, (out, calls)
    print("  ✓ non-TLS connection errors: messages, category and www-fallback rule unchanged")


def test_fetch_sends_plain_sni_and_host_header():
    """A URI-proof fetch through the validator's session (SecureTLSAdapter ->
    SSRF-safe urllib3 connection -> _safe_create_connection) resolves the
    absolute name, but sends the plain hostname as TLS SNI and HTTP Host.
    urllib3 2.x strips the dot from both; this catches code of ours that adds it back.

    Hermetic: getaddrinfo returns a public IP, the TCP socket and the TLS
    handshake are mocked, and the mocked TLS socket replays a canned HTTP
    response that holds the relay's family ID.
    """
    _clear_host_safety_cache()
    v = ParallelAROIValidator(max_workers=1)
    # Environment proxies would route the fetch around _safe_create_connection.
    v.session.trust_env = False
    family_id = 'the_legitimate_public_family_id_value___'
    relay = {
        'nickname': 'PlainSNIRelay',
        'fingerprint': 'K' * 40,
        'family_ids': [family_id],
        'contact': 'url:operator.invalid proof:uri-familyid-ed25519 ciissversion:3',
    }
    looked_up = []
    sni = []
    sent = []

    def public_getaddrinfo(host, *args, **kwargs):
        looked_up.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]

    body = (family_id + '\n').encode()
    tls_sock = MagicMock()
    tls_sock.sendall.side_effect = sent.append
    tls_sock.makefile.return_value = io.BytesIO(
        b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n'
        b'Content-Length: %d\r\n\r\n%s' % (len(body), body)
    )

    def fake_wrap_socket(self, sock, server_hostname=None, **kwargs):
        sni.append(server_hostname)
        return tls_sock

    with patch('aroi_validator.socket.getaddrinfo', side_effect=public_getaddrinfo), \
         patch('aroi_validator.socket.socket', return_value=MagicMock()), \
         patch.object(ssl.SSLContext, 'wrap_socket', fake_wrap_socket):
        out = v.validate_relay(relay)
    _clear_host_safety_cache()

    assert out['valid'] is True, out
    assert set(looked_up) == {'operator.invalid.'}, (
        f"resolver must only see absolute names; got {looked_up}"
    )
    assert sni == ['operator.invalid'], f"SNI must be the plain hostname; got {sni}"
    request = b''.join(sent)
    host_headers = [
        line for line in request.split(b'\r\n') if line.lower().startswith(b'host:')
    ]
    assert host_headers == [b'Host: operator.invalid'], (
        f"Host header must be the plain hostname; got {host_headers}"
    )
    print("  ✓ URI fetch resolves the absolute name; SNI and Host header keep the plain name")


def test_code_commit():
    """AROIVALIDATOR_COMMIT wins when it is 7-40 hex digits; otherwise git
    rev-parse HEAD in the code's directory; any failure gives None.
    Hermetic: subprocess.run is mocked."""
    commit = '0123456789abcdef0123456789abcdef01234567'

    def code_commit(env_value, **run):
        with patch.dict(os.environ), \
             patch('aroi_validator.subprocess.run', **run) as mock_run:
            os.environ.pop('AROIVALIDATOR_COMMIT', None)
            if env_value is not None:
                os.environ['AROIVALIDATOR_COMMIT'] = env_value
            return get_code_commit(), mock_run

    git_ok = {'return_value': MagicMock(stdout=commit + '\n')}

    # Env var: full or abbreviated hex, lowercased; git is not run.
    for value, expected in ((commit.upper(), commit), (' 6e070ff\n', '6e070ff')):
        got, mock_run = code_commit(value, **git_ok)
        assert got == expected, (value, got)
        assert mock_run.call_count == 0, value

    # Unset or invalid env var: ask git about the checkout holding aroi_validator.py.
    code_dir = os.path.dirname(os.path.realpath(sys.modules['aroi_validator'].__file__))
    for value in (None, '', 'main', 'abc123', 'g' * 40, 'a' * 41):
        got, mock_run = code_commit(value, **git_ok)
        assert got == commit, (value, got)
        assert mock_run.call_count == 1, value
        assert mock_run.call_args.args[0] == ['git', '-C', code_dir, 'rev-parse', 'HEAD'], (
            mock_run.call_args
        )
        assert 0 < mock_run.call_args.kwargs['timeout'] <= 10, mock_run.call_args

    # Every git failure, or output that isn't a full commit, gives None.
    failures = (
        {'side_effect': FileNotFoundError(2, 'No such file or directory', 'git')},
        {'side_effect': PermissionError(13, 'Permission denied', 'git')},
        {'side_effect': subprocess.TimeoutExpired('git', 5)},
        {'side_effect': subprocess.CalledProcessError(128, 'git')},
        {'return_value': MagicMock(stdout='')},
        {'return_value': MagicMock(stdout='6e070ff\n')},
        {'return_value': MagicMock(stdout='fatal: not a git repository\n')},
    )
    for run in failures:
        got, _ = code_commit(None, **run)
        assert got is None, (run, got)
    print("  ✓ code commit: env var wins when valid hex, else git rev-parse HEAD, else None")


def test_save_results_records_code_commit():
    """save_results writes metadata.code_commit, resolved once per save
    rather than once per relay."""
    commit = '0123456789abcdef0123456789abcdef01234567'
    results = [
        {'valid': True, 'proof_type': 'dns-rsa', 'ciissversion': '2'},
        {'valid': False, 'proof_type': 'uri-familyid-ed25519', 'ciissversion': '3'},
        {'valid': False, 'proof_type': None, 'ciissversion': None},
    ]
    cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        try:
            with patch('aroi_validator.get_code_commit', return_value=commit) as mock_commit:
                path = save_results(results, 'aroi_validation_test.json')
            saved = json.loads(path.read_text())
            latest = json.loads((path.parent / 'latest.json').read_text())
        finally:
            os.chdir(cwd)

    assert mock_commit.call_count == 1, mock_commit.call_count
    assert saved['metadata']['code_commit'] == commit, saved['metadata']
    assert latest['metadata']['code_commit'] == commit, latest['metadata']
    print("  ✓ save_results records metadata.code_commit, resolved once per save")


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
    test_absolute_dns_name()
    test_operator_hosts_resolved_without_search_domain()
    test_absolute_dns_name_unicode_full_stops()
    test_malformed_hostnames_fail_cleanly()
    test_relay_with_malformed_hostname_fails_cleanly()
    test_overlong_hostname_rejected_before_lookup()
    test_numeric_shorthand_is_ip_literal()
    test_hosts_file_only_name_not_consulted()
    test_tls_failures_report_cause()
    test_non_tls_connection_errors_unchanged()
    test_fetch_sends_plain_sni_and_host_header()
    test_code_commit()
    test_save_results_records_code_commit()
    print("\nAll mocked-input tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
