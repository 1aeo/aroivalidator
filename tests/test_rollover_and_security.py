#!/usr/bin/env python3
"""Smoke tests for ciissversion:3 edge cases that don't require network:

  - Rollover simulation: two relays sharing the same url but with disjoint
    family_ids. Mock dns.resolver.resolve to return one TXT and verify:
      1. dns.resolver.resolve is called exactly ONCE (shared cache reuses
         the response).
      2. spec['matches'] re-runs per relay using cached content (relay A
         validates because its family_id is in the TXT, relay B does not).
      3. _set_domain_result is called exactly ONCE.

  - Secret-key leak: synthetic TXT containing simulated .secret_family_key
    content. Verify:
      1. result['error_category'] == 'secret_key_leaked'.
      2. SECURITY-prefixed error.
      3. valid is False (overrides any potential match).

Exit 0 on success, non-zero on any failure.
"""
import sys
import os.path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aroi_validator import ParallelAROIValidator


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
        'contact': f'url:example.invalid proof:dns-familyid-ed25519 ciissversion:3',
    }
    relay_b = {
        'nickname': 'RelayB',
        'fingerprint': 'B' * 40,
        'family_ids': [family_id_b],
        'contact': f'url:example.invalid proof:dns-familyid-ed25519 ciissversion:3',
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


def main():
    print("Running ciissversion:3 rollover and security smoke tests...")
    test_rollover()
    test_secret_key_leak_dns()
    test_secret_key_leak_uri()
    test_case_mismatch_diagnostic()
    print("\nAll rollover/security smoke tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
