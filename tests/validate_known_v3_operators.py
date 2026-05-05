#!/usr/bin/env python3
"""Smoke test: validate all distinct ciissversion:3 operators currently on
the live Tor network.

Run from the repo root:
    python3 tests/validate_known_v3_operators.py

Queries Onionoo for relays declaring ciissversion:3, groups by (url, proof),
picks one relay per group, and validates it. Useful for regression-checking
that ciissversion:3 support still works against real-world deployments.

Exit code 0 on full success, non-zero if any operator fails to validate.
"""
import sys
from collections import defaultdict

import requests

# Make repo root importable when running from tests/
import os.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aroi_validator import ParallelAROIValidator, _AROI_PATTERNS


def main() -> int:
    print("Fetching ciissversion:3 relays from Onionoo...")
    resp = requests.get(
        'https://onionoo.torproject.org/details',
        params={
            'type': 'relay',
            'contact': 'ciissversion:3',
            'fields': 'nickname,fingerprint,contact,running,last_seen,family_ids',
        },
        timeout=30,
    ).json()
    relays = resp.get('relays', [])
    print(f"  → {len(relays)} relays returned")

    # Group by (url, proof) to identify distinct operators
    groups: dict = defaultdict(list)
    for r in relays:
        contact = r.get('contact', '') or ''
        url_m = _AROI_PATTERNS['url'].search(contact)
        proof_m = _AROI_PATTERNS['proof'].search(contact)
        ver_m = _AROI_PATTERNS['ciissversion'].search(contact)
        if not (url_m and proof_m and ver_m and ver_m.group(1) == '3'):
            continue
        if proof_m.group(1) not in ('dns-familyid-ed25519', 'uri-familyid-ed25519'):
            continue
        groups[(url_m.group(1), proof_m.group(1))].append(r)

    print(f"  → {len(groups)} distinct (url, proof) ciissversion:3 operator groups\n")

    validator = ParallelAROIValidator(max_workers=1)
    print(f"{'Operator':<40} {'Proof':<24} {'Result':<8} Detail")
    print("=" * 110)

    passed = 0
    failed = 0
    for (url, proof), group in groups.items():
        relay = group[0]
        out = validator.validate_relay(relay)
        valid = out.get('valid')
        label = "✓ VALID" if valid else "✗ FAIL"
        nickname = relay.get('nickname', '?')
        fp_short = relay.get('fingerprint', '')[:8]
        print(f"{url:<40} {proof:<24} {label:<8} {nickname} ({fp_short}…)")
        if not valid:
            print(f"  └─ error: {out.get('error')}")
            if out.get('hint'):
                print(f"  └─ hint:  {out['hint']}")
            failed += 1
        else:
            passed += 1

    print("=" * 110)
    print(
        f"Summary: {passed} valid, {failed} failed across "
        f"{len(groups)} distinct ciissversion:3 operators"
    )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
