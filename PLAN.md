# PLAN — Add CIISS v3 support alongside v2

## 1. Executive summary

Add support for CIISS **Version 3** of the Tor relay ContactInfo spec
(<https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/>, dated
2026-03-26) while keeping **Version 2** byte-identical. Operators pick which
ciissversions to validate with a new `--ciiss-versions` CLI flag (env fallback
`CIISS_VERSIONS`); default is every ciissversion this build understands.
Adding or retiring a ciissversion becomes a data-only change: one entry in
`PROOF_SPECS` + one line in `SUPPORTED_CIISSVERSIONS_DEFAULT`.

Beyond mere protocol support, this change treats every validation failure as
a **teachable moment for operators migrating from ciissversion:2 to
ciissversion:3**. Each ciissversion:3 failure carries:
- `error_category`: an exact tag (enum-like string, refactor-safe) identifying
  the root cause — used by both hints and statistics.
- `hint`: operator-facing next step (which Tor command to run, which file to
  publish, which record to add), looked up by category tag.

A separate `aroi_cli.py insights` subcommand renders human-readable
migration-guidance prose from any saved results JSON — **not** in the
validator hot path. The machine-readable categories (`v3_failure_categories`
in stats) are always in the JSON so automated pipelines get them for free.

v3 introduces two new proof methods (`dns-familyid-ed25519`,
`uri-familyid-ed25519`) that verify an ed25519 **family ID** instead of an
RSA fingerprint, using a new Onionoo field `family_ids`. v2's `dns-rsa` and
`uri-rsa` are **not valid under v3** and are rejected as unsupported.

Net target: ~+220 / −170 LOC in `aroi_validator.py`, ~+25 in `aroi_cli.py` +
`app.py` combined, plus README. Most new code is two data tables
(`PROOF_SPECS` + `CATEGORY_INFO`) and a separate insights subcommand; two
per-kind validator methods collapse into one generic one.

## 2. Operator migration path — what an operator actually has to change

This section is referenced by error hints and README migration FAQ.

1. **Generate a happy-family key** (one-time, per operator, shared across
   all relays in the family):
   ```
   tor --keygen-family /path/to/familykeys/myfamily
   ```
   Produces `myfamily.secret_family_key` (keep secret!) and
   `myfamily.public_family_id` (a 43-character, case-sensitive string — this
   is what gets published).
2. **Configure Tor** on every relay in the family to use the happy-family
   key per the Tor manual (replaces manual `MyFamily <fp1>,<fp2>,...`
   listings). Restart. Wait for Onionoo to pick up the new `family_ids`
   field (~1 refresh cycle).
3. **Update ContactInfo** on every relay:
   - `ciissversion:2` → `ciissversion:3`
   - `proof:dns-rsa` → `proof:dns-familyid-ed25519`, or
   - `proof:uri-rsa` → `proof:uri-familyid-ed25519`
4. **Publish the new proof**:
   - **DNS path**: delete the old per-relay TXT records at
     `<rsa-fp>.<domain>`; publish ONE shared TXT record at
     `we-run-this-tor-ed25519-family-id.<domain>` whose value is the
     contents of `public_family_id`. During key rollover, two records may
     exist simultaneously.
   - **URI path**: replace
     `/.well-known/tor-relay/rsa-fingerprint.txt` with
     `/.well-known/tor-relay/ed25519-family-id.txt` containing the
     `public_family_id` (one or more lines, case-sensitive, HTTPS only,
     trusted CA, no redirects).
5. **Never** publish the contents of `.secret_family_key` anywhere. Only
   `.public_family_id` goes into DNS / HTTP.

## 3. v2 vs v3 — spec differences that matter for this tool

| Aspect | v2 | v3 |
|---|---|---|
| `ciissversion` value | `2` | `3` |
| Mandatory fields | `ciissversion`, `proof`, `url` (all three) | `ciissversion` + ≥1 other; `url` optional; `proof` mandatory **iff** `url` is set |
| Allowed `proof` values | `dns-rsa`, `uri-rsa` | `dns-familyid-ed25519`, `uri-familyid-ed25519` (RSA proofs NOT allowed under v3) |
| DNS query | per-relay `<rsa-fp>.<domain>` | shared `we-run-this-tor-ed25519-family-id.<domain>` |
| DNS value | substring `"we-run-this-tor-relay"` | one or more 43-char case-sensitive ed25519 family IDs (rollover allows multiple) |
| URI path | `/.well-known/tor-relay/rsa-fingerprint.txt` | `/.well-known/tor-relay/ed25519-family-id.txt` |
| URI tokens | 40-char hex RSA fingerprints (case-insensitive) | 43-char case-sensitive ed25519 family IDs |
| Compared against | `relay.fingerprint` | `relay.family_ids[]` (Onionoo; new in our fetch) |
| DNS cache-on-success shareable? | No (per-relay subdomain) | Yes (same TXT for all relays on the domain) |
| DNSSEC / trusted CA | spec-required, not enforced by this tool | same gap, same reason, documented |

Informational-only v3 fields (`uplinkbw`, `hoster`, `pgp`, `matrix`, etc.) are
not part of AROI proof verification — explicitly out of scope.

## 4. Field-combination decision table (authoritative)

Let `<N>` = the relay's declared ciissversion (dynamic). All "v3" rows below
use `<N>` so future ciissversion:4+ reuse the same wording.

| # | Version | `url` | `proof` | `family_ids` | Resulting error / success | Stats bucket |
|---|---|---|---|---|---|---|
| 1 | any (missing `ciissversion`) | — | — | — | `Missing AROI fields: ciissversion` *(existing)* | no_proof |
| 2 | declared `ciissversion` not in `--ciiss-versions` | — | — | — | `Unsupported ciissversion: <N> (supported: 2,3)` (category=`ciissversion_unsupported`) | no_proof |
| 3 | v2 | absent | `dns-rsa`/`uri-rsa` | — | `Missing AROI field: url, required for DNS-RSA proof` / `… URI-RSA proof` *(existing)* | dns_rsa / uri_rsa |
| 4 | v2 | any | absent | — | `Missing AROI fields: proof` *(existing)* | no_proof |
| 5 | v2 | present | `dns-familyid-…`/`uri-familyid-…`/other | — | `Unsupported proof type: <type>` *(existing)* | no_proof |
| 6 | v3 | absent | absent or present (spec ignores `proof` when `url` is absent) | — | **Not an error.** Spec-compliant: operator declared `ciissversion:3` with informational fields only, no domain claim → no proof to run. `valid=False, error=None, proof_type=None`. Aggregated in stats as `no_proof.ciissversion3_no_url`. v3 has **no "default proof type"**; proofs only exist to verify a declared `url`. | no_proof |
| 7 | v3 | present | absent | — | `Missing AROI field: proof, required when url is set` (category=`missing_proof_field`) | no_proof |
| 8 | v3 | present | `dns-rsa`/`uri-rsa` (legacy proof on v3) | — | `Unsupported proof type: <type>` (category=`wrong_proof_type_rsa`) | no_proof |
| 9 | v3 | present | any other unrecognized proof | — | `Unsupported proof type: <type>` (no category — genuinely unknown) | no_proof |
| 10 | v3 | present, invalid domain | `dns-familyid-ed25519` | — | `DNS-FamilyID: Invalid domain in url field: <url>` (category=`invalid_url`) | dns_familyid_ed25519 |
| 11 | v3 | present, invalid domain | `uri-familyid-ed25519` | — | `URI-FamilyID: Invalid domain in url field: <url>` (category=`invalid_url`) | uri_familyid_ed25519 |
| 12 | v3 | present | `dns-familyid-ed25519` | empty/absent | `DNS-FamilyID: Relay has no family_ids in Onionoo, cannot verify ciissversion:<N> proof` (category=`missing_family_ids`) | dns_familyid_ed25519 |
| 13 | v3 | present | `uri-familyid-ed25519` | empty/absent | `URI-FamilyID: Relay has no family_ids in Onionoo, cannot verify ciissversion:<N> proof` (category=`missing_family_ids`) | uri_familyid_ed25519 |
| 14 | v3 | present | `dns-familyid-ed25519` | present | DNS TXT lookup. **(a)** Secret-key sniff on TXT content first. If leaked → `SECURITY: DNS-FamilyID: published content appears to contain .secret_family_key. Rotate immediately.` (category=`secret_key_leaked`). **(b)** Else match → `valid=true`. **(c)** Else mismatch → `DNS-FamilyID: TXT record content does not match relay family_ids. Expected one of: <ids>, found: <records[:100]>` (+ `" (case mismatch detected — spec requires case-sensitive match)"` suffix if case-insensitive match) (category=`dns_content_mismatch`) | dns_familyid_ed25519 |
| 15 | v3 | present | `uri-familyid-ed25519` | present | HTTPS fetch. **(a)** Secret-key sniff on response text first (category=`secret_key_leaked`). **(b)** Match → `valid=true`. **(c)** Mismatch → `URI-FamilyID: family_id not found at <domain>` (+ case-mismatch suffix if applicable) (category=`uri_content_mismatch`) | uri_familyid_ed25519 |
| 16 | v3 | present | `dns-familyid-ed25519` | present | NXDOMAIN → `DNS-FamilyID: TXT record not found at <domain>` (category=`dns_txt_missing`) | dns_familyid_ed25519 |
| 17 | v3 | present | `uri-familyid-ed25519` | present | HTTP 404 → `URI-FamilyID: proof file not found at <domain> at URL: <url>` (category=`uri_file_missing`) | uri_familyid_ed25519 |
| 18 | v3 | present | any familyid proof | present | Network / TLS / non-404 HTTP errors → existing error templates with `DNS-FamilyID:` / `URI-FamilyID:` prefix via `spec['label']` (category=`transport_error`) | dns_familyid_ed25519 / uri_familyid_ed25519 |

## 5. Implementation design

### 5.1 `PROOF_SPECS` — unified shape for all kinds

```python
PROOF_SPECS = {
    ('2', 'dns-rsa'): {
        'kind': 'dns', 'label': 'DNS-RSA',
        'locator': lambda relay, domain: f"{relay['fingerprint'].lower()}.{domain}",
        'shared_proof': False,
        'expected_desc': "'we-run-this-tor-relay'",
        'matches': lambda content, relay: any(
            'we-run-this-tor-relay' in r.lower() for r in content),
    },
    ('2', 'uri-rsa'): {
        'kind': 'uri', 'label': 'URI-RSA',
        'locator': lambda relay, domain: '/.well-known/tor-relay/rsa-fingerprint.txt',
        'shared_proof': True,
        'expected_desc': 'relay RSA fingerprint',
        'matches': lambda content, relay: relay['fingerprint'].upper() in {
            l.strip().upper() for l in content.splitlines()
            if l.strip() and not l.strip().startswith('#')},
    },
    ('3', 'dns-familyid-ed25519'): {
        'kind': 'dns', 'label': 'DNS-FamilyID',
        'locator': lambda relay, domain: f"we-run-this-tor-ed25519-family-id.{domain}",
        'shared_proof': True,
        'expected_desc': 'relay family_ids (43-char ed25519)',
        'matches': lambda content, relay: bool(
            {r.strip() for r in content if r.strip()}
            & _norm_family_ids(relay)),
    },
    ('3', 'uri-familyid-ed25519'): {
        'kind': 'uri', 'label': 'URI-FamilyID',
        'locator': lambda relay, domain: '/.well-known/tor-relay/ed25519-family-id.txt',
        'shared_proof': True,
        'expected_desc': 'relay family_ids (43-char ed25519)',
        'matches': lambda content, relay: bool(
            {l.strip() for l in content.splitlines()
             if l.strip() and not l.strip().startswith('#')}
            & _norm_family_ids(relay)),
    },
}

SUPPORTED_CIISSVERSIONS_DEFAULT = ('2', '3')
ALL_KNOWN_CIISSVERSIONS = tuple(sorted({v for (v, _) in PROOF_SPECS}))
```

### 5.2 `CATEGORY_INFO` — single category metadata table

Hints + insights titles + insights actions all live in one dict keyed by
`error_category`. Adding a category = one entry; retiring = one deletion.

### 5.3 `_parse_aroi_fields` — pure parser

Always returns `(dict, list)`. No version-specific gating in the parser.

### 5.4 `validate_relay` — single dispatcher

ciissversion-aware required-field checks; spec lookup; delegation. v2 error
strings byte-identical. v3 errors get category tag + hint.

### 5.5 `_validate_kind(relay, aroi, result, spec)` — unified per-kind validator

One function replaces both `_validate_dns_rsa` and `_validate_uri_rsa`.
Branches on `spec['kind']`. Cache lookup, content match, error formatting
all spec-driven. Includes secret-key-leak sniff in `_finalize_match`,
case-mismatch diagnostic, multi-string TXT concatenation, force-HTTPS for
.well-known, port-stripping via `parsed.hostname`.

### 5.6 Domain cache — keyed by `(domain, proof_type)`

Tuple cache key prevents v2/v3 cross-contamination on the same domain.

### 5.7 `_fetch_with_retry` + `_categorize_ssl_error` — required `error_label`

`error_label` becomes a required kwarg. `_fetch_with_retry` now returns
4-tuple with optional `error_category`.

### 5.8 Onionoo fetch — add `family_ids`

Extend `fields=` to include `family_ids`.

### 5.9 `calculate_statistics`

Adds `ciissversion_declared`, `ciissversion_validated`,
`v3_failure_categories`, `proof_types.no_proof.{no_aroi, ciissversion3_no_url}`.

### 5.10 `insights` subcommand

`aroi_cli.py insights [file]`. Plain text output. Reads saved JSON. Renders
human-readable migration guidance using `CATEGORY_INFO`.

### 5.11 `save_results` — `aroivalidator_schema_version: 2`

### 5.12 CLI flag plumbing

`--ciiss-versions`, env `CIISS_VERSIONS`, multiselect in interactive UI.
Precedence: flag > env > default.

### 5.13 `run_validation` / `ParallelAROIValidator`

Both accept `supported_ciissversions` kwarg.

### 5.14 README updates

Setup-from-scratch guide, v2→v3 migration guide, error reference
restructure, hint/category table, security notes about
`.secret_family_key`.

## 6. Files changed + LOC estimate

| File | Approx LOC |
|---|---|
| `aroi_validator.py` | +220 / −170 (≈ +50 net) |
| `aroi_cli.py` | +25 |
| `app.py` | +15 |
| `README.md` | +100 |
| `setup.py` / `pyproject.toml` / `uv.lock` | 0 |

## 7. Testing strategy

Inline dispatcher smoke test (no network), live v3 happy-path against
DFRI27, v2-only regression for byte-identical v2 errors, multi-ciissversion
batch + insights subcommand, rollover simulation, secret-key-leak smoke
test, CLI surface tests, interactive UI manual check, error-message audit.

## 8. Rollout & retirement

Adding ciissversion:4 = one row in `PROOF_SPECS`, append to tuple. No other
code. Retiring v2 = remove from `SUPPORTED_CIISSVERSIONS_DEFAULT`.

## 9. Out of scope

DNSSEC enforcement, informational v3 fields, bridge proofs, automated test
framework introduction.
