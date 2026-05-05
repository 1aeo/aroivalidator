# AROI Validator

A validation tool for Tor relay operator proofs (AROI — Authenticated Relay
Operator Identifier). Validates relay-operator domain claims via DNS or
HTTPS, supporting both **CIISS ContactInfo specification version 2** (RSA
fingerprint proofs) and **version 3** (ed25519 family-ID proofs). Queries
the Tor network's Onionoo API.

CIISS spec: <https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/>

## Quick Start

```bash
# Install dependencies and configure
python setup.py

# Run the application (default is interactive web UI)
python aroi_cli.py

# Or run specific modes
python aroi_cli.py interactive   # Web UI for validation
python aroi_cli.py batch         # Command-line batch processing
python aroi_cli.py viewer        # Web UI for viewing saved results
python aroi_cli.py insights      # Render ciissversion:2 → :3 migration summary

# Pick which CIISS versions to validate (default: 2,3)
python aroi_cli.py batch --ciiss-versions 2,3
python aroi_cli.py batch --ciiss-versions 3       # only ciissversion:3
CIISS_VERSIONS=2 python aroi_cli.py batch         # env-var fallback
```

Alternative for web UI only:
```bash
streamlit run app.py --server.port 5000
```

## Script Parameters

### aroi_cli.py
The main entry point for all operations. Accepts one mode parameter:
- `interactive` (default) — Launches the web UI for interactive validation
- `batch` — Runs automated validation with JSON output
- `viewer` — Opens the web-based results viewer
- `insights` — Renders a human-readable ciissversion:2 → ciissversion:3
  migration summary from a saved results JSON
  (default: `validation_results/latest.json`)

Flag (applies to interactive and batch modes):
- `--ciiss-versions <list>` — Comma-separated CIISS versions to validate.
  Default: `2,3`. Accepts a subset to filter validation
  (e.g. `--ciiss-versions 3` to validate only ciissversion:3 relays).
  Falls back to `CIISS_VERSIONS` env var when flag is absent.

Note: `app.py` contains the actual implementation but users should use
`aroi_cli.py` as the entry point.

### Batch Mode Environment Variables
Configure batch validation using environment variables:
- `BATCH_LIMIT` — Maximum number of relays to validate (default: 100, 0 = all)
- `PARALLEL` — Enable parallel processing: true/false (default: true)
- `MAX_WORKERS` — Number of worker threads (default: 10)
- `CIISS_VERSIONS` — Fallback for `--ciiss-versions` (CSV, e.g. `2,3`).
  Flag takes precedence over env var.

Example:
```bash
BATCH_LIMIT=500 MAX_WORKERS=20 python aroi_cli.py batch --ciiss-versions 2,3
```

## Features

- **Multi-version CIISS support**: Validates both ciissversion:2
  (RSA-fingerprint proofs) and ciissversion:3 (ed25519 family-ID proofs)
- **Web Interface**: Streamlit application for interactive relay validation
- **Command Line Tool**: CLI interface for batch processing
- **Parallel Processing**: Concurrent validation with ThreadPoolExecutor
- **Proof Types**: `dns-rsa`, `uri-rsa` (v2) and `dns-familyid-ed25519`,
  `uri-familyid-ed25519` (v3)
- **Operator Migration Guidance**: every ciissversion:3 failure carries an
  `error_category` tag and `hint` field pointing at the specific operator
  fix (which Tor command to run, which file to publish, which record to add)
- **Migration Insights**: `insights` subcommand renders an aggregate
  ciissversion:2 → ciissversion:3 migration breakdown grouped by root cause
- **Security**: detects accidentally-published `.secret_family_key` content
- **Result Tracking**: JSON output with timestamps in `validation_results/`

## Architecture

### Core Components

- **app.py** - Streamlit web UI for interactive validation
- **aroi_cli.py** - Command-line dispatcher for batch operations
- **aroi_validator.py** - Core validation engine with parallel processing

### Validation Flow

1. Fetch relay data from Onionoo API
2. **Filter out stale relays** (offline > 14 days) - workaround for Onionoo API bug
3. Extract AROI proof fields from relay contact info
4. Validate proofs via DNS TXT records or URI-based RSA
5. Calculate success rates by proof type
6. Save results as timestamped JSON

### Stale Relay Filtering

The validator automatically filters out relays that have been offline for more than 14 days. This works around an [Onionoo API bug](https://gitlab.torproject.org/tpo/network-health/metrics/onionoo/-/issues/40052) where ~244 relays offline for over a year are incorrectly returned despite documentation stating only relays from the past week are included.

**Impact**: Validates ~10,693 active relays instead of ~10,937 total relays in the API response.

### Data Storage

Results saved to `validation_results/` as JSON:
```json
{
  "metadata": {
    "timestamp": "ISO timestamp",
    "total_relays": int,
    "valid_relays": int,
    "success_rate": float
  },
  "statistics": { ... },
  "results": [ ... ]
}
```

## Dependencies

- **streamlit** - Web UI framework
- **dnspython** - DNS/DNSSEC validation
- **pandas** - Data manipulation
- **requests** - HTTP client
- **urllib3** - SSL/TLS handling

## Security Notes

### SSRF protection (Server-Side Request Forgery)

Relay `ContactInfo url:` is operator-provided and untrusted. The validator
fetches `https://<that-host>/.well-known/...` for v2 `uri-rsa` and v3
`uri-familyid-ed25519` proofs, so a malicious operator could otherwise
point us at internal infrastructure. Three-layer mitigation:

1. **IP-literal hostnames are rejected outright.** A relay that publishes
   `url:127.0.0.1` or `url:169.254.169.254` (cloud metadata IP) gets
   `error_category: unsafe_target` before any network connect.
2. **DNS-resolved addresses are checked.** The hostname is resolved
   (A and AAAA) and rejected if any returned address is in a
   loopback / private (RFC1918, RFC4193) / link-local / multicast /
   reserved / unspecified range.
3. **HTTP redirects are disabled** (`allow_redirects=False`). A 3xx
   response on the proof URI is treated as a proof failure with
   `error_category: redirect_disallowed`. CIISS spec also mandates
   "MUST NOT redirect to another domain".

Tests for these protections live in `tests/test_rollover_and_security.py`
(`test_ip_safety_classification`, `test_is_safe_public_host_*`,
`test_uri_validation_blocked_*`, `test_redirect_disallowed`). Run them with
`pytest` or directly via `python3 tests/test_rollover_and_security.py`.

There is a residual TOCTOU window between our pre-flight DNS check and
`requests`' own resolution. For threat models that require eliminating
this, a custom HTTPAdapter that pins the resolved IP would be needed
(out of scope today; the current mitigation catches the entire realistic
threat surface — a relay operator publishing a private/loopback URL).

### TLS/SSL Configuration

The validator uses configurable TLS settings to balance security with compatibility:

- **Minimum TLS Version**: TLS 1.2 (TLS 1.0/1.1 are deprecated and no longer supported)
- **Legacy Mode**: Relaxed cipher settings (SECLEVEL=1) available for older servers
- **Certificate Verification**: Disabled by default for relay operator domains (see below)

### Certificate Verification

Certificate verification is disabled by default when connecting to relay operator domains because:
1. Many Tor relay operators use self-signed certificates
2. Some have misconfigured TLS (expired certs, wrong hostnames)
3. The validator only fetches public proof files, not sensitive data

This is a deliberate security trade-off for this specific use case. The Onionoo API (torproject.org) connections always use proper TLS verification.

### Input Validation

- **File Operations**: All filenames are sanitized to prevent path traversal attacks
- **Environment Variables**: Batch mode validates and bounds all configuration values
- **Worker Limits**: Maximum 100 parallel workers to prevent resource exhaustion

### Logging

Security-relevant events are logged:
- Disabled certificate verification warnings
- Legacy TLS mode activation
- Invalid filename attempts (potential path traversal)
- JSON parsing errors

### Recommendations for Production Use

1. Run in a sandboxed environment if processing untrusted relay data
2. Monitor logs for security warnings
3. Consider enabling certificate verification if your target relays support it
4. Use appropriate network firewall rules to limit outbound connections

## Error Messages Reference

The validator produces standardized error messages categorized by proof type. Each error in the JSON output is paired with the relay's fingerprint.

### Missing Fields

| Error Message |
|---------------|
| `No contact information` |
| `Missing AROI fields: ciissversion, proof` |
| `Missing AROI fields: proof` |
| `Missing AROI fields: ciissversion` |
| `Missing AROI field: url, required for URI-RSA proof` |
| `Missing AROI field: url, required for DNS-RSA proof` |

### Unsupported/Invalid

| Error Message |
|---------------|
| `Unsupported ciissversion: <version>` |
| `Unsupported proof type: <type>` |
| `DNS-RSA: Invalid domain in url field: <url>` |
| `URI-RSA: Invalid domain in url field: <url>` |

### DNS-RSA Errors

| Error Message |
|---------------|
| `DNS-RSA: TXT record not found at <domain>` |
| `DNS-RSA: Lookup failed, no TXT record answer for <domain>` |
| `DNS-RSA: Lookup failed: <error>` |
| `DNS-RSA: TXT record has invalid proof content. Expected 'we-run-this-tor-relay', found: <content>` |

### URI-RSA: Fingerprint Not Found

| Error Message |
|---------------|
| `URI-RSA: Fingerprint not found at <domain>` |

### URI-RSA: HTTP Errors

| Error Message |
|---------------|
| `URI-RSA: HTTP error <code> for <domain> at URL: <URL>` |

### URI-RSA: HTTP SSL/TLS Errors

| Error Message |
|---------------|
| `URI-RSA: HTTP SSL handshake failure due to older version <version> for <domain> at URL: <URL>` |
| `URI-RSA: HTTP SSL handshake failure due to SSLv3 handshake for <domain> at URL: <URL>` |
| `URI-RSA: HTTP SSL error unexpected EOF for <domain> at URL: <URL>` |
| `URI-RSA: HTTP SSL certificate verification failed for <domain> at URL: <URL>` |
| `URI-RSA: HTTP SSL certificate expired on <date> for <domain> at URL: <URL>` |
| `URI-RSA: HTTP SSL certificate is self-signed (issuer: <issuer>) for <domain> at URL: <URL>` |
| `URI-RSA: HTTP SSL certificate chain contains self-signed cert (issuer: <issuer>) for <domain> at URL: <URL>` |
| `URI-RSA: HTTP SSL certificate chain incomplete for <domain> at URL: <URL>` |
| `URI-RSA: HTTP SSL unknown CA "<issuer>" for <domain> at URL: <URL>` |
| `URI-RSA: HTTP SSL hostname mismatch for remote <hosts> but expected <domain> at URL: <URL>` |
| `URI-RSA: HTTP SSL error <error> for <domain> at URL: <URL>` |

### URI-RSA: HTTP Name Resolution Errors

| Error Message |
|---------------|
| `URI-RSA: HTTP error name resolution failed for <domain> at URL: <URL>` |

### URI-RSA: HTTP Connection Errors

| Error Message |
|---------------|
| `URI-RSA: HTTP error connection timed out after 5s for URL: <URL>` |
| `URI-RSA: HTTP error connection refused for URL: <URL>` |
| `URI-RSA: HTTP error connection reset for URL: <URL>` |
| `URI-RSA: HTTP error connection max retries exceeded for URL: <URL>` |
| `URI-RSA: HTTP error connection remote end closed connection for URL: <URL>` |
| `URI-RSA: HTTP error <error> for URL: <URL>` |

### URI-RSA: Cached Domain Errors

When a domain has been tested multiple times and failed, subsequent requests use the cached result:

| Error Message |
|---------------|
| `URI-RSA: HTTP error connection timed out after 5s for URL: <URL>. Used domain cache after N attempts.` |
| `URI-RSA: HTTP error connection max retries exceeded for URL: <URL>. Used domain cache after N attempts.` |
| `URI-RSA: HTTP error <code> for <domain> at URL: <URL>. Used domain cache after N attempts.` |

### Other

| Error Message |
|---------------|
| `Validation exception: <error>` |

### ciissversion:3 Error Messages

For ciissversion:3 the proof prefix is `DNS-FamilyID:` or `URI-FamilyID:` (the
ed25519 family ID, not an RSA fingerprint, is being verified).

#### Missing AROI Fields (v3)

| Error Message | error_category |
|---|---|
| `Missing AROI fields: ciissversion` | (none) |
| `Missing AROI field: proof, required when url is set` | `missing_proof_field` |
| `Unsupported proof type: dns-rsa` (on a `ciissversion:3` relay) | `wrong_proof_type_rsa` |
| `Unsupported proof type: uri-rsa` (on a `ciissversion:3` relay) | `wrong_proof_type_rsa` |
| `Unsupported proof type: <other>` | (none) |
| `Unsupported ciissversion: <N> (supported: 2,3)` | `ciissversion_unsupported` |

#### DNS-FamilyID Errors

| Error Message | error_category |
|---|---|
| `DNS-FamilyID: Invalid domain in url field: <url>` | `invalid_url` |
| `DNS-FamilyID: Relay has no family_ids in Onionoo, cannot verify ciissversion:<N> proof` | `missing_family_ids` |
| `DNS-FamilyID: TXT record not found at <domain>` | `dns_txt_missing` |
| `DNS-FamilyID: Lookup failed, no TXT record answer for <domain>` | `dns_txt_missing` |
| `DNS-FamilyID: TXT record content does not match relay family_ids. Expected one of: <ids>, found: <records>` (`+ " (case mismatch detected — spec requires case-sensitive match)"` when applicable) | `dns_content_mismatch` |
| `DNS-FamilyID: Lookup failed: <error>` | `transport_error` |

#### URI-FamilyID Errors

| Error Message | error_category |
|---|---|
| `URI-FamilyID: Invalid domain in url field: <url>` | `invalid_url` |
| `URI-FamilyID: Relay has no family_ids in Onionoo, cannot verify ciissversion:<N> proof` | `missing_family_ids` |
| `URI-FamilyID: proof file not found at <domain> at URL: <url>` (HTTP 404) | `uri_file_missing` |
| `URI-FamilyID: family_id not found at <domain>` (`+ " (case mismatch detected — spec requires case-sensitive match)"` when applicable) | `uri_content_mismatch` |
| (HTTP/SSL transport errors — same templates as URI-RSA, with `URI-FamilyID:` prefix) | `transport_error` |

#### SSRF / Redirect Errors (URI proofs, both v2 and v3)

These prevent the validator from following untrusted redirects or
connecting to private/loopback addresses. Same templates apply to v2
(`URI-RSA:` prefix) and v3 (`URI-FamilyID:` prefix).

| Error Message | error_category |
|---|---|
| `<URI-RSA \| URI-FamilyID>: url is an IP literal, not a domain (SSRF-blocked: <ip>)` | `unsafe_target` |
| `<URI-RSA \| URI-FamilyID>: resolves to non-public address(es): <ip,...> (SSRF-blocked: <hostname>)` | `unsafe_target` |
| `<URI-RSA \| URI-FamilyID>: HTTP redirect (<3xx>) to <Location> for <domain> at URL: <url> — CIISS spec disallows redirects on proof URI` | `redirect_disallowed` |

#### Security

| Error Message | error_category |
|---|---|
| `SECURITY: DNS-FamilyID: published content appears to contain .secret_family_key. Rotate immediately.` | `secret_key_leaked` |
| `SECURITY: URI-FamilyID: published content appears to contain .secret_family_key. Rotate immediately.` | `secret_key_leaked` |

The validator detects accidentally-published `.secret_family_key` content
(>200 chars per line, or matching Tor key-file headers) and flags it as a
security incident. **Never publish `.secret_family_key`** — only the
43-character `.public_family_id` content goes in DNS or HTTP.

## Operator Guides (CIISS v3)

### Operator setup guide: building a ciissversion:3 AROI from scratch

**Starting state:** running one or more Tor relays with a plain `ContactInfo`
email/name. No AROI yet.

**Target state:** full ciissversion:3 AROI proving your domain via ed25519
family ID.

#### Prerequisites
- A domain you control (DNS path: must support DNSSEC; URI path: must serve
  HTTPS with a trusted CA cert).
- SSH/shell access to each relay.
- One secure host (admin laptop) where you'll generate and keep the family
  keys.

#### Step 1 — Generate the happy-family keypair (once, secure host)

```bash
tor --keygen-family /path/to/familykeys/myfamily
```

Back up `myfamily.secret_family_key` securely (treat like a PGP private
key). `myfamily.public_family_id` is the 43-character public string you'll
publish in DNS/HTTP.

#### Step 2 — Configure every relay to use the happy-family key

On each relay:
1. Copy `myfamily.secret_family_key` to Tor's key directory. Match
   permissions to other Tor key files (owner-read-only, same user as Tor).
2. Configure the happy-family directive in `torrc` to point at that key
   file (consult the current Tor manual for the exact directive name).
3. Do NOT set a manual `MyFamily` list — the happy-family key replaces it.
4. Restart Tor (`systemctl restart tor@default` or equivalent).

#### Step 3 — Wait for Onionoo to pick up `family_ids`

Typically < 24 hours. Verify with:

```bash
curl "https://onionoo.torproject.org/details?lookup=<fingerprint>&fields=family_ids" | jq
```

Do not proceed until you see `family_ids: ["<your-public_family_id>"]`.

#### Step 4 — Choose a proof path

- **DNS path** if your domain is DNSSEC-signed and you prefer one TXT
  record over an HTTPS endpoint.
- **URI path** if you serve HTTPS (or can run a static site) and DNSSEC
  isn't available.

Both paths are equally valid; pick one.

#### Step 5a — DNS path setup

Create one TXT record:
- **Name**: `we-run-this-tor-ed25519-family-id.<your-domain>`
- **Value**: contents of `myfamily.public_family_id` (43 chars,
  case-sensitive)

Verify:
```bash
dig TXT we-run-this-tor-ed25519-family-id.<your-domain> +dnssec +short
```

#### Step 5b — URI path setup

Create `/.well-known/tor-relay/ed25519-family-id.txt` containing one or
more public_family_ids (one per line, case-sensitive). Serve over HTTPS
with a trusted CA cert. **No redirects, no CAPTCHAs, no auth.**

If you use Cloudflare: add a Page Rule allowing
`/.well-known/tor-relay/*` unchallenged. This is the most common cause of
verification failure.

```bash
curl -v https://<your-domain>/.well-known/tor-relay/ed25519-family-id.txt
```

#### Step 6 — Update ContactInfo on every relay

Set the relay's torrc `ContactInfo` line to include at minimum:

```
# DNS path
<your normal contact text> url:<your-domain> proof:dns-familyid-ed25519 ciissversion:3

# OR URI path
<your normal contact text> url:<your-domain> proof:uri-familyid-ed25519 ciissversion:3
```

Same `url`, same `proof`, same `ciissversion:3` on every relay in the
family.

Restart Tor.

#### Step 7 — Verify

After ~24 hours:
```bash
python aroi_cli.py batch --ciiss-versions 3 2>&1 | grep <your-fingerprint>
```

Expect `Valid ✅` with `proof_type: dns-familyid-ed25519` (or
`uri-familyid-ed25519`).

If it fails, run:
```bash
python aroi_cli.py insights
```

The root-cause breakdown will tell you which step to revisit.

#### Ongoing maintenance

- **Adding a relay**: copy `secret_family_key`, configure torrc, restart,
  set ContactInfo to match. NO DNS / HTTP changes.
- **Removing a relay**: just decommission. NO DNS / HTTP changes.
- **Rotating the family key**: `tor --keygen-family <new-file>` on the
  secure host. Publish BOTH old and new public_family_ids during rollover
  (two TXT records, or two lines in the URI file). Once Onionoo shows the
  new family_id on all relays, drop the old one.
- **Never** commit `.secret_family_key` to version control or container
  images. Treat like an SSH private key.

### Operator migration guide: ciissversion:2 → ciissversion:3

**Starting state:** ciissversion:2 AROI working (`ciissversion:2 proof:dns-rsa
url:<domain>` or `proof:uri-rsa` equivalent).

**Target state:** `ciissversion:3 proof:dns-familyid-ed25519` (or
`uri-familyid-ed25519`) with one shared family-id proof instead of per-relay
RSA fingerprints.

1. **Generate the happy-family keypair** (Step 1 above; once per operator).
2. **Deploy `secret_family_key` to every relay** in the family.
3. **Update each relay's torrc**: replace any manual `MyFamily <fp1>,...`
   line with the happy-family directive pointing at the secret key file.
   Restart.
4. **Wait for Onionoo** to pick up `family_ids` on every relay (~1
   refresh cycle).
5. **Update `ContactInfo`** on every relay:
   - `ciissversion:2` → `ciissversion:3`
   - `proof:dns-rsa` → `proof:dns-familyid-ed25519` (DNS path), OR
   - `proof:uri-rsa` → `proof:uri-familyid-ed25519` (URI path)
   - Same `url:` value as before is fine.
6. **Publish the new proof**:
   - **DNS**: Delete old per-relay TXT records at `<rsa-fp>.<domain>`.
     Add the shared TXT at
     `we-run-this-tor-ed25519-family-id.<domain>`.
   - **URI**: Replace `/.well-known/tor-relay/rsa-fingerprint.txt` with
     `/.well-known/tor-relay/ed25519-family-id.txt`.
7. **Verify** with `python aroi_cli.py batch --ciiss-versions 3 ...` and
   `python aroi_cli.py insights`.

### How to interpret a failed ciissversion:3 validation

| Symptom | error_category | Operator fix |
|---|---|---|
| `... Relay has no family_ids in Onionoo, cannot verify ciissversion:3 proof` | `missing_family_ids` | Run `tor --keygen-family`, configure Tor's happy-family directive, restart, wait 1 Onionoo cycle |
| `Unsupported proof type: dns-rsa` (on v3 relay) | `wrong_proof_type_rsa` | Change ContactInfo `proof:` to `dns-familyid-ed25519` or `uri-familyid-ed25519`. If you meant to stay on v2, also keep `ciissversion:2`. |
| `DNS-FamilyID: TXT record not found at <domain>` | `dns_txt_missing` | Publish a TXT record at `we-run-this-tor-ed25519-family-id.<your-domain>` containing `.public_family_id` contents (43 chars, case-sensitive). DNSSEC required. |
| `URI-FamilyID: proof file not found at <domain> ...` (HTTP 404) | `uri_file_missing` | Publish `https://<your-domain>/.well-known/tor-relay/ed25519-family-id.txt`. HTTPS only, trusted CA, no redirects. |
| `... TXT record content does not match relay family_ids` | `dns_content_mismatch` | Confirm the TXT record contains `.public_family_id` content (NOT `.secret_family_key`). Case-sensitive. During key rollover, both old and new IDs may co-exist. |
| `URI-FamilyID: family_id not found at <domain>` | `uri_content_mismatch` | File exists but doesn't contain this relay's family_id. Check `.public_family_id` contents (case matters). |
| `Missing AROI field: proof, required when url is set` (v3) | `missing_proof_field` | With `ciissversion:3`, `proof` is mandatory whenever `url` is set. Add a v3 proof type or remove `url:`. |
| `SECURITY: ... published content appears to contain .secret_family_key. Rotate immediately.` | `secret_key_leaked` | **SECURITY INCIDENT.** Rotate the family key NOW with `tor --keygen-family <new-file>`, replace the published value with the new `.public_family_id`, update every relay's Tor config. |
| `... url is an IP literal, not a domain (SSRF-blocked: <ip>)` or `... resolves to non-public address(es): ...` | `unsafe_target` | The `url:` field must point at a publicly-routable domain (your operator website). IP literals and hostnames resolving to loopback / private (RFC1918, RFC4193) / link-local addresses are rejected as SSRF-unsafe. |
| `... HTTP redirect (<3xx>) to <location> ... CIISS spec disallows redirects on proof URI` | `redirect_disallowed` | The `.well-known` proof file must be served directly with no 3xx redirects. Remove redirects from the `/.well-known/tor-relay/` path on your webserver. |

To see all failures grouped by category for any saved batch run:

```bash
python aroi_cli.py insights
# or against a specific saved file:
python aroi_cli.py insights validation_results/aroi_validation_*.json
```

### Common gotchas during v2 → v3 migration

- **Onionoo lag**: ContactInfo changes propagate through the consensus and
  Onionoo on a ~daily cadence. Allow 24 hours after a torrc change before
  declaring failure.
- **Cloudflare**: blocks automated fetches by default. Add a Page Rule
  exempting `/.well-known/tor-relay/*` for the URI path.
- **Wrong file pasted**: never paste `.secret_family_key`. Always
  `.public_family_id`. The validator detects leaked secret keys and tags
  `secret_key_leaked`.
- **Case sensitivity**: ed25519 family IDs are 43-char case-sensitive.
  v2 RSA fingerprints were case-insensitive hex; the new strings are not.
  The validator emits a case-mismatch suffix on content-mismatch errors
  to help diagnose.
- **DNSSEC**: spec requires DNSSEC for the DNS path, but this validator
  does not currently enforce DNSSEC (gap exists for both v2 and v3).