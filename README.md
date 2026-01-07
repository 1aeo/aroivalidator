# AROI Validator

A validation tool for Tor relay operator proofs using the Accuracy, Relevance, Objectivity, and Informativeness (AROI) framework. Validates relay operator contact information through DNS and URI-based RSA proofs by querying the Tor network's Onionoo API.

## Quick Start

```bash
# Install dependencies and configure
python setup.py

# Run the application (default is interactive web UI)
python aroi_cli.py

# Or run specific modes
python aroi_cli.py interactive  # Web UI for validation
python aroi_cli.py batch        # Command-line batch processing  
python aroi_cli.py viewer       # Web UI for viewing results
```

Alternative for web UI only:
```bash
streamlit run app.py --server.port 5000
```

## Script Parameters

### aroi_cli.py
The main entry point for all operations. Accepts one mode parameter:
- `interactive` (default) - Launches the web UI for interactive validation
- `batch` - Runs automated validation with JSON output
- `viewer` - Opens the web-based results viewer

Note: `app.py` contains the actual implementation but users should use `aroi_cli.py` as the entry point.

### Batch Mode Environment Variables
Configure batch validation using environment variables:
- `BATCH_LIMIT` - Maximum number of relays to validate (default: 100, 0 = all)
- `PARALLEL` - Enable parallel processing: true/false (default: true)
- `MAX_WORKERS` - Number of worker threads (default: 10)

Example:
```bash
BATCH_LIMIT=500 MAX_WORKERS=20 python aroi_cli.py batch
```

## Features

- **Web Interface**: Streamlit application for interactive relay validation
- **Command Line Tool**: CLI interface for batch processing
- **Parallel Processing**: Concurrent validation with ThreadPoolExecutor
- **Proof Types**: Supports both dns-rsa and uri-rsa validation
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