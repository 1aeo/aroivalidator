"""
AROI Validator with Parallel Processing Support
Supports CIISS ContactInfo specification versions 2 and 3.

CIISS spec: https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/
- ciissversion:2 — proof types: dns-rsa, uri-rsa (verifies relay RSA fingerprint)
- ciissversion:3 — proof types: dns-familyid-ed25519, uri-familyid-ed25519
                   (verifies operator's ed25519 family ID against relay.family_ids)
"""
import concurrent.futures
import json
import logging
import re
import socket
import ssl
import string
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Sequence, Tuple
from urllib.parse import urlparse

import dns.resolver
import requests
import urllib3

# Suppress SSL warnings when certificate verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Pre-computed constants for filename validation
_ALLOWED_FILENAME_CHARS = frozenset(string.ascii_letters + string.digits + '._-')
_MAX_WORKERS_LIMIT = 100

# Default configuration constants
DEFAULT_VERIFY_CERTIFICATES = True
DEFAULT_ALLOW_LEGACY_TLS = True
DEFAULT_MAX_RETRIES = 0
DEFAULT_TIMEOUT_SECONDS = 5
DEFAULT_DOMAIN_MAX_ATTEMPTS = 3

# aroivalidator output schema version. Bumped when we add stats keys, per-result
# fields, or change semantic shape. NOT a CIISS spec version.
AROIVALIDATOR_SCHEMA_VERSION = 2

# Proof type constants (existing, retained for backward compatibility)
PROOF_TYPE_DNS_RSA = "dns-rsa"
PROOF_TYPE_URI_RSA = "uri-rsa"
PROOF_TYPE_DNS_FAMILYID_ED25519 = "dns-familyid-ed25519"
PROOF_TYPE_URI_FAMILYID_ED25519 = "uri-familyid-ed25519"

# Connectivity error indicators (used for cache decisions)
_CONNECTIVITY_ERROR_PATTERNS = ('timed out', 'connection refused', 'connection reset', 'connection error')

# Pre-compiled regex patterns for AROI field parsing
_AROI_PATTERNS = {
    'ciissversion': re.compile(r'\bciissversion:(\S+)', re.IGNORECASE),
    'proof': re.compile(r'\bproof:(\S+)', re.IGNORECASE),
    'url': re.compile(r'\burl:(\S+)', re.IGNORECASE),
    'email': re.compile(r'\bemail:(\S+)', re.IGNORECASE),
}

# Tor secret key file header pattern. Used to detect operators who paste
# .secret_family_key contents instead of .public_family_id (security incident).
_SECRET_KEY_HEADER_RE = re.compile(r'ed25519.*(secret|private)', re.IGNORECASE)
_SECRET_KEY_LENGTH_THRESHOLD = 200  # public_family_id is 43 chars; anything >200 is suspicious


def _norm_family_ids(relay: Dict[str, Any]) -> set:
    """Normalize family_ids from Onionoo (strip whitespace, drop empties).
    Case is preserved — CIISS v3 spec mandates 43-char case-sensitive match."""
    return {s.strip() for s in (relay.get('family_ids') or []) if s and s.strip()}


def _looks_like_secret_key(content_lines: List[str]) -> bool:
    """Detect whether published proof content appears to contain .secret_family_key.

    Heuristic: any line >200 chars OR matching Tor key-file header pattern.
    A real public_family_id is exactly 43 chars; anything dramatically longer
    or containing the key-type header is the operator's secret material.
    """
    for line in content_lines:
        if not isinstance(line, str):
            continue
        if len(line) > _SECRET_KEY_LENGTH_THRESHOLD:
            return True
        if _SECRET_KEY_HEADER_RE.search(line):
            return True
    return False


# ============================================================================
# CATEGORY_INFO: single source of truth for error_category → operator guidance.
# Used by _finalize_hint (per-result hint) AND format_migration_insights
# (aggregate breakdown). Adding a category = one entry; retiring = one deletion.
# ============================================================================

CATEGORY_INFO: Dict[str, Dict[str, Optional[str]]] = {
    'missing_family_ids': {
        'hint': ("Run 'tor --keygen-family <file>' on the relay, configure "
                 "Tor's happy-family directive to use <file>.secret_family_key, "
                 "restart, and wait for Onionoo to refresh (typically < 24h)."),
        'title': "ciissversion:3 relays missing family_ids in Onionoo",
        'action': ("run 'tor --keygen-family', configure Tor, restart, "
                   "wait 1 Onionoo cycle"),
    },
    'dns_txt_missing': {
        'hint': ("Publish a TXT record at we-run-this-tor-ed25519-family-id."
                 "<your-domain> containing the contents of your "
                 ".public_family_id file (43 characters, case-sensitive). "
                 "DNSSEC is required by the spec."),
        'title': "ciissversion:3 DNS proofs with TXT record missing",
        'action': "publish we-run-this-tor-ed25519-family-id.<domain> TXT record",
    },
    'dns_content_mismatch': {
        'hint': ("The TXT record must contain the operator's public_family_id "
                 "(from 'tor --keygen-family'). Never publish the "
                 ".secret_family_key. During key rollover, both old and new "
                 "public_family_id values may co-exist in the TXT record."),
        'title': ("ciissversion:3 DNS proofs where TXT content doesn't match "
                  "family_ids"),
        'action': ("check TXT contains .public_family_id contents "
                   "(NOT .secret_family_key)"),
    },
    'uri_file_missing': {
        'hint': ("Publish https://<your-domain>/.well-known/tor-relay/"
                 "ed25519-family-id.txt containing your public_family_id "
                 "(43-char, case-sensitive). HTTPS only, trusted CA, "
                 "no redirects."),
        'title': "ciissversion:3 URI proofs with well-known file missing (404)",
        'action': "publish /.well-known/tor-relay/ed25519-family-id.txt",
    },
    'uri_content_mismatch': {
        'hint': ("File exists but does not contain this relay's family_id. "
                 "Confirm you pasted the contents of your .public_family_id "
                 "file (case matters). Never paste .secret_family_key."),
        'title': ("ciissversion:3 URI proofs where file content doesn't match "
                  "family_ids"),
        'action': ("check file contains .public_family_id contents "
                   "(NOT .secret_family_key)"),
    },
    'wrong_proof_type_rsa': {
        'hint': ("ciissversion:3 requires proof:dns-familyid-ed25519 or "
                 "proof:uri-familyid-ed25519. If you meant to stay on "
                 "ciissversion:2, also keep ciissversion:2 (not 3)."),
        'title': "ciissversion:3 relays declaring a ciissversion:2 proof type (dns-rsa/uri-rsa)",
        'action': ("change ContactInfo proof to dns-familyid-ed25519 or "
                   "uri-familyid-ed25519"),
    },
    'missing_proof_field': {
        'hint': ("With ciissversion:3, 'proof' is mandatory whenever 'url' "
                 "is set. Either add proof:dns-familyid-ed25519 or "
                 "proof:uri-familyid-ed25519, or remove the url field."),
        'title': "ciissversion:3 relays with 'url' set but 'proof' missing",
        'action': ("add proof:dns-familyid-ed25519 or "
                   "proof:uri-familyid-ed25519, or remove url"),
    },
    'invalid_url': {
        'hint': ("The url field is not a parseable domain. Set url to your "
                 "operator domain (with or without https:// prefix), e.g. "
                 "url:example.com"),
        'title': "ciissversion:3 relays with invalid url field",
        'action': "fix the url field in ContactInfo to be a valid domain",
    },
    'secret_key_leaked': {
        'hint': ("SECURITY INCIDENT: the published content looks like "
                 ".secret_family_key (Tor key header or >200 chars). "
                 "ROTATE the family key NOW with 'tor --keygen-family "
                 "<newfile>', replace the published value with the new "
                 ".public_family_id, and update every relay's Tor config."),
        'title': ("ciissversion:3 relays that appear to have published "
                  ".secret_family_key"),
        'action': ("SECURITY: rotate the family key IMMEDIATELY with "
                   "'tor --keygen-family <newfile>'"),
    },
    'ciissversion_unsupported': {
        'hint': None,  # error string already explains supported versions
        'title': "relays declaring a ciissversion not enabled by this run",
        'action': "(adjust --ciiss-versions, or operator should match supported list)",
    },
    'transport_error': {
        'hint': None,  # the transport-level error string already carries detail
        'title': "ciissversion:3 proofs failing due to network/TLS/HTTP errors",
        'action': "inspect the per-relay error for specifics (timeout, cert, etc.)",
    },
}


def _finalize_hint(result: dict) -> None:
    """Attach hint to result by error_category tag.
    Called at tail of validate_relay only for ciissversion:3 results."""
    cat = result.get('error_category')
    info = CATEGORY_INFO.get(cat) if cat else None
    if info and info.get('hint'):
        result['hint'] = info['hint']


# ============================================================================
# PROOF_SPECS: keyed by (ciissversion, proof_type). Single source of truth for
# proof-type behaviour. Adding a proof type = one entry. Retiring a version =
# remove that version's rows.
# ============================================================================

# Forward declaration; populated below the lambdas to keep them short.
PROOF_SPECS: Dict[Tuple[str, str], Dict[str, Any]] = {
    ('2', PROOF_TYPE_DNS_RSA): {
        'kind': 'dns', 'label': 'DNS-RSA',
        # v2 DNS query is per-relay: <rsa-fp>.<domain>
        'locator': lambda relay, domain: f"{relay['fingerprint'].lower()}.{domain}",
        'shared_proof': False,  # per-relay subdomain — cannot reuse success
        'expected_desc': "'we-run-this-tor-relay'",
        # content is List[str] of TXT records; substring match
        'matches': lambda content, relay: any(
            'we-run-this-tor-relay' in r.lower() for r in content),
    },
    ('2', PROOF_TYPE_URI_RSA): {
        'kind': 'uri', 'label': 'URI-RSA',
        'locator': lambda relay, domain: '/.well-known/tor-relay/rsa-fingerprint.txt',
        'shared_proof': True,  # one file lists all relays
        'expected_desc': 'relay RSA fingerprint',
        # content is str (response.text); RSA fingerprints are case-insensitive hex
        'matches': lambda content, relay: relay['fingerprint'].upper() in {
            l.strip().upper() for l in content.splitlines()
            if l.strip() and not l.strip().startswith('#')
        },
    },
    ('3', PROOF_TYPE_DNS_FAMILYID_ED25519): {
        'kind': 'dns', 'label': 'DNS-FamilyID',
        # v3 DNS query is shared across the family
        'locator': lambda relay, domain: f"we-run-this-tor-ed25519-family-id.{domain}",
        'shared_proof': True,
        'expected_desc': 'relay family_ids (43-char ed25519)',
        # content is List[str]; case-sensitive set intersection
        'matches': lambda content, relay: bool(
            {r.strip() for r in content if r.strip()}
            & _norm_family_ids(relay)),
    },
    ('3', PROOF_TYPE_URI_FAMILYID_ED25519): {
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

# What this build understands (data-driven from PROOF_SPECS).
ALL_KNOWN_CIISSVERSIONS = tuple(sorted({v for (v, _) in PROOF_SPECS}))
# What ships enabled by default. Ops can narrow with --ciiss-versions.
SUPPORTED_CIISSVERSIONS_DEFAULT = ('2', '3')


def parse_ciissversions_flag(s: str) -> Tuple[str, ...]:
    """Parse a comma-separated --ciiss-versions value into a validated tuple.

    Raises ValueError for empty input or unknown ciissversions.
    """
    parts = [p.strip() for p in (s or '').split(',') if p.strip()]
    if not parts:
        raise ValueError("--ciiss-versions must name at least one ciissversion")
    bad = [p for p in parts if p not in ALL_KNOWN_CIISSVERSIONS]
    if bad:
        raise ValueError(
            f"unknown ciissversion(s): {','.join(bad)} "
            f"(known: {','.join(ALL_KNOWN_CIISSVERSIONS)})"
        )
    return tuple(parts)


class SecureTLSAdapter(requests.adapters.HTTPAdapter):
    """TLS adapter with configurable security settings.

    By default uses secure settings (TLS 1.2+, certificate verification).
    Can be configured for legacy server compatibility when explicitly needed.
    """

    def __init__(self, verify_certificates: bool = True, allow_legacy_tls: bool = False, **kwargs):
        self.verify_certificates = verify_certificates
        self.allow_legacy_tls = allow_legacy_tls
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        if self.verify_certificates:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            logger.warning("SSL certificate verification disabled - vulnerable to MITM attacks")
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        if self.allow_legacy_tls:
            ctx.set_ciphers('DEFAULT@SECLEVEL=1')

        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)


class ParallelAROIValidator:
    """AROI validator with parallel processing and multi-ciissversion support."""

    def __init__(
        self,
        max_workers: int = 20,
        verify_certificates: bool = DEFAULT_VERIFY_CERTIFICATES,
        allow_legacy_tls: bool = DEFAULT_ALLOW_LEGACY_TLS,
        supported_ciissversions: Sequence[str] = SUPPORTED_CIISSVERSIONS_DEFAULT,
    ):
        if not isinstance(max_workers, int) or max_workers < 1:
            raise ValueError("max_workers must be a positive integer")
        if max_workers > _MAX_WORKERS_LIMIT:
            logger.warning(f"max_workers={max_workers} exceeds limit, capping to {_MAX_WORKERS_LIMIT}")
            max_workers = _MAX_WORKERS_LIMIT

        self.max_workers = max_workers
        self.verify_certificates = verify_certificates
        self._supported_ciissversions = tuple(str(v) for v in supported_ciissversions)
        self.onionoo_url = "https://onionoo.torproject.org/details"
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'AROIValidator/1.0'})

        tls_adapter = SecureTLSAdapter(
            verify_certificates=verify_certificates,
            allow_legacy_tls=allow_legacy_tls,
        )
        self.session.mount('https://', tls_adapter)
        self.session.mount('http://', tls_adapter)

        # Domain cache keyed by (domain, proof_type) tuple.
        # Per-proof-type so a domain serving a working DNS proof and a broken
        # URI proof (or vice versa) are tracked independently.
        # Entry shapes:
        #   {'status': 'pending'}                                   — being tested
        #   {'status': 'retry', 'error_msg': str, 'attempts': int}  — failed but retries left
        #   {'status': 'failed', 'error_msg': str,
        #    'error_category': str, 'attempts': int}                — exhausted
        #   {'status': 'success', 'raw': List[str]|str,
        #    'attempts': int}                                       — verified, content cached
        self._domain_cache: Dict[Tuple[str, str], Dict] = {}
        self._domain_cache_lock = threading.Lock()
        self._domain_conditions: Dict[Tuple[str, str], threading.Condition] = {}
        self._domain_max_attempts = DEFAULT_DOMAIN_MAX_ATTEMPTS

    # ------------------------------------------------------------------
    # Domain cache (keyed by (domain, proof_type))
    # ------------------------------------------------------------------

    def _get_domain_status(self, cache_key: Tuple[str, str]) -> tuple:
        """Get domain status from cache, waiting if another thread is testing it.

        Returns (status, payload):
            ('should_test', None): caller should test
            ('failed', dict): exhausted; payload has error_msg + error_category
            ('success', dict): verified; payload has raw content
        """
        with self._domain_cache_lock:
            if cache_key not in self._domain_cache:
                self._domain_cache[cache_key] = {'status': 'pending', 'attempts': 0}
                self._domain_conditions[cache_key] = threading.Condition(self._domain_cache_lock)
                return ('should_test', None)

            entry = self._domain_cache[cache_key]
            status = entry['status']

            if status == 'pending':
                condition = self._domain_conditions[cache_key]
                wait_success = condition.wait(timeout=DEFAULT_TIMEOUT_SECONDS + 1.0)
                if not wait_success:
                    logger.warning(f"Timeout waiting for cache entry {cache_key} - taking over")
                    self._domain_cache[cache_key]['status'] = 'pending'
                    return ('should_test', None)
                entry = self._domain_cache[cache_key]
                status = entry['status']
                if status == 'pending':
                    return ('should_test', None)

            if status == 'retry':
                self._domain_cache[cache_key]['status'] = 'pending'
                return ('should_test', None)

            return (status, entry)

    def _set_domain_result(
        self,
        cache_key: Tuple[str, str],
        success: bool,
        raw: Any = None,
        error_msg: Optional[str] = None,
        error_category: Optional[str] = None,
    ) -> None:
        """Record result of a domain test attempt."""
        with self._domain_cache_lock:
            entry = self._domain_cache.get(cache_key, {'attempts': 0})
            entry['attempts'] = entry.get('attempts', 0) + 1

            if success:
                entry['status'] = 'success'
                entry['raw'] = raw
                # Drop stale failure fields if any
                entry.pop('error_msg', None)
                entry.pop('error_category', None)
                logger.info(f"Domain proof cached as reachable: {cache_key}")
            elif entry['attempts'] >= self._domain_max_attempts:
                # Append cache suffix to error message (preserves existing wording)
                final_msg = (error_msg or 'unknown error')
                if 'Used domain cache after' not in final_msg:
                    final_msg = f"{final_msg}. Used domain cache after {entry['attempts']} attempts."
                entry['status'] = 'failed'
                entry['error_msg'] = final_msg
                entry['error_category'] = error_category or 'transport_error'
                logger.info(f"Domain proof cached as unreachable after {entry['attempts']} attempts: {cache_key}")
            else:
                entry['status'] = 'retry'
                entry['error_msg'] = error_msg
                entry['error_category'] = error_category
                logger.debug(f"Cache entry attempt {entry['attempts']}/{self._domain_max_attempts} failed: {cache_key}")

            self._domain_cache[cache_key] = entry

            if cache_key in self._domain_conditions:
                self._domain_conditions[cache_key].notify_all()

    def clear_domain_cache(self) -> None:
        """Clear the domain cache (call before each validation run)."""
        with self._domain_cache_lock:
            self._domain_cache.clear()
            self._domain_conditions.clear()

    # ------------------------------------------------------------------
    # Onionoo
    # ------------------------------------------------------------------

    def fetch_relay_data(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Fetch relay data from Onionoo and filter out stale relays.

        Includes `family_ids` (new for ciissversion:3) — Onionoo returns this
        only for relays whose Tor daemon has a happy-family key.
        """
        try:
            response = self.session.get(
                self.onionoo_url,
                params={
                    'type': 'relay',
                    'fields': 'nickname,fingerprint,contact,running,last_seen,family_ids',
                },
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            relays = data.get('relays', [])
            filtered_relays = self._filter_active_relays(relays)
            return filtered_relays[:limit] if limit else filtered_relays
        except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
            logger.error(f"Error fetching relay data: {e}")
            return []

    def _filter_active_relays(self, relays: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cutoff_date = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=14)
        return [
            relay for relay in relays
            if relay.get('running', False) or self._is_recently_seen(relay, cutoff_date)
        ]

    def _is_recently_seen(self, relay: Dict[str, Any], cutoff_date: datetime) -> bool:
        last_seen_str = relay.get('last_seen')
        if not last_seen_str:
            return False
        try:
            last_seen = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
            return last_seen >= cutoff_date
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Validation entry point — single dispatcher
    # ------------------------------------------------------------------

    def validate_relay(self, relay: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a single relay's AROI proof. Dispatches by ciissversion + proof type."""
        result = {
            'nickname': relay.get('nickname', 'Unknown'),
            'fingerprint': relay.get('fingerprint', ''),
            'valid': False,
            'proof_type': None,
            'domain': None,
            'validation_steps': [],
            'error': None,
        }

        contact = relay.get('contact', '')
        if not contact:
            result['error'] = "No contact information"
            return result

        aroi, _ = self._parse_aroi_fields(contact)

        # Row 1: missing ciissversion (required for any AROI claim)
        if 'ciissversion' not in aroi:
            missing = ['ciissversion']
            if 'proof' not in aroi:
                missing.append('proof')
            result['error'] = f"Missing AROI fields: {', '.join(missing)}"
            return result

        version = aroi['ciissversion']
        result['ciissversion'] = version  # used by stats + insights

        # Row 2: ciissversion not enabled by --ciiss-versions
        if version not in self._supported_ciissversions:
            result['error'] = (
                f"Unsupported ciissversion: {version} "
                f"(supported: {','.join(self._supported_ciissversions)})"
            )
            result['error_category'] = 'ciissversion_unsupported'
            return result

        has_url = bool(aroi.get('url'))
        proof_type = aroi.get('proof')

        # ciissversion-specific required-fields rules (matches §4 decision table)
        if version == '2':
            # Row 4: v2 with no proof
            if not proof_type:
                result['error'] = "Missing AROI fields: proof"
                return result
        elif version == '3':
            # Row 6: v3 with no url is spec-compliant, NOT an error.
            # CIISS v3 spec: `proof` is ignored when `url` is not set. An
            # operator may declare ciissversion:3 with informational fields
            # only (email, pgp, ...) and no domain claim. There's nothing to
            # verify; v3 has no "default proof type". Same shape as v2 no-AROI.
            if not has_url:
                return result
            # Row 7: v3 with url but no proof
            if not proof_type:
                result['error'] = "Missing AROI field: proof, required when url is set"
                result['error_category'] = 'missing_proof_field'
                _finalize_hint(result)
                return result

        # Spec lookup (rows 5, 8, 9)
        spec = PROOF_SPECS.get((version, proof_type))
        if spec is None:
            result['error'] = f"Unsupported proof type: {proof_type}"
            # Row 8: v3 declaring a v2 proof type — pin specific guidance
            if version == '3' and proof_type in (PROOF_TYPE_DNS_RSA, PROOF_TYPE_URI_RSA):
                result['error_category'] = 'wrong_proof_type_rsa'
                _finalize_hint(result)
            return result

        # Rows 10–18: dispatch to per-kind validator
        out = self._validate_kind(relay, aroi, result, spec)
        if version == '3':
            _finalize_hint(out)
        return out

    def _parse_aroi_fields(self, contact: str) -> Tuple[Dict[str, str], List[str]]:
        """Pure parser: extract recognized AROI fields from contact string.

        Returns (fields_dict, missing_list). `missing_list` is informational
        (kept for any callers that read it); validate_relay does its own
        ciissversion-aware required-field checks.
        """
        fields: Dict[str, str] = {}
        for field, pattern in _AROI_PATTERNS.items():
            match = pattern.search(contact)
            if match:
                fields[field] = match.group(1)
        # Spec: keys MUST appear only once; if duplicated only the first is
        # considered (re.search returns the first match). We honor that.
        missing = [f for f in ('ciissversion', 'proof') if f not in fields]
        return fields, missing

    # ------------------------------------------------------------------
    # Per-kind validator (DNS or URI), spec-driven
    # ------------------------------------------------------------------

    def _validate_kind(
        self,
        relay: Dict[str, Any],
        aroi: Dict[str, str],
        result: Dict[str, Any],
        spec: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generic per-kind validator. Branches on spec['kind'] for transport;
        all version-specific behavior is in spec callbacks."""
        label = spec['label']
        # Set proof_type early so invalid-domain rows still bucket correctly.
        result['proof_type'] = aroi['proof']

        url = aroi.get('url')
        domain = self._extract_domain(url)
        if not domain:
            result['error'] = f"{label}: Invalid domain in url field: {url}"
            result['error_category'] = 'invalid_url'
            return result

        version = aroi['ciissversion']
        # ciissversion:3+ requires family_ids from Onionoo. Derived rule (one
        # condition for all future non-v2 versions until a future spec proves
        # otherwise). Empty list and missing key both fall here via `or []`.
        if version != '2' and not relay.get('family_ids'):
            result['error'] = (
                f"{label}: Relay has no family_ids in Onionoo, "
                f"cannot verify ciissversion:{version} proof"
            )
            result['error_category'] = 'missing_family_ids'
            return result

        result['domain'] = domain

        cache_key = (domain, aroi['proof'])
        status, entry = self._get_domain_status(cache_key)
        if status == 'failed':
            result['error'] = entry.get('error_msg') or 'cached failure'
            result['error_category'] = entry.get('error_category') or 'transport_error'
            return result
        if status == 'success' and spec['shared_proof']:
            return self._finalize_match(
                result, spec, entry['raw'], relay, domain, cached=True
            )

        # Cache miss — actually fetch.
        if spec['kind'] == 'dns':
            return self._validate_dns_fetch(relay, aroi, result, spec, domain, cache_key)
        return self._validate_uri_fetch(relay, aroi, result, spec, url, domain, cache_key)

    def _validate_dns_fetch(self, relay, aroi, result, spec, domain, cache_key) -> Dict:
        """Fetch DNS TXT records and dispatch to _finalize_match."""
        label = spec['label']
        query_name = spec['locator'](relay, domain)
        try:
            answers = dns.resolver.resolve(query_name, 'TXT')
            # Multi-string TXT records: rdata.strings is tuple[bytes]; concatenate
            # before stripping. Matters for long v3 family_id rollover content.
            raw_records = [
                ''.join(
                    s.decode() if isinstance(s, bytes) else s
                    for s in rdata.strings
                ).strip()
                for rdata in answers
            ]
            self._set_domain_result(cache_key, success=True, raw=raw_records)
            return self._finalize_match(result, spec, raw_records, relay, domain, cached=False)
        except dns.resolver.NXDOMAIN:
            # NXDOMAIN: TXT name doesn't exist. For v2 dns-rsa this is just
            # "this relay isn't in the list" (per-relay subdomain). For v3
            # dns-familyid, this means the operator never published the
            # shared TXT — actionable error with hint.
            result['error'] = f"{label}: TXT record not found at {domain}"
            result['error_category'] = 'dns_txt_missing'
            return result
        except (dns.resolver.Timeout, dns.resolver.NoNameservers) as e:
            msg = f"{label}: Lookup failed: {e}"
            self._set_domain_result(
                cache_key, success=False,
                error_msg=msg, error_category='transport_error',
            )
            result['error'] = msg
            result['error_category'] = 'transport_error'
            return result
        except Exception as e:
            result['error'] = f"{label}: Lookup failed: {e}"
            result['error_category'] = 'transport_error'
            return result

    def _validate_uri_fetch(self, relay, aroi, result, spec, url, domain, cache_key) -> Dict:
        """Fetch URI proof via HTTPS (with www-fallback) and dispatch to _finalize_match."""
        label = spec['label']
        path = spec['locator'](relay, domain)
        # Force HTTPS for .well-known fetches regardless of operator's url:
        # scheme. CIISS spec requires HTTPS. Use parsed.hostname (port-stripped,
        # lowercase) to avoid `:8443` appearing in the fetch URL.
        primary_url = f"https://{domain}{path}"

        response, error_msg, error_category, attempts = self._fetch_with_retry(
            primary_url, error_label=label
        )
        if response is not None:
            self._set_domain_result(cache_key, success=True, raw=response.text)
            return self._finalize_match(
                result, spec, response.text, relay, domain, cached=False
            )

        all_errors = [error_msg]
        # www fallback only for HTTP-level errors, not connectivity errors.
        is_connectivity = any(p in error_msg.lower() for p in _CONNECTIVITY_ERROR_PATTERNS)
        if not is_connectivity and not domain.startswith('www.'):
            www_url = f"https://www.{domain}{path}"
            response2, err2, cat2, _ = self._fetch_with_retry(www_url, error_label=label)
            if response2 is not None:
                self._set_domain_result(cache_key, success=True, raw=response2.text)
                return self._finalize_match(
                    result, spec, response2.text, relay, domain, cached=False
                )
            all_errors.append(err2)

        # All variants failed.
        combined_msg = "; ".join(e for e in all_errors if e) or "Failed to fetch URI proof"
        self._set_domain_result(
            cache_key, success=False,
            error_msg=all_errors[0] if all_errors else combined_msg,
            error_category=error_category,
        )
        result['error'] = combined_msg
        result['error_category'] = error_category or 'transport_error'
        return result

    # ------------------------------------------------------------------
    # _finalize_match: secret-key sniff + match + content-mismatch error
    # ------------------------------------------------------------------

    def _finalize_match(
        self,
        result: Dict[str, Any],
        spec: Dict[str, Any],
        content: Any,
        relay: Dict[str, Any],
        domain: str,
        cached: bool,
    ) -> Dict[str, Any]:
        """Run secret-key sniff, then spec['matches']; on miss produce a
        kind- and version-appropriate not-found error with category tag."""
        label = spec['label']
        version = result.get('ciissversion') or '2'

        # Secret-key sniff (security-protective; runs for both v2 and v3, but
        # only v3 can credibly leak a family secret_family_key. Cheap to run.)
        if version == '3':
            content_lines = content if isinstance(content, list) else (
                content.splitlines() if isinstance(content, str) else []
            )
            if _looks_like_secret_key(content_lines):
                result['error'] = (
                    f"SECURITY: {label}: published content appears to "
                    f"contain .secret_family_key. Rotate immediately."
                )
                result['error_category'] = 'secret_key_leaked'
                return result

        if spec['matches'](content, relay):
            result['valid'] = True
            step = 'cached' if cached else 'fetched'
            result['validation_steps'].append({
                'step': f"{label} proof matched ({step})",
                'success': True,
                'details': f"Content matched for {domain}",
            })
            return result

        # Mismatch — produce a kind+version-appropriate error.
        if spec['kind'] == 'dns':
            found_summary = '; '.join(content)[:100] if content else 'empty'
            if version == '2':
                result['error'] = (
                    f"{label}: TXT record has invalid proof content. "
                    f"Expected {spec['expected_desc']}, found: {found_summary}"
                )
            else:
                # v3: report relay's family_ids alongside found records
                expected_ids = ', '.join(sorted(_norm_family_ids(relay))) or '(none)'
                result['error'] = (
                    f"{label}: TXT record content does not match relay family_ids. "
                    f"Expected one of: {expected_ids}, found: {found_summary}"
                )
                # Diagnostic: case-mismatch suffix when content matches family_ids
                # only by case-insensitive comparison.
                if self._case_mismatch_only(content, relay, kind='dns'):
                    result['error'] += " (case mismatch detected — spec requires case-sensitive match)"
            result['error_category'] = 'dns_content_mismatch'
        else:  # 'uri'
            if version == '2':
                # Preserve existing v2 wording byte-for-byte
                result['error'] = f"{label}: Fingerprint not found at {domain}"
            else:
                result['error'] = f"{label}: family_id not found at {domain}"
                if self._case_mismatch_only(content, relay, kind='uri'):
                    result['error'] += " (case mismatch detected — spec requires case-sensitive match)"
            result['error_category'] = 'uri_content_mismatch'
        return result

    @staticmethod
    def _case_mismatch_only(content: Any, relay: Dict[str, Any], kind: str) -> bool:
        """Return True if content matches family_ids case-insensitively but not
        case-sensitively. Diagnostic for v3 content-mismatch errors."""
        relay_fids = _norm_family_ids(relay)
        if not relay_fids:
            return False
        if kind == 'dns':
            tokens = {r.strip() for r in (content or []) if r.strip()}
        else:
            tokens = {
                l.strip() for l in (content or '').splitlines()
                if l.strip() and not l.strip().startswith('#')
            }
        if tokens & relay_fids:
            return False  # exact match exists → not a case mismatch
        ci_tokens = {t.lower() for t in tokens}
        ci_fids = {f.lower() for f in relay_fids}
        return bool(ci_tokens & ci_fids)

    # ------------------------------------------------------------------
    # URL parsing helpers
    # ------------------------------------------------------------------

    def _normalize_url(self, url: str) -> str:
        """Ensure URL has a scheme (default https)."""
        if not url.startswith(('http://', 'https://')):
            return 'https://' + url
        return url

    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract hostname (port-stripped, lowercase) from a url-ish string."""
        if not url or not isinstance(url, str):
            return None
        url = self._normalize_url(url)
        try:
            parsed = urlparse(url)
            # parsed.hostname strips port and lowercases.
            domain = parsed.hostname
            if not domain:
                # Fallback: take first path segment if netloc was empty
                domain = parsed.path.split('/')[0].split(':')[0].lower() if parsed.path else None
            if domain and '.' in domain:
                return domain
            return None
        except (ValueError, AttributeError) as e:
            logger.debug(f"Failed to extract domain from {url}: {e}")
            return None

    # ------------------------------------------------------------------
    # HTTP retry + SSL error categorization (parameterized by error_label)
    # ------------------------------------------------------------------

    def _fetch_with_retry(
        self,
        url: str,
        error_label: str,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> Tuple[Optional[requests.Response], str, Optional[str], int]:
        """Fetch URL with retry logic. Returns (response, error_msg, error_category, attempts).

        error_label is required (e.g. 'URI-RSA' for v2, 'URI-FamilyID' for v3).
        v3 HTTP 404 is rendered as 'proof file not found' with category
        'uri_file_missing' — different from generic '404 for' wording.
        """
        max_attempts = max_retries + 1
        last_error = ""
        last_category: Optional[str] = None
        attempt = 1

        for attempt in range(1, max_attempts + 1):
            try:
                response = self.session.get(
                    url,
                    timeout=DEFAULT_TIMEOUT_SECONDS,
                    verify=self.verify_certificates,
                )
                response.raise_for_status()
                return response, "", None, attempt

            except requests.exceptions.Timeout:
                last_error = f"{error_label}: HTTP error connection timed out after {DEFAULT_TIMEOUT_SECONDS}s for URL: {url}"
                last_category = 'transport_error'
                if attempt < max_attempts:
                    continue

            except requests.exceptions.ConnectionError as e:
                error_str = str(e).lower()
                last_category = 'transport_error'
                if 'refused' in error_str:
                    last_error = f"{error_label}: HTTP error connection refused for URL: {url}"
                    if attempt < max_attempts:
                        continue
                elif 'reset' in error_str:
                    last_error = f"{error_label}: HTTP error connection reset for URL: {url}"
                    if attempt < max_attempts:
                        continue
                elif 'remotedisconnected' in error_str or 'remote end closed' in error_str:
                    last_error = f"{error_label}: HTTP error connection remote end closed connection for URL: {url}"
                    break
                elif 'max retries' in error_str or 'nameresolution' in error_str:
                    domain = urlparse(url).hostname or ''
                    if 'nameresolution' in error_str:
                        last_error = f"{error_label}: HTTP error name resolution failed for {domain} at URL: {url}"
                    else:
                        last_error = f"{error_label}: HTTP error connection max retries exceeded for URL: {url}"
                    break
                else:
                    last_error = f"{error_label}: HTTP error connection max retries exceeded for URL: {url}"
                    break

            except requests.exceptions.SSLError as e:
                last_error = self._categorize_ssl_error(str(e), url, error_label, attempt, max_attempts)
                last_category = 'transport_error'
                break

            except requests.exceptions.HTTPError as e:
                domain = urlparse(url).hostname or ''
                status = e.response.status_code if e.response is not None else 0
                # v3 special case: 404 on the well-known proof file is the
                # most actionable failure (operator never published the file).
                if status == 404 and error_label == 'URI-FamilyID':
                    last_error = f"{error_label}: proof file not found at {domain} at URL: {url}"
                    last_category = 'uri_file_missing'
                else:
                    last_error = f"{error_label}: HTTP error {status} for {domain} at URL: {url}"
                    last_category = 'transport_error'
                break

            except Exception as e:
                last_error = f"{error_label}: HTTP error {str(e)[:100]} for URL: {url}"
                last_category = 'transport_error'
                break

        return None, last_error, last_category, attempt

    def _categorize_ssl_error(
        self,
        error_str: str,
        url: str,
        error_label: str,
        attempt: int = 1,
        max_attempts: int = 2,
    ) -> str:
        """Categorize SSL errors and return detailed, actionable error messages."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        error_lower = error_str.lower()

        cert_info_cache: Dict[str, Any] = {}

        def get_cert_info():
            if 'data' not in cert_info_cache:
                cert_info_cache['data'] = self._get_ssl_cert_info(hostname)
            return cert_info_cache['data']

        # (patterns, message_func) table
        error_patterns = [
            (['timed out', 'timeout'],
             lambda: f"{error_label}: HTTP error connection timed out after {DEFAULT_TIMEOUT_SECONDS}s for URL: {url}"),
            (['connection refused'],
             lambda: f"{error_label}: HTTP error connection refused for URL: {url}"),
            (['connection reset'],
             lambda: f"{error_label}: HTTP error connection reset for URL: {url}"),
            (['certificate verify failed'],
             lambda: f"{error_label}: HTTP SSL certificate verification failed for {hostname} at URL: {url}"),
            (['certificate has expired', 'cert_has_expired'],
             lambda: f"{error_label}: HTTP SSL certificate expired on {get_cert_info().get('expiration', 'unknown date')} for {hostname} at URL: {url}"),
            (['self signed certificate in certificate chain'],
             lambda: f"{error_label}: HTTP SSL certificate chain contains self-signed cert (issuer: {get_cert_info().get('issuer_name', 'unknown')}) for {hostname} at URL: {url}"),
            (['self signed certificate', 'self_signed_cert'],
             lambda: f"{error_label}: HTTP SSL certificate is self-signed (issuer: {get_cert_info().get('issuer_name', 'unknown')}) for {hostname} at URL: {url}"),
            (['unable to get local issuer'],
             lambda: f"{error_label}: HTTP SSL certificate chain incomplete for {hostname} at URL: {url}"),
            (['unknown ca', 'unable to get issuer'],
             lambda: f"{error_label}: HTTP SSL unknown CA \"{get_cert_info().get('issuer_name', 'unknown')}\" for {hostname} at URL: {url}"),
            (['sslv3_alert_handshake_failure', 'sslv3 alert handshake'],
             lambda: f"{error_label}: HTTP SSL handshake failure due to SSLv3 handshake for {hostname} at URL: {url}"),
            (['handshake failure', 'handshake_failure'],
             lambda: f"{error_label}: HTTP SSL handshake failure due to older version {get_cert_info().get('tls_version', 'unknown')} for {hostname} at URL: {url}"),
            (['unexpected_eof', 'unexpected eof'],
             lambda: f"{error_label}: HTTP SSL error unexpected EOF for {hostname} at URL: {url}"),
        ]

        if 'hostname' in error_lower and ('mismatch' in error_lower or "doesn't match" in error_lower):
            cert_hosts = get_cert_info().get('hostnames', ['unknown'])
            cert_hosts_str = ', '.join(cert_hosts) if cert_hosts else 'unknown'
            return f"{error_label}: HTTP SSL hostname mismatch for remote {cert_hosts_str} but expected {hostname} at URL: {url}"

        for patterns, message_func in error_patterns:
            if any(p in error_lower for p in patterns):
                return message_func()

        return f"{error_label}: HTTP SSL error {error_str[:100]} for {hostname} at URL: {url}"

    @staticmethod
    def _parse_cert_field(field_data: list) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for item in field_data:
            if isinstance(item, tuple):
                if len(item) == 2 and isinstance(item[0], str):
                    result[item[0]] = item[1]
                else:
                    for subitem in item:
                        if isinstance(subitem, tuple) and len(subitem) == 2:
                            result[subitem[0]] = subitem[1]
        return result

    def _get_ssl_cert_info(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    tls_version = ssock.version()

                    if not cert:
                        return {'tls_version': tls_version}

                    not_after = cert.get('notAfter', '')
                    try:
                        exp_str = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d')
                    except (ValueError, TypeError):
                        exp_str = not_after

                    issuer = self._parse_cert_field(cert.get('issuer', []))
                    subject = self._parse_cert_field(cert.get('subject', []))

                    issuer_cn = issuer.get('commonName', '')
                    issuer_org = issuer.get('organizationName', '')
                    cn = subject.get('commonName', '')
                    san = [x[1] for x in cert.get('subjectAltName', []) if x[0] == 'DNS']

                    return {
                        'expiration': exp_str,
                        'issuer_name': issuer_cn or issuer_org or 'Unknown',
                        'common_name': cn,
                        'subject_alt_names': san,
                        'hostnames': list(set([cn] + san)) if cn else san,
                        'tls_version': tls_version,
                    }
        except (socket.error, ssl.SSLError, OSError) as e:
            return {'error': str(e)}

    # ------------------------------------------------------------------
    # Parallel orchestration
    # ------------------------------------------------------------------

    def validate_parallel(
        self,
        relays: Optional[List[Dict]] = None,
        limit: Optional[int] = None,
        progress_callback: Optional[Callable] = None,
        stop_check: Optional[Callable] = None,
    ) -> List[Dict[str, Any]]:
        """Validate relays in parallel using thread pool."""
        self.clear_domain_cache()

        if relays is None:
            relays = self.fetch_relay_data(limit)
        elif limit:
            relays = relays[:limit]

        total_relays = len(relays)
        results: List[Dict[str, Any]] = []
        completed = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_relay = {
                executor.submit(self.validate_relay, relay): relay
                for relay in relays
            }

            for future in concurrent.futures.as_completed(future_to_relay):
                if stop_check and stop_check():
                    for f in future_to_relay:
                        f.cancel()
                    break

                relay = future_to_relay[future]
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total_relays, result)
                except Exception as e:
                    error_result = {
                        'nickname': relay.get('nickname', 'Unknown'),
                        'fingerprint': relay.get('fingerprint', ''),
                        'valid': False,
                        'error': f"Validation exception: {str(e)}",
                    }
                    results.append(error_result)
                    completed += 1
                    if progress_callback:
                        progress_callback(completed, total_relays, error_result)

        # Cache summary
        with self._domain_cache_lock:
            failed_count, success_count = 0, 0
            for cache_key, entry in self._domain_cache.items():
                if entry['status'] == 'failed':
                    failed_count += 1
                elif entry['status'] == 'success':
                    success_count += 1
            if failed_count:
                logger.info(f"Domain cache: {failed_count} (domain,proof) entries unreachable")
            if success_count:
                logger.info(f"Domain cache: {success_count} (domain,proof) entries cached")

        return results


# ============================================================================
# Module-level entry points (used by CLI/UI)
# ============================================================================

def run_validation(
    progress_callback: Optional[Callable] = None,
    stop_check: Optional[Callable] = None,
    limit: Optional[int] = None,
    parallel: bool = True,
    max_workers: int = 20,
    verify_certificates: bool = DEFAULT_VERIFY_CERTIFICATES,
    allow_legacy_tls: bool = DEFAULT_ALLOW_LEGACY_TLS,
    supported_ciissversions: Sequence[str] = SUPPORTED_CIISSVERSIONS_DEFAULT,
) -> List[Dict[str, Any]]:
    """Run AROI validation with optional parallel processing."""
    validator = ParallelAROIValidator(
        max_workers=max_workers if parallel else 1,
        verify_certificates=verify_certificates,
        allow_legacy_tls=allow_legacy_tls,
        supported_ciissversions=supported_ciissversions,
    )

    if parallel:
        logger.info(
            f"Using parallel validation with {validator.max_workers} workers, "
            f"ciissversions={','.join(validator._supported_ciissversions)}"
        )
        return validator.validate_parallel(
            limit=limit,
            progress_callback=progress_callback,
            stop_check=stop_check,
        )

    logger.info(
        f"Using sequential validation, ciissversions={','.join(validator._supported_ciissversions)}"
    )
    relays = validator.fetch_relay_data(limit)
    results = []
    total = len(relays)
    for idx, relay in enumerate(relays, 1):
        if stop_check and stop_check():
            break
        result = validator.validate_relay(relay)
        results.append(result)
        if progress_callback:
            progress_callback(idx, total, result)
    return results


def results_to_dataframe(results: list, include_error: bool = False) -> "pd.DataFrame":
    """Convert validation results to a pandas DataFrame."""
    import pandas as pd

    columns = ['Nickname', 'Fingerprint', 'Valid', 'Proof Type', 'Domain']
    if include_error:
        columns.append('Error')

    df_data = [
        {
            'Nickname': r.get('nickname', 'Unknown'),
            'Fingerprint': r.get('fingerprint', ''),
            'Valid': '✅' if r.get('valid') else '❌',
            'Proof Type': r.get('proof_type') or 'None',
            'Domain': r.get('domain') or 'N/A',
            **(({'Error': r.get('error') or ''}) if include_error else {}),
        }
        for r in results
    ]

    return pd.DataFrame(df_data, columns=columns)


# ============================================================================
# Statistics
# ============================================================================

def calculate_statistics(results: List[Dict]) -> Dict:
    """Calculate validation statistics in a single pass through results."""
    total_relays = len(results)
    valid_relays = 0

    # Per-proof-type counters: proof_type_str -> [total, valid]
    proof_counters: Dict[str, List[int]] = {}
    no_proof_total = 0
    no_aroi = 0  # no ciissversion at all
    ciissv3_no_url = 0  # ciissversion:3 with informational fields only

    # ciissversion distribution counters
    declared: Dict[str, int] = {}  # what relays declared in ContactInfo
    validated: Dict[str, int] = {}  # what this run actually validated (had spec lookup)
    filtered_out = 0

    # v3 failure category tally
    v3_failure_categories: Dict[str, int] = {k: 0 for k in CATEGORY_INFO.keys()}

    for r in results:
        is_valid = r.get('valid', False)
        if is_valid:
            valid_relays += 1

        proof_type = r.get('proof_type')
        if proof_type:
            key = proof_type.replace('-', '_')
            counter = proof_counters.setdefault(key, [0, 0])
            counter[0] += 1
            if is_valid:
                counter[1] += 1
        else:
            no_proof_total += 1
            if r.get('ciissversion') == '3':
                ciissv3_no_url += 1
            else:
                no_aroi += 1

        # ciissversion distribution
        version = r.get('ciissversion')
        if version is None:
            declared['none'] = declared.get('none', 0) + 1
        else:
            declared[version] = declared.get(version, 0) + 1

        # validated bucket: only counts when we actually had a spec to apply or
        # made a definitive ciissversion-aware decision (any relay where
        # validate_relay reached past the version-supported check).
        if r.get('error_category') == 'ciissversion_unsupported':
            filtered_out += 1
        elif version is None:
            validated['none'] = validated.get('none', 0) + 1
        else:
            validated[version] = validated.get(version, 0) + 1

        # v3 failure categories: count any v3 result with an error_category.
        if version == '3':
            cat = r.get('error_category')
            if cat and cat in v3_failure_categories:
                v3_failure_categories[cat] += 1

    def calc_rate(valid: int, total: int) -> float:
        return (valid / total * 100) if total > 0 else 0.0

    proof_types_block: Dict[str, Dict[str, Any]] = {
        key: {
            'total': counts[0],
            'valid': counts[1],
            'success_rate': calc_rate(counts[1], counts[0]),
        }
        for key, counts in proof_counters.items()
    }
    # Ensure legacy v2 keys are always present for back-compat consumers.
    for legacy_key in ('dns_rsa', 'uri_rsa'):
        proof_types_block.setdefault(legacy_key, {'total': 0, 'valid': 0, 'success_rate': 0.0})

    proof_types_block['no_proof'] = {
        'total': no_proof_total,
        'no_aroi': no_aroi,
        'ciissversion3_no_url': ciissv3_no_url,
    }

    return {
        'total_relays': total_relays,
        'valid_relays': valid_relays,
        'invalid_relays': total_relays - valid_relays,
        'success_rate': calc_rate(valid_relays, total_relays),
        'proof_types': proof_types_block,
        'ciissversion_declared': declared,
        'ciissversion_validated': {**validated, 'filtered_out': filtered_out},
        'v3_failure_categories': v3_failure_categories,
    }


# ============================================================================
# Migration insights formatter (used by `aroi_cli.py insights`)
# ============================================================================

def format_migration_insights(stats: Dict, results: List[Dict]) -> str:
    """Render a human-readable ciissversion:2 → ciissversion:3 migration summary."""
    lines: List[str] = []

    declared = stats.get('ciissversion_declared', {}) or {}
    declared_total = sum(declared.values()) or 1
    lines.append("=== ciissversion declared by relays (in Onionoo) ===")
    for v in sorted(declared.keys()):
        label = f"ciissversion:{v}" if v != 'none' else "none"
        lines.append(f"  {label:<22} {declared[v]:>6} relays  ({declared[v] / declared_total * 100:5.1f}%)")

    validated = stats.get('ciissversion_validated', {}) or {}
    if validated:
        lines.append("")
        lines.append("=== ciissversion validated by this run ===")
        for v in sorted(k for k in validated if k != 'filtered_out'):
            label = f"ciissversion:{v}" if v != 'none' else "none"
            lines.append(f"  {label:<22} {validated[v]:>6} relays  validated")
        if validated.get('filtered_out'):
            lines.append(f"  {'(filtered out)':<22} {validated['filtered_out']:>6} relays  skipped by --ciiss-versions")

    proof_types = stats.get('proof_types', {}) or {}
    v3_proof_keys = [k for k in proof_types if 'familyid' in k]
    if v3_proof_keys:
        lines.append("")
        lines.append("=== ciissversion:3 validity breakdown ===")
        for k in sorted(v3_proof_keys):
            info = proof_types[k]
            lines.append(
                f"  {k:<26} {info['total']:>6} relays  "
                f"{info['valid']:>4} valid ({info['success_rate']:5.1f}%)"
            )

    cats = stats.get('v3_failure_categories', {}) or {}
    actionable = sorted(
        ((k, v) for k, v in cats.items() if v > 0 and k != 'transport_error' and k != 'ciissversion_unsupported'),
        key=lambda kv: -kv[1],
    )
    if actionable:
        lines.append("")
        lines.append("=== ciissversion:3 failure root causes (actionable) ===")
        for cat, count in actionable:
            info = CATEGORY_INFO.get(cat, {})
            title = info.get('title') or cat
            action = info.get('action') or "(see error detail)"
            lines.append(f"  {count:>4}  {title}")
            lines.append(f"        → {action}")

    if cats.get('transport_error'):
        lines.append("")
        lines.append(
            f"  {cats['transport_error']:>4}  ciissversion:3 proofs failing due to network/TLS/HTTP errors"
        )
        lines.append("        → inspect per-relay error for specifics (timeout, cert, etc.)")

    valid_v2 = sum(
        1 for r in results
        if r.get('ciissversion') == '2' and r.get('valid')
    )
    if valid_v2:
        lines.append("")
        lines.append("=== ciissversion:2 → ciissversion:3 upgrade candidates ===")
        lines.append(
            f"  {valid_v2} ciissversion:2 relays are currently valid — "
            "these operators can migrate cleanly when ready"
        )

    leaked = cats.get('secret_key_leaked', 0)
    lines.append("")
    if leaked == 0:
        lines.append("(!) 0 relays appear to have leaked .secret_family_key. Good.")
    else:
        lines.append(
            f"(!!) {leaked} relays appear to have leaked .secret_family_key. "
            "Investigate immediately and notify operators."
        )

    return "\n".join(lines)


# ============================================================================
# Persistence
# ============================================================================

def save_results(results: List[Dict], filename: Optional[str] = None) -> Path:
    """Save validation results to JSON file."""
    results_dir = Path('validation_results').resolve()
    results_dir.mkdir(exist_ok=True)

    if filename is None:
        filename = f"aroi_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    else:
        filename = _sanitize_filename(filename)

    statistics = calculate_statistics(results)

    output_data = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'aroivalidator_schema_version': AROIVALIDATOR_SCHEMA_VERSION,
            **{k: statistics[k] for k in ('total_relays', 'valid_relays', 'invalid_relays', 'success_rate')},
        },
        'statistics': statistics,
        'results': results,
    }

    file_path = results_dir / filename
    json_content = json.dumps(output_data, indent=2)

    file_path.write_text(json_content)
    (results_dir / 'latest.json').write_text(json_content)

    return file_path


def _sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal attacks."""
    if not filename:
        raise ValueError("Filename cannot be empty")

    safe_name = Path(filename).name
    if not safe_name.endswith('.json'):
        raise ValueError("Invalid filename: must end with .json")
    if safe_name.startswith('.'):
        raise ValueError("Invalid filename: hidden files not allowed")
    if not all(c in _ALLOWED_FILENAME_CHARS for c in safe_name):
        raise ValueError("Invalid filename: contains invalid characters")
    return safe_name


def load_results(filename: str = 'latest.json') -> Optional[Dict]:
    """Load validation results from JSON file."""
    try:
        safe_filename = _sanitize_filename(filename)
    except ValueError as e:
        logger.warning(f"Invalid filename rejected: {filename} - {e}")
        return None

    file_path = Path('validation_results').resolve() / safe_filename

    if not file_path.exists():
        return None

    try:
        return json.loads(file_path.read_text())
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {safe_filename}: {e}")
        return None
    except OSError as e:
        logger.error(f"Error reading {safe_filename}: {e}")
        return None


def list_result_files() -> List[Path]:
    """List all available result files."""
    results_dir = Path('validation_results')
    if not results_dir.exists():
        return []
    json_files = list(results_dir.glob('aroi_validation_*.json'))
    json_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return json_files


if __name__ == "__main__":
    print("Testing Parallel AROI Validator (CIISS v2 + v3)")
    print("=" * 50)

    def progress_callback(current, total, result):
        status = "✓" if result['valid'] else "✗"
        print(f"[{current}/{total}] {status} {result.get('nickname', 'Unknown')}")

    results = run_validation(
        progress_callback=progress_callback,
        limit=10,
        parallel=True,
        max_workers=5,
    )

    stats = calculate_statistics(results)
    print("\n" + "=" * 50)
    print(f"Total: {stats['total_relays']}, Valid: {stats['valid_relays']} ({stats['success_rate']:.1f}%)")
