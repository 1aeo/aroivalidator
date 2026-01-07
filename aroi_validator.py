"""
AROI Validator with Parallel Processing Support
Simplified and optimized version with parallel validation capability
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
from typing import Dict, Any, List, Optional, Callable
from urllib.parse import urlparse

import dns.resolver
import requests
import urllib3

# Suppress SSL warnings when certificate verification is disabled
# This is expected behavior for this tool - see Security Notes in README
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging for security events
logger = logging.getLogger(__name__)

# Pre-computed constants for filename validation
_ALLOWED_FILENAME_CHARS = frozenset(string.ascii_letters + string.digits + '._-')
_MAX_WORKERS_LIMIT = 100

# Default configuration constants (DRY - single source of truth)
DEFAULT_VERIFY_CERTIFICATES = True
DEFAULT_ALLOW_LEGACY_TLS = True
DEFAULT_MAX_RETRIES = 0  # No per-request retries - domain gets multiple attempts via cache
DEFAULT_TIMEOUT_SECONDS = 5  # 5s timeout per attempt
DEFAULT_DOMAIN_MAX_ATTEMPTS = 3  # Reduced from 10: 3 consecutive failures is enough to mark domain bad

# Proof type constants (DRY - avoid magic strings)
PROOF_TYPE_DNS_RSA = "dns-rsa"
PROOF_TYPE_URI_RSA = "uri-rsa"

# Connectivity error indicators (DRY - used for cache decisions)
_CONNECTIVITY_ERROR_PATTERNS = ('timed out', 'connection refused', 'connection reset', 'connection error')

# Pre-compiled regex patterns for AROI field parsing (efficiency)
_AROI_PATTERNS = {
    'ciissversion': re.compile(r'\bciissversion:(\S+)', re.IGNORECASE),
    'proof': re.compile(r'\bproof:(\S+)', re.IGNORECASE),
    'url': re.compile(r'\burl:(\S+)', re.IGNORECASE),
    'email': re.compile(r'\bemail:(\S+)', re.IGNORECASE),
}


class SecureTLSAdapter(requests.adapters.HTTPAdapter):
    """
    TLS adapter with configurable security settings.
    
    By default uses secure settings (TLS 1.2+, certificate verification).
    Can be configured for legacy server compatibility when explicitly needed.
    """
    
    def __init__(self, verify_certificates: bool = True, allow_legacy_tls: bool = False, **kwargs):
        """
        Initialize the TLS adapter.
        
        Args:
            verify_certificates: Whether to verify SSL certificates (default: True)
            allow_legacy_tls: Whether to use relaxed cipher settings (SECLEVEL=1) for 
                compatibility with older servers (default: False). Note: TLS 1.2 is
                always the minimum version regardless of this setting.
        """
        self.verify_certificates = verify_certificates
        self.allow_legacy_tls = allow_legacy_tls
        super().__init__(**kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        
        # Always use TLS 1.2 as minimum (TLS 1.0/1.1 are deprecated)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        
        if self.verify_certificates:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            logger.warning("SSL certificate verification disabled - vulnerable to MITM attacks")
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        
        if self.allow_legacy_tls:
            # SECLEVEL=1 allows older ciphers for compatibility with legacy servers
            # TLS 1.2 remains the minimum version for security
            ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)


class ParallelAROIValidator:
    """Simplified AROI validator with parallel processing support"""
    
    def __init__(
        self, 
        max_workers: int = 20,
        verify_certificates: bool = DEFAULT_VERIFY_CERTIFICATES,
        allow_legacy_tls: bool = DEFAULT_ALLOW_LEGACY_TLS
    ):
        """
        Initialize the validator.
        
        Args:
            max_workers: Maximum number of parallel workers
            verify_certificates: Whether to verify SSL certificates (default: False for 
                compatibility with self-signed certs on Tor relay operator domains)
            allow_legacy_tls: Whether to allow legacy TLS settings (default: True)
        
        Security Note: Certificate verification is disabled by default because many Tor
        relay operators use self-signed certificates or have misconfigured TLS. This is
        a known trade-off for this specific use case. The validator only fetches public
        proof files, not sensitive data.
        """
        # Validate and cap max_workers to prevent resource exhaustion
        if not isinstance(max_workers, int) or max_workers < 1:
            raise ValueError("max_workers must be a positive integer")
        if max_workers > _MAX_WORKERS_LIMIT:
            logger.warning(f"max_workers={max_workers} exceeds limit, capping to {_MAX_WORKERS_LIMIT}")
            max_workers = _MAX_WORKERS_LIMIT
        
        self.max_workers = max_workers
        self.verify_certificates = verify_certificates
        self.onionoo_url = "https://onionoo.torproject.org/details"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AROIValidator/1.0'
        })
        
        # Configure TLS adapter with explicit security settings
        tls_adapter = SecureTLSAdapter(
            verify_certificates=verify_certificates,
            allow_legacy_tls=allow_legacy_tls
        )
        self.session.mount('https://', tls_adapter)
        self.session.mount('http://', tls_adapter)
        
        # Thread-safe domain status cache with attempt tracking
        # Maps domain -> {'status': str, 'data': str|None, 'attempts': int, 'fingerprints': set|None}
        #   status='pending': one thread is testing, others wait
        #   status='retry': previous attempt failed, but attempts remain - next thread should try
        #   status='failed': all attempts exhausted, data=error message
        #   status='success': domain reachable, data=response text, fingerprints=parsed set
        self._domain_cache: Dict[str, Dict] = {}
        self._domain_cache_lock = threading.Lock()
        self._domain_conditions: Dict[str, threading.Condition] = {}
        self._domain_max_attempts = DEFAULT_DOMAIN_MAX_ATTEMPTS
    
    def _get_domain_status(self, domain: str) -> tuple:
        """
        Get domain status from cache, waiting if another thread is testing it.
        
        Returns:
            (status, data) tuple:
            - ('should_test', None): Caller should test this domain
            - ('failed', error_msg): Domain failed all attempts, use cached error
            - ('success', response_text): Domain succeeded, use cached response
        """
        with self._domain_cache_lock:
            if domain not in self._domain_cache:
                # First thread to test this domain - mark as pending
                self._domain_cache[domain] = {'status': 'pending', 'data': None, 'attempts': 0}
                self._domain_conditions[domain] = threading.Condition(self._domain_cache_lock)
                return ('should_test', None)
            
            cache_entry = self._domain_cache[domain]
            status = cache_entry['status']
            
            if status == 'pending':
                # Another thread is testing - wait for result (with timeout)
                condition = self._domain_conditions[domain]
                # Wait slightly longer than the network timeout to give tester a chance
                wait_success = condition.wait(timeout=DEFAULT_TIMEOUT_SECONDS + 1.0)
                
                if not wait_success:
                    # Timed out waiting for other thread - take over as tester
                    # This prevents one stuck thread from blocking everyone
                    logger.warning(f"Timeout waiting for domain check: {domain} - taking over")
                    self._domain_cache[domain]['status'] = 'pending'
                    return ('should_test', None)
                
                # Re-check status after waking
                cache_entry = self._domain_cache[domain]
                status = cache_entry['status']
                
                # If still pending (spurious wake or race), try testing ourselves
                if status == 'pending':
                     return ('should_test', None)
            
            if status == 'retry':
                # Previous attempt failed but we have attempts left - this thread should try
                self._domain_cache[domain]['status'] = 'pending'
                return ('should_test', None)
            
            # Return final status (success or failed)
            return (status, cache_entry['data'])
    
    def _set_domain_result(self, domain: str, success: bool, data: Optional[str]) -> None:
        """
        Record result of a domain test attempt.
        
        Args:
            domain: The domain that was tested
            success: Whether the request succeeded
            data: Response text (if success) or error message (if failure)
        """
        with self._domain_cache_lock:
            cache_entry = self._domain_cache.get(domain, {'attempts': 0})
            cache_entry['attempts'] += 1
            
            if success:
                cache_entry['status'] = 'success'
                cache_entry['data'] = data
                # Pre-parse fingerprint set for O(1) lookups (avoids re-parsing for each relay)
                cache_entry['fingerprints'] = self._parse_fingerprint_list(data) if data else set()
                logger.info(f"Domain cached as reachable: {domain}")
            elif cache_entry['attempts'] >= self._domain_max_attempts:
                # Exhausted all attempts - append cache suffix to error message
                cache_entry['status'] = 'failed'
                cache_entry['data'] = f"{data}. Used domain cache after {cache_entry['attempts']} attempts."
                logger.info(f"Domain cached as unreachable after {cache_entry['attempts']} attempts: {domain}")
            else:
                # Still have attempts left - mark as retry so next thread tries
                cache_entry['status'] = 'retry'
                cache_entry['data'] = data
                logger.debug(f"Domain attempt {cache_entry['attempts']}/{self._domain_max_attempts} failed: {domain}")
            
            self._domain_cache[domain] = cache_entry
            
            # Wake up waiting threads
            if domain in self._domain_conditions:
                self._domain_conditions[domain].notify_all()
    
    def clear_domain_cache(self) -> None:
        """Clear the domain cache (call before each validation run)."""
        with self._domain_cache_lock:
            self._domain_cache.clear()
            self._domain_conditions.clear()
        
    def fetch_relay_data(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Fetch relay data from Onionoo API and filter out stale relays.
        
        Filters out relays that have been offline for more than 14 days to work around
        Onionoo API bug: https://gitlab.torproject.org/tpo/network-health/metrics/onionoo/-/issues/40052
        """
        try:
            response = self.session.get(
                self.onionoo_url,
                params={'type': 'relay', 'fields': 'nickname,fingerprint,contact,running,last_seen'},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            relays = data.get('relays', [])
            
            # Filter out relays offline for more than 14 days
            filtered_relays = self._filter_active_relays(relays)
            
            return filtered_relays[:limit] if limit else filtered_relays
        except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
            logger.error(f"Error fetching relay data: {e}")
            return []
    
    def _filter_active_relays(self, relays: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter out relays that have been offline for more than 14 days.
        
        Workaround for Onionoo API bug where relays offline for over a year are returned
        despite documentation stating only relays from the past week are included.
        """
        cutoff_date = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=14)
        return [
            relay for relay in relays
            if relay.get('running', False) or self._is_recently_seen(relay, cutoff_date)
        ]
    
    def _is_recently_seen(self, relay: Dict[str, Any], cutoff_date: datetime) -> bool:
        """Check if a non-running relay was seen within the cutoff period."""
        last_seen_str = relay.get('last_seen')
        if not last_seen_str:
            return False
        try:
            last_seen = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
            return last_seen >= cutoff_date
        except ValueError:
            return False
    
    def validate_relay(self, relay: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a single relay's AROI proof"""
        result = {
            'nickname': relay.get('nickname', 'Unknown'),
            'fingerprint': relay.get('fingerprint', ''),
            'valid': False,
            'proof_type': None,
            'domain': None,
            'validation_steps': [],
            'error': None
        }
        
        contact = relay.get('contact', '')
        if not contact:
            result['error'] = "No contact information"
            return result
        
        # Parse AROI fields
        aroi_fields, missing_fields = self._parse_aroi_fields(contact)
        if not aroi_fields:
            result['error'] = f"Missing AROI fields: {', '.join(missing_fields)}"
            return result
        
        # Check ciissversion
        if aroi_fields.get('ciissversion') != '2':
            result['error'] = f"Unsupported ciissversion: {aroi_fields.get('ciissversion')}"
            return result
        
        # Validate based on proof type
        proof_type = aroi_fields.get('proof')
        if proof_type == PROOF_TYPE_DNS_RSA:
            result = self._validate_dns_rsa(relay, aroi_fields, result)
        elif proof_type == PROOF_TYPE_URI_RSA:
            result = self._validate_uri_rsa(relay, aroi_fields, result)
        else:
            result['error'] = f"Unsupported proof type: {proof_type}"
        
        return result
    
    def _parse_aroi_fields(self, contact: str) -> tuple:
        """
        Parse AROI fields from contact information.
        
        Returns:
            Tuple of (fields_dict or None, list of missing required field names)
        """
        fields = {}
        required_fields = ['ciissversion', 'proof']
        
        # Use pre-compiled patterns for efficiency
        for field, pattern in _AROI_PATTERNS.items():
            match = pattern.search(contact)
            if match:
                fields[field] = match.group(1)
        
        missing = [f for f in required_fields if f not in fields]
        
        if 'ciissversion' in fields and 'proof' in fields:
            return fields, missing
        return None, missing
    
    def _validate_dns_rsa(self, relay: Dict, aroi_fields: Dict, result: Dict) -> Dict:
        """Validate DNS-RSA proof"""
        url = aroi_fields.get('url')
        if not url:
            result['error'] = "Missing AROI field: url, required for DNS-RSA proof"
            return result
        
        # Extract domain
        domain = self._extract_domain(url)
        if not domain:
            result['error'] = f"DNS-RSA: Invalid domain in url field: {url}"
            return result
        
        result['proof_type'] = PROOF_TYPE_DNS_RSA
        result['domain'] = domain
        
        # Check domain cache status
        status, data = self._get_domain_status(domain)
        
        if status == 'failed':
            result['error'] = data  # Error already has cache suffix from _set_domain_result
            return result
        # Note: DNS-RSA doesn't benefit from 'success' caching since each relay
        # has a unique subdomain query. We still check for 'failed' to skip dead domains.
        
        # Construct DNS query domain
        fingerprint = relay['fingerprint'].lower()
        query_domain = f"{fingerprint}.{domain}"
        
        # Query DNS TXT record
        try:
            answers = dns.resolver.resolve(query_domain, 'TXT')
            txt_records = [str(rdata).strip('"') for rdata in answers]
            
            # DNS worked - mark domain as reachable (cache empty response, just marks as success)
            self._set_domain_result(domain, success=True, data="")
            
            # Validate proof
            if self._validate_proof_content(txt_records, relay['fingerprint']):
                result['valid'] = True
                result['validation_steps'].append({
                    'step': 'DNS TXT lookup',
                    'success': True,
                    'details': f"Found valid proof at {query_domain}"
                })
            else:
                # Show actual content found
                found_content = '; '.join(txt_records)[:100] if txt_records else 'empty'
                result['error'] = f"DNS-RSA: TXT record has invalid proof content. Expected 'we-run-this-tor-relay', found: {found_content}"
        except (dns.resolver.Timeout, dns.resolver.NoNameservers) as e:
            # Record DNS timeout/unreachable (counts toward domain's attempt limit)
            error_msg = f"DNS-RSA: Lookup failed: {str(e)}"
            self._set_domain_result(domain, success=False, data=error_msg)
            result['error'] = error_msg
        except dns.resolver.NXDOMAIN:
            # NXDOMAIN is expected for relays not in the list - don't count against domain
            result['error'] = f"DNS-RSA: TXT record not found at {domain}"
        except Exception as e:
            result['error'] = f"DNS-RSA: Lookup failed: {str(e)}"
        
        return result
    
    def _validate_uri_rsa(self, relay: Dict, aroi_fields: Dict, result: Dict) -> Dict:
        """Validate URI-RSA proof according to ContactInfo spec"""
        url = aroi_fields.get('url')
        if not url:
            result['error'] = "Missing AROI field: url, required for URI-RSA proof"
            return result
        
        # Normalize URL (ensure it has a scheme)
        url = self._normalize_url(url)
        
        # Extract base URL (scheme + domain only, no path)
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        domain = parsed.netloc
        
        # Validate domain before proceeding
        if not domain or '.' not in domain:
            result['error'] = f"URI-RSA: Invalid domain in url field: {aroi_fields.get('url')}"
            return result
        
        result['proof_type'] = PROOF_TYPE_URI_RSA
        result['domain'] = domain
        
        fingerprint = relay['fingerprint'].upper()
        
        # Check domain cache - this will wait if another thread is testing
        status, data = self._get_domain_status(domain)
        
        if status == 'failed':
            result['error'] = data  # Error already has cache suffix from _set_domain_result
            return result
        elif status == 'success':
            # Domain succeeded before - use cached fingerprint set for O(1) lookup
            with self._domain_cache_lock:
                cached_fingerprints = self._domain_cache[domain].get('fingerprints', set())
            
            if fingerprint in cached_fingerprints:
                result['valid'] = True
                result['validation_steps'].append({
                    'step': 'URI proof fetch (cached)',
                    'success': True,
                    'details': f"Found fingerprint in cached response for {domain}"
                })
                return result
            else:
                result['error'] = f"URI-RSA: Fingerprint not listed at {domain}"
                return result
        
        # status == 'should_test': We should test this domain
        # Try the primary URL first
        primary_url = f"{base_url}/.well-known/tor-relay/rsa-fingerprint.txt"
        response, error, attempts = self._fetch_with_retry(primary_url)
        
        if response:
            # Success! Cache the response for other relays using this domain
            self._set_domain_result(domain, success=True, data=response.text)
            
            # Optimization: Use the cached fingerprint set we just created
            with self._domain_cache_lock:
                cached_fingerprints = self._domain_cache[domain].get('fingerprints', set())
            
            if fingerprint in cached_fingerprints:
                result['valid'] = True
                result['validation_steps'].append({
                    'step': 'URI proof fetch',
                    'success': True,
                    'details': f"Found fingerprint in {primary_url}"
                })
                return result
            else:
                result['error'] = f"URI-RSA: Fingerprint not listed at {domain}"
                return result
        
        all_errors = [error]
        
        # Only try www variant if primary failed with HTTP error (not timeout/connection error)
        # If the domain itself is unreachable, www variant won't help
        is_connectivity_error = any(p in error.lower() for p in _CONNECTIVITY_ERROR_PATTERNS)
        
        if not is_connectivity_error and not parsed.netloc.startswith('www.'):
            www_url = f"{parsed.scheme}://www.{parsed.netloc}/.well-known/tor-relay/rsa-fingerprint.txt"
            response, error, attempts = self._fetch_with_retry(www_url)
            
            if response:
                self._set_domain_result(domain, success=True, data=response.text)
                
                # Optimization: Use the cached fingerprint set we just created
                with self._domain_cache_lock:
                    cached_fingerprints = self._domain_cache[domain].get('fingerprints', set())
                
                if fingerprint in cached_fingerprints:
                    result['valid'] = True
                    result['validation_steps'].append({
                        'step': 'URI proof fetch',
                        'success': True,
                        'details': f"Found fingerprint in {www_url}"
                    })
                    return result
                else:
                    result['error'] = f"URI-RSA: Fingerprint not listed at {domain}"
                    return result
            else:
                all_errors.append(error)
        
        # All URL variations failed - record this attempt (may allow more attempts)
        error_msg = "; ".join(all_errors) if all_errors else "Failed to fetch URI proof"
        self._set_domain_result(domain, success=False, data=all_errors[0] if all_errors else error_msg)
        result['error'] = error_msg
        return result
    
    def _parse_fingerprint_list(self, text: str) -> set:
        """Parse fingerprint list from response text into a set for O(1) lookups."""
        return {
            line.strip().upper()
            for line in text.split('\n')
            if line.strip() and not line.strip().startswith('#')
        }
    
    def _normalize_url(self, url: str) -> str:
        """
        Ensure URL has a scheme, defaulting to https.
        
        Args:
            url: The URL to normalize
            
        Returns:
            URL with scheme prefix
        """
        if not url.startswith(('http://', 'https://')):
            return 'https://' + url
        return url
    
    @staticmethod
    def _parse_cert_field(field_data: list) -> Dict[str, str]:
        """Parse certificate field (issuer/subject) into a flat dict. DRY helper."""
        result = {}
        for item in field_data:
            if isinstance(item, tuple):
                # Handle both ((key, val),) and (key, val) formats
                if len(item) == 2 and isinstance(item[0], str):
                    result[item[0]] = item[1]
                else:
                    for subitem in item:
                        if isinstance(subitem, tuple) and len(subitem) == 2:
                            result[subitem[0]] = subitem[1]
        return result
    
    def _get_ssl_cert_info(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Fetch SSL certificate details for detailed error messages.
        
        Returns dict with: expiration, issuer_name, hostnames, tls_version, etc.
        """
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
                    
                    # Parse expiration date
                    not_after = cert.get('notAfter', '')
                    try:
                        exp_str = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d')
                    except (ValueError, TypeError):
                        exp_str = not_after
                    
                    # Parse issuer and subject using shared helper
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
                        'tls_version': tls_version
                    }
        except (socket.error, ssl.SSLError, OSError) as e:
            return {'error': str(e)}
    
    def _fetch_with_retry(self, url: str, max_retries: int = DEFAULT_MAX_RETRIES) -> tuple:
        """
        Fetch URL with retry logic for transient failures.
        
        Args:
            url: The URL to fetch
            max_retries: Number of retries (default: 1)
            
        Returns:
            Tuple of (response or None, error_message, attempt_count)
        """
        max_attempts = max_retries + 1
        last_error = ""
        
        for attempt in range(1, max_attempts + 1):
            try:
                response = self.session.get(
                    url, 
                    timeout=DEFAULT_TIMEOUT_SECONDS, 
                    verify=self.verify_certificates
                )
                response.raise_for_status()
                return response, "", attempt
                
            except requests.exceptions.Timeout as e:
                last_error = f"URI-RSA: HTTP error connection timed out after {DEFAULT_TIMEOUT_SECONDS}s for URL: {url}"
                if attempt < max_attempts:
                    continue  # Retry
                    
            except requests.exceptions.ConnectionError as e:
                error_str = str(e).lower()
                if 'refused' in error_str:
                    last_error = f"URI-RSA: HTTP error connection refused for URL: {url}"
                    if attempt < max_attempts:
                        continue  # Retry
                elif 'reset' in error_str:
                    last_error = f"URI-RSA: HTTP error connection reset for URL: {url}"
                    if attempt < max_attempts:
                        continue  # Retry
                elif 'remotedisconnected' in error_str or 'remote end closed' in error_str:
                    last_error = f"URI-RSA: HTTP error connection remote end closed connection for URL: {url}"
                    break  # Don't retry
                elif 'max retries' in error_str or 'nameresolution' in error_str:
                    domain = urlparse(url).netloc
                    if 'nameresolution' in error_str:
                        last_error = f"URI-RSA: HTTP error name resolution failed for {domain} at URL: {url}"
                    else:
                        last_error = f"URI-RSA: HTTP error connection max retries exceeded for URL: {url}"
                    break  # Don't retry
                else:
                    last_error = f"URI-RSA: HTTP error connection max retries exceeded for URL: {url}"
                    break  # Don't retry other connection errors
                    
            except requests.exceptions.SSLError as e:
                last_error = self._categorize_ssl_error(str(e), url, attempt, max_attempts)
                break  # Don't retry SSL errors
                
            except requests.exceptions.HTTPError as e:
                domain = urlparse(url).netloc
                last_error = f"URI-RSA: HTTP error {e.response.status_code} for {domain} at URL: {url}"
                break  # Don't retry HTTP errors
                
            except Exception as e:
                last_error = f"URI-RSA: HTTP error {str(e)[:100]} for URL: {url}"
                break
        
        return None, last_error, attempt
    
    def _categorize_ssl_error(self, error_str: str, url: str, attempt: int = 1, max_attempts: int = 2) -> str:
        """
        Categorize SSL errors and return detailed, actionable error messages.
        
        Uses a table-driven approach for maintainability and readability.
        """
        parsed = urlparse(url)
        hostname = parsed.netloc
        error_lower = error_str.lower()
        
        # Lazy certificate info lookup - only fetch when needed
        cert_info_cache = {}
        def get_cert_info():
            if 'data' not in cert_info_cache:
                cert_info_cache['data'] = self._get_ssl_cert_info(hostname)
            return cert_info_cache['data']
        
        # Table-driven error pattern matching: (patterns, message_func)
        error_patterns = [
            # Connection errors (these still use old format as they're handled in _fetch_with_retry)
            (['timed out', 'timeout'],
             lambda: f"URI-RSA: HTTP error connection timed out after {DEFAULT_TIMEOUT_SECONDS}s for URL: {url}"),
            (['connection refused'],
             lambda: f"URI-RSA: HTTP error connection refused for URL: {url}"),
            (['connection reset'],
             lambda: f"URI-RSA: HTTP error connection reset for URL: {url}"),
            # SSL Certificate errors
            (['certificate verify failed'],
             lambda: f"URI-RSA: HTTP SSL certificate verification failed for {hostname} at URL: {url}"),
            (['certificate has expired', 'cert_has_expired'],
             lambda: f"URI-RSA: HTTP SSL certificate expired on {get_cert_info().get('expiration', 'unknown date')} for {hostname} at URL: {url}"),
            (['self signed certificate in certificate chain'],
             lambda: f"URI-RSA: HTTP SSL certificate chain contains self-signed cert (issuer: {get_cert_info().get('issuer_name', 'unknown')}) for {hostname} at URL: {url}"),
            (['self signed certificate', 'self_signed_cert'],
             lambda: f"URI-RSA: HTTP SSL certificate is self-signed (issuer: {get_cert_info().get('issuer_name', 'unknown')}) for {hostname} at URL: {url}"),
            (['unable to get local issuer'],
             lambda: f"URI-RSA: HTTP SSL certificate chain incomplete for {hostname} at URL: {url}"),
            (['unknown ca', 'unable to get issuer'],
             lambda: f"URI-RSA: HTTP SSL unknown CA \"{get_cert_info().get('issuer_name', 'unknown')}\" for {hostname} at URL: {url}"),
            # SSLv3 handshake failure (specific pattern)
            (['sslv3_alert_handshake_failure', 'sslv3 alert handshake'],
             lambda: f"URI-RSA: HTTP SSL handshake failure due to SSLv3 handshake for {hostname} at URL: {url}"),
            # General TLS handshake failure
            (['handshake failure', 'handshake_failure'],
             lambda: f"URI-RSA: HTTP SSL handshake failure due to older version {get_cert_info().get('tls_version', 'unknown')} for {hostname} at URL: {url}"),
            # Unexpected EOF
            (['unexpected_eof', 'unexpected eof'],
             lambda: f"URI-RSA: HTTP SSL error unexpected EOF for {hostname} at URL: {url}"),
        ]
        
        # Special case: hostname mismatch (requires compound check)
        if 'hostname' in error_lower and ('mismatch' in error_lower or "doesn't match" in error_lower):
            cert_hosts = get_cert_info().get('hostnames', ['unknown'])
            cert_hosts_str = ', '.join(cert_hosts) if cert_hosts else 'unknown'
            return f"URI-RSA: HTTP SSL hostname mismatch for remote {cert_hosts_str} but expected {hostname} at URL: {url}"
        
        # Match against pattern table
        for patterns, message_func in error_patterns:
            if any(p in error_lower for p in patterns):
                return message_func()
        
        # Generic fallback
        return f"URI-RSA: HTTP SSL error {error_str[:100]} for {hostname} at URL: {url}"
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """
        Extract domain from URL.
        
        Args:
            url: The URL to extract domain from
            
        Returns:
            Domain string or None if extraction fails
        """
        if not url or not isinstance(url, str):
            return None
        
        # Normalize URL (ensure it has a scheme)
        url = self._normalize_url(url)
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            # Basic domain validation
            if domain and '.' in domain:
                return domain
            return None
        except (ValueError, AttributeError) as e:
            logger.debug(f"Failed to extract domain from {url}: {e}")
            return None
    
    def _validate_proof_content(self, content_list: List[str], fingerprint: str) -> bool:
        """Validate DNS-RSA proof content according to ContactInfo spec v2"""
        # DNS-RSA requires "we-run-this-tor-relay" text
        expected_proof = "we-run-this-tor-relay"
        return any(expected_proof in content.lower() for content in content_list)
    
    def validate_parallel(
        self, 
        relays: Optional[List[Dict]] = None,
        limit: Optional[int] = None,
        progress_callback: Optional[Callable] = None,
        stop_check: Optional[Callable] = None
    ) -> List[Dict[str, Any]]:
        """
        Validate relays in parallel using thread pool
        
        Args:
            relays: List of relays to validate (fetches if None)
            limit: Maximum number of relays to validate
            progress_callback: Function to call with (current, total, result)
            stop_check: Function that returns True if validation should stop
        
        Returns:
            List of validation results
        """
        # Clear domain cache at start of each validation run
        self.clear_domain_cache()
        
        # Fetch relays if not provided
        if relays is None:
            relays = self.fetch_relay_data(limit)
        elif limit:
            relays = relays[:limit]
        
        total_relays = len(relays)
        results = []
        completed = 0
        
        # Use ThreadPoolExecutor for parallel validation
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all validation tasks
            future_to_relay = {
                executor.submit(self.validate_relay, relay): relay 
                for relay in relays
            }
            
            # Process completed tasks as they finish
            for future in concurrent.futures.as_completed(future_to_relay):
                # Check if we should stop
                if stop_check and stop_check():
                    # Cancel remaining futures
                    for f in future_to_relay:
                        f.cancel()
                    break
                
                relay = future_to_relay[future]
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1
                    
                    # Report progress
                    if progress_callback:
                        progress_callback(completed, total_relays, result)
                        
                except Exception as e:
                    # Handle validation error
                    error_result = {
                        'nickname': relay.get('nickname', 'Unknown'),
                        'fingerprint': relay.get('fingerprint', ''),
                        'valid': False,
                        'error': f"Validation exception: {str(e)}"
                    }
                    results.append(error_result)
                    completed += 1
                    
                    if progress_callback:
                        progress_callback(completed, total_relays, error_result)
        
        # Log summary of domain cache results (single pass)
        with self._domain_cache_lock:
            failed_count, success_count = 0, 0
            failed_details = []
            for domain, entry in self._domain_cache.items():
                if entry['status'] == 'failed':
                    failed_count += 1
                    failed_details.append((domain, entry.get('data', '')))
                elif entry['status'] == 'success':
                    success_count += 1
            if failed_count:
                logger.info(f"Domain cache: {failed_count} domains unreachable (after max attempts)")
                for domain, error in failed_details:
                    logger.debug(f"  - {domain}: {error[:80] if error else 'unknown error'}")
            if success_count:
                logger.info(f"Domain cache: {success_count} domains reachable and cached")
        
        return results


def run_validation(
    progress_callback: Optional[Callable] = None,
    stop_check: Optional[Callable] = None,
    limit: Optional[int] = None,
    parallel: bool = True,
    max_workers: int = 20,
    verify_certificates: bool = DEFAULT_VERIFY_CERTIFICATES,
    allow_legacy_tls: bool = DEFAULT_ALLOW_LEGACY_TLS
) -> List[Dict[str, Any]]:
    """
    Run AROI validation with optional parallel processing.
    
    Args:
        progress_callback: Function to call with (current, total, result)
        stop_check: Function that returns True if validation should stop
        limit: Maximum relays to validate (None for all)
        parallel: Whether to use parallel processing
        max_workers: Number of parallel workers (1-100, validated by ParallelAROIValidator)
        verify_certificates: Whether to verify SSL certificates
        allow_legacy_tls: Whether to allow legacy TLS settings
    
    Returns:
        List of validation results
    """
    # ParallelAROIValidator handles max_workers validation and capping
    validator = ParallelAROIValidator(
        max_workers=max_workers if parallel else 1,
        verify_certificates=verify_certificates,
        allow_legacy_tls=allow_legacy_tls
    )
    
    if parallel:
        logger.info(f"Using parallel validation with {validator.max_workers} workers")
        return validator.validate_parallel(
            limit=limit,
            progress_callback=progress_callback,
            stop_check=stop_check
        )
    
    # Sequential validation
    logger.info("Using sequential validation")
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
    """
    Convert validation results to a pandas DataFrame.
    
    Args:
        results: List of validation result dictionaries
        include_error: Whether to include the error column
        
    Returns:
        pandas DataFrame with formatted results
    """
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
            **(({'Error': r.get('error') or ''}) if include_error else {})
        }
        for r in results
    ]
    
    return pd.DataFrame(df_data, columns=columns)


def calculate_statistics(results: List[Dict]) -> Dict:
    """Calculate validation statistics in a single pass through results."""
    total_relays = len(results)
    valid_relays = 0
    
    # Counters for proof types: [total, valid]
    dns_rsa = [0, 0]
    uri_rsa = [0, 0]
    no_proof = 0
    
    # Single pass through results
    for r in results:
        is_valid = r.get('valid', False)
        if is_valid:
            valid_relays += 1
        
        proof_type = r.get('proof_type')
        if proof_type == PROOF_TYPE_DNS_RSA:
            dns_rsa[0] += 1
            if is_valid:
                dns_rsa[1] += 1
        elif proof_type == PROOF_TYPE_URI_RSA:
            uri_rsa[0] += 1
            if is_valid:
                uri_rsa[1] += 1
        else:
            no_proof += 1
    
    def calc_rate(valid: int, total: int) -> float:
        return (valid / total * 100) if total > 0 else 0.0
    
    return {
        'total_relays': total_relays,
        'valid_relays': valid_relays,
        'invalid_relays': total_relays - valid_relays,
        'success_rate': calc_rate(valid_relays, total_relays),
        'proof_types': {
            'dns_rsa': {
                'total': dns_rsa[0],
                'valid': dns_rsa[1],
                'success_rate': calc_rate(dns_rsa[1], dns_rsa[0])
            },
            'uri_rsa': {
                'total': uri_rsa[0],
                'valid': uri_rsa[1],
                'success_rate': calc_rate(uri_rsa[1], uri_rsa[0])
            },
            'no_proof': {
                'total': no_proof
            }
        }
    }


def save_results(results: List[Dict], filename: Optional[str] = None) -> Path:
    """
    Save validation results to JSON file.
    
    Args:
        results: List of validation results to save
        filename: Optional custom filename (will be sanitized)
        
    Returns:
        Path to the saved file
        
    Raises:
        ValueError: If the filename is invalid
        OSError: If the file cannot be written
    """
    results_dir = Path('validation_results').resolve()
    results_dir.mkdir(exist_ok=True)
    
    if filename is None:
        filename = f"aroi_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    else:
        filename = _sanitize_filename(filename)
    
    statistics = calculate_statistics(results)
    
    # Metadata is a subset of statistics plus timestamp (avoid duplication)
    output_data = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            **{k: statistics[k] for k in ('total_relays', 'valid_relays', 'invalid_relays', 'success_rate')}
        },
        'statistics': statistics,
        'results': results
    }
    
    # Write to both timestamped file and latest.json
    file_path = results_dir / filename
    json_content = json.dumps(output_data, indent=2)
    
    file_path.write_text(json_content)
    (results_dir / 'latest.json').write_text(json_content)
    
    return file_path


def _sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal attacks.
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        Sanitized filename with only the base name component
        
    Raises:
        ValueError: If the filename is invalid or empty after sanitization
    """
    if not filename:
        raise ValueError("Filename cannot be empty")
    
    # Get only the base name to prevent path traversal
    safe_name = Path(filename).name
    
    # Validate constraints
    if not safe_name.endswith('.json'):
        raise ValueError("Invalid filename: must end with .json")
    
    if safe_name.startswith('.'):
        raise ValueError("Invalid filename: hidden files not allowed")
    
    # Use pre-computed frozenset for O(1) character validation
    if not all(c in _ALLOWED_FILENAME_CHARS for c in safe_name):
        raise ValueError("Invalid filename: contains invalid characters")
    
    return safe_name


def load_results(filename: str = 'latest.json') -> Optional[Dict]:
    """
    Load validation results from JSON file.
    
    Args:
        filename: Name of the file to load (must be within validation_results directory)
        
    Returns:
        Parsed JSON data or None if file doesn't exist or is invalid
        
    Security:
        Filename is sanitized to prevent path traversal attacks.
    """
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
    """List all available result files"""
    results_dir = Path('validation_results')
    
    if not results_dir.exists():
        return []
    
    json_files = list(results_dir.glob('aroi_validation_*.json'))
    json_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    
    return json_files


if __name__ == "__main__":
    # Test parallel validation
    print("Testing Parallel AROI Validator")
    print("=" * 50)
    
    def progress_callback(current, total, result):
        status = "✓" if result['valid'] else "✗"
        print(f"[{current}/{total}] {status} {result.get('nickname', 'Unknown')}")
    
    # Test with 10 relays using parallel processing
    results = run_validation(
        progress_callback=progress_callback,
        limit=10,
        parallel=True,
        max_workers=5
    )
    
    stats = calculate_statistics(results)
    print("\n" + "=" * 50)
    print(f"Total: {stats['total_relays']}, Valid: {stats['valid_relays']} ({stats['success_rate']:.1f}%)")
