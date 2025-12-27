"""
AROI Validator with Parallel Processing Support
Simplified and optimized version with parallel validation capability
"""
import concurrent.futures
import json
import logging
import re
import ssl
import string
from datetime import datetime, timedelta
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
        max_workers: int = 10,
        verify_certificates: bool = False,
        allow_legacy_tls: bool = True
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
        except Exception as e:
            print(f"Error fetching relay data: {e}")
            return []
    
    def _filter_active_relays(self, relays: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter out relays that have been offline for more than 14 days.
        
        Workaround for Onionoo API bug where relays offline for over a year are returned
        despite documentation stating only relays from the past week are included.
        """
        cutoff_date = datetime.utcnow() - timedelta(days=14)
        active_relays = []
        
        for relay in relays:
            # If relay is running, include it
            if relay.get('running', False):
                active_relays.append(relay)
                continue
            
            # If relay is not running, check last_seen
            last_seen_str = relay.get('last_seen')
            if last_seen_str:
                try:
                    # Parse timestamp: "2025-11-22 16:00:00"
                    last_seen = datetime.strptime(last_seen_str, '%Y-%m-%d %H:%M:%S')
                    
                    # Include relay if it was seen within the last 14 days
                    if last_seen >= cutoff_date:
                        active_relays.append(relay)
                except ValueError:
                    # If we can't parse the timestamp, exclude it for safety
                    continue
            # If no last_seen field, exclude the relay
        
        return active_relays
    
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
        aroi_fields = self._parse_aroi_fields(contact)
        if not aroi_fields:
            result['error'] = "Missing AROI fields"
            return result
        
        # Check ciissversion
        if aroi_fields.get('ciissversion') != '2':
            result['error'] = f"Unsupported ciissversion: {aroi_fields.get('ciissversion')}"
            return result
        
        # Validate based on proof type
        proof_type = aroi_fields.get('proof')
        if proof_type == 'dns-rsa':
            result = self._validate_dns_rsa(relay, aroi_fields, result)
        elif proof_type == 'uri-rsa':
            result = self._validate_uri_rsa(relay, aroi_fields, result)
        else:
            result['error'] = f"Unsupported proof type: {proof_type}"
        
        return result
    
    def _parse_aroi_fields(self, contact: str) -> Optional[Dict[str, str]]:
        """Parse AROI fields from contact information"""
        fields = {}
        patterns = {
            'ciissversion': r'\bciissversion:(\S+)',
            'proof': r'\bproof:(\S+)',
            'url': r'\burl:(\S+)',
            'email': r'\bemail:(\S+)'
        }
        
        for field, pattern in patterns.items():
            match = re.search(pattern, contact, re.IGNORECASE)
            if match:
                fields[field] = match.group(1)
        
        return fields if 'ciissversion' in fields and 'proof' in fields else None
    
    def _validate_dns_rsa(self, relay: Dict, aroi_fields: Dict, result: Dict) -> Dict:
        """Validate DNS-RSA proof"""
        url = aroi_fields.get('url')
        if not url:
            result['error'] = "Missing URL for dns-rsa proof"
            return result
        
        # Extract domain
        domain = self._extract_domain(url)
        if not domain:
            result['error'] = "Invalid URL for DNS lookup"
            return result
        
        result['proof_type'] = 'dns-rsa'
        result['domain'] = domain
        
        # Construct DNS query domain
        fingerprint = relay['fingerprint'].lower()
        query_domain = f"{fingerprint}.{domain}"
        
        # Query DNS TXT record
        try:
            answers = dns.resolver.resolve(query_domain, 'TXT')
            txt_records = [str(rdata).strip('"') for rdata in answers]
            
            # Validate proof
            if self._validate_proof_content(txt_records, relay['fingerprint']):
                result['valid'] = True
                result['validation_steps'].append({
                    'step': 'DNS TXT lookup',
                    'success': True,
                    'details': f"Found valid proof at {query_domain}"
                })
            else:
                result['error'] = "Invalid proof content in DNS TXT record"
        except Exception as e:
            result['error'] = f"DNS lookup failed: {str(e)}"
        
        return result
    
    def _validate_uri_rsa(self, relay: Dict, aroi_fields: Dict, result: Dict) -> Dict:
        """Validate URI-RSA proof according to ContactInfo spec"""
        url = aroi_fields.get('url')
        if not url:
            result['error'] = "Missing URL for uri-rsa proof"
            return result
        
        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Extract base URL (scheme + domain only, no path)
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        result['proof_type'] = 'uri-rsa'
        result['domain'] = parsed.netloc
        
        # Try multiple URL variations
        urls_to_try = []
        
        # Original URL
        urls_to_try.append(f"{base_url}/.well-known/tor-relay/rsa-fingerprint.txt")
        
        # Try with www prefix if not already present
        if not parsed.netloc.startswith('www.'):
            www_base = f"{parsed.scheme}://www.{parsed.netloc}"
            urls_to_try.append(f"{www_base}/.well-known/tor-relay/rsa-fingerprint.txt")
        
        fingerprint = relay['fingerprint'].upper()
        all_errors = []
        
        for proof_url in urls_to_try:
            try:
                # Use session's configured TLS settings (adapter handles SSL context)
                response = self.session.get(
                    proof_url, 
                    timeout=10, 
                    verify=self.verify_certificates
                )
                response.raise_for_status()
                
                # Check if fingerprint is listed in the file
                if self._check_fingerprint_in_response(response.text, fingerprint):
                    result['valid'] = True
                    result['validation_steps'].append({
                        'step': 'URI proof fetch',
                        'success': True,
                        'details': f"Found fingerprint in {proof_url}"
                    })
                    return result
                else:
                    all_errors.append(f"Fingerprint not found in {proof_url}")
                    
            except requests.exceptions.HTTPError as e:
                # Handle HTTP errors (403, 404, etc.)
                all_errors.append(f"{e.response.status_code} {e.response.reason} for {proof_url}")
                
            except Exception as e:
                all_errors.append(f"Failed to fetch {proof_url}: {str(e)}")
        
        # If we get here, all attempts failed - show all errors
        if len(all_errors) > 1:
            result['error'] = "; ".join(all_errors)
        elif all_errors:
            result['error'] = all_errors[0]
        else:
            result['error'] = "Failed to fetch URI proof"
        return result
    
    def _check_fingerprint_in_response(self, text: str, fingerprint: str) -> bool:
        """Check if fingerprint exists in response text using O(1) set lookup."""
        # Build set of valid fingerprints (excluding comments and empty lines)
        valid_fingerprints = {
            line.strip().upper()
            for line in text.split('\n')
            if line.strip() and not line.strip().startswith('#')
        }
        return fingerprint in valid_fingerprints
    
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
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
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
        
        return results


def run_validation(
    progress_callback: Optional[Callable] = None,
    stop_check: Optional[Callable] = None,
    limit: Optional[int] = None,
    parallel: bool = True,
    max_workers: int = 10,
    verify_certificates: bool = False,
    allow_legacy_tls: bool = True
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
        print(f"Using parallel validation with {validator.max_workers} workers")
        return validator.validate_parallel(
            limit=limit,
            progress_callback=progress_callback,
            stop_check=stop_check
        )
    
    # Sequential validation
    print("Using sequential validation")
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
        if proof_type == 'dns-rsa':
            dns_rsa[0] += 1
            if is_valid:
                dns_rsa[1] += 1
        elif proof_type == 'uri-rsa':
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
    timestamp = datetime.now().isoformat()
    
    output_data = {
        'metadata': {
            'timestamp': timestamp,
            'total_relays': statistics['total_relays'],
            'valid_relays': statistics['valid_relays'],
            'invalid_relays': statistics['invalid_relays'],
            'success_rate': statistics['success_rate']
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