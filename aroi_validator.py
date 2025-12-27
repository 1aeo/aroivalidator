"""
AROI Validator with Parallel Processing Support
Simplified and optimized version with parallel validation capability
"""
import concurrent.futures
import time
import requests
import json
import base64
import re
import dns.resolver
import dns.dnssec
import dns.rdatatype
import ssl
import urllib3
import logging
from typing import Dict, Any, List, Optional, Callable
from urllib.parse import urlparse, urljoin
from datetime import datetime
from pathlib import Path

# Configure logging for security events
logger = logging.getLogger(__name__)

# Note: SSL warnings are intentionally NOT disabled globally.
# Legacy TLS connections will log warnings when used.


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
            allow_legacy_tls: Whether to allow TLS 1.0/1.1 for legacy servers (default: False)
        """
        self.verify_certificates = verify_certificates
        self.allow_legacy_tls = allow_legacy_tls
        super().__init__(**kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        
        if self.verify_certificates:
            # Secure mode: verify certificates and hostnames
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            # Legacy mode: disable verification (logged as warning)
            logger.warning("SSL certificate verification disabled - vulnerable to MITM attacks")
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        
        if self.allow_legacy_tls:
            # Allow TLS 1.2 as minimum (TLS 1.0/1.1 are deprecated and insecure)
            # Even in legacy mode, we use TLS 1.2 as the minimum secure version
            logger.warning("Legacy TLS mode enabled - using relaxed cipher settings")
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        else:
            # Modern secure mode: TLS 1.2+ with strong ciphers
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        
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
        # Validate max_workers to prevent resource exhaustion
        if not isinstance(max_workers, int) or max_workers < 1:
            raise ValueError("max_workers must be a positive integer")
        if max_workers > 100:
            logger.warning(f"max_workers={max_workers} is very high, limiting to 100")
            max_workers = 100
        
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
        from datetime import datetime, timedelta
        
        active_relays = []
        now = datetime.utcnow()
        max_offline_days = 14
        cutoff_date = now - timedelta(days=max_offline_days)
        
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
        """Check if fingerprint exists in response text"""
        lines = text.strip().split('\n')
        for line in lines:
            line = line.strip()
            # Skip comments and empty lines
            if line.startswith('#') or not line:
                continue
            # Check if this line contains the fingerprint (case-insensitive)
            if fingerprint == line.upper():
                return True
        return False
    
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
    Run AROI validation with optional parallel processing
    
    Args:
        progress_callback: Function to call with (current, total, result)
        stop_check: Function that returns True if validation should stop
        limit: Maximum number of relays to validate (None for all, must be positive if set)
        parallel: Whether to use parallel processing
        max_workers: Number of parallel workers (if parallel=True), must be 1-100
        verify_certificates: Whether to verify SSL certificates
        allow_legacy_tls: Whether to allow legacy TLS settings
    
    Returns:
        List of validation results
        
    Raises:
        ValueError: If parameters are invalid
    """
    # Validate inputs
    if limit is not None:
        if not isinstance(limit, int) or limit < 0:
            raise ValueError("limit must be a non-negative integer or None")
    
    if not isinstance(max_workers, int) or max_workers < 1:
        raise ValueError("max_workers must be a positive integer")
    
    max_workers = min(max_workers, 100)  # Cap at 100 workers
    
    validator = ParallelAROIValidator(
        max_workers=max_workers if parallel else 1,
        verify_certificates=verify_certificates,
        allow_legacy_tls=allow_legacy_tls
    )
    
    if parallel:
        print(f"Using parallel validation with {max_workers} workers")
        return validator.validate_parallel(
            limit=limit,
            progress_callback=progress_callback,
            stop_check=stop_check
        )
    else:
        print("Using sequential validation")
        # Sequential validation (backwards compatible)
        relays = validator.fetch_relay_data(limit)
        results = []
        
        for idx, relay in enumerate(relays):
            if stop_check and stop_check():
                break
            
            result = validator.validate_relay(relay)
            results.append(result)
            
            if progress_callback:
                progress_callback(idx + 1, len(relays), result)
        
        return results


def calculate_statistics(results: List[Dict]) -> Dict:
    """Calculate validation statistics"""
    total_relays = len(results)
    valid_relays = sum(1 for r in results if r['valid'])
    invalid_relays = total_relays - valid_relays
    success_rate = (valid_relays / total_relays * 100) if total_relays > 0 else 0
    
    # Proof type analysis
    dns_rsa_results = [r for r in results if r.get('proof_type') == 'dns-rsa']
    uri_rsa_results = [r for r in results if r.get('proof_type') == 'uri-rsa']
    no_proof_results = [r for r in results if not r.get('proof_type')]
    
    return {
        'total_relays': total_relays,
        'valid_relays': valid_relays,
        'invalid_relays': invalid_relays,
        'success_rate': success_rate,
        'proof_types': {
            'dns_rsa': {
                'total': len(dns_rsa_results),
                'valid': sum(1 for r in dns_rsa_results if r['valid']),
                'success_rate': (sum(1 for r in dns_rsa_results if r['valid']) / len(dns_rsa_results) * 100) if dns_rsa_results else 0
            },
            'uri_rsa': {
                'total': len(uri_rsa_results),
                'valid': sum(1 for r in uri_rsa_results if r['valid']),
                'success_rate': (sum(1 for r in uri_rsa_results if r['valid']) / len(uri_rsa_results) * 100) if uri_rsa_results else 0
            },
            'no_proof': {
                'total': len(no_proof_results)
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
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if filename is None:
        filename = f'aroi_validation_{timestamp}.json'
    else:
        # Sanitize user-provided filename
        filename = _sanitize_filename(filename)
    
    statistics = calculate_statistics(results)
    
    output_data = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'total_relays': statistics['total_relays'],
            'valid_relays': statistics['valid_relays'],
            'invalid_relays': statistics['invalid_relays'],
            'success_rate': statistics['success_rate']
        },
        'statistics': statistics,
        'results': results
    }
    
    # Save with timestamp
    file_path = results_dir / filename
    
    # Verify the path is within the results directory (defense in depth)
    if not str(file_path.resolve()).startswith(str(results_dir)):
        raise ValueError("Invalid filename: path traversal detected")
    
    with open(file_path, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    # Also save as latest
    latest_path = results_dir / 'latest.json'
    with open(latest_path, 'w') as f:
        json.dump(output_data, f, indent=2)
    
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
    
    # Ensure no path separators remain
    if '/' in safe_name or '\\' in safe_name:
        raise ValueError("Invalid filename: contains path separators")
    
    # Reject names that start with dots (hidden files) except for specific allowed names
    if safe_name.startswith('.') and safe_name not in ['.json']:
        raise ValueError("Invalid filename: hidden files not allowed")
    
    # Validate the filename contains only safe characters
    import string
    allowed_chars = set(string.ascii_letters + string.digits + '._-')
    if not all(c in allowed_chars for c in safe_name):
        raise ValueError("Invalid filename: contains invalid characters")
    
    # Ensure it ends with .json
    if not safe_name.endswith('.json'):
        raise ValueError("Invalid filename: must end with .json")
    
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
    results_dir = Path('validation_results').resolve()
    
    try:
        safe_filename = _sanitize_filename(filename)
    except ValueError as e:
        logger.warning(f"Invalid filename rejected: {filename} - {e}")
        return None
    
    file_path = results_dir / safe_filename
    
    # Double-check that the resolved path is within the results directory
    try:
        file_path = file_path.resolve()
        if not str(file_path).startswith(str(results_dir)):
            logger.warning(f"Path traversal attempt detected: {filename}")
            return None
    except (OSError, ValueError):
        return None
    
    if not file_path.exists():
        return None
    
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
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