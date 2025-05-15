"""
Security Checks Module for LUINT.
Handles IP/domain blacklist checks, vulnerability scanning based on detected technologies,
and security header analysis.
"""
import re
import socket
import requests
import dns.resolver
import dns.exception
import concurrent.futures
from typing import Dict, List, Any, Optional, Union, Set
from urllib.parse import urlparse

from luint.utils.logger import get_logger, LoggerAdapter
from luint.utils.helpers import is_ip_address, is_domain, normalize_url
from luint.utils.output_manager import progress_bar
from luint.constants import SECURITY_HEADERS, DEFAULT_HEADERS, API_ENDPOINTS
from luint.models.vulnerability import VulnerabilityDatabase

logger = get_logger()


class SecurityChecksScanner:
    """
    Security Checks Scanner for LUINT.
    Performs various security checks including blacklist checking, vulnerability scanning,
    and security analysis.
    """
    
    def __init__(self, target: str, config: Dict = None, 
                 cache_manager=None, rate_limiter=None, api_key_manager=None):
        """
        Initialize the Security Checks Scanner.
        
        Args:
            target (str): Domain or IP to scan
            config (dict, optional): Module configuration
            cache_manager: Cache manager instance
            rate_limiter: Rate limiter instance
            api_key_manager: API key manager instance
        """
        self.target = target
        self.config = config or {}
        self.module_config = self.config.get('modules', {}).get('security_checks', {})
        self.cache_manager = cache_manager
        self.rate_limiter = rate_limiter
        self.api_key_manager = api_key_manager
        self.vuln_db = VulnerabilityDatabase(self.config)
        
        # Setup module-specific logger
        self.logger = LoggerAdapter(logger, module_name='security_checks', target=target)
        
        # Determine if target is IP or domain
        self.is_ip = is_ip_address(target)
        self.is_domain = is_domain(target)
        
        # Normalize target for HTTP requests
        self.target_url = normalize_url(target)
        
        # Get target IP (resolving domain if needed)
        self.target_ip = self._get_target_ip()
        
        # Configuration options
        self.check_headers = self.module_config.get('check_headers', True)
        self.check_ssl = self.module_config.get('check_ssl', True)
        self.check_blacklists = self.module_config.get('check_blacklists', True)
        
        # Timeout for HTTP requests
        self.timeout = self.config.get('general', {}).get('timeout', 30)
    
    def _get_target_ip(self) -> Optional[str]:
        """
        Get the IP address for the target.
        
        Returns:
            str or None: Target IP address or None if resolution fails
        """
        if self.is_ip:
            return self.target
        elif self.is_domain:
            # Check if we have DNS info results cached
            if self.cache_manager:
                dns_results = self.cache_manager.get(self.target, namespace='dns_info')
                if dns_results and 'dns_records' in dns_results and 'A' in dns_results['dns_records']:
                    return dns_results['dns_records']['A'][0]
            
            # If not cached, resolve the domain
            try:
                return socket.gethostbyname(self.target)
            except socket.gaierror:
                self.logger.warning(f"Could not resolve domain {self.target}")
                return None
        
        return None
    
    def scan(self) -> Dict[str, Any]:
        """
        Run all security checks.
        
        Returns:
            dict: Consolidated security checks results
        """
        results = {
            'target': self.target,
            'target_ip': self.target_ip
        }
        
        # Check cache first
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='security_checks')
            if cached_results:
                self.logger.info(f"Using cached security checks results for {self.target}")
                return cached_results
        
        # Check blacklists
        if self.check_blacklists and self.target_ip:
            blacklist_results = self.check_ip_domain_blacklists()
            if blacklist_results:
                results['blacklist_checks'] = blacklist_results
        
        # Analyze HTTP security headers
        if self.check_headers:
            header_results = self.analyze_security_headers()
            if header_results:
                results['security_headers'] = header_results
        
        # Shodan host lookup (if API key available)
        if self.api_key_manager and self.api_key_manager.has_key('shodan') and self.target_ip:
            shodan_results = self.shodan_host_lookup()
            if shodan_results:
                results['shodan'] = shodan_results
        
        # Search for vulnerabilities based on detected technologies
        vuln_results = self.scan_vulnerabilities_by_tech()
        if vuln_results:
            results['vulnerabilities'] = vuln_results
        
        # Cache results if cache manager is available
        if self.cache_manager and results:
            self.cache_manager.set(self.target, results, namespace='security_checks')
            
        return results
    
    def check_ip_domain_blacklists(self) -> Dict[str, Any]:
        """
        Check if target IP or domain is listed in various blacklists.
        
        Returns:
            dict: Blacklist checking results
        """
        self.logger.info(f"Checking blacklists for {self.target}")
        
        results = {
            'dnsbl_checks': [],
            'api_checks': {},
            'total_blacklists_checked': 0,
            'blacklisted_on': 0
        }
        
        # DNS-based blacklist checks
        dnsbl_results = self.check_dnsbl()
        if dnsbl_results:
            results['dnsbl_checks'] = dnsbl_results['results']
            results['total_blacklists_checked'] += dnsbl_results['total_checked']
            results['blacklisted_on'] += dnsbl_results['blacklisted_on']
        
        # VirusTotal checks (if API key available)
        if self.api_key_manager and self.api_key_manager.has_key('virustotal'):
            vt_results = self.check_virustotal()
            if vt_results:
                results['api_checks']['virustotal'] = vt_results
                results['total_blacklists_checked'] += vt_results.get('total_engines', 0)
                results['blacklisted_on'] += vt_results.get('detected_by', 0)
        
        # AbuseIPDB checks (if API key available)
        if self.api_key_manager and self.api_key_manager.has_key('abuseipdb') and self.target_ip:
            abuseipdb_results = self.check_abuseipdb()
            if abuseipdb_results:
                results['api_checks']['abuseipdb'] = abuseipdb_results
                results['total_blacklists_checked'] += 1
                if abuseipdb_results.get('is_listed', False):
                    results['blacklisted_on'] += 1
        
        # URLScan.io checks (if API key available)
        if self.api_key_manager and self.api_key_manager.has_key('urlscan'):
            urlscan_results = self.check_urlscan()
            if urlscan_results:
                results['api_checks']['urlscan'] = urlscan_results
                results['total_blacklists_checked'] += 1
                if urlscan_results.get('is_malicious', False):
                    results['blacklisted_on'] += 1
        
        results['is_blacklisted'] = results['blacklisted_on'] > 0
        
        self.logger.info(f"Blacklist checks complete: found on {results['blacklisted_on']} of {results['total_blacklists_checked']} blacklists")
        
        return results
    
    def check_dnsbl(self) -> Dict[str, Any]:
        """
        Check if the target is listed in DNS-based blacklists (DNSBLs).
        
        Returns:
            dict: DNSBL checking results
        """
        self.logger.info(f"Checking DNSBLs for {self.target_ip}")
        
        results = {
            'results': [],
            'total_checked': 0,
            'blacklisted_on': 0
        }
        
        # Get DNSBL servers from config
        dnsbls = self.config.get('security_checks', {}).get('dnsbl_servers', [
            'zen.spamhaus.org',
            'bl.spamcop.net',
            'dnsbl.sorbs.net'  # Fallback minimum list
        ])
        
        # If target is a domain, use the IP address for DNSBL checks
        ip = self.target_ip
        if not ip:
            self.logger.warning("No IP address available for DNSBL checks")
            return results
        
        # Reverse the IP address for DNSBL queries
        ip_parts = ip.split('.')
        reversed_ip = '.'.join(ip_parts[::-1])
        
        # Function to check a single DNSBL
        def check_single_dnsbl(dnsbl):
            dnsbl_result = {
                'dnsbl': dnsbl,
                'is_listed': False,
                'response': None,
                'txt': None
            }
            
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('dns')
                    
                # Create the DNSBL query
                lookup = f"{reversed_ip}.{dnsbl}"
                
                # Query A record
                try:
                    answers = dns.resolver.resolve(lookup, 'A')
                    dnsbl_result['is_listed'] = True
                    dnsbl_result['response'] = [str(rdata) for rdata in answers]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                
                # If listed, try to get TXT record for details
                if dnsbl_result['is_listed']:
                    try:
                        txt_answers = dns.resolver.resolve(lookup, 'TXT')
                        dnsbl_result['txt'] = [str(rdata).strip('"') for rdata in txt_answers]
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                
            except dns.exception.DNSException as e:
                dnsbl_result['error'] = str(e)
            
            return dnsbl_result
        
        # Create progress bar
        with progress_bar(f"Checking DNSBLs for {ip}", unit="blacklists") as progress:
            progress.update(total=len(dnsbls))
            
            # Use ThreadPoolExecutor for parallel DNSBL checks
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_dnsbl = {executor.submit(check_single_dnsbl, dnsbl): dnsbl for dnsbl in dnsbls}
                
                for future in concurrent.futures.as_completed(future_to_dnsbl):
                    progress.update(advance=1)
                    
                    result = future.result()
                    results['total_checked'] += 1
                    
                    if result['is_listed']:
                        results['blacklisted_on'] += 1
                    
                    results['results'].append(result)
        
        # Sort results with blacklisted first
        results['results'].sort(key=lambda x: (not x['is_listed'], x['dnsbl']))
        
        self.logger.info(f"DNSBL checks complete: {ip} is listed on {results['blacklisted_on']} of {results['total_checked']} blacklists")
        
        return results
    
    def check_virustotal(self) -> Dict[str, Any]:
        """
        Check the target on VirusTotal.
        
        Returns:
            dict: VirusTotal checking results
        """
        self.logger.info(f"Checking VirusTotal for {self.target}")
        
        results = {
            'is_in_dataset': False,
            'scan_date': None,
            'total_engines': 0,
            'detected_by': 0,
            'detection_ratio': 0,
            'categories': [],
            'detections': []
        }
        
        # Get VirusTotal API key
        if not self.api_key_manager or not self.api_key_manager.has_key('virustotal'):
            self.logger.warning("No VirusTotal API key available")
            return results
        
        vt_api_key = self.api_key_manager.get_key('virustotal')
        
        try:
            # Choose appropriate endpoint
            if self.is_ip:
                url = API_ENDPOINTS['virustotal']['ip'].format(target=self.target)
            else:
                url = API_ENDPOINTS['virustotal']['domain'].format(target=self.target)
            
            if self.rate_limiter:
                self.rate_limiter.wait('virustotal')
            
            # Make the API request
            headers = {
                'x-apikey': vt_api_key
            }
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data and 'attributes' in data['data']:
                    attributes = data['data']['attributes']
                    results['is_in_dataset'] = True
                    
                    # Last analysis date
                    if 'last_analysis_date' in attributes:
                        results['scan_date'] = attributes['last_analysis_date']
                    
                    # Analysis results
                    if 'last_analysis_stats' in attributes:
                        stats = attributes['last_analysis_stats']
                        results['total_engines'] = sum(stats.values())
                        results['detected_by'] = stats.get('malicious', 0) + stats.get('suspicious', 0)
                        
                        if results['total_engines'] > 0:
                            results['detection_ratio'] = (results['detected_by'] / results['total_engines']) * 100
                    
                    # Categories
                    if 'categories' in attributes:
                        results['categories'] = attributes['categories']
                    
                    # Engine detections
                    if 'last_analysis_results' in attributes:
                        analysis_results = attributes['last_analysis_results']
                        
                        for engine, engine_result in analysis_results.items():
                            result_category = engine_result.get('category', '')
                            
                            if result_category in ['malicious', 'suspicious']:
                                detection = {
                                    'engine': engine,
                                    'category': result_category,
                                    'result': engine_result.get('result', '')
                                }
                                results['detections'].append(detection)
                
                self.logger.info(f"VirusTotal check complete: {self.target} detected by {results['detected_by']} of {results['total_engines']} engines")
                
            elif response.status_code == 404:
                self.logger.info(f"{self.target} not found in VirusTotal dataset")
            else:
                self.logger.warning(f"VirusTotal API returned status code {response.status_code}")
                results['error'] = f"API returned status code {response.status_code}"
        
        except requests.RequestException as e:
            self.logger.error(f"Error querying VirusTotal API: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def check_abuseipdb(self) -> Dict[str, Any]:
        """
        Check the target IP on AbuseIPDB.
        
        Returns:
            dict: AbuseIPDB checking results
        """
        if not self.target_ip:
            self.logger.warning("No IP address available for AbuseIPDB check")
            return None
            
        self.logger.info(f"Checking AbuseIPDB for {self.target_ip}")
        
        results = {
            'is_listed': False,
            'abuse_confidence_score': 0,
            'total_reports': 0,
            'last_reported_at': None,
            'categories': []
        }
        
        # Get AbuseIPDB API key
        if not self.api_key_manager or not self.api_key_manager.has_key('abuseipdb'):
            self.logger.warning("No AbuseIPDB API key available")
            return results
        
        abuseipdb_api_key = self.api_key_manager.get_key('abuseipdb')
        
        try:
            url = API_ENDPOINTS['abuseipdb']['check']
            
            if self.rate_limiter:
                self.rate_limiter.wait('abuseipdb')
            
            # Make the API request
            headers = {
                'Key': abuseipdb_api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': self.target_ip,
                'maxAgeInDays': 90,
                'verbose': True
            }
            
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data:
                    ip_data = data['data']
                    
                    # Parse results
                    results['abuse_confidence_score'] = ip_data.get('abuseConfidenceScore', 0)
                    results['is_listed'] = results['abuse_confidence_score'] > 0
                    results['total_reports'] = ip_data.get('totalReports', 0)
                    results['last_reported_at'] = ip_data.get('lastReportedAt')
                    
                    # Get categories
                    if 'reports' in ip_data and ip_data['reports']:
                        categories_set = set()
                        
                        # AbuseIPDB category reference
                        category_map = {
                            1: "DNS Compromise",
                            2: "DNS Poisoning",
                            3: "Fraud Orders",
                            4: "DDoS Attack",
                            5: "FTP Brute-Force",
                            6: "Ping of Death",
                            7: "Phishing",
                            8: "Fraud VoIP",
                            9: "Open Proxy",
                            10: "Web Spam",
                            11: "Email Spam",
                            12: "Blog Spam",
                            13: "VPN IP",
                            14: "Port Scan",
                            15: "Hacking",
                            16: "SQL Injection",
                            17: "Spoofing",
                            18: "Brute-Force",
                            19: "Bad Web Bot",
                            20: "Exploited Host",
                            21: "Web App Attack",
                            22: "SSH",
                            23: "IoT Targeted"
                        }
                        
                        for report in ip_data['reports']:
                            for category in report.get('categories', []):
                                if category in category_map:
                                    categories_set.add(category_map[category])
                                else:
                                    categories_set.add(f"Category {category}")
                        
                        results['categories'] = sorted(list(categories_set))
                
                self.logger.info(f"AbuseIPDB check complete: {self.target_ip} has confidence score {results['abuse_confidence_score']}%")
                
            else:
                self.logger.warning(f"AbuseIPDB API returned status code {response.status_code}")
                results['error'] = f"API returned status code {response.status_code}"
        
        except requests.RequestException as e:
            self.logger.error(f"Error querying AbuseIPDB API: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def check_urlscan(self) -> Dict[str, Any]:
        """
        Check the target on URLScan.io.
        
        Returns:
            dict: URLScan.io checking results
        """
        self.logger.info(f"Checking URLScan.io for {self.target}")
        
        results = {
            'is_in_dataset': False,
            'is_malicious': False,
            'total_results': 0,
            'malicious_results': 0,
            'latest_scans': []
        }
        
        # Get URLScan API key (optional)
        urlscan_api_key = None
        if self.api_key_manager and self.api_key_manager.has_key('urlscan'):
            urlscan_api_key = self.api_key_manager.get_key('urlscan')
        
        try:
            # Search for the target
            url = API_ENDPOINTS['urlscan']['search']
            
            # Determine search query
            if self.is_domain:
                search_query = f"domain:{self.target}"
            elif self.is_ip:
                search_query = f"ip:{self.target}"
            else:
                search_query = f"page.url:{self.target}"
            
            headers = {}
            if urlscan_api_key:
                headers['API-Key'] = urlscan_api_key
            
            params = {
                'q': search_query,
                'size': 100
            }
            
            if self.rate_limiter:
                self.rate_limiter.wait('urlscan')
            
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'results' in data and data['results']:
                    results['is_in_dataset'] = True
                    results['total_results'] = data.get('total', len(data['results']))
                    
                    # Process the results
                    for result in data['results'][:10]:  # Limit to 10 most recent
                        task = result.get('task', {})
                        page = result.get('page', {})
                        
                        scan = {
                            'scan_id': result.get('_id'),
                            'scan_date': task.get('time'),
                            'url': page.get('url'),
                            'domain': page.get('domain'),
                            'ip': page.get('ip'),
                            'country': page.get('country'),
                            'server': page.get('server'),
                            'status': page.get('statusCode')
                        }
                        
                        # Check verdict
                        if 'verdicts' in result:
                            verdicts = result['verdicts']
                            scan['overall_verdict'] = verdicts.get('overall', {}).get('malicious', False)
                            scan['verdict_categories'] = verdicts.get('overall', {}).get('categories', [])
                            
                            if scan['overall_verdict']:
                                results['malicious_results'] += 1
                        
                        results['latest_scans'].append(scan)
                    
                    results['is_malicious'] = results['malicious_results'] > 0
                
                self.logger.info(f"URLScan.io check complete: {self.target} found in {results['total_results']} scans, {results['malicious_results']} malicious")
                
            elif response.status_code == 404:
                self.logger.info(f"{self.target} not found in URLScan.io dataset")
            else:
                self.logger.warning(f"URLScan.io API returned status code {response.status_code}")
                results['error'] = f"API returned status code {response.status_code}"
        
        except requests.RequestException as e:
            self.logger.error(f"Error querying URLScan.io API: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def analyze_security_headers(self) -> Dict[str, Any]:
        """
        Analyze HTTP security headers.
        
        Returns:
            dict: Security headers analysis results
        """
        self.logger.info(f"Analyzing security headers for {self.target_url}")
        
        results = {
            'url': self.target_url,
            'present_headers': {},
            'missing_headers': [],
            'score': 0,
            'grade': 'F',
            'issues': []
        }
        
        # Check if we already have HTTP headers from the server info module
        headers_data = None
        if self.cache_manager:
            server_info = self.cache_manager.get(self.target, namespace='server_info')
            if server_info and 'http_headers' in server_info:
                headers_data = server_info['http_headers'].get('headers', {})
        
        # If no cached data, make a request
        if not headers_data:
            try:
                headers = DEFAULT_HEADERS.copy()
                
                if self.rate_limiter:
                    self.rate_limiter.wait('http')
                
                response = requests.get(
                    self.target_url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                headers_data = dict(response.headers)
                
            except requests.RequestException as e:
                self.logger.error(f"Error fetching HTTP headers: {str(e)}")
                results['error'] = f"Failed to fetch headers: {str(e)}"
                return results
        
        # Check for the presence of security headers
        total_points = 0
        max_points = 0
        
        # Define security headers with their importance and best practices
        security_header_checks = {
            'Strict-Transport-Security': {
                'points': 20,
                'best_practice': 'max-age=31536000; includeSubDomains; preload',
                'description': 'HTTP Strict Transport Security (HSTS) enforces secure (HTTPS) connections to the server',
                'regex': r'max-age=(\d+)',
                'min_value': 15768000  # 6 months in seconds
            },
            'Content-Security-Policy': {
                'points': 20,
                'best_practice': "default-src 'self'; script-src 'self'",
                'description': 'Content Security Policy (CSP) helps prevent XSS attacks',
                'check_function': lambda val: "'none'" not in val.lower() and "'unsafe-inline'" not in val.lower()
            },
            'X-Content-Type-Options': {
                'points': 10,
                'best_practice': 'nosniff',
                'description': 'Prevents browsers from interpreting files as a different content-type',
                'check_function': lambda val: val.lower() == 'nosniff'
            },
            'X-Frame-Options': {
                'points': 10,
                'best_practice': 'DENY or SAMEORIGIN',
                'description': 'Protects against clickjacking attacks',
                'check_function': lambda val: val.upper() in ['DENY', 'SAMEORIGIN']
            },
            'X-XSS-Protection': {
                'points': 10,
                'best_practice': '1; mode=block',
                'description': 'Enables XSS filtering in browsers',
                'check_function': lambda val: val == '1; mode=block'
            },
            'Referrer-Policy': {
                'points': 5,
                'best_practice': 'strict-origin-when-cross-origin or no-referrer',
                'description': 'Controls how much referrer information is included with requests',
                'check_function': lambda val: val.lower() in ['no-referrer', 'no-referrer-when-downgrade', 'strict-origin', 'strict-origin-when-cross-origin']
            },
            'Permissions-Policy': {
                'points': 5,
                'best_practice': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
                'description': 'Controls which browser features can be used (replaces Feature-Policy)',
                'required': False
            },
            'Feature-Policy': {
                'points': 5,
                'best_practice': 'camera none; microphone none; geolocation none',
                'description': 'Controls which browser features can be used (deprecated in favor of Permissions-Policy)',
                'required': False
            }
        }
        
        # Add additional modern security headers
        modern_headers = {
            'Cross-Origin-Embedder-Policy': {
                'points': 5,
                'best_practice': 'require-corp',
                'description': 'Prevents a document from loading cross-origin resources that don\'t provide CORS or CORP headers',
                'required': False
            },
            'Cross-Origin-Opener-Policy': {
                'points': 5,
                'best_practice': 'same-origin',
                'description': 'Prevents other domains from opening/controlling your window',
                'required': False
            },
            'Cross-Origin-Resource-Policy': {
                'points': 5,
                'best_practice': 'same-origin or same-site',
                'description': 'Prevents other domains from reading your resources',
                'required': False
            }
        }
        
        # Merge modern headers
        for header, config in modern_headers.items():
            security_header_checks[header] = config
        
        # Check each security header
        for header, config in security_header_checks.items():
            max_points += config['points']
            
            # Find the header (case-insensitive)
            header_value = None
            for response_header, value in headers_data.items():
                if response_header.lower() == header.lower():
                    header_value = value
                    break
            
            if header_value:
                # Header is present, check if it meets best practices
                is_valid = True
                
                if 'check_function' in config:
                    is_valid = config['check_function'](header_value)
                elif 'regex' in config and 'min_value' in config:
                    # Check if value meets minimum requirement (e.g., HSTS max-age)
                    matches = re.search(config['regex'], header_value)
                    if matches:
                        value = int(matches.group(1))
                        is_valid = value >= config['min_value']
                
                if is_valid:
                    total_points += config['points']
                    results['present_headers'][header] = {
                        'value': header_value,
                        'meets_best_practice': True
                    }
                else:
                    total_points += config['points'] * 0.5  # Half points for having it but not optimal
                    results['present_headers'][header] = {
                        'value': header_value,
                        'meets_best_practice': False,
                        'best_practice': config['best_practice']
                    }
                    results['issues'].append(f"{header} is present but does not follow best practices")
            elif config.get('required', True):
                # Required header is missing
                results['missing_headers'].append({
                    'header': header,
                    'best_practice': config['best_practice'],
                    'description': config['description']
                })
                results['issues'].append(f"Missing security header: {header}")
        
        # Calculate score and grade
        if max_points > 0:
            results['score'] = (total_points / max_points) * 100
            
            # Assign grade based on score
            if results['score'] >= 90:
                results['grade'] = 'A'
            elif results['score'] >= 80:
                results['grade'] = 'B'
            elif results['score'] >= 70:
                results['grade'] = 'C'
            elif results['score'] >= 60:
                results['grade'] = 'D'
            else:
                results['grade'] = 'F'
        
        # Additional checks for HTTPS
        parsed_url = urlparse(self.target_url)
        if parsed_url.scheme == 'https':
            # Check HSTS preload status
            if 'Strict-Transport-Security' in results['present_headers']:
                hsts_value = results['present_headers']['Strict-Transport-Security']['value']
                if 'preload' not in hsts_value:
                    results['issues'].append("HSTS header does not include preload directive")
                if 'includeSubDomains' not in hsts_value:
                    results['issues'].append("HSTS header does not include includeSubDomains directive")
        else:
            results['issues'].append("Site is not using HTTPS")
            results['score'] *= 0.5  # Penalize score for not using HTTPS
        
        self.logger.info(f"Security headers analysis complete: Score {results['score']:.2f}%, Grade {results['grade']}")
        
        return results
    
    def shodan_host_lookup(self) -> Dict[str, Any]:
        """
        Query Shodan for information about the target.
        
        Returns:
            dict: Shodan lookup results
        """
        self.logger.info(f"Querying Shodan for {self.target_ip}")
        
        results = {
            'found': False,
            'ports': [],
            'vulnerabilities': [],
            'tags': [],
            'services': []
        }
        
        # Get Shodan API key
        if not self.api_key_manager or not self.api_key_manager.has_key('shodan'):
            self.logger.warning("No Shodan API key available")
            return results
        
        shodan_api_key = self.api_key_manager.get_key('shodan')
        
        try:
            url = API_ENDPOINTS['shodan']['host'].format(target=self.target_ip)
            
            params = {
                'key': shodan_api_key,
                'minify': False  # Get full results
            }
            
            if self.rate_limiter:
                self.rate_limiter.wait('shodan')
            
            response = requests.get(
                url,
                params=params,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                results['found'] = True
                
                # Basic information
                results['ip'] = data.get('ip_str', self.target_ip)
                results['hostnames'] = data.get('hostnames', [])
                results['country'] = data.get('country_name')
                results['city'] = data.get('city')
                results['org'] = data.get('org')
                results['isp'] = data.get('isp')
                results['last_update'] = data.get('last_update')
                results['tags'] = data.get('tags', [])
                
                # Get open ports
                results['ports'] = data.get('ports', [])
                
                # Process services
                if 'data' in data:
                    for service in data['data']:
                        service_info = {
                            'port': service.get('port'),
                            'protocol': service.get('transport', 'unknown'),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'cpe': service.get('cpe', []),
                            'banner': service.get('data', '')[:500]  # Truncate long banners
                        }
                        
                        # Add module information if available
                        if 'http' in service:
                            http_info = service['http']
                            service_info['http'] = {
                                'server': http_info.get('server', ''),
                                'title': http_info.get('title', ''),
                                'location': http_info.get('location', ''),
                                'robots_hash': http_info.get('robots_hash', '')
                            }
                        
                        results['services'].append(service_info)
                
                # Get vulnerabilities
                if 'vulns' in data:
                    for vuln_id, vuln_data in data['vulns'].items():
                        vuln_info = {
                            'id': vuln_id,
                            'cvss': vuln_data.get('cvss', 0),
                            'summary': vuln_data.get('summary', ''),
                            'references': vuln_data.get('references', [])
                        }
                        results['vulnerabilities'].append(vuln_info)
                
                # Sort vulnerabilities by CVSS score
                results['vulnerabilities'].sort(key=lambda x: x.get('cvss', 0), reverse=True)
                
                self.logger.info(f"Shodan lookup complete: {self.target_ip} has {len(results['ports'])} open ports, {len(results['vulnerabilities'])} vulnerabilities")
                
            elif response.status_code == 404:
                self.logger.info(f"{self.target_ip} not found in Shodan database")
            else:
                self.logger.warning(f"Shodan API returned status code {response.status_code}")
                results['error'] = f"API returned status code {response.status_code}"
        
        except requests.RequestException as e:
            self.logger.error(f"Error querying Shodan API: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def scan_vulnerabilities_by_tech(self) -> Dict[str, Any]:
        """
        Scan for vulnerabilities based on detected technologies.
        
        Returns:
            dict: Vulnerability scanning results
        """
        self.logger.info(f"Scanning for vulnerabilities based on detected technologies for {self.target}")
        
        results = {
            'total': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'vulnerabilities': []
        }
        
        # Get detected technologies from server info module
        technologies = []
        tech_info = None
        
        if self.cache_manager:
            server_info = self.cache_manager.get(self.target, namespace='server_info')
            if server_info and 'web_technologies' in server_info:
                tech_info = server_info['web_technologies']
                
                # Extract technologies
                if 'technologies' in tech_info:
                    technologies.extend(tech_info['technologies'])
                
                if 'cms' in tech_info and tech_info['cms']:
                    technologies.append(f"CMS: {tech_info['cms']}")
                
                if 'server' in tech_info and tech_info['server']:
                    technologies.append(f"Server: {tech_info['server']}")
                
                if 'javascript_frameworks' in tech_info:
                    for framework in tech_info['javascript_frameworks']:
                        technologies.append(f"JS Framework: {framework}")
        
        if not technologies:
            self.logger.warning("No technologies detected for vulnerability scanning")
            return results
        
        # Using the vulnerability database manager to access a PostgreSQL or local JSON database
        self.logger.info("Accessing vulnerability database for technology vulnerabilities")
        
        # Check detected technologies against vulnerability database
        detected_vulns = []
        
        for tech in technologies:
            # Extract the technology name and try to extract version if available
            tech_parts = tech.split(':')
            tech_name = tech_parts[-1].strip() if len(tech_parts) > 1 else tech.strip()
            
            # Extract version if it's contained in the tech name
            version = None
            version_match = re.search(r'(\d+\.\d+\.?\d*)', tech_name)
            if version_match:
                version = version_match.group(1)
                tech_name = tech_name.split(' ')[0].strip()  # Extract just the name part
            
            self.logger.debug(f"Checking vulnerabilities for {tech_name} {version if version else ''}")
            
            # Try to find vulnerabilities for this technology in our database
            # Categorize technology into appropriate service category
            service_category = "http"  # Default to http service
            
            # Get tech categories from config
            tech_categories = self.config.get('security_checks', {}).get('tech_categories', {})
            
            # Map technology to appropriate service category
            tech_name_lower = tech_name.lower()
            service_category = "http"  # Default category
            
            for category, techs in tech_categories.items():
                if any(tech.lower() in tech_name_lower for tech in techs):
                    service_category = category
                    break
            
            # Query our vulnerability database
            vulns = self.vuln_db.get_vulnerabilities(service_category, tech_name, version or "")
            
            if vulns:
                self.logger.info(f"Found {len(vulns)} vulnerabilities for {tech_name}")
                for vuln in vulns:
                    detected_vulns.append({
                        'technology': tech_name + (f" {version}" if version else ""),
                        'id': vuln.get('vuln_id', vuln.get('id')),
                        'name': vuln.get('name', 'Unknown vulnerability'),
                        'description': vuln.get('description', 'No description available'),
                        'severity': vuln.get('severity', 'medium'),
                        'cvss': vuln.get('cvss', 5.0),
                        'references': vuln.get('references', [])
                    })
            else:
                # Try direct keyword search in case the technology wasn't properly categorized
                search_results = self.vuln_db.search_vulnerabilities(tech_name)
                if search_results:
                    self.logger.info(f"Found {len(search_results)} vulnerabilities via keyword search for {tech_name}")
                    for vuln in search_results[:5]:  # Limit to top 5 results for keyword search
                        detected_vulns.append({
                            'technology': tech_name + (f" {version}" if version else ""),
                            'id': vuln.get('vuln_id', vuln.get('id')),
                            'name': vuln.get('name', 'Unknown vulnerability'),
                            'description': vuln.get('description', 'No description available'),
                            'severity': vuln.get('severity', 'medium'),
                            'cvss': vuln.get('cvss', 5.0),
                            'references': vuln.get('references', [])
                        })
        
        # Additional checks based on HTTP headers or other information
        if tech_info and 'server' in tech_info and tech_info['server']:
            server = tech_info['server'].lower()
            
            # Extract and check versions using vulnerability database
            version_patterns = {
                'apache': r'apache/(\d+\.\d+\.\d+)',
                'php': r'php/(\d+\.\d+\.\d+)',
                'nginx': r'nginx/(\d+\.\d+\.\d+)'
            }
            
            for tech, pattern in version_patterns.items():
                if tech in server.lower():
                    version_match = re.search(pattern, server, re.IGNORECASE)
                    if version_match:
                        version = version_match.group(1)
                        # Query vulnerability database for version-specific issues
                        vulns = self.vuln_db.get_vulnerabilities('http', tech, version)
                        if vulns:
                            detected_vulns.extend(vulns)
        
        # Add results
        results['vulnerabilities'] = detected_vulns
        results['total'] = len(detected_vulns)
        
        # Count by severity
        for vuln in detected_vulns:
            severity = vuln.get('severity', '').lower()
            if severity in ['critical', 'high']:
                results['high'] += 1
            elif severity == 'medium':
                results['medium'] += 1
            elif severity in ['low', 'info', 'informational']:
                results['low'] += 1
        
        self.logger.info(f"Vulnerability scan complete: found {results['total']} potential vulnerabilities ({results['high']} high, {results['medium']} medium, {results['low']} low)")
        
        return results
