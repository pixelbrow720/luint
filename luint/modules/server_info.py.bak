"""
Server Information Module for LUINT.
Handles IP geolocation, ASN information, HTTP/HTTPS headers, SSL/TLS certificate analysis,
port scanning, web technology detection, and more.

This module provides comprehensive reconnaissance on server infrastructure and configurations.
It collects and analyzes technical details about web servers, network services, security implementations,
and infrastructure components to build a detailed profile of the target's technical environment.

Key capabilities:
- IP geolocation and network ownership analysis (ISP, hosting provider, etc.)
- TCP/UDP port scanning with service detection and version fingerprinting
- Web server identification and HTTP header security analysis
- SSL/TLS certificate examination, validation, and vulnerability checks
- Web technology stack detection (server software, frameworks, CMS)
- Server-side security configuration assessment
- Load balancer and CDN detection
- Web application firewall (WAF) detection and identification
- Service vulnerability scanning based on version information
- Server response time analysis and performance profiling
- HTTP security header validation (HSTS, CSP, X-XSS-Protection, etc.)
- Cookie security analysis and session management assessment
- Favicon fingerprinting for technology identification
- Web server version and banner information collection
- Operating system detection through TCP/IP fingerprinting
- Service configuration analysis and security assessment

This module forms a critical part of the security assessment process by identifying
potentially vulnerable services, misconfigurations, and information leakage that could
be leveraged in further reconnaissance or exploitation attempts.
"""
import socket
import ssl
import re
import json
import concurrent.futures
import ipaddress
import requests
import time
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional, Union, Tuple
import OpenSSL.crypto as crypto
from datetime import datetime
import nmap

from luint.utils.logger import get_logger, LoggerAdapter
from luint.utils.helpers import is_ip_address, is_domain, normalize_url
from luint.constants import SECURITY_HEADERS, WEB_TECHNOLOGIES, DEFAULT_HEADERS

logger = get_logger()


class ServerInfoScanner:
    """
    Server Information Scanner for LUINT.
    Gathers information about server infrastructure and configuration.
    """
    
    def __init__(self, target: str, config: Dict = None, 
                 cache_manager=None, rate_limiter=None, api_key_manager=None):
        """
        Initialize the Server Information Scanner.
        
        Args:
            target (str): Domain or IP to scan
            config (dict, optional): Module configuration
            cache_manager: Cache manager instance
            rate_limiter: Rate limiter instance
            api_key_manager: API key manager instance
        """
        self.target = target
        self.config = config or {}
        self.module_config = self.config.get('modules', {}).get('server_info', {})
        self.cache_manager = cache_manager
        self.rate_limiter = rate_limiter
        self.api_key_manager = api_key_manager
        
        # Setup module-specific logger
        self.logger = LoggerAdapter(logger, module_name='server_info', target=target)
        
        # Normalize target (determine if IP or domain)
        self.is_ip = is_ip_address(target)
        self.is_domain = is_domain(target)
        
        # HTTP timeout
        self.timeout = self.module_config.get('timeout', 10)
        
        # Port scan configuration
        self.port_scan_timeout = self.module_config.get('port_scan_timeout', 5)
        self.common_ports = self.module_config.get('common_ports', [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443])
    
    def scan(self) -> Dict[str, Any]:
        """
        Run all server information gathering methods.
        
        Returns:
            dict: Consolidated server information results
        """
        results = {}
        
        # Check cache first
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='server_info')
            if cached_results:
                self.logger.info(f"Using cached server information results for {self.target}")
                return cached_results
        
        # IP Geolocation
        geo_results = self.get_ip_geolocation()
        if geo_results:
            results['geolocation'] = geo_results
        
        # ASN Information
        asn_results = self.get_asn_info()
        if asn_results:
            results['asn'] = asn_results
        
        # HTTP/HTTPS Headers Analysis
        http_headers = self.analyze_http_headers()
        if http_headers:
            results['http_headers'] = http_headers
        
        # SSL/TLS Certificate Analysis
        ssl_results = self.analyze_ssl_certificate()
        if ssl_results:
            results['ssl_certificate'] = ssl_results
        
        # Port Scanning
        port_scan_results = self.scan_ports()
        if port_scan_results:
            results['port_scan'] = port_scan_results
        
        # Web Technology Detection
        tech_results = self.detect_web_technologies()
        if tech_results:
            results['web_technologies'] = tech_results
        
        # Fetch and analyze robots.txt
        robots_results = self.fetch_robots_txt()
        if robots_results:
            results['robots_txt'] = robots_results
        
        # Fetch and analyze sitemap.xml
        sitemap_results = self.fetch_sitemap_xml()
        if sitemap_results:
            results['sitemap_xml'] = sitemap_results
        
        # Favicon hash lookup
        favicon_results = self.favicon_hash_lookup()
        if favicon_results:
            results['favicon_hash'] = favicon_results
        
        # Check for cloud provider
        cloud_results = self.check_cloud_provider()
        if cloud_results:
            results['cloud_provider'] = cloud_results
        
        # Enhanced Server Analysis - New Features
        
        # Web Server Fingerprinting
        server_fingerprint = self.web_server_fingerprint()
        if server_fingerprint:
            results['server_fingerprint'] = server_fingerprint
        
        # HTTP Security Analysis
        security_analysis = self.analyze_http_security()
        if security_analysis:
            results['security_analysis'] = security_analysis
        
        # CORS Policy Analysis
        cors_analysis = self.analyze_cors_policy()
        if cors_analysis:
            results['cors_policy'] = cors_analysis
        
        # Firewall Detection
        firewall_detection = self.detect_firewall()
        if firewall_detection:
            results['firewall_detection'] = firewall_detection
        
        # CDN Detection
        cdn_detection = self.detect_cdn()
        if cdn_detection:
            results['cdn_detection'] = cdn_detection
        
        # Server Vulnerability Check
        vuln_check = self.check_server_vulnerabilities()
        if vuln_check:
            results['vulnerability_check'] = vuln_check
        
        # Response Time Analysis
        response_time = self.analyze_response_time()
        if response_time:
            results['response_time'] = response_time
            
        # Enhanced Security Posture Analysis
        security_posture = self.analyze_infrastructure_security_posture()
        if security_posture:
            results['security_posture'] = security_posture
            
        # Advanced Port Vulnerability Scan (performed only when explicitly requested due to resource intensity)
        if self.module_config.get('perform_advanced_port_scan', False):
            advanced_port_scan = self.perform_advanced_port_vulnerability_scan()
            if advanced_port_scan:
                results['advanced_port_scan'] = advanced_port_scan
            
        # Cache results if cache manager is available
        if self.cache_manager and results:
            self.cache_manager.set(self.target, results, namespace='server_info')
            
        return results
    
    def get_ip_geolocation(self) -> Dict[str, Any]:
        """
        Get IP geolocation information.
        
        Returns:
            dict: IP geolocation data
        """
        self.logger.info(f"Getting IP geolocation for {self.target}")
        
        # If target is a domain, resolve it to an IP first
        ip = self.target
        if not self.is_ip:
            try:
                ip = socket.gethostbyname(self.target)
            except socket.gaierror:
                self.logger.error(f"Could not resolve domain {self.target} to IP")
                return {'error': f"Could not resolve domain {self.target} to IP"}
        
        # Try using IPinfo API first if we have a key
        ipinfo_key = None
        if self.api_key_manager:
            ipinfo_key = self.api_key_manager.get_key('ipinfo')
        
        if ipinfo_key:
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('ipinfo')
                
                response = requests.get(
                    f"https://ipinfo.io/{ip}/json",
                    params={'token': ipinfo_key},
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Process the response
                    result = {
                        'ip': data.get('ip'),
                        'hostname': data.get('hostname'),
                        'city': data.get('city'),
                        'region': data.get('region'),
                        'country': data.get('country'),
                        'location': data.get('loc'),
                        'org': data.get('org'),
                        'postal': data.get('postal'),
                        'timezone': data.get('timezone'),
                        'source': 'ipinfo.io'
                    }
                    
                    # Parse location into latitude and longitude if present
                    if 'loc' in data and ',' in data['loc']:
                        lat, lon = data['loc'].split(',')
                        result['latitude'] = lat
                        result['longitude'] = lon
                    
                    self.logger.info(f"Successfully retrieved geolocation data for {ip} from IPinfo")
                    return result
                else:
                    self.logger.warning(f"IPinfo API returned status code {response.status_code}")
            
            except requests.RequestException as e:
                self.logger.error(f"Error querying IPinfo API: {str(e)}")
        
        # Fallback to ip-api.com (free, no API key required)
        try:
            if self.rate_limiter:
                self.rate_limiter.wait('http')
            
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    result = {
                        'ip': ip,
                        'city': data.get('city'),
                        'region': data.get('regionName'),
                        'country': data.get('country'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'asname': data.get('asname'),
                        'timezone': data.get('timezone'),
                        'source': 'ip-api.com'
                    }
                    
                    self.logger.info(f"Successfully retrieved geolocation data for {ip} from ip-api.com")
                    return result
                else:
                    self.logger.warning(f"ip-api.com returned error status: {data.get('message', 'Unknown error')}")
            else:
                self.logger.warning(f"ip-api.com returned status code {response.status_code}")
        
        except requests.RequestException as e:
            self.logger.error(f"Error querying ip-api.com: {str(e)}")
        
        return {'error': "Could not retrieve geolocation data"}
    
    def get_asn_info(self) -> Dict[str, Any]:
        """
        Get Autonomous System Number (ASN) information.
        
        Returns:
            dict: ASN information
        """
        self.logger.info(f"Getting ASN information for {self.target}")
        
        # If target is a domain, resolve it to an IP first
        ip = self.target
        if not self.is_ip:
            try:
                ip = socket.gethostbyname(self.target)
            except socket.gaierror:
                self.logger.error(f"Could not resolve domain {self.target} to IP")
                return {'error': f"Could not resolve domain {self.target} to IP"}
        
        # Try to get from geolocation result first (to avoid duplicate API calls)
        geo_result = None
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='server_info')
            if cached_results and 'geolocation' in cached_results:
                geo_result = cached_results['geolocation']
        
        if geo_result and ('as' in geo_result or 'org' in geo_result):
            asn_info = {
                'ip': ip
            }
            
            if 'as' in geo_result:
                asn_info['asn'] = geo_result['as']
            if 'asname' in geo_result:
                asn_info['asn_name'] = geo_result['asname']
            if 'org' in geo_result:
                asn_info['organization'] = geo_result['org']
            if 'isp' in geo_result:
                asn_info['isp'] = geo_result['isp']
                
            asn_info['source'] = geo_result.get('source', 'geolocation_data')
            
            self.logger.info(f"Using ASN information from geolocation data for {ip}")
            return asn_info
        
        # Query ASN data from bgpview.io API (free, no API key required)
        try:
            if self.rate_limiter:
                self.rate_limiter.wait('http')
            
            response = requests.get(
                f"https://api.bgpview.io/ip/{ip}",
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'ok' and 'data' in data:
                    result_data = data['data']
                    
                    # Extract ASN information
                    asn_info = {
                        'ip': ip,
                        'prefixes': []
                    }
                    
                    # Get prefix information
                    for prefix_data in result_data.get('prefixes', []):
                        prefix_info = {
                            'prefix': prefix_data.get('prefix'),
                            'asn': prefix_data.get('asn', {}).get('asn'),
                            'name': prefix_data.get('asn', {}).get('name'),
                            'description': prefix_data.get('asn', {}).get('description'),
                            'country_code': prefix_data.get('asn', {}).get('country_code')
                        }
                        asn_info['prefixes'].append(prefix_info)
                    
                    # If we have at least one prefix, use the first one for main ASN info
                    if asn_info['prefixes']:
                        first_prefix = asn_info['prefixes'][0]
                        asn_info['asn'] = first_prefix.get('asn')
                        asn_info['asn_name'] = first_prefix.get('name')
                        asn_info['asn_description'] = first_prefix.get('description')
                        asn_info['country_code'] = first_prefix.get('country_code')
                    
                    asn_info['source'] = 'bgpview.io'
                    
                    self.logger.info(f"Successfully retrieved ASN information for {ip} from bgpview.io")
                    return asn_info
                else:
                    error_msg = data.get('status_message', 'Unknown error')
                    self.logger.warning(f"bgpview.io API returned error: {error_msg}")
            else:
                self.logger.warning(f"bgpview.io API returned status code {response.status_code}")
        
        except requests.RequestException as e:
            self.logger.error(f"Error querying bgpview.io API: {str(e)}")
        
        return {'error': "Could not retrieve ASN information"}
    
    def analyze_http_headers(self) -> Dict[str, Any]:
        """
        Analyze HTTP and HTTPS headers.
        
        Returns:
            dict: HTTP/HTTPS headers analysis
        """
        self.logger.info(f"Analyzing HTTP/HTTPS headers for {self.target}")
        
        url = self.target
        if not url.startswith('http'):
            if self.is_domain:
                # Try HTTPS first, then fall back to HTTP if needed
                url = f"https://{self.target}"
            else:
                # For IP addresses, we'll need to try both
                url = f"http://{self.target}"
        
        results = {
            'url': url,
            'headers': {},
            'security_headers': {
                'present': [],
                'missing': []
            },
            'server_info': {},
            'redirects': []
        }
        
        # Track if we need to fall back to HTTP
        https_failed = False
        
        try:
            if self.rate_limiter:
                self.rate_limiter.wait('http')
            
            # Use custom headers but don't follow redirects yet (we'll track them)
            headers = DEFAULT_HEADERS.copy()
            
            # Make the request
            response = requests.get(
                url, 
                headers=headers, 
                timeout=self.timeout,
                allow_redirects=False,
                verify=False  # Ignore SSL certificate errors for scanning
            )
            
            # Process initial response
            self._process_http_response(response, results)
            
            # Track redirects manually
            redirect_url = url
            max_redirects = 5
            redirect_count = 0
            
            while redirect_count < max_redirects and 300 <= response.status_code < 400 and 'location' in response.headers:
                redirect_count += 1
                
                # Get the redirect URL
                redirect_url = response.headers['location']
                
                # If it's a relative URL, make it absolute
                if not redirect_url.startswith('http'):
                    redirect_url = urllib.parse.urljoin(url, redirect_url)
                
                # Add to redirects list
                results['redirects'].append({
                    'status_code': response.status_code,
                    'location': redirect_url
                })
                
                # Make the next request
                if self.rate_limiter:
                    self.rate_limiter.wait('http')
                
                response = requests.get(
                    redirect_url, 
                    headers=headers, 
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False
                )
                
                # Process response
                self._process_http_response(response, results, is_final=(redirect_count == max_redirects))
            
            # Update final URL
            if redirect_count > 0:
                results['final_url'] = redirect_url
            
        except requests.exceptions.SSLError:
            self.logger.warning(f"SSL Error for {url}, falling back to HTTP")
            https_failed = True
        except requests.RequestException as e:
            self.logger.warning(f"Error making request to {url}: {str(e)}")
            https_failed = True
        
        # If HTTPS failed and we tried HTTPS, fall back to HTTP
        if https_failed and url.startswith('https://'):
            http_url = f"http://{self.target}"
            self.logger.info(f"Trying HTTP fallback: {http_url}")
            
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('http')
                
                # Use custom headers
                headers = DEFAULT_HEADERS.copy()
                
                # Make the request
                response = requests.get(
                    http_url, 
                    headers=headers, 
                    timeout=self.timeout,
                    verify=False
                )
                
                # Process response
                results = {
                    'url': http_url,
                    'headers': {},
                    'security_headers': {
                        'present': [],
                        'missing': []
                    },
                    'server_info': {},
                    'redirects': []
                }
                
                self._process_http_response(response, results)
                
                # Check for redirect to HTTPS
                if response.history:
                    for r in response.history:
                        results['redirects'].append({
                            'status_code': r.status_code,
                            'location': r.headers.get('location', '')
                        })
                    
                    results['final_url'] = response.url
                
            except requests.RequestException as e:
                self.logger.error(f"Error making HTTP request to {http_url}: {str(e)}")
                results['error'] = f"Failed to connect to both HTTPS and HTTP: {str(e)}"
        
        # Check for security headers
        for header in SECURITY_HEADERS:
            normalized_header = header.lower()
            
            # Check if the header is present in any form (case-insensitive)
            found = False
            for response_header in results['headers']:
                if response_header.lower() == normalized_header:
                    results['security_headers']['present'].append(header)
                    found = True
                    break
            
            if not found:
                results['security_headers']['missing'].append(header)
        
        # Summarize results
        results['total_headers'] = len(results['headers'])
        results['security_score'] = len(results['security_headers']['present']) / len(SECURITY_HEADERS) * 100
        
        self.logger.info(f"Completed HTTP/HTTPS header analysis for {self.target}")
        return results
    
    def _process_http_response(self, response, results, is_final=True):
        """
        Process an HTTP response and update results.
        
        Args:
            response: Requests response object
            results: Results dictionary to update
            is_final: Whether this is the final response in a redirect chain
        """
        # Add headers
        for header, value in response.headers.items():
            results['headers'][header] = value
        
        # Extract server info
        if 'Server' in response.headers:
            results['server_info']['server'] = response.headers['Server']
        
        if 'X-Powered-By' in response.headers:
            results['server_info']['powered_by'] = response.headers['X-Powered-By']
        
        # Status code
        if is_final:
            results['status_code'] = response.status_code
        
        # Content info (only for final response)
        if is_final and response.status_code == 200:
            results['content_type'] = response.headers.get('Content-Type', 'unknown')
            results['content_length'] = response.headers.get('Content-Length', 'unknown')
    
    def analyze_ssl_certificate(self) -> Dict[str, Any]:
        """
        Analyze SSL/TLS certificate.
        
        Returns:
            dict: SSL/TLS certificate analysis
        """
        self.logger.info(f"Analyzing SSL/TLS certificate for {self.target}")
        
        # Only perform SSL/TLS analysis on domains, not IPs
        target = self.target
        port = 443
        
        # If target is a URL, extract the domain and possibly the port
        if target.startswith(('http://', 'https://')):
            parsed_url = urlparse(target)
            target = parsed_url.netloc
            
            # Extract port if specified
            if ':' in target:
                target, port_str = target.split(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 443
        
        # If no scheme and there's a port specified
        elif ':' in target:
            target, port_str = target.split(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 443
        
        results = {
            'target': target,
            'port': port,
            'has_ssl': False
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Don't verify certificate for scanning purposes
            
            # Connect to the server
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    results['has_ssl'] = True
                    
                    # Get certificate
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                    
                    # Extract certificate details
                    results['version'] = cert.get_version() + 1  # Version is 0-indexed
                    results['serial_number'] = '%x' % cert.get_serial_number()
                    results['signature_algorithm'] = cert.get_signature_algorithm().decode('utf-8')
                    
                    # Validity period
                    not_before = datetime.datetime.strptime(cert.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')
                    not_after = datetime.datetime.strptime(cert.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
                    results['valid_from'] = not_before.strftime('%Y-%m-%d %H:%M:%S UTC')
                    results['valid_until'] = not_after.strftime('%Y-%m-%d %H:%M:%S UTC')
                    
                    # Check if expired
                    now = datetime.datetime.utcnow()
                    results['is_expired'] = now > not_after
                    results['days_until_expiry'] = (not_after - now).days
                    
                    # Issuer details
                    issuer = cert.get_issuer()
                    issuer_components = {}
                    for i in range(issuer.get_entry_count()):
                        entry = issuer.get_entry(i)
                        issuer_components[entry.get_object().decode('utf-8')] = entry.get_data().decode('utf-8')
                    
                    results['issuer'] = {
                        'common_name': issuer_components.get('commonName', 'N/A'),
                        'organization': issuer_components.get('organizationName', 'N/A'),
                        'organizational_unit': issuer_components.get('organizationalUnitName', 'N/A'),
                        'country': issuer_components.get('countryName', 'N/A'),
                        'raw': str(issuer)
                    }
                    
                    # Subject details
                    subject = cert.get_subject()
                    subject_components = {}
                    for i in range(subject.get_entry_count()):
                        entry = subject.get_entry(i)
                        subject_components[entry.get_object().decode('utf-8')] = entry.get_data().decode('utf-8')
                    
                    results['subject'] = {
                        'common_name': subject_components.get('commonName', 'N/A'),
                        'organization': subject_components.get('organizationName', 'N/A'),
                        'organizational_unit': subject_components.get('organizationalUnitName', 'N/A'),
                        'country': subject_components.get('countryName', 'N/A'),
                        'raw': str(subject)
                    }
                    
                    # Alternative names
                    alt_names = []
                    for i in range(cert.get_extension_count()):
                        ext = cert.get_extension(i)
                        if ext.get_short_name().decode('utf-8') == 'subjectAltName':
                            # Parse the extension data
                            alt_names_str = ext.get_data().decode('utf-8')
                            # Extract domain names (very simplistic)
                            import re
                            alt_names = re.findall(r'DNS:([\w\.-]+)', alt_names_str)
                    
                    results['subject_alternative_names'] = alt_names
                    
                    # Get SSL/TLS protocol version
                    results['protocol_version'] = ssock.version()
                    
                    # Get cipher suite
                    results['cipher_suite'] = ssock.cipher()
                    
                    # Is certificate self-signed?
                    results['is_self_signed'] = issuer_components.get('commonName') == subject_components.get('commonName')
                    
                    self.logger.info(f"Successfully analyzed SSL/TLS certificate for {target}")
                    
        except (socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
            self.logger.warning(f"Could not connect to {target}:{port} for SSL/TLS analysis: {str(e)}")
            results['error'] = f"Connection error: {str(e)}"
        except ssl.SSLError as e:
            self.logger.warning(f"SSL error for {target}:{port}: {str(e)}")
            results['error'] = f"SSL error: {str(e)}"
        except Exception as e:
            self.logger.error(f"Error analyzing SSL/TLS certificate for {target}:{port}: {str(e)}")
            results['error'] = f"Error: {str(e)}"
        
        return results
    
    def scan_ports(self) -> Dict[str, Any]:
        """
        Scan common ports on the target.
        
        Returns:
            dict: Port scanning results
        """
        self.logger.info(f"Scanning ports for {self.target}")
        
        # Resolve domain to IP if needed
        ip = self.target
        if not self.is_ip:
            try:
                ip = socket.gethostbyname(self.target)
                self.logger.debug(f"Resolved {self.target} to IP: {ip}")
            except socket.gaierror:
                self.logger.error(f"Could not resolve domain {self.target} to IP")
                return {'error': f"Could not resolve domain {self.target} to IP"}
        
        results = {
            'ip': ip,
            'open_ports': [],
            'total_scanned': len(self.common_ports)
        }
        
        # Create a nmap scanner instance
        nm = nmap.PortScanner()
        
        try:
            # Prepare port list string for nmap
            ports_str = ','.join(map(str, self.common_ports))
            
            # Run nmap scan
            self.logger.debug(f"Starting nmap scan on {ip} for ports {ports_str}")
            nm.scan(ip, ports_str, arguments=f'-T4 --max-retries 1 --host-timeout {self.port_scan_timeout}s')
            
            # Process results
            if ip in nm.all_hosts():
                for port in nm[ip]['tcp']:
                    port_info = nm[ip]['tcp'][port]
                    if port_info['state'] == 'open':
                        port_data = {
                            'port': port,
                            'protocol': 'tcp',
                            'service': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                        results['open_ports'].append(port_data)
            
            results['open_ports'].sort(key=lambda x: x['port'])
            results['total_open'] = len(results['open_ports'])
            
            self.logger.info(f"Port scan complete for {ip}. Found {results['total_open']} open ports.")
            
        except nmap.PortScannerError as e:
            self.logger.error(f"Error during port scan: {str(e)}")
            results['error'] = f"Port scanning error: {str(e)}"
        except Exception as e:
            self.logger.error(f"Unexpected error during port scan: {str(e)}")
            results['error'] = f"Error: {str(e)}"
        
        return results
    
    def detect_web_technologies(self) -> Dict[str, Any]:
        """
        Detect web technologies used by the target.
        
        Returns:
            dict: Web technology detection results
        """
        self.logger.info(f"Detecting web technologies for {self.target}")
        
        # Normalize URL
        url = normalize_url(self.target)
        
        results = {
            'url': url,
            'technologies': [],
            'server': None,
            'cms': None,
            'javascript_frameworks': [],
            'analytics': [],
            'server_languages': []
        }
        
        try:
            if self.rate_limiter:
                self.rate_limiter.wait('http')
                
            # Make HTTP request
            headers = DEFAULT_HEADERS.copy()
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code != 200:
                self.logger.warning(f"Received non-200 status code: {response.status_code}")
                results['status_code'] = response.status_code
                return results
            
            # Extract technology information from headers
            if 'Server' in response.headers:
                results['server'] = response.headers['Server']
                results['technologies'].append(f"Server: {response.headers['Server']}")
            
            if 'X-Powered-By' in response.headers:
                power = response.headers['X-Powered-By']
                results['technologies'].append(f"Powered By: {power}")
                
                # Detect server language
                if 'php' in power.lower():
                    results['server_languages'].append('PHP')
                elif 'asp.net' in power.lower():
                    results['server_languages'].append('ASP.NET')
                elif 'jboss' in power.lower() or 'jsp' in power.lower():
                    results['server_languages'].append('Java')
            
            # Get page content
            content = response.text
            
            # Check for common technologies in content
            # CMS detection
            cms_patterns = {
                'WordPress': [
                    r'wp-content', r'wp-includes', r'wp-json', r'"generator" content="WordPress'
                ],
                'Drupal': [
                    r'Drupal.settings', r'sites/all/themes', r'sites/all/modules', r'"generator" content="Drupal'
                ],
                'Joomla': [
                    r'com_content', r'com_contact', r'com_users', r'"generator" content="Joomla'
                ],
                'Magento': [
                    r'Mage.Cookies', r'var BLANK_URL', r'Magento_', r'"generator" content="Magento'
                ],
                'Shopify': [
                    r'Shopify.theme', r'cdn.shopify.com', r'shopify-payment-button'
                ],
                'Wix': [
                    r'wix-bolt', r'wix-image', r'wix.com', r'X-Wix-'
                ]
            }
            
            for cms, patterns in cms_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        results['cms'] = cms
                        results['technologies'].append(f"CMS: {cms}")
                        break
                if results['cms']:
                    break
            
            # JavaScript frameworks
            js_frameworks = {
                'jQuery': [r'jquery', r'jQuery'],
                'React': [r'react.js', r'react-dom', r'reactjs'],
                'Angular': [r'angular.js', r'ng-app', r'ng-controller'],
                'Vue': [r'vue.js', r'vue-router', r'vuex'],
                'Bootstrap': [r'bootstrap.', r'data-toggle=', r'data-target='],
                'Tailwind CSS': [r'tailwind', r'tw-', r'className="[^"]*\s[a-z]+\-[a-z]+\-'],
                'Font Awesome': [r'font-awesome', r'fa-', r'fontawesome']
            }
            
            for js, patterns in js_frameworks.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        results['javascript_frameworks'].append(js)
                        results['technologies'].append(f"JS Framework: {js}")
                        break
            
            # Analytics
            analytics = {
                'Google Analytics': [r'ga\(', r'google-analytics.com', r'GoogleAnalyticsObject'],
                'Google Tag Manager': [r'googletagmanager.com', r'gtm.js', r'GTM-'],
                'Facebook Pixel': [r'connect.facebook.net', r'fbq\(', r'facebook-jssdk'],
                'Hotjar': [r'hotjar.com', r'hjSetting', r'_hjSettings'],
                'Matomo/Piwik': [r'piwik.js', r'matomo.js', r'_paq']
            }
            
            for tool, patterns in analytics.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        results['analytics'].append(tool)
                        results['technologies'].append(f"Analytics: {tool}")
                        break
            
            # Server language hints from content
            language_patterns = {
                'PHP': [r'\.php"', r'\.php\?', r'PHPSESSID'],
                'ASP.NET': [r'\.aspx', r'__VIEWSTATE', r'asp.net'],
                'Java': [r'\.jsp', r'\.do', r'jsessionid'],
                'Ruby': [r'\.rb', r'rails', r'ruby on rails'],
                'Python': [r'\.py', r'django', r'flask'],
                'Node.js': [r'node_modules', r'express', r'nextjs']
            }
            
            for lang, patterns in language_patterns.items():
                if lang not in results['server_languages']:  # Skip if already detected from headers
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            results['server_languages'].append(lang)
                            results['technologies'].append(f"Language: {lang}")
                            break
            
            # Web server hint from detected server header
            if results['server']:
                server = results['server'].lower()
                if 'apache' in server:
                    results['technologies'].append("Web Server: Apache")
                elif 'nginx' in server:
                    results['technologies'].append("Web Server: Nginx")
                elif 'iis' in server or 'microsoft' in server:
                    results['technologies'].append("Web Server: Microsoft IIS")
                elif 'cloudflare' in server:
                    results['technologies'].append("CDN: Cloudflare")
                    
            # CDN detection from headers
            cdn_headers = {
                'Cloudflare': ['cf-ray', 'cf-cache-status'],
                'Akamai': ['x-akamai-transformed', 'akamai-origin-hop'],
                'Fastly': ['fastly-io-info', 'x-fastly'],
                'CloudFront': ['x-amz-cf-id', 'x-amz-cf-pop'],
                'Varnish': ['x-varnish', 'via']
            }
            
            for cdn, header_keys in cdn_headers.items():
                for header in header_keys:
                    if any(h.lower() == header.lower() for h in response.headers):
                        results['technologies'].append(f"CDN: {cdn}")
                        break
            
            # Remove duplicates
            results['technologies'] = list(set(results['technologies']))
            results['javascript_frameworks'] = list(set(results['javascript_frameworks']))
            results['analytics'] = list(set(results['analytics']))
            results['server_languages'] = list(set(results['server_languages']))
            
            self.logger.info(f"Detected {len(results['technologies'])} technologies for {url}")
            
        except requests.RequestException as e:
            self.logger.error(f"Error during web technology detection: {str(e)}")
            results['error'] = f"Connection error: {str(e)}"
        
        return results
    
    def fetch_robots_txt(self) -> Dict[str, Any]:
        """
        Fetch and analyze robots.txt file.
        
        Returns:
            dict: robots.txt analysis results
        """
        self.logger.info(f"Fetching robots.txt for {self.target}")
        
        # Normalize URL
        base_url = normalize_url(self.target)
        robots_url = f"{base_url}/robots.txt"
        
        results = {
            'url': robots_url,
            'exists': False,
            'user_agents': [],
            'disallowed_paths': [],
            'allowed_paths': [],
            'sitemaps': []
        }
        
        try:
            if self.rate_limiter:
                self.rate_limiter.wait('http')
                
            # Fetch robots.txt
            response = requests.get(
                robots_url,
                headers=DEFAULT_HEADERS,
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                results['exists'] = True
                results['content'] = response.text
                
                # Parse robots.txt
                current_user_agent = None
                
                for line in response.text.splitlines():
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Check for User-agent
                    if line.lower().startswith('user-agent:'):
                        user_agent = line[len('user-agent:'):].strip()
                        current_user_agent = user_agent
                        if user_agent not in results['user_agents']:
                            results['user_agents'].append(user_agent)
                    
                    # Check for Disallow
                    elif line.lower().startswith('disallow:'):
                        path = line[len('disallow:'):].strip()
                        if path:  # Only add non-empty paths
                            results['disallowed_paths'].append({
                                'path': path,
                                'user_agent': current_user_agent
                            })
                    
                    # Check for Allow
                    elif line.lower().startswith('allow:'):
                        path = line[len('allow:'):].strip()
                        if path:  # Only add non-empty paths
                            results['allowed_paths'].append({
                                'path': path,
                                'user_agent': current_user_agent
                            })
                    
                    # Check for Sitemap
                    elif line.lower().startswith('sitemap:'):
                        sitemap = line[len('sitemap:'):].strip()
                        if sitemap:  # Only add non-empty sitemaps
                            results['sitemaps'].append(sitemap)
                
                # Summary
                results['disallowed_count'] = len(results['disallowed_paths'])
                results['allowed_count'] = len(results['allowed_paths'])
                results['sitemaps_count'] = len(results['sitemaps'])
                
                self.logger.info(f"Successfully fetched robots.txt with {results['disallowed_count']} disallowed paths")
            else:
                self.logger.info(f"No robots.txt found (status code: {response.status_code})")
                results['status_code'] = response.status_code
                
        except requests.RequestException as e:
            self.logger.warning(f"Error fetching robots.txt: {str(e)}")
            results['error'] = f"Connection error: {str(e)}"
        
        return results
    
    def fetch_sitemap_xml(self) -> Dict[str, Any]:
        """
        Fetch and analyze sitemap.xml file.
        
        Returns:
            dict: sitemap.xml analysis results
        """
        self.logger.info(f"Fetching sitemap.xml for {self.target}")
        
        # Normalize URL
        base_url = normalize_url(self.target)
        sitemap_url = f"{base_url}/sitemap.xml"
        
        # Check if we found a sitemap URL in robots.txt
        robots_result = None
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='server_info')
            if cached_results and 'robots_txt' in cached_results and cached_results['robots_txt'].get('exists', False):
                robots_result = cached_results['robots_txt']
        
        if robots_result and robots_result.get('sitemaps', []):
            sitemap_url = robots_result['sitemaps'][0]
            self.logger.info(f"Using sitemap URL from robots.txt: {sitemap_url}")
        
        results = {
            'url': sitemap_url,
            'exists': False,
            'urls': [],
            'sitemaps': []  # For sitemap index files
        }
        
        try:
            if self.rate_limiter:
                self.rate_limiter.wait('http')
                
            # Fetch sitemap.xml
            response = requests.get(
                sitemap_url,
                headers=DEFAULT_HEADERS,
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                results['exists'] = True
                
                # Check content type to ensure it's XML
                content_type = response.headers.get('Content-Type', '')
                if not ('xml' in content_type.lower() or response.text.strip().startswith('<?xml')):
                    self.logger.warning(f"Sitemap doesn't appear to be XML. Content type: {content_type}")
                    results['error'] = "Response doesn't appear to be XML"
                    return results
                
                # Parse XML response
                import xml.etree.ElementTree as ET
                try:
                    xml_content = response.text
                    root = ET.fromstring(xml_content)
                    
                    # Determine namespace if any
                    ns = ''
                    if '}' in root.tag:
                        ns = root.tag.split('}')[0] + '}'
                    
                    # Check if it's a sitemap index
                    if root.tag == f'{ns}sitemapindex':
                        for sitemap in root.findall(f'.//{ns}sitemap'):
                            loc = sitemap.find(f'{ns}loc')
                            lastmod = sitemap.find(f'{ns}lastmod')
                            
                            if loc is not None:
                                sitemap_info = {
                                    'url': loc.text.strip()
                                }
                                
                                if lastmod is not None:
                                    sitemap_info['lastmod'] = lastmod.text.strip()
                                
                                results['sitemaps'].append(sitemap_info)
                    
                    # Check if it's a regular sitemap
                    elif root.tag == f'{ns}urlset':
                        for url in root.findall(f'.//{ns}url'):
                            loc = url.find(f'{ns}loc')
                            lastmod = url.find(f'{ns}lastmod')
                            changefreq = url.find(f'{ns}changefreq')
                            priority = url.find(f'{ns}priority')
                            
                            if loc is not None:
                                url_info = {
                                    'url': loc.text.strip()
                                }
                                
                                if lastmod is not None:
                                    url_info['lastmod'] = lastmod.text.strip()
                                
                                if changefreq is not None:
                                    url_info['changefreq'] = changefreq.text.strip()
                                
                                if priority is not None:
                                    url_info['priority'] = priority.text.strip()
                                
                                results['urls'].append(url_info)
                    
                    # Summary
                    results['is_sitemap_index'] = len(results['sitemaps']) > 0
                    results['urls_count'] = len(results['urls'])
                    results['sitemaps_count'] = len(results['sitemaps'])
                    
                    self.logger.info(f"Successfully parsed sitemap with {results['urls_count']} URLs and {results['sitemaps_count']} sub-sitemaps")
                    
                except ET.ParseError as e:
                    self.logger.error(f"Error parsing XML: {str(e)}")
                    results['error'] = f"XML parsing error: {str(e)}"
                
            else:
                self.logger.info(f"No sitemap.xml found (status code: {response.status_code})")
                results['status_code'] = response.status_code
                
        except requests.RequestException as e:
            self.logger.warning(f"Error fetching sitemap.xml: {str(e)}")
            results['error'] = f"Connection error: {str(e)}"
        
        return results
    
    def favicon_hash_lookup(self) -> Dict[str, Any]:
        """
        Generate favicon hash and lookup for technology fingerprinting.
        
        Returns:
            dict: Favicon hash analysis results
        """
        self.logger.info(f"Performing favicon hash lookup for {self.target}")
        
        # Normalize URL
        base_url = normalize_url(self.target)
        
        results = {
            'url': base_url,
            'favicon_found': False,
            'matches': []
        }
        
        # List of possible favicon locations
        favicon_paths = [
            '/favicon.ico',
            '/favicon.png',
            '/apple-touch-icon.png',
            '/apple-touch-icon-precomposed.png'
        ]
        
        # Try to find the favicon by looking in HTML first
        html_favicon_url = None
        try:
            if self.rate_limiter:
                self.rate_limiter.wait('http')
                
            # Fetch the main page
            response = requests.get(
                base_url,
                headers=DEFAULT_HEADERS,
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                # Look for favicon link tags
                # <link rel="icon" href="favicon.ico">
                # <link rel="shortcut icon" href="favicon.ico">
                favicon_pattern = re.compile(r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
                matches = favicon_pattern.findall(response.text)
                
                if matches:
                    favicon_path = matches[0]
                    # Handle relative paths
                    if not favicon_path.startswith(('http://', 'https://')):
                        if favicon_path.startswith('/'):
                            html_favicon_url = f"{base_url}{favicon_path}"
                        else:
                            html_favicon_url = f"{base_url}/{favicon_path}"
                    else:
                        html_favicon_url = favicon_path
                    
                    self.logger.debug(f"Found favicon in HTML: {html_favicon_url}")
        except requests.RequestException:
            pass
        
        # List of URLs to try for favicon
        favicon_urls = []
        if html_favicon_url:
            favicon_urls.append(html_favicon_url)
        
        for path in favicon_paths:
            favicon_urls.append(f"{base_url}{path}")
        
        # Try each favicon URL
        favicon_content = None
        favicon_url = None
        
        for url in favicon_urls:
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('http')
                    
                response = requests.get(
                    url,
                    headers=DEFAULT_HEADERS,
                    timeout=self.timeout,
                    verify=False
                )
                
                if response.status_code == 200 and response.content:
                    content_type = response.headers.get('Content-Type', '')
                    if 'image' in content_type or 'icon' in content_type or url.endswith('.ico'):
                        favicon_content = response.content
                        favicon_url = url
                        break
            except requests.RequestException:
                continue
        
        if favicon_content:
            results['favicon_found'] = True
            results['favicon_url'] = favicon_url
            
            # Generate favicon hash (MurmurHash)
            try:
                import mmh3
                import base64
                
                # Convert favicon to base64
                b64_favicon = base64.b64encode(favicon_content).decode('utf-8')
                
                # Generate hash
                favicon_hash = mmh3.hash(b64_favicon)
                results['favicon_hash'] = favicon_hash
                
                # Use hash to check common frameworks
                # This is a very limited set of hash mappings for example
                hash_mappings = {
                    -335242539: "Wordpress",
                    2013614628: "Joomla",
                    1913972014: "Drupal",
                    1594232344: "phpMyAdmin",
                    116323821: "Django",
                    1001811429: "Spring Boot",
                    -1395400951: "Tomcat",
                    -1713851588: "jQuery UI",
                    -1090626818: "MediaWiki"
                }
                
                if favicon_hash in hash_mappings:
                    results['matches'].append(hash_mappings[favicon_hash])
                
                # Shodan favicon search URL (for reference)
                results['shodan_url'] = f"https://www.shodan.io/search?query=http.favicon.hash:{favicon_hash}"
                
                self.logger.info(f"Generated favicon hash: {favicon_hash}")
                
            except ImportError:
                self.logger.warning("mmh3 module not available for favicon hash generation")
                results['error'] = "mmh3 module required for favicon hash generation"
            except Exception as e:
                self.logger.error(f"Error generating favicon hash: {str(e)}")
                results['error'] = f"Error: {str(e)}"
        else:
            self.logger.info("No favicon found")
        
        return results
    
    def check_cloud_provider(self) -> Dict[str, Any]:
        """
        Check if the target is hosted on a cloud provider.
        
        Returns:
            dict: Cloud provider detection results
        """
        self.logger.info(f"Checking cloud provider for {self.target}")
        
        results = {
            'target': self.target,
            'is_cloud_hosted': False,
            'provider': None,
            'indicators': []
        }
        
        # Resolve domain to IP if needed
        ip = self.target
        if not self.is_ip:
            try:
                ip = socket.gethostbyname(self.target)
            except socket.gaierror:
                self.logger.error(f"Could not resolve domain {self.target} to IP")
                return {'error': f"Could not resolve domain {self.target} to IP"}
        
        # Get geolocation and ASN info for additional context
        geo_info = None
        asn_info = None
        
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='server_info')
            if cached_results:
                if 'geolocation' in cached_results:
                    geo_info = cached_results['geolocation']
                if 'asn' in cached_results:
                    asn_info = cached_results['asn']
        
        # Cloud provider IP ranges
        # This is a simplified version, real implementation would use more comprehensive data
        cloud_ip_ranges = {
            'AWS': [
                '3.0.0.0/8',     # Various AWS
                '13.32.0.0/12',  # CloudFront
                '13.224.0.0/12', # CloudFront
                '52.0.0.0/8',    # Various AWS
                '54.0.0.0/8',    # Various AWS
                '99.84.0.0/16',  # CloudFront
                '99.86.0.0/16',  # CloudFront
                '108.128.0.0/13', # Various AWS
                '162.250.0.0/16', # AWS
                '172.16.0.0/12',  # AWS
                '204.246.164.0/22', # CloudFront
                '204.246.168.0/22', # CloudFront
                '204.246.174.0/23', # CloudFront
                '204.246.176.0/20', # CloudFront
                '205.251.192.0/19', # CloudFront
                '205.251.249.0/24', # CloudFront
                '205.251.250.0/23', # CloudFront
                '205.251.252.0/23', # CloudFront
                '205.251.254.0/24', # CloudFront
                '216.137.32.0/19', # CloudFront
                '216.182.0.0/16'   # AWS
            ],
            'Google Cloud': [
                '8.8.4.0/24',    # Google DNS
                '8.8.8.0/24',    # Google DNS
                '8.34.208.0/20',  # Google
                '8.35.192.0/20',  # Google
                '34.0.0.0/8',     # Google
                '35.184.0.0/13',  # Google Cloud
                '35.192.0.0/13',  # Google Cloud
                '35.200.0.0/13',  # Google Cloud
                '35.208.0.0/12',  # Google Cloud
                '35.224.0.0/12',  # Google Cloud
                '35.240.0.0/13',  # Google Cloud
                '64.233.160.0/19', # Google
                '66.102.0.0/20',  # Google
                '66.249.64.0/19', # Google
                '70.32.128.0/19', # Google
                '72.14.192.0/18', # Google
                '74.125.0.0/16',  # Google
                '108.177.0.0/17', # Google
                '130.211.0.0/16', # Google Cloud
                '142.250.0.0/15', # Google
                '172.217.0.0/16', # Google
                '173.194.0.0/16', # Google
                '209.85.128.0/17', # Google
                '216.58.192.0/19', # Google
                '216.239.32.0/19'  # Google
            ],
            'Microsoft Azure': [
                '13.64.0.0/11',   # Azure
                '13.96.0.0/13',   # Azure
                '13.104.0.0/14',  # Azure
                '20.33.0.0/16',   # Azure
                '20.34.0.0/15',   # Azure
                '20.36.0.0/14',   # Azure
                '20.40.0.0/13',   # Azure
                '20.48.0.0/12',   # Azure
                '20.64.0.0/10',   # Azure
                '20.128.0.0/16',  # Azure
                '20.135.0.0/16',  # Azure
                '20.136.0.0/16',  # Azure
                '20.140.0.0/15',  # Azure
                '20.143.0.0/16',  # Azure
                '20.144.0.0/14',  # Azure
                '20.150.0.0/15',  # Azure
                '20.152.0.0/16',  # Azure
                '20.153.0.0/16',  # Azure
                '20.157.0.0/16',  # Azure
                '20.158.0.0/15',  # Azure
                '20.160.0.0/12',  # Azure
                '20.176.0.0/14',  # Azure
                '20.180.0.0/14',  # Azure
                '20.184.0.0/13',  # Azure
                '20.192.0.0/10',  # Azure
                '40.64.0.0/10',   # Azure
                '40.74.0.0/15',   # Azure
                '40.76.0.0/14',   # Azure
                '40.80.0.0/12',   # Azure
                '40.96.0.0/12',   # Azure
                '40.112.0.0/13',  # Azure
                '40.120.0.0/14',  # Azure
                '40.124.0.0/16',  # Azure
                '40.125.0.0/17',  # Azure
                '40.126.0.0/18',  # Azure
                '40.127.0.0/18',  # Azure
                '52.96.0.0/12',   # Azure
                '52.112.0.0/14',  # Azure
                '52.120.0.0/14',  # Azure
                '52.125.0.0/16',  # Azure
                '52.126.0.0/15',  # Azure
                '52.132.0.0/14',  # Azure
                '52.136.0.0/13',  # Azure
                '52.144.0.0/12',  # Azure
                '52.160.0.0/11',  # Azure
                '52.224.0.0/11',  # Azure
                '104.40.0.0/13',  # Azure
                '104.146.0.0/15', # Azure
                '104.208.0.0/13',  # Azure
                '157.55.0.0/16',  # Azure
                '157.56.0.0/14',  # Azure
                '168.61.0.0/16',  # Azure
                '168.62.0.0/15',  # Azure
                '191.232.0.0/13', # Azure
                '191.234.32.0/19', # Azure
                '191.236.0.0/14', # Azure
                '191.238.0.0/15'  # Azure
            ],
            'Cloudflare': [
                '104.16.0.0/12',  # Cloudflare
                '104.24.0.0/14',  # Cloudflare
                '108.162.192.0/18', # Cloudflare
                '162.158.0.0/15',  # Cloudflare
                '172.64.0.0/13',   # Cloudflare
                '173.245.48.0/20', # Cloudflare
                '188.114.96.0/20', # Cloudflare
                '190.93.240.0/20', # Cloudflare
                '197.234.240.0/22', # Cloudflare
                '198.41.128.0/17'  # Cloudflare
            ],
            'Digital Ocean': [
                '45.55.0.0/16',    # Digital Ocean
                '64.225.0.0/16',   # Digital Ocean
                '104.131.0.0/16',  # Digital Ocean
                '104.236.0.0/16',  # Digital Ocean
                '128.199.0.0/16',  # Digital Ocean
                '134.122.0.0/16',  # Digital Ocean
                '138.68.0.0/16',   # Digital Ocean
                '139.59.0.0/16',   # Digital Ocean
                '157.230.0.0/16',  # Digital Ocean
                '159.65.0.0/16',   # Digital Ocean
                '159.89.0.0/16',   # Digital Ocean
                '159.203.0.0/16',  # Digital Ocean
                '161.35.0.0/16',   # Digital Ocean
                '162.243.0.0/16',  # Digital Ocean
                '165.227.0.0/16',  # Digital Ocean
                '178.62.0.0/16',   # Digital Ocean
                '192.241.128.0/17', # Digital Ocean
                '198.211.96.0/19'  # Digital Ocean
            ]
        }
        
        # Check if IP is in any cloud provider's range
        for provider, ip_ranges in cloud_ip_ranges.items():
            for ip_range in ip_ranges:
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
                        results['is_cloud_hosted'] = True
                        results['provider'] = provider
                        results['indicators'].append(f"IP {ip} is in {provider} range {ip_range}")
                        break
                except ValueError:
                    continue
            
            if results['is_cloud_hosted']:
                break
        
        # Check ASN information for cloud provider indicators
        if asn_info and not results['is_cloud_hosted']:
            asn_name = asn_info.get('asn_name', '').lower()
            asn_description = asn_info.get('asn_description', '').lower()
            org = asn_info.get('organization', '').lower()
            
            cloud_asn_indicators = {
                'AWS': ['amazon', 'aws', 'amazon web services'],
                'Google Cloud': ['google', 'google cloud', 'gcp'],
                'Microsoft Azure': ['microsoft', 'azure', 'msft'],
                'Cloudflare': ['cloudflare'],
                'Digital Ocean': ['digital ocean', 'digitalocean'],
                'Linode': ['linode'],
                'Heroku': ['heroku', 'salesforce'],
                'OVH': ['ovh'],
                'Hetzner': ['hetzner'],
                'IBM Cloud': ['softlayer', 'ibm cloud', 'ibm'],
                'Oracle Cloud': ['oracle', 'oracle cloud'],
                'Rackspace': ['rackspace'],
                'Alibaba Cloud': ['alibaba', 'aliyun', 'alicloud'],
                'Tencent Cloud': ['tencent'],
                'DigitalRealty': ['digitalrealty'],
                'Akamai': ['akamai']
            }
            
            for provider, indicators in cloud_asn_indicators.items():
                for indicator in indicators:
                    if (indicator in asn_name or 
                        indicator in asn_description or 
                        indicator in org):
                        results['is_cloud_hosted'] = True
                        results['provider'] = provider
                        results['indicators'].append(f"ASN information indicates {provider}: {indicator} found in ASN data")
                        break
                
                if results['is_cloud_hosted']:
                    break
        
        # Check HTTP headers for cloud hosting indicators if we have them
        if not results['is_cloud_hosted']:
            http_headers = {}
            if self.cache_manager:
                cached_results = self.cache_manager.get(self.target, namespace='server_info')
                if cached_results and 'http_headers' in cached_results:
                    http_headers = cached_results['http_headers'].get('headers', {})
            
            header_indicators = {
                'AWS': ['x-amz-', 'aws', 'amazon', 'cloudfront'],
                'Google Cloud': ['x-goog-', 'gcp'],
                'Microsoft Azure': ['azure', 'microsoft-iis'],
                'Cloudflare': ['cf-ray', 'cloudflare'],
                'Akamai': ['akamai', 'akamaighost'],
                'Fastly': ['fastly', 'x-fastly'],
                'Heroku': ['heroku'],
                'DigitalOcean': ['digitalocean'],
                'GitHub Pages': ['github-pages', 'github.io'],
                'Vercel': ['vercel', 'zeit'],
                'Netlify': ['netlify']
            }
            
            for header, value in http_headers.items():
                header_lower = header.lower()
                value_lower = str(value).lower()
                
                for provider, indicators in header_indicators.items():
                    for indicator in indicators:
                        if (indicator in header_lower or 
                            indicator in value_lower):
                            results['is_cloud_hosted'] = True
                            results['provider'] = provider
                            results['indicators'].append(f"HTTP header indicates {provider}: {indicator} found in header {header}")
                            break
                    
                    if results['is_cloud_hosted']:
                        break
                
                if results['is_cloud_hosted']:
                    break
        
        # Final result
        if results['is_cloud_hosted']:
            self.logger.info(f"Target {self.target} appears to be hosted on {results['provider']}")
        else:
            self.logger.info(f"Target {self.target} does not appear to be cloud hosted")
        
        return results
        
    def web_server_fingerprint(self) -> Dict[str, Any]:
        """
        Perform detailed web server fingerprinting to identify server type, version, and architecture.
        
        Returns:
            dict: Web server fingerprint results
        """
        self.logger.info(f"Performing web server fingerprinting for {self.target}")
        
        results = {
            'server_type': None,
            'server_version': None,
            'server_technologies': [],
            'server_os': None,
            'confidence': 0,
            'signature_matches': [],
            'banner_analysis': {},
            'error_page_signatures': []
        }
        
        # List of server signatures to match
        server_signatures = {
            'Apache': {
                'headers': [('Server', r'Apache(?:/(\d+\.\d+\.\d+))?')],
                'error_patterns': [
                    r'<address>Apache(?:/(\d+\.\d+\.\d+))?.+?Server at',
                    r'<title>(\d+) .+ - Apache (?:./(\d+\.\d+\.\d+))?',
                ],
                'technology_indicators': ['PHP', 'mod_perl', 'mod_python', 'OpenSSL']
            },
            'Nginx': {
                'headers': [('Server', r'nginx(?:/(\d+\.\d+\.\d+))?')],
                'error_patterns': [
                    r'<hr><center>nginx(?:/(\d+\.\d+\.\d+))?</center>',
                ],
                'technology_indicators': ['PHP-FPM', 'uWSGI', 'Phusion Passenger']
            },
            'Microsoft-IIS': {
                'headers': [('Server', r'Microsoft-IIS(?:/(\d+\.\d+))?')],
                'error_patterns': [
                    r'<title>\d+ - .+?</title>.+?Microsoft-IIS(?:/(\d+\.\d+))?',
                ],
                'technology_indicators': ['.NET', 'ASP.NET', 'Windows']
            },
            'LiteSpeed': {
                'headers': [('Server', r'LiteSpeed(?:/(\d+\.\d+))?')],
                'error_patterns': [
                    r'<title>LiteSpeed .+?</title>',
                ],
                'technology_indicators': ['PHP', 'LiteSpeed Cache']
            },
            'Tomcat': {
                'headers': [
                    ('Server', r'Apache Tomcat(?:/(\d+\.\d+\.\d+))?'),
                    ('X-Powered-By', r'Apache Tomcat(?:/(\d+\.\d+\.\d+))?')
                ],
                'error_patterns': [
                    r'<title>Apache Tomcat(?:/(\d+\.\d+\.\d+))?.+?Error Report</title>',
                ],
                'technology_indicators': ['Java', 'JSP', 'Servlet']
            },
            'Lighttpd': {
                'headers': [('Server', r'lighttpd(?:/(\d+\.\d+\.\d+))?')],
                'error_patterns': [
                    r'<title>\d+ .+?</title>.+?lighttpd',
                ],
                'technology_indicators': ['PHP', 'FastCGI']
            },
            'Caddy': {
                'headers': [('Server', r'Caddy')],
                'error_patterns': [],
                'technology_indicators': ['Go']
            }
        }
        
        # First, check headers from cached results
        headers_result = None
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='server_info')
            if cached_results and 'http_headers' in cached_results:
                headers_result = cached_results['http_headers']
        
        if headers_result and 'headers' in headers_result:
            headers = headers_result['headers']
            results['banner_analysis']['server_header'] = headers.get('Server', 'Not disclosed')
            
            # Check for server type and version in headers
            for server_type, signature in server_signatures.items():
                for header_name, pattern in signature['headers']:
                    if header_name in headers:
                        match = re.search(pattern, headers[header_name], re.IGNORECASE)
                        if match:
                            results['server_type'] = server_type
                            if match.groups() and match.group(1):
                                results['server_version'] = match.group(1)
                            results['confidence'] = 85
                            results['signature_matches'].append(f"Header match: {header_name}: {headers[header_name]}")
                            break
                
                # Look for technology indicators
                for tech in signature['technology_indicators']:
                    for header_value in headers.values():
                        if isinstance(header_value, str) and tech.lower() in header_value.lower():
                            if tech not in results['server_technologies']:
                                results['server_technologies'].append(tech)
        
        # Try to fetch an error page to analyze signatures
        if not results['server_type'] or results['confidence'] < 90:
            try:
                # Request a non-existent page to trigger an error
                error_url = normalize_url(self.target) + "/non_existent_page_" + str(int(time.time()))
                
                if self.rate_limiter:
                    self.rate_limiter.wait('http')
                    
                error_response = requests.get(
                    error_url,
                    headers=DEFAULT_HEADERS,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False
                )
                
                # Check error page content for server signatures
                for server_type, signature in server_signatures.items():
                    for pattern in signature['error_patterns']:
                        match = re.search(pattern, error_response.text, re.IGNORECASE | re.DOTALL)
                        if match:
                            # Found server signature in error page
                            results['server_type'] = server_type
                            if match.groups() and match.group(1) and not results['server_version']:
                                results['server_version'] = match.group(1)
                            results['confidence'] = 95
                            results['error_page_signatures'].append(pattern)
                            break
            
            except requests.RequestException as e:
                self.logger.warning(f"Error fetching error page: {str(e)}")
        
        # Try to determine OS based on collected information
        if results['server_type']:
            if results['server_type'] == 'Microsoft-IIS':
                results['server_os'] = 'Windows'
            elif results['server_type'] in ['Apache', 'Nginx', 'LiteSpeed', 'Lighttpd']:
                # Look for OS indicators in headers
                headers_str = str(headers_result).lower() if headers_result else ""
                if 'win' in headers_str or 'windows' in headers_str:
                    results['server_os'] = 'Windows'
                elif 'debian' in headers_str or 'ubuntu' in headers_str:
                    results['server_os'] = 'Linux (Debian/Ubuntu)'
                elif 'centos' in headers_str or 'rhel' in headers_str or 'fedora' in headers_str:
                    results['server_os'] = 'Linux (CentOS/RHEL)'
                elif 'unix' in headers_str or 'linux' in headers_str:
                    results['server_os'] = 'Unix/Linux'
                elif 'freebsd' in headers_str:
                    results['server_os'] = 'FreeBSD'
                else:
                    results['server_os'] = 'Unix/Linux (Probable)'
        
        # Add summary
        if results['server_type']:
            server_desc = f"{results['server_type']}"
            if results['server_version']:
                server_desc += f" {results['server_version']}"
            if results['server_os']:
                server_desc += f" on {results['server_os']}"
            
            results['summary'] = server_desc
            
            self.logger.info(f"Identified web server: {server_desc} (confidence: {results['confidence']}%)")
        else:
            results['summary'] = "Unknown server"
            self.logger.info(f"Could not identify web server type")
            
        return results
        
    def analyze_http_security(self) -> Dict[str, Any]:
        """
        Perform a comprehensive HTTP security analysis of the target.
        
        Returns:
            dict: HTTP security analysis results
        """
        self.logger.info(f"Analyzing HTTP security for {self.target}")
        
        results = {
            'security_grade': 'F',
            'summary': '',
            'issues': [],
            'recommendations': [],
            'security_headers': {},
            'security_scores': {},
            'content_security': {},
            'ssl_security': {},
            'cookie_security': {}
        }
        
        # Security headers to check
        required_security_headers = {
            'Strict-Transport-Security': {
                'weight': 5,
                'description': 'HTTP Strict Transport Security (HSTS)',
                'recommended': 'max-age=31536000; includeSubDomains; preload',
                'validator': lambda v: 'max-age=' in v and int(re.search(r'max-age=(\d+)', v).group(1)) >= 15768000
            },
            'Content-Security-Policy': {
                'weight': 5,
                'description': 'Content Security Policy (CSP)',
                'recommended': "default-src 'self'; script-src 'self'; object-src 'none'; img-src 'self'",
                'validator': lambda v: "default-src" in v and "'unsafe-inline'" not in v
            },
            'X-Frame-Options': {
                'weight': 3,
                'description': 'X-Frame-Options (prevents clickjacking)',
                'recommended': 'DENY or SAMEORIGIN',
                'validator': lambda v: v.upper() in ['DENY', 'SAMEORIGIN']
            },
            'X-Content-Type-Options': {
                'weight': 3,
                'description': 'X-Content-Type-Options (prevents MIME sniffing)',
                'recommended': 'nosniff',
                'validator': lambda v: v.lower() == 'nosniff'
            },
            'Referrer-Policy': {
                'weight': 2,
                'description': 'Referrer Policy',
                'recommended': 'no-referrer, same-origin, or strict-origin',
                'validator': lambda v: v.lower() in ['no-referrer', 'no-referrer-when-downgrade', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin']
            },
            'X-XSS-Protection': {
                'weight': 2,
                'description': 'X-XSS-Protection',
                'recommended': '1; mode=block',
                'validator': lambda v: v == '1; mode=block'
            },
            'Feature-Policy': {
                'weight': 1,
                'description': 'Feature Policy (or Permissions Policy)',
                'recommended': "camera 'none'; microphone 'none'; geolocation 'self'",
                'validator': lambda v: len(v) > 20  # Basic check that it's non-trivial
            },
            'Permissions-Policy': {
                'weight': 1,
                'description': 'Permissions Policy (modern replacement for Feature-Policy)',
                'recommended': "camera=(), microphone=(), geolocation=(self)",
                'validator': lambda v: len(v) > 20  # Basic check that it's non-trivial
            }
        }
        
        # Check headers from cached results
        headers_result = None
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='server_info')
            if cached_results and 'http_headers' in cached_results:
                headers_result = cached_results['http_headers']
        
        if not headers_result:
            self.logger.warning("No HTTP headers found in cache, security analysis may be incomplete")
            results['issues'].append("No HTTP headers available for analysis")
            return results
        
        headers = headers_result.get('headers', {})
        cookies = headers_result.get('cookies', {})
        is_https = headers_result.get('url', '').startswith('https')
        
        # Analyze security headers
        total_score = 0
        total_weight = 0
        
        for header, details in required_security_headers.items():
            weight = details['weight']
            total_weight += weight
            
            # Check if header exists and validate its value
            if header in headers:
                value = headers[header]
                try:
                    valid = details['validator'](value)
                except Exception:
                    valid = False
                
                results['security_headers'][header] = {
                    'present': True,
                    'value': value,
                    'valid': valid,
                    'description': details['description'],
                    'recommended': details['recommended']
                }
                
                if valid:
                    score = weight
                    results['security_scores'][header] = weight
                else:
                    score = weight / 2  # Partial credit for having the header but invalid value
                    results['security_scores'][header] = weight / 2
                    results['issues'].append(f"{header} is present but has an invalid/weak value")
                    results['recommendations'].append(f"Update {header} to a stronger value like: {details['recommended']}")
            else:
                results['security_headers'][header] = {
                    'present': False,
                    'value': None,
                    'valid': False,
                    'description': details['description'],
                    'recommended': details['recommended']
                }
                
                score = 0
                results['security_scores'][header] = 0
                results['issues'].append(f"Missing {header} header")
                results['recommendations'].append(f"Add {header} header with value: {details['recommended']}")
            
            total_score += score
        
        # Analyze cookies for security settings
        if cookies:
            results['cookie_security'] = {
                'cookie_count': len(cookies),
                'secure_cookies': 0,
                'httponly_cookies': 0,
                'samesite_cookies': 0,
                'insecure_cookies': []
            }
            
            for cookie_name, cookie in cookies.items():
                secure = cookie.get('secure', False)
                httponly = cookie.get('httponly', False)
                samesite = cookie.get('samesite', None)
                
                if secure:
                    results['cookie_security']['secure_cookies'] += 1
                if httponly:
                    results['cookie_security']['httponly_cookies'] += 1
                if samesite and samesite.lower() in ['strict', 'lax']:
                    results['cookie_security']['samesite_cookies'] += 1
                
                if not secure or not httponly:
                    results['cookie_security']['insecure_cookies'].append({
                        'name': cookie_name,
                        'secure': secure,
                        'httponly': httponly,
                        'samesite': samesite
                    })
            
            # Add cookie issues
            if len(results['cookie_security']['insecure_cookies']) > 0:
                results['issues'].append(f"Found {len(results['cookie_security']['insecure_cookies'])} cookies with insecure settings")
                results['recommendations'].append("Set 'Secure', 'HttpOnly', and 'SameSite=Strict' for all cookies")
            
            # Adjust score based on cookie security
            cookie_score = 0
            if results['cookie_security']['cookie_count'] > 0:
                secure_ratio = results['cookie_security']['secure_cookies'] / results['cookie_security']['cookie_count']
                httponly_ratio = results['cookie_security']['httponly_cookies'] / results['cookie_security']['cookie_count']
                
                cookie_score = (secure_ratio + httponly_ratio) * 5  # Max 10 points for cookies
                total_score += cookie_score
                total_weight += 10
                
                results['security_scores']['cookie_security'] = cookie_score
        
        # Check if using HTTPS
        if is_https:
            total_score += 10
            results['security_scores']['https'] = 10
        else:
            results['issues'].append("Site is not using HTTPS")
            results['recommendations'].append("Migrate to HTTPS and enforce it with HSTS")
            results['security_scores']['https'] = 0
        
        total_weight += 10  # Add HTTPS weight
        
        # Calculate security grade
        if total_weight > 0:
            normalized_score = (total_score / total_weight) * 100
            
            if normalized_score >= 90:
                grade = 'A+'
            elif normalized_score >= 85:
                grade = 'A'
            elif normalized_score >= 80:
                grade = 'A-'
            elif normalized_score >= 75:
                grade = 'B+'
            elif normalized_score >= 70:
                grade = 'B'
            elif normalized_score >= 65:
                grade = 'B-'
            elif normalized_score >= 60:
                grade = 'C+'
            elif normalized_score >= 55:
                grade = 'C'
            elif normalized_score >= 50:
                grade = 'C-'
            elif normalized_score >= 45:
                grade = 'D+'
            elif normalized_score >= 40:
                grade = 'D'
            elif normalized_score >= 35:
                grade = 'D-'
            else:
                grade = 'F'
                
            results['security_grade'] = grade
            results['score'] = normalized_score
        
        # Summarize findings
        results['summary'] = f"Security Grade: {results['security_grade']} ({len(results['issues'])} issues found)"
        
        self.logger.info(f"HTTP security analysis completed: Grade {results['security_grade']}")
        
        return results
        
    def analyze_cors_policy(self) -> Dict[str, Any]:
        """
        Analyze Cross-Origin Resource Sharing (CORS) policy.
        
        Returns:
            dict: CORS policy analysis results
        """
        self.logger.info(f"Analyzing CORS policy for {self.target}")
        
        results = {
            'has_cors': False,
            'wildcard_origin': False,
            'allows_credentials': False,
            'allowed_origins': [],
            'allowed_methods': [],
            'allowed_headers': [],
            'exposed_headers': [],
            'max_age': None,
            'issues': [],
            'recommendations': []
        }
        
        # Check headers from cached results
        headers_result = None
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='server_info')
            if cached_results and 'http_headers' in cached_results:
                headers_result = cached_results['http_headers']
        
        if not headers_result:
            self.logger.warning("No HTTP headers found in cache, CORS analysis may be incomplete")
            return results
        
        headers = headers_result.get('headers', {})
        
        # Check for CORS headers
        cors_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers',
            'Access-Control-Allow-Credentials',
            'Access-Control-Expose-Headers',
            'Access-Control-Max-Age'
        ]
        
        for header in cors_headers:
            if header in headers:
                results['has_cors'] = True
                break
        
        if not results['has_cors']:
            # Try to get CORS headers by sending an OPTIONS request with origin header
            try:
                url = normalize_url(self.target)
                
                if self.rate_limiter:
                    self.rate_limiter.wait('http')
                    
                options_headers = DEFAULT_HEADERS.copy()
                options_headers['Origin'] = 'https://example.com'
                options_headers['Access-Control-Request-Method'] = 'GET'
                options_headers['Access-Control-Request-Headers'] = 'Content-Type'
                
                options_response = requests.options(
                    url,
                    headers=options_headers,
                    timeout=self.timeout,
                    verify=False
                )
                
                # Check if we received CORS headers in response
                options_headers = options_response.headers
                for header in cors_headers:
                    if header in options_headers:
                        results['has_cors'] = True
                        headers[header] = options_headers[header]
                        break
            
            except requests.RequestException as e:
                self.logger.warning(f"Error sending OPTIONS request: {str(e)}")
        
        if not results['has_cors']:
            self.logger.info(f"No CORS policy detected for {self.target}")
            return results
        
        # Analyze Allow-Origin
        if 'Access-Control-Allow-Origin' in headers:
            origin = headers['Access-Control-Allow-Origin']
            if origin == '*':
                results['wildcard_origin'] = True
                results['issues'].append("Wildcard CORS origin (*) allows any domain to make cross-origin requests")
                results['recommendations'].append("Limit CORS to specific trusted domains instead of using a wildcard")
            elif origin:
                results['allowed_origins'] = [origin.strip() for origin in origin.split(',')]
        
        # Analyze Allow-Credentials
        if 'Access-Control-Allow-Credentials' in headers:
            creds = headers['Access-Control-Allow-Credentials'].lower()
            if creds == 'true':
                results['allows_credentials'] = True
                
                if results['wildcard_origin']:
                    results['issues'].append("Allowing credentials with a wildcard origin is a serious security risk")
                    results['recommendations'].append("Never use wildcard origins when allowing credentials")
        
        # Analyze Allow-Methods
        if 'Access-Control-Allow-Methods' in headers:
            methods = headers['Access-Control-Allow-Methods']
            results['allowed_methods'] = [m.strip() for m in methods.split(',')]
            
            sensitive_methods = ['PUT', 'DELETE', 'PATCH']
            allowed_sensitive = [m for m in results['allowed_methods'] if m in sensitive_methods]
            
            if allowed_sensitive:
                results['issues'].append(f"CORS policy allows sensitive HTTP methods: {', '.join(allowed_sensitive)}")
                results['recommendations'].append("Limit CORS methods to only those required by your application")
        
        # Analyze Allow-Headers
        if 'Access-Control-Allow-Headers' in headers:
            header_list = headers['Access-Control-Allow-Headers']
            if header_list == '*':
                results['issues'].append("Wildcard CORS allowed headers (*) may expose sensitive headers")
                results['recommendations'].append("Explicitly specify which headers are allowed for CORS")
            else:
                results['allowed_headers'] = [h.strip() for h in header_list.split(',')]
        
        # Analyze Expose-Headers
        if 'Access-Control-Expose-Headers' in headers:
            exposed = headers['Access-Control-Expose-Headers']
            results['exposed_headers'] = [h.strip() for h in exposed.split(',')]
            
            sensitive_headers = ['Authorization', 'X-API-Key', 'Cookie', 'Set-Cookie']
            exposed_sensitive = [h for h in results['exposed_headers'] if any(s.lower() in h.lower() for s in sensitive_headers)]
            
            if exposed_sensitive:
                results['issues'].append(f"CORS exposes potentially sensitive headers: {', '.join(exposed_sensitive)}")
                results['recommendations'].append("Avoid exposing sensitive headers via CORS")
        
        # Analyze Max-Age
        if 'Access-Control-Max-Age' in headers:
            try:
                max_age = int(headers['Access-Control-Max-Age'])
                results['max_age'] = max_age
                
                # Extremely long cache times may prevent security updates from applying quickly
                if max_age > 86400:  # 24 hours
                    results['issues'].append(f"Long CORS max age ({max_age} seconds) may delay security updates")
                    results['recommendations'].append("Consider using a shorter max age value (86400 seconds or less)")
            except ValueError:
                pass
        
        # Add summary
        origin_desc = "wildcard (*)" if results['wildcard_origin'] else ", ".join(results['allowed_origins'] or ["Not specified"])
        creds_desc = "Yes" if results['allows_credentials'] else "No"
        
        results['summary'] = f"CORS policy allows origins: {origin_desc} (with credentials: {creds_desc})"
        
        if not results['issues']:
            results['issues'].append("No major CORS security issues detected")
        
        self.logger.info(f"CORS analysis completed: {len(results['issues'])} issues found")
        
        return results
        
    def detect_firewall(self) -> Dict[str, Any]:
        """
        Attempt to detect web application firewalls or security solutions in place.
        
        Returns:
            dict: Firewall detection results
        """
        self.logger.info(f"Detecting web application firewalls for {self.target}")
        
        results = {
            'firewall_detected': False,
            'firewall_type': None,
            'confidence': 0,
            'indicators': [],
            'detection_methods': [],
            'evasion_complexity': 'Unknown'
        }
        
        # Firewall signature patterns
        firewall_signatures = {
            'Cloudflare': {
                'headers': [
                    ('CF-RAY', r'.+'),
                    ('Server', r'cloudflare'),
                    ('CF-Cache-Status', r'.+')
                ],
                'cookies': ['__cfduid', '__cf_bm', 'cf_clearance'],
                'blocks': [
                    'cloudflare', 'attention required', 'captcha',
                    'ray id:', 'sorry, you have been blocked',
                    'your browser is being managed'
                ],
                'complexity': 'High'
            },
            'AWS WAF': {
                'headers': [
                    ('X-AMZ-CF-ID', r'.+'),
                    ('X-AMZ-ID', r'.+')
                ],
                'cookies': [],
                'blocks': [
                    'aws', 'waf', 'request blocked',
                    'access denied by aws'
                ],
                'complexity': 'High'
            },
            'Akamai': {
                'headers': [
                    ('X-Akamai-Transformed', r'.+'),
                    ('Akamai-Origin-Hop', r'.+'),
                    ('Server', r'AkamaiGHost')
                ],
                'cookies': ['akacd_', 'ak_bmsc', 'akauid'],
                'blocks': [],
                'complexity': 'Very High'
            },
            'ModSecurity': {
                'headers': [
                    ('Server', r'(apache|nginx).+modsecurity'),
                    ('X-Mod-Security', r'.+')
                ],
                'cookies': [],
                'blocks': [
                    'mod_security', 'not acceptable', 'access denied',
                    'blocked by mod_security', 'application firewall error'
                ],
                'complexity': 'Medium'
            },
            'Sucuri': {
                'headers': [
                    ('X-Sucuri-ID', r'.+'),
                    ('X-Sucuri-Cache', r'.+'),
                    ('Server', r'Sucuri')
                ],
                'cookies': ['sucuri_cloudproxy_uuid'],
                'blocks': [
                    'sucuri website firewall', 'access denied - sucuri',
                    'website firewall access rules', 'protected by sucuri'
                ],
                'complexity': 'Medium'
            },
            'Imperva/Incapsula': {
                'headers': [
                    ('X-Iinfo', r'.+'),
                    ('X-CDN', r'Incapsula'),
                    ('Set-Cookie', r'incap_ses_')
                ],
                'cookies': ['incap_ses_', 'visid_incap_'],
                'blocks': [
                    'incapsula', 'imperva', 'blocked or limited',
                    'contact site owner', 'further action is required'
                ],
                'complexity': 'High'
            },
            'F5 BIG-IP ASM': {
                'headers': [
                    ('Server', r'BIG-IP'),
                    ('Via', r'BIG-IP')
                ],
                'cookies': ['BIGipServer', 'F5_fullWT', 'F5_ST', 'TS'],
                'blocks': [
                    'the requested url was rejected', 'please consult with your administrator',
                    'your support id is', 'request rejected by big-ip'
                ],
                'complexity': 'Medium'
            },
            'Barracuda': {
                'headers': [
                    ('Server', r'Barracuda.+WAF'),
                    ('X-Barracuda', r'.+')
                ],
                'cookies': ['barra_counter_session'],
                'blocks': [
                    'barracuda', 'you are attempting to access a forbidden site',
                    'access denied by security policy'
                ],
                'complexity': 'Medium'
            },
            'Fortinet FortiWeb': {
                'headers': [
                    ('Set-Cookie', r'FORTIWAFSID=')
                ],
                'cookies': ['FORTIWAFSID'],
                'blocks': [
                    'fortinet', 'fortigate', 'fortiweb', 'application has encountered an error'
                ],
                'complexity': 'Medium'
            }
        }
        
        # Get HTTP headers from cached results
        headers_result = None
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='server_info')
            if cached_results and 'http_headers' in cached_results:
                headers_result = cached_results['http_headers']
        
        if headers_result and 'headers' in headers_result:
            headers = headers_result['headers']
            cookies = headers_result.get('cookies', {})
            
            # Check for firewall signatures in headers
            for firewall, sig in firewall_signatures.items():
                # Check headers
                for header_name, pattern in sig['headers']:
                    if header_name in headers and re.search(pattern, str(headers[header_name]), re.IGNORECASE):
                        results['firewall_detected'] = True
                        results['firewall_type'] = firewall
                        results['confidence'] = 85
                        results['indicators'].append(f"Header match: {header_name}: {headers[header_name]}")
                        results['evasion_complexity'] = sig['complexity']
                        break
                
                # Check cookies
                for cookie_name in sig['cookies']:
                    if cookie_name in cookies or any(cookie_name.lower() in c.lower() for c in cookies):
                        results['firewall_detected'] = True
                        results['firewall_type'] = firewall if not results['firewall_type'] else results['firewall_type']
                        results['confidence'] = max(results['confidence'], 80)
                        results['indicators'].append(f"Cookie match: {cookie_name}")
                        results['evasion_complexity'] = sig['complexity']
                        break
                
                if results['firewall_detected'] and results['firewall_type'] == firewall:
                    break
        
        # If no firewall detected with passive means, try active detection
        if not results['firewall_detected']:
            results['detection_methods'].append("Active probing")
            
            # URLs to check
            test_paths = [
                "/?param=<script>alert(1)</script>",  # Basic XSS
                "/?param=../../../../../etc/passwd",   # Directory traversal
                "/?param=1 OR 1=1",                   # SQL injection
                "/?param=eval(alert(1))",             # Code injection
                "/wp-login.php",                      # CMS probing
                "/.env"                               # Sensitive file
            ]
            
            block_responses = []
            
            # Send test requests
            base_url = normalize_url(self.target)
            
            for path in test_paths:
                try:
                    if self.rate_limiter:
                        self.rate_limiter.wait('http')
                        
                    response = requests.get(
                        base_url + path,
                        headers=DEFAULT_HEADERS,
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False
                    )
                    
                    # Status codes common for WAF blocks (403, 406, 429, 503)
                    if response.status_code in [403, 406, 429, 503]:
                        block_responses.append((path, response))
                    
                    # Check response body for firewall blocks
                    for firewall, sig in firewall_signatures.items():
                        for block_text in sig['blocks']:
                            if block_text in response.text.lower():
                                results['firewall_detected'] = True
                                results['firewall_type'] = firewall
                                results['confidence'] = 90
                                results['indicators'].append(f"Block text match: {block_text}")
                                results['evasion_complexity'] = sig['complexity']
                                break
                        
                        if results['firewall_detected']:
                            break
                
                except requests.RequestException:
                    # Connection errors might indicate firewall blocking
                    continue
                
                if results['firewall_detected']:
                    break
            
            # If multiple paths were blocked but we couldn't identify the specific firewall
            if not results['firewall_detected'] and len(block_responses) >= 2:
                results['firewall_detected'] = True
                results['firewall_type'] = "Unknown WAF"
                results['confidence'] = 70
                for path, response in block_responses:
                    results['indicators'].append(f"Blocked request to {path} (Status: {response.status_code})")
                results['evasion_complexity'] = "Unknown"
        
        if results['firewall_detected']:
            self.logger.info(f"Detected firewall: {results['firewall_type']} (confidence: {results['confidence']}%)")
            
            # Add summary
            results['summary'] = f"Detected {results['firewall_type']} firewall with {results['confidence']}% confidence"
        else:
            self.logger.info(f"No web application firewall detected for {self.target}")
            
            # Add summary
            results['summary'] = "No web application firewall detected"
            
        return results
    
    def detect_cdn(self) -> Dict[str, Any]:
        """
        Detect if the target is using a Content Delivery Network (CDN).
        
        Returns:
            dict: CDN detection results
        """
        self.logger.info(f"Detecting CDN for {self.target}")
        
        results = {
            'cdn_detected': False,
            'cdn_provider': None,
            'confidence': 0,
            'indicators': []
        }
        
        # CDN signature patterns
        cdn_signatures = {
            'Cloudflare': {
                'headers': [
                    ('CF-RAY', r'.+'),
                    ('Server', r'cloudflare'),
                    ('CF-Cache-Status', r'.+')
                ],
                'dns_indicators': ['cloudflare.com', 'cloudflare.net'],
                'cname_indicators': ['cloudflare.com', 'cloudflare.net']
            },
            'Akamai': {
                'headers': [
                    ('X-Akamai-Transformed', r'.+'),
                    ('Server', r'AkamaiGHost'),
                    ('X-Akamai-SSL-Client-Sid', r'.+')
                ],
                'dns_indicators': ['akamai.net', 'edgekey.net', 'edgesuite.net'],
                'cname_indicators': ['akamai.net', 'edgekey.net', 'edgesuite.net']
            },
            'Fastly': {
                'headers': [
                    ('Fastly-Debug-Digest', r'.+'),
                    ('X-Served-By', r'cache.+'),
                    ('X-Cache', r'.+'),
                    ('X-Cache-Hits', r'.+')
                ],
                'dns_indicators': ['fastly.net'],
                'cname_indicators': ['fastly.net']
            },
            'Amazon CloudFront': {
                'headers': [
                    ('X-Amz-Cf-Id', r'.+'),
                    ('X-Amz-Cf-Pop', r'.+'),
                    ('Via', r'.+cloudfront.net')
                ],
                'dns_indicators': ['cloudfront.net'],
                'cname_indicators': ['cloudfront.net']
            },
            'KeyCDN': {
                'headers': [
                    ('X-Edge-Location', r'.+'),
                    ('Server', r'keycdn.+'),
                    ('X-Edge', r'.+')
                ],
                'dns_indicators': ['kxcdn.com'],
                'cname_indicators': ['kxcdn.com']
            },
            'Imperva/Incapsula': {
                'headers': [
                    ('X-Iinfo', r'.+'),
                    ('X-CDN', r'Incapsula')
                ],
                'dns_indicators': ['incapdns.net'],
                'cname_indicators': ['incapdns.net']
            },
            'Sucuri': {
                'headers': [
                    ('X-Sucuri-ID', r'.+'),
                    ('X-Sucuri-Cache', r'.+'),
                    ('Server', r'Sucuri')
                ],
                'dns_indicators': ['sucuri.net'],
                'cname_indicators': ['sucuri.net']
            },
            'Limelight Networks': {
                'headers': [
                    ('X-Limelight-Purge-Id', r'.+')
                ],
                'dns_indicators': ['limelight.com', 'lldns.net'],
                'cname_indicators': ['limelight.com', 'lldns.net']
            }
        }
        
        # Get HTTP headers from cached results
        headers_result = None
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='server_info')
            if cached_results and 'http_headers' in cached_results:
                headers_result = cached_results['http_headers']
        
        if headers_result and 'headers' in headers_result:
            headers = headers_result['headers']
            
            # Check for CDN signatures in headers
            for cdn, sig in cdn_signatures.items():
                for header_name, pattern in sig['headers']:
                    if header_name in headers and re.search(pattern, str(headers[header_name]), re.IGNORECASE):
                        results['cdn_detected'] = True
                        results['cdn_provider'] = cdn
                        results['confidence'] = 95
                        results['indicators'].append(f"Header match: {header_name}: {headers[header_name]}")
                        break
                
                if results['cdn_detected'] and results['cdn_provider'] == cdn:
                    break
        
        # If no CDN detected, check DNS records
        if not results['cdn_detected'] and not self.is_ip:
            try:
                # Check CNAME records
                dns_result = None
                if self.cache_manager:
                    cached_results = self.cache_manager.get(self.target, namespace='dns_info')
                    if cached_results and 'dns_records' in cached_results:
                        dns_result = cached_results['dns_records']
                
                if dns_result and 'CNAME' in dns_result:
                    cname_records = dns_result['CNAME']
                    
                    for cdn, sig in cdn_signatures.items():
                        for cname in cname_records:
                            for indicator in sig['cname_indicators']:
                                if indicator.lower() in str(cname).lower():
                                    results['cdn_detected'] = True
                                    results['cdn_provider'] = cdn
                                    results['confidence'] = 90
                                    results['indicators'].append(f"CNAME match: {cname} contains {indicator}")
                                    break
                            
                            if results['cdn_detected']:
                                break
                        
                        if results['cdn_detected']:
                            break
            
            except Exception as e:
                self.logger.warning(f"Error checking DNS records for CDN: {str(e)}")
        
        # Check for multiple IP addresses
        if not results['cdn_detected'] and not self.is_ip:
            try:
                ips = socket.gethostbyname_ex(self.target)[2]
                
                if len(ips) > 1:
                    results['cdn_detected'] = True
                    results['cdn_provider'] = "Unknown CDN"
                    results['confidence'] = 60
                    results['indicators'].append(f"Multiple IP addresses: {', '.join(ips)}")
            except socket.gaierror:
                pass
        
        if results['cdn_detected']:
            self.logger.info(f"Detected CDN: {results['cdn_provider']} (confidence: {results['confidence']}%)")
            
            # Add summary
            provider = results['cdn_provider']
            results['summary'] = f"Detected {provider} CDN with {results['confidence']}% confidence"
        else:
            self.logger.info(f"No CDN detected for {self.target}")
            
            # Add summary
            results['summary'] = "No CDN detected"
            
        return results
    
    def check_server_vulnerabilities(self) -> Dict[str, Any]:
        """
        Check for known server vulnerabilities based on detected software and versions.
        
        Returns:
            dict: Server vulnerability check results
        """
        self.logger.info(f"Checking for server vulnerabilities for {self.target}")
        
        results = {
            'vulnerabilities': [],
            'cve_count': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'security_notices': []
        }
        
        # Get server info from cached results
        server_result = None
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='server_info')
            if cached_results and 'server_fingerprint' in cached_results:
                server_result = cached_results['server_fingerprint']
            elif cached_results and 'http_headers' in cached_results and 'headers' in cached_results['http_headers'] and 'Server' in cached_results['http_headers']['headers']:
                # Create a basic server fingerprint from the Server header
                server = cached_results['http_headers']['headers']['Server']
                server_version = None
                
                # Try to extract the version from the Server header
                match = re.search(r'([a-zA-Z]+)(?:/|\s+)(\d+\.\d+\.?\d*)', str(server))
                if match:
                    server_type = match.group(1)
                    server_version = match.group(2)
                    
                    server_result = {
                        'server_type': server_type,
                        'server_version': server_version
                    }
        
        # Only proceed if we have a server type and version
        if not server_result or not server_result.get('server_type') or not server_result.get('server_version'):
            self.logger.warning("Not enough server information to check for vulnerabilities")
            results['security_notices'].append("Server version information not available or hidden (good security practice)")
            return results
        
        server_type = server_result['server_type'].lower()
        server_version = server_result['server_version']
        
        # Known vulnerabilities database (simplified for common server types)
        # In a real implementation, this would connect to a CVE database or use an API
        vulnerabilities_db = {
            'apache': {
                '2.4.49': [
                    {
                        'cve_id': 'CVE-2021-41773',
                        'severity': 'critical',
                        'title': 'Path Traversal and Remote Code Execution Vulnerability',
                        'description': 'A path traversal attack in Apache HTTP Server 2.4.49 allows attackers to access files outside the document root.',
                        'recommendation': 'Upgrade to Apache 2.4.50 or later.'
                    }
                ],
                '2.4.50': [
                    {
                        'cve_id': 'CVE-2021-42013',
                        'severity': 'critical',
                        'title': 'Path Traversal Vulnerability',
                        'description': 'The fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient, allowing attackers to use a different variant to conduct path traversal attacks.',
                        'recommendation': 'Upgrade to Apache 2.4.51 or later.'
                    }
                ]
            },
            'nginx': {
                '1.20.0': [
                    {
                        'cve_id': 'CVE-2021-23017',
                        'severity': 'high',
                        'title': 'Nginx Resolver DoS Vulnerability',
                        'description': 'A vulnerability in the DNS resolver in Nginx before 1.20.1 allows attackers to cause a denial of service via a crafted DNS response.',
                        'recommendation': 'Upgrade to Nginx 1.20.1 or later.'
                    }
                ]
            },
            'microsoft-iis': {
                '7.5': [
                    {
                        'cve_id': 'CVE-2010-3972',
                        'severity': 'high',
                        'title': 'IIS FTP Service NLST Command Vulnerability',
                        'description': 'Buffer overflow in the FTP service in IIS 7.5 allows remote attackers to execute arbitrary code via a crafted NLST command.',
                        'recommendation': 'Apply Microsoft security patch or disable the FTP service if not needed.'
                    }
                ]
            }
        }
        
        # Check for exact version match
        if server_type in vulnerabilities_db and server_version in vulnerabilities_db[server_type]:
            for vuln in vulnerabilities_db[server_type][server_version]:
                results['vulnerabilities'].append(vuln)
                results['cve_count'] += 1
                
                if vuln['severity'] == 'critical':
                    results['critical_count'] += 1
                elif vuln['severity'] == 'high':
                    results['high_count'] += 1
                elif vuln['severity'] == 'medium':
                    results['medium_count'] += 1
        
        # Add security notice based on detected server
        if server_type == 'apache' and server_version < '2.4.51':
            results['security_notices'].append(f"Apache HTTP Server versions below 2.4.51 may be vulnerable to path traversal attacks")
        elif server_type == 'nginx' and server_version < '1.20.1':
            results['security_notices'].append(f"Nginx versions below 1.20.1 may be vulnerable to DNS resolver DoS attacks")
        elif server_type == 'microsoft-iis' and server_version < '10.0':
            results['security_notices'].append(f"Older versions of IIS may contain known security vulnerabilities")
        
        # Check for server version exposure
        if server_result and 'server_version' in server_result and server_result['server_version']:
            results['security_notices'].append("Server version is exposed in headers, which provides information to potential attackers")
        
        # Add a generic notice if no specific vulnerabilities found
        if not results['vulnerabilities'] and not results['security_notices']:
            results['security_notices'].append(f"No known critical vulnerabilities found for {server_type} {server_version}")
        
        # Add summary
        results['summary'] = f"Found {results['cve_count']} vulnerabilities ({results['critical_count']} critical, {results['high_count']} high)"
        
        self.logger.info(f"Vulnerability check completed: {results['cve_count']} vulnerabilities found")
        
        return results
    
    def analyze_response_time(self) -> Dict[str, Any]:
        """
        Analyze server response time performance.
        
        Returns:
            dict: Response time analysis results
        """
        self.logger.info(f"Analyzing response time for {self.target}")
        
        results = {
            'average_response_time': 0,
            'min_response_time': 0,
            'max_response_time': 0,
            'response_times': [],
            'performance_rating': None,
            'recommendations': []
        }
        
        # Number of requests to make
        num_requests = 3
        
        # Normalize URL
        url = normalize_url(self.target)
        
        try:
            # Make multiple requests to get average response time
            for i in range(num_requests):
                if self.rate_limiter:
                    self.rate_limiter.wait('http')
                
                start_time = time.time()
                response = requests.get(
                    url,
                    headers=DEFAULT_HEADERS,
                    timeout=self.timeout,
                    verify=False
                )
                end_time = time.time()
                
                response_time = (end_time - start_time) * 1000  # Convert to milliseconds
                results['response_times'].append(response_time)
                
                # Short delay between requests
                time.sleep(1)
            
            # Calculate statistics
            results['average_response_time'] = sum(results['response_times']) / len(results['response_times'])
            results['min_response_time'] = min(results['response_times'])
            results['max_response_time'] = max(results['response_times'])
            
            # Performance rating
            if results['average_response_time'] < 100:
                results['performance_rating'] = 'Excellent'
            elif results['average_response_time'] < 300:
                results['performance_rating'] = 'Good'
            elif results['average_response_time'] < 1000:
                results['performance_rating'] = 'Average'
            else:
                results['performance_rating'] = 'Slow'
                results['recommendations'].append("Server response time is slow. Consider implementing caching or optimizing server performance.")
            
            # Check for inconsistent response times
            if results['max_response_time'] > 3 * results['min_response_time']:
                results['recommendations'].append("Response times are inconsistent, which may indicate server load issues or resource constraints.")
            
            # Add summary
            results['summary'] = f"Average response time: {results['average_response_time']:.2f}ms ({results['performance_rating']})"
            
            self.logger.info(f"Response time analysis completed: {results['average_response_time']:.2f}ms ({results['performance_rating']})")
        
        except requests.RequestException as e:
            self.logger.warning(f"Error analyzing response time: {str(e)}")
            results['error'] = f"Connection error: {str(e)}"
            
        return results
        
    def analyze_infrastructure_security_posture(self) -> Dict[str, Any]:
        """
        Perform a comprehensive infrastructure security posture assessment.
        
        This method analyzes various aspects of the server's infrastructure security:
        - Port exposure analysis
        - Service version security state
        - SSL/TLS implementation security
        - HTTP security header configuration
        - Firewall implementation
        - Cloud security configuration
        - Overall infrastructure security scoring
        
        Returns:
            dict: Comprehensive infrastructure security assessment
        """
        self.logger.info(f"Analyzing infrastructure security posture for {self.target}")
        
        results = {
            'target': self.target,
            'security_score': 0,
            'max_score': 100,
            'grade': 'F',
            'security_issues': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            },
            'recommendations': [],
            'passed_checks': [],
            'exposed_services': [],
            'component_scores': {
                'ports_services': 0,
                'ssl_tls': 0,
                'http_security': 0,
                'firewall': 0,
                'cloud_security': 0,
                'version_vulnerabilities': 0
            },
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Gather required data if not already cached
        cached_data = {}
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='server_info')
            if cached_results:
                cached_data = cached_results
        
        # Port scanning analysis
        port_data = cached_data.get('port_scan', self.scan_ports())
        if port_data:
            results['port_exposure_analysis'] = self._analyze_port_exposure(port_data)
            
            # Score for port exposure (0-20 points)
            exposure_severity = len(results['port_exposure_analysis'].get('high_risk_ports', []))
            exposure_score = max(0, 20 - (exposure_severity * 2))
            results['component_scores']['ports_services'] = exposure_score
            
            if exposure_severity > 0:
                severity = 'critical' if exposure_severity > 5 else 'high'
                results['security_issues'][severity].append(f"{exposure_severity} high-risk ports exposed")
                results['recommendations'].append("Restrict access to high-risk ports using a firewall or disable unnecessary services")
            else:
                results['passed_checks'].append("No high-risk ports exposed")
        
        # SSL/TLS security analysis
        ssl_data = cached_data.get('ssl_certificate', self.analyze_ssl_certificate())
        if ssl_data:
            results['ssl_tls_analysis'] = self._analyze_ssl_tls_security(ssl_data)
            results['component_scores']['ssl_tls'] = results['ssl_tls_analysis'].get('score', 0)
            
            # Add SSL/TLS issues and recommendations
            for issue in results['ssl_tls_analysis'].get('issues', []):
                severity = issue.get('severity', 'medium')
                results['security_issues'][severity].append(issue.get('description', 'SSL/TLS issue detected'))
                if 'recommendation' in issue:
                    results['recommendations'].append(issue['recommendation'])
            
            # Add passed checks
            for passed in results['ssl_tls_analysis'].get('passed_checks', []):
                results['passed_checks'].append(passed)
        
        # HTTP security headers analysis
        headers_data = cached_data.get('http_headers', self.analyze_http_headers())
        security_data = cached_data.get('security_analysis', self.analyze_http_security())
        if headers_data and security_data:
            results['http_security_analysis'] = self._analyze_http_security_headers(headers_data, security_data)
            results['component_scores']['http_security'] = results['http_security_analysis'].get('score', 0)
            
            # Add HTTP security issues and recommendations
            for issue in results['http_security_analysis'].get('issues', []):
                severity = issue.get('severity', 'medium')
                results['security_issues'][severity].append(issue.get('description', 'HTTP security issue detected'))
                if 'recommendation' in issue:
                    results['recommendations'].append(issue['recommendation'])
            
            # Add passed checks
            for passed in results['http_security_analysis'].get('passed_checks', []):
                results['passed_checks'].append(passed)
        
        # Firewall implementation analysis
        firewall_data = cached_data.get('firewall_detection', self.detect_firewall())
        if firewall_data:
            results['firewall_analysis'] = self._analyze_firewall_implementation(firewall_data)
            results['component_scores']['firewall'] = results['firewall_analysis'].get('score', 0)
            
            # Add firewall issues and recommendations
            if results['firewall_analysis'].get('firewall_detected', False):
                results['passed_checks'].append(f"Web Application Firewall detected: {results['firewall_analysis'].get('firewall_name', 'Unknown')}")
            else:
                results['security_issues']['high'].append("No Web Application Firewall detected")
                results['recommendations'].append("Implement a Web Application Firewall for improved protection against common web attacks")
        
        # Cloud provider security analysis
        cloud_data = cached_data.get('cloud_provider', self.check_cloud_provider())
        if cloud_data:
            results['cloud_security_analysis'] = self._analyze_cloud_security(cloud_data)
            results['component_scores']['cloud_security'] = results['cloud_security_analysis'].get('score', 0)
            
            # Add cloud security issues and recommendations
            for issue in results['cloud_security_analysis'].get('issues', []):
                severity = issue.get('severity', 'medium')
                results['security_issues'][severity].append(issue.get('description', 'Cloud security issue detected'))
                if 'recommendation' in issue:
                    results['recommendations'].append(issue['recommendation'])
            
            # Add passed checks
            for passed in results['cloud_security_analysis'].get('passed_checks', []):
                results['passed_checks'].append(passed)
        
        # Server vulnerability analysis
        vuln_data = cached_data.get('vulnerability_check', self.check_server_vulnerabilities())
        if vuln_data:
            results['vulnerability_analysis'] = self._analyze_version_vulnerabilities(vuln_data)
            results['component_scores']['version_vulnerabilities'] = results['vulnerability_analysis'].get('score', 0)
            
            # Add vulnerability issues and recommendations
            for issue in results['vulnerability_analysis'].get('issues', []):
                severity = issue.get('severity', 'medium')
                results['security_issues'][severity].append(issue.get('description', 'Version vulnerability detected'))
                if 'recommendation' in issue:
                    results['recommendations'].append(issue['recommendation'])
            
        # Calculate overall security score and grade
        component_scores = results['component_scores']
        total_score = sum(component_scores.values())
        
        # Adjust the score based on critical and high issues
        critical_issues = len(results['security_issues']['critical'])
        high_issues = len(results['security_issues']['high'])
        
        penalty = (critical_issues * 10) + (high_issues * 5)
        adjusted_score = max(0, total_score - penalty)
        
        results['security_score'] = adjusted_score
        
        # Assign a grade based on the security score
        if adjusted_score >= 90:
            results['grade'] = 'A'
        elif adjusted_score >= 80:
            results['grade'] = 'B'
        elif adjusted_score >= 70:
            results['grade'] = 'C'
        elif adjusted_score >= 60:
            results['grade'] = 'D'
        else:
            results['grade'] = 'F'
            
        # Generate summary
        results['summary'] = self._generate_security_summary(results)
        
        return results

    def _analyze_port_exposure(self, port_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze port exposure for security issues.
        
        Args:
            port_data (dict): Port scan results
            
        Returns:
            dict: Port exposure analysis
        """
        results = {
            'open_ports_count': 0,
            'high_risk_ports': [],
            'medium_risk_ports': [],
            'low_risk_ports': [],
            'unusual_ports': [],
            'common_services': [],
            'recommendations': []
        }
        
        # Define high-risk ports
        high_risk_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            445: 'SMB',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
        
        # Medium-risk ports
        medium_risk_ports = {
            20: 'FTP-data',
            43: 'WHOIS',
            67: 'DHCP',
            68: 'DHCP',
            79: 'Finger',
            110: 'POP3',
            111: 'RPC',
            123: 'NTP',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            161: 'SNMP',
            389: 'LDAP',
            1434: 'MSSQL Browser',
            5000: 'Docker',
            8000: 'HTTP Alt',
            8008: 'HTTP Alt',
            8080: 'HTTP Proxy',
            8888: 'HTTP Alt'
        }
        
        # Check for open ports
        if 'open_ports' in port_data:
            open_ports = port_data['open_ports']
            results['open_ports_count'] = len(open_ports)
            
            for port_info in open_ports:
                port = port_info.get('port')
                service = port_info.get('service', 'unknown')
                
                # Record service information
                if service != 'unknown':
                    results['common_services'].append(f"{service} on port {port}")
                
                # Categorize risk
                if port in high_risk_ports:
                    results['high_risk_ports'].append({
                        'port': port,
                        'service': service,
                        'standard_service': high_risk_ports[port],
                        'recommendation': f"Restrict access to port {port} ({high_risk_ports[port]}) if not required"
                    })
                elif port in medium_risk_ports:
                    results['medium_risk_ports'].append({
                        'port': port,
                        'service': service,
                        'standard_service': medium_risk_ports[port]
                    })
                else:
                    results['low_risk_ports'].append({
                        'port': port,
                        'service': service
                    })
                    
                    # Check for unusual ports
                    if port > 10000 and service != 'unknown':
                        results['unusual_ports'].append({
                            'port': port,
                            'service': service,
                            'concern': 'High port with active service - could be non-standard implementation'
                        })
        
        # Generate recommendations
        if results['high_risk_ports']:
            results['recommendations'].append(f"Restrict access to {len(results['high_risk_ports'])} high-risk ports using firewall rules")
        
        if results['unusual_ports']:
            results['recommendations'].append(f"Investigate {len(results['unusual_ports'])} unusual high-numbered ports with active services")
        
        # Add recommendation for exposing database ports
        db_ports = [p for p in results['high_risk_ports'] if p['port'] in [1433, 3306, 5432, 27017, 6379]]
        if db_ports:
            db_names = [p['standard_service'] for p in db_ports]
            results['recommendations'].append(f"Database ports exposed publicly ({', '.join(db_names)}). Consider restricting these to internal network access only")
        
        return results

    def _analyze_ssl_tls_security(self, ssl_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze SSL/TLS implementation for security issues.
        
        Args:
            ssl_data (dict): SSL/TLS analysis results
            
        Returns:
            dict: SSL/TLS security analysis
        """
        results = {
            'score': 0,
            'issues': [],
            'passed_checks': [],
            'certificate_expiry_days': None,
            'weak_cipher_suites': [],
            'secure_protocols': [],
            'insecure_protocols': []
        }
        
        # Certificate validation
        if ssl_data.get('validation_result', {}).get('valid', False):
            results['passed_checks'].append("SSL/TLS certificate is valid")
            results['score'] += 5
        else:
            validation_errors = ssl_data.get('validation_result', {}).get('errors', [])
            if validation_errors:
                error_desc = '; '.join(validation_errors)
                results['issues'].append({
                    'severity': 'high',
                    'description': f"Invalid SSL/TLS certificate: {error_desc}",
                    'recommendation': "Fix certificate issues to prevent browser warnings and ensure secure connections"
                })
        
        # Certificate expiry
        if 'not_after' in ssl_data:
            try:
                expiry_date = datetime.strptime(ssl_data['not_after'], '%Y-%m-%d %H:%M:%S')
                current_date = datetime.now()
                days_remaining = (expiry_date - current_date).days
                
                results['certificate_expiry_days'] = days_remaining
                
                if days_remaining < 0:
                    results['issues'].append({
                        'severity': 'critical',
                        'description': f"SSL/TLS certificate expired {abs(days_remaining)} days ago",
                        'recommendation': "Renew the SSL/TLS certificate immediately"
                    })
                elif days_remaining < 30:
                    results['issues'].append({
                        'severity': 'high',
                        'description': f"SSL/TLS certificate expires in {days_remaining} days",
                        'recommendation': "Renew the SSL/TLS certificate soon to prevent interruption"
                    })
                elif days_remaining < 90:
                    results['issues'].append({
                        'severity': 'medium',
                        'description': f"SSL/TLS certificate expires in {days_remaining} days",
                        'recommendation': "Plan to renew the SSL/TLS certificate"
                    })
                else:
                    results['passed_checks'].append(f"SSL/TLS certificate valid for {days_remaining} more days")
                    results['score'] += 5
            except (ValueError, TypeError):
                pass
        
        # Check key length
        key_length = ssl_data.get('key_length', 0)
        if key_length >= 4096:
            results['passed_checks'].append(f"Strong key length ({key_length} bits)")
            results['score'] += 5
        elif key_length >= 2048:
            results['passed_checks'].append(f"Adequate key length ({key_length} bits)")
            results['score'] += 3
        elif key_length > 0:
            results['issues'].append({
                'severity': 'medium',
                'description': f"Weak key length ({key_length} bits)",
                'recommendation': "Use at least 2048-bit keys for adequate security"
            })
        
        # Check signature algorithm
        signature_algorithm = ssl_data.get('signature_algorithm', '').lower()
        if signature_algorithm:
            if 'sha256' in signature_algorithm or 'sha384' in signature_algorithm or 'sha512' in signature_algorithm:
                results['passed_checks'].append(f"Strong signature algorithm ({signature_algorithm})")
                results['score'] += 5
            elif 'sha1' in signature_algorithm:
                results['issues'].append({
                    'severity': 'medium',
                    'description': f"Weak signature algorithm ({signature_algorithm})",
                    'recommendation': "Use SHA-256 or stronger signature algorithms"
                })
            elif 'md5' in signature_algorithm:
                results['issues'].append({
                    'severity': 'high',
                    'description': f"Very weak signature algorithm ({signature_algorithm})",
                    'recommendation': "Update to SHA-256 or stronger signature algorithms immediately"
                })
        
        # SSL/TLS protocol versions
        protocols = ssl_data.get('protocols', [])
        if protocols:
            for protocol in protocols:
                protocol_name = protocol.get('protocol', '').upper()
                if protocol_name in ['TLSV1.2', 'TLSV1.3']:
                    results['secure_protocols'].append(protocol_name)
                elif protocol_name in ['SSLV2', 'SSLV3', 'TLSV1.0', 'TLSV1.1']:
                    results['insecure_protocols'].append(protocol_name)
            
            if 'TLSV1.3' in [p.get('protocol', '').upper() for p in protocols]:
                results['passed_checks'].append("TLSv1.3 supported (latest and most secure version)")
                results['score'] += 5
            elif 'TLSV1.2' in [p.get('protocol', '').upper() for p in protocols]:
                results['passed_checks'].append("TLSv1.2 supported (secure)")
                results['score'] += 3
            
            if any(p.get('protocol', '').upper() in ['SSLV2', 'SSLV3'] for p in protocols):
                results['issues'].append({
                    'severity': 'critical',
                    'description': "Obsolete SSL protocols (SSLv2/SSLv3) supported",
                    'recommendation': "Disable SSLv2 and SSLv3 immediately as they are fundamentally insecure"
                })
            
            if any(p.get('protocol', '').upper() in ['TLSV1.0', 'TLSV1.1'] for p in protocols):
                results['issues'].append({
                    'severity': 'high',
                    'description': "Deprecated TLS protocols (TLSv1.0/TLSv1.1) supported",
                    'recommendation': "Disable TLSv1.0 and TLSv1.1 as they contain known vulnerabilities"
                })
        
        # Check cipher suites
        ciphers = ssl_data.get('cipher_suites', [])
        if ciphers:
            weak_ciphers = []
            strong_cipher_count = 0
            
            for cipher in ciphers:
                cipher_name = cipher.get('name', '').upper()
                
                # Check for weak ciphers
                if any(x in cipher_name for x in ['NULL', 'EXPORT', 'RC4', 'DES', 'MD5', 'ANON']):
                    weak_ciphers.append(cipher_name)
                
                # Count strong ciphers
                if any(x in cipher_name for x in ['AES-256', 'AES-128']) and 'GCM' in cipher_name:
                    strong_cipher_count += 1
            
            if weak_ciphers:
                results['weak_cipher_suites'] = weak_ciphers
                results['issues'].append({
                    'severity': 'high',
                    'description': f"{len(weak_ciphers)} weak cipher suites supported",
                    'recommendation': "Disable weak cipher suites and use only strong modern ciphers"
                })
            
            if strong_cipher_count > 0:
                results['passed_checks'].append(f"{strong_cipher_count} strong cipher suites supported")
                results['score'] += min(5, strong_cipher_count)
        
        # Check for Perfect Forward Secrecy
        supports_pfs = False
        if ciphers:
            for cipher in ciphers:
                cipher_name = cipher.get('name', '').upper()
                if any(x in cipher_name for x in ['DHE', 'ECDHE']):
                    supports_pfs = True
                    break
        
        if supports_pfs:
            results['passed_checks'].append("Perfect Forward Secrecy supported")
            results['score'] += 5
        else:
            results['issues'].append({
                'severity': 'medium',
                'description': "Perfect Forward Secrecy not supported",
                'recommendation': "Enable cipher suites that support Perfect Forward Secrecy (DHE/ECDHE)"
            })
        
        # Cap the score at 20 points for this component
        results['score'] = min(20, results['score'])
        
        return results

    def _analyze_http_security_headers(self, headers_data: Dict[str, Any], security_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze HTTP security headers configuration.
        
        Args:
            headers_data (dict): HTTP headers analysis results
            security_data (dict): Security headers analysis results
            
        Returns:
            dict: HTTP security headers analysis
        """
        results = {
            'score': 0,
            'issues': [],
            'passed_checks': [],
            'missing_security_headers': [],
            'header_recommendations': []
        }
        
        # Security headers to check
        critical_headers = [
            ('Content-Security-Policy', 'Prevents XSS and data injection attacks'),
            ('X-XSS-Protection', 'Provides XSS filtering capabilities'),
            ('X-Content-Type-Options', 'Prevents MIME-sniffing attacks'),
            ('X-Frame-Options', 'Protects against clickjacking'),
            ('Strict-Transport-Security', 'Enforces HTTPS usage'),
            ('Referrer-Policy', 'Controls information in the Referer header')
        ]
        
        recommended_headers = [
            ('Permissions-Policy', 'Controls browser features'),
            ('Cross-Origin-Resource-Policy', 'Prevents resource access from other origins'),
            ('Cross-Origin-Opener-Policy', 'Restricts window.opener communications'),
            ('Cross-Origin-Embedder-Policy', 'Requires explicitly granted permissions for embedded content')
        ]
        
        # Extract headers
        headers = headers_data.get('headers', {})
        
        # Check each critical header
        for header_name, description in critical_headers:
            normalized_name = header_name.lower()
            header_found = False
            
            for h in headers:
                if h.lower() == normalized_name:
                    header_found = True
                    results['passed_checks'].append(f"{header_name} header present")
                    results['score'] += 2
                    break
            
            if not header_found:
                results['missing_security_headers'].append(header_name)
                results['issues'].append({
                    'severity': 'high',
                    'description': f"Missing {header_name} header",
                    'recommendation': f"Implement {header_name} header: {description}"
                })
        
        # Check each recommended header
        for header_name, description in recommended_headers:
            normalized_name = header_name.lower()
            header_found = False
            
            for h in headers:
                if h.lower() == normalized_name:
                    header_found = True
                    results['passed_checks'].append(f"{header_name} header present")
                    results['score'] += 1
                    break
            
            if not header_found:
                results['missing_security_headers'].append(header_name)
                results['issues'].append({
                    'severity': 'medium',
                    'description': f"Missing {header_name} header",
                    'recommendation': f"Consider implementing {header_name} header: {description}"
                })
        
        # Check Content-Security-Policy value
        csp_header = None
        for h in headers:
            if h.lower() == 'content-security-policy':
                csp_header = headers[h]
                break
        
        if csp_header:
            csp_strength = self._analyze_csp_strength(csp_header)
            if csp_strength == 'strong':
                results['passed_checks'].append("Strong Content-Security-Policy configuration")
                results['score'] += 3
            elif csp_strength == 'medium':
                results['passed_checks'].append("Moderate Content-Security-Policy configuration")
                results['score'] += 1
            else:
                results['issues'].append({
                    'severity': 'medium',
                    'description': "Weak Content-Security-Policy configuration",
                    'recommendation': "Strengthen CSP by avoiding 'unsafe-inline', 'unsafe-eval', and overly permissive sources"
                })
        
        # Check HSTS configuration
        hsts_header = None
        for h in headers:
            if h.lower() == 'strict-transport-security':
                hsts_header = headers[h]
                break
        
        if hsts_header:
            max_age_match = re.search(r'max-age=(\d+)', hsts_header)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age >= 31536000:  # 1 year
                    results['passed_checks'].append("Strong HSTS configuration (≥ 1 year)")
                    results['score'] += 2
                elif max_age >= 15768000:  # 6 months
                    results['passed_checks'].append("Good HSTS configuration (≥ 6 months)")
                    results['score'] += 1
                else:
                    results['issues'].append({
                        'severity': 'low',
                        'description': f"Short HSTS max-age ({max_age} seconds)",
                        'recommendation': "Increase HSTS max-age to at least 1 year (31536000 seconds)"
                    })
            
            if 'includesubdomains' in hsts_header.lower():
                results['passed_checks'].append("HSTS includes subdomains")
                results['score'] += 1
            else:
                results['issues'].append({
                    'severity': 'low',
                    'description': "HSTS does not include subdomains",
                    'recommendation': "Add 'includeSubDomains' directive to HSTS header"
                })
            
            if 'preload' in hsts_header.lower():
                results['passed_checks'].append("HSTS preload ready")
                results['score'] += 1
            else:
                results['issues'].append({
                    'severity': 'low',
                    'description': "HSTS not preload-ready",
                    'recommendation': "Add 'preload' directive to HSTS header for better protection"
                })
        
        # Check Cookie Security
        cookie_security = security_data.get('cookie_security', {})
        if cookie_security:
            secure_cookies = cookie_security.get('secure_cookies', False)
            httponly_cookies = cookie_security.get('httponly_cookies', False)
            samesite_cookies = cookie_security.get('samesite_cookies', False)
            
            if secure_cookies:
                results['passed_checks'].append("Cookies use 'Secure' flag")
                results['score'] += 1
            else:
                results['issues'].append({
                    'severity': 'medium',
                    'description': "Cookies missing 'Secure' flag",
                    'recommendation': "Add 'Secure' flag to cookies to ensure they're only sent over HTTPS"
                })
            
            if httponly_cookies:
                results['passed_checks'].append("Cookies use 'HttpOnly' flag")
                results['score'] += 1
            else:
                results['issues'].append({
                    'severity': 'medium',
                    'description': "Cookies missing 'HttpOnly' flag",
                    'recommendation': "Add 'HttpOnly' flag to cookies to prevent JavaScript access"
                })
            
            if samesite_cookies:
                results['passed_checks'].append("Cookies use 'SameSite' attribute")
                results['score'] += 1
            else:
                results['issues'].append({
                    'severity': 'medium',
                    'description': "Cookies missing 'SameSite' attribute",
                    'recommendation': "Add 'SameSite' attribute to cookies to prevent CSRF attacks"
                })
        
        # Cap the score at 20 points for this component
        results['score'] = min(20, results['score'])
        
        return results

    def _analyze_csp_strength(self, csp_header: str) -> str:
        """
        Analyze the strength of a Content-Security-Policy header.
        
        Args:
            csp_header (str): The CSP header value
            
        Returns:
            str: 'strong', 'medium', or 'weak'
        """
        csp_lower = csp_header.lower()
        
        # Check for weak configurations
        if "'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower:
            return 'weak'
        
        if "default-src 'self'" in csp_lower or "default-src 'none'" in csp_lower:
            # Check for granular directives
            granular_directives = ['script-src', 'style-src', 'img-src', 'connect-src', 
                               'font-src', 'object-src', 'media-src', 'frame-src']
            
            directive_count = sum(1 for directive in granular_directives if directive in csp_lower)
            
            if directive_count >= 5:
                return 'strong'
            elif directive_count >= 3:
                return 'medium'
        
        return 'weak'

    def _analyze_firewall_implementation(self, firewall_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze firewall implementation for security posture.
        
        Args:
            firewall_data (dict): Firewall detection results
            
        Returns:
            dict: Firewall implementation analysis
        """
        results = {
            'score': 0,
            'firewall_detected': False,
            'firewall_name': None,
            'firewall_confidence': 0,
            'protection_level': 'none'
        }
        
        # Check if a firewall was detected
        if firewall_data.get('detected', False):
            results['firewall_detected'] = True
            results['firewall_name'] = firewall_data.get('name', 'Unknown WAF')
            results['firewall_confidence'] = firewall_data.get('confidence', 0)
            
            # Award 20 points for having a WAF
            results['score'] = 20
            
            # Classify protection level based on firewall
            top_tier_wafs = ['Cloudflare', 'Akamai', 'AWS WAF', 'Imperva', 'F5 BIG-IP ASM']
            mid_tier_wafs = ['Sucuri', 'Wordfence', 'ModSecurity', 'Fortinet', 'Barracuda']
            
            if results['firewall_name'] in top_tier_wafs:
                results['protection_level'] = 'high'
            elif results['firewall_name'] in mid_tier_wafs:
                results['protection_level'] = 'medium'
            else:
                results['protection_level'] = 'basic'
        
        return results

    def _analyze_cloud_security(self, cloud_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze cloud provider security posture.
        
        Args:
            cloud_data (dict): Cloud provider detection results
            
        Returns:
            dict: Cloud security analysis
        """
        results = {
            'score': 10,  # Base score for being on a cloud provider with some security
            'cloud_provider': None,
            'issues': [],
            'passed_checks': [],
            'misconfigurations': []
        }
        
        # Check if a cloud provider was detected
        if cloud_data.get('detected', False):
            provider = cloud_data.get('provider', 'Unknown')
            results['cloud_provider'] = provider
            results['passed_checks'].append(f"Using cloud provider: {provider}")
            
            # Check for specific cloud providers and their typical security features
            if provider in ['AWS', 'Amazon Web Services']:
                if cloud_data.get('cloudfront_detected', False):
                    results['passed_checks'].append("Using CloudFront CDN with built-in security features")
                    results['score'] += 5
                else:
                    results['issues'].append({
                        'severity': 'low',
                        'description': "Not using CloudFront CDN",
                        'recommendation': "Consider using CloudFront for additional security features like AWS Shield and AWS WAF"
                    })
                    
                # Check for S3 bucket misconfigurations (if detected)
                if cloud_data.get('s3_detected', False) and cloud_data.get('s3_public', False):
                    results['issues'].append({
                        'severity': 'high',
                        'description': "Public S3 bucket detected",
                        'recommendation': "Review S3 bucket permissions and restrict public access"
                    })
                    results['misconfigurations'].append("Public S3 bucket")
                    results['score'] -= 5
            
            elif provider in ['Azure', 'Microsoft Azure']:
                if cloud_data.get('azure_front_door_detected', False):
                    results['passed_checks'].append("Using Azure Front Door with built-in security features")
                    results['score'] += 5
                else:
                    results['issues'].append({
                        'severity': 'low',
                        'description': "Not using Azure Front Door",
                        'recommendation': "Consider using Azure Front Door for additional security features"
                    })
            
            elif provider in ['Google Cloud', 'GCP']:
                if cloud_data.get('google_cloud_armor_detected', False):
                    results['passed_checks'].append("Using Google Cloud Armor for protection")
                    results['score'] += 5
                else:
                    results['issues'].append({
                        'severity': 'low',
                        'description': "No evidence of Google Cloud Armor",
                        'recommendation': "Consider using Google Cloud Armor for additional protection"
                    })
            
            elif provider in ['Cloudflare']:
                results['passed_checks'].append("Using Cloudflare with built-in security features")
                results['score'] += 10
            
            # Check for specific security headers that suggest cloud security features
            if cloud_data.get('security_headers', {}):
                security_headers = cloud_data['security_headers']
                
                # Check for headers indicating cloud security features
                if any(h.lower() == 'cf-ray' for h in security_headers):
                    results['passed_checks'].append("Cloudflare protection confirmed via CF-Ray header")
                
                if any(h.lower() == 'x-azure-ref' for h in security_headers):
                    results['passed_checks'].append("Azure protection confirmed via X-Azure-Ref header")
                
                if any(h.lower() == 'x-amz-cf-id' for h in security_headers):
                    results['passed_checks'].append("AWS CloudFront confirmed via X-Amz-Cf-Id header")
        else:
            # No cloud provider detected - could be self-hosted or smaller provider
            results['cloud_provider'] = 'Not detected'
            results['issues'].append({
                'severity': 'medium',
                'description': "No major cloud provider detected",
                'recommendation': "Consider using a major cloud provider with built-in security features"
            })
            results['score'] = 5  # Lower base score for non-cloud or unknown provider
        
        # Cap the score at 20 points for this component
        results['score'] = min(20, results['score'])
        
        return results

    def _analyze_version_vulnerabilities(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze software version vulnerabilities.
        
        Args:
            vuln_data (dict): Vulnerability check results
            
        Returns:
            dict: Vulnerability analysis
        """
        results = {
            'score': 20,  # Start with full score and subtract based on issues
            'issues': [],
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'cve_list': []
        }
        
        # Check for vulnerabilities
        vulnerabilities = vuln_data.get('vulnerabilities', [])
        
        if vulnerabilities:
            results['total_vulnerabilities'] = len(vulnerabilities)
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'medium').lower()
                cve_id = vuln.get('cve_id', 'Unknown')
                title = vuln.get('title', 'Unspecified vulnerability')
                
                # Add to CVE list
                results['cve_list'].append({
                    'cve_id': cve_id,
                    'severity': severity,
                    'title': title
                })
                
                # Count by severity
                if severity == 'critical':
                    results['critical_vulnerabilities'] += 1
                    results['score'] -= 5  # -5 points per critical vulnerability
                elif severity == 'high':
                    results['high_vulnerabilities'] += 1
                    results['score'] -= 3  # -3 points per high vulnerability
                elif severity == 'medium':
                    results['medium_vulnerabilities'] += 1
                    results['score'] -= 1  # -1 point per medium vulnerability
                elif severity == 'low':
                    results['low_vulnerabilities'] += 1
                    results['score'] -= 0.5  # -0.5 points per low vulnerability
                
                # Add issue
                results['issues'].append({
                    'severity': severity,
                    'description': f"{cve_id}: {title}",
                    'recommendation': vuln.get('recommendation', 'Update to the latest secure version')
                })
        
        # Ensure score doesn't go below 0
        results['score'] = max(0, results['score'])
        
        return results

    def _generate_security_summary(self, results: Dict[str, Any]) -> str:
        """
        Generate a summary of the security assessment.
        
        Args:
            results (dict): Security assessment results
            
        Returns:
            str: Summary text
        """
        grade = results['grade']
        score = results['security_score']
        critical_issues = len(results['security_issues']['critical'])
        high_issues = len(results['security_issues']['high'])
        
        if grade == 'A':
            summary = f"Excellent security posture (Score: {score}/100). "
            if critical_issues == 0 and high_issues == 0:
                summary += "No critical or high severity issues detected."
            else:
                summary += f"However, {critical_issues} critical and {high_issues} high severity issues should be addressed."
        elif grade == 'B':
            summary = f"Good security posture (Score: {score}/100). "
            summary += f"Address {critical_issues} critical and {high_issues} high severity issues to improve security."
        elif grade == 'C':
            summary = f"Average security posture (Score: {score}/100). "
            summary += f"Several security improvements needed. {critical_issues} critical and {high_issues} high severity issues require attention."
        elif grade == 'D':
            summary = f"Below average security posture (Score: {score}/100). "
            summary += f"Significant security improvements required. {critical_issues} critical and {high_issues} high severity issues need immediate attention."
        else:  # F
            summary = f"Poor security posture (Score: {score}/100). "
            summary += f"Urgent security improvements required. {critical_issues} critical and {high_issues} high severity issues need immediate remediation."
        
        # Add top recommendations if available
        if results['recommendations']:
            top_recommendations = results['recommendations'][:3]
            summary += "\n\nTop recommendations:\n- " + "\n- ".join(top_recommendations)
        
        return summary

    def perform_advanced_port_vulnerability_scan(self) -> Dict[str, Any]:
        """
        Perform an advanced port vulnerability scan using nmap scripts.
        
        This method goes beyond basic port scanning to identify potential
        vulnerabilities in the services running on open ports.
        
        Returns:
            dict: Advanced port vulnerability scan results
        """
        self.logger.info(f"Performing advanced port vulnerability scan for {self.target}")
        
        results = {
            'target': self.target,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'open_ports': [],
            'vulnerabilities': [],
            'security_issues': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            },
            'safe_ports': [],
            'services': [],
            'recommendations': []
        }
        
        # Resolve domain to IP if needed
        ip = self.target
        if not self.is_ip:
            try:
                ip = socket.gethostbyname(self.target)
            except socket.gaierror:
                self.logger.error(f"Could not resolve domain {self.target} to IP")
                results['error'] = f"Could not resolve domain {self.target} to IP"
                return results
        
        # Initialize port scanner
        try:
            nm = nmap.PortScanner()
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap error: {str(e)}")
            results['error'] = f"Nmap error: {str(e)}"
            return results
        
        # Get list of ports to scan (already open ports from basic scan)
        port_list = []
        cached_ports = None
        
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='server_info')
            if cached_results and 'port_scan' in cached_results:
                cached_ports = cached_results['port_scan']
        
        if cached_ports and 'open_ports' in cached_ports:
            for port_info in cached_ports['open_ports']:
                if 'port' in port_info:
                    port_list.append(str(port_info['port']))
        
        # If no ports are cached, use common ports
        if not port_list:
            port_list = [str(p) for p in self.common_ports]
        
        port_spec = ','.join(port_list)
        
        # Basic scan with service and version detection
        try:
            self.logger.info(f"Running service detection scan on ports {port_spec}")
            nm.scan(ip, ports=port_spec, arguments='-sV -T4')
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap service detection error: {str(e)}")
            results['error'] = f"Nmap service detection error: {str(e)}"
            return results
        
        # Check if the target was scanned
        if ip not in nm.all_hosts():
            self.logger.error(f"No scan results for {ip}")
            results['error'] = f"No scan results for {ip}"
            return results
        
        # Process open ports and services
        for port in nm[ip].all_tcp():
            port_info = nm[ip]['tcp'][port]
            
            if port_info['state'] == 'open':
                service_info = {
                    'port': port,
                    'service': port_info['name'],
                    'product': port_info.get('product', ''),
                    'version': port_info.get('version', ''),
                    'extra_info': port_info.get('extrainfo', '')
                }
                
                results['open_ports'].append(port)
                results['services'].append(service_info)
                
                # Check for known vulnerable services and versions
                service_vulnerabilities = self._check_service_vulnerabilities(
                    service_info['service'],
                    service_info['product'],
                    service_info['version']
                )
                
                if service_vulnerabilities:
                    for vuln in service_vulnerabilities:
                        results['vulnerabilities'].append(vuln)
                        severity = vuln.get('severity', 'medium')
                        results['security_issues'][severity].append(vuln)
                else:
                    results['safe_ports'].append(port)
        
        # Perform vulnerability scanning with nmap scripts on open ports
        if results['open_ports']:
            port_spec = ','.join(map(str, results['open_ports']))
            
            try:
                self.logger.info(f"Running vulnerability scan on ports {port_spec}")
                # Use a selection of safe vulnerability detection scripts
                nm.scan(ip, ports=port_spec, arguments='-sV --script=vuln,auth,default -T4')
            except nmap.PortScannerError as e:
                self.logger.error(f"Nmap vulnerability scan error: {str(e)}")
                results['error'] = f"Nmap vulnerability scan error, partial results available"
                # Continue with partial results
        
            # Process vulnerability scan results
            if ip in nm.all_hosts():
                for port in nm[ip].all_tcp():
                    port_info = nm[ip]['tcp'][port]
                    
                    # Check for script results which contain vulnerability info
                    if 'script' in port_info:
                        script_results = port_info['script']
                        
                        for script_name, output in script_results.items():
                            # Extract vulnerabilities from script output
                            if 'VULNERABLE' in output or 'vulnerable' in output.lower():
                                vuln_info = self._parse_vulnerability_script(script_name, output, port)
                                if vuln_info:
                                    results['vulnerabilities'].append(vuln_info)
                                    severity = vuln_info.get('severity', 'medium')
                                    results['security_issues'][severity].append(vuln_info)
        
        # Generate recommendations based on found issues
        results['recommendations'] = self._generate_port_security_recommendations(results)
        
        return results

    def _check_service_vulnerabilities(self, service: str, product: str, version: str) -> List[Dict[str, Any]]:
        """
        Check for known vulnerabilities in the detected service and version.
        
        Args:
            service (str): Service name (e.g., http, ssh)
            product (str): Product name (e.g., Apache, OpenSSH)
            version (str): Version string
            
        Returns:
            list: List of vulnerability dictionaries
        """
        vulnerabilities = []
        
        # Simple vulnerability database keyed by service and product
        # In a real implementation, this would connect to a CVE database or API
        vuln_db = {
            'http': {
                'Apache': {
                    '2.4.49': [
                        {
                            'cve_id': 'CVE-2021-41773',
                            'severity': 'critical',
                            'description': 'Path traversal vulnerability in Apache HTTP Server 2.4.49',
                            'recommendation': 'Upgrade to Apache 2.4.51 or later'
                        }
                    ],
                    '2.4.50': [
                        {
                            'cve_id': 'CVE-2021-42013',
                            'severity': 'critical',
                            'description': 'Path traversal vulnerability in Apache HTTP Server 2.4.50',
                            'recommendation': 'Upgrade to Apache 2.4.51 or later'
                        }
                    ]
                },
                'nginx': {
                    '1.20.0': [
                        {
                            'cve_id': 'CVE-2021-23017',
                            'severity': 'high',
                            'description': 'Nginx resolver vulnerabilities',
                            'recommendation': 'Upgrade to nginx 1.20.1 or later'
                        }
                    ]
                }
            },
            'ssh': {
                'OpenSSH': {
                    '7.2': [
                        {
                            'cve_id': 'CVE-2016-6210',
                            'severity': 'medium',
                            'description': 'User enumeration vulnerability in OpenSSH 7.2',
                            'recommendation': 'Upgrade to OpenSSH 7.3 or later'
                        }
                    ]
                }
            },
            'ssl/https': {
                'OpenSSL': {
                    '1.0.1': [
                        {
                            'cve_id': 'CVE-2014-0160',
                            'severity': 'critical',
                            'description': 'Heartbleed vulnerability in OpenSSL',
                            'recommendation': 'Upgrade to OpenSSL 1.0.1g or later'
                        }
                    ]
                }
            },
            'ftp': {
                'vsftpd': {
                    '2.3.4': [
                        {
                            'cve_id': 'CVE-2011-2523',
                            'severity': 'critical',
                            'description': 'Backdoor vulnerability in vsftpd 2.3.4',
                            'recommendation': 'Upgrade to vsftpd 2.3.5 or later'
                        }
                    ]
                }
            }
        }
        
        # Normalize inputs for lookup
        service = service.lower()
        if product:
            product = product.strip()
        if version:
            version = version.strip()
        
        # Look for exact matches
        if service in vuln_db and product in vuln_db[service] and version in vuln_db[service][product]:
            vulnerabilities.extend(vuln_db[service][product][version])
        
        # Look for partial version matches
        if service in vuln_db and product in vuln_db[service]:
            for vuln_version, vulns in vuln_db[service][product].items():
                # Check if the detected version is affected by comparing version components
                if version and self._is_version_affected(version, vuln_version):
                    for vuln in vulns:
                        # Only add if not already added (avoid duplicates)
                        if not any(v['cve_id'] == vuln['cve_id'] for v in vulnerabilities):
                            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _is_version_affected(self, detected_version: str, vulnerable_version: str) -> bool:
        """
        Check if the detected version is affected by comparing version components.
        
        Args:
            detected_version (str): Detected version string
            vulnerable_version (str): Vulnerable version string
            
        Returns:
            bool: True if affected, False otherwise
        """
        # Simple version comparison logic
        try:
            detected_parts = [int(p) for p in detected_version.split('.')]
            vulnerable_parts = [int(p) for p in vulnerable_version.split('.')]
            
            # Pad with zeros to make same length
            max_len = max(len(detected_parts), len(vulnerable_parts))
            detected_parts += [0] * (max_len - len(detected_parts))
            vulnerable_parts += [0] * (max_len - len(vulnerable_parts))
            
            # Compare components
            for i in range(max_len):
                if detected_parts[i] > vulnerable_parts[i]:
                    # Detected version is newer than vulnerable version
                    return False
                elif detected_parts[i] < vulnerable_parts[i]:
                    # Detected version is older than vulnerable version
                    return True
            
            # Exact match
            return True
        except (ValueError, TypeError):
            # If parsing fails, be cautious and assume affected
            return True

    def _parse_vulnerability_script(self, script_name: str, output: str, port: int) -> Dict[str, Any]:
        """
        Parse vulnerability information from nmap script output.
        
        Args:
            script_name (str): Name of the script
            output (str): Script output text
            port (int): Port number
            
        Returns:
            dict: Vulnerability information
        """
        vuln_info = {
            'port': port,
            'script': script_name,
            'details': output.strip(),
            'severity': 'medium',  # Default severity
            'recommendation': 'Update the affected service to the latest version'
        }
        
        # Try to extract CVE IDs
        cve_pattern = r'(CVE-\d{4}-\d{4,})'
        cve_matches = re.findall(cve_pattern, output)
        if cve_matches:
            vuln_info['cve_id'] = cve_matches[0]
        
        # Determine severity based on script name or output content
        if 'critical' in output.lower() or 'high risk' in output.lower():
            vuln_info['severity'] = 'critical'
        elif 'high' in output.lower():
            vuln_info['severity'] = 'high'
        elif 'medium' in output.lower():
            vuln_info['severity'] = 'medium'
        elif 'low' in output.lower():
            vuln_info['severity'] = 'low'
        
        # Special handling for common vulnerability scripts
        if 'ssl-heartbleed' in script_name and 'VULNERABLE' in output:
            vuln_info['severity'] = 'critical'
            vuln_info['cve_id'] = 'CVE-2014-0160'
            vuln_info['recommendation'] = 'Update OpenSSL to version 1.0.1g or later'
        elif 'ssl-poodle' in script_name and 'VULNERABLE' in output:
            vuln_info['severity'] = 'high'
            vuln_info['cve_id'] = 'CVE-2014-3566'
            vuln_info['recommendation'] = 'Disable SSLv3 or update to a patched version'
        elif 'ssl-ccs-injection' in script_name and 'VULNERABLE' in output:
            vuln_info['severity'] = 'high'
            vuln_info['cve_id'] = 'CVE-2014-0224'
            vuln_info['recommendation'] = 'Update OpenSSL to version 0.9.8za, 1.0.0m, or 1.0.1h or later'
        elif 'http-shellshock' in script_name and 'VULNERABLE' in output:
            vuln_info['severity'] = 'critical'
            vuln_info['cve_id'] = 'CVE-2014-6271'
            vuln_info['recommendation'] = 'Update Bash to a patched version'
        
        return vuln_info

    def _generate_port_security_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """
        Generate security recommendations based on port scan results.
        
        Args:
            results (dict): Port scan results
            
        Returns:
            list: List of recommendations
        """
        recommendations = []
        
        # Create a set of ports with issues
        vulnerable_ports = set()
        for severity in results['security_issues']:
            for issue in results['security_issues'][severity]:
                if 'port' in issue:
                    vulnerable_ports.add(issue['port'])
        
        # General recommendations based on open ports
        dangerous_ports = {21: 'FTP', 23: 'Telnet', 3389: 'RDP', 445: 'SMB'}
        
        for port, service in dangerous_ports.items():
            if port in results['open_ports']:
                recommendations.append(f"Consider restricting access to {service} (port {port}) or replacing with a more secure alternative")
        
        # Recommendations for database ports
        database_ports = {3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB', 1433: 'MS SQL', 1521: 'Oracle'}
        
        db_ports_open = [p for p in results['open_ports'] if p in database_ports]
        if db_ports_open:
            db_names = [database_ports[p] for p in db_ports_open]
            recommendations.append(f"Database ports are publicly accessible ({', '.join(db_names)}). Consider restricting to internal access only")
        
        # Recommendation for SSH
        if 22 in results['open_ports']:
            recommendations.append("Ensure SSH is configured with key-based authentication and disable password authentication")
        
        # Add recommendations from vulnerability findings
        vuln_recommendations = set()
        for vuln in results['vulnerabilities']:
            if 'recommendation' in vuln:
                vuln_recommendations.add(vuln['recommendation'])
        
        recommendations.extend(list(vuln_recommendations))
        
        # General recommendation for reducing attack surface
        if len(results['open_ports']) > 5:
            recommendations.append(f"Reduce exposed services: {len(results['open_ports'])} open ports detected, consider disabling unnecessary services")
        
        # Add firewall recommendation if needed
        if vulnerable_ports and not any('firewall' in r.lower() for r in recommendations):
            recommendations.append("Implement a firewall to restrict access to vulnerable services")
        
        return recommendations
