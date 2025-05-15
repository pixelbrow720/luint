"""
Server Info Module additions.
These methods will be added to enhance the server_info module with more advanced security and analysis features.
"""
from typing import Dict, Any, List, Tuple
import re
import json
import socket
import requests
import ssl
import mmh3
import base64
from datetime import datetime
import time
import io
from urllib.parse import urlparse, urljoin
import nmap


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
        exposure_severity = len(results['port_exposure_analysis']['high_risk_ports'])
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
        results['component_scores']['ssl_tls'] = results['ssl_tls_analysis']['score']
        
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
        results['component_scores']['http_security'] = results['http_security_analysis']['score']
        
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
        results['component_scores']['firewall'] = results['firewall_analysis']['score']
        
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
        results['component_scores']['cloud_security'] = results['cloud_security_analysis']['score']
        
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
        results['component_scores']['version_vulnerabilities'] = results['vulnerability_analysis']['score']
        
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
    
    # Check for OCSP Stapling
    ocsp_stapling = ssl_data.get('ocsp_stapling', False)
    if ocsp_stapling:
        results['passed_checks'].append("OCSP Stapling enabled")
        results['score'] += 5
    else:
        results['issues'].append({
            'severity': 'low',
            'description': "OCSP Stapling not enabled",
            'recommendation': "Enable OCSP Stapling for improved certificate validation performance"
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
        scanner = nmap.PortScanner()
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
        scanner.scan(ip, ports=port_spec, arguments='-sV -T4')
    except nmap.PortScannerError as e:
        self.logger.error(f"Nmap service detection error: {str(e)}")
        results['error'] = f"Nmap service detection error: {str(e)}"
        return results
    
    # Check if the target was scanned
    if ip not in scanner.all_hosts():
        self.logger.error(f"No scan results for {ip}")
        results['error'] = f"No scan results for {ip}"
        return results
    
    # Process open ports and services
    for port in scanner[ip].all_tcp():
        port_info = scanner[ip]['tcp'][port]
        
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
            scanner.scan(ip, ports=port_spec, arguments='-sV --script=vuln,auth,default -T4')
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap vulnerability scan error: {str(e)}")
            results['error'] = f"Nmap vulnerability scan error, partial results available"
            # Continue with partial results
    
        # Process vulnerability scan results
        if ip in scanner.all_hosts():
            for port in scanner[ip].all_tcp():
                port_info = scanner[ip]['tcp'][port]
                
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