"""
DNS Info Module additions.
These are new methods to be added to the DNSInfoScanner class.
"""
import socket
import ssl
import time
import requests
import dns.resolver
import dns.message
import dns.rcode
import dns.rdatatype
from typing import Dict, Any

def check_dns_over_https(self, domain: str) -> Dict[str, Any]:
    """
    Check if the domain or its nameservers support DNS over HTTPS (DoH).
    
    This method tests several popular DoH providers and checks if the domain's
    nameservers support DoH by attempting to resolve the domain using DoH endpoints.
    
    Args:
        domain (str): The domain to check DoH support for
        
    Returns:
        dict: DNS over HTTPS support analysis with test results
    """
    self.logger.info(f"Checking DNS over HTTPS support for {domain}")
    results = {
        'domain': domain,
        'supported': False,
        'providers_tested': [],
        'working_providers': [],
        'response_times_ms': {},
        'errors': {}
    }
    
    # List of popular DoH providers to test
    doh_providers = {
        'Google': 'https://dns.google/resolve',
        'Cloudflare': 'https://cloudflare-dns.com/dns-query',
        'Quad9': 'https://dns.quad9.net/dns-query',
        'AdGuard': 'https://dns.adguard.com/dns-json'
    }
    
    # Get nameservers for the domain to check if they offer DoH
    try:
        ns_records = self.resolver.resolve(domain, 'NS')
        nameservers = [rdata.target.to_text() for rdata in ns_records]
    except Exception as e:
        nameservers = []
        results['errors']['ns_lookup'] = str(e)
    
    # Add nameservers to the testing list if they have known DoH endpoints
    for ns in nameservers:
        ns_name = ns.rstrip('.')
        if 'cloudflare' in ns_name:
            doh_providers[f'NS: {ns_name}'] = 'https://cloudflare-dns.com/dns-query'
        elif 'google' in ns_name:
            doh_providers[f'NS: {ns_name}'] = 'https://dns.google/resolve'
    
    # Test each DoH provider
    for provider_name, endpoint in doh_providers.items():
        results['providers_tested'].append(provider_name)
        
        try:
            # Different providers use different API formats
            if 'dns-json' in endpoint or 'resolve' in endpoint:
                # JSON API format (Google, AdGuard)
                params = {
                    'name': domain,
                    'type': 'A',
                    'do': 'true'  # DNSSEC OK flag
                }
                
                start_time = time.time()
                response = requests.get(
                    endpoint,
                    params=params,
                    headers={'Accept': 'application/dns-json'},
                    timeout=5
                )
                end_time = time.time()
                
                if response.status_code == 200:
                    data = response.json()
                    if 'Answer' in data or 'Status' in data:
                        results['working_providers'].append(provider_name)
                        results['response_times_ms'][provider_name] = round((end_time - start_time) * 1000, 2)
                
            else:
                # DNS Wire Format (Cloudflare, Quad9)
                headers = {
                    'Accept': 'application/dns-message',
                    'Content-Type': 'application/dns-message'
                }
                
                # Create a DNS query message
                query = dns.message.make_query(domain, dns.rdatatype.A)
                query_wire = query.to_wire()
                
                start_time = time.time()
                response = requests.post(
                    endpoint,
                    headers=headers,
                    data=query_wire,
                    timeout=5
                )
                end_time = time.time()
                
                if response.status_code == 200:
                    try:
                        response_msg = dns.message.from_wire(response.content)
                        if len(response_msg.answer) > 0 or response_msg.rcode() == dns.rcode.NOERROR:
                            results['working_providers'].append(provider_name)
                            results['response_times_ms'][provider_name] = round((end_time - start_time) * 1000, 2)
                    except Exception as e:
                        results['errors'][provider_name] = str(e)
        
        except Exception as e:
            results['errors'][provider_name] = str(e)
    
    # Determine if DoH is supported based on test results
    results['supported'] = len(results['working_providers']) > 0
    
    return results

def check_dns_over_tls(self, domain: str) -> Dict[str, Any]:
    """
    Check if the domain or its nameservers support DNS over TLS (DoT).
    
    This method tests if the domain's nameservers support DoT by attempting
    to establish TLS connections to the nameservers on port 853 (standard DoT port).
    
    Args:
        domain (str): The domain to check DoT support for
        
    Returns:
        dict: DNS over TLS support analysis with test results
    """
    self.logger.info(f"Checking DNS over TLS support for {domain}")
    results = {
        'domain': domain,
        'supported': False,
        'nameservers_tested': [],
        'supporting_nameservers': [],
        'tls_info': {},
        'errors': {}
    }
    
    # Get nameservers for the domain
    try:
        ns_records = self.resolver.resolve(domain, 'NS')
        nameservers = [rdata.target.to_text().rstrip('.') for rdata in ns_records]
        results['nameservers_tested'] = nameservers
    except Exception as e:
        results['errors']['ns_lookup'] = str(e)
        return results
    
    # Add well-known DoT providers to test
    dot_servers = nameservers + ['1.1.1.1', '8.8.8.8', '9.9.9.9']
    
    # Test each nameserver for DoT support
    for ns in dot_servers:
        try:
            # Attempt to establish a TLS connection to the nameserver on port 853
            context = ssl.create_default_context()
            with socket.create_connection((ns, 853), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ns) as ssock:
                    # If we get here, the TLS connection was successful
                    results['supporting_nameservers'].append(ns)
                    
                    # Get TLS certificate information
                    cert = ssock.getpeercert()
                    results['tls_info'][ns] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serialNumber': cert.get('serialNumber', 'N/A'),
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter']
                    }
        except Exception as e:
            results['errors'][ns] = str(e)
    
    # Determine if DoT is supported based on test results
    results['supported'] = len(results['supporting_nameservers']) > 0
    
    return results

def analyze_dns_security_posture(self, domain: str) -> Dict[str, Any]:
    """
    Perform a comprehensive DNS security posture assessment.
    
    This method evaluates various DNS security aspects including DNSSEC, DoH/DoT support,
    SPF/DMARC/DKIM records, CAA records, and checks for common DNS misconfigurations
    and vulnerabilities. It provides severity ratings and recommendations for remediation.
    
    Args:
        domain (str): The domain to assess
        
    Returns:
        dict: Comprehensive DNS security assessment with vulnerabilities and recommendations
    """
    self.logger.info(f"Analyzing DNS security posture for {domain}")
    security_results = {
        'domain': domain,
        'security_score': 0,
        'max_score': 100,
        'grade': 'F',
        'vulnerabilities': {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        },
        'recommendations': [],
        'passed_checks': []
    }
    
    # Get DNSSEC status
    dnssec_result = self.check_dnssec(domain)
    if dnssec_result.get('enabled', False) and dnssec_result.get('validated', False):
        security_results['passed_checks'].append('DNSSEC properly implemented and validated')
        security_results['security_score'] += 20
    elif dnssec_result.get('enabled', False) and not dnssec_result.get('validated', False):
        security_results['vulnerabilities']['high'].append('DNSSEC is enabled but validation failed')
        security_results['recommendations'].append('Fix DNSSEC configuration issues to ensure proper validation')
    else:
        security_results['vulnerabilities']['medium'].append('DNSSEC not implemented')
        security_results['recommendations'].append('Implement DNSSEC to protect against DNS spoofing attacks')
    
    # Check SPF, DMARC, DKIM records for email security
    spf_result = self.analyze_spf_record(domain)
    if spf_result.get('record', None):
        if 'all' in spf_result.get('mechanisms', []):
            security_results['passed_checks'].append('SPF record properly configured with "all" mechanism')
            security_results['security_score'] += 10
        else:
            security_results['vulnerabilities']['medium'].append('SPF record missing "all" mechanism')
            security_results['recommendations'].append('Add an "all" qualifier to your SPF record to explicitly define handling of non-matched emails')
    else:
        security_results['vulnerabilities']['high'].append('Missing SPF record')
        security_results['recommendations'].append('Implement SPF record to prevent email spoofing')
    
    dmarc_result = self.analyze_dmarc_record(domain)
    if dmarc_result.get('record', None):
        policy = dmarc_result.get('policy', 'none')
        if policy == 'reject' or policy == 'quarantine':
            security_results['passed_checks'].append(f'DMARC record properly configured with {policy} policy')
            security_results['security_score'] += 15
        else:
            security_results['vulnerabilities']['medium'].append('DMARC policy set to "none"')
            security_results['recommendations'].append('Strengthen DMARC policy to "quarantine" or "reject" for better protection')
    else:
        security_results['vulnerabilities']['high'].append('Missing DMARC record')
        security_results['recommendations'].append('Implement DMARC record to improve email authentication')
    
    # Check for CAA records
    caa_result = self.analyze_caa_records(domain)
    if caa_result.get('records', []):
        security_results['passed_checks'].append('CAA records implemented')
        security_results['security_score'] += 10
    else:
        security_results['vulnerabilities']['low'].append('Missing CAA records')
        security_results['recommendations'].append('Implement CAA records to control which certificate authorities can issue certificates for your domain')
    
    # Check for DNS over HTTPS/TLS support
    doh_result = self.check_dns_over_https(domain)
    dot_result = self.check_dns_over_tls(domain)
    
    if doh_result.get('supported', False) or dot_result.get('supported', False):
        security_results['passed_checks'].append('DNS encryption (DoH/DoT) supported')
        security_results['security_score'] += 15
    else:
        security_results['vulnerabilities']['low'].append('No DNS encryption (DoH/DoT) support detected')
        security_results['recommendations'].append('Consider using DNS providers that support encryption')
    
    # Check for zone transfer vulnerability
    zone_transfer_result = self.attempt_zone_transfer(domain)
    if zone_transfer_result.get('vulnerable', False):
        security_results['vulnerabilities']['critical'].append('DNS zone transfer allowed - severe security risk')
        security_results['recommendations'].append('Disable zone transfers immediately to prevent information leakage')
    else:
        security_results['passed_checks'].append('Zone transfers properly restricted')
        security_results['security_score'] += 15
    
    # Check DNS propagation consistency
    propagation_result = self.check_dns_propagation(domain)
    if propagation_result.get('consistent', True):
        security_results['passed_checks'].append('DNS records are consistently propagated')
        security_results['security_score'] += 10
    else:
        security_results['vulnerabilities']['medium'].append('Inconsistent DNS record propagation detected')
        security_results['recommendations'].append('Investigate DNS inconsistencies that could lead to service disruptions')
    
    # Analyze nameserver configuration
    ns_results = None
    try:
        ns_records = self.resolver.resolve(domain, 'NS')
        ns_results = [rdata.target.to_text() for rdata in ns_records]
    except Exception:
        pass
        
    if ns_results:
        if len(ns_results) < 2:
            security_results['vulnerabilities']['high'].append('Single point of failure: only one nameserver configured')
            security_results['recommendations'].append('Configure at least two nameservers for redundancy')
        else:
            security_results['passed_checks'].append(f'Multiple nameservers ({len(ns_results)}) properly configured')
            security_results['security_score'] += 5
    
    # Assign a grade based on the security score
    score = security_results['security_score']
    if score >= 90:
        security_results['grade'] = 'A'
    elif score >= 80:
        security_results['grade'] = 'B'
    elif score >= 70:
        security_results['grade'] = 'C'
    elif score >= 60:
        security_results['grade'] = 'D'
    else:
        security_results['grade'] = 'F'
    
    return security_results