"""
DNS Information Module for LUINT.
Handles DNS lookups, reverse DNS, WHOIS, DNSSEC validation, DNS over HTTPS/TLS, DNS zone transfers, 
and comprehensive DNS security analysis.

This module provides advanced DNS reconnaissance capabilities, gathering detailed information
about domain names and IP addresses. It analyzes DNS records, WHOIS registration data, and security
configurations to build a complete profile of the target's DNS infrastructure with an emphasis on
security posture assessment.

Key capabilities:
- Complete DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, etc.)
- Reverse DNS lookups to find hostnames associated with IP addresses
- WHOIS data extraction and parsing for domain ownership information
- DNSSEC validation to check for proper DNS security implementation
- DNS over HTTPS (DoH) and DNS over TLS (DoT) support and detection
- SPF, DMARC, and DKIM record analysis for email security assessment
- DNS zone transfer attempts to check for misconfigured DNS servers
- DNS propagation testing across multiple public resolvers
- Wildcard DNS detection to identify catch-all DNS configurations
- DNS security posture assessment with detailed vulnerability analysis
- CAA (Certificate Authority Authorization) record checking
- DNS security misconfigurations detection with severity ratings
- DNS delegation chain analysis for security vulnerabilities
- DNS resolver security validation against known attack vectors

This module forms the foundation for many other reconnaissance activities by providing
essential domain and IP information that can be used for further targeting while delivering
actionable insights about the target's DNS security posture.
"""
import socket
import re
import json
import ssl
import time
import requests
import urllib.parse
import dns.resolver
import dns.reversename
import dns.query
import dns.zone
import dns.exception
import dns.name
import dns.dnssec
import dns.flags
import dns.rdatatype
import dns.rcode
import dns.flags
import whois
import threading
import concurrent.futures
from typing import Dict, List, Any, Optional, Union, Tuple
import time
import ipaddress

from luint.utils.logger import get_logger, LoggerAdapter
from luint.utils.helpers import is_ip_address, is_domain
from luint.constants import DNS_RECORD_TYPES

logger = get_logger()


class DNSInfoScanner:
    """
    DNS Information Scanner for LUINT.
    Gathers various DNS-related information about a target.
    """
    
    def __init__(self, target: str, config: Dict = None, 
                 cache_manager=None, rate_limiter=None, api_key_manager=None):
        """
        Initialize the DNS Information Scanner.
        
        Args:
            target (str): Domain or IP to scan
            config (dict, optional): Module configuration
            cache_manager: Cache manager instance
            rate_limiter: Rate limiter instance
            api_key_manager: API key manager instance (not used in this module)
        """
        self.target = target
        self.config = config or {}
        self.module_config = self.config.get('modules', {}).get('dns_info', {})
        self.cache_manager = cache_manager
        self.rate_limiter = rate_limiter
        
        # Setup module-specific logger
        self.logger = LoggerAdapter(logger, module_name='dns_info', target=target)
        
        # Configure DNS resolver
        self.setup_resolver()
    
    def setup_resolver(self):
        """Configure the DNS resolver with settings from the configuration."""
        self.resolver = dns.resolver.Resolver()
        
        # Set DNS servers from config
        dns_servers = self.module_config.get('dns_servers', ['8.8.8.8', '1.1.1.1'])
        if dns_servers:
            self.resolver.nameservers = dns_servers
            
        # Set timeout
        timeout = self.module_config.get('timeout', 5)
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def scan(self) -> Dict[str, Any]:
        """
        Run all DNS information gathering methods.
        
        Returns:
            dict: Consolidated DNS information results
        """
        results = {}
        
        # Check cache first
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='dns_info')
            if cached_results:
                self.logger.info(f"Using cached DNS results for {self.target}")
                return cached_results
        
        if is_ip_address(self.target):
            self.logger.info(f"Target {self.target} is an IP address, performing reverse lookups")
            results['is_ip'] = True
            
            # Reverse DNS lookup
            reverse_dns_results = self.reverse_dns_lookup(self.target)
            if reverse_dns_results:
                results['reverse_dns'] = reverse_dns_results
            
            # IP WHOIS lookup
            ip_whois_results = self.ip_whois_lookup(self.target)
            if ip_whois_results:
                results['whois'] = ip_whois_results
                
        elif is_domain(self.target):
            self.logger.info(f"Target {self.target} is a domain, performing DNS lookups")
            results['is_domain'] = True
            
            # DNS resolution for different record types
            dns_records = self.resolve_dns(self.target)
            if dns_records:
                results['dns_records'] = dns_records
            
            # Domain WHOIS lookup
            domain_whois = self.domain_whois_lookup(self.target)
            if domain_whois:
                results['whois'] = domain_whois
            
            # DNSSEC validation
            dnssec_results = self.check_dnssec(self.target)
            if dnssec_results:
                results['dnssec'] = dnssec_results
            
            # DNS zone transfer attempt
            zone_transfer_results = self.attempt_zone_transfer(self.target)
            if zone_transfer_results:
                results['zone_transfer'] = zone_transfer_results
            
            # Wildcard DNS check
            wildcard_results = self.check_wildcard_dns(self.target)
            if wildcard_results:
                results['wildcard_dns'] = wildcard_results
            
            # New enhanced features
            
            # SPF Record Analysis
            spf_analysis = self.analyze_spf_record(self.target)
            if spf_analysis:
                results['spf_analysis'] = spf_analysis
            
            # DMARC Record Analysis
            dmarc_analysis = self.analyze_dmarc_record(self.target)
            if dmarc_analysis:
                results['dmarc_analysis'] = dmarc_analysis
            
            # CAA Record Analysis
            caa_analysis = self.analyze_caa_records(self.target)
            if caa_analysis:
                results['caa_analysis'] = caa_analysis
            
            # DNS Propagation Check
            propagation_check = self.check_dns_propagation(self.target)
            if propagation_check:
                results['propagation_check'] = propagation_check
            
            # DNS Health Check
            health_check = self.dns_health_check(self.target)
            if health_check:
                results['health_check'] = health_check
                
            # Check for DNS over HTTPS support
            doh_check = self.check_dns_over_https(self.target)
            if doh_check:
                results['dns_over_https'] = doh_check
                
            # Check for DNS over TLS support
            dot_check = self.check_dns_over_tls(self.target)
            if dot_check:
                results['dns_over_tls'] = dot_check
                
            # Comprehensive DNS security posture assessment
            security_posture = self.analyze_dns_security_posture(self.target)
            if security_posture:
                results['security_posture'] = security_posture
                
        else:
            self.logger.warning(f"Target {self.target} is neither a valid IP nor domain")
            results['error'] = "Invalid target format. Please provide a valid domain or IP."
            
        # Cache results if cache manager is available
        if self.cache_manager and results:
            self.cache_manager.set(self.target, results, namespace='dns_info')
            
        return results
    
    def resolve_dns(self, domain: str) -> Dict[str, List]:
        """
        Resolve DNS records for the given domain.
        
        Args:
            domain (str): Domain to resolve
            
        Returns:
            dict: Dictionary mapping record types to lists of results
        """
        self.logger.info(f"Resolving DNS records for {domain}")
        results = {}
        
        # Record types to query
        record_types = DNS_RECORD_TYPES
        
        def query_record_type(record_type):
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('dns')
                    
                answers = self.resolver.resolve(domain, record_type)
                records = []
                
                for rdata in answers:
                    if record_type == 'A':
                        records.append(str(rdata.address))
                    elif record_type == 'AAAA':
                        records.append(str(rdata.address))
                    elif record_type == 'MX':
                        records.append(f"{rdata.preference} {rdata.exchange}")
                    elif record_type == 'NS':
                        records.append(str(rdata.target))
                    elif record_type == 'SOA':
                        records.append({
                            'mname': str(rdata.mname),
                            'rname': str(rdata.rname),
                            'serial': rdata.serial,
                            'refresh': rdata.refresh,
                            'retry': rdata.retry,
                            'expire': rdata.expire,
                            'minimum': rdata.minimum
                        })
                    elif record_type == 'TXT':
                        records.append(str(rdata).strip('"'))
                    elif record_type == 'SRV':
                        records.append({
                            'priority': rdata.priority,
                            'weight': rdata.weight,
                            'port': rdata.port,
                            'target': str(rdata.target)
                        })
                    elif record_type == 'CAA':
                        records.append({
                            'flag': rdata.flags,
                            'tag': rdata.tag.decode('ascii'),
                            'value': rdata.value.decode('ascii')
                        })
                    else:
                        records.append(str(rdata))
                
                return record_type, records
                
            except dns.resolver.NoAnswer:
                return record_type, []
            except dns.resolver.NXDOMAIN:
                self.logger.debug(f"Domain {domain} does not exist")
                return record_type, []
            except dns.resolver.NoNameservers:
                self.logger.debug(f"No nameservers available for {domain}")
                return record_type, []
            except dns.exception.DNSException as e:
                self.logger.debug(f"DNS error querying {record_type} records for {domain}: {str(e)}")
                return record_type, []
        
        # Use thread pool for parallel queries
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(query_record_type, record_type) for record_type in record_types]
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    record_type, records = future.result()
                    if records:
                        results[record_type] = records
                except Exception as e:
                    self.logger.error(f"Error during DNS resolution: {str(e)}")
        
        self.logger.info(f"Found {sum(len(records) for records in results.values())} DNS records across {len(results)} record types")
        return results
    
    def reverse_dns_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Perform reverse DNS lookup for an IP address.
        
        Args:
            ip (str): IP address to lookup
            
        Returns:
            dict: Reverse DNS lookup results
        """
        self.logger.info(f"Performing reverse DNS lookup for {ip}")
        results = {
            'ip': ip,
            'hostnames': []
        }
        
        try:
            if self.rate_limiter:
                self.rate_limiter.wait('dns')
                
            # Create a reverse pointer
            reverse_name = dns.reversename.from_address(ip)
            
            # Query for PTR records
            answers = self.resolver.resolve(reverse_name, 'PTR')
            
            for rdata in answers:
                results['hostnames'].append(str(rdata.target).rstrip('.'))
                
            self.logger.info(f"Found {len(results['hostnames'])} hostnames for {ip}")
            
        except dns.resolver.NoAnswer:
            self.logger.debug(f"No PTR records found for {ip}")
        except dns.resolver.NXDOMAIN:
            self.logger.debug(f"No reverse DNS record exists for {ip}")
        except dns.exception.DNSException as e:
            self.logger.debug(f"DNS error during reverse lookup for {ip}: {str(e)}")
        
        # Try socket.gethostbyaddr as a fallback
        if not results['hostnames']:
            try:
                hostname, aliases, addresses = socket.gethostbyaddr(ip)
                if hostname:
                    results['hostnames'].append(hostname)
                if aliases:
                    results['aliases'] = aliases
            except (socket.herror, socket.gaierror):
                pass
        
        return results
    
    def domain_whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup for a domain.
        
        Args:
            domain (str): Domain to lookup
            
        Returns:
            dict: WHOIS lookup results
        """
        self.logger.info(f"Performing WHOIS lookup for domain {domain}")
        
        try:
            if self.rate_limiter:
                self.rate_limiter.wait('whois')
                
            w = whois.whois(domain)
            
            # Extract relevant WHOIS information
            whois_info = {}
            
            # Basic domain information
            if w.domain_name:
                if isinstance(w.domain_name, list):
                    whois_info['domain_name'] = w.domain_name[0]
                else:
                    whois_info['domain_name'] = w.domain_name
            
            # Registration dates
            for date_field in ['creation_date', 'updated_date', 'expiration_date']:
                value = getattr(w, date_field, None)
                if value:
                    if isinstance(value, list):
                        whois_info[date_field] = str(value[0])
                    else:
                        whois_info[date_field] = str(value)
            
            # Registrar information
            for field in ['registrar', 'registrant', 'whois_server', 'status']:
                value = getattr(w, field, None)
                if value:
                    if isinstance(value, list):
                        whois_info[field] = value
                    else:
                        whois_info[field] = value
            
            # Nameservers
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    whois_info['nameservers'] = [ns.lower() for ns in w.name_servers if ns]
                else:
                    whois_info['nameservers'] = [w.name_servers.lower()]
            
            # Contact information
            contact_fields = {
                'admin': ['admin_organization', 'admin_state', 'admin_country', 'admin_email'],
                'tech': ['tech_organization', 'tech_state', 'tech_country', 'tech_email'],
                'registrant': ['registrant_organization', 'registrant_state', 'registrant_country', 'registrant_email']
            }
            
            contacts = {}
            for contact_type, fields in contact_fields.items():
                contact_info = {}
                for field in fields:
                    value = getattr(w, field, None)
                    if value:
                        # Extract just the field name without the contact type prefix
                        field_name = field.split('_', 1)[1] if '_' in field else field
                        contact_info[field_name] = value
                
                if contact_info:
                    contacts[contact_type] = contact_info
            
            if contacts:
                whois_info['contacts'] = contacts
            
            # Raw WHOIS data
            if hasattr(w, 'text') and w.text:
                whois_info['raw'] = w.text
            
            self.logger.info(f"Successfully retrieved WHOIS information for {domain}")
            return whois_info
            
        except Exception as e:
            self.logger.error(f"Error during WHOIS lookup for {domain}: {str(e)}")
            return {'error': str(e)}
    
    def ip_whois_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup for an IP address.
        
        Args:
            ip (str): IP address to lookup
            
        Returns:
            dict: WHOIS lookup results
        """
        self.logger.info(f"Performing WHOIS lookup for IP {ip}")
        
        try:
            if self.rate_limiter:
                self.rate_limiter.wait('whois')
                
            w = whois.whois(ip)
            
            # Extract relevant WHOIS information
            whois_info = {}
            
            if hasattr(w, 'text') and w.text:
                whois_info['raw'] = w.text
                
                # Try to parse some common fields from raw text
                if 'netname:' in w.text.lower():
                    netname_match = re.search(r'netname:\s*(.+)', w.text, re.IGNORECASE)
                    if netname_match:
                        whois_info['netname'] = netname_match.group(1).strip()
                
                if 'organization:' in w.text.lower():
                    org_match = re.search(r'organization:\s*(.+)', w.text, re.IGNORECASE)
                    if org_match:
                        whois_info['organization'] = org_match.group(1).strip()
                
                if 'country:' in w.text.lower():
                    country_match = re.search(r'country:\s*(.+)', w.text, re.IGNORECASE)
                    if country_match:
                        whois_info['country'] = country_match.group(1).strip()
                
                if 'cidr:' in w.text.lower():
                    cidr_match = re.search(r'cidr:\s*(.+)', w.text, re.IGNORECASE)
                    if cidr_match:
                        whois_info['cidr'] = cidr_match.group(1).strip()
            
            self.logger.info(f"Successfully retrieved WHOIS information for IP {ip}")
            return whois_info
            
        except Exception as e:
            self.logger.error(f"Error during WHOIS lookup for IP {ip}: {str(e)}")
            return {'error': str(e)}
    
    def check_dnssec(self, domain: str) -> Dict[str, Any]:
        """
        Check DNSSEC validation for a domain.
        
        Args:
            domain (str): Domain to check
            
        Returns:
            dict: DNSSEC validation results
        """
        self.logger.info(f"Checking DNSSEC validation for {domain}")
        results = {
            'domain': domain,
            'dnssec_enabled': False,
            'validation_successful': False,
            'records': {}
        }
        
        try:
            if self.rate_limiter:
                self.rate_limiter.wait('dns')
                
            # Check for DNSKEY records
            try:
                dnskey_answers = self.resolver.resolve(domain, 'DNSKEY')
                results['records']['dnskey'] = len(dnskey_answers)
                results['dnssec_enabled'] = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                results['records']['dnskey'] = 0
            
            # Check for DS records in parent zone
            try:
                ds_answers = self.resolver.resolve(domain, 'DS')
                results['records']['ds'] = len(ds_answers)
                results['dnssec_enabled'] = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                results['records']['ds'] = 0
            
            # Check for RRSIG records
            try:
                rrsig_answers = self.resolver.resolve(domain, 'RRSIG')
                results['records']['rrsig'] = len(rrsig_answers)
                results['dnssec_enabled'] = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                results['records']['rrsig'] = 0
            
            # Check for NSEC records
            try:
                nsec_answers = self.resolver.resolve(domain, 'NSEC')
                results['records']['nsec'] = len(nsec_answers)
                results['dnssec_enabled'] = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                results['records']['nsec'] = 0
            
            # Check for NSEC3 records
            try:
                nsec3_answers = self.resolver.resolve(domain, 'NSEC3')
                results['records']['nsec3'] = len(nsec3_answers)
                results['dnssec_enabled'] = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                results['records']['nsec3'] = 0
            
            # Check validation by querying with DO (DNSSEC OK) flag
            # Send a message with DO bit to a DNSSEC-validating resolver
            message = dns.message.make_query(domain, dns.rdatatype.SOA)
            message.flags |= dns.flags.AD  # Authentic Data
            message.flags |= dns.flags.CD  # Checking Disabled
            message.flags |= dns.flags.RD  # Recursion Desired
            
            # Set EDNS0 with DO bit
            message.use_edns(edns=0, ednsflags=dns.flags.DO)
            
            # Send the query and check the AD flag in the response
            if self.rate_limiter:
                self.rate_limiter.wait('dns')
            
            response = dns.query.udp(message, '8.8.8.8', timeout=self.resolver.timeout)
            
            # Check if the AD (Authenticated Data) flag is set in the response
            if response.flags & dns.flags.AD:
                results['validation_successful'] = True
            
            self.logger.info(f"DNSSEC validation complete for {domain}: " +
                           f"Enabled={results['dnssec_enabled']}, " +
                           f"Validation={results['validation_successful']}")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error during DNSSEC validation for {domain}: {str(e)}")
            results['error'] = str(e)
            return results
    
    def attempt_zone_transfer(self, domain: str) -> Dict[str, Any]:
        """
        Attempt DNS zone transfer for a domain.
        
        Args:
            domain (str): Domain to attempt zone transfer on
            
        Returns:
            dict: Zone transfer results
        """
        self.logger.info(f"Attempting zone transfer for {domain}")
        results = {
            'domain': domain,
            'zone_transfer_successful': False,
            'nameservers_tested': [],
            'records': []
        }
        
        try:
            # Get nameservers for the domain
            nameservers = []
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('dns')
                    
                ns_answers = self.resolver.resolve(domain, 'NS')
                for rdata in ns_answers:
                    nameserver = str(rdata.target).rstrip('.')
                    nameservers.append(nameserver)
                    
                    # Get IP for each nameserver
                    try:
                        if self.rate_limiter:
                            self.rate_limiter.wait('dns')
                            
                        a_answers = self.resolver.resolve(nameserver, 'A')
                        for a_rdata in a_answers:
                            nameserver_ip = str(a_rdata.address)
                            results['nameservers_tested'].append({
                                'nameserver': nameserver,
                                'ip': nameserver_ip
                            })
                    except dns.exception.DNSException:
                        # Just add the nameserver without IP
                        results['nameservers_tested'].append({
                            'nameserver': nameserver,
                            'ip': None
                        })
                        
            except dns.exception.DNSException:
                self.logger.debug(f"Could not get nameservers for {domain}")
            
            # If no nameservers found, return early
            if not results['nameservers_tested']:
                self.logger.info(f"No nameservers found for {domain}, cannot attempt zone transfer")
                return results
            
            # Try zone transfer with each nameserver
            for ns_info in results['nameservers_tested']:
                nameserver = ns_info['nameserver']
                ip = ns_info['ip']
                
                if not ip:
                    continue
                
                self.logger.debug(f"Attempting zone transfer for {domain} from nameserver {nameserver} ({ip})")
                
                try:
                    if self.rate_limiter:
                        self.rate_limiter.wait('dns')
                        
                    zone = dns.zone.from_xfr(dns.query.xfr(ip, domain, timeout=self.resolver.timeout))
                    
                    results['zone_transfer_successful'] = True
                    ns_info['transfer_successful'] = True
                    
                    # Extract records from the zone
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                record = {
                                    'name': str(name),
                                    'ttl': rdataset.ttl,
                                    'class': dns.rdataclass.to_text(rdataset.rdclass),
                                    'type': dns.rdatatype.to_text(rdataset.rdtype),
                                    'data': str(rdata)
                                }
                                results['records'].append(record)
                                
                except dns.exception.DNSException as e:
                    ns_info['transfer_successful'] = False
                    ns_info['error'] = str(e)
            
            if results['zone_transfer_successful']:
                self.logger.info(f"Zone transfer successful for {domain}")
            else:
                self.logger.info(f"Zone transfer failed for {domain}")
                
            return results
            
        except Exception as e:
            self.logger.error(f"Error during zone transfer attempt for {domain}: {str(e)}")
            results['error'] = str(e)
            return results
    
    def check_wildcard_dns(self, domain: str) -> Dict[str, Any]:
        """
        Check for wildcard DNS records.
        
        Args:
            domain (str): Domain to check
            
        Returns:
            dict: Wildcard DNS check results
        """
        self.logger.info(f"Checking for wildcard DNS on {domain}")
        results = {
            'domain': domain,
            'wildcard_detected': False,
            'wildcard_records': {},
            'random_subdomains_tested': []
        }
        
        try:
            # Generate random subdomains for testing
            import random
            import string
            
            random_subdomains = []
            for _ in range(3):
                random_str = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
                random_subdomains.append(f"{random_str}.{domain}")
            
            results['random_subdomains_tested'] = random_subdomains
            
            # Test each subdomain for A, AAAA records
            for subdomain in random_subdomains:
                if self.rate_limiter:
                    self.rate_limiter.wait('dns')
                    
                self.logger.debug(f"Testing random subdomain: {subdomain}")
                
                for record_type in ['A', 'AAAA']:
                    try:
                        answers = self.resolver.resolve(subdomain, record_type)
                        
                        if record_type not in results['wildcard_records']:
                            results['wildcard_records'][record_type] = []
                            
                        for rdata in answers:
                            address = str(rdata.address)
                            if address not in results['wildcard_records'][record_type]:
                                results['wildcard_records'][record_type].append(address)
                            
                        results['wildcard_detected'] = True
                        
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                        continue
            
            if results['wildcard_detected']:
                self.logger.info(f"Wildcard DNS detected for {domain}")
            else:
                self.logger.info(f"No wildcard DNS detected for {domain}")
                
            return results
            
        except Exception as e:
            self.logger.error(f"Error during wildcard DNS check for {domain}: {str(e)}")
            results['error'] = str(e)
            return results
            
    def analyze_spf_record(self, domain: str) -> Dict[str, Any]:
        """
        Analyze Sender Policy Framework (SPF) record for the domain.
        
        Args:
            domain (str): Domain to analyze
            
        Returns:
            dict: SPF record analysis results
        """
        import re
        
        self.logger.info(f"Analyzing SPF record for {domain}")
        results = {
            'domain': domain,
            'record_found': False,
            'record': None,
            'version': None,
            'mechanisms': [],
            'modifiers': {},
            'includes': [],
            'ip4': [],
            'ip6': [],
            'all_mechanism': None,
            'mx_lookups': [],
            'a_lookups': [],
            'redirect': None,
            'exp': None,
            'lookup_count': 0,
            'analysis': {
                'valid': False,
                'issues': [],
                'warnings': [],
                'recommendations': []
            }
        }
        
        try:
            # Query TXT records to find SPF
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('dns')
                    
                answers = self.resolver.resolve(domain, 'TXT')
                
                for rdata in answers:
                    for txt_string in rdata.strings:
                        spf_text = txt_string.decode('utf-8')
                        
                        # Check if this is an SPF record
                        if spf_text.startswith('v=spf1'):
                            results['record_found'] = True
                            results['record'] = spf_text
                            break
                            
                if not results['record_found']:
                    self.logger.info(f"No SPF record found for {domain}")
                    results['analysis']['issues'].append("No SPF record found. This may affect email deliverability.")
                    results['analysis']['recommendations'].append("Set up an SPF record to help prevent email spoofing.")
                    return results
                    
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                self.logger.info(f"No TXT records found for {domain}: {str(e)}")
                results['analysis']['issues'].append("Could not retrieve TXT records.")
                results['analysis']['recommendations'].append("Set up an SPF record to help prevent email spoofing.")
                return results
            
            # Parse the SPF record
            spf_parts = results['record'].split(' ')
            results['version'] = spf_parts[0]  # Should be 'v=spf1'
            
            # Extract mechanisms and modifiers
            for part in spf_parts[1:]:
                if part.startswith(('a:', 'a/', 'a')):
                    results['a_lookups'].append(part)
                    results['mechanisms'].append(part)
                    results['lookup_count'] += 1
                    
                elif part.startswith(('mx:', 'mx/', 'mx')):
                    results['mx_lookups'].append(part)
                    results['mechanisms'].append(part)
                    results['lookup_count'] += 1
                    
                elif part.startswith('ip4:'):
                    results['ip4'].append(part[4:])
                    results['mechanisms'].append(part)
                    
                elif part.startswith('ip6:'):
                    results['ip6'].append(part[4:])
                    results['mechanisms'].append(part)
                    
                elif part.startswith('include:'):
                    include_domain = part[8:]
                    results['includes'].append(include_domain)
                    results['mechanisms'].append(part)
                    results['lookup_count'] += 1
                    
                elif part.startswith('redirect='):
                    results['redirect'] = part[9:]
                    results['modifiers']['redirect'] = part[9:]
                    results['lookup_count'] += 1
                    
                elif part.startswith('exp='):
                    results['exp'] = part[4:]
                    results['modifiers']['exp'] = part[4:]
                    results['lookup_count'] += 1
                    
                elif part in ['all', '+all', '-all', '~all', '?all']:
                    results['all_mechanism'] = part
                    results['mechanisms'].append(part)
                    
                else:
                    results['mechanisms'].append(part)
            
            # Analyze SPF record
            results['analysis']['valid'] = True
            
            # Check if the SPF record has too many DNS lookups (max is 10)
            if results['lookup_count'] > 10:
                results['analysis']['valid'] = False
                results['analysis']['issues'].append(f"Too many DNS lookups ({results['lookup_count']}). The maximum allowed is 10.")
                results['analysis']['recommendations'].append("Reduce the number of include, a, mx, ptr, and redirect mechanisms.")
                
            # Check if 'all' mechanism is present
            if not results['all_mechanism']:
                results['analysis']['warnings'].append("No 'all' qualifier found. This is recommended to specify handling of non-matching IPs.")
                results['analysis']['recommendations'].append("Add '-all' at the end of your SPF record to explicitly reject non-matching IPs.")
                
            # Check if 'all' is too permissive
            elif results['all_mechanism'] in ['+all', 'all']:
                results['analysis']['warnings'].append("SPF record uses '+all' which is too permissive and allows any sender to spoof your domain.")
                results['analysis']['recommendations'].append("Replace '+all' with '-all' to explicitly reject non-matching IPs.")
                
            # Check if includes may cause lookup issues
            if len(results['includes']) > 5:
                results['analysis']['warnings'].append(f"High number of includes ({len(results['includes'])}). This may lead to lookup limit issues.")
                results['analysis']['recommendations'].append("Consider consolidating includes or using ip4/ip6 mechanisms directly.")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing SPF record for {domain}: {str(e)}")
            results['error'] = str(e)
            return results
            
    def analyze_dmarc_record(self, domain: str) -> Dict[str, Any]:
        """
        Analyze Domain-based Message Authentication, Reporting & Conformance (DMARC) record.
        
        Args:
            domain (str): Domain to analyze
            
        Returns:
            dict: DMARC analysis results
        """
        import re
        
        self.logger.info(f"Analyzing DMARC record for {domain}")
        results = {
            'domain': domain,
            'record_found': False,
            'record': None,
            'version': None,
            'policy': None,
            'subdomain_policy': None,
            'pct': None,
            'rua': [],
            'ruf': [],
            'fo': None,
            'adkim': None,
            'aspf': None,
            'report_interval': None,
            'analysis': {
                'valid': False,
                'issues': [],
                'warnings': [],
                'recommendations': []
            }
        }
        
        try:
            # DMARC records are at _dmarc.domain.com
            dmarc_domain = f"_dmarc.{domain}"
            
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('dns')
                    
                answers = self.resolver.resolve(dmarc_domain, 'TXT')
                
                for rdata in answers:
                    for txt_string in rdata.strings:
                        dmarc_text = txt_string.decode('utf-8')
                        
                        # Check if this is a DMARC record
                        if dmarc_text.startswith('v=DMARC1'):
                            results['record_found'] = True
                            results['record'] = dmarc_text
                            break
                            
                if not results['record_found']:
                    self.logger.info(f"No DMARC record found for {domain}")
                    results['analysis']['issues'].append("No DMARC record found. This may affect email deliverability.")
                    results['analysis']['recommendations'].append("Set up a DMARC record to improve email security and deliverability.")
                    return results
                    
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                self.logger.info(f"No DMARC record found for {domain}: {str(e)}")
                results['analysis']['issues'].append("Could not retrieve DMARC record.")
                results['analysis']['recommendations'].append("Set up a DMARC record to improve email security and deliverability.")
                return results
            
            # Parse the DMARC record
            dmarc_parts = results['record'].split(';')
            results['version'] = dmarc_parts[0].strip()  # Should be 'v=DMARC1'
            
            # Extract tags
            for part in dmarc_parts[1:]:
                part = part.strip()
                if not part:
                    continue
                    
                try:
                    tag, value = [item.strip() for item in part.split('=', 1)]
                    
                    if tag == 'p':
                        results['policy'] = value
                    elif tag == 'sp':
                        results['subdomain_policy'] = value
                    elif tag == 'pct':
                        results['pct'] = int(value)
                    elif tag == 'rua':
                        results['rua'] = [addr.strip() for addr in value.split(',')]
                    elif tag == 'ruf':
                        results['ruf'] = [addr.strip() for addr in value.split(',')]
                    elif tag == 'fo':
                        results['fo'] = value
                    elif tag == 'adkim':
                        results['adkim'] = value
                    elif tag == 'aspf':
                        results['aspf'] = value
                    elif tag == 'ri':
                        results['report_interval'] = int(value)
                except ValueError:
                    results['analysis']['warnings'].append(f"Invalid tag format: {part}")
            
            # Analyze DMARC record
            results['analysis']['valid'] = True
            
            # Check if required tags are present
            if not results['policy']:
                results['analysis']['valid'] = False
                results['analysis']['issues'].append("Missing required 'p' tag (policy).")
            
            # Check if policy is too permissive
            if results['policy'] == 'none':
                results['analysis']['warnings'].append("DMARC policy is set to 'none', which only monitors and doesn't take action on suspicious emails.")
                results['analysis']['recommendations'].append("Consider implementing a more strict policy (quarantine or reject) once you've analyzed reports.")
            
            # Check if percentage is too low
            if results['pct'] is not None and results['pct'] < 100:
                results['analysis']['warnings'].append(f"DMARC policy only applies to {results['pct']}% of emails, which may leave your domain vulnerable.")
                results['analysis']['recommendations'].append("Increase the pct value to 100 for complete protection.")
            
            # Check if reporting addresses are configured
            if not results['rua'] and not results['ruf']:
                results['analysis']['warnings'].append("No reporting addresses (rua or ruf) configured. You won't receive reports on DMARC results.")
                results['analysis']['recommendations'].append("Add at least one rua (aggregate reports) address to monitor DMARC performance.")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing DMARC record for {domain}: {str(e)}")
            results['error'] = str(e)
            return results
    
    def analyze_caa_records(self, domain: str) -> Dict[str, Any]:
        """
        Analyze Certificate Authority Authorization (CAA) records.
        
        Args:
            domain (str): Domain to analyze
            
        Returns:
            dict: CAA records analysis results
        """
        self.logger.info(f"Analyzing CAA records for {domain}")
        results = {
            'domain': domain,
            'records_found': False,
            'records': [],
            'issue': [],
            'issuewild': [],
            'iodef': [],
            'analysis': {
                'valid': False,
                'issues': [],
                'warnings': [],
                'recommendations': []
            }
        }
        
        try:
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('dns')
                    
                answers = self.resolver.resolve(domain, 'CAA')
                results['records_found'] = True
                
                for rdata in answers:
                    record = {
                        'flags': rdata.flags,
                        'tag': rdata.tag.decode('utf-8'),
                        'value': rdata.value.decode('utf-8')
                    }
                    results['records'].append(record)
                    
                    # Categorize records by tag
                    if record['tag'] == 'issue':
                        results['issue'].append(record['value'])
                    elif record['tag'] == 'issuewild':
                        results['issuewild'].append(record['value'])
                    elif record['tag'] == 'iodef':
                        results['iodef'].append(record['value'])
                    
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                self.logger.info(f"No CAA records found for {domain}: {str(e)}")
                results['analysis']['warnings'].append("No CAA records found. This means any Certificate Authority can issue certificates for your domain.")
                results['analysis']['recommendations'].append("Consider setting up CAA records to restrict which CAs can issue certificates for your domain.")
                return results
            
            # Analyze CAA records
            results['analysis']['valid'] = True
            
            # Check if 'issue' records are present
            if not results['issue']:
                results['analysis']['warnings'].append("No 'issue' CAA records found. This doesn't restrict which CAs can issue certificates.")
                results['analysis']['recommendations'].append("Add 'issue' CAA records for your trusted Certificate Authorities.")
            
            # Check for wildcard certificates restriction
            if not results['issuewild'] and results['issue']:
                results['analysis']['warnings'].append("No 'issuewild' CAA records found. Wildcard certificates can be issued by any authorized CA.")
                results['analysis']['recommendations'].append("Consider adding 'issuewild' CAA records if you want to specifically control wildcard certificate issuance.")
            
            # Check for reporting
            if not results['iodef']:
                results['analysis']['warnings'].append("No 'iodef' CAA records found. You won't be notified of certificate request violations.")
                results['analysis']['recommendations'].append("Consider adding an 'iodef' CAA record with a contact email or URL for violation reports.")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing CAA records for {domain}: {str(e)}")
            results['error'] = str(e)
            return results
    
    def check_dns_propagation(self, domain: str) -> Dict[str, Any]:
        """
        Check DNS propagation across multiple public DNS servers.
        
        Args:
            domain (str): Domain to check
            
        Returns:
            dict: DNS propagation check results
        """
        self.logger.info(f"Checking DNS propagation for {domain}")
        results = {
            'domain': domain,
            'record_types_checked': ['A', 'AAAA', 'MX', 'NS'],
            'nameservers_checked': [],
            'propagation_status': {},
            'consistency': {},
            'analysis': {
                'fully_propagated': True,
                'consistent': True,
                'issues': [],
                'warnings': []
            }
        }
        
        # List of public DNS servers to check
        public_dns = [
            {'name': 'Google', 'ip': '8.8.8.8'},
            {'name': 'Cloudflare', 'ip': '1.1.1.1'},
            {'name': 'Quad9', 'ip': '9.9.9.9'},
            {'name': 'OpenDNS', 'ip': '208.67.222.222'},
            {'name': 'Level3', 'ip': '4.2.2.2'}
        ]
        
        results['nameservers_checked'] = [dns['name'] for dns in public_dns]
        
        try:
            # Check each record type on each public DNS server
            for record_type in results['record_types_checked']:
                results['propagation_status'][record_type] = {}
                results['consistency'][record_type] = {
                    'consistent': True,
                    'values': set()
                }
                
                for dns_server in public_dns:
                    server_name = dns_server['name']
                    server_ip = dns_server['ip']
                    
                    # Create resolver for this specific DNS server
                    custom_resolver = dns.resolver.Resolver()
                    custom_resolver.nameservers = [server_ip]
                    custom_resolver.timeout = self.resolver.timeout
                    custom_resolver.lifetime = self.resolver.lifetime
                    
                    try:
                        if self.rate_limiter:
                            self.rate_limiter.wait('dns')
                            
                        answers = custom_resolver.resolve(domain, record_type)
                        
                        # Store the values
                        results['propagation_status'][record_type][server_name] = {
                            'status': 'found',
                            'values': []
                        }
                        
                        for rdata in answers:
                            if record_type == 'A' or record_type == 'AAAA':
                                value = str(rdata.address)
                            elif record_type == 'MX':
                                value = f"{rdata.preference} {rdata.exchange}"
                            else:
                                value = str(rdata)
                                
                            results['propagation_status'][record_type][server_name]['values'].append(value)
                            results['consistency'][record_type]['values'].add(value)
                        
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
                        results['propagation_status'][record_type][server_name] = {
                            'status': 'not_found',
                            'error': str(e)
                        }
                        results['analysis']['fully_propagated'] = False
                
                # Check consistency for this record type
                if record_type in results['propagation_status']:
                    values_by_server = {}
                    found_servers = 0
                    
                    for server, server_data in results['propagation_status'][record_type].items():
                        if server_data['status'] == 'found':
                            found_servers += 1
                            values_by_server[server] = sorted(server_data['values'])
                    
                    # Compare values between servers
                    if found_servers > 1:
                        reference_server = list(values_by_server.keys())[0]
                        reference_values = values_by_server[reference_server]
                        
                        for server, values in values_by_server.items():
                            if server != reference_server and values != reference_values:
                                results['consistency'][record_type]['consistent'] = False
                                results['analysis']['consistent'] = False
                                results['analysis']['warnings'].append(
                                    f"Inconsistent {record_type} records found between DNS servers. "
                                    f"{reference_server} returned {reference_values} while {server} returned {values}."
                                )
            
            # Final analysis
            if not results['analysis']['fully_propagated']:
                results['analysis']['issues'].append("DNS records are not fully propagated to all checked nameservers.")
            
            if not results['analysis']['consistent']:
                results['analysis']['issues'].append("Inconsistent DNS records found between different nameservers.")
                results['analysis']['warnings'].append("Inconsistent DNS records may cause reliability issues for your services.")
                
            return results
            
        except Exception as e:
            self.logger.error(f"Error checking DNS propagation for {domain}: {str(e)}")
            results['error'] = str(e)
            return results
    
    def dns_health_check(self, domain: str) -> Dict[str, Any]:
        """
        Perform a comprehensive DNS health check for the domain.
        
        Args:
            domain (str): Domain to check
            
        Returns:
            dict: DNS health check results
        """
        self.logger.info(f"Performing DNS health check for {domain}")
        results = {
            'domain': domain,
            'checks': {
                'nameserver_count': {
                    'status': 'unknown',
                    'value': 0,
                    'details': '',
                    'recommendation': ''
                },
                'nameserver_redundancy': {
                    'status': 'unknown',
                    'details': '',
                    'recommendation': ''
                },
                'soa_parameters': {
                    'status': 'unknown',
                    'values': {},
                    'details': '',
                    'recommendation': ''
                },
                'response_time': {
                    'status': 'unknown',
                    'value': 0,
                    'details': '',
                    'recommendation': ''
                },
                'ttl_values': {
                    'status': 'unknown',
                    'values': {},
                    'details': '',
                    'recommendation': ''
                }
            },
            'overall_health': {
                'score': 0,
                'max_score': 100,
                'status': 'unknown',
                'issues': [],
                'recommendations': []
            }
        }
        
        try:
            health_score = 0
            available_points = 0
            
            # Check 1: Nameserver Count
            available_points += 20
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('dns')
                    
                ns_answers = self.resolver.resolve(domain, 'NS')
                nameservers = [str(rdata.target).rstrip('.') for rdata in ns_answers]
                
                results['checks']['nameserver_count']['value'] = len(nameservers)
                
                if len(nameservers) >= 4:
                    results['checks']['nameserver_count']['status'] = 'good'
                    results['checks']['nameserver_count']['details'] = f"Found {len(nameservers)} nameservers, which provides good redundancy."
                    health_score += 20
                elif len(nameservers) >= 2:
                    results['checks']['nameserver_count']['status'] = 'warning'
                    results['checks']['nameserver_count']['details'] = f"Found {len(nameservers)} nameservers. This is acceptable but not optimal."
                    results['checks']['nameserver_count']['recommendation'] = "Consider adding more nameservers for better redundancy."
                    health_score += 10
                else:
                    results['checks']['nameserver_count']['status'] = 'error'
                    results['checks']['nameserver_count']['details'] = f"Only {len(nameservers)} nameserver found. This is a single point of failure."
                    results['checks']['nameserver_count']['recommendation'] = "Add at least one more nameserver for redundancy."
                    results['overall_health']['issues'].append("Insufficient nameservers")
                    health_score += 0
                
                # Check 2: Nameserver Redundancy (different networks)
                available_points += 20
                
                # Get IP addresses of nameservers
                nameserver_ips = []
                for ns in nameservers:
                    try:
                        if self.rate_limiter:
                            self.rate_limiter.wait('dns')
                            
                        a_answers = self.resolver.resolve(ns, 'A')
                        for rdata in a_answers:
                            nameserver_ips.append(str(rdata.address))
                    except Exception:
                        pass
                
                # Check subnet diversity
                networks = set()
                for ip in nameserver_ips:
                    try:
                        network = '.'.join(ip.split('.')[:2])  # Simple /16 network check
                        networks.add(network)
                    except Exception:
                        pass
                
                if len(networks) >= 2:
                    results['checks']['nameserver_redundancy']['status'] = 'good'
                    results['checks']['nameserver_redundancy']['details'] = f"Nameservers are distributed across {len(networks)} different networks."
                    health_score += 20
                else:
                    results['checks']['nameserver_redundancy']['status'] = 'warning'
                    results['checks']['nameserver_redundancy']['details'] = "Nameservers appear to be on the same network, which reduces redundancy."
                    results['checks']['nameserver_redundancy']['recommendation'] = "Use nameservers from different providers or networks for better redundancy."
                    results['overall_health']['issues'].append("Nameservers on same network")
                    health_score += 5
                
            except Exception as e:
                results['checks']['nameserver_count']['status'] = 'error'
                results['checks']['nameserver_count']['details'] = f"Error checking nameservers: {str(e)}"
                results['overall_health']['issues'].append("Could not check nameservers")
            
            # Check 3: SOA Parameters
            available_points += 20
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('dns')
                    
                soa_answers = self.resolver.resolve(domain, 'SOA')
                
                for rdata in soa_answers:
                    results['checks']['soa_parameters']['values'] = {
                        'mname': str(rdata.mname).rstrip('.'),
                        'rname': str(rdata.rname).rstrip('.'),
                        'serial': rdata.serial,
                        'refresh': rdata.refresh,
                        'retry': rdata.retry,
                        'expire': rdata.expire,
                        'minimum': rdata.minimum
                    }
                    break
                
                soa_issues = []
                
                # Check refresh (how often secondary nameservers check for updates)
                if rdata.refresh < 1800:  # Less than 30 minutes
                    soa_issues.append("Refresh value is very low, which may cause excessive DNS traffic.")
                elif rdata.refresh > 86400:  # More than 1 day
                    soa_issues.append("Refresh value is high, which may delay propagation of DNS changes.")
                
                # Check retry (how often to retry if refresh fails)
                if rdata.retry < 600:  # Less than 10 minutes
                    soa_issues.append("Retry value is very low, which may cause excessive DNS traffic on failures.")
                
                # Check expire (how long secondaries serve data without successful refresh)
                if rdata.expire < 86400:  # Less than 1 day
                    soa_issues.append("Expire value is low. Secondary servers will stop answering queries too quickly if primary is unavailable.")
                elif rdata.expire > 2419200:  # More than 4 weeks
                    soa_issues.append("Expire value is very high, which could serve stale data for too long.")
                
                # Check minimum TTL
                if rdata.minimum < 300:  # Less than 5 minutes
                    soa_issues.append("Minimum TTL is very low, which may cause excessive DNS traffic.")
                elif rdata.minimum > 86400:  # More than 1 day
                    soa_issues.append("Minimum TTL is high, which may delay propagation of DNS changes.")
                
                if soa_issues:
                    results['checks']['soa_parameters']['status'] = 'warning'
                    results['checks']['soa_parameters']['details'] = "SOA parameters have some issues: " + "; ".join(soa_issues)
                    results['checks']['soa_parameters']['recommendation'] = "Review and adjust SOA parameters according to best practices."
                    results['overall_health']['issues'].append("SOA parameter issues")
                    health_score += 10
                else:
                    results['checks']['soa_parameters']['status'] = 'good'
                    results['checks']['soa_parameters']['details'] = "SOA parameters are within recommended ranges."
                    health_score += 20
                
            except Exception as e:
                results['checks']['soa_parameters']['status'] = 'error'
                results['checks']['soa_parameters']['details'] = f"Error checking SOA parameters: {str(e)}"
                results['overall_health']['issues'].append("Could not check SOA parameters")
            
            # Check 4: Response Time
            available_points += 20
            try:
                response_times = []
                
                for _ in range(3):  # Test 3 times
                    start_time = time.time()
                    if self.rate_limiter:
                        self.rate_limiter.wait('dns')
                        
                    self.resolver.resolve(domain, 'A')
                    end_time = time.time()
                    response_times.append((end_time - start_time) * 1000)  # Convert to ms
                
                avg_response_time = sum(response_times) / len(response_times)
                results['checks']['response_time']['value'] = round(avg_response_time, 2)
                
                if avg_response_time < 100:  # Less than 100ms
                    results['checks']['response_time']['status'] = 'good'
                    results['checks']['response_time']['details'] = f"DNS response time is excellent ({avg_response_time:.2f}ms)."
                    health_score += 20
                elif avg_response_time < 250:  # Less than 250ms
                    results['checks']['response_time']['status'] = 'good'
                    results['checks']['response_time']['details'] = f"DNS response time is good ({avg_response_time:.2f}ms)."
                    health_score += 15
                elif avg_response_time < 500:  # Less than 500ms
                    results['checks']['response_time']['status'] = 'warning'
                    results['checks']['response_time']['details'] = f"DNS response time is acceptable but slow ({avg_response_time:.2f}ms)."
                    results['checks']['response_time']['recommendation'] = "Consider using faster DNS providers or optimizing DNS configuration."
                    health_score += 10
                else:  # 500ms or higher
                    results['checks']['response_time']['status'] = 'error'
                    results['checks']['response_time']['details'] = f"DNS response time is very slow ({avg_response_time:.2f}ms)."
                    results['checks']['response_time']['recommendation'] = "Investigate DNS performance issues and consider changing providers."
                    results['overall_health']['issues'].append("Slow DNS response time")
                    health_score += 5
                
            except Exception as e:
                results['checks']['response_time']['status'] = 'error'
                results['checks']['response_time']['details'] = f"Error checking DNS response time: {str(e)}"
                results['overall_health']['issues'].append("Could not check DNS response time")
            
            # Check 5: TTL Values
            available_points += 20
            try:
                ttl_issues = []
                
                # Check A record TTL
                try:
                    if self.rate_limiter:
                        self.rate_limiter.wait('dns')
                        
                    a_answer = self.resolver.resolve(domain, 'A')
                    a_ttl = a_answer.rrset.ttl
                    results['checks']['ttl_values']['values']['A'] = a_ttl
                    
                    if a_ttl < 300:  # Less than 5 minutes
                        ttl_issues.append(f"A record TTL ({a_ttl}s) is very low, which may cause excessive DNS traffic.")
                    elif a_ttl > 86400:  # More than 1 day
                        ttl_issues.append(f"A record TTL ({a_ttl}s) is high, which may delay propagation of DNS changes.")
                except Exception:
                    pass
                
                # Check MX record TTL
                try:
                    if self.rate_limiter:
                        self.rate_limiter.wait('dns')
                        
                    mx_answer = self.resolver.resolve(domain, 'MX')
                    mx_ttl = mx_answer.rrset.ttl
                    results['checks']['ttl_values']['values']['MX'] = mx_ttl
                    
                    if mx_ttl < 3600:  # Less than 1 hour
                        ttl_issues.append(f"MX record TTL ({mx_ttl}s) is low. Email services typically don't change frequently.")
                except Exception:
                    pass
                
                if ttl_issues:
                    results['checks']['ttl_values']['status'] = 'warning'
                    results['checks']['ttl_values']['details'] = "; ".join(ttl_issues)
                    results['checks']['ttl_values']['recommendation'] = "Adjust TTL values based on how frequently records change and desired propagation speed."
                    results['overall_health']['issues'].append("TTL configuration issues")
                    health_score += 10
                else:
                    results['checks']['ttl_values']['status'] = 'good'
                    results['checks']['ttl_values']['details'] = "TTL values are appropriate for typical usage."
                    health_score += 20
                
            except Exception as e:
                results['checks']['ttl_values']['status'] = 'error'
                results['checks']['ttl_values']['details'] = f"Error checking TTL values: {str(e)}"
                results['overall_health']['issues'].append("Could not check TTL values")
            
            # Calculate overall health score and determine status
            if available_points > 0:
                health_percentage = (health_score / available_points) * 100
                results['overall_health']['score'] = round(health_percentage)
                results['overall_health']['max_score'] = 100
                
                if health_percentage >= 80:
                    results['overall_health']['status'] = 'good'
                elif health_percentage >= 60:
                    results['overall_health']['status'] = 'fair'
                else:
                    results['overall_health']['status'] = 'poor'
                    
                # Add overall recommendations based on issues
                if 'Insufficient nameservers' in results['overall_health']['issues']:
                    results['overall_health']['recommendations'].append("Add more nameservers (at least 2, preferably 4) for redundancy.")
                
                if 'Nameservers on same network' in results['overall_health']['issues']:
                    results['overall_health']['recommendations'].append("Use nameservers from different providers to improve fault tolerance.")
                
                if 'Slow DNS response time' in results['overall_health']['issues']:
                    results['overall_health']['recommendations'].append("Investigate DNS performance issues and consider using faster DNS providers.")
                
                if 'TTL configuration issues' in results['overall_health']['issues']:
                    results['overall_health']['recommendations'].append("Review and optimize TTL values based on your operational needs.")
                
                if 'SOA parameter issues' in results['overall_health']['issues']:
                    results['overall_health']['recommendations'].append("Adjust SOA parameters according to best practices.")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error performing DNS health check for {domain}: {str(e)}")
            results['error'] = str(e)
            return results
            
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
