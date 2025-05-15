"""
Subdomain Enumeration Module for LUINT.
Handles passive and active subdomain discovery techniques including brute force, permutation scanning,
passive sources (VirusTotal, URLScan.io, crt.sh), and virtual host discovery.
"""
import dns.resolver
import dns.exception
import concurrent.futures
import socket
import requests
import re
import time
import json
import random
import string
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urlparse

from luint.utils.logger import get_logger, LoggerAdapter
from luint.utils.helpers import is_ip_address, is_domain
from luint.utils.output_manager import progress_bar
from luint.constants import API_ENDPOINTS

logger = get_logger()


class SubdomainEnumScanner:
    """
    Subdomain Enumeration Scanner for LUINT.
    Discovers subdomains using various techniques.
    """
    
    def __init__(self, target: str, config: Dict = None, 
                 cache_manager=None, rate_limiter=None, api_key_manager=None):
        """
        Initialize the Subdomain Enumeration Scanner.
        
        Args:
            target (str): Domain to scan
            config (dict, optional): Module configuration
            cache_manager: Cache manager instance
            rate_limiter: Rate limiter instance
            api_key_manager: API key manager instance
        """
        self.target = target
        self.config = config or {}
        self.module_config = self.config.get('modules', {}).get('subdomain_enum', {})
        self.cache_manager = cache_manager
        self.rate_limiter = rate_limiter
        self.api_key_manager = api_key_manager
        
        # Setup module-specific logger
        self.logger = LoggerAdapter(logger, module_name='subdomain_enum', target=target)
        
        # Clean and validate the target
        self.target = self._clean_target(target)
        
        # Max number of subdomains to discover
        self.max_subdomains = self.module_config.get('max_subdomains', 500)
        
        # Wordlist configuration
        self.wordlist_path = self.module_config.get('wordlist_path', '')
        
        # DNS resolver configuration
        self.setup_resolver()
    
    def setup_resolver(self):
        """Configure the DNS resolver with settings from the configuration."""
        self.resolver = dns.resolver.Resolver()
        
        # Set DNS servers from config
        dns_servers = self.config.get('modules', {}).get('dns_info', {}).get('dns_servers', ['8.8.8.8', '1.1.1.1'])
        if dns_servers:
            self.resolver.nameservers = dns_servers
            
        # Set timeout
        timeout = self.config.get('modules', {}).get('dns_info', {}).get('timeout', 5)
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def _clean_target(self, target: str) -> str:
        """
        Clean and validate the target domain.
        
        Args:
            target (str): Target to clean
            
        Returns:
            str: Cleaned target
        """
        # Remove protocol if present
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            target = parsed.netloc
            
        # Remove www. prefix if present
        if target.startswith('www.'):
            target = target[4:]
            
        # Remove any trailing slashes, paths, query strings, etc.
        target = target.split('/')[0]
        target = target.split('?')[0]
        target = target.split('#')[0]
        
        # Check if it's a valid domain
        if not is_domain(target):
            self.logger.error(f"Target {target} is not a valid domain")
            raise ValueError(f"Target {target} is not a valid domain. Subdomain enumeration requires a valid domain name.")
        
        return target
    
    def scan(self) -> Dict[str, Any]:
        """
        Run all subdomain enumeration methods.
        
        Returns:
            dict: Consolidated subdomain enumeration results
        """
        results = {
            'domain': self.target,
            'subdomains': [],
            'total_discovered': 0
        }
        
        # Check cache first
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='subdomain_enum')
            if cached_results:
                self.logger.info(f"Using cached subdomain enumeration results for {self.target}")
                return cached_results
        
        # Track all discovered subdomains across methods
        all_subdomains = set()
        
        # Passive subdomain discovery
        passive_results = self.passive_subdomain_discovery()
        if passive_results:
            results['passive_discovery'] = passive_results
            for source, subdomains in passive_results.items():
                if isinstance(subdomains, list):
                    all_subdomains.update(subdomains)
        
        # Brute force subdomain discovery
        brute_force_results = self.brute_force_subdomains()
        if brute_force_results:
            results['brute_force'] = brute_force_results
            all_subdomains.update(brute_force_results.get('discovered', []))
        
        # Permutation scanning
        permutation_results = self.permutation_scanning(list(all_subdomains))
        if permutation_results:
            results['permutation'] = permutation_results
            all_subdomains.update(permutation_results.get('discovered', []))
        
        # Virtual host discovery
        vhost_results = self.virtual_host_discovery()
        if vhost_results:
            results['virtual_hosts'] = vhost_results
            all_subdomains.update([vh.get('hostname') for vh in vhost_results.get('discovered', [])])
        
        # Compile all unique subdomains
        results['subdomains'] = sorted(list(all_subdomains))
        results['total_discovered'] = len(results['subdomains'])
        
        # Resolve all discovered subdomains
        if results['subdomains']:
            resolution_results = self.resolve_subdomains(results['subdomains'])
            if resolution_results:
                results['resolution'] = resolution_results
        
        # Cache results if cache manager is available
        if self.cache_manager and results:
            self.cache_manager.set(self.target, results, namespace='subdomain_enum')
            
        self.logger.info(f"Discovered {results['total_discovered']} subdomains for {self.target}")
        return results
    
    def passive_subdomain_discovery(self) -> Dict[str, List[str]]:
        """
        Discover subdomains using passive techniques.
        
        Returns:
            dict: Passive subdomain discovery results grouped by source
        """
        self.logger.info(f"Starting passive subdomain discovery for {self.target}")
        results = {}
        
        # VirusTotal API
        vt_subdomains = self.virustotal_subdomains()
        if vt_subdomains:
            results['virustotal'] = vt_subdomains
        
        # URLScan.io API
        urlscan_subdomains = self.urlscan_subdomains()
        if urlscan_subdomains:
            results['urlscan'] = urlscan_subdomains
        
        # crt.sh (Certificate Transparency logs)
        crtsh_subdomains = self.crtsh_subdomains()
        if crtsh_subdomains:
            results['crtsh'] = crtsh_subdomains
        
        # AlienvaultOTX (if key is available)
        if self.api_key_manager and self.api_key_manager.has_key('otx'):
            otx_subdomains = self.otx_subdomains()
            if otx_subdomains:
                results['otx'] = otx_subdomains
        
        # SecurityTrails (if key is available)
        if self.api_key_manager and self.api_key_manager.has_key('securitytrails'):
            securitytrails_subdomains = self.securitytrails_subdomains()
            if securitytrails_subdomains:
                results['securitytrails'] = securitytrails_subdomains
        
        # Compile summary
        total_passive = sum(len(subdomains) for subdomains in results.values())
        self.logger.info(f"Passive discovery found {total_passive} subdomains from {len(results)} sources")
        
        return results
    
    def virustotal_subdomains(self) -> List[str]:
        """
        Get subdomains from VirusTotal API.
        
        Returns:
            list: Subdomains discovered from VirusTotal
        """
        self.logger.info(f"Checking VirusTotal for subdomains of {self.target}")
        subdomains = []
        
        # Check if we have a VirusTotal API key
        if not self.api_key_manager or not self.api_key_manager.has_key('virustotal'):
            self.logger.warning("No VirusTotal API key available")
            return subdomains
        
        vt_api_key = self.api_key_manager.get_key('virustotal')
        
        try:
            # Use the domain endpoint
            url = API_ENDPOINTS['virustotal']['domain'].format(target=self.target)
            
            if self.rate_limiter:
                self.rate_limiter.wait('virustotal')
            
            response = requests.get(
                url,
                headers={
                    'x-apikey': vt_api_key
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract subdomains from the response
                if 'data' in data and 'attributes' in data['data'] and 'last_dns_records' in data['data']['attributes']:
                    for record in data['data']['attributes'].get('last_dns_records', []):
                        if record.get('type') == 'A' or record.get('type') == 'AAAA':
                            subdomain = record.get('value')
                            if subdomain and subdomain not in subdomains and subdomain.endswith(f".{self.target}"):
                                subdomains.append(subdomain)
                
                # Try to get subdomains from the relationships data
                if 'data' in data and 'relationships' in data['data'] and 'subdomains' in data['data']['relationships']:
                    subdomain_data = data['data']['relationships']['subdomains']
                    if 'data' in subdomain_data:
                        for item in subdomain_data['data']:
                            subdomain = item.get('id', '')
                            if subdomain and subdomain not in subdomains and subdomain.endswith(f".{self.target}"):
                                subdomains.append(subdomain)
                
                self.logger.info(f"Found {len(subdomains)} subdomains from VirusTotal")
            else:
                self.logger.warning(f"VirusTotal API returned status code {response.status_code}")
        
        except requests.RequestException as e:
            self.logger.error(f"Error querying VirusTotal API: {str(e)}")
        
        return subdomains
    
    def urlscan_subdomains(self) -> List[str]:
        """
        Get subdomains from URLScan.io API.
        
        Returns:
            list: Subdomains discovered from URLScan.io
        """
        self.logger.info(f"Checking URLScan.io for subdomains of {self.target}")
        subdomains = []
        
        # Check if we have a URLScan API key
        urlscan_api_key = None
        if self.api_key_manager and self.api_key_manager.has_key('urlscan'):
            urlscan_api_key = self.api_key_manager.get_key('urlscan')
        
        try:
            # Use the search endpoint
            search_url = API_ENDPOINTS['urlscan']['search']
            
            # Prepare headers
            headers = {
                'Content-Type': 'application/json'
            }
            
            if urlscan_api_key:
                headers['API-Key'] = urlscan_api_key
            
            # Search for the domain
            search_query = f"domain:{self.target}"
            
            if self.rate_limiter:
                self.rate_limiter.wait('urlscan')
            
            response = requests.get(
                search_url,
                params={'q': search_query},
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'results' in data:
                    # Extract unique subdomains from the results
                    for result in data['results']:
                        page = result.get('page', {})
                        domain = page.get('domain', '')
                        
                        if domain and domain != self.target and domain.endswith(f".{self.target}"):
                            if domain not in subdomains:
                                subdomains.append(domain)
                
                self.logger.info(f"Found {len(subdomains)} subdomains from URLScan.io")
            else:
                self.logger.warning(f"URLScan.io API returned status code {response.status_code}")
        
        except requests.RequestException as e:
            self.logger.error(f"Error querying URLScan.io API: {str(e)}")
        
        return subdomains
    
    def crtsh_subdomains(self) -> List[str]:
        """
        Get subdomains from crt.sh (Certificate Transparency logs).
        
        Returns:
            list: Subdomains discovered from crt.sh
        """
        self.logger.info(f"Checking crt.sh for subdomains of {self.target}")
        subdomains = []
        
        try:
            # Use the crt.sh JSON endpoint
            url = API_ENDPOINTS['crtsh']['domain'].format(target=self.target)
            
            if self.rate_limiter:
                self.rate_limiter.wait('http')
            
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    # Extract unique subdomains
                    for cert in data:
                        name_value = cert.get('name_value', '')
                        
                        # Look for wildcard domains and normal domains
                        if name_value:
                            # Split by newlines and process each entry
                            for entry in name_value.split('\n'):
                                entry = entry.strip()
                                
                                # Skip if entry is empty or only a wildcard
                                if not entry or entry == f"*.{self.target}":
                                    continue
                                
                                # Remove wildcard part if present
                                domain = entry.replace(f"*.{self.target}", f".{self.target}")
                                
                                # Check if domain is related to our target
                                if domain.endswith(f".{self.target}"):
                                    if domain not in subdomains:
                                        subdomains.append(domain)
                    
                    self.logger.info(f"Found {len(subdomains)} subdomains from crt.sh")
                except json.JSONDecodeError:
                    self.logger.warning("Failed to parse JSON response from crt.sh")
            else:
                self.logger.warning(f"crt.sh returned status code {response.status_code}")
        
        except requests.RequestException as e:
            self.logger.error(f"Error querying crt.sh: {str(e)}")
        
        return subdomains
    
    def otx_subdomains(self) -> List[str]:
        """
        Get subdomains from AlienVault OTX.
        
        Returns:
            list: Subdomains discovered from OTX
        """
        self.logger.info(f"Checking AlienVault OTX for subdomains of {self.target}")
        subdomains = []
        
        # Check if we have an OTX API key
        if not self.api_key_manager or not self.api_key_manager.has_key('otx'):
            self.logger.warning("No OTX API key available")
            return subdomains
        
        otx_api_key = self.api_key_manager.get_key('otx')
        
        try:
            # OTX API endpoint for passive DNS
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.target}/passive_dns"
            
            if self.rate_limiter:
                self.rate_limiter.wait('http')
            
            response = requests.get(
                url,
                headers={
                    'X-OTX-API-KEY': otx_api_key
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'passive_dns' in data:
                    for record in data['passive_dns']:
                        hostname = record.get('hostname', '')
                        
                        if hostname and hostname.endswith(f".{self.target}"):
                            if hostname not in subdomains:
                                subdomains.append(hostname)
                
                self.logger.info(f"Found {len(subdomains)} subdomains from OTX")
            else:
                self.logger.warning(f"OTX API returned status code {response.status_code}")
        
        except requests.RequestException as e:
            self.logger.error(f"Error querying OTX API: {str(e)}")
        
        return subdomains
    
    def securitytrails_subdomains(self) -> List[str]:
        """
        Get subdomains from SecurityTrails API.
        
        Returns:
            list: Subdomains discovered from SecurityTrails
        """
        self.logger.info(f"Checking SecurityTrails for subdomains of {self.target}")
        subdomains = []
        
        # Check if we have a SecurityTrails API key
        if not self.api_key_manager or not self.api_key_manager.has_key('securitytrails'):
            self.logger.warning("No SecurityTrails API key available")
            return subdomains
        
        securitytrails_api_key = self.api_key_manager.get_key('securitytrails')
        
        try:
            # SecurityTrails subdomains endpoint
            url = f"https://api.securitytrails.com/v1/domain/{self.target}/subdomains"
            
            if self.rate_limiter:
                self.rate_limiter.wait('http')
            
            response = requests.get(
                url,
                headers={
                    'APIKEY': securitytrails_api_key
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        # SecurityTrails returns just the subdomain part, we need to append the main domain
                        full_subdomain = f"{subdomain}.{self.target}"
                        if full_subdomain not in subdomains:
                            subdomains.append(full_subdomain)
                
                self.logger.info(f"Found {len(subdomains)} subdomains from SecurityTrails")
            else:
                self.logger.warning(f"SecurityTrails API returned status code {response.status_code}")
        
        except requests.RequestException as e:
            self.logger.error(f"Error querying SecurityTrails API: {str(e)}")
        
        return subdomains
    
    def load_wordlist(self) -> List[str]:
        """
        Load subdomain wordlist from file or use a default list.
        
        Returns:
            list: Wordlist of potential subdomains
        """
        wordlist = []
        
        # Try to load from specified path
        if self.wordlist_path:
            try:
                with open(self.wordlist_path, 'r') as file:
                    wordlist = [line.strip() for line in file if line.strip()]
                self.logger.info(f"Loaded {len(wordlist)} entries from wordlist {self.wordlist_path}")
                return wordlist
            except (IOError, OSError) as e:
                self.logger.warning(f"Failed to load wordlist from {self.wordlist_path}: {str(e)}")
        
        # Use a small default wordlist
        default_wordlist = [
            "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", 
            "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal",
            "admin", "intranet", "git", "jenkins", "shop", "db", "database",
            "proxy", "cdn", "status", "status", "images", "img", "auth", "beta",
            "ftp", "sftp", "apps", "app", "mobile", "m", "media", "help", "redirect",
            "store", "login", "office", "demo", "internal", "wiki", "support", "docs",
            "backup", "monitor", "grafana", "localhost", "metrics", "dashboard", "download"
        ]
        
        self.logger.info(f"Using default wordlist with {len(default_wordlist)} entries")
        return default_wordlist
    
    def brute_force_subdomains(self) -> Dict[str, Any]:
        """
        Discover subdomains using brute force technique.
        
        Returns:
            dict: Brute force subdomain discovery results
        """
        self.logger.info(f"Starting brute force subdomain discovery for {self.target}")
        
        wordlist = self.load_wordlist()
        
        # Use a smaller list if the default is too large
        if len(wordlist) > 1000:
            self.logger.info(f"Wordlist is large ({len(wordlist)} entries), using a subset")
            wordlist = wordlist[:1000]
        
        results = {
            'wordlist_size': len(wordlist),
            'discovered': [],
            'total_discovered': 0
        }
        
        # Function to check a subdomain
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.target}"
            
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('dns')
                    
                answers = self.resolver.resolve(full_domain, 'A')
                if answers:
                    return full_domain
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                pass
            
            return None
        
        # Create progress bar
        with progress_bar(f"Brute forcing subdomains for {self.target}", unit="subdomains") as progress:
            progress.update(total=len(wordlist))
            
            # Use ThreadPoolExecutor for parallel checks
            discovered = set()
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain for subdomain in wordlist}
                
                completed = 0
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    completed += 1
                    progress.update(advance=1)
                    
                    result = future.result()
                    if result:
                        discovered.add(result)
                        
                    # Check if we've hit the max subdomains limit
                    if len(discovered) >= self.max_subdomains:
                        self.logger.info(f"Reached maximum subdomain limit ({self.max_subdomains}), stopping brute force")
                        break
        
        results['discovered'] = sorted(list(discovered))
        results['total_discovered'] = len(results['discovered'])
        self.logger.info(f"Brute force discovered {results['total_discovered']} subdomains for {self.target}")
        
        return results
    
    def permutation_scanning(self, existing_subdomains: List[str]) -> Dict[str, Any]:
        """
        Discover subdomains using permutation of existing subdomains.
        
        Args:
            existing_subdomains (list): List of already-discovered subdomains
            
        Returns:
            dict: Permutation scanning results
        """
        self.logger.info(f"Starting permutation scanning for {self.target}")
        
        if not existing_subdomains:
            self.logger.info("No existing subdomains to permutate")
            return {
                'discovered': [],
                'total_discovered': 0
            }
        
        results = {
            'base_subdomains': len(existing_subdomains),
            'permutations_generated': 0,
            'discovered': [],
            'total_discovered': 0
        }
        
        # Extract subdomain parts from existing subdomains
        subdomain_parts = set()
        for subdomain in existing_subdomains:
            if subdomain.endswith(f".{self.target}"):
                # Extract the subdomain part without the main domain
                parts = subdomain[:-len(f".{self.target}")].split('.')
                subdomain_parts.update(parts)
        
        # Add some common prefixes and suffixes
        prefixes = ['dev', 'test', 'stage', 'prod', 'api', 'app', 'admin', 'portal', 'beta']
        suffixes = ['2', '3', 'dev', 'staging', 'test', 'prod', 'backup', 'old', 'new', 'net', 'internal']
        
        # Generate permutations
        permutations = set()
        
        # Add subdomain parts with prefixes/suffixes
        for part in subdomain_parts:
            for prefix in prefixes:
                permutations.add(f"{prefix}-{part}")
                permutations.add(f"{prefix}.{part}")
            
            for suffix in suffixes:
                permutations.add(f"{part}-{suffix}")
                permutations.add(f"{part}.{suffix}")
        
        # Add combinations of subdomain parts
        parts_list = list(subdomain_parts)
        if len(parts_list) > 1:
            for i in range(min(len(parts_list), 10)):  # Limit to avoid exponential growth
                for j in range(i+1, min(len(parts_list), 10)):
                    permutations.add(f"{parts_list[i]}-{parts_list[j]}")
                    permutations.add(f"{parts_list[i]}.{parts_list[j]}")
        
        # Remove any that are already in the existing subdomains list
        permutations = {p for p in permutations if f"{p}.{self.target}" not in existing_subdomains}
        
        results['permutations_generated'] = len(permutations)
        
        # Function to check a permutation
        def check_permutation(permutation):
            full_domain = f"{permutation}.{self.target}"
            
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('dns')
                    
                answers = self.resolver.resolve(full_domain, 'A')
                if answers:
                    return full_domain
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                pass
            
            return None
        
        # Limit number of permutations to check
        max_permutations = 1000
        if len(permutations) > max_permutations:
            self.logger.info(f"Limiting permutations from {len(permutations)} to {max_permutations}")
            permutations = set(list(permutations)[:max_permutations])
        
        # Create progress bar
        with progress_bar(f"Checking permutations for {self.target}", unit="permutations") as progress:
            progress.update(total=len(permutations))
            
            # Use ThreadPoolExecutor for parallel checks
            discovered = set()
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_permutation = {executor.submit(check_permutation, permutation): permutation for permutation in permutations}
                
                completed = 0
                for future in concurrent.futures.as_completed(future_to_permutation):
                    completed += 1
                    progress.update(advance=1)
                    
                    result = future.result()
                    if result:
                        discovered.add(result)
                        
                    # Check if we've hit the max subdomains limit
                    if len(discovered) >= self.max_subdomains:
                        self.logger.info(f"Reached maximum subdomain limit ({self.max_subdomains}), stopping permutation scanning")
                        break
        
        results['discovered'] = sorted(list(discovered))
        results['total_discovered'] = len(results['discovered'])
        self.logger.info(f"Permutation scanning discovered {results['total_discovered']} new subdomains for {self.target}")
        
        return results
    
    def virtual_host_discovery(self) -> Dict[str, Any]:
        """
        Discover virtual hosts by checking for different responses with different Host headers.
        
        Returns:
            dict: Virtual host discovery results
        """
        self.logger.info(f"Starting virtual host discovery for {self.target}")
        
        # First we need to get the IP address(es) for the target
        target_ips = []
        try:
            answers = self.resolver.resolve(self.target, 'A')
            for rdata in answers:
                target_ips.append(str(rdata.address))
        except dns.exception.DNSException:
            self.logger.warning(f"Could not resolve {self.target} to an IP address")
            return {
                'discovered': [],
                'total_discovered': 0,
                'error': f"Could not resolve {self.target} to an IP address"
            }
        
        if not target_ips:
            self.logger.warning(f"No IP addresses found for {self.target}")
            return {
                'discovered': [],
                'total_discovered': 0,
                'error': f"No IP addresses found for {self.target}"
            }
        
        # Use the first IP
        target_ip = target_ips[0]
        self.logger.info(f"Using IP address {target_ip} for virtual host discovery")
        
        results = {
            'target_ip': target_ip,
            'discovered': [],
            'total_discovered': 0
        }
        
        # Create a list of subdomains to check (both discovered and potential ones)
        subdomains_to_check = []
        
        # Check if we have discovered subdomains from other methods
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='subdomain_enum')
            if cached_results and 'subdomains' in cached_results:
                subdomains_to_check.extend(cached_results['subdomains'])
        
        # Add some common subdomains if we don't have many
        if len(subdomains_to_check) < 10:
            common_subdomains = [
                f"www.{self.target}",
                f"dev.{self.target}",
                f"admin.{self.target}",
                f"api.{self.target}",
                f"mail.{self.target}",
                f"webmail.{self.target}",
                f"remote.{self.target}",
                f"vpn.{self.target}",
                f"ftp.{self.target}",
                f"test.{self.target}"
            ]
            subdomains_to_check.extend(common_subdomains)
        
        # Add random subdomains for baseline comparison
        random_subdomains = []
        for _ in range(3):
            random_str = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
            random_subdomains.append(f"{random_str}.{self.target}")
        
        # Remove duplicates
        subdomains_to_check = list(set(subdomains_to_check))
        
        # Get response for random subdomains (baseline)
        baseline_responses = []
        
        for subdomain in random_subdomains:
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('http')
                    
                # Connect directly to the IP with a custom Host header
                response = requests.get(
                    f"http://{target_ip}",
                    headers={
                        'Host': subdomain,
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                    },
                    timeout=10,
                    allow_redirects=False
                )
                
                baseline_responses.append({
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'headers': dict(response.headers)
                })
            except requests.RequestException:
                pass
        
        if not baseline_responses:
            self.logger.warning(f"Could not establish baseline responses for {self.target}")
            return results
        
        # Function to check a virtual host
        def check_vhost(subdomain):
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('http')
                    
                # Connect directly to the IP with a custom Host header
                response = requests.get(
                    f"http://{target_ip}",
                    headers={
                        'Host': subdomain,
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                    },
                    timeout=10,
                    allow_redirects=False
                )
                
                # Check if the response is different from the baseline
                is_different = True
                for baseline in baseline_responses:
                    # Check status code, content length, and server header
                    if (response.status_code == baseline['status_code'] and
                        abs(len(response.content) - baseline['content_length']) < 100 and
                        response.headers.get('Server') == baseline['headers'].get('Server')):
                        is_different = False
                        break
                
                if is_different:
                    return {
                        'hostname': subdomain,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'server': response.headers.get('Server', 'Unknown'),
                        'is_virtual': True
                    }
            except requests.RequestException:
                pass
            
            return None
        
        # Limit number of subdomains to check
        max_vhosts = 200
        if len(subdomains_to_check) > max_vhosts:
            self.logger.info(f"Limiting virtual host checks from {len(subdomains_to_check)} to {max_vhosts}")
            subdomains_to_check = subdomains_to_check[:max_vhosts]
        
        # Create progress bar
        with progress_bar(f"Checking virtual hosts on {target_ip}", unit="vhosts") as progress:
            progress.update(total=len(subdomains_to_check))
            
            # Use ThreadPoolExecutor for parallel checks
            discovered = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_subdomain = {executor.submit(check_vhost, subdomain): subdomain for subdomain in subdomains_to_check}
                
                completed = 0
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    completed += 1
                    progress.update(advance=1)
                    
                    result = future.result()
                    if result:
                        discovered.append(result)
        
        results['discovered'] = discovered
        results['total_discovered'] = len(results['discovered'])
        
        # Add baseline info
        results['baseline'] = {
            'random_subdomains': random_subdomains,
            'responses': baseline_responses
        }
        
        self.logger.info(f"Virtual host discovery found {results['total_discovered']} virtual hosts for {self.target}")
        
        return results
    
    def resolve_subdomains(self, subdomains: List[str]) -> Dict[str, Any]:
        """
        Resolve subdomains to IP addresses.
        
        Args:
            subdomains (list): List of subdomains to resolve
            
        Returns:
            dict: Subdomain resolution results
        """
        self.logger.info(f"Resolving {len(subdomains)} subdomains for {self.target}")
        
        results = {
            'resolved': [],
            'unresolved': [],
            'total_resolved': 0
        }
        
        # Function to resolve a subdomain
        def resolve_subdomain(subdomain):
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('dns')
                    
                # Try A record
                a_records = []
                try:
                    answers = self.resolver.resolve(subdomain, 'A')
                    for rdata in answers:
                        a_records.append(str(rdata.address))
                except dns.exception.DNSException:
                    pass
                
                # Try AAAA record
                aaaa_records = []
                try:
                    answers = self.resolver.resolve(subdomain, 'AAAA')
                    for rdata in answers:
                        aaaa_records.append(str(rdata.address))
                except dns.exception.DNSException:
                    pass
                
                # Try CNAME record
                cname_records = []
                try:
                    answers = self.resolver.resolve(subdomain, 'CNAME')
                    for rdata in answers:
                        cname_records.append(str(rdata.target))
                except dns.exception.DNSException:
                    pass
                
                if a_records or aaaa_records or cname_records:
                    return {
                        'subdomain': subdomain,
                        'a_records': a_records,
                        'aaaa_records': aaaa_records,
                        'cname_records': cname_records,
                        'resolved': True
                    }
                else:
                    return {
                        'subdomain': subdomain,
                        'resolved': False
                    }
            except Exception as e:
                return {
                    'subdomain': subdomain,
                    'resolved': False,
                    'error': str(e)
                }
        
        # Create progress bar
        with progress_bar(f"Resolving subdomains for {self.target}", unit="subdomains") as progress:
            progress.update(total=len(subdomains))
            
            # Use ThreadPoolExecutor for parallel resolution
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_subdomain = {executor.submit(resolve_subdomain, subdomain): subdomain for subdomain in subdomains}
                
                completed = 0
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    completed += 1
                    progress.update(advance=1)
                    
                    result = future.result()
                    if result:
                        if result['resolved']:
                            results['resolved'].append(result)
                        else:
                            results['unresolved'].append(result['subdomain'])
        
        results['total_resolved'] = len(results['resolved'])
        results['total_unresolved'] = len(results['unresolved'])
        
        self.logger.info(f"Resolved {results['total_resolved']} subdomains for {self.target}")
        
        return results
