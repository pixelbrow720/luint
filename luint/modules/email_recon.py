"""
Email Reconnaissance Module for LUINT.
Handles email harvesting from web pages, SPF/DKIM/DMARC record analysis,
and contact information gathering from WHOIS records.
"""
import re
import dns.resolver
import dns.exception
import requests
import concurrent.futures
from typing import Dict, List, Any, Optional, Set
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

from luint.utils.logger import get_logger, LoggerAdapter
from luint.utils.helpers import is_ip_address, is_domain, normalize_url, extract_emails
from luint.utils.output_manager import progress_bar
from luint.constants import REGEX_PATTERNS, DEFAULT_HEADERS

logger = get_logger()


class EmailReconScanner:
    """
    Email Reconnaissance Scanner for LUINT.
    Discovers email addresses and analyzes email security configurations.
    """
    
    def __init__(self, target: str, config: Dict = None, 
                 cache_manager=None, rate_limiter=None, api_key_manager=None):
        """
        Initialize the Email Reconnaissance Scanner.
        
        Args:
            target (str): Domain or IP to scan
            config (dict, optional): Module configuration
            cache_manager: Cache manager instance
            rate_limiter: Rate limiter instance
            api_key_manager: API key manager instance (not used in this module)
        """
        self.target = target
        self.config = config or {}
        self.module_config = self.config.get('modules', {}).get('email_recon', {})
        self.cache_manager = cache_manager
        self.rate_limiter = rate_limiter
        
        # Setup module-specific logger
        self.logger = LoggerAdapter(logger, module_name='email_recon', target=target)
        
        # Normalize target domain
        if is_domain(target):
            self.domain = self._clean_domain(target)
        else:
            # Target is an IP, we'll need a domain for some checks
            self.domain = self._get_domain_from_ip(target)
            
        self.target_url = normalize_url(target)
        
        # Configure DNS resolver
        self.setup_resolver()
        
        # Options
        self.extract_from_whois = self.module_config.get('extract_from_whois', True)
        self.extract_from_pages = self.module_config.get('extract_from_pages', True)
        
        # Timeout for HTTP requests
        self.timeout = self.config.get('general', {}).get('timeout', 30)
    
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
    
    def _clean_domain(self, domain: str) -> str:
        """
        Clean and normalize a domain name.
        
        Args:
            domain (str): Domain to clean
            
        Returns:
            str: Cleaned domain
        """
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            domain = parsed.netloc
            
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        # Remove any trailing slashes, paths, query strings, etc.
        domain = domain.split('/')[0]
        domain = domain.split('?')[0]
        domain = domain.split('#')[0]
        
        return domain
    
    def _get_domain_from_ip(self, ip: str) -> Optional[str]:
        """
        Try to get a domain name from an IP address using reverse DNS.
        
        Args:
            ip (str): IP address
            
        Returns:
            str or None: Domain name if found, None otherwise
        """
        if not is_ip_address(ip):
            return None
            
        # Check if we have DNS info results cached
        if self.cache_manager:
            dns_results = self.cache_manager.get(ip, namespace='dns_info')
            if dns_results and 'reverse_dns' in dns_results:
                hostnames = dns_results['reverse_dns'].get('hostnames', [])
                if hostnames:
                    # Get the first hostname
                    hostname = hostnames[0]
                    return self._clean_domain(hostname)
                    
        # If not cached, try a reverse DNS lookup
        try:
            import socket
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname:
                return self._clean_domain(hostname)
        except (socket.herror, socket.gaierror):
            pass
            
        return None
    
    def scan(self) -> Dict[str, Any]:
        """
        Run all email reconnaissance methods.
        
        Returns:
            dict: Consolidated email reconnaissance results
        """
        results = {
            'target': self.target,
            'domain': self.domain,
            'emails': [],
            'total_emails': 0
        }
        
        # Check if we have a valid domain
        if not self.domain:
            self.logger.warning(f"No valid domain found for {self.target}, some checks will be skipped")
            results['warning'] = "No valid domain found, some checks skipped"
        
        # Check cache first
        if self.cache_manager:
            cached_results = self.cache_manager.get(self.target, namespace='email_recon')
            if cached_results:
                self.logger.info(f"Using cached email reconnaissance results for {self.target}")
                return cached_results
        
        # Search for emails on web pages
        if self.extract_from_pages and self.domain:
            web_emails = self.find_emails_web()
            if web_emails:
                results['web_emails'] = web_emails
                results['emails'].extend(web_emails.get('discovered', []))
        
        # Extract emails from WHOIS
        if self.extract_from_whois and self.domain:
            whois_emails = self.extract_whois_emails()
            if whois_emails:
                results['whois_emails'] = whois_emails
                results['emails'].extend(whois_emails.get('discovered', []))
        
        # Analyze SPF records
        if self.domain:
            spf_results = self.analyze_spf()
            if spf_results:
                results['spf'] = spf_results
        
        # Analyze DKIM records
        if self.domain:
            dkim_results = self.analyze_dkim()
            if dkim_results:
                results['dkim'] = dkim_results
        
        # Analyze DMARC records
        if self.domain:
            dmarc_results = self.analyze_dmarc()
            if dmarc_results:
                results['dmarc'] = dmarc_results
        
        # Remove duplicate emails
        results['emails'] = sorted(list(set(results['emails'])))
        results['total_emails'] = len(results['emails'])
        
        # Cache results if cache manager is available
        if self.cache_manager and results:
            self.cache_manager.set(self.target, results, namespace='email_recon')
            
        return results
    
    def find_emails_web(self) -> Dict[str, Any]:
        """
        Find email addresses on web pages.
        
        Returns:
            dict: Web email discovery results
        """
        self.logger.info(f"Searching for email addresses on web pages for {self.target_url}")
        
        results = {
            'pages_checked': 0,
            'discovered': [],
            'total': 0,
            'sources': {}
        }
        
        # List of pages to check
        pages_to_check = [self.target_url]
        checked_pages = set()
        
        # Add common pages that might contain contact information
        base_url = f"{urlparse(self.target_url).scheme}://{urlparse(self.target_url).netloc}"
        
        common_pages = [
            '/contact',
            '/contact-us',
            '/about',
            '/about-us',
            '/team',
            '/staff',
            '/our-team',
            '/company',
            '/support',
            '/help',
            '/careers',
            '/privacy',
            '/terms',
            '/leadership'
        ]
        
        for page in common_pages:
            pages_to_check.append(urljoin(base_url, page))
        
        # Remove duplicates
        pages_to_check = list(set(pages_to_check))
        
        # Function to check a page for emails
        def check_page(url):
            emails_found = set()
            
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('http')
                    
                headers = DEFAULT_HEADERS.copy()
                
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False
                )
                
                if response.status_code != 200:
                    return url, list(emails_found)
                
                content_type = response.headers.get('Content-Type', '').lower()
                
                # Check HTML content
                if 'text/html' in content_type:
                    # First check the raw HTML for emails
                    emails = extract_emails(response.text)
                    for email in emails:
                        if self.domain in email.lower():
                            emails_found.add(email)
                    
                    # Then use BeautifulSoup to find obfuscated emails
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Check for emails in mailto links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        if href.startswith('mailto:'):
                            email = href[7:].split('?')[0].strip()
                            if email and '@' in email:
                                if self.domain in email.lower():
                                    emails_found.add(email)
                    
                    # Check for emails in scripts (often used for obfuscation)
                    for script in soup.find_all('script'):
                        script_text = script.string
                        if script_text:
                            # Look for patterns like "user" + "@" + "domain.com"
                            parts = re.findall(r'[\'"][^\'\"]+[\'"]\s*\+\s*[\'"]\@[\'"]\s*\+\s*[\'"][^\'\"]+[\'"]', script_text)
                            for part in parts:
                                try:
                                    # Try to handle simple JavaScript concatenation
                                    parts = re.findall(r'[\'"]([^\'\"]+)[\'"]', part)
                                    if len(parts) == 3 and parts[1] == '@':
                                        email = f"{parts[0]}@{parts[2]}"
                                        if self.domain in email.lower():
                                            emails_found.add(email)
                                except:
                                    pass
                            
                            # Look for other email patterns
                            emails = extract_emails(script_text)
                            for email in emails:
                                if self.domain in email.lower():
                                    emails_found.add(email)
                    
                    # Check for emails in specific elements (like contact forms)
                    contact_elements = soup.find_all(['div', 'p', 'span'], text=re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'))
                    for element in contact_elements:
                        emails = extract_emails(element.text)
                        for email in emails:
                            if self.domain in email.lower():
                                emails_found.add(email)
                    
                    # Find more pages to check
                    if len(checked_pages) < 20:  # Limit to 20 pages
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            
                            # Skip non-HTTP links
                            if not href.startswith(('http://', 'https://', '/')):
                                continue
                            
                            # Convert to absolute URL if needed
                            if href.startswith('/'):
                                href = urljoin(base_url, href)
                            
                            # Skip external links
                            if not href.startswith(base_url):
                                continue
                            
                            # Skip already checked pages
                            if href in checked_pages:
                                continue
                            
                            # Add page to checked_pages to avoid adding it again from other sources
                            checked_pages.add(href)
                            
                            # Add to pages to check
                            pages_to_check.append(href)
                
                # Add any other content types as needed
                
                return url, list(emails_found)
                
            except (requests.RequestException, UnicodeDecodeError) as e:
                self.logger.debug(f"Error checking {url} for emails: {str(e)}")
                return url, []
        
        discovered_emails = set()
        email_sources = {}
        
        # Create progress bar
        with progress_bar(f"Searching for emails on {self.target_url}", unit="pages") as progress:
            progress.update(total=len(pages_to_check))
            
            # Use ThreadPoolExecutor for parallel page checks
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                # Check initial pages
                futures_to_pages = {executor.submit(check_page, page): page for page in pages_to_check}
                
                for i, future in enumerate(concurrent.futures.as_completed(futures_to_pages)):
                    url, emails = future.result()
                    
                    # Record results
                    if emails:
                        for email in emails:
                            discovered_emails.add(email)
                            
                            # Track which page the email was found on
                            if email not in email_sources:
                                email_sources[email] = []
                            if url not in email_sources[email]:
                                email_sources[email].append(url)
                    
                    # Mark page as checked
                    checked_pages.add(url)
                    results['pages_checked'] += 1
                    
                    # Update the progress bar
                    progress.update(advance=1)
                    
                    # If the list of pages to check has grown, update the progress bar
                    if i == len(pages_to_check) - 1 and len(pages_to_check) < len(checked_pages) + 10:
                        # Add some more pages to check from the list that grew
                        new_pages = [p for p in pages_to_check if p not in checked_pages][:10]
                        
                        if new_pages:
                            new_futures = {executor.submit(check_page, page): page for page in new_pages}
                            futures_to_pages.update(new_futures)
                            progress.update(total=len(futures_to_pages))
        
        # Prepare results
        results['discovered'] = sorted(list(discovered_emails))
        results['total'] = len(results['discovered'])
        
        for email in results['discovered']:
            if email in email_sources:
                results['sources'][email] = email_sources[email]
        
        self.logger.info(f"Found {results['total']} email addresses on {results['pages_checked']} web pages")
        
        return results
    
    def extract_whois_emails(self) -> Dict[str, Any]:
        """
        Extract email addresses from WHOIS records.
        
        Returns:
            dict: WHOIS email extraction results
        """
        self.logger.info(f"Extracting email addresses from WHOIS records for {self.domain}")
        
        results = {
            'discovered': [],
            'total': 0,
            'sources': {}
        }
        
        # Check if we have WHOIS data from DNS module
        whois_data = None
        if self.cache_manager:
            dns_results = self.cache_manager.get(self.target, namespace='dns_info')
            if dns_results and 'whois' in dns_results:
                whois_data = dns_results['whois']
        
        if not whois_data:
            self.logger.warning("No WHOIS data available")
            return results
        
        # Extract emails from raw WHOIS data if available
        if 'raw' in whois_data:
            raw_whois = whois_data['raw']
            emails = extract_emails(raw_whois)
            
            for email in emails:
                if email not in results['discovered']:
                    results['discovered'].append(email)
                    results['sources'][email] = ['WHOIS Raw Data']
        
        # Extract from contact information if available
        if 'contacts' in whois_data:
            contacts = whois_data['contacts']
            
            for contact_type, contact_info in contacts.items():
                if 'email' in contact_info:
                    email = contact_info['email']
                    if email and '@' in email and email not in results['discovered']:
                        results['discovered'].append(email)
                        results['sources'][email] = [f"WHOIS {contact_type.title()} Contact"]
        
        # Extract emails from registrar and registrant fields
        for field in ['registrar', 'registrant']:
            if field in whois_data and whois_data[field]:
                field_data = whois_data[field]
                
                # Handle both string and list types
                if isinstance(field_data, str):
                    emails = extract_emails(field_data)
                    for email in emails:
                        if email not in results['discovered']:
                            results['discovered'].append(email)
                            results['sources'][email] = [f"WHOIS {field.title()}"]
                            
                elif isinstance(field_data, list):
                    for item in field_data:
                        emails = extract_emails(str(item))
                        for email in emails:
                            if email not in results['discovered']:
                                results['discovered'].append(email)
                                results['sources'][email] = [f"WHOIS {field.title()}"]
        
        results['total'] = len(results['discovered'])
        self.logger.info(f"Found {results['total']} email addresses in WHOIS records")
        
        return results
    
    def analyze_spf(self) -> Dict[str, Any]:
        """
        Analyze SPF records.
        
        Returns:
            dict: SPF analysis results
        """
        self.logger.info(f"Analyzing SPF records for {self.domain}")
        
        results = {
            'domain': self.domain,
            'has_spf': False,
            'record': None,
            'mechanisms': [],
            'all_mechanism': None,
            'includes': [],
            'ip4': [],
            'ip6': [],
            'errors': []
        }
        
        try:
            if self.rate_limiter:
                self.rate_limiter.wait('dns')
                
            # Query for SPF record in TXT records
            answers = self.resolver.resolve(self.domain, 'TXT')
            
            # Find SPF record in TXT records
            spf_record = None
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                if txt_record.startswith('v=spf1'):
                    spf_record = txt_record
                    break
            
            if not spf_record:
                self.logger.info(f"No SPF record found for {self.domain}")
                return results
            
            # Record found, parse it
            results['has_spf'] = True
            results['record'] = spf_record
            
            # Parse mechanisms
            parts = spf_record.split()
            
            for part in parts[1:]:  # Skip v=spf1
                # Extract qualifier
                qualifier = '+'  # Default qualifier is '+'
                if part[0] in ['+', '-', '~', '?']:
                    qualifier = part[0]
                    part = part[1:]
                
                # Add to mechanisms list
                results['mechanisms'].append({
                    'qualifier': qualifier,
                    'mechanism': part
                })
                
                # Check for specific mechanisms
                if part == 'all' or part.startswith('all:'):
                    results['all_mechanism'] = qualifier + 'all'
                elif part.startswith('include:'):
                    domain = part[8:]
                    results['includes'].append(domain)
                elif part.startswith('ip4:'):
                    ip4 = part[4:]
                    results['ip4'].append(ip4)
                elif part.startswith('ip6:'):
                    ip6 = part[4:]
                    results['ip6'].append(ip6)
            
            # Check for issues
            if not results['all_mechanism']:
                results['errors'].append("No 'all' mechanism specified")
                
            if results['all_mechanism'] == '+all':
                results['errors'].append("SPF record uses '+all' which allows all senders (very permissive)")
            
            # Analyze record characteristics
            results['analysis'] = {
                'allows_all': results['all_mechanism'] == '+all',
                'neutral': results['all_mechanism'] == '?all',
                'softfail': results['all_mechanism'] == '~all',
                'hardfail': results['all_mechanism'] == '-all',
                'external_includes': len(results['includes']) > 0,
                'uses_ip_addresses': len(results['ip4']) > 0 or len(results['ip6']) > 0
            }
            
            self.logger.info(f"Successfully analyzed SPF record for {self.domain}")
            
        except dns.resolver.NoAnswer:
            self.logger.info(f"No TXT records found for {self.domain}")
        except dns.resolver.NXDOMAIN:
            self.logger.warning(f"Domain {self.domain} does not exist")
        except dns.exception.DNSException as e:
            self.logger.error(f"DNS error analyzing SPF records: {str(e)}")
            results['errors'].append(f"DNS error: {str(e)}")
        
        return results
    
    def analyze_dkim(self) -> Dict[str, Any]:
        """
        Analyze DKIM records.
        
        Returns:
            dict: DKIM analysis results
        """
        self.logger.info(f"Analyzing DKIM records for {self.domain}")
        
        results = {
            'domain': self.domain,
            'has_dkim': False,
            'selectors_found': [],
            'records': {}
        }
        
        # Common DKIM selectors to check
        selectors = [
            'default', 'dkim', 'k1', 'key1', 'selector1', 'selector2',
            'mail', 'email', 'sig1', 'google'
        ]
        
        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{self.domain}"
            
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait('dns')
                    
                # Query for DKIM record in TXT records
                answers = self.resolver.resolve(dkim_domain, 'TXT')
                
                for rdata in answers:
                    dkim_record = rdata.to_text().strip('"')
                    
                    # Check if it's a valid DKIM record
                    if 'v=dkim1' in dkim_record or 'k=rsa' in dkim_record:
                        results['has_dkim'] = True
                        
                        if selector not in results['selectors_found']:
                            results['selectors_found'].append(selector)
                        
                        # Parse the record
                        record_parts = {}
                        parts = dkim_record.replace('"', '').replace(' ', '').split(';')
                        
                        for part in parts:
                            if not part:
                                continue
                                
                            if '=' in part:
                                key, value = part.split('=', 1)
                                record_parts[key] = value
                        
                        results['records'][selector] = {
                            'full_record': dkim_record,
                            'parsed': record_parts
                        }
                
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass
            except dns.exception.DNSException:
                pass
                
        # Order selectors and add summary
        results['selectors_found'] = sorted(results['selectors_found'])
        results['total_selectors'] = len(results['selectors_found'])
        
        self.logger.info(f"Found {results['total_selectors']} DKIM selectors for {self.domain}")
        
        return results
    
    def analyze_dmarc(self) -> Dict[str, Any]:
        """
        Analyze DMARC records.
        
        Returns:
            dict: DMARC analysis results
        """
        self.logger.info(f"Analyzing DMARC records for {self.domain}")
        
        results = {
            'domain': self.domain,
            'has_dmarc': False,
            'record': None,
            'parsed': {},
            'errors': []
        }
        
        try:
            if self.rate_limiter:
                self.rate_limiter.wait('dns')
                
            # Query for DMARC record in TXT records
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            
            # Find DMARC record in TXT records
            dmarc_record = None
            for rdata in answers:
                txt_record = rdata.to_text().strip('"')
                if txt_record.startswith('v=DMARC1'):
                    dmarc_record = txt_record
                    break
            
            if not dmarc_record:
                self.logger.info(f"No DMARC record found for {self.domain}")
                return results
            
            # Record found, parse it
            results['has_dmarc'] = True
            results['record'] = dmarc_record
            
            # Parse tag-value pairs
            parts = dmarc_record.replace('"', '').split(';')
            
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                    
                if '=' in part:
                    tag, value = part.split('=', 1)
                    tag = tag.strip()
                    value = value.strip()
                    results['parsed'][tag] = value
            
            # Check for required tags
            if 'p' not in results['parsed']:
                results['errors'].append("Missing required policy tag (p)")
            
            # Check policy and add analysis
            policy = results['parsed'].get('p', 'none')
            results['analysis'] = {
                'policy': policy,
                'subdomain_policy': results['parsed'].get('sp', policy),  # Default to p if sp not specified
                'percentage': results['parsed'].get('pct', '100'),
                'reporting': 'rua' in results['parsed'] or 'ruf' in results['parsed'],
                'strict_policy': policy == 'reject',
                'quarantine_policy': policy == 'quarantine',
                'none_policy': policy == 'none'
            }
            
            # Check for issues
            if policy == 'none':
                results['errors'].append("DMARC policy is 'none', which only monitors and doesn't enforce")
            
            if 'rua' not in results['parsed'] and 'ruf' not in results['parsed']:
                results['errors'].append("No reporting URIs specified (rua or ruf)")
            
            self.logger.info(f"Successfully analyzed DMARC record for {self.domain}")
            
        except dns.resolver.NoAnswer:
            self.logger.info(f"No DMARC TXT record found for {self.domain}")
        except dns.resolver.NXDOMAIN:
            self.logger.info(f"DMARC record does not exist for {self.domain}")
        except dns.exception.DNSException as e:
            self.logger.error(f"DNS error analyzing DMARC records: {str(e)}")
            results['errors'].append(f"DNS error: {str(e)}")
        
        return results
