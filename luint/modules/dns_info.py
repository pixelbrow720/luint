"""Implements a more robust DNSSEC checking method in the DNSInfoScanner class."""
import dns.resolver
import dns.message
import dns.rcode
import dns.rdatatype
import socket
import ssl
import time
import requests

class DNSInfoScanner:
    """
    DNS Information Scanner for LUINT.
    Gathers information about DNS configuration, records, and security posture.
    Includes advanced DNS security analysis capabilities.
    """

    def __init__(self, target):
        self.target = target

    def get_a_record(self):
        pass

    def check_dnssec(self):
        """
        Check DNSSEC configuration and validation.
        Returns dict with DNSSEC status and details.
        """
        results = {
            'enabled': False,
            'validated': False,
            'issues': [],
            'records': {}
        }

        try:
            # Create new resolver instance for DNSSEC checks
            resolver = dns.resolver.Resolver()
            resolver.use_edns(edns=0, ednsflags=dns.flags.DO)

            # Try to get DNSKEY records
            try:
                dnskey = resolver.resolve(self.target, 'DNSKEY')
                results['records']['dnskey'] = len(dnskey.response.answer)
                results['enabled'] = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                results['issues'].append("No DNSKEY records found")
                return results

            # Try to get DS records from parent zone
            try:
                parent = '.'.join(self.target.split('.')[1:])
                ds = resolver.resolve(self.target, 'DS')
                results['records']['ds'] = len(ds.response.answer)
                results['validated'] = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                results['issues'].append("No DS records found in parent zone")

            # Check for NSEC/NSEC3 records
            try:
                # Query for a definitely non-existent subdomain
                resolver.resolve(f"nonexistent.{self.target}", 'A')
            except dns.resolver.NXDOMAIN as e:
                if 'NSEC' in str(e.response):
                    results['records']['nsec'] = 'NSEC'
                elif 'NSEC3' in str(e.response):
                    results['records']['nsec'] = 'NSEC3'

        except Exception as e:
            results['issues'].append(f"Error checking DNSSEC: {str(e)}")

        return results

    def get_ns_record(self):
        pass
`