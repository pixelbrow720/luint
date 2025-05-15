#!/usr/bin/env python
"""
Test script to verify that DNS Info and Server Info modules work properly.
"""
import time
import logging
import concurrent.futures
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(name)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

try:
    # Import the scanner classes
    from luint.modules.dns_info import DNSInfoScanner
    from luint.modules.server_info import ServerInfoScanner
    
    print("✓ Successfully imported the modules")
    
    # Test domain - use a common domain that's always available
    test_domain = "example.com"
    
    # Initialize the scanners
    dns_scanner = DNSInfoScanner(test_domain)
    server_scanner = ServerInfoScanner(test_domain)
    
    print(f"✓ Successfully initialized scanners for {test_domain}")
    
    # Verify all referenced methods exist in DNS scanner
    dns_methods = [
        'check_dns_over_https',
        'check_dns_over_tls',
        'analyze_dns_security_posture'
    ]
    
    for method in dns_methods:
        if hasattr(dns_scanner, method) and callable(getattr(dns_scanner, method)):
            print(f"✓ DNS Scanner: Method '{method}' exists and is callable")
        else:
            print(f"✗ DNS Scanner: Method '{method}' is missing or not callable")
    
    # Verify all referenced methods exist in Server scanner
    server_methods = [
        'analyze_infrastructure_security_posture',
        'perform_advanced_port_vulnerability_scan'
    ]
    
    for method in server_methods:
        if hasattr(server_scanner, method) and callable(getattr(server_scanner, method)):
            print(f"✓ Server Scanner: Method '{method}' exists and is callable")
        else:
            print(f"✗ Server Scanner: Method '{method}' is missing or not callable")
    
    # Perform a minimal, quick test of the scan methods
    # This is just to verify they run without errors, not to get complete results
    print("\nRunning quick test of the scan() methods...")
    
    def run_dns_scan():
        try:
            dns_scanner.scan()
            return "✓ DNS Scanner scan() completed successfully"
        except Exception as e:
            return f"✗ DNS Scanner scan() failed: {str(e)}"
    
    def run_server_scan():
        try:
            server_scanner.scan()
            return "✓ Server Scanner scan() completed successfully"
        except Exception as e:
            return f"✗ Server Scanner scan() failed: {str(e)}"
    
    # Run both scans in parallel for efficiency
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        dns_future = executor.submit(run_dns_scan)
        server_future = executor.submit(run_server_scan)
        
        print(dns_future.result())
        print(server_future.result())
    
    print("\nModule verification completed!")

except ImportError as e:
    print(f"Failed to import modules: {str(e)}")
except Exception as e:
    print(f"Unexpected error: {str(e)}")