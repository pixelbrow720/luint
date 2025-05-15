#!/usr/bin/env python
"""
Test script to verify that critical methods in DNS Info and Server Info modules exist.
"""
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

def test_dns_info_methods():
    """Test if critical methods exist in DNSInfoScanner class."""
    try:
        from luint.modules.dns_info import DNSInfoScanner
        
        # Initialize with a dummy target
        scanner = DNSInfoScanner("example.com")
        
        # Check critical methods
        critical_methods = [
            'check_dns_over_https',
            'check_dns_over_tls',
            'analyze_dns_security_posture'
        ]
        
        missing_methods = []
        for method in critical_methods:
            if not hasattr(scanner, method) or not callable(getattr(scanner, method)):
                missing_methods.append(method)
        
        if missing_methods:
            logger.error(f"DNS Info Scanner is missing critical methods: {', '.join(missing_methods)}")
            return False
        else:
            logger.info("DNS Info Scanner has all required methods")
            return True
            
    except Exception as e:
        logger.error(f"Error testing DNS Info Scanner: {str(e)}")
        return False

def test_server_info_methods():
    """Test if critical methods exist in ServerInfoScanner class."""
    try:
        from luint.modules.server_info import ServerInfoScanner
        
        # Initialize with a dummy target
        scanner = ServerInfoScanner("example.com")
        
        # Check critical methods
        critical_methods = [
            'analyze_infrastructure_security_posture',
            'perform_advanced_port_vulnerability_scan'
        ]
        
        missing_methods = []
        for method in critical_methods:
            if not hasattr(scanner, method) or not callable(getattr(scanner, method)):
                missing_methods.append(method)
        
        if missing_methods:
            logger.error(f"Server Info Scanner is missing critical methods: {', '.join(missing_methods)}")
            return False
        else:
            logger.info("Server Info Scanner has all required methods")
            return True
            
    except Exception as e:
        logger.error(f"Error testing Server Info Scanner: {str(e)}")
        return False

if __name__ == "__main__":
    print("Testing DNS Info Scanner...")
    dns_result = test_dns_info_methods()
    
    print("\nTesting Server Info Scanner...")
    server_result = test_server_info_methods()
    
    if dns_result and server_result:
        print("\n✅ All critical methods are present in both modules!")
    else:
        print("\n❌ Some critical methods are missing!")