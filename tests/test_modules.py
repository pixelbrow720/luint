
#!/usr/bin/env python
"""Test suite for DNS Info and Server Info modules with proper mocking and assertions."""
import pytest
from unittest.mock import patch, Mock
import dns.resolver
import nmap

from luint.modules.dns_info import DNSInfoScanner
from luint.modules.server_info import ServerInfoScanner

@pytest.fixture
def dns_scanner():
    return DNSInfoScanner("example.com")

@pytest.fixture
def server_scanner():
    return ServerInfoScanner("example.com")

@pytest.fixture
def mock_dns_response():
    mock_answer = Mock()
    mock_answer.response.answer = [Mock()]
    mock_answer.response.answer[0].items = ["93.184.216.34"]
    return mock_answer

def test_dns_scanner_methods_exist(dns_scanner):
    """Verify critical DNS scanner methods exist and are callable."""
    critical_methods = [
        'check_dns_over_https',
        'check_dns_over_tls',
        'analyze_dns_security_posture'
    ]
    
    for method in critical_methods:
        assert hasattr(dns_scanner, method), f"Missing method: {method}"
        assert callable(getattr(dns_scanner, method)), f"Method not callable: {method}"

def test_server_scanner_methods_exist(server_scanner):
    """Verify critical server scanner methods exist and are callable."""
    critical_methods = [
        'analyze_infrastructure_security_posture',
        'perform_advanced_port_vulnerability_scan'
    ]
    
    for method in critical_methods:
        assert hasattr(server_scanner, method), f"Missing method: {method}"
        assert callable(getattr(server_scanner, method)), f"Method not callable: {method}"

@patch('dns.resolver.resolve')
def test_dns_scanner_basic_lookup(mock_resolve, dns_scanner, mock_dns_response):
    """Test basic DNS lookup functionality."""
    mock_resolve.return_value = mock_dns_response.response.answer[0]
    
    result = dns_scanner.scan()
    assert result is not None
    assert 'a_records' in result
    assert '93.184.216.34' in result['a_records']

@patch('nmap.PortScanner')
def test_server_scanner_port_scan(mock_port_scanner, server_scanner):
    """Test basic port scanning functionality."""
    mock_scanner = Mock()
    mock_scanner.scan.return_value = {
        'scan': {
            'example.com': {
                'tcp': {
                    80: {'state': 'open', 'name': 'http'},
                    443: {'state': 'open', 'name': 'https'}
                }
            }
        }
    }
    mock_port_scanner.return_value = mock_scanner
    
    result = server_scanner.scan()
    assert result is not None
    assert 'open_ports' in result
    assert 80 in result['open_ports']
    assert 443 in result['open_ports']

@patch('requests.get')
def test_server_scanner_http_headers(mock_get, server_scanner):
    """Test HTTP header analysis."""
    mock_response = Mock()
    mock_response.headers = {
        'Server': 'nginx/1.16.1',
        'X-Frame-Options': 'DENY'
    }
    mock_get.return_value = mock_response
    
    result = server_scanner.analyze_http_headers("https://example.com")
    assert result is not None
    assert 'Server' in result
    assert result['Server'] == 'nginx/1.16.1'

if __name__ == "__main__":
    pytest.main([__file__])
