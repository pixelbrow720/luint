"""
Proxy manager for handling HTTP/HTTPS proxies.
"""
import os
import random
from typing import Dict, List, Optional, Tuple, Union
import requests

from luint.utils.logger import get_logger

logger = get_logger()


class ProxyManager:
    """
    Manages HTTP/HTTPS proxies for requests.
    """
    
    def __init__(self, proxies: Optional[Union[str, List[str], Dict[str, str]]] = None):
        """
        Initialize the proxy manager.
        
        Args:
            proxies: Can be one of:
                - None: No proxy
                - str: A single proxy URL (e.g., "http://user:pass@host:port")
                - list: A list of proxy URLs to rotate through
                - dict: A dictionary mapping protocols to proxy URLs 
                  (e.g., {"http": "http://proxy1", "https": "https://proxy2"})
        """
        self.proxies = []
        self.current_index = 0
        
        if proxies is None:
            # Check if proxies are defined in environment variables
            http_proxy = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
            https_proxy = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
            
            if http_proxy or https_proxy:
                proxy_dict = {}
                if http_proxy:
                    proxy_dict['http'] = http_proxy
                if https_proxy:
                    proxy_dict['https'] = https_proxy
                self.proxies.append(proxy_dict)
        
        elif isinstance(proxies, str):
            # Single proxy string
            self.proxies.append({
                'http': proxies,
                'https': proxies
            })
        
        elif isinstance(proxies, list):
            # List of proxy strings
            for proxy in proxies:
                if isinstance(proxy, str):
                    self.proxies.append({
                        'http': proxy,
                        'https': proxy
                    })
                elif isinstance(proxy, dict):
                    self.proxies.append(proxy)
        
        elif isinstance(proxies, dict):
            # Proxy dictionary
            self.proxies.append(proxies)
    
    def get_proxy(self) -> Optional[Dict[str, str]]:
        """
        Get the current proxy configuration.
        
        Returns:
            dict or None: Proxy configuration for requests or None if no proxies are configured
        """
        if not self.proxies:
            return None
            
        if len(self.proxies) == 1:
            return self.proxies[0]
            
        # Rotate through proxies
        proxy = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        return proxy
    
    def get_random_proxy(self) -> Optional[Dict[str, str]]:
        """
        Get a random proxy configuration.
        
        Returns:
            dict or None: Random proxy configuration or None if no proxies are configured
        """
        if not self.proxies:
            return None
        return random.choice(self.proxies)
    
    def add_proxy(self, proxy: Union[str, Dict[str, str]]):
        """
        Add a proxy to the proxy list.
        
        Args:
            proxy (str or dict): Proxy URL or proxy configuration dictionary
        """
        if isinstance(proxy, str):
            self.proxies.append({
                'http': proxy,
                'https': proxy
            })
        elif isinstance(proxy, dict):
            self.proxies.append(proxy)
    
    def remove_proxy(self, proxy: Union[str, Dict[str, str]]) -> bool:
        """
        Remove a proxy from the proxy list.
        
        Args:
            proxy (str or dict): Proxy URL or proxy configuration dictionary to remove
            
        Returns:
            bool: True if proxy was removed, False otherwise
        """
        if isinstance(proxy, str):
            proxy_dict = {
                'http': proxy,
                'https': proxy
            }
            if proxy_dict in self.proxies:
                self.proxies.remove(proxy_dict)
                return True
        elif isinstance(proxy, dict):
            if proxy in self.proxies:
                self.proxies.remove(proxy)
                return True
        return False
    
    def clear_proxies(self):
        """Clear all proxies."""
        self.proxies = []
        self.current_index = 0
    
    def test_proxy(self, proxy: Optional[Union[str, Dict[str, str]]] = None, 
                  test_url: str = 'https://httpbin.org/ip', timeout: int = 10) -> Tuple[bool, str]:
        """
        Test if a proxy is working by making a request to a test URL.
        
        Args:
            proxy (str or dict, optional): Proxy to test. If None, tests the current proxy.
            test_url (str): URL to test proxy with
            timeout (int): Request timeout in seconds
            
        Returns:
            tuple: (success, message)
        """
        if not proxy:
            proxy = self.get_proxy()
            if not proxy:
                return False, "No proxy configured"
                
        if isinstance(proxy, str):
            proxy_dict = {
                'http': proxy,
                'https': proxy
            }
        else:
            proxy_dict = proxy
        
        try:
            response = requests.get(test_url, proxies=proxy_dict, timeout=timeout)
            response.raise_for_status()
            return True, f"Proxy test successful, IP: {response.json().get('origin', 'unknown')}"
        except requests.exceptions.RequestException as e:
            return False, f"Proxy test failed: {str(e)}"
    
    def test_all_proxies(self, test_url: str = 'https://httpbin.org/ip', 
                        timeout: int = 10) -> Dict[int, Tuple[bool, str]]:
        """
        Test all configured proxies.
        
        Args:
            test_url (str): URL to test proxy with
            timeout (int): Request timeout in seconds
            
        Returns:
            dict: Dictionary mapping proxy index to (success, message) tuples
        """
        results = {}
        for i, proxy in enumerate(self.proxies):
            results[i] = self.test_proxy(proxy, test_url, timeout)
        return results
    
    def has_proxy(self) -> bool:
        """
        Check if any proxies are configured.
        
        Returns:
            bool: True if proxies are configured, False otherwise
        """
        return len(self.proxies) > 0
    
    def get_proxy_count(self) -> int:
        """
        Get the number of configured proxies.
        
        Returns:
            int: Number of proxies
        """
        return len(self.proxies)
