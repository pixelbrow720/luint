"""
API Key Manager for handling API keys for various services.
"""
import os
from typing import Dict, Optional, List, Any
import re

from luint.utils.logger import get_logger

logger = get_logger()


class APIKeyManager:
    """
    Manages API keys for external services used by LUINT.
    Handles retrieval, validation, and masking of API keys.
    """
    
    def __init__(self, api_keys_config: Optional[Dict[str, str]] = None):
        """
        Initialize the API Key Manager.
        
        Args:
            api_keys_config (dict, optional): Dictionary of API keys from configuration
        """
        self.api_keys = {}
        
        # List of supported services
        self.supported_services = [
            'shodan',
            'virustotal',
            'urlscan',
            'abuseipdb',
            'ipinfo'
        ]
        
        # Initialize from provided config
        if api_keys_config:
            for service, key in api_keys_config.items():
                self.set_key(service, key)
            
        # Override with environment variables if they exist
        self._load_from_environment()
    
    def _load_from_environment(self):
        """
        Load API keys from environment variables.
        
        Environment variables should be in the format:
        LUINT_API_KEY_SERVICENAME (e.g., LUINT_API_KEY_SHODAN)
        """
        # Standard environment variable pattern
        pattern = r'^LUINT_API_KEY_([A-Z]+)$'
        
        for env_var, value in os.environ.items():
            match = re.match(pattern, env_var)
            if match and value:
                service = match.group(1).lower()
                self.set_key(service, value)
                logger.debug(f"Loaded API key for {service} from environment variable")
                
        # Also check for specific service environment variables
        service_env_vars = {
            'shodan': ['SHODAN_API_KEY'],
            'virustotal': ['VIRUSTOTAL_API_KEY', 'VT_API_KEY'],
            'urlscan': ['URLSCAN_API_KEY'],
            'abuseipdb': ['ABUSEIPDB_API_KEY'],
            'ipinfo': ['IPINFO_API_KEY']
        }
        
        for service, env_vars in service_env_vars.items():
            for env_var in env_vars:
                value = os.environ.get(env_var)
                if value:
                    self.set_key(service, value)
                    logger.debug(f"Loaded API key for {service} from {env_var}")
    
    def get_key(self, service: str) -> Optional[str]:
        """
        Get an API key for a service.
        
        Args:
            service (str): Service name
            
        Returns:
            str or None: API key for the service or None if not found
        """
        return self.api_keys.get(service.lower())
    
    def set_key(self, service: str, key: str):
        """
        Set an API key for a service.
        
        Args:
            service (str): Service name
            key (str): API key
        """
        if key:  # Only set if key is not empty
            self.api_keys[service.lower()] = key
    
    def delete_key(self, service: str) -> bool:
        """
        Delete an API key for a service.
        
        Args:
            service (str): Service name
            
        Returns:
            bool: True if the key was deleted, False if it wasn't found
        """
        service = service.lower()
        if service in self.api_keys:
            del self.api_keys[service]
            return True
        return False
    
    def has_key(self, service: str) -> bool:
        """
        Check if an API key exists for a service.
        
        Args:
            service (str): Service name
            
        Returns:
            bool: True if the key exists, False otherwise
        """
        return service.lower() in self.api_keys and bool(self.api_keys[service.lower()])
    
    def list_keys(self) -> Dict[str, str]:
        """
        Get a dictionary of all API keys.
        
        Returns:
            dict: Dictionary of service names and their API keys
        """
        return self.api_keys.copy()
    
    def list_supported_services(self) -> List[str]:
        """
        Get a list of supported services.
        
        Returns:
            list: List of supported service names
        """
        return self.supported_services.copy()
    
    def mask_key(self, key: str) -> str:
        """
        Mask an API key for display purposes.
        
        Args:
            key (str): API key to mask
            
        Returns:
            str: Masked API key
        """
        if not key:
            return ""
            
        if len(key) <= 8:
            return "*" * len(key)
            
        return key[:4] + "*" * (len(key) - 8) + key[-4:]
    
    def get_missing_keys(self) -> List[str]:
        """
        Get a list of supported services that don't have API keys.
        
        Returns:
            list: List of service names without API keys
        """
        return [service for service in self.supported_services 
                if not self.has_key(service)]
