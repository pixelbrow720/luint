"""
Rate limiter for API requests to prevent hitting rate limits.
"""
import time
import threading
from collections import defaultdict
from typing import Dict, Optional

from luint.utils.logger import get_logger

logger = get_logger()

class RateLimiter:
    """
    A rate limiter to control request frequency to external services.
    Uses a token bucket algorithm implementation.
    """
    
    def __init__(self, requests_per_minute: Dict[str, int] = None):
        """
        Initialize the rate limiter.
        
        Args:
            requests_per_minute (dict): Dictionary mapping service names to requests per minute limits
        """
        self.requests_per_minute = requests_per_minute or {'default': 60}
        self.lock = threading.Lock()
        self.tokens = defaultdict(lambda: 0)
        self.last_refill = defaultdict(lambda: time.time())
        
        # Initialize tokens for each service
        for service in self.requests_per_minute:
            self.tokens[service] = self.requests_per_minute[service]
    
    def _refill_tokens(self, service: str):
        """
        Refill tokens based on time elapsed since last refill.
        
        Args:
            service (str): Service name
        """
        now = time.time()
        seconds_since_refill = now - self.last_refill[service]
        
        # Calculate number of tokens to add (tokens per second * elapsed seconds)
        rpm = self.requests_per_minute.get(service, self.requests_per_minute.get('default', 60))
        new_tokens = (rpm / 60.0) * seconds_since_refill
        
        # Add tokens, but don't exceed maximum
        self.tokens[service] = min(self.tokens[service] + new_tokens, rpm)
        self.last_refill[service] = now
    
    def consume(self, service: str = 'default', tokens: float = 1.0) -> bool:
        """
        Consume tokens for a service. If enough tokens are available, returns True.
        If not, returns False.
        
        Args:
            service (str): Service name
            tokens (float): Number of tokens to consume (defaults to 1.0)
            
        Returns:
            bool: True if tokens were consumed, False if not enough tokens
        """
        with self.lock:
            self._refill_tokens(service)
            
            if self.tokens[service] >= tokens:
                self.tokens[service] -= tokens
                return True
            return False
    
    def wait_for_token(self, service: str = 'default', tokens: float = 1.0, max_wait: Optional[float] = None):
        """
        Wait until tokens are available for a service.
        
        Args:
            service (str): Service name
            tokens (float): Number of tokens to wait for (defaults to 1.0)
            max_wait (float, optional): Maximum time to wait in seconds
            
        Returns:
            bool: True if tokens were consumed, False if max_wait was reached
        """
        start_time = time.time()
        
        while True:
            with self.lock:
                self._refill_tokens(service)
                
                if self.tokens[service] >= tokens:
                    self.tokens[service] -= tokens
                    return True
            
            # Check if we've waited too long
            if max_wait is not None and time.time() - start_time > max_wait:
                logger.warning(f"Rate limit wait timeout for service '{service}' after {max_wait} seconds")
                return False
            
            # Calculate wait time until next token is available
            rpm = self.requests_per_minute.get(service, self.requests_per_minute.get('default', 60))
            wait_time = min(1.0, (tokens - self.tokens[service]) / (rpm / 60.0))
            
            # Sleep for a short time
            time.sleep(min(0.2, wait_time))
    
    def update_limits(self, requests_per_minute: Dict[str, int]):
        """
        Update rate limits for services.
        
        Args:
            requests_per_minute (dict): Dictionary mapping service names to requests per minute limits
        """
        with self.lock:
            for service, rpm in requests_per_minute.items():
                # If lowering the limit, also lower the current tokens
                if service in self.requests_per_minute and rpm < self.requests_per_minute[service]:
                    ratio = rpm / self.requests_per_minute[service]
                    self.tokens[service] = min(self.tokens[service] * ratio, rpm)
                
                self.requests_per_minute[service] = rpm
    
    def get_available_tokens(self, service: str = 'default') -> float:
        """
        Get the number of available tokens for a service.
        
        Args:
            service (str): Service name
            
        Returns:
            float: Number of available tokens
        """
        with self.lock:
            self._refill_tokens(service)
            return self.tokens[service]


class ApiRateLimiter:
    """
    A wrapper around RateLimiter for API services with specific limits.
    """
    
    def __init__(self, config=None):
        """
        Initialize the API rate limiter.
        
        Args:
            config (dict, optional): Configuration dictionary containing rate limiting settings
        """
        rate_limits = {}
        
        if config and 'rate_limiting' in config and config['rate_limiting'].get('enabled', True):
            rate_limits = config['rate_limiting'].get('requests_per_minute', {})
        
        # Default limits for common APIs
        default_limits = {
            'default': 60,         # Default for unspecified services
            'shodan': 60,          # Shodan API rate limit
            'virustotal': 4,       # VirusTotal free API (4 req/min)
            'urlscan': 30,         # URLScan.io API
            'abuseipdb': 30,       # AbuseIPDB API
            'ipinfo': 50,          # IPInfo API
            'dns': 100,            # DNS lookups
            'whois': 10,           # WHOIS lookups
            'http': 60             # General HTTP requests
        }
        
        # Merge default limits with configured limits
        for service, limit in default_limits.items():
            if service not in rate_limits:
                rate_limits[service] = limit
        
        self.rate_limiter = RateLimiter(rate_limits)
    
    def wait(self, service: str = 'default', max_wait: Optional[float] = None) -> bool:
        """
        Wait for a token to become available for a service.
        
        Args:
            service (str): Service name
            max_wait (float, optional): Maximum time to wait in seconds
            
        Returns:
            bool: True if token was consumed, False if max_wait was reached
        """
        return self.rate_limiter.wait_for_token(service, 1.0, max_wait)
    
    def update_limits(self, limits: Dict[str, int]):
        """
        Update rate limits for services.
        
        Args:
            limits (dict): Dictionary mapping service names to requests per minute limits
        """
        self.rate_limiter.update_limits(limits)
