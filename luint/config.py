"""
Configuration management for LUINT.
"""
import os
import yaml
from luint.utils.logger import get_logger

logger = get_logger()

DEFAULT_CONFIG = {
    "general": {
        "user_agent": "LUINT-Scanner/1.0",
        "timeout": 30,
        "max_retries": 3,
        "concurrent_requests": 5,
        "cache_duration": 3600  # 1 hour in seconds
    },
    "api_keys": {
        "shodan": "",
        "virustotal": "",
        "urlscan": "",
        "abuseipdb": "",
        "ipinfo": ""
    },
    "modules": {
        "dns_info": {
            "enabled": True,
            "dns_servers": ["8.8.8.8", "1.1.1.1"],
            "timeout": 5
        },
        "server_info": {
            "enabled": True,
            "port_scan_timeout": 5,
            "common_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
        },
        "subdomain_enum": {
            "enabled": True,
            "wordlist_path": "",
            "max_subdomains": 500
        },
        "content_discovery": {
            "enabled": True,
            "max_depth": 2,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        },
        "email_recon": {
            "enabled": True,
            "extract_from_whois": True,
            "extract_from_pages": True
        },
        "security_checks": {
            "enabled": True,
            "check_headers": True,
            "check_ssl": True,
            "check_blacklists": True
        },
        "social_media": {
            "enabled": True,
            "platforms": [
                "facebook", "twitter", "linkedin", "instagram", 
                "github", "youtube", "reddit"
            ]
        }
    },
    "output": {
        "default_format": "json",
        "pretty_print": True,
        "colors_enabled": True
    },
    "proxy": {
        "enabled": False,
        "address": "",
        "auth": {
            "username": "",
            "password": ""
        }
    },
    "rate_limiting": {
        "enabled": True,
        "requests_per_minute": {
            "default": 60,
            "shodan": 60,
            "virustotal": 4,
            "urlscan": 30,
            "abuseipdb": 30,
            "ipinfo": 50
        }
    }
}


def load_config(config_path=None):
    """
    Load configuration from a YAML file or use default config.
    
    Args:
        config_path (str, optional): Path to the configuration file. 
            If not provided, uses default configuration.
            
    Returns:
        dict: Configuration data
    """
    config = DEFAULT_CONFIG.copy()
    
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as file:
                user_config = yaml.safe_load(file)
                
            if user_config:
                # Deeply merge user config with default config
                merge_configs(config, user_config)
                logger.info(f"Configuration loaded from {config_path}")
            else:
                logger.warning(f"Config file {config_path} is empty or invalid. Using default configuration.")
        except Exception as e:
            logger.error(f"Error loading config from {config_path}: {str(e)}")
            logger.info("Using default configuration")
    else:
        if config_path:
            logger.warning(f"Config file {config_path} not found. Using default configuration.")
        else:
            logger.info("No configuration file specified. Using default configuration.")
    
    return config


def merge_configs(base_config, user_config):
    """
    Recursively merge user configuration into base configuration.
    
    Args:
        base_config (dict): Base configuration to update
        user_config (dict): User configuration to merge in
    """
    for key, value in user_config.items():
        if key in base_config and isinstance(base_config[key], dict) and isinstance(value, dict):
            merge_configs(base_config[key], value)
        else:
            base_config[key] = value


def save_config(config, config_path):
    """
    Save configuration to a YAML file.
    
    Args:
        config (dict): Configuration data to save
        config_path (str): Path to save the configuration file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        directory = os.path.dirname(config_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            
        with open(config_path, 'w') as file:
            yaml.dump(config, file, default_flow_style=False)
        
        logger.info(f"Configuration saved to {config_path}")
        return True
    except Exception as e:
        logger.error(f"Error saving config to {config_path}: {str(e)}")
        return False
