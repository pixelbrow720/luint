"""
Configuration management for LUINT.
"""
import os
import yaml
from luint.utils.logger import get_logger

logger = get_logger()

# Default configuration values for LUINT
DEFAULT_CONFIG = {
    "general": {
        "threads": 10,
        "timeout": 30,
        "retry_count": 3,
        "cache_duration": 3600,
        "user_agent": "LUINT-Scanner/1.0",
        "verify_ssl": True,
        "output_dir": "results",
        "verbosity": 1
    },
    "modules": {
        "dns_info": {
            "nameservers": ["8.8.8.8", "1.1.1.1"],
            "timeout": 5,
            "check_dnssec": True,
            "check_doh_dot": True,
            "attempt_zone_transfer": False,
            "check_wildcard": True,
            "whois_retries": 3,
            "check_email_records": True,
            "security_assessment": True
        },
        "server_info": {
            "ports": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
            "scan_timeout": 5,
            "detect_waf": True,
            "ssl_check": True,
            "detect_tech": True,
            "banner_grabbing": True,
            "perform_advanced_port_scan": False,
            "security_assessment": True,
            "http_methods": ["GET", "HEAD", "OPTIONS"],
            "check_cloud_metadata": False
        },
        "subdomain_enum": {
            "wordlist": "wordlists/subdomains.txt",  # Can be comma-separated list
            "max_subdomains": 1000,
            "timeout": 5,
            "use_bruteforce": True,
            "use_cert_transparency": True,
            "use_vhost_discovery": True,
            "use_permutations": True,
            "permutation_patterns": ["prefix", "suffix", "hyphen"],
            "threads": {
                "brute_force": 30,
                "permutation": 20,
                "passive": 10
            },
            "permutation_depth": 3,  # Max depth for permutation combinations
            "max_permutations_per_level": 100,  # Max permutations to try per depth level
            "check_similar_domains": False,
            "passive_sources": {
                "virustotal": True,
                "urlscan": True,
                "crtsh": True,
                "otx": True,
                "securitytrails": True,
                "anubis": False,  # New source
                "bufferover": False,  # New source
                "riddler": False  # New source
            }
        },
        "content_discovery": {
            "directories_wordlist": "wordlists/directories.txt",
            "files_wordlist": "wordlists/files.txt",
            "max_depth": 3,
            "threads": 20,
            "extensions": [".php", ".asp", ".aspx", ".jsp", ".html", ".js", ".txt", ".pdf", ".bak", ".config", ".old", ".sql", ".xml", ".json"],
            "follow_redirects": True,
            "extract_metadata": True,
            "use_crawler": True,
            "max_crawl_pages": 100,
            "detect_sensitive_files": True
        }
    },
    "api_keys": {
        "shodan": "",
        "virustotal": "",
        "censys": "",
        "alienvault": "",
        "urlscan": "",
        "abuseipdb": "",
        "ipinfo": ""
    },
    "logging": {
        "level": "INFO",
        "log_file": "logs/luint.log",
        "max_file_size": 5242880,
        "backup_count": 3
    },
    "proxy": {
        "enabled": False,
        "url": "http://127.0.0.1:8080",
        "verify_ssl": True
    },
    "security_checks": {
        "dnsbl_servers": [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "dnsbl.sorbs.net",
            "dnsbl-1.uceprotect.net",
            "spam.dnsbl.anonmails.de",
            "spam.spamrats.com",
            "cbl.abuseat.org",
            "b.barracudacentral.org",
            "bl.mailspike.net",
            "dyna.spamrats.com"
        ],
        "tech_categories": {
            "cms": ["wordpress", "drupal", "joomla"],
            "database": ["mysql", "postgresql", "mongodb", "redis", "cassandra"],
            "framework": ["django", "flask", "laravel", "react", "angular", "vue"],
            "http": ["apache", "nginx", "iis"],
            "language": ["php", "python", "java", "ruby"]
        }
    },
    "rate_limiting": {
        "enabled": True,
        "default_rpm": 60,
        "services": {
            "shodan": 60,
            "virustotal": 4,
            "censys": 120,
            "alienvault": 100,
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