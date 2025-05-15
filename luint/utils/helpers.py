"""
Helper functions used throughout the LUINT tool.
"""
import re
import socket
import ipaddress
import hashlib
import urllib.parse
from datetime import datetime
import random
import json
import csv
import os
import string
from typing import List, Dict, Any, Union, Optional

from luint.constants import REGEX_PATTERNS


class SetEncoder(json.JSONEncoder):
    """Custom JSON encoder that can handle sets by converting them to lists."""
    def default(self, o):
        if isinstance(o, set):
            return list(o)
        return super().default(o)


def is_ip_address(target: str) -> bool:
    """
    Check if the target is a valid IP address.
    
    Args:
        target (str): The target to check
        
    Returns:
        bool: True if target is a valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_domain(target: str) -> bool:
    """
    Check if the target is a valid domain name.
    
    Args:
        target (str): The target to check
        
    Returns:
        bool: True if target is a valid domain name, False otherwise
    """
    pattern = re.compile(REGEX_PATTERNS['domain'])
    return bool(pattern.match(target))


def is_url(target: str) -> bool:
    """
    Check if the target is a valid URL.
    
    Args:
        target (str): The target to check
        
    Returns:
        bool: True if target is a valid URL, False otherwise
    """
    pattern = re.compile(REGEX_PATTERNS['url'])
    return bool(pattern.match(target))


def extract_domain_from_url(url: str) -> str:
    """
    Extract the domain name from a URL.
    
    Args:
        url (str): The URL to extract domain from
        
    Returns:
        str: Extracted domain name or original URL if extraction fails
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        return parsed_url.netloc
    except Exception:
        return url


def normalize_url(url: str) -> str:
    """
    Normalize a URL by ensuring it has a scheme.
    
    Args:
        url (str): The URL to normalize
        
    Returns:
        str: Normalized URL
    """
    if not url:
        return url
        
    if not (url.startswith('http://') or url.startswith('https://')):
        return f'https://{url}'
    return url


def get_random_user_agent() -> str:
    """
    Get a random user agent string from common browser user agents.
    
    Returns:
        str: Random user agent string
    """
    user_agents = [
        # Chrome
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
        # Firefox
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
        # Safari
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        # Edge
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
    ]
    return random.choice(user_agents)


def extract_emails(text: str) -> List[str]:
    """
    Extract email addresses from text.
    
    Args:
        text (str): Text to extract emails from
        
    Returns:
        list: List of found email addresses
    """
    pattern = re.compile(REGEX_PATTERNS['email'])
    return list(set(pattern.findall(text)))


def extract_ips(text: str) -> List[str]:
    """
    Extract IP addresses from text.
    
    Args:
        text (str): Text to extract IPs from
        
    Returns:
        list: List of found IP addresses
    """
    pattern = re.compile(REGEX_PATTERNS['ip_address'])
    return list(set(pattern.findall(text)))


def extract_domains(text: str) -> List[str]:
    """
    Extract domain names from text.
    
    Args:
        text (str): Text to extract domains from
        
    Returns:
        list: List of found domain names
    """
    pattern = re.compile(REGEX_PATTERNS['domain'])
    return list(set(pattern.findall(text)))


def extract_social_media(text: str) -> Dict[str, List[str]]:
    """
    Extract social media handles from text.
    
    Args:
        text (str): Text to extract social media handles from
        
    Returns:
        dict: Dictionary with platform names as keys and lists of handles as values
    """
    result = {}
    for platform, pattern in REGEX_PATTERNS['social_media'].items():
        regex = re.compile(pattern)
        matches = regex.findall(text)
        if matches:
            result[platform] = list(set(matches))
    return result


def generate_hash(data: str, algorithm: str = 'sha256') -> str:
    """
    Generate a hash of the provided data.
    
    Args:
        data (str): Data to hash
        algorithm (str, optional): Hash algorithm to use. Defaults to 'sha256'.
        
    Returns:
        str: Hash digest as hexadecimal string
    """
    if algorithm == 'md5':
        return hashlib.md5(data.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(data.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(data.encode()).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(data.encode()).hexdigest()
    else:
        return hashlib.sha256(data.encode()).hexdigest()


def format_timestamp(timestamp: Optional[float] = None) -> str:
    """
    Format a timestamp as a string.
    
    Args:
        timestamp (float, optional): Timestamp to format. Defaults to current time.
        
    Returns:
        str: Formatted timestamp string
    """
    if timestamp is None:
        timestamp = datetime.now().timestamp()
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def save_to_file(data: Any, filepath: str, format_type: str = 'json') -> bool:
    """
    Save data to a file in the specified format.
    
    Args:
        data (Any): Data to save
        filepath (str): Path to save the file to
        format_type (str, optional): Format to save as ('json', 'csv', 'txt'). Defaults to 'json'.
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Create directory if it doesn't exist
        directory = os.path.dirname(filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            
        if format_type.lower() == 'json':
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, sort_keys=True, ensure_ascii=False, cls=SetEncoder)
                
        elif format_type.lower() == 'csv':
            # If data is a list of dictionaries
            if isinstance(data, list) and all(isinstance(item, dict) for item in data):
                if not data:
                    # Empty list, create file with no rows
                    with open(filepath, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f)
                        writer.writerow(['No data available'])
                    return True
                    
                # Get all possible fields from all dictionaries
                fieldnames = set()
                for item in data:
                    fieldnames.update(item.keys())
                
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
                    writer.writeheader()
                    writer.writerows(data)
                    
            # If data is a dictionary
            elif isinstance(data, dict):
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Key', 'Value'])
                    for key, value in data.items():
                        # Convert complex values to JSON strings
                        if isinstance(value, (dict, list)):
                            value = json.dumps(value)
                        writer.writerow([key, value])
                        
            else:
                # Fallback for other data types
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(str(data))
                    
        else:  # Default to text
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(str(data))
                
        return True
        
    except Exception as e:
        print(f"Error saving to file: {str(e)}")
        return False


def generate_random_string(length: int = 8) -> str:
    """
    Generate a random string of specified length.
    
    Args:
        length (int, optional): Length of the string to generate. Defaults to 8.
        
    Returns:
        str: Random string
    """
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve a hostname to an IP address.
    
    Args:
        hostname (str): Hostname to resolve
        
    Returns:
        str or None: Resolved IP address or None if resolution failed
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def truncate_string(s: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Truncate a string to a maximum length, appending a suffix if truncated.
    
    Args:
        s (str): String to truncate
        max_length (int, optional): Maximum length. Defaults to 100.
        suffix (str, optional): Suffix to append if truncated. Defaults to '...'.
        
    Returns:
        str: Truncated string
    """
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix


def parse_cidr(cidr: str) -> List[str]:
    """
    Parse a CIDR notation string and return all IP addresses in the range.
    
    Args:
        cidr (str): CIDR notation string (e.g., "192.168.1.0/24")
        
    Returns:
        list: List of all IP addresses in the range
    """
    try:
        return [str(ip) for ip in ipaddress.IPv4Network(cidr, strict=False)]
    except (ValueError, ipaddress.AddressValueError):
        return []


def merge_dictionaries(dict1: Dict, dict2: Dict) -> Dict:
    """
    Recursively merge two dictionaries.
    
    Args:
        dict1 (dict): First dictionary
        dict2 (dict): Second dictionary
        
    Returns:
        dict: Merged dictionary
    """
    result = dict1.copy()
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dictionaries(result[key], value)
        else:
            result[key] = value
    return result
