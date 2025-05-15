"""
Constants used throughout the LUINT tool.
"""

# Version information
VERSION = "1.0.0"

# ASCII Art Banner
BANNER = r"""
  _      _    _ _____ _   _ _______ 
 | |    | |  | |_   _| \ | |__   __|
 | |    | |  | | | | |  \| |  | |   
 | |    | |  | | | | | . ` |  | |   
 | |____| |__| |_| |_| |\  |  | |   
 |______|\____/|_____|_| \_|  |_|   
                                     
 LUINT - OpenSource Intelligence Tool                                    
"""

VERSION_INFO = """
Version: 1.0.0
Author: pixelbrow720
GitHub: https://github.com/pixelbrow720
Twitter: @BrowPixel
Email: pixelbrow13@gmail.com
"""

# HTTP Request Headers
DEFAULT_HEADERS = {
    'User-Agent': 'LUINT-Scanner/1.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'close'
}

# Module categories
MODULE_CATEGORIES = {
    'dns_info': 'DNS Information',
    'server_info': 'Server & Infrastructure',
    'subdomain_enum': 'Subdomain Enumeration',
    'content_discovery': 'Content & File Analysis',
    'email_recon': 'Email & Contact',
    'security_checks': 'Reputation & Security',
    'social_media': 'Social Media & Network'
}

# Error messages
ERROR_MESSAGES = {
    'api_key_missing': 'API key for {service} is missing. Please add it to your configuration.',
    'connection_error': 'Connection error occurred when connecting to {service}: {error}',
    'rate_limit_exceeded': 'Rate limit exceeded for {service}. Please try again later.',
    'timeout_error': 'Request to {service} timed out after {timeout} seconds.',
    'invalid_target': 'Invalid target specified. Please provide a valid domain or IP.',
    'module_not_found': 'Module {module} not found.',
    'unknown_error': 'An unknown error occurred: {error}'
}

# Common regex patterns
REGEX_PATTERNS = {
    'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    'domain': r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
    'url': r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
    'social_media': {
        'facebook': r'facebook\.com/([a-zA-Z0-9._%+-]+)',
        'twitter': r'(?:twitter\.com|x\.com)/([a-zA-Z0-9_]+)',
        'linkedin': r'linkedin\.com/(?:in|company)/([a-zA-Z0-9_-]+)',
        'instagram': r'instagram\.com/([a-zA-Z0-9_]+)',
        'github': r'github\.com/([a-zA-Z0-9_-]+)',
        'youtube': r'youtube\.com/(?:user|channel)/([a-zA-Z0-9_-]+)',
        'reddit': r'reddit\.com/(?:user|r)/([a-zA-Z0-9_-]+)'
    }
}

# Common DNS record types
DNS_RECORD_TYPES = [
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT', 'CAA', 'DNSKEY', 
    'DS', 'NSEC', 'NSEC3', 'RRSIG', 'TLSA'
]

# Common HTTP security headers
SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
    'Referrer-Policy',
    'Feature-Policy',
    'Permissions-Policy',
    'Cross-Origin-Embedder-Policy',
    'Cross-Origin-Opener-Policy',
    'Cross-Origin-Resource-Policy'
]

# Common web technologies
WEB_TECHNOLOGIES = [
    'WordPress', 'Drupal', 'Joomla', 'Magento', 'Shopify', 'Wix', 'Squarespace',
    'Django', 'Flask', 'Laravel', 'Symfony', 'Angular', 'React', 'Vue', 'jQuery',
    'Bootstrap', 'PHP', 'ASP.NET', 'Node.js', 'Ruby on Rails', 'Apache', 'Nginx',
    'IIS', 'Cloudflare', 'Akamai', 'Fastly', 'Amazon CloudFront', 'Google Cloud CDN'
]

# Common sensitive files and directories to check
SENSITIVE_FILES = [
    'robots.txt',
    'sitemap.xml',
    '.git/HEAD',
    '.env',
    '.htaccess',
    'wp-config.php',
    'config.php',
    'phpinfo.php',
    'admin/',
    'administrator/',
    'login/',
    'wp-admin/',
    'backup/',
    'backup.zip',
    'backup.tar.gz',
    'db.sql',
    'database.sql',
    'debug.log',
    'error.log',
    'server-status',
    'server-info',
    '.DS_Store',
    '.svn/entries',
    '.idea/',
    '.vscode/',
    'Dockerfile',
    'docker-compose.yml',
    'README.md',
    'CHANGELOG.md',
    'LICENSE',
    'CONTRIBUTING.md',
    'package.json',
    'composer.json',
    'Gemfile',
    'requirements.txt'
]

# API endpoints
API_ENDPOINTS = {
    'virustotal': {
        'domain': 'https://www.virustotal.com/api/v3/domains/{target}',
        'ip': 'https://www.virustotal.com/api/v3/ip_addresses/{target}',
        'url': 'https://www.virustotal.com/api/v3/urls'
    },
    'shodan': {
        'host': 'https://api.shodan.io/shodan/host/{target}',
        'dns': 'https://api.shodan.io/dns/resolve'
    },
    'urlscan': {
        'scan': 'https://urlscan.io/api/v1/scan/',
        'result': 'https://urlscan.io/api/v1/result/{uuid}',
        'search': 'https://urlscan.io/api/v1/search/'
    },
    'abuseipdb': {
        'check': 'https://api.abuseipdb.com/api/v2/check'
    },
    'ipinfo': {
        'ip': 'https://ipinfo.io/{target}/json'
    },
    'crtsh': {
        'domain': 'https://crt.sh/?q={target}&output=json'
    }
}

# Color codes for terminal output
COLORS = {
    'reset': '\033[0m',
    'black': '\033[30m',
    'red': '\033[31m',
    'green': '\033[32m',
    'yellow': '\033[33m',
    'blue': '\033[34m',
    'magenta': '\033[35m',
    'cyan': '\033[36m',
    'white': '\033[37m',
    'bold': '\033[1m',
    'underline': '\033[4m'
}

# Common file extensions for content discovery
COMMON_EXTENSIONS = [
    'html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'cgi', 'pl', 'py', 'rb', 'css', 'js',
    'xml', 'json', 'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip',
    'tar', 'gz', 'rar', '7z', 'bak', 'old', 'config', 'conf', 'ini', 'log', 'sql',
    'db', 'sqlite', 'sqlite3', 'bak', 'backup', 'swp', 'env', 'gitignore', 'git',
    'htaccess', 'htpasswd', 'md', 'yml', 'yaml', 'toml', 'csv', 'svg', 'ico', 'png',
    'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'mp3', 'mp4', 'wav', 'avi', 'mov', 'wmv'
]
