# LUINT - A Comprehensive OSINT Tool

LUINT (Lookup Intelligence) is a powerful modular OSINT (Open Source Intelligence) tool designed for advanced network reconnaissance and security analysis.

<p align="center">
  <img src="generated-icon.png" alt="LUINT Logo" width="150" height="150">
</p>

## Features

- **Modular Architecture**: 6 specialized modules with 69 total intelligence gathering capabilities
- **Comprehensive DNS Analysis**: Complete DNS information with security posture assessment and grading
- **Advanced Server Analysis**: Infrastructure security evaluation with detailed recommendations
- **Subdomain Discovery**: Multiple techniques for thorough subdomain enumeration
- **Content Discovery**: Find hidden directories, files, and sensitive information
- **Email Reconnaissance**: Gather and analyze email-related information
- **Security Assessment**: Evaluate overall security posture with actionable recommendations
- **Multiple Output Formats**: JSON, CSV, TXT, and HTML reporting
- **Recursive Scanning**: Automatically discover and scan related targets
- **Caching & Rate Limiting**: Respect API limits and optimize performance
- **Detailed Documentation**: Comprehensive guides in multiple languages

## Installation

```bash
# Clone the repository
git clone https://github.com/pixelbrow720/luint.git
cd luint

# Create a virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package and dependencies
pip install -e .

# Verify installation
python check_environment.py
```

For detailed installation instructions, see [PANDUAN_INSTALASI.md](PANDUAN_INSTALASI.md).

## Quick Start

```bash
# Show help
python main.py --help

# List available modules
python main.py modules

# Run a scan with specific modules
python main.py scan -m dns_info -m server_info example.com

# Run all modules
python main.py scan -a example.com -o results.json

# Generate an HTML report from JSON results
python main.py report results.json -o report.html
```

## Usage Examples

### DNS Security Analysis

```bash
python main.py scan -m dns_info example.com
```

This will perform a comprehensive DNS analysis including:
- DNS records (A, AAAA, MX, NS, TXT, etc.)
- WHOIS lookup
- DNSSEC validation
- SPF/DMARC/DKIM analysis
- DNS security posture assessment with A-F grading

### Server Infrastructure Analysis

```bash
python main.py scan -m server_info example.com
```

This will analyze the server infrastructure including:
- Geolocation and ASN information
- HTTP/HTTPS header analysis
- SSL/TLS certificate validation
- Port scanning with service detection
- Web technology detection
- Infrastructure security assessment with A-F grading

### Content Discovery

```bash
python main.py scan -m content_discovery example.com
```

This will search for hidden content including:
- Directory brute-forcing
- Sensitive file detection
- Metadata extraction
- Web crawling and link extraction

### Recursive Scanning

```bash
python main.py scan -r -d 2 -m subdomain_enum example.com
```

This will recursively discover and scan subdomains up to a depth of 2.

## Advanced Configuration

LUINT uses a configuration file (`config.yaml`) for customization:

```yaml
general:
  cache_duration: 3600  # Cache duration in seconds
  threads: 10           # Maximum number of threads
  timeout: 30           # Default request timeout

modules:
  dns_info:
    dns_servers: ['8.8.8.8', '1.1.1.1']
    check_dnssec: true
    
  server_info:
    ports: [80, 443, 8080, 8443]
    scan_timeout: 5
    detect_waf: true
    ssl_check: true
    perform_advanced_port_scan: false  # Set to true for comprehensive vulnerability scanning
  
  # More module configurations...

api_keys:
  shodan: "YOUR_SHODAN_API_KEY"
  censys: "YOUR_CENSYS_API_KEY"
  virustotal: "YOUR_VIRUSTOTAL_API_KEY"
```

## Project Structure

For detailed information about the code structure and architecture, see [STRUKTUR_KODE.md](docs/STRUKTUR_KODE.md).

## Security Features

For detailed information about the security assessment features, see [FITUR_KEAMANAN.md](docs/FITUR_KEAMANAN.md).

## Project Status

For information about the project's maturity and readiness, see [KESIAPAN_PROYEK.md](docs/KESIAPAN_PROYEK.md).

## License

This project is licensed under the MIT License.

## Acknowledgements

- The OSINT community for inspiration and best practices
- All the open-source libraries that made this project possible

## Disclaimer

LUINT is designed for legal and ethical security research. Always ensure you have proper authorization before conducting scans on any system or network you don't own. The authors accept no liability for misuse of this tool.
