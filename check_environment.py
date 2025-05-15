#!/usr/bin/env python3
"""
LUINT Environment Check Script.
Verifies that all required dependencies and configurations are properly set up.
"""
import sys
import os
import importlib
import subprocess
import json
import platform

def print_header(message):
    """Print a formatted header."""
    print("\n" + "=" * 80)
    print(f" {message}")
    print("=" * 80)

def print_success(message):
    """Print a success message."""
    print(f"✓ {message}")

def print_warning(message):
    """Print a warning message."""
    print(f"⚠ {message}")

def print_error(message):
    """Print an error message."""
    print(f"✗ {message}")

def check_python_version():
    """Check Python version."""
    print_header("Checking Python Version")
    version = sys.version_info
    min_version = (3, 8)
    
    print(f"Detected Python version: {version.major}.{version.minor}.{version.micro}")
    
    if (version.major, version.minor) >= min_version:
        print_success(f"Python version {version.major}.{version.minor}.{version.micro} meets requirements (>= 3.8)")
        return True
    else:
        print_error(f"Python version {version.major}.{version.minor}.{version.micro} does not meet requirements (>= 3.8)")
        return False

def check_dependencies():
    """Check required dependencies."""
    print_header("Checking Required Dependencies")
    
    
    required_packages = [
        "beautifulsoup4",
        "click",
        "dnspython",
        "email-validator",
        "flask",
        "flask-sqlalchemy",
        "jinja2",
        "mmh3",
        "psycopg2-binary",
        "pyopenssl",
        "python-nmap",
        "python-whois",
        "pyyaml",
        "requests",
        "rich",
        "trafilatura"
    ]
    
    missing_packages = []
    installed_packages = {}
    
    for package in required_packages:
        try:
            module = importlib.import_module(package.replace('-', '_'))
            if hasattr(module, '__version__'):
                version = module.__version__
            elif hasattr(module, 'version'):
                version = module.version
            else:
                version = "Unknown"
            
            installed_packages[package] = version
            print_success(f"{package} (v{version}) is installed")
        except ImportError:
            missing_packages.append(package)
            print_error(f"{package} is not installed")
    
    return True

def check_directories():
    """Check required directories."""
    print_header("Checking Required Directories")
    
    directories = [
        "logs",
        "wordlists"
    ]
    
    missing_dirs = []
    
    for directory in directories:
        if os.path.exists(directory) and os.path.isdir(directory):
            print_success(f"{directory}/ directory exists")
        else:
            missing_dirs.append(directory)
            print_error(f"{directory}/ directory does not exist")
    
    if missing_dirs:
        print("\nCreating missing directories...")
        for directory in missing_dirs:
            os.makedirs(directory, exist_ok=True)
            print_success(f"Created {directory}/ directory")
    
    return True

def check_nmap():
    """Check nmap installation."""
    print_header("Checking Nmap Installation")
    
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
        version_line = result.stdout.strip().split('\n')[0]
        print_success(f"Nmap is installed: {version_line}")
        return True
    except FileNotFoundError:
        print_error("Nmap is not installed or not in PATH")
        print("\nNmap is required for port scanning features.")
        print("Install nmap:")
        print("  - On Ubuntu/Debian: sudo apt-get install nmap")
        print("  - On CentOS/RHEL: sudo yum install nmap")
        print("  - On macOS: brew install nmap")
        print("  - On Windows: Download from https://nmap.org/download.html")
        return False

def check_config():
    """Check configuration files."""
    print_header("Checking Configuration Files")
    
    if os.path.exists('config.yaml'):
        print_success("config.yaml exists")
    else:
        if os.path.exists('config.yaml.example'):
            print_warning("config.yaml does not exist, but config.yaml.example is available")
            print("Consider copying config.yaml.example to config.yaml and customizing it:")
            print("  cp config.yaml.example config.yaml")
        else:
            print_error("Neither config.yaml nor config.yaml.example exist")
    
    return True

def check_wordlists():
    """Check wordlist files."""
    print_header("Checking Wordlist Files")
    
    wordlist_dir = 'wordlists'
    if not os.path.exists(wordlist_dir):
        print_error(f"{wordlist_dir}/ directory does not exist")
        return False
    
    wordlists = os.listdir(wordlist_dir)
    if wordlists:
        print_success(f"Found {len(wordlists)} wordlist files in {wordlist_dir}/")
        for wordlist in wordlists:
            file_path = os.path.join(wordlist_dir, wordlist)
            size = os.path.getsize(file_path)
            print(f"  - {wordlist} ({size} bytes)")
    else:
        print_warning(f"No wordlist files found in {wordlist_dir}/")
        print("Wordlists are required for brute force capabilities.")
        print("Consider adding wordlists for subdomain enumeration and content discovery.")
    
    return True

def system_info():
    """Display system information."""
    print_header("System Information")
    
    print(f"Operating System: {platform.system()} {platform.release()}")
    print(f"Platform: {platform.platform()}")
    print(f"Python Path: {sys.executable}")
    print(f"Current Directory: {os.getcwd()}")
    
    # Check available memory
    try:
        if platform.system() == 'Linux':
            cmd = "free -m | awk 'NR==2{print $2}'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            mem = int(result.stdout.strip())
            print(f"System Memory: {mem} MB")
        elif platform.system() == 'Darwin':  # macOS
            cmd = "sysctl hw.memsize | awk '{print $2/1024/1024}'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            mem = int(float(result.stdout.strip()))
            print(f"System Memory: {mem} MB")
        elif platform.system() == 'Windows':
            import ctypes
            kernel32 = ctypes.windll.kernel32
            c_ulong = ctypes.c_ulong
            class MEMORYSTATUS(ctypes.Structure):
                _fields_ = [
                    ('dwLength', c_ulong),
                    ('dwMemoryLoad', c_ulong),
                    ('dwTotalPhys', c_ulong),
                    ('dwAvailPhys', c_ulong),
                    ('dwTotalPageFile', c_ulong),
                    ('dwAvailPageFile', c_ulong),
                    ('dwTotalVirtual', c_ulong),
                    ('dwAvailVirtual', c_ulong)
                ]
            memoryStatus = MEMORYSTATUS()
            memoryStatus.dwLength = ctypes.sizeof(MEMORYSTATUS)
            kernel32.GlobalMemoryStatus(ctypes.byref(memoryStatus))
            mem = memoryStatus.dwTotalPhys / (1024*1024)
            print(f"System Memory: {int(mem)} MB")
    except:
        print("Could not determine system memory")

def main():
    """Run all checks."""
    print("""
    _      _    _ _____ _   _ _______
   | |    | |  | |_   _| \ | |__   __|
   | |    | |  | | | | |  \| |  | |
   | |    | |  | | | | | . ` |  | |
   | |____| |__| |_| |_| |\  |  | |
   |______|\____/|_____|_| \_|  |_|
                                                          
   Environment Check Tool
    """)
    
    system_info()
    
    # Run all checks
    checks = [
        check_python_version(),
        check_dependencies(),
        check_directories(),
        check_nmap(),
        check_config(),
        check_wordlists()
    ]
    
    # Summary
    print_header("Summary")
    
    
    if all(checks):
        print_success("All checks passed! Your environment is ready for LUINT.")
        print("\nTo run LUINT, use: python main.py --help")
        return 0
    else:
        print_warning("Some checks failed. Please address the issues above before running LUINT.")
        return 1

if __name__ == "__main__":
    sys.exit(main())