#!/usr/bin/env python3
"""
LUINT - A comprehensive modular OSINT tool for network reconnaissance and security analysis.
Author: pixelbrow720
"""
import os
import sys

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from luint.cli import main

if __name__ == "__main__":
    main()
