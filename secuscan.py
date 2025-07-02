#!/usr/bin/env python3
"""
SecuScan CLI Entry Point
Simple entry point for the SecuScan security scanner
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    """Main entry point for SecuScan CLI."""
    # Import and run the main function
    from main import main as main_function
    main_function()

if __name__ == "__main__":
    main() 