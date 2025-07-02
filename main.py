import argparse
import os
import sys
from cli_tool.scanner import run_full_scan, run_quick_scan, run_comprehensive_scan, validate_scan_parameters

# Import banner for display
try:
    from cli_tool.banner import print_banner, interactive_cli
except ImportError:
    def print_banner():
        print("SecuScan - Advanced Vulnerability & Misconfiguration Scanner")
    def interactive_cli():
        print("Interactive CLI not available")

REPORTS_DIR = os.environ.get("SECUAUTH_REPORTS_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "../../reports/html")))

def main():
    # Show banner at startup
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="SecuScan: Advanced Vulnerability & Misconfiguration Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive CLI mode (Metasploit-style)
  python main.py --interactive

  # Quick security assessment
  python main.py --target 127.0.0.1 --quick

  # Comprehensive scan with all features
  python main.py --target 127.0.0.1 --comprehensive

  # Port scan with vulnerability detection
  python main.py --target 127.0.0.1 --scan-type ports --scan-profile vuln

  # Web security scan with SSL analysis
  python main.py --target https://example.com --scan-type web --timeout 30

  # CVE check with NVD API integration
  python main.py --target 127.0.0.1 --scan-type cve --use-api

  # Network discovery and security analysis
  python main.py --target 192.168.1.0/24 --scan-type network

  # Full scan with custom report name
  python main.py --target 127.0.0.1 --scan-type full --output html --report-name my_scan_report
        """
    )
    
    # Basic arguments
    parser.add_argument("--target", "-t", 
        help="Target IP address, hostname, or URL")
    parser.add_argument("--scan-type", "-s",
        choices=["full", "ports", "cve", "web", "password", "config", "network"],
        default="full", help="Type of scan to perform")
    parser.add_argument("--output", "-o", choices=["json", "html"], default="json",
        help="Report output format")
    
    # Enhanced scan options
    parser.add_argument("--scan-profile", choices=["default", "stealth", "aggressive", "vuln"], 
        default="default", help="Scan profile for port scanning")
    parser.add_argument("--scan-speed", choices=["fast", "normal", "slow"], default="fast",
        help="Set the speed of the scan (legacy option, use --scan-profile instead)")
    parser.add_argument("--use-api", action="store_true",
        help="Use NVD API for enhanced CVE detection")
    parser.add_argument("--timeout", type=int, default=30,
        help="Timeout for web scans in seconds")
    
    # Scan modes
    parser.add_argument("--quick", action="store_true",
        help="Run a quick security assessment")
    parser.add_argument("--comprehensive", action="store_true",
        help="Run a comprehensive security assessment with all features")
    parser.add_argument("--interactive", "-i", action="store_true",
        help="Launch interactive CLI mode (Metasploit-style)")
    
    # Report options
    parser.add_argument("--report-name", type=str, default=None,
        help="Custom report filename")
    parser.add_argument("--run-tests", action="store_true",
        help="Run all unit tests")
    
    # Advanced options
    parser.add_argument("--verbose", "-v", action="store_true",
        help="Enable verbose output")
    parser.add_argument("--dry-run", action="store_true",
        help="Validate parameters without running scan")

    args = parser.parse_args()

    # Handle interactive mode
    if args.interactive:
        interactive_cli()
        return

    # Handle test execution
    if args.run_tests:
        run_tests()
        return

    # Check if target is required (except for interactive mode)
    if not args.target and not args.interactive:
        print("Error: --target is required for non-interactive scans")
        print("Use --interactive for CLI mode or provide a target with --target")
        sys.exit(1)

    # Validate scan parameters
    config = validate_scan_parameters(args.target, args.scan_type, args.scan_profile)
    
    if not config["valid"]:
        print("Configuration errors:")
        for error in config["errors"]:
            print(f"   - {error}")
        sys.exit(1)
    
    if config["warnings"]:
        print("Configuration warnings:")
        for warning in config["warnings"]:
            print(f"   - {warning}")
        print()

    # Handle dry run
    if args.dry_run:
        print("Configuration is valid!")
        print(f"Target: {args.target}")
        print(f"Scan Type: {args.scan_type}")
        print(f"Scan Profile: {config['scan_profile']}")
        print(f"Output Format: {args.output}")
        if args.use_api:
            print("NVD API: Enabled")
        return

    # Convert legacy scan-speed to scan-profile
    if args.scan_speed != "fast":
        speed_to_profile = {
            "normal": "default",
            "slow": "aggressive"
        }
        args.scan_profile = speed_to_profile.get(args.scan_speed, "default")
        if args.verbose:
            print(f"Converted scan-speed '{args.scan_speed}' to scan-profile '{args.scan_profile}'")

    # Determine nmap arguments based on scan profile
    nmap_args = get_nmap_args_for_profile(args.scan_profile)

    # Generate report filename
    import time
    report_filename = args.report_name or f"scan_report_{int(time.time())}.{args.output}"

    # Run appropriate scan mode
    if args.quick:
        print("Running quick security assessment...")
        run_quick_scan(args.target, args.output)
    elif args.comprehensive:
        print("Running comprehensive security assessment...")
        run_comprehensive_scan(args.target, args.output)
    else:
        print(f"Running {args.scan_type} scan with {args.scan_profile} profile...")
        run_full_scan(
            target=args.target,
            scan_type=args.scan_type,
            output_format=args.output,
            nmap_args=nmap_args,
            report_filename=report_filename,
            scan_profile=args.scan_profile,
            use_nvd_api=args.use_api,
            timeout=args.timeout
        )

def get_nmap_args_for_profile(profile: str) -> list:
    """Convert scan profile to nmap arguments."""
    profiles = {
        "default": ["-T4", "--top-ports", "1000"],
        "stealth": ["-sS", "-T2", "--top-ports", "100"],
        "aggressive": ["-T5", "-p-", "--version-intensity", "9"],
        "vuln": ["-T4", "--script=vuln", "--top-ports", "1000"]
    }
    return profiles.get(profile, profiles["default"])

def run_tests():
    """Run all unit tests."""
    import subprocess
    import sys
    
    print("Running unit tests...")
    
    try:
        # Run pytest if available
        result = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-v"], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print("All tests passed!")
            print(result.stdout)
        else:
            print("Some tests failed:")
            print(result.stdout)
            print(result.stderr)
            
    except FileNotFoundError:
        print("pytest not found. Running basic test validation...")
        
        # Basic test validation
        test_files = [
            "tests/test_ports.py",
            "tests/test_cve_check.py", 
            "tests/test_web_scan.py",
            "tests/test_password_audit.py",
            "tests/test_config_audit.py"
        ]
        
        for test_file in test_files:
            if os.path.exists(test_file):
                print(f"{test_file} exists")
            else:
                print(f"{test_file} missing")

if __name__ == "__main__":
    main()


# Example Usage:
# python main.py --interactive                    # Launch interactive CLI
# python main.py --target 127.0.0.1 --scan-type ports --output json
# python main.py --target 127.0.0.1 --scan-type cve --output json
# python main.py --target http://localhost --scan-type web --output html
# python main.py --target 127.0.0.1 --scan-type password --output json