"""
SecuScan Scanner Module

Coordinates all scanning modules and report generation with enhanced features.
"""

from typing import Literal, Dict, Any, Optional
from .ports import scan_ports, get_scan_summary
from .cve_check import check_cves
from .web_scan import scan_web_headers
from .password_audit import audit_passwords
from .config_audit import audit_config
from .network_discovery import generate_network_map, check_network_security
from reports.reporter import generate_report
import time
from datetime import datetime

def run_full_scan(
    target: str,
    scan_type: Literal["full", "ports", "cve", "web", "password", "config", "network"],
    output_format: Literal["json", "html", "pdf"],
    nmap_args: list = None,
    report_filename: str = None,
    scan_profile: str = "default",
    use_nvd_api: bool = False,
    timeout: int = 30
) -> None:
    """
    Run the requested scan(s) and generate a report with enhanced features.

    Args:
        target (str): Target IP address or hostname.
        scan_type (str): Type of scan to perform.
        output_format (str): Output format for the report.
        nmap_args (list): Custom nmap arguments.
        report_filename (str): Custom report filename.
        scan_profile (str): Scan profile (default, stealth, aggressive, vuln).
        use_nvd_api (bool): Whether to use NVD API for CVE checks.
        timeout (int): Timeout for web scans.

    Example:
        run_full_scan("127.0.0.1", "full", "json", scan_profile="vuln")
    """
    start_time = time.time()
    results = {}
    scan_metadata = {
        "target": target,
        "scan_type": scan_type,
        "scan_profile": scan_profile,
        "start_time": datetime.now().isoformat(),
        "scan_duration": 0
    }

    try:
        if scan_type in ("full", "ports"):
            print(f"[*] Scanning ports with profile: {scan_profile}...")
            port_results = scan_ports(target, nmap_args=nmap_args, scan_profile=scan_profile)
            results["ports"] = port_results
            
            # Add port scan summary
            if port_results and "error" not in port_results[0]:
                results["port_summary"] = get_scan_summary(port_results)

        if scan_type in ("full", "cve"):
            print(f"[*] Checking for CVEs (API: {use_nvd_api})...")
            cve_results = check_cves(target, use_api=use_nvd_api)
            results["cves"] = cve_results

        if scan_type in ("full", "web"):
            print(f"[*] Scanning web headers (timeout: {timeout}s)...")
            # For web scan, target should be a URL (http(s)://...)
            web_results = scan_web_headers(target, timeout=timeout)
            results["web"] = web_results

        if scan_type in ("full", "password"):
            print("[*] Auditing passwords...")
            password_results = audit_passwords()
            results["password_audit"] = password_results

        if scan_type in ("full", "config"):
            print("[*] Auditing system configurations...")
            config_results = audit_config()
            results["config_audit"] = config_results

        if scan_type in ("full", "network"):
            print("[*] Performing network discovery...")
            network_results = generate_network_map(target)
            if "error" not in network_results:
                security_analysis = check_network_security(network_results)
                network_results["security_analysis"] = security_analysis
            results["network_discovery"] = network_results

        # Calculate scan duration
        scan_duration = time.time() - start_time
        scan_metadata["scan_duration"] = round(scan_duration, 2)
        results["metadata"] = scan_metadata

        print(f"[*] Generating {output_format} report...")
        generate_report(results, output_format, report_filename=report_filename)
        
        # Print summary
        print_scan_summary(results, scan_duration)
        
    except Exception as e:
        print(f"[ERROR] Scan failed: {str(e)}")
        results["error"] = str(e)
        results["metadata"] = scan_metadata
        generate_report(results, output_format, report_filename=report_filename)

def print_scan_summary(results: Dict[str, Any], duration: float) -> None:
    """Print a summary of scan results."""
    print(f"\n{'='*50}")
    print("SCAN SUMMARY")
    print(f"{'='*50}")
    print(f"Scan completed in {duration:.2f} seconds")
    
    if "ports" in results:
        ports = results["ports"]
        if ports and "error" not in ports[0]:
            print(f"Ports found: {len(ports)}")
            if "port_summary" in results:
                summary = results["port_summary"]
                print(f"  - Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
                print(f"  - Risk levels: {summary.get('risk_distribution', {})}")
    
    if "cves" in results:
        cves = results["cves"]
        if cves and "error" not in cves[0]:
            findings = cves[0].get("cve_findings", [])
            if findings and "info" not in findings[0]:
                print(f"CVEs found: {len(findings)}")
                if "summary" in cves[0]:
                    summary = cves[0]["summary"]
                    print(f"  - Average CVSS: {summary.get('cvss_score_average', 0):.1f}")
                    print(f"  - Severity distribution: {summary.get('severity_distribution', {})}")
    
    if "web" in results:
        web = results["web"]
        if "error" not in web:
            risk = web.get("overall_risk_score", {})
            print(f"Web security grade: {risk.get('level', 'unknown').upper()}")
            print(f"  - Risk score: {risk.get('score', 0)}")
    
    if "network_discovery" in results:
        network = results["network_discovery"]
        if "error" not in network:
            summary = network.get("summary", {})
            print(f"Network hosts discovered: {summary.get('total_hosts', 0)}")
            print(f"  - Total services: {summary.get('total_services', 0)}")
            if "security_analysis" in network:
                security = network["security_analysis"]
                print(f"  - Security risk level: {security.get('risk_level', 'unknown').upper()}")
                print(f"  - Security issues found: {security.get('total_issues', 0)}")
    
    print(f"{'='*50}")

def run_quick_scan(target: str, output_format: str = "json") -> None:
    """
    Run a quick security assessment with essential checks.
    
    Args:
        target (str): Target IP or URL.
        output_format (str): Output format.
    """
    print("[*] Running quick security assessment...")
    
    # Quick port scan (top 100 ports)
    print("[*] Quick port scan...")
    port_results = scan_ports(target, nmap_args=["-T4", "--top-ports", "100"])
    
    # Basic web scan if target is a URL
    web_results = {}
    if target.startswith(('http://', 'https://')) or '://' in target:
        print("[*] Basic web security check...")
        web_results = scan_web_headers(target, timeout=10)
    
    # Quick CVE check (local only)
    cve_results = {}
    if target in ("localhost", "127.0.0.1"):
        print("[*] Quick CVE check...")
        cve_results = check_cves(target, use_api=False)
    
    results = {
        "quick_scan": True,
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "ports": port_results,
        "web": web_results,
        "cves": cve_results
    }
    
    generate_report(results, output_format, f"quick_scan_{int(time.time())}.{output_format}")

def run_comprehensive_scan(target: str, output_format: str = "html") -> None:
    """
    Run a comprehensive security assessment with all available checks.
    
    Args:
        target (str): Target IP or URL.
        output_format (str): Output format.
    """
    print("[*] Running comprehensive security assessment...")
    
    # Full scan with all profiles
    run_full_scan(
        target=target,
        scan_type="full",
        output_format=output_format,
        scan_profile="vuln",
        use_nvd_api=True,
        timeout=60,
        report_filename=f"comprehensive_scan_{int(time.time())}.{output_format}"
    )

def validate_scan_parameters(
    target: str,
    scan_type: str,
    scan_profile: str = "default"
) -> Dict[str, Any]:
    """
    Validate scan parameters and return configuration.
    
    Args:
        target (str): Target to scan.
        scan_type (str): Type of scan.
        scan_profile (str): Scan profile.
        
    Returns:
        Dict[str, Any]: Validated configuration.
    """
    config = {
        "valid": True,
        "warnings": [],
        "errors": []
    }
    
    # Validate target
    if not target:
        config["errors"].append("Target is required")
        config["valid"] = False
    
    # Validate scan type
    valid_types = ["full", "ports", "cve", "web", "password", "config", "network"]
    if scan_type not in valid_types:
        config["errors"].append(f"Invalid scan type. Must be one of: {valid_types}")
        config["valid"] = False
    
    # Validate scan profile
    valid_profiles = ["default", "stealth", "aggressive", "vuln"]
    if scan_profile not in valid_profiles:
        config["warnings"].append(f"Invalid scan profile '{scan_profile}', using 'default'")
        scan_profile = "default"
    
    # Platform-specific warnings
    import platform
    if scan_type in ["password", "config"] and platform.system() != "Linux":
        config["warnings"].append(f"{scan_type} scan is only supported on Linux")
    
    # Web scan validation
    if scan_type == "web" and not (target.startswith(('http://', 'https://')) or '://' in target):
        config["warnings"].append("Web scan target should be a URL (http:// or https://)")
    
    # Network scan validation
    if scan_type == "network":
        try:
            import ipaddress
            ipaddress.IPv4Network(target, strict=False)
        except ValueError:
            config["warnings"].append("Network scan target should be a valid network range (e.g., 192.168.1.0/24)")
    
    config["scan_profile"] = scan_profile
    return config