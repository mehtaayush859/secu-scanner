"""
Port Scanning Module for SecuScan

Uses nmap to scan open ports and grab service banners with advanced features.
"""

import subprocess
import re
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

# Common vulnerable services and versions
VULNERABLE_SERVICES = {
    "ssh": {
        "OpenSSH": {"7.2p1", "7.2p2", "7.1p1", "7.1p2"},
        "Dropbear": {"2016.74", "2016.73", "2015.71"}
    },
    "http": {
        "Apache": {"2.4.49", "2.4.50", "2.4.51"},
        "nginx": {"1.16.1", "1.17.0", "1.18.0"}
    },
    "ftp": {
        "vsftpd": {"2.3.4"},
        "ProFTPD": {"1.3.3c", "1.3.3d"}
    }
}

def scan_ports(target: str, nmap_args: list = None, scan_profile: str = "default") -> List[Dict[str, Any]]:
    """
    Scan open ports on the target using nmap with advanced features.

    Args:
        target (str): Target IP or hostname.
        nmap_args (list): Extra nmap arguments for speed/port range.
        scan_profile (str): Scan profile (default, stealth, aggressive, vuln)

    Returns:
        List[Dict[str, Any]]: List of open ports with enhanced service info.

    Example:
        >>> scan_ports("127.0.0.1", scan_profile="vuln")
        [{'port': 22, 'protocol': 'tcp', 'service': 'ssh', 'version': 'OpenSSH 8.2p1', 'risk_level': 'low'}]
    """
    try:
        # Define scan profiles
        profiles = {
            "default": ["-sV", "-T4", "--top-ports", "1000"],
            "stealth": ["-sS", "-sV", "-T2", "--top-ports", "100"],
            "aggressive": ["-sV", "-T5", "-p-", "--version-intensity", "9"],
            "vuln": ["-sV", "-T4", "--script=vuln", "--top-ports", "1000"]
        }
        
        base_args = ["nmap"] + profiles.get(scan_profile, profiles["default"])
        if nmap_args:
            base_args = ["nmap"] + nmap_args + [target]
        else:
            base_args.append(target)
            
        result = subprocess.run(
            base_args,
            capture_output=True, text=True, check=True
        )
        
        ports = parse_nmap_output(result.stdout)
        
        # Enhance with vulnerability assessment
        if scan_profile == "vuln":
            ports = enhance_with_vulnerabilities(ports)
        
        # Add risk assessment
        ports = add_risk_assessment(ports)
        
        return ports
    except FileNotFoundError:
        return [{"error": "nmap not installed or not found in PATH."}]
    except subprocess.CalledProcessError as e:
        return [{"error": f"nmap scan failed: {e}"}]
    except Exception as e:
        return [{"error": str(e)}]

def parse_nmap_output(output: str) -> List[Dict[str, Any]]:
    """
    Parse nmap output to extract open ports and service banners.

    Args:
        output (str): Raw nmap output.

    Returns:
        List[Dict[str, Any]]: Parsed port and service info.
    """
    ports = []
    lines = output.splitlines()
    parsing = False
    
    for line in lines:
        if line.strip().startswith("PORT"):
            parsing = True
            continue
        if parsing:
            if line.strip() == "" or line.startswith("Nmap done"):
                break
                
            # Enhanced regex for better parsing
            match = re.match(r"(\d+)\/(\w+)\s+(\w+)\s+(\S+)\s+(.*)", line)
            if match:
                port, proto, state, service, version = match.groups()
                if state == "open":
                    ports.append({
                        "port": int(port),
                        "protocol": proto,
                        "state": state,
                        "service": service,
                        "version": version.strip(),
                        "scan_time": datetime.now().isoformat()
                    })
            else:
                # Fallback for simpler format
                match = re.match(r"(\d+)\/(\w+)\s+open\s+(\S+)", line)
                if match:
                    port, proto, service = match.groups()
                    ports.append({
                        "port": int(port),
                        "protocol": proto,
                        "state": "open",
                        "service": service,
                        "version": "",
                        "scan_time": datetime.now().isoformat()
                    })
    return ports

def enhance_with_vulnerabilities(ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Add vulnerability information to port scan results.
    
    Args:
        ports (List[Dict[str, Any]]): List of port scan results.
        
    Returns:
        List[Dict[str, Any]]: Enhanced port results with vulnerability info.
    """
    for port in ports:
        service = port.get("service", "").lower()
        version = port.get("version", "")
        
        # Check for known vulnerable versions
        vulnerabilities = []
        if service in VULNERABLE_SERVICES:
            for software, vulnerable_versions in VULNERABLE_SERVICES[service].items():
                if software.lower() in version.lower():
                    for vuln_version in vulnerable_versions:
                        if vuln_version in version:
                            vulnerabilities.append({
                                "type": "known_vulnerable_version",
                                "software": software,
                                "version": vuln_version,
                                "description": f"Known vulnerable {software} version {vuln_version}"
                            })
        
        # Add common port vulnerabilities
        common_vulns = get_common_port_vulnerabilities(port.get("port", 0), service)
        vulnerabilities.extend(common_vulns)
        
        if vulnerabilities:
            port["vulnerabilities"] = vulnerabilities
            port["risk_level"] = "high"
        else:
            port["vulnerabilities"] = []
            port["risk_level"] = "low"
    
    return ports

def get_common_port_vulnerabilities(port: int, service: str) -> List[Dict[str, Any]]:
    """
    Get common vulnerabilities for specific ports and services.
    
    Args:
        port (int): Port number.
        service (str): Service name.
        
    Returns:
        List[Dict[str, Any]]: List of common vulnerabilities.
    """
    common_vulns = []
    
    # SSH vulnerabilities
    if port == 22 and service == "ssh":
        common_vulns.append({
            "type": "weak_configuration",
            "description": "SSH service detected - check for weak authentication",
            "recommendation": "Disable password authentication, use key-based auth"
        })
    
    # HTTP vulnerabilities
    elif port == 80 and service == "http":
        common_vulns.append({
            "type": "insecure_protocol",
            "description": "HTTP service detected - traffic is unencrypted",
            "recommendation": "Use HTTPS instead of HTTP"
        })
    
    # FTP vulnerabilities
    elif port == 21 and service == "ftp":
        common_vulns.append({
            "type": "insecure_protocol",
            "description": "FTP service detected - credentials sent in plaintext",
            "recommendation": "Use SFTP or FTPS instead"
        })
    
    # Telnet vulnerabilities
    elif port == 23 and service == "telnet":
        common_vulns.append({
            "type": "insecure_protocol",
            "description": "Telnet service detected - extremely insecure",
            "recommendation": "Disable telnet, use SSH instead"
        })
    
    return common_vulns

def add_risk_assessment(ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Add risk assessment to port scan results.
    
    Args:
        ports (List[Dict[str, Any]]): List of port scan results.
        
    Returns:
        List[Dict[str, Any]]: Port results with risk assessment.
    """
    for port in ports:
        risk_score = 0
        port_num = port.get("port", 0)
        service = port.get("service", "").lower()
        
        # High-risk ports
        if port_num in [21, 23, 3389, 1433, 3306]:
            risk_score += 3
        elif port_num in [22, 80, 443, 8080]:
            risk_score += 2
        elif port_num < 1024:
            risk_score += 1
        
        # High-risk services
        if service in ["telnet", "ftp", "rsh", "rlogin"]:
            risk_score += 3
        elif service in ["ssh", "http", "https"]:
            risk_score += 1
        
        # Vulnerabilities found
        if port.get("vulnerabilities"):
            risk_score += len(port["vulnerabilities"]) * 2
        
        # Assign risk level
        if risk_score >= 5:
            port["risk_level"] = "critical"
        elif risk_score >= 3:
            port["risk_level"] = "high"
        elif risk_score >= 1:
            port["risk_level"] = "medium"
        else:
            port["risk_level"] = "low"
        
        port["risk_score"] = risk_score
    
    return ports

def get_scan_summary(ports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a summary of port scan results.
    
    Args:
        ports (List[Dict[str, Any]]): List of port scan results.
        
    Returns:
        Dict[str, Any]: Summary statistics.
    """
    if not ports or "error" in ports[0]:
        return {"error": "No valid scan results"}
    
    total_ports = len(ports)
    risk_levels = {}
    services = {}
    vulnerabilities = 0
    
    for port in ports:
        # Count risk levels
        risk = port.get("risk_level", "unknown")
        risk_levels[risk] = risk_levels.get(risk, 0) + 1
        
        # Count services
        service = port.get("service", "unknown")
        services[service] = services.get(service, 0) + 1
        
        # Count vulnerabilities
        if port.get("vulnerabilities"):
            vulnerabilities += len(port["vulnerabilities"])
    
    return {
        "total_ports": total_ports,
        "risk_distribution": risk_levels,
        "service_distribution": services,
        "total_vulnerabilities": vulnerabilities,
        "scan_timestamp": datetime.now().isoformat()
    }