"""
Network Discovery Module for SecuScan

Advanced network discovery and host enumeration capabilities.
"""

import subprocess
import ipaddress
import socket
import threading
import time
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
import concurrent.futures

def discover_network_hosts(network: str, scan_type: str = "ping") -> List[Dict[str, Any]]:
    """
    Discover active hosts in a network range.
    
    Args:
        network (str): Network range (e.g., "192.168.1.0/24")
        scan_type (str): Discovery method (ping, arp, nmap)
        
    Returns:
        List[Dict[str, Any]]: List of discovered hosts.
    """
    try:
        # Validate network range
        network_obj = ipaddress.IPv4Network(network, strict=False)
        
        if scan_type == "ping":
            return ping_sweep(network_obj)
        elif scan_type == "arp":
            return arp_scan(network_obj)
        elif scan_type == "nmap":
            return nmap_discovery(network_obj)
        else:
            return [{"error": f"Unknown scan type: {scan_type}"}]
            
    except Exception as e:
        return [{"error": f"Network discovery failed: {str(e)}"}]

def ping_sweep(network: ipaddress.IPv4Network) -> List[Dict[str, Any]]:
    """Perform ping sweep to discover hosts."""
    hosts = []
    
    def ping_host(ip):
        try:
            # Use system ping command
            if os.name == 'nt':  # Windows
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "1000", str(ip)],
                    capture_output=True, text=True, timeout=5
                )
            else:  # Unix/Linux
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", str(ip)],
                    capture_output=True, text=True, timeout=5
                )
            
            if result.returncode == 0:
                return {
                    "ip": str(ip),
                    "status": "up",
                    "method": "ping",
                    "response_time": extract_ping_time(result.stdout)
                }
        except Exception:
            pass
        
        return {
            "ip": str(ip),
            "status": "down",
            "method": "ping"
        }
    
    # Use ThreadPoolExecutor for concurrent scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(ping_host, ip) for ip in network.hosts()]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result["status"] == "up":
                hosts.append(result)
    
    return hosts

def arp_scan(network: ipaddress.IPv4Network) -> List[Dict[str, Any]]:
    """Perform ARP scan to discover hosts (Linux only)."""
    if os.name == 'nt':
        return [{"error": "ARP scan not supported on Windows"}]
    
    hosts = []
    try:
        # Use arping for ARP discovery
        for ip in network.hosts():
            try:
                result = subprocess.run(
                    ["arping", "-c", "1", "-w", "1", str(ip)],
                    capture_output=True, text=True, timeout=3
                )
                
                if result.returncode == 0:
                    hosts.append({
                        "ip": str(ip),
                        "status": "up",
                        "method": "arp",
                        "mac": extract_mac_address(result.stdout)
                    })
            except Exception:
                continue
                
    except FileNotFoundError:
        return [{"error": "arping command not found. Install iputils-arping."}]
    
    return hosts

def nmap_discovery(network: ipaddress.IPv4Network) -> List[Dict[str, Any]]:
    """Use nmap for host discovery."""
    try:
        result = subprocess.run(
            ["nmap", "-sn", str(network)],
            capture_output=True, text=True, check=True
        )
        
        hosts = []
        lines = result.stdout.splitlines()
        
        for line in lines:
            if "Nmap scan report for" in line:
                # Extract IP and hostname
                parts = line.split()
                ip = parts[-1].strip("()")
                hostname = parts[4] if len(parts) > 4 else ""
                
                hosts.append({
                    "ip": ip,
                    "hostname": hostname,
                    "status": "up",
                    "method": "nmap"
                })
        
        return hosts
        
    except FileNotFoundError:
        return [{"error": "nmap not found in PATH"}]
    except subprocess.CalledProcessError as e:
        return [{"error": f"nmap discovery failed: {e}"}]

def extract_ping_time(output: str) -> Optional[float]:
    """Extract response time from ping output."""
    try:
        if "time=" in output:
            time_str = output.split("time=")[1].split()[0]
            return float(time_str.replace("ms", ""))
        elif "time " in output:
            time_str = output.split("time ")[1].split()[0]
            return float(time_str.replace("ms", ""))
    except Exception:
        pass
    return None

def extract_mac_address(output: str) -> Optional[str]:
    """Extract MAC address from arping output."""
    try:
        if "[" in output and "]" in output:
            mac = output.split("[")[1].split("]")[0]
            return mac
    except Exception:
        pass
    return None

def scan_network_services(network: str, ports: List[int] = None) -> List[Dict[str, Any]]:
    """
    Scan network for common services.
    
    Args:
        network (str): Network range
        ports (List[int]): Ports to scan (default: common ports)
        
    Returns:
        List[Dict[str, Any]]: Network service scan results.
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080]
    
    try:
        # Use nmap for service scanning
        port_str = ",".join(map(str, ports))
        result = subprocess.run(
            ["nmap", "-sV", "-p", port_str, network],
            capture_output=True, text=True, check=True
        )
        
        return parse_nmap_service_output(result.stdout)
        
    except FileNotFoundError:
        return [{"error": "nmap not found in PATH"}]
    except subprocess.CalledProcessError as e:
        return [{"error": f"Service scan failed: {e}"}]

def parse_nmap_service_output(output: str) -> List[Dict[str, Any]]:
    """Parse nmap service detection output."""
    services = []
    current_host = None
    
    lines = output.splitlines()
    for line in lines:
        if "Nmap scan report for" in line:
            parts = line.split()
            current_host = parts[-1].strip("()")
        elif "/tcp" in line and "open" in line:
            if current_host:
                # Parse port/service line
                parts = line.split()
                port_proto = parts[0]
                state = parts[1]
                service = parts[2] if len(parts) > 2 else "unknown"
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                
                port = int(port_proto.split("/")[0])
                
                services.append({
                    "host": current_host,
                    "port": port,
                    "protocol": "tcp",
                    "state": state,
                    "service": service,
                    "version": version
                })
    
    return services

def generate_network_map(network: str) -> Dict[str, Any]:
    """
    Generate a comprehensive network map.
    
    Args:
        network (str): Network range to map
        
    Returns:
        Dict[str, Any]: Network map with hosts and services
    """
    print(f"[*] Discovering hosts in {network}...")
    hosts = discover_network_hosts(network, "nmap")
    
    if "error" in hosts[0]:
        return {"error": hosts[0]["error"]}
    
    print(f"[*] Found {len(hosts)} active hosts. Scanning services...")
    
    # Scan services for each host
    all_services = []
    for host in hosts:
        host_ip = host["ip"]
        print(f"[*] Scanning services on {host_ip}...")
        
        services = scan_network_services(host_ip)
        if services and "error" not in services[0]:
            all_services.extend(services)
    
    # Group services by host
    host_services = {}
    for service in all_services:
        host = service["host"]
        if host not in host_services:
            host_services[host] = []
        host_services[host].append(service)
    
    # Generate summary
    total_services = len(all_services)
    service_types = {}
    for service in all_services:
        service_name = service["service"]
        service_types[service_name] = service_types.get(service_name, 0) + 1
    
    return {
        "network": network,
        "scan_timestamp": datetime.now().isoformat(),
        "hosts": hosts,
        "services": all_services,
        "host_services": host_services,
        "summary": {
            "total_hosts": len(hosts),
            "total_services": total_services,
            "service_distribution": service_types
        }
    }

def check_network_security(network_map: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze network map for security issues.
    
    Args:
        network_map (Dict[str, Any]): Network map from generate_network_map
        
    Returns:
        Dict[str, Any]: Security analysis results
    """
    if "error" in network_map:
        return {"error": network_map["error"]}
    
    security_issues = []
    risk_score = 0
    
    # Check for common security issues
    for service in network_map.get("services", []):
        port = service["port"]
        service_name = service["service"]
        
        # High-risk services
        if port == 23 and service_name == "telnet":
            security_issues.append({
                "type": "insecure_service",
                "host": service["host"],
                "port": port,
                "service": service_name,
                "description": "Telnet service detected - extremely insecure",
                "severity": "critical",
                "recommendation": "Disable telnet, use SSH instead"
            })
            risk_score += 10
        
        elif port == 21 and service_name == "ftp":
            security_issues.append({
                "type": "insecure_service",
                "host": service["host"],
                "port": port,
                "service": service_name,
                "description": "FTP service detected - credentials sent in plaintext",
                "severity": "high",
                "recommendation": "Use SFTP or FTPS instead"
            })
            risk_score += 8
        
        elif port == 80 and service_name == "http":
            security_issues.append({
                "type": "insecure_protocol",
                "host": service["host"],
                "port": port,
                "service": service_name,
                "description": "HTTP service detected - traffic is unencrypted",
                "severity": "medium",
                "recommendation": "Use HTTPS instead"
            })
            risk_score += 3
        
        # Database services exposed
        elif port in [3306, 5432, 1433] and service_name in ["mysql", "postgresql", "mssql"]:
            security_issues.append({
                "type": "exposed_database",
                "host": service["host"],
                "port": port,
                "service": service_name,
                "description": f"Database service {service_name} exposed to network",
                "severity": "high",
                "recommendation": "Restrict database access to localhost or VPN"
            })
            risk_score += 7
    
    # Check for default ports
    default_ports = [22, 80, 443, 3389, 8080]
    for service in network_map.get("services", []):
        if service["port"] in default_ports:
            risk_score += 1
    
    # Determine overall risk level
    if risk_score >= 20:
        risk_level = "critical"
    elif risk_score >= 15:
        risk_level = "high"
    elif risk_score >= 10:
        risk_level = "medium"
    elif risk_score >= 5:
        risk_level = "low"
    else:
        risk_level = "minimal"
    
    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "security_issues": security_issues,
        "total_issues": len(security_issues),
        "recommendations": generate_network_recommendations(security_issues)
    }

def generate_network_recommendations(issues: List[Dict[str, Any]]) -> List[str]:
    """Generate recommendations based on security issues."""
    recommendations = []
    
    # Count issue types
    issue_types = {}
    for issue in issues:
        issue_type = issue["type"]
        issue_types[issue_type] = issue_types.get(issue_type, 0) + 1
    
    # Generate recommendations
    if issue_types.get("insecure_service", 0) > 0:
        recommendations.append("Disable or replace insecure services (telnet, ftp)")
    
    if issue_types.get("insecure_protocol", 0) > 0:
        recommendations.append("Implement HTTPS for all web services")
    
    if issue_types.get("exposed_database", 0) > 0:
        recommendations.append("Restrict database access and implement proper authentication")
    
    if len(issues) > 5:
        recommendations.append("Conduct a comprehensive security audit of the network")
    
    return recommendations 