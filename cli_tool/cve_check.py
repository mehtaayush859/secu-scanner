"""
CVE Detection Module for SecuScan

Extracts installed software, checks against NVD CVE feed, and reports vulnerabilities with enhanced features.
"""

import json
import os
import platform
import subprocess
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import hashlib

NVD_FEED_PATH = os.environ.get(
    "SECUAUTH_NVD_FEED_PATH",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../data/cve_cache.json"))
)

# NVD API configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")  # Optional API key for higher rate limits

def get_installed_software() -> List[Dict[str, str]]:
    """
    Extract installed software and versions from the system with enhanced detection.

    Returns:
        List[Dict[str, str]]: List of {'name': ..., 'version': ..., 'source': ...}
    """
    software = []
    system = platform.system()
    
    if system == "Windows":
        software.extend(get_windows_software())
    else:
        software.extend(get_linux_software())
    
    # Add system information
    software.append({
        "name": f"{system} OS",
        "version": platform.release(),
        "source": "system"
    })
    
    # Add Python packages
    software.extend(get_python_packages())
    
    return software

def get_windows_software() -> List[Dict[str, str]]:
    """Extract Windows software from registry."""
    software = []
    try:
        # PowerShell command to get installed software as JSON
        ps_command = (
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
            "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
            "Select-Object DisplayName,DisplayVersion,Publisher | "
            "Where-Object { $_.DisplayName -and $_.DisplayVersion } | "
            "ConvertTo-Json"
        )
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            capture_output=True, text=True, check=True
        )
        
        ps_output = result.stdout.strip()
        if ps_output:
            entries = json.loads(ps_output)
            if isinstance(entries, dict):
                entries = [entries]
            for entry in entries:
                name = entry.get("DisplayName")
                version = entry.get("DisplayVersion")
                publisher = entry.get("Publisher", "")
                if name and version:
                    software.append({
                        "name": name,
                        "version": version,
                        "publisher": publisher,
                        "source": "windows_registry"
                    })
    except Exception as e:
        print(f"[WARNING] Could not extract Windows software: {e}")
    
    return software

def get_linux_software() -> List[Dict[str, str]]:
    """Extract Linux software from package managers."""
    software = []
    
    # Try dpkg-query (Debian/Ubuntu)
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package} ${Version} ${Maintainer}\n"],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.splitlines():
            if line.strip():
                parts = line.strip().split()
                if len(parts) >= 2:
                    software.append({
                        "name": parts[0],
                        "version": parts[1],
                        "maintainer": parts[2] if len(parts) > 2 else "",
                        "source": "dpkg"
                    })
        return software
    except Exception:
        pass
    
    # Try rpm (RedHat/CentOS)
    try:
        result = subprocess.run(
            ["rpm", "-qa", "--qf", "%{NAME} %{VERSION} %{VENDOR}\n"],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.splitlines():
            if line.strip():
                parts = line.strip().split()
                if len(parts) >= 2:
                    software.append({
                        "name": parts[0],
                        "version": parts[1],
                        "vendor": parts[2] if len(parts) > 2 else "",
                        "source": "rpm"
                    })
        return software
    except Exception:
        pass
    
    return software

def get_python_packages() -> List[Dict[str, str]]:
    """Extract installed Python packages."""
    software = []
    try:
        result = subprocess.run(
            ["pip", "list", "--format=json"],
            capture_output=True, text=True, check=True
        )
        packages = json.loads(result.stdout)
        for pkg in packages:
            software.append({
                "name": pkg["name"],
                "version": pkg["version"],
                "source": "pip"
            })
    except Exception:
        # Fallback to pip freeze
        try:
            result = subprocess.run(
                ["pip", "freeze"],
                capture_output=True, text=True, check=True
            )
            for line in result.stdout.splitlines():
                if "==" in line:
                    name, version = line.split("==", 1)
                    software.append({
                        "name": name,
                        "version": version,
                        "source": "pip"
                    })
        except Exception:
            pass
    
    return software

def load_nvd_feed() -> list:
    """
    Load the NVD CVE feed from local JSON with fallback to API.
    """
    if os.path.exists(NVD_FEED_PATH):
        try:
            with open(NVD_FEED_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "vulnerabilities" in data:
                    return [item["cve"] for item in data["vulnerabilities"] if "cve" in item]
                elif "CVE_Items" in data:
                    return data["CVE_Items"]
                return data
        except Exception as e:
            print(f"[WARNING] Error loading local NVD feed: {e}")
    
    # Fallback to API
    return fetch_nvd_api()

def fetch_nvd_api(limit: int = 100) -> list:
    """
    Fetch recent CVEs from NVD API.
    
    Args:
        limit (int): Number of recent CVEs to fetch.
        
    Returns:
        list: List of CVE entries.
    """
    try:
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        
        # Get recent CVEs
        params = {
            "resultsPerPage": limit,
            "startIndex": 0
        }
        
        response = requests.get(NVD_API_BASE, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        if "vulnerabilities" in data:
            return [item["cve"] for item in data["vulnerabilities"] if "cve" in item]
        
        return []
    except Exception as e:
        print(f"[WARNING] Could not fetch from NVD API: {e}")
        return []

def search_cve_by_software(software_name: str, software_version: str) -> List[Dict[str, Any]]:
    """
    Search for CVEs specific to a software package using NVD API.
    
    Args:
        software_name (str): Name of the software.
        software_version (str): Version of the software.
        
    Returns:
        List[Dict[str, Any]]: List of matching CVEs.
    """
    try:
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        
        # Search by CPE
        cpe = f"cpe:2.3:a:*:{software_name.lower()}:{software_version}:*:*:*:*:*:*:*:*"
        params = {
            "cpeName": cpe,
            "resultsPerPage": 20
        }
        
        response = requests.get(NVD_API_BASE, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        if "vulnerabilities" in data:
            return [item["cve"] for item in data["vulnerabilities"] if "cve" in item]
        
        return []
    except Exception as e:
        print(f"[WARNING] Could not search CVEs for {software_name}: {e}")
        return []

def calculate_cvss_score(cve: Dict[str, Any]) -> float:
    """
    Calculate CVSS score from CVE data.
    
    Args:
        cve (Dict[str, Any]): CVE entry.
        
    Returns:
        float: CVSS score (0.0 to 10.0).
    """
    try:
        # Try CVSS v3.1 first
        metrics = cve.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])[0]
        if cvss_v31:
            return float(cvss_v31.get("cvssData", {}).get("baseScore", 0))
        
        # Fallback to CVSS v3.0
        cvss_v30 = metrics.get("cvssMetricV30", [{}])[0]
        if cvss_v30:
            return float(cvss_v30.get("cvssData", {}).get("baseScore", 0))
        
        # Fallback to CVSS v2
        cvss_v2 = metrics.get("cvssMetricV2", [{}])[0]
        if cvss_v2:
            return float(cvss_v2.get("cvssData", {}).get("baseScore", 0))
        
        return 0.0
    except Exception:
        return 0.0

def match_cves(software_list: List[Dict[str, str]], nvd_feed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Match installed software against NVD CVE feed with enhanced matching.

    Args:
        software_list (List[Dict[str, str]]): Installed software.
        nvd_feed (List[Dict[str, Any]]): NVD CVE entries.

    Returns:
        List[Dict[str, Any]]: List of detected CVEs with enhanced information.
    """
    findings = []
    
    for sw in software_list:
        sw_name = sw["name"].lower()
        sw_version = sw["version"]
        
        # Search local feed
        local_matches = search_local_feed(sw_name, sw_version, nvd_feed)
        findings.extend(local_matches)
        
        # Search API for additional matches
        api_matches = search_cve_by_software(sw_name, sw_version)
        for cve in api_matches:
            findings.append(create_cve_finding(cve, sw))
    
    # Remove duplicates and sort by severity
    unique_findings = remove_duplicate_cves(findings)
    return sorted(unique_findings, key=lambda x: x.get("cvss_score", 0), reverse=True)

def search_local_feed(sw_name: str, sw_version: str, nvd_feed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Search local NVD feed for matching CVEs."""
    findings = []
    
    for cve in nvd_feed:
        cve_id = cve.get("id", "") or cve.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
        
        # Get description
        desc = ""
        if "descriptions" in cve and isinstance(cve["descriptions"], list) and cve["descriptions"]:
            desc = cve["descriptions"][0].get("value", "")
        elif "cve" in cve and "description" in cve["cve"]:
            desc = cve["cve"]["description"]["description_data"][0].get("value", "")
        
        # Check configurations
        configurations = cve.get("configurations", {})
        if isinstance(configurations, dict):
            nodes = configurations.get("nodes", [])
        elif isinstance(configurations, list):
            nodes = configurations
        else:
            nodes = []
        
        for node in nodes:
            cpe_matches = node.get("cpeMatch", []) or node.get("cpe_match", [])
            for cpe in cpe_matches:
                cpe_uri = cpe.get("criteria") or cpe.get("cpe23Uri", "")
                if sw_name in cpe_uri and sw_version in cpe_uri and cpe.get("vulnerable", False):
                    findings.append(create_cve_finding(cve, {"name": sw_name, "version": sw_version}))
    
    return findings

def create_cve_finding(cve: Dict[str, Any], software: Dict[str, str]) -> Dict[str, Any]:
    """Create a standardized CVE finding."""
    cve_id = cve.get("id", "") or cve.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
    
    # Get description
    desc = ""
    if "descriptions" in cve and isinstance(cve["descriptions"], list) and cve["descriptions"]:
        desc = cve["descriptions"][0].get("value", "")
    elif "cve" in cve and "description" in cve["cve"]:
        desc = cve["cve"]["description"]["description_data"][0].get("value", "")
    
    # Get severity
    metrics = cve.get("metrics", {})
    severity = "UNKNOWN"
    cvss_score = 0.0
    
    cvss_v31 = metrics.get("cvssMetricV31", [{}])[0]
    if cvss_v31:
        severity = cvss_v31.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
        cvss_score = float(cvss_v31.get("cvssData", {}).get("baseScore", 0))
    
    # Get published date
    published = cve.get("published", "") or cve.get("cve", {}).get("CVE_data_meta", {}).get("DATE_PUBLIC", "")
    
    return {
        "cve_id": cve_id,
        "software": software["name"],
        "version": software["version"],
        "description": desc,
        "severity": severity,
        "cvss_score": cvss_score,
        "published": published,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "source": software.get("source", "unknown")
    }

def remove_duplicate_cves(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate CVE findings based on CVE ID."""
    seen = set()
    unique_findings = []
    
    for finding in findings:
        cve_id = finding.get("cve_id")
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            unique_findings.append(finding)
    
    return unique_findings

def check_cves(target: str, use_api: bool = False) -> List[Dict[str, Any]]:
    """
    Main entry: Extract installed software, load NVD feed, and match CVEs.

    Args:
        target (str): Target IP or hostname (currently only local supported).
        use_api (bool): Whether to use NVD API for additional searches.

    Returns:
        List[Dict[str, Any]]: List of detected CVEs and software list.
    """
    if target not in ("localhost", "127.0.0.1"):
        return [{"error": "Remote CVE check not supported yet. Run locally."}]
    
    software = get_installed_software()
    if not software:
        return [{"error": "Could not extract installed software list."}]
    
    nvd_feed = load_nvd_feed()
    if not nvd_feed and not use_api:
        return [{"error": "NVD feed not found. Download and place cve_cache.json in data/."}]
    
    findings = match_cves(software, nvd_feed)
    
    # Generate summary
    summary = generate_cve_summary(findings, software)
    
    return [{
        "software_checked": software,
        "cve_findings": findings if findings else [{"info": "No known CVEs detected for installed software."}],
        "summary": summary
    }]

def generate_cve_summary(findings: List[Dict[str, Any]], software: List[Dict[str, str]]) -> Dict[str, Any]:
    """Generate a summary of CVE findings."""
    if not findings or "info" in findings[0]:
        return {
            "total_cves": 0,
            "severity_distribution": {},
            "cvss_score_average": 0.0,
            "software_count": len(software)
        }
    
    severity_counts = {}
    cvss_scores = []
    
    for finding in findings:
        if "cve_id" in finding:  # Skip info messages
            severity = finding.get("severity", "UNKNOWN")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            cvss_score = finding.get("cvss_score", 0)
            if cvss_score > 0:
                cvss_scores.append(cvss_score)
    
    return {
        "total_cves": len([f for f in findings if "cve_id" in f]),
        "severity_distribution": severity_counts,
        "cvss_score_average": sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0,
        "cvss_score_max": max(cvss_scores) if cvss_scores else 0.0,
        "software_count": len(software),
        "scan_timestamp": datetime.now().isoformat()
    }