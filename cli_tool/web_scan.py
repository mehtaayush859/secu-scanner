"""
Web Header Scanning Module

Checks for missing or insecure HTTP headers (OWASP Top 10) and provides comprehensive security analysis.
"""

import requests
import ssl
import socket
import urllib.parse
from typing import Dict, Any, List
from datetime import datetime
import json

# Enhanced OWASP security checks
OWASP_HEADER_CHECKS = {
    "Content-Security-Policy": {
        "description": "Helps prevent XSS attacks by specifying allowed content sources.",
        "recommendation": "Implement a strict CSP policy",
        "severity": "high"
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS and protects against protocol downgrade attacks.",
        "recommendation": "Set HSTS header with max-age >= 31536000",
        "severity": "high"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking by controlling whether the site can be framed.",
        "recommendation": "Set to DENY or SAMEORIGIN",
        "severity": "medium"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-sniffing attacks.",
        "recommendation": "Set to nosniff",
        "severity": "medium"
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is sent with requests.",
        "recommendation": "Set to strict-origin-when-cross-origin",
        "severity": "low"
    },
    "Permissions-Policy": {
        "description": "Restricts use of powerful browser features.",
        "recommendation": "Implement restrictive permissions policy",
        "severity": "medium"
    },
    "Cache-Control": {
        "description": "Controls caching, important for sensitive data.",
        "recommendation": "Set appropriate cache headers for sensitive content",
        "severity": "low"
    },
    "Set-Cookie": {
        "description": "Should use Secure and HttpOnly flags for cookies.",
        "recommendation": "Set Secure and HttpOnly flags on all cookies",
        "severity": "high"
    },
    "Access-Control-Allow-Origin": {
        "description": "Controls CORS, should not be too permissive.",
        "recommendation": "Avoid using '*' for CORS in production",
        "severity": "medium"
    }
}

def scan_web_headers(target: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Scan HTTP headers for security best practices (OWASP Top 10) with enhanced analysis.

    Args:
        target (str): Target URL (http(s)://...).
        timeout (int): Request timeout in seconds.

    Returns:
        Dict[str, Any]: Comprehensive header analysis results and recommendations.

    Example:
        scan_web_headers("http://localhost")
    """
    try:
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        # Parse URL
        parsed_url = urllib.parse.urlparse(target)
        
        # Perform HTTP scan
        http_results = scan_http_headers(target, timeout)
        
        # Perform SSL/TLS scan if HTTPS
        ssl_results = {}
        if parsed_url.scheme == 'https':
            ssl_results = scan_ssl_tls(parsed_url.netloc, timeout)
        
        # Combine results
        results = {
            "target": target,
            "scan_timestamp": datetime.now().isoformat(),
            "http_analysis": http_results,
            "ssl_analysis": ssl_results,
            "overall_risk_score": calculate_overall_risk(http_results, ssl_results)
        }
        
        return results
        
    except Exception as e:
        return {"error": str(e)}

def scan_http_headers(target: str, timeout: int) -> Dict[str, Any]:
    """Scan HTTP headers for security issues."""
    try:
        # Make request with custom headers to avoid detection
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        resp = requests.get(target, headers=headers, timeout=timeout, allow_redirects=True)
        headers = resp.headers
        
        findings = {}
        missing_headers = []
        insecure_headers = []
        
        # Check for each recommended header
        for header, config in OWASP_HEADER_CHECKS.items():
            if header not in headers:
                missing_headers.append({
                    "header": header,
                    "description": config["description"],
                    "recommendation": config["recommendation"],
                    "severity": config["severity"]
                })
            else:
                # Additional checks for specific headers
                header_value = headers[header]
                validation_result = validate_header_value(header, header_value)
                if validation_result:
                    insecure_headers.append(validation_result)
        
        # Check cookies
        cookie_issues = check_cookie_security(resp.cookies)
        
        # Check for information disclosure
        info_disclosure = check_information_disclosure(headers)
        
        return {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "headers": dict(headers),
            "missing_headers": missing_headers,
            "insecure_headers": insecure_headers,
            "cookie_issues": cookie_issues,
            "information_disclosure": info_disclosure,
            "redirect_chain": [r.url for r in resp.history] + [resp.url]
        }
        
    except requests.exceptions.RequestException as e:
        return {"error": f"HTTP request failed: {str(e)}"}

def validate_header_value(header: str, value: str) -> Dict[str, Any]:
    """Validate specific header values for security issues."""
    issues = []
    
    if header == "Strict-Transport-Security":
        if "max-age=" not in value:
            issues.append("Missing max-age parameter")
        else:
            try:
                max_age = int(value.split("max-age=")[1].split(";")[0])
                if max_age < 31536000:  # 1 year
                    issues.append("HSTS max-age should be at least 31536000")
            except (ValueError, IndexError):
                issues.append("Invalid max-age value")
    
    elif header == "X-Frame-Options":
        if value.lower() not in ["deny", "sameorigin"]:
            issues.append("Should be set to DENY or SAMEORIGIN")
    
    elif header == "X-Content-Type-Options":
        if value.lower() != "nosniff":
            issues.append("Should be set to nosniff")
    
    elif header == "Access-Control-Allow-Origin":
        if value == "*":
            issues.append("Too permissive - avoid using '*' in production")
    
    elif header == "Content-Security-Policy":
        if "unsafe-inline" in value or "unsafe-eval" in value:
            issues.append("Contains unsafe directives")
    
    if issues:
        return {
            "header": header,
            "value": value,
            "issues": issues,
            "severity": OWASP_HEADER_CHECKS[header]["severity"]
        }
    
    return None

def check_cookie_security(cookies) -> List[Dict[str, Any]]:
    """Check cookies for security issues."""
    issues = []
    
    for cookie in cookies:
        cookie_issues = []
        
        if not cookie.secure:
            cookie_issues.append("Missing Secure flag")
        
        if not cookie.has_nonstandard_attr("HttpOnly"):
            cookie_issues.append("Missing HttpOnly flag")
        
        if not cookie.has_nonstandard_attr("SameSite"):
            cookie_issues.append("Missing SameSite attribute")
        elif cookie.get_nonstandard_attr("SameSite") not in ["Strict", "Lax"]:
            cookie_issues.append("SameSite should be Strict or Lax")
        
        if cookie_issues:
            issues.append({
                "cookie_name": cookie.name,
                "domain": cookie.domain,
                "issues": cookie_issues
            })
    
    return issues

def check_information_disclosure(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Check for information disclosure in headers."""
    issues = []
    
    # Check for server information
    if "Server" in headers:
        issues.append({
            "type": "server_info",
            "header": "Server",
            "value": headers["Server"],
            "description": "Server information exposed"
        })
    
    # Check for powered-by headers
    for header, value in headers.items():
        if "powered-by" in header.lower() or "x-powered-by" in header.lower():
            issues.append({
                "type": "framework_info",
                "header": header,
                "value": value,
                "description": "Framework/technology information exposed"
            })
    
    # Check for version information
    for header, value in headers.items():
        if any(keyword in header.lower() for keyword in ["version", "build", "release"]):
            issues.append({
                "type": "version_info",
                "header": header,
                "value": value,
                "description": "Version information exposed"
            })
    
    return issues

def scan_ssl_tls(hostname: str, timeout: int) -> Dict[str, Any]:
    """Scan SSL/TLS configuration."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Analyze certificate
                cert_analysis = analyze_certificate(cert)
                
                # Analyze cipher suite
                cipher_analysis = analyze_cipher_suite(cipher)
                
                # Check for common vulnerabilities
                vuln_checks = check_ssl_vulnerabilities(hostname, version, cipher)
                
                return {
                    "certificate": cert_analysis,
                    "cipher_suite": cipher_analysis,
                    "protocol_version": version,
                    "vulnerabilities": vuln_checks,
                    "overall_grade": calculate_ssl_grade(cert_analysis, cipher_analysis, vuln_checks)
                }
    
    except Exception as e:
        return {"error": f"SSL/TLS scan failed: {str(e)}"}

def analyze_certificate(cert) -> Dict[str, Any]:
    """Analyze SSL certificate for security issues."""
    issues = []
    
    # Check expiration
    if 'notAfter' in cert:
        from datetime import datetime
        expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        if expiry < datetime.now():
            issues.append("Certificate has expired")
        elif (expiry - datetime.now()).days < 30:
            issues.append("Certificate expires soon")
    
    # Check key size
    if 'subjectAltName' not in cert:
        issues.append("Missing Subject Alternative Names")
    
    # Check issuer
    issuer = dict(x[0] for x in cert['issuer'])
    if 'commonName' in issuer and 'Let\'s Encrypt' in issuer['commonName']:
        # Let's Encrypt is fine, but check for self-signed
        pass
    elif 'commonName' in issuer and issuer['commonName'] == 'localhost':
        issues.append("Self-signed certificate detected")
    
    return {
        "subject": dict(x[0] for x in cert['subject']),
        "issuer": issuer,
        "expiry": cert.get('notAfter'),
        "issues": issues
    }

def analyze_cipher_suite(cipher) -> Dict[str, Any]:
    """Analyze cipher suite for security issues."""
    cipher_name, cipher_version, cipher_bits = cipher
    
    issues = []
    
    # Check for weak ciphers
    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'SHA1']
    for weak in weak_ciphers:
        if weak in cipher_name:
            issues.append(f"Weak cipher detected: {weak}")
    
    # Check key size
    if cipher_bits < 128:
        issues.append(f"Key size too small: {cipher_bits} bits")
    
    return {
        "name": cipher_name,
        "version": cipher_version,
        "bits": cipher_bits,
        "issues": issues
    }

def check_ssl_vulnerabilities(hostname: str, version: str, cipher) -> List[Dict[str, Any]]:
    """Check for common SSL/TLS vulnerabilities."""
    vulnerabilities = []
    
    # Check for old protocols
    if version in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
        vulnerabilities.append({
            "type": "weak_protocol",
            "description": f"Using deprecated protocol: {version}",
            "severity": "high"
        })
    
    # Check for known weak ciphers
    weak_ciphers = [
        'RC4', 'DES', '3DES', 'MD5', 'SHA1',
        'NULL', 'EXPORT', 'LOW', 'MEDIUM'
    ]
    
    for weak in weak_ciphers:
        if weak in cipher[0]:
            vulnerabilities.append({
                "type": "weak_cipher",
                "description": f"Using weak cipher: {cipher[0]}",
                "severity": "high"
            })
    
    return vulnerabilities

def calculate_ssl_grade(cert_analysis: Dict, cipher_analysis: Dict, vulnerabilities: List) -> str:
    """Calculate overall SSL/TLS grade."""
    score = 100
    
    # Deduct for certificate issues
    score -= len(cert_analysis.get("issues", [])) * 10
    
    # Deduct for cipher issues
    score -= len(cipher_analysis.get("issues", [])) * 15
    
    # Deduct for vulnerabilities
    for vuln in vulnerabilities:
        if vuln["severity"] == "high":
            score -= 25
        elif vuln["severity"] == "medium":
            score -= 15
        else:
            score -= 5
    
    # Assign grade
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"

def calculate_overall_risk(http_results: Dict, ssl_results: Dict) -> Dict[str, Any]:
    """Calculate overall risk score for the web application."""
    risk_score = 0
    issues = []
    
    # HTTP issues
    if "missing_headers" in http_results:
        for header in http_results["missing_headers"]:
            if header["severity"] == "high":
                risk_score += 3
            elif header["severity"] == "medium":
                risk_score += 2
            else:
                risk_score += 1
            issues.append(f"Missing {header['header']}")
    
    if "insecure_headers" in http_results:
        for header in http_results["insecure_headers"]:
            if header["severity"] == "high":
                risk_score += 2
            else:
                risk_score += 1
            issues.append(f"Insecure {header['header']}")
    
    # SSL issues
    if "error" not in ssl_results:
        if ssl_results.get("overall_grade") in ["D", "F"]:
            risk_score += 5
            issues.append("Poor SSL/TLS configuration")
        
        if ssl_results.get("vulnerabilities"):
            risk_score += len(ssl_results["vulnerabilities"]) * 2
            issues.append(f"{len(ssl_results['vulnerabilities'])} SSL vulnerabilities found")
    
    # Determine risk level
    if risk_score >= 10:
        risk_level = "critical"
    elif risk_score >= 7:
        risk_level = "high"
    elif risk_score >= 4:
        risk_level = "medium"
    elif risk_score >= 1:
        risk_level = "low"
    else:
        risk_level = "minimal"
    
    return {
        "score": risk_score,
        "level": risk_level,
        "issues": issues,
        "recommendations": generate_recommendations(http_results, ssl_results)
    }

def generate_recommendations(http_results: Dict, ssl_results: Dict) -> List[str]:
    """Generate security recommendations based on scan results."""
    recommendations = []
    
    # HTTP recommendations
    if "missing_headers" in http_results:
        for header in http_results["missing_headers"]:
            recommendations.append(f"Add {header['header']}: {header['recommendation']}")
    
    if "insecure_headers" in http_results:
        for header in http_results["insecure_headers"]:
            recommendations.append(f"Fix {header['header']}: {', '.join(header['issues'])}")
    
    # SSL recommendations
    if "error" not in ssl_results:
        if ssl_results.get("overall_grade") in ["D", "F"]:
            recommendations.append("Upgrade SSL/TLS configuration to use modern protocols and ciphers")
        
        if ssl_results.get("vulnerabilities"):
            recommendations.append("Address SSL/TLS vulnerabilities identified in the scan")
    
    return recommendations