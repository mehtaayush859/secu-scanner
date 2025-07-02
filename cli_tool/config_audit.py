"""
Configuration Baseline Audit Module for SecuScan

Checks system configuration files against secure baselines (e.g., CIS benchmarks).
"""

import os
from typing import List, Dict, Any
import platform

# Example SSH baseline (expand as needed)
SSH_BASELINE = {
    "PermitRootLogin": "no",
    "PasswordAuthentication": "no",
    "Protocol": "2",
    "X11Forwarding": "no"
}

def check_ssh_config(path: str = "/etc/ssh/sshd_config") -> List[Dict[str, Any]]:
    """
    Check SSH server configuration against secure baseline.

    Args:
        path (str): Path to sshd_config.

    Returns:
        List[Dict[str, Any]]: List of findings.
    """
    findings = []
    if not os.path.exists(path):
        return [{"error": f"{path} not found or not accessible."}]
    try:
        with open(path, "r") as f:
            config_lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        config_dict = {}
        for line in config_lines:
            if " " in line:
                key, value = line.split(None, 1)
                config_dict[key] = value
        for key, expected in SSH_BASELINE.items():
            actual = config_dict.get(key)
            if actual is None:
                findings.append({
                    "setting": key,
                    "issue": "Missing",
                    "recommendation": f"Set {key} to '{expected}'"
                })
            elif actual.lower() != expected.lower():
                findings.append({
                    "setting": key,
                    "issue": f"Value is '{actual}', expected '{expected}'",
                    "recommendation": f"Set {key} to '{expected}'"
                })
    except Exception as e:
        findings.append({"error": str(e)})
    return findings if findings else [{"info": "SSH config matches secure baseline."}]

def audit_config():
    """
    Run all configuration baseline checks.

    Returns:
        Dict[str, Any]: Results for each config file checked.
    """
    if platform.system() != "Linux":
        return [{"error": "Config Audit is only supported on Linux systems."}]
    return {
        "ssh_config": check_ssh_config()
        # Add more config checks here (e.g., sudoers, firewall, etc.)
    }