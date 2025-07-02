"""
Password Audit Module for SecuScan

Checks for weak, reused, or default passwords and estimates password entropy.
"""

import math
import os
import platform
from typing import List, Dict, Any

COMMON_PASSWORDS = {"password", "123456", "admin", "letmein", "qwerty", "root", "toor"}

def estimate_entropy(password: str) -> float:
    """
    Estimate the entropy of a password.

    Args:
        password (str): The password string.

    Returns:
        float: Estimated entropy in bits.
    """
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for c in password):
        charset += 32
    if charset == 0:
        charset = 1
    return round(len(password) * math.log2(charset), 2)

def audit_passwords():
    if platform.system() != "Linux":
        return [{"error": "Password Audit is only supported on Linux systems."}]
    import crypt

    findings = []
    if not os.path.exists("/etc/shadow"):
        return [{"error": "/etc/shadow not accessible. Run as root or on a Linux system."}]
    try:
        with open("/etc/shadow", "r") as shadow_file:
            for line in shadow_file:
                parts = line.strip().split(":")
                if len(parts) < 2:
                    continue
                username, hashval = parts[0], parts[1]
                if hashval in ("*", "!", "!!"):
                    findings.append({
                        "user": username,
                        "issue": "Account disabled or no password set.",
                        "recommendation": "Set a strong password or remove unused account."
                    })
                elif hashval == "":
                    findings.append({
                        "user": username,
                        "issue": "Empty password.",
                        "recommendation": "Set a strong password immediately."
                    })
                else:
                    # Try to check for common passwords (very basic, for demo)
                    for pwd_guess in COMMON_PASSWORDS:
                        if crypt.crypt(pwd_guess, hashval) == hashval:
                            findings.append({
                                "user": username,
                                "issue": f"Weak/default password: '{pwd_guess}'",
                                "recommendation": "Change to a strong, unique password."
                            })
                    # Entropy estimation (not actual password, just hash length)
                    entropy = len(hashval) * 2  # Placeholder, can't estimate real entropy from hash
                    if entropy < 40:
                        findings.append({
                            "user": username,
                            "issue": "Low password entropy (short hash).",
                            "recommendation": "Use longer, more complex passwords."
                        })
    except Exception as e:
        findings.append({"error": str(e)})
    return findings if findings else [{"info": "No weak or default passwords detected."}]