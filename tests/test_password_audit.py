from cli_tool.password_audit import audit_passwords
import platform
import pytest

def test_audit_passwords_runs():
    """Test that audit_passwords returns a list and handles unsupported OS gracefully."""
    findings = audit_passwords()
    assert isinstance(findings, list), "Should always return a list"
    if platform.system() == "Windows":
        assert findings, "Should return at least one item on Windows (error)"
        assert "error" in findings[0], "Should return error on Windows platform"