from cli_tool.config_audit import audit_config
import pytest

def test_audit_config_runs():
    """Test that audit_config returns expected structure for supported and unsupported platforms."""
    result = audit_config()
    assert isinstance(result, (dict, list)), "Result should be dict or list"
    if isinstance(result, dict):
        assert "ssh_config" in result, "Missing 'ssh_config' in result"
        assert isinstance(result["ssh_config"], list), "'ssh_config' should be a list"
    else:
        # Non-Linux platform or error
        assert len(result) > 0, "Result list should not be empty on error"
        assert "error" in result[0], "Error key should be present in result list item"