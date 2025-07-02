from cli_tool.cve_check import get_installed_software
import pytest

def test_get_installed_software_runs():
    """Test that get_installed_software returns a list of dicts with required keys."""
    sw = get_installed_software()
    assert isinstance(sw, list), "Should return a list"
    if sw:
        assert isinstance(sw[0], dict), "Each item should be a dict"
        assert "name" in sw[0], "Missing 'name' key in software dict"
        assert "version" in sw[0], "Missing 'version' key in software dict"