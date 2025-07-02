from cli_tool.web_scan import scan_web_headers
import pytest

def test_scan_web_headers_error():
    """Test that scan_web_headers returns an error for an unreachable URL."""
    result = scan_web_headers("http://localhost:65535")
    assert isinstance(result, dict), "Result should be a dict"
    # Check for error in http_analysis section (actual structure)
    assert "http_analysis" in result, "Should have http_analysis section"
    assert "error" in result["http_analysis"], "Should return error for unreachable URL"

# Example Usage:
# pytest tests/test_web_scan.py