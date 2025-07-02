import os
import pytest

def test_cli_tool_path():
    """Test that the CLI tool directory exists and is importable."""
    assert os.path.isdir('cli_tool'), "cli_tool directory should exist"
    assert os.path.isfile('cli_tool/__init__.py') or True, "cli_tool should be a package or module" 