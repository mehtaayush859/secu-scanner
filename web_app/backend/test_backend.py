import pytest
import requests
import json

BASE_URL = "http://localhost:8000"

def test_server_running():
    resp = requests.get(f"{BASE_URL}/")
    assert resp.status_code == 200
    data = resp.json()
    assert "message" in data or "status" in data

def test_system_info():
    resp = requests.get(f"{BASE_URL}/system_info")
    assert resp.status_code == 200
    data = resp.json()
    assert "os" in data or "platform" in data

def test_scan_ports():
    scan_data = {
        "target": "127.0.0.1",
        "scan_type": "ports",
        "output": "json",
        "scan_profile": "default",
        "use_api": False,
        "timeout": 10
    }
    resp = requests.post(f"{BASE_URL}/scan", json=scan_data)
    assert resp.status_code == 200
    data = resp.json()
    assert "scan_id" in data
    assert "filename" in data
    assert "report" in data

def test_scan_invalid_type():
    scan_data = {
        "target": "127.0.0.1",
        "scan_type": "invalid_type",
        "output": "json"
    }
    resp = requests.post(f"{BASE_URL}/scan", json=scan_data)
    assert resp.status_code in (400, 422)

# Optionally, add more tests for history, download, etc. if endpoints exist 