import pytest
from cli_tool.network_discovery import discover_network_hosts, scan_network_services, generate_network_map, check_network_security

def test_discover_network_hosts_invalid():
    result = discover_network_hosts('invalid_network', scan_type='ping')
    assert isinstance(result, list)
    assert 'error' in result[0]

def test_discover_network_hosts_ping(monkeypatch):
    # Patch ping_sweep to avoid real network calls
    monkeypatch.setattr('cli_tool.network_discovery.ping_sweep', lambda net: [{"ip": "127.0.0.1", "status": "up", "method": "ping"}])
    result = discover_network_hosts('127.0.0.0/30', scan_type='ping')
    assert isinstance(result, list)
    assert result[0]['status'] == 'up'

def test_scan_network_services(monkeypatch):
    # Patch subprocess.run to avoid real nmap call
    monkeypatch.setattr('subprocess.run', lambda *a, **k: type('obj', (object,), {"stdout": "Nmap scan report for 127.0.0.1\n22/tcp open ssh OpenSSH\n", "returncode": 0})())
    result = scan_network_services('127.0.0.1', ports=[22])
    assert isinstance(result, list)
    assert result[0]['port'] == 22
    assert result[0]['service'] == 'ssh'

def test_generate_network_map(monkeypatch):
    monkeypatch.setattr('cli_tool.network_discovery.discover_network_hosts', lambda n, s='nmap': [{"ip": "127.0.0.1", "status": "up", "method": "nmap"}])
    monkeypatch.setattr('cli_tool.network_discovery.scan_network_services', lambda ip, ports=None: [{"host": "127.0.0.1", "port": 22, "service": "ssh", "protocol": "tcp", "state": "open", "version": "OpenSSH"}])
    result = generate_network_map('127.0.0.1/32')
    assert isinstance(result, dict)
    assert 'hosts' in result
    assert 'services' in result

def test_check_network_security():
    network_map = {
        "services": [
            {"host": "127.0.0.1", "port": 23, "service": "telnet"},
            {"host": "127.0.0.1", "port": 80, "service": "http"},
        ]
    }
    result = check_network_security(network_map)
    assert isinstance(result, dict)
    assert result['risk_level'] in ("critical", "high", "medium", "low", "minimal")
    assert isinstance(result['security_issues'], list) 