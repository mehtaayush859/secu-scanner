import pytest
from cli_tool.ports import parse_nmap_output

@pytest.mark.parametrize("sample,expected", [
    ("""
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
""", [(22, "ssh", "OpenSSH"), (80, "http", "Apache")]),
    ("""
PORT     STATE SERVICE VERSION
443/tcp  open  https   nginx 1.18.0
""", [(443, "https", "nginx")]),
    ("""
PORT     STATE SERVICE VERSION
""", []),
])
def test_parse_nmap_output_basic(sample, expected):
    result = parse_nmap_output(sample)
    for idx, (port, service, version_keyword) in enumerate(expected):
        assert result[idx]["port"] == port
        assert result[idx]["service"] == service
        assert version_keyword in result[idx]["version"]
    assert len(result) == len(expected)

# Optionally, test risk scoring if available
try:
    from cli_tool.ports import risk_score_ports
    def test_risk_score_ports():
        sample = [
            {"port": 22, "service": "ssh", "version": "OpenSSH"},
            {"port": 23, "service": "telnet", "version": "BusyBox"},
        ]
        score = risk_score_ports(sample)
        assert isinstance(score, dict)
        assert "total_risk" in score
except ImportError:
    pass