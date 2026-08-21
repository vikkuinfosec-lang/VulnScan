from contextlib import contextmanager
from unittest.mock import patch

from vulnscan.checks.ports import check_ports
from vulnscan.utils import parse_target


def _fake_create_connection(open_ports: set[int]):
    @contextmanager
    def _connect(address, timeout):
        host, port = address
        if port not in open_ports:
            raise OSError("connection refused")
        yield object()

    return _connect


def test_open_high_risk_port_is_flagged_high():
    with patch("vulnscan.checks.ports.socket.create_connection", side_effect=_fake_create_connection({6379})):
        findings = check_ports(parse_target("example.com"), timeout=5, ports=[22, 80, 6379])

    assert len(findings) == 1
    assert findings[0].id == "PORT-6379-OPEN"
    assert findings[0].severity.value == "High"


def test_no_open_ports_yields_no_findings():
    with patch("vulnscan.checks.ports.socket.create_connection", side_effect=_fake_create_connection(set())):
        findings = check_ports(parse_target("example.com"), timeout=5, ports=[22, 80, 443])

    assert findings == []


def test_expected_web_port_open_is_info_severity():
    with patch("vulnscan.checks.ports.socket.create_connection", side_effect=_fake_create_connection({443})):
        findings = check_ports(parse_target("example.com"), timeout=5, ports=[443])

    assert len(findings) == 1
    assert findings[0].severity.value == "Info"


def test_unencrypted_mail_port_open_is_medium_severity():
    with patch("vulnscan.checks.ports.socket.create_connection", side_effect=_fake_create_connection({21})):
        findings = check_ports(parse_target("example.com"), timeout=5, ports=[21])

    assert len(findings) == 1
    assert findings[0].severity.value == "Medium"


def test_custom_port_list_is_respected():
    with patch("vulnscan.checks.ports.socket.create_connection", side_effect=_fake_create_connection({9999})):
        findings = check_ports(parse_target("example.com"), timeout=5, ports=[9999])

    assert len(findings) == 1
    assert findings[0].id == "PORT-9999-OPEN"
    assert "unknown service" in findings[0].title
