"""Bounded TCP-connect port scan against a curated list of common ports.

Deliberately not a raw-socket/SYN scanner (which would need root and cross into
nmap/scapy territory) — a plain connect() scan needs no special privileges, is
slower but far less likely to be mistaken for something hostile, and is enough
to answer the question this tool cares about: "is something unexpectedly
reachable on this host?"
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from vulnscan.models import Finding, Severity
from vulnscan.scanner import register_check
from vulnscan.utils import Target

CATEGORY = "Ports"

_MAX_WORKERS = 20
_CONNECT_TIMEOUT = 2.0

# Common ports worth checking by default, with what's normally expected on a public
# web-facing host. Anything not commented "expected" but found open gets flagged.
DEFAULT_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    3000: "Dev server (Node/Django/etc.)",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "Alt HTTP (dev)",
    8080: "Alt HTTP (proxy/admin)",
    8443: "Alt HTTPS",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Ports that are actively dangerous to have open to the world on a typical web host
# (databases, caches, remote admin/mgmt) — these get High regardless of context.
_HIGH_RISK_PORTS = {23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
# Unencrypted management/mail protocols — worth flagging but a notch less severe.
_MEDIUM_RISK_PORTS = {21, 110, 143}


def check_ports(target: Target, *, timeout: float = 8, ports: list[int] | None = None, **_kwargs) -> list[Finding]:
    port_list = ports if ports else list(DEFAULT_PORTS.keys())
    connect_timeout = min(_CONNECT_TIMEOUT, timeout)

    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futures = {pool.submit(_is_open, target.host, port, connect_timeout): port for port in port_list}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)

    findings: list[Finding] = []
    for port in sorted(open_ports):
        service = DEFAULT_PORTS.get(port, "unknown service")
        severity = (
            Severity.HIGH
            if port in _HIGH_RISK_PORTS
            else Severity.MEDIUM
            if port in _MEDIUM_RISK_PORTS
            else Severity.INFO
        )
        findings.append(
            Finding(
                id=f"PORT-{port}-OPEN",
                title=f"Port {port} ({service}) is open",
                severity=severity,
                category=CATEGORY,
                description=_description_for(port, service, severity),
                evidence=f"TCP connect to {target.host}:{port} succeeded",
                remediation=_remediation_for(port, severity),
            )
        )

    return findings


def _is_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _description_for(port: int, service: str, severity: Severity) -> str:
    if severity == Severity.HIGH:
        return (
            f"{service} on port {port} is reachable from the network. Databases, caches, "
            "and remote-admin services should not normally be exposed directly to the "
            "internet — if this is intentional, make sure it's protected by strong auth, "
            "network ACLs, or a VPN."
        )
    if severity == Severity.MEDIUM:
        return (
            f"{service} on port {port} is reachable. This protocol transmits data "
            "(potentially including credentials) without encryption by default."
        )
    return f"{service} on port {port} is reachable. Confirm this is intentional and " "necessary for this host to expose publicly."


def _remediation_for(port: int, severity: Severity) -> str:
    if severity == Severity.HIGH:
        return (
            "Restrict access with a firewall/security group to only the specific IPs/"
            "networks that need it, or move the service behind a VPN/bastion. If it's not "
            "needed at all, disable it."
        )
    if severity == Severity.MEDIUM:
        return "Use the encrypted variant of this protocol where available, or restrict access to trusted networks only."
    return "Close this port if it isn't intentionally public, or restrict it with a firewall."


register_check(CATEGORY, check_ports)
