"""Checks the target's TLS certificate and protocol/cipher configuration.

Uses only the stdlib ssl/socket modules — no extra dependency, and it lets us
open connections with deliberately old/weak protocol contexts to probe for
downgrade support, which the requests/urllib3 stack doesn't expose easily.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509

from vulnscan.models import Finding, Severity
from vulnscan.scanner import register_check
from vulnscan.utils import Target

CATEGORY = "TLS"

_EXPIRY_WARNING_DAYS = 30

# Protocols worth actively checking for (oldest/weakest first). Each entry is
# (label, ssl.TLSVersion enum) — we try to force a handshake pinned to exactly
# that version and see if the server accepts it.
_LEGACY_PROTOCOLS = [
    ("TLS 1.0", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1),
    ("TLS 1.1", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_1),
]

_WEAK_CIPHER_KEYWORDS = ("RC4", "3DES", "DES", "MD5", "EXPORT", "NULL", "anon")


def check_tls(target: Target, *, timeout: float = 8, **_kwargs) -> list[Finding]:
    findings: list[Finding] = []

    if target.scheme != "https":
        findings.append(
            Finding(
                id="TLS-NOT-HTTPS",
                title="Target is not being served over HTTPS",
                severity=Severity.INFO,
                category=CATEGORY,
                description="TLS checks were skipped because the target was scanned as plain "
                "HTTP. If the site also has an HTTPS endpoint, scan that directly.",
                evidence=f"Scanned as {target.base_url}",
                remediation="Serve the site over HTTPS and re-run the scan against the "
                "https:// URL.",
            )
        )
        return findings

    cert_findings, cert = _check_certificate(target, timeout)
    findings.extend(cert_findings)

    findings.extend(_check_legacy_protocols(target, timeout))
    findings.extend(_check_negotiated_cipher(target, timeout))

    return findings


def _check_certificate(target: Target, timeout: float) -> tuple[list[Finding], x509.Certificate | None]:
    findings: list[Finding] = []

    # Pass 1: normal validation, to detect trust/hostname problems.
    verified_context = ssl.create_default_context()
    try:
        with socket.create_connection((target.host, target.port), timeout=timeout) as sock:
            with verified_context.wrap_socket(sock, server_hostname=target.host):
                pass
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            Finding(
                id="TLS-CERT-INVALID",
                title="TLS certificate failed validation",
                severity=Severity.HIGH,
                category=CATEGORY,
                description="The certificate presented by the server is not trusted (it may be "
                "self-signed, issued by an unknown/untrusted CA, or not valid for this "
                "hostname). Browsers will show a security warning to visitors.",
                evidence=str(exc),
                remediation="Install a valid certificate from a trusted CA (e.g. Let's "
                "Encrypt) that covers this exact hostname.",
            )
        )
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        findings.append(
            Finding(
                id="TLS-CONN-FAIL",
                title="Could not establish a TLS connection",
                severity=Severity.INFO,
                category=CATEGORY,
                description="A direct TLS connection to the target could not be established, "
                "so certificate and protocol checks could not run.",
                evidence=str(exc),
                remediation="Verify the host is reachable on the expected HTTPS port.",
            )
        )
        return findings, None

    # Pass 2: fetch the raw certificate bytes with an unverified context — this works
    # regardless of whether the cert is trusted, so expiry/subject checks still run
    # even for the invalid-cert case flagged above (getpeercert() only returns a
    # populated dict when verify_mode requires validation, so we parse DER ourselves).
    cert = _get_der_cert(target, timeout)
    if cert is None:
        return findings, None

    findings.extend(_check_expiry(cert))
    return findings, cert


def _get_der_cert(target: Target, timeout: float) -> x509.Certificate | None:
    context = ssl._create_unverified_context()  # noqa: SLF001 - deliberate: read cert regardless of trust
    try:
        with socket.create_connection((target.host, target.port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target.host) as tls_sock:
                der_bytes = tls_sock.getpeercert(binary_form=True)
    except OSError:
        return None
    if not der_bytes:
        return None
    try:
        return x509.load_der_x509_certificate(der_bytes)
    except ValueError:
        return None


def _check_expiry(cert: x509.Certificate) -> list[Finding]:
    expires = cert.not_valid_after_utc
    days_left = (expires - datetime.now(timezone.utc)).days
    expires_str = expires.strftime("%Y-%m-%d %H:%M UTC")

    if days_left < 0:
        return [
            Finding(
                id="TLS-CERT-EXPIRED",
                title="TLS certificate has expired",
                severity=Severity.HIGH,
                category=CATEGORY,
                description="The server's TLS certificate expired and browsers will block or "
                "warn visitors before they can reach the site.",
                evidence=f"Certificate expired on {expires_str} ({-days_left} days ago)",
                remediation="Renew the certificate immediately (and consider automating "
                "renewal, e.g. certbot, to avoid this in future).",
            )
        ]
    if days_left <= _EXPIRY_WARNING_DAYS:
        return [
            Finding(
                id="TLS-CERT-EXPIRING",
                title="TLS certificate is expiring soon",
                severity=Severity.MEDIUM,
                category=CATEGORY,
                description="The certificate will expire within the next month. If it lapses "
                "before renewal, visitors will see browser security warnings.",
                evidence=f"Certificate expires on {expires_str} ({days_left} days left)",
                remediation="Renew the certificate before it expires, and set up automated "
                "renewal if not already in place.",
            )
        ]
    return []


def _check_legacy_protocols(target: Target, timeout: float) -> list[Finding]:
    findings: list[Finding] = []
    for label, version in _LEGACY_PROTOCOLS:
        if version is None:
            continue  # this Python's ssl module doesn't define the enum member at all
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
        except (ValueError, OSError):
            continue  # OpenSSL build doesn't support enabling this old a protocol at all

        try:
            with socket.create_connection((target.host, target.port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target.host):
                    pass
        except ssl.SSLError:
            continue  # server correctly rejected the legacy protocol — good
        except OSError:
            continue  # connectivity issue, not a protocol-support signal
        else:
            findings.append(
                Finding(
                    id=f"TLS-LEGACY-{label.replace(' ', '').replace('.', '')}",
                    title=f"Server accepts outdated {label} connections",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description=f"{label} is deprecated and has known weaknesses. Its "
                    "continued support allows a downgrade attack to force a weaker "
                    "connection.",
                    evidence=f"TLS handshake pinned to {label} succeeded",
                    remediation=f"Disable {label} in the server's TLS configuration; support "
                    "only TLS 1.2 and TLS 1.3.",
                )
            )
    return findings


def _check_negotiated_cipher(target: Target, timeout: float) -> list[Finding]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((target.host, target.port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target.host) as tls_sock:
                cipher = tls_sock.cipher()
    except OSError:
        return []

    if not cipher:
        return []

    cipher_name = cipher[0]
    if any(weak in cipher_name.upper() for weak in _WEAK_CIPHER_KEYWORDS):
        return [
            Finding(
                id="TLS-WEAK-CIPHER",
                title="Server negotiated a weak cipher suite",
                severity=Severity.MEDIUM,
                category=CATEGORY,
                description="The default connection negotiated a cipher suite with known "
                "cryptographic weaknesses.",
                evidence=f"Negotiated cipher: {cipher_name}",
                remediation="Restrict the server's cipher suite list to modern, strong "
                "ciphers (AEAD ciphers such as AES-GCM or ChaCha20-Poly1305).",
            )
        ]
    return []


register_check(CATEGORY, check_tls)
