from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from vulnscan.checks.tls import _check_expiry


def _self_signed_cert(*, not_valid_after: datetime, not_valid_before: datetime | None = None) -> x509.Certificate:
    """Build a real (small, fast) self-signed certificate in memory with a chosen
    expiry, so _check_expiry can be tested without any network I/O.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.invalid")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before or datetime.now(timezone.utc) - timedelta(days=365))
        .not_valid_after(not_valid_after)
    )
    return builder.sign(key, hashes.SHA256())


def test_expired_certificate_is_high_severity():
    cert = _self_signed_cert(not_valid_after=datetime.now(timezone.utc) - timedelta(days=5))
    findings = _check_expiry(cert)
    assert len(findings) == 1
    assert findings[0].id == "TLS-CERT-EXPIRED"
    assert findings[0].severity.value == "High"


def test_certificate_expiring_soon_is_medium_severity():
    cert = _self_signed_cert(not_valid_after=datetime.now(timezone.utc) + timedelta(days=10))
    findings = _check_expiry(cert)
    assert len(findings) == 1
    assert findings[0].id == "TLS-CERT-EXPIRING"
    assert findings[0].severity.value == "Medium"


def test_certificate_valid_for_a_long_time_has_no_finding():
    cert = _self_signed_cert(not_valid_after=datetime.now(timezone.utc) + timedelta(days=200))
    findings = _check_expiry(cert)
    assert findings == []


def test_certificate_expiring_at_the_boundary_is_flagged():
    cert = _self_signed_cert(not_valid_after=datetime.now(timezone.utc) + timedelta(days=29))
    findings = _check_expiry(cert)
    assert len(findings) == 1
    assert findings[0].id == "TLS-CERT-EXPIRING"
