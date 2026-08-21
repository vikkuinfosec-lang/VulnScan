from unittest.mock import MagicMock, patch

from requests.cookies import RequestsCookieJar
from requests.structures import CaseInsensitiveDict

from vulnscan.checks.headers import check_headers
from vulnscan.utils import parse_target


def _make_response(headers: dict, *, cookies: RequestsCookieJar | None = None, url: str = "https://example.com/"):
    resp = MagicMock()
    resp.headers = CaseInsensitiveDict(headers)
    resp.cookies = cookies if cookies is not None else RequestsCookieJar()
    resp.url = url
    return resp


def _cookie_jar(**flags) -> RequestsCookieJar:
    """Build a single cookie with the given http.cookiejar-style rest flags,
    e.g. _cookie_jar(Secure=None, HttpOnly=None, SameSite='Lax').
    """
    import http.cookiejar as cookiejar

    jar = RequestsCookieJar()
    cookie = cookiejar.Cookie(
        version=0,
        name="session",
        value="abc123",
        port=None,
        port_specified=False,
        domain="example.com",
        domain_specified=True,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure="Secure" in flags,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest=flags,
    )
    jar.set_cookie(cookie)
    return jar


FULL_GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


def test_all_headers_missing_flags_everything():
    resp = _make_response({})
    with patch("vulnscan.checks.headers.safe_get", return_value=resp) as mock_get:
        findings = check_headers(parse_target("https://example.com"), timeout=5)

    ids = {f.id for f in findings}
    assert {"HDR-HSTS", "HDR-CSP", "HDR-XFO", "HDR-XCTO", "HDR-REFPOL", "HDR-PERMPOL"} <= ids
    assert mock_get.called


def test_fully_configured_headers_produce_no_findings_for_those_checks():
    resp = _make_response(FULL_GOOD_HEADERS)
    with patch("vulnscan.checks.headers.safe_get", return_value=resp):
        findings = check_headers(parse_target("https://example.com"), timeout=5)

    ids = {f.id for f in findings}
    assert not ({"HDR-HSTS", "HDR-CSP", "HDR-XFO", "HDR-XCTO", "HDR-REFPOL", "HDR-PERMPOL"} & ids)


def test_server_and_x_powered_by_disclosure_flagged():
    headers = dict(FULL_GOOD_HEADERS, Server="Apache/2.4.41 (Ubuntu)", **{"X-Powered-By": "PHP/7.2.3"})
    resp = _make_response(headers)
    with patch("vulnscan.checks.headers.safe_get", return_value=resp):
        findings = check_headers(parse_target("https://example.com"), timeout=5)

    ids = {f.id for f in findings}
    assert "HDR-DISC-SERVER" in ids
    assert "HDR-DISC-XPOWEREDBY" in ids


def test_cookie_missing_all_flags_is_flagged():
    jar = _cookie_jar()  # no Secure, no HttpOnly, no SameSite
    resp = _make_response(FULL_GOOD_HEADERS, cookies=jar)
    with patch("vulnscan.checks.headers.safe_get", return_value=resp):
        findings = check_headers(parse_target("https://example.com"), timeout=5)

    cookie_findings = [f for f in findings if f.id.startswith("HDR-COOKIE-")]
    assert len(cookie_findings) == 1
    assert "Secure" in cookie_findings[0].evidence
    assert "HttpOnly" in cookie_findings[0].evidence
    assert "SameSite" in cookie_findings[0].evidence


def test_cookie_with_all_flags_not_flagged():
    jar = _cookie_jar(Secure=None, HttpOnly=None, SameSite="Lax")
    resp = _make_response(FULL_GOOD_HEADERS, cookies=jar)
    with patch("vulnscan.checks.headers.safe_get", return_value=resp):
        findings = check_headers(parse_target("https://example.com"), timeout=5)

    cookie_findings = [f for f in findings if f.id.startswith("HDR-COOKIE-")]
    assert cookie_findings == []


def test_csp_with_frame_ancestors_satisfies_clickjacking_check():
    headers = dict(FULL_GOOD_HEADERS)
    del headers["X-Frame-Options"]
    headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    resp = _make_response(headers)
    with patch("vulnscan.checks.headers.safe_get", return_value=resp):
        findings = check_headers(parse_target("https://example.com"), timeout=5)

    assert "HDR-XFO" not in {f.id for f in findings}


def test_no_response_yields_connectivity_info_finding():
    with patch("vulnscan.checks.headers.safe_get", return_value=None):
        findings = check_headers(parse_target("https://example.com"), timeout=5)

    assert len(findings) == 1
    assert findings[0].id == "HDR-CONN-FAIL"
