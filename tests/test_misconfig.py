from unittest.mock import MagicMock, patch

from requests.structures import CaseInsensitiveDict

from vulnscan.checks.misconfig import _CORS_TEST_ORIGIN, check_misconfig
from vulnscan.utils import parse_target

BASE = "https://example.com"


def _resp(status: int, body: bytes = b"", headers: dict | None = None):
    resp = MagicMock()
    resp.status_code = status
    resp.content = body
    resp.text = body.decode(errors="ignore")
    resp.headers = CaseInsensitiveDict(headers or {})
    return resp


def _router(by_path: dict, default):
    """Build a safe_get side_effect that dispatches on the request path (the part
    of the URL after the base_url), falling back to `default` for anything else —
    including the random baseline-404 probe path, which is never in by_path.
    """

    def _side_effect(url, **kwargs):
        path = url[len(BASE) :]
        return by_path.get(path, default)

    return _side_effect


def test_exposed_sensitive_file_is_flagged():
    router = _router(
        {"/.env": _resp(200, b"DB_PASSWORD=hunter2\nAPI_KEY=xyz")},
        default=_resp(404, b"not found padding padding padding padding padding padding"),
    )
    with patch("vulnscan.checks.misconfig.safe_get", side_effect=router):
        findings = check_misconfig(parse_target(BASE), timeout=5)

    ids = {f.id for f in findings}
    assert "MISC-EXPOSED-env" in ids
    exposed = next(f for f in findings if f.id == "MISC-EXPOSED-env")
    assert exposed.severity.value == "High"


def test_soft_404_catch_all_does_not_false_positive():
    # Every path, including the random baseline probe, returns the same
    # catch-all 200 page — nothing should be flagged as "exposed".
    catch_all = _resp(200, b"<html>Welcome to our SPA! Renders for any route.</html>")
    with patch("vulnscan.checks.misconfig.safe_get", return_value=catch_all):
        findings = check_misconfig(parse_target(BASE), timeout=5)

    exposed = [f for f in findings if f.id.startswith("MISC-EXPOSED-")]
    assert exposed == []


def test_directory_listing_detected():
    router = _router(
        {"/images/": _resp(200, b"<html><title>Index of /images/</title>Index of /images/</html>")},
        default=_resp(404, b"not found"),
    )
    with patch("vulnscan.checks.misconfig.safe_get", side_effect=router):
        findings = check_misconfig(parse_target(BASE), timeout=5)

    assert any(f.id == "MISC-DIRLIST-images" for f in findings)


def test_no_directory_listing_when_forbidden():
    router = _router({}, default=_resp(403, b"forbidden"))
    with patch("vulnscan.checks.misconfig.safe_get", side_effect=router):
        findings = check_misconfig(parse_target(BASE), timeout=5)

    assert not [f for f in findings if f.id.startswith("MISC-DIRLIST-")]


def test_cors_reflects_origin_with_credentials_is_high():
    router = _router(
        {
            "/": _resp(
                200,
                b"home",
                headers={
                    "Access-Control-Allow-Origin": _CORS_TEST_ORIGIN,
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        },
        default=_resp(404, b"not found"),
    )
    with patch("vulnscan.checks.misconfig.safe_get", side_effect=router):
        findings = check_misconfig(parse_target(BASE), timeout=5)

    cors = next(f for f in findings if f.id == "MISC-CORS-REFLECT")
    assert cors.severity.value == "High"


def test_cors_wildcard_is_info():
    router = _router(
        {"/": _resp(200, b"home", headers={"Access-Control-Allow-Origin": "*"})},
        default=_resp(404, b"not found"),
    )
    with patch("vulnscan.checks.misconfig.safe_get", side_effect=router):
        findings = check_misconfig(parse_target(BASE), timeout=5)

    cors = next(f for f in findings if f.id == "MISC-CORS-WILDCARD")
    assert cors.severity.value == "Info"


def test_no_cors_header_no_cors_finding():
    router = _router({"/": _resp(200, b"home")}, default=_resp(404, b"not found"))
    with patch("vulnscan.checks.misconfig.safe_get", side_effect=router):
        findings = check_misconfig(parse_target(BASE), timeout=5)

    assert not [f for f in findings if f.id.startswith("MISC-CORS-")]


def test_no_response_at_all_yields_connectivity_finding():
    with patch("vulnscan.checks.misconfig.safe_get", return_value=None):
        findings = check_misconfig(parse_target(BASE), timeout=5)

    assert len(findings) == 1
    assert findings[0].id == "MISC-CONN-FAIL"
