"""Checks for common web server misconfigurations: exposed sensitive files,
directory listing, and permissive CORS.
"""

from __future__ import annotations

import uuid

import requests

from vulnscan.models import Finding, Severity
from vulnscan.scanner import register_check
from vulnscan.utils import Target, safe_get

CATEGORY = "Misconfig"

# path -> (severity, why it matters)
_SENSITIVE_PATHS: dict[str, tuple[Severity, str]] = {
    "/.git/HEAD": (Severity.HIGH, "Exposes the git repository, potentially including full source history and secrets."),
    "/.git/config": (Severity.HIGH, "Exposes the git repository configuration, potentially including credentials/remote URLs."),
    "/.env": (Severity.HIGH, "Environment files commonly contain database credentials, API keys, and secrets."),
    "/.env.local": (Severity.HIGH, "Environment files commonly contain database credentials, API keys, and secrets."),
    "/.aws/credentials": (Severity.HIGH, "Exposes AWS access keys."),
    "/id_rsa": (Severity.HIGH, "Exposes a private SSH key."),
    "/wp-config.php.bak": (Severity.HIGH, "Backup config files often contain database credentials in plaintext."),
    "/config.php.bak": (Severity.HIGH, "Backup config files often contain database credentials in plaintext."),
    "/.htpasswd": (Severity.MEDIUM, "Exposes password hashes used for HTTP basic auth."),
    "/docker-compose.yml": (Severity.MEDIUM, "May expose internal service topology, ports, and environment variables."),
    "/backup.zip": (Severity.MEDIUM, "Backup archives may contain source code, data, or credentials."),
    "/.DS_Store": (Severity.LOW, "Can leak local file/directory names from the developer's machine."),
    "/server-status": (Severity.MEDIUM, "Apache mod_status can expose internal request details and client IPs."),
    "/phpinfo.php": (Severity.MEDIUM, "Exposes detailed server/PHP configuration useful for further attacks."),
}

_DIRECTORY_CANDIDATES = ["/images/", "/uploads/", "/assets/", "/backup/", "/files/"]
_LISTING_MARKERS = ("Index of /", "<title>Directory listing for")

_CORS_TEST_ORIGIN = f"https://vulnscan-cors-test-{uuid.uuid4().hex[:8]}.invalid"


def check_misconfig(target: Target, *, timeout: float = 8, **_kwargs) -> list[Finding]:
    findings: list[Finding] = []

    baseline = _get_baseline_404(target, timeout)
    if baseline is None:
        findings.append(
            Finding(
                id="MISC-CONN-FAIL",
                title="Could not connect to target for misconfiguration checks",
                severity=Severity.INFO,
                category=CATEGORY,
                description="The target did not respond, so exposed-file, directory-listing, "
                "and CORS checks could not run.",
                evidence=f"GET {target.base_url} — no response",
                remediation="Verify the host is reachable, then re-run the scan.",
            )
        )
        return findings

    findings.extend(_check_sensitive_paths(target, timeout, baseline))
    findings.extend(_check_directory_listing(target, timeout))
    findings.extend(_check_cors(target, timeout))
    return findings


def _get_baseline_404(target: Target, timeout: float) -> tuple[int, int] | None:
    """Fetch a definitely-nonexistent path so we can tell a real 200 apart from a
    soft-404 (many sites return HTTP 200 with a friendly "not found" page for any
    path), by comparing status code and response length against this baseline.
    """
    probe_path = f"/vulnscan-nonexistent-{uuid.uuid4().hex}"
    resp = _safe_get(target, probe_path, timeout)
    if resp is None:
        return None
    return resp.status_code, len(resp.content)


def _check_sensitive_paths(target: Target, timeout: float, baseline: tuple[int, int]) -> list[Finding]:
    baseline_status, baseline_len = baseline
    findings: list[Finding] = []

    for path, (severity, why) in _SENSITIVE_PATHS.items():
        resp = _safe_get(target, path, timeout)
        if resp is None or resp.status_code != 200:
            continue

        # Soft-404 guard: if this "200" looks just like the baseline nonexistent-path
        # response (same status, similar length), the server likely serves a catch-all
        # page rather than genuinely exposing the file — skip it.
        if baseline_status == 200 and abs(len(resp.content) - baseline_len) < 32:
            continue

        findings.append(
            Finding(
                id=f"MISC-EXPOSED-{path.strip('/').replace('/', '-').replace('.', '')}",
                title=f"Sensitive path exposed: {path}",
                severity=severity,
                category=CATEGORY,
                description=why,
                evidence=f"GET {path} returned HTTP {resp.status_code} ({len(resp.content)} bytes)",
                remediation=f"Remove {path} from the publicly served directory, or block "
                "access to it at the web server/proxy level.",
            )
        )
    return findings


def _check_directory_listing(target: Target, timeout: float) -> list[Finding]:
    findings: list[Finding] = []
    for path in _DIRECTORY_CANDIDATES:
        resp = _safe_get(target, path, timeout)
        if resp is None or resp.status_code != 200:
            continue
        body = resp.text[:2000]
        if any(marker in body for marker in _LISTING_MARKERS):
            findings.append(
                Finding(
                    id=f"MISC-DIRLIST-{path.strip('/')}",
                    title=f"Directory listing enabled at {path}",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="The web server is returning an auto-generated file listing "
                    "for this directory instead of a 403/404, which can reveal file names "
                    "and structure not meant to be browsed directly.",
                    evidence=f"GET {path} returned an autoindex-style listing",
                    remediation="Disable directory autoindexing in the web server config "
                    "(e.g. 'Options -Indexes' in Apache, 'autoindex off;' in nginx).",
                )
            )
    return findings


def _check_cors(target: Target, timeout: float) -> list[Finding]:
    resp = _safe_get(target, "/", timeout, headers={"Origin": _CORS_TEST_ORIGIN})
    if resp is None:
        return []

    acao = resp.headers.get("Access-Control-Allow-Origin")
    if not acao:
        return []

    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

    if acao == _CORS_TEST_ORIGIN:
        severity = Severity.HIGH if acac else Severity.MEDIUM
        credential_note = " together with 'Access-Control-Allow-Credentials: true'" if acac else ""
        return [
            Finding(
                id="MISC-CORS-REFLECT",
                title="CORS policy reflects arbitrary Origin" + (" with credentials allowed" if acac else ""),
                severity=severity,
                category=CATEGORY,
                description="The server echoes back whatever Origin header the client sends "
                "as Access-Control-Allow-Origin" + credential_note + ". This lets any website "
                "make cross-origin requests to this site" + (" using the victim's cookies/session" if acac else "") + ".",
                evidence=f"Sent 'Origin: {_CORS_TEST_ORIGIN}', got back "
                f"'Access-Control-Allow-Origin: {acao}'"
                + (", 'Access-Control-Allow-Credentials: true'" if acac else ""),
                remediation="Validate the Origin header against an explicit allow-list on the "
                "server side instead of reflecting any value, especially for any endpoint "
                "that relies on cookies/session auth.",
            )
        ]

    if acao == "*":
        return [
            Finding(
                id="MISC-CORS-WILDCARD",
                title="CORS allows any origin (Access-Control-Allow-Origin: *)",
                severity=Severity.INFO,
                category=CATEGORY,
                description="A wildcard CORS policy is fine for a fully public, unauthenticated "
                "API, but is worth double-checking if any endpoint under this origin relies "
                "on cookies or session state.",
                evidence="Access-Control-Allow-Origin: *",
                remediation="Confirm no cookie/session-authenticated endpoints are served from "
                "an origin with a wildcard CORS policy; scope it down if they are.",
            )
        ]

    return []


def _safe_get(target: Target, path: str, timeout: float, **kwargs) -> requests.Response | None:
    url = target.base_url.rstrip("/") + path
    try:
        return safe_get(url, timeout=timeout, allow_redirects=False, **kwargs)
    except requests.exceptions.SSLError:
        return None


register_check(CATEGORY, check_misconfig)
