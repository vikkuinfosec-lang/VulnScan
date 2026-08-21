"""Checks for missing/misconfigured HTTP security headers and cookie flags."""

from __future__ import annotations

import requests

from vulnscan.models import Finding, Severity
from vulnscan.scanner import register_check
from vulnscan.utils import Target, safe_get

CATEGORY = "Headers"

_OWASP_HEADERS_REF = "https://owasp.org/www-project-secure-headers/"


def check_headers(target: Target, *, timeout: float = 8, **_kwargs) -> list[Finding]:
    findings: list[Finding] = []

    try:
        resp = safe_get(target.base_url, timeout=timeout)
    except requests.exceptions.SSLError as exc:
        findings.append(
            Finding(
                id="HDR-TLS-FAIL",
                title="TLS handshake failed while fetching headers",
                severity=Severity.HIGH,
                category=CATEGORY,
                description="Could not establish a valid HTTPS connection to the target, so "
                "header checks could not run over HTTPS. This usually indicates a certificate "
                "problem (see the TLS section for details).",
                evidence=str(exc),
                remediation="Fix the underlying certificate/TLS issue reported in the TLS "
                "section of this report.",
            )
        )
        return findings

    if resp is None:
        findings.append(
            Finding(
                id="HDR-CONN-FAIL",
                title="Could not connect to target over HTTPS",
                severity=Severity.INFO,
                category=CATEGORY,
                description="The target did not respond to an HTTPS request within the "
                "configured timeout, so header checks could not be performed.",
                evidence=f"GET {target.base_url} — no response",
                remediation="Verify the host is reachable and serving HTTPS on the expected "
                "port, then re-run the scan.",
            )
        )
        return findings

    headers = resp.headers
    findings.extend(_check_hsts(headers, target))
    findings.extend(_check_csp_and_frame_options(headers))
    findings.extend(_check_content_type_options(headers))
    findings.extend(_check_referrer_policy(headers))
    findings.extend(_check_permissions_policy(headers))
    findings.extend(_check_server_disclosure(headers))
    findings.extend(_check_cookies(resp))
    findings.extend(_check_http_redirect(target, timeout))

    return findings


def _check_hsts(headers, target: Target) -> list[Finding]:
    hsts = headers.get("Strict-Transport-Security")
    if hsts:
        return []
    return [
        Finding(
            id="HDR-HSTS",
            title="Missing Strict-Transport-Security (HSTS) header",
            severity=Severity.HIGH,
            category=CATEGORY,
            description="Without HSTS, browsers will happily fall back to plain HTTP for this "
            "site, which lets an on-path attacker downgrade the connection and intercept or "
            "tamper with traffic (SSL-stripping).",
            evidence=f"No Strict-Transport-Security header on {target.base_url}",
            remediation="Add a response header such as "
            "'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' "
            "once you're confident every subdomain is served over HTTPS.",
            references=[_OWASP_HEADERS_REF, "https://hstspreload.org/"],
        )
    ]


def _check_csp_and_frame_options(headers) -> list[Finding]:
    findings: list[Finding] = []
    csp = headers.get("Content-Security-Policy")
    xfo = headers.get("X-Frame-Options")

    if not csp:
        findings.append(
            Finding(
                id="HDR-CSP",
                title="Missing Content-Security-Policy header",
                severity=Severity.MEDIUM,
                category=CATEGORY,
                description="Without a CSP, the browser has no server-defined restriction on "
                "which scripts/styles/frames can load, which widens the impact of any XSS "
                "vulnerability elsewhere on the site.",
                evidence="No Content-Security-Policy header present",
                remediation="Define a Content-Security-Policy appropriate to the site, starting "
                "restrictive (e.g. default-src 'self') and loosening only as needed.",
                references=[_OWASP_HEADERS_REF],
            )
        )

    has_frame_ancestors = bool(csp) and "frame-ancestors" in csp.lower()
    if not xfo and not has_frame_ancestors:
        findings.append(
            Finding(
                id="HDR-XFO",
                title="Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
                severity=Severity.MEDIUM,
                category=CATEGORY,
                description="Neither X-Frame-Options nor a CSP frame-ancestors directive is "
                "set, so the page can be embedded in an iframe on another site and used for a "
                "clickjacking attack.",
                evidence="No X-Frame-Options header and no CSP frame-ancestors directive",
                remediation="Add 'X-Frame-Options: DENY' (or SAMEORIGIN if framing by your own "
                "site is needed), or set 'frame-ancestors' in your CSP.",
                references=[_OWASP_HEADERS_REF],
            )
        )
    return findings


def _check_content_type_options(headers) -> list[Finding]:
    value = headers.get("X-Content-Type-Options", "")
    if value.lower() == "nosniff":
        return []
    return [
        Finding(
            id="HDR-XCTO",
            title="Missing X-Content-Type-Options header",
            severity=Severity.LOW,
            category=CATEGORY,
            description="Without 'nosniff', some browsers will try to guess (MIME-sniff) a "
            "response's content type, which can turn an upload/reflection endpoint into an "
            "XSS vector.",
            evidence=f"X-Content-Type-Options: {value or '(missing)'}",
            remediation="Add the response header 'X-Content-Type-Options: nosniff'.",
            references=[_OWASP_HEADERS_REF],
        )
    ]


def _check_referrer_policy(headers) -> list[Finding]:
    if headers.get("Referrer-Policy"):
        return []
    return [
        Finding(
            id="HDR-REFPOL",
            title="Missing Referrer-Policy header",
            severity=Severity.LOW,
            category=CATEGORY,
            description="Without a Referrer-Policy, the browser's default behavior may leak "
            "the full URL (including sensitive query parameters) to third parties in outbound "
            "links and resource requests.",
            evidence="No Referrer-Policy header present",
            remediation="Add a header such as 'Referrer-Policy: strict-origin-when-cross-origin'.",
            references=[_OWASP_HEADERS_REF],
        )
    ]


def _check_permissions_policy(headers) -> list[Finding]:
    if headers.get("Permissions-Policy"):
        return []
    return [
        Finding(
            id="HDR-PERMPOL",
            title="Missing Permissions-Policy header",
            severity=Severity.INFO,
            category=CATEGORY,
            description="Permissions-Policy lets you explicitly disable powerful browser "
            "features (camera, microphone, geolocation, etc.) that the site doesn't use, "
            "reducing the blast radius of any injected script.",
            evidence="No Permissions-Policy header present",
            remediation="Add a Permissions-Policy header disabling features the site doesn't "
            "need, e.g. 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
            references=[_OWASP_HEADERS_REF],
        )
    ]


def _check_server_disclosure(headers) -> list[Finding]:
    findings: list[Finding] = []
    for header_name in ("Server", "X-Powered-By"):
        value = headers.get(header_name)
        if value:
            findings.append(
                Finding(
                    id=f"HDR-DISC-{header_name.upper().replace('-', '')}",
                    title=f"{header_name} header discloses server/technology details",
                    severity=Severity.LOW,
                    category=CATEGORY,
                    description="Revealing the exact server software/version (or backend "
                    "framework) makes it easier for an attacker to look up known "
                    "vulnerabilities for that specific version.",
                    evidence=f"{header_name}: {value}",
                    remediation=f"Suppress or generalize the {header_name} header at the "
                    "web server/proxy/framework level.",
                )
            )
    return findings


def _check_cookies(resp: requests.Response) -> list[Finding]:
    findings: list[Finding] = []
    for cookie in resp.cookies:
        # http.cookiejar parses non-standard attributes (HttpOnly, SameSite) into
        # cookie._rest, exposed via has_nonstandard_attr()/get_nonstandard_attr().
        samesite = cookie.get_nonstandard_attr("SameSite")
        issues = []
        if not cookie.secure:
            issues.append("missing 'Secure' flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("missing 'HttpOnly' flag")
        if not samesite:
            issues.append("missing 'SameSite' attribute")

        if issues:
            findings.append(
                Finding(
                    id=f"HDR-COOKIE-{cookie.name}",
                    title=f"Cookie '{cookie.name}' set without recommended security flags",
                    severity=Severity.MEDIUM,
                    category=CATEGORY,
                    description="Cookies missing Secure/HttpOnly/SameSite are more exposed to "
                    "theft over insecure connections, access via injected JavaScript (XSS), "
                    "or use in cross-site request forgery.",
                    evidence=f"Set-Cookie: {cookie.name}=... ({', '.join(issues)})",
                    remediation="Set 'Secure', 'HttpOnly', and an appropriate 'SameSite' "
                    "(Lax or Strict) attribute on session/auth cookies.",
                    references=[_OWASP_HEADERS_REF],
                )
            )
    return findings


def _check_http_redirect(target: Target, timeout: float) -> list[Finding]:
    if target.scheme != "https":
        return []

    http_url = f"http://{target.host}"
    resp = safe_get(http_url, timeout=timeout, allow_redirects=True, verify=True)
    if resp is None:
        return []  # plain HTTP not even reachable — nothing to flag here

    final_scheme = resp.url.split("://", 1)[0]
    if final_scheme == "https":
        return []

    return [
        Finding(
            id="HDR-NO-HTTPS-REDIRECT",
            title="Plain HTTP is served without redirecting to HTTPS",
            severity=Severity.HIGH,
            category=CATEGORY,
            description="The site responds on plain HTTP without redirecting to HTTPS, so a "
            "user who types the bare domain (or follows an http:// link) will have their "
            "traffic sent unencrypted, exposing it to interception and tampering.",
            evidence=f"GET {http_url} did not redirect to https:// (final URL: {resp.url})",
            remediation="Configure the web server/load balancer to redirect all HTTP requests "
            "to HTTPS (301/308), and add HSTS once that's in place.",
        )
    ]


register_check(CATEGORY, check_headers)
