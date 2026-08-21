"""Shared helpers: target parsing and a safe requests wrapper used by check modules."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import requests

DEFAULT_TIMEOUT = 8
DEFAULT_USER_AGENT = "vulnscan/0.1 (+authorized-security-scan; https://github.com/)"


@dataclass
class Target:
    """A normalized scan target, derived from whatever the user typed on the CLI."""

    raw: str
    scheme: str
    host: str
    port: int

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}" if self._is_nonstandard_port() else f"{self.scheme}://{self.host}"

    def _is_nonstandard_port(self) -> bool:
        return not ((self.scheme == "https" and self.port == 443) or (self.scheme == "http" and self.port == 80))


def parse_target(raw: str) -> Target:
    """Accepts things like 'example.com', 'https://example.com', 'http://example.com:8080/path'.

    Defaults to https when no scheme is given, since that's what we want to probe first.
    """
    candidate = raw.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    if not parsed.hostname:
        raise ValueError(f"Could not parse a hostname out of target: {raw!r}")

    scheme = parsed.scheme or "https"
    port = parsed.port or (443 if scheme == "https" else 80)
    return Target(raw=raw, scheme=scheme, host=parsed.hostname, port=port)


def safe_get(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    allow_redirects: bool = True,
    verify: bool = True,
    **kwargs,
) -> requests.Response | None:
    """A requests.get() wrapper that swallows connection-level errors and returns None
    instead, so check modules can stay simple (no try/except sprawl) and just check for
    None to decide whether to emit a "could not connect" info finding.
    """
    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", DEFAULT_USER_AGENT)
    try:
        return requests.get(
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
            headers=headers,
            **kwargs,
        )
    except requests.exceptions.SSLError:
        raise  # callers may want to distinguish TLS failures from plain connectivity failures
    except requests.exceptions.RequestException:
        return None
