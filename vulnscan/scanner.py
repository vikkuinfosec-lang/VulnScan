"""Orchestrates the individual check modules and aggregates their findings."""

from __future__ import annotations

import logging

from vulnscan.models import Finding, ScanResult
from vulnscan.utils import Target, parse_target

logger = logging.getLogger("vulnscan")

# Registry of check modules to run. Each entry is (category_name, callable).
# Populated incrementally as check modules are implemented (Phases 2-5).
# A check callable takes a Target and returns list[Finding]; it must not raise —
# it should catch its own errors and append to ScanResult.errors via the run_scan loop.
_CHECKS: list[tuple[str, callable]] = []


def register_check(category: str, func: callable) -> None:
    """Add a check function to the scan pipeline. Called by checks/*.py modules."""
    _CHECKS.append((category, func))


def run_scan(raw_target: str, *, timeout: float = 8, ports: list[int] | None = None) -> ScanResult:
    """Run every registered check against the target and return an aggregated ScanResult."""
    target: Target = parse_target(raw_target)
    started = ScanResult.now()

    result = ScanResult(target=target.base_url, started_at=started, finished_at=started)

    if not _CHECKS:
        logger.warning("No checks registered yet — scanner skeleton has nothing to run.")

    for category, check_func in _CHECKS:
        try:
            findings: list[Finding] = check_func(target, timeout=timeout, ports=ports)
            result.findings.extend(findings)
        except Exception as exc:  # noqa: BLE001 - a single check failing must not kill the scan
            msg = f"{category} check failed: {exc}"
            logger.error(msg)
            result.errors.append(msg)

    result.finished_at = ScanResult.now()
    return result
