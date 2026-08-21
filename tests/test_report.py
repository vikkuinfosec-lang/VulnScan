import json
from datetime import datetime, timedelta, timezone

from vulnscan.models import Finding, ScanResult, Severity
from vulnscan.report import to_html_report, to_json_report


def _sample_result() -> ScanResult:
    start = datetime.now(timezone.utc)
    return ScanResult(
        target="https://example.com",
        started_at=start,
        finished_at=start + timedelta(seconds=1.5),
        findings=[
            Finding(
                id="HDR-HSTS",
                title="Missing HSTS",
                severity=Severity.HIGH,
                category="Headers",
                description="desc <script>alert(1)</script>",
                evidence="no header",
                remediation="add it",
                references=["https://owasp.org"],
            )
        ],
        errors=["Ports check failed: timeout"],
    )


def test_json_report_round_trips_findings():
    payload = json.loads(to_json_report(_sample_result()))
    assert payload["target"] == "https://example.com"
    assert payload["summary"]["High"] == 1
    assert payload["findings"][0]["id"] == "HDR-HSTS"
    assert payload["errors"] == ["Ports check failed: timeout"]


def test_html_report_is_self_contained_and_escapes_user_content():
    html = to_html_report(_sample_result())
    assert html.startswith("<!doctype html>")
    assert "example.com" in html
    assert "HDR-HSTS" in html
    # the description contains a raw <script> tag — must come out escaped, not live.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_report_with_no_findings_says_so():
    start = datetime.now(timezone.utc)
    result = ScanResult(target="https://clean.example", started_at=start, finished_at=start)
    html = to_html_report(result)
    assert "No findings" in html
