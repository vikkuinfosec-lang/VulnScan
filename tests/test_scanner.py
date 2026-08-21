from vulnscan import scanner
from vulnscan.models import Finding, Severity


def _ok_check(target, **kwargs):
    return [
        Finding(
            id="OK-1",
            title="ok",
            severity=Severity.LOW,
            category="Test",
            description="d",
            evidence="e",
            remediation="r",
        )
    ]


def _broken_check(target, **kwargs):
    raise RuntimeError("boom")


def test_run_scan_aggregates_findings_from_all_registered_checks(monkeypatch):
    monkeypatch.setattr(scanner, "_CHECKS", [("Test", _ok_check)])
    result = scanner.run_scan("example.com")
    assert len(result.findings) == 1
    assert result.findings[0].id == "OK-1"
    assert result.errors == []


def test_run_scan_survives_a_check_raising(monkeypatch):
    monkeypatch.setattr(scanner, "_CHECKS", [("Broken", _broken_check), ("Test", _ok_check)])
    result = scanner.run_scan("example.com")
    # the failing check shouldn't take down the ones after it
    assert len(result.findings) == 1
    assert result.findings[0].id == "OK-1"
    assert len(result.errors) == 1
    assert "Broken check failed" in result.errors[0]


def test_run_scan_with_no_checks_registered_returns_empty_result(monkeypatch):
    monkeypatch.setattr(scanner, "_CHECKS", [])
    result = scanner.run_scan("example.com")
    assert result.findings == []
    assert result.target == "https://example.com"
