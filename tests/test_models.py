from datetime import datetime, timedelta, timezone

from vulnscan.models import Finding, ScanResult, Severity


def _finding(id_, severity, category="Cat"):
    return Finding(
        id=id_,
        title=f"title-{id_}",
        severity=severity,
        category=category,
        description="desc",
        evidence="evidence",
        remediation="fix it",
    )


def test_severity_rank_orders_high_first():
    assert Severity.HIGH.rank < Severity.MEDIUM.rank < Severity.LOW.rank < Severity.INFO.rank


def test_findings_sorted_by_severity_then_category_then_id():
    start = datetime.now(timezone.utc)
    result = ScanResult(
        target="example.com",
        started_at=start,
        finished_at=start + timedelta(seconds=1),
        findings=[
            _finding("B-2", Severity.LOW, "B"),
            _finding("A-1", Severity.HIGH, "A"),
            _finding("A-2", Severity.MEDIUM, "A"),
        ],
    )
    ordered = result.findings_sorted()
    assert [f.id for f in ordered] == ["A-1", "A-2", "B-2"]


def test_counts_by_severity():
    start = datetime.now(timezone.utc)
    result = ScanResult(
        target="example.com",
        started_at=start,
        finished_at=start,
        findings=[
            _finding("1", Severity.HIGH),
            _finding("2", Severity.HIGH),
            _finding("3", Severity.LOW),
        ],
    )
    counts = result.counts_by_severity()
    assert counts == {"High": 2, "Medium": 0, "Low": 1, "Info": 0}


def test_duration_seconds():
    start = datetime.now(timezone.utc)
    result = ScanResult(target="x", started_at=start, finished_at=start + timedelta(seconds=2.5))
    assert result.duration_seconds == 2.5
