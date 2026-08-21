"""Renders a ScanResult as console output (rich), JSON, or a self-contained HTML report."""

from __future__ import annotations

import json
from html import escape

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vulnscan.models import ScanResult, Severity

_SEVERITY_STYLE = {
    Severity.HIGH: "bold white on red",
    Severity.MEDIUM: "bold black on yellow",
    Severity.LOW: "bold black on cyan",
    Severity.INFO: "dim",
}

_SEVERITY_HEX = {
    Severity.HIGH: "#dc2626",
    Severity.MEDIUM: "#d97706",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}


def print_console_report(result: ScanResult, console: Console | None = None) -> None:
    """Pretty-print a ScanResult to the terminal using rich."""
    console = console or Console()

    counts = result.counts_by_severity()
    summary = "  ".join(f"[{_SEVERITY_STYLE[Severity(sev)]}] {sev}: {n} [/]" for sev, n in counts.items())
    header = Text.from_markup(
        f"Target: [bold]{result.target}[/bold]   "
        f"Duration: {result.duration_seconds:.2f}s   "
        f"Findings: {len(result.findings)}"
    )
    console.print(Panel(header, title="vulnscan report", expand=False))
    console.print(Text.from_markup(summary))
    console.print()

    if not result.findings:
        console.print("[green]No findings.[/green]" if not result.errors else "[yellow]No findings (some checks did not complete — see errors below).[/yellow]")
    else:
        # Compact overview table first, for a quick scan.
        table = Table(show_lines=False)
        table.add_column("Sev", width=8, no_wrap=True)
        table.add_column("ID", no_wrap=True)
        table.add_column("Category", no_wrap=True)
        table.add_column("Finding")

        for f in result.findings_sorted():
            style = _SEVERITY_STYLE[f.severity]
            table.add_row(Text(f.severity.value, style=style), f.id, f.category, f.title)
        console.print(table)

        # Then full detail per finding (description, evidence, remediation), grouped by
        # severity — this is what makes the report actually actionable, not just a list.
        console.print()
        for f in result.findings_sorted():
            style = _SEVERITY_STYLE[f.severity]
            border = style.split(" on ")[-1] if " on " in style else style
            body = Text()
            body.append(f.description + "\n\n")
            body.append("Evidence: ", style="bold")
            body.append(f.evidence + "\n")
            body.append("Fix: ", style="bold")
            body.append(f.remediation)
            if f.references:
                body.append("\nRef: " + ", ".join(f.references), style="dim")
            console.print(
                Panel(
                    body,
                    title=f"{f.severity.value} — {f.id} — {f.title}",
                    title_align="left",
                    border_style=border,
                )
            )

    if result.errors:
        console.print()
        console.print("[bold red]Errors during scan:[/bold red]")
        for err in result.errors:
            console.print(f"  - {err}")


def to_json_report(result: ScanResult) -> str:
    """Serialize a ScanResult to a JSON string (machine-readable, for CI/tooling use)."""
    payload = {
        "target": result.target,
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat(),
        "duration_seconds": result.duration_seconds,
        "summary": result.counts_by_severity(),
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "references": f.references,
            }
            for f in result.findings_sorted()
        ],
        "errors": result.errors,
    }
    return json.dumps(payload, indent=2)


def to_html_report(result: ScanResult) -> str:
    """Render a ScanResult as a single self-contained HTML file (inline CSS, no external assets)."""
    counts = result.counts_by_severity()

    summary_cards = "".join(
        f"""
        <div class="card">
          <div class="card-count" style="color:{_SEVERITY_HEX[Severity(sev)]}">{n}</div>
          <div class="card-label">{escape(sev)}</div>
        </div>"""
        for sev, n in counts.items()
    )

    if result.findings:
        rows = "".join(
            f"""
            <tr>
              <td><span class="badge" style="background:{_SEVERITY_HEX[f.severity]}">{escape(f.severity.value)}</span></td>
              <td>{escape(f.id)}</td>
              <td>{escape(f.category)}</td>
              <td>
                <div class="finding-title">{escape(f.title)}</div>
                <div class="finding-desc">{escape(f.description)}</div>
              </td>
              <td><code>{escape(f.evidence)}</code></td>
              <td>{escape(f.remediation)}</td>
            </tr>"""
            for f in result.findings_sorted()
        )
        table_html = f"""
        <table>
          <thead>
            <tr><th>Severity</th><th>ID</th><th>Category</th><th>Finding</th><th>Evidence</th><th>Remediation</th></tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>"""
    else:
        table_html = '<p class="empty">No findings.</p>'

    errors_html = ""
    if result.errors:
        items = "".join(f"<li>{escape(e)}</li>" for e in result.errors)
        errors_html = f'<h2>Errors during scan</h2><ul class="errors">{items}</ul>'

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Vulnerability Scan Report — {escape(result.target)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{
    font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
    max-width: 1100px; margin: 2rem auto; padding: 0 1.5rem;
    background: #0f172a; color: #e2e8f0;
  }}
  h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
  .meta {{ color: #94a3b8; margin-bottom: 1.5rem; font-size: 0.9rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .card {{
    background: #1e293b; border-radius: 8px; padding: 1rem 1.5rem;
    text-align: center; min-width: 100px;
  }}
  .card-count {{ font-size: 2rem; font-weight: 700; }}
  .card-label {{ font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
  table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 0.75rem 1rem; border-bottom: 1px solid #334155; vertical-align: top; }}
  th {{ background: #0f172a; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; }}
  tr:last-child td {{ border-bottom: none; }}
  .badge {{ color: white; padding: 0.15rem 0.6rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; white-space: nowrap; }}
  .finding-title {{ font-weight: 600; margin-bottom: 0.25rem; }}
  .finding-desc {{ color: #94a3b8; font-size: 0.9rem; }}
  code {{ background: #0f172a; padding: 0.15rem 0.4rem; border-radius: 4px; font-size: 0.85rem; }}
  .empty {{ color: #4ade80; }}
  .errors {{ color: #fca5a5; }}
  footer {{ margin-top: 2rem; color: #64748b; font-size: 0.8rem; }}
  @media (prefers-color-scheme: light) {{
    body {{ background: #f8fafc; color: #0f172a; }}
    .card, table {{ background: #ffffff; }}
    th {{ background: #f1f5f9; }}
    td {{ border-bottom-color: #e2e8f0; }}
    code {{ background: #f1f5f9; }}
  }}
</style>
</head>
<body>
  <h1>Vulnerability Scan Report</h1>
  <div class="meta">
    Target: <strong>{escape(result.target)}</strong> &nbsp;|&nbsp;
    Scanned: {escape(result.started_at.isoformat())} &nbsp;|&nbsp;
    Duration: {result.duration_seconds:.2f}s &nbsp;|&nbsp;
    Findings: {len(result.findings)}
  </div>
  <div class="summary">{summary_cards}</div>
  {table_html}
  {errors_html}
  <footer>Generated by vulnscan — for authorized security testing only.</footer>
</body>
</html>"""
