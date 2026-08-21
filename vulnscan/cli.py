"""Command-line entry point for vulnscan."""

from __future__ import annotations

import argparse
import sys

from rich.console import Console

from vulnscan import __version__
from vulnscan import checks  # noqa: F401 - side effect: registers all check modules
from vulnscan.report import print_console_report, to_html_report, to_json_report
from vulnscan.scanner import run_scan

BANNER = r"""
__     __     _       _   _  _____
\ \   / /   _| |_ __ | \ | |/ ____|  ___ __ _ _ __
 \ \ / / | | | | '_ \|  \| | (___   / __/ _` | '_ \
  \ V /| |_| | | | | | |\  |\___ \ | (_| (_| | | | |
   \_/  \__,_|_|_| |_|_| \_|____/  \___\__,_|_| |_|
"""

DISCLAIMER = (
    "This tool performs active network requests and connection attempts against the\n"
    "target you specify. Only scan systems you own or have EXPLICIT WRITTEN PERMISSION\n"
    "to test. Scanning systems without authorization may be illegal in your jurisdiction.\n"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description="A defensive vulnerability scanner: checks security headers, TLS config, "
        "open ports, and common misconfigurations on an authorized target.",
    )
    parser.add_argument("target", help="Target host or URL, e.g. example.com or https://example.com")
    parser.add_argument(
        "--format",
        choices=["console", "json", "html"],
        default="console",
        help="Output format (default: console)",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write report to FILE instead of stdout (required for json/html unless you redirect stdout)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Per-request network timeout in seconds (default: 8)",
    )
    parser.add_argument(
        "--ports",
        metavar="LIST",
        default=None,
        help="Comma-separated ports or ranges to scan, e.g. '22,80,443,8000-8100'. "
        "Defaults to a curated common-port list.",
    )
    parser.add_argument(
        "--yes-i-am-authorized",
        action="store_true",
        help="Skip the interactive confirmation prompt (for scripted/CI use). "
        "You are still responsible for having authorization to scan the target.",
    )
    parser.add_argument("--version", action="version", version=f"vulnscan {__version__}")
    return parser


def _parse_ports(spec: str | None) -> list[int] | None:
    if not spec:
        return None
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def _confirm_authorization(target: str, console: Console) -> bool:
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(f"[yellow]{DISCLAIMER}[/yellow]")
    console.print(f"Target: [bold]{target}[/bold]")
    try:
        answer = input("Do you own this target or have explicit permission to scan it? [y/N]: ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console()

    if not args.yes_i_am_authorized:
        if not _confirm_authorization(args.target, console):
            console.print("[red]Aborted: authorization not confirmed.[/red]")
            return 1

    try:
        ports = _parse_ports(args.ports)
    except ValueError as exc:
        console.print(f"[red]Invalid --ports value: {exc}[/red]")
        return 2

    try:
        result = run_scan(args.target, timeout=args.timeout, ports=ports)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        return 2

    if args.format == "console":
        print_console_report(result, console=console)
    elif args.format == "json":
        output = to_json_report(result)
        _emit(output, args.output)
    elif args.format == "html":
        output = to_html_report(result)
        _emit(output, args.output)

    return 1 if any(f.severity.value == "High" for f in result.findings) else 0


def _emit(content: str, output_path: str | None) -> None:
    if output_path:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"Report written to {output_path}")
    else:
        print(content)


if __name__ == "__main__":
    sys.exit(main())
