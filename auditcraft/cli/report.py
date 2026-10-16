"""``auditcraft report`` — create and build structured audit reports."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from auditcraft.core.report_builder import (
    build_report_from_file,
    load_summary,
    save_summary,
)
from auditcraft.models.issue import Finding, ReportSummary, Severity

console = Console()
console_err = Console(stderr=True)

DEFAULT_SUMMARY = Path("audit_summary.json")
DEFAULT_OUTPUT = Path("AUDIT_REPORT.md")


def _resolve(summary_path: Optional[Path]) -> Path:
    return summary_path if summary_path is not None else DEFAULT_SUMMARY


def init_cmd(
    project: str,
    auditor: Optional[str] = None,
    output: Optional[Path] = None,
) -> None:
    """Initialize an empty audit summary JSON."""
    out = output if output is not None else DEFAULT_SUMMARY
    summary = ReportSummary(project=project, auditor=auditor, findings=[])
    save_summary(summary, out)
    console.print(f"[bold green]Initialized summary:[/bold green] {out}")


def add_cmd(
    title: str,
    severity: str = "medium",
    description: str = "",
    recommendation: str = "",
    location: Optional[str] = None,
    summary_path: Optional[Path] = None,
    non_interactive: bool = False,
) -> None:
    """Append a finding to the summary JSON."""
    path = _resolve(summary_path)
    summary = load_summary(path)

    if not non_interactive:
        if not description:
            description = input("Description: ")
        if not recommendation:
            recommendation = input("Recommendation: ")

    try:
        sev = Severity(severity.lower())
    except ValueError:
        console_err.print(f"[bold red]Invalid severity:[/bold red] {severity!r}")
        raise SystemExit(2)

    finding = Finding(
        title=title,
        severity=sev,
        description=description,
        recommendation=recommendation,
        location=location,
    )
    summary.findings.append(finding)
    save_summary(summary, path)
    console.print(f"[bold green]Added finding[/bold green] ({sev.value}): {title}")


def build_cmd(
    summary_path: Optional[Path] = None,
    output: Optional[Path] = None,
    json_output: bool = False,
) -> None:
    """Render the Markdown audit report from the summary JSON."""
    path = _resolve(summary_path)
    summary = load_summary(path)

    if json_output:
        console.print_json(summary.model_dump_json())
        return

    markdown = build_report_from_file(path)
    out = output if output is not None else DEFAULT_OUTPUT
    out.write_text(markdown, encoding="utf-8")
    console.print(f"[bold green]Wrote report:[/bold green] {out}")

    table = Table(title="Findings by severity")
    table.add_column("Severity", style="bold cyan")
    table.add_column("Count", justify="right")
    counts = summary.counts_by_severity()
    for sev, count in counts.items():
        table.add_row(sev, str(count))
    table.add_row("[bold]Total[/bold]", f"[bold]{len(summary.findings)}[/bold]")
    console.print(table)
