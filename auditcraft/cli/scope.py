"""``auditcraft scope`` — count nSLOC for a project."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table

from auditcraft.core.sloc_counter import count_scope, report_to_json

console = Console()


def _render_table(report) -> None:  # noqa: ANN001
    table = Table(title="AuditCraft — scope summary", show_lines=False)
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value", justify="right")
    table.add_row("Files", str(report.files))
    table.add_row("Total lines", str(report.total))
    table.add_row("Comments", str(report.comments))
    table.add_row("Blank", str(report.blank))
    table.add_row("[bold green]nSLOC[/bold green]", f"[bold green]{report.nsloc}[/bold green]")
    console.print(table)

    if report.per_file:
        detail = Table(title="Per-file breakdown", show_lines=False)
        detail.add_column("File", overflow="fold")
        detail.add_column("Lang", justify="center")
        detail.add_column("Total", justify="right")
        detail.add_column("Comments", justify="right")
        detail.add_column("Blank", justify="right")
        detail.add_column("nSLOC", justify="right")
        for entry in report.per_file:
            detail.add_row(
                str(entry.path),
                entry.language,
                str(entry.total),
                str(entry.comments),
                str(entry.blank),
                str(entry.nsloc),
            )
        console.print(detail)


def run(
    path: Path = Path("."),
    json_output: bool = False,
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
) -> None:
    """Count nSLOC for Solidity/Rust sources under PATH."""
    report = count_scope(path, include=include, exclude=exclude)
    if json_output:
        console.print_json(report_to_json(report))
    else:
        _render_table(report)
