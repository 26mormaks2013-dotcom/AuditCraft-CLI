"""``auditcraft scope`` — count nSLOC and cyclomatic complexity for a project."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from auditcraft.core.sloc_counter import (
    ComplexityReport,
    ScopeReport,
    complexity_to_json,
    count_scope,
    count_scope_complexity,
    report_to_json,
)

console = Console()


def _render_table(report: ScopeReport) -> None:
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


def _complexity_style(cc: int) -> str:
    if cc >= 15:
        return "bold red"
    if cc >= 10:
        return "bold yellow"
    if cc >= 5:
        return "yellow"
    return "green"


def _render_complexity(report: ComplexityReport) -> None:
    if not report.functions:
        console.print("[yellow]No Solidity functions found for complexity analysis.[/yellow]")
        return

    summary = Table(title="AuditCraft — cyclomatic complexity", show_lines=False)
    summary.add_column("Metric", style="bold cyan")
    summary.add_column("Value", justify="right")
    summary.add_row("Functions", str(len(report.functions)))
    summary.add_row("Max complexity", str(report.max_complexity))
    summary.add_row("Avg complexity", f"{report.avg_complexity:.2f}")
    console.print(summary)

    detail = Table(title="Functions by complexity (top 25)", show_lines=False)
    detail.add_column("Function", style="bold")
    detail.add_column("File", overflow="fold")
    detail.add_column("Line", justify="right")
    detail.add_column("CC", justify="right")
    for fn in report.functions[:25]:
        style = _complexity_style(fn.complexity)
        detail.add_row(
            fn.name,
            str(fn.path),
            str(fn.line),
            f"[{style}]{fn.complexity}[/{style}]",
        )
    console.print(detail)


def run(
    path: Path = Path("."),
    json_output: bool = False,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    complexity: bool = False,
) -> None:
    """Count nSLOC (and optionally cyclomatic complexity) under PATH."""
    if complexity:
        cc_report = count_scope_complexity(path, include=include, exclude=exclude)
        if json_output:
            console.print_json(complexity_to_json(cc_report))
        else:
            _render_complexity(cc_report)
        return

    report = count_scope(path, include=include, exclude=exclude)
    if json_output:
        console.print_json(report_to_json(report))
    else:
        _render_table(report)
