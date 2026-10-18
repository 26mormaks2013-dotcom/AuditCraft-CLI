"""AuditCraft — CLI for exporting findings to contest platforms."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from auditcraft.core import contest_export, static_checker

console = Console()


def run(
    path: Path,
    platform: str = "sherlock",
    output: Path | None = None,
    project: str = "auditcraft",
    rules: list[str] | None = None,
    min_severity: str | None = None,
) -> None:
    """Run static checks on PATH and export findings as a contest ZIP."""
    if not path.exists():
        console.print(f"[red]Path not found:[/] {path}")
        raise typer.Exit(code=1)

    try:
        result = static_checker.run_checks(path, rules=rules, min_severity=min_severity)
    except ValueError as exc:
        console.print(f"[red]Invalid options:[/] {exc}")
        raise typer.Exit(code=1)

    if not result.findings:
        console.print("[yellow]No findings to export.[/]")
        return

    dest = output if output is not None else Path(f"{platform}_submission.zip")

    try:
        written = contest_export.export_findings(
            result, dest, platform=platform, project=project
        )
    except ValueError as exc:
        console.print(f"[red]Export failed:[/] {exc}")
        raise typer.Exit(code=1)

    console.print(
        Panel.fit(
            f"[bold]Export ready:[/] {written}\n"
            f"[bold]Platform:[/] {platform}\n"
            f"[bold]Project:[/] {project}\n"
            f"[bold]Findings:[/] {len(result.findings)}",
            title="Contest Export",
            border_style="cyan",
        )
    )
