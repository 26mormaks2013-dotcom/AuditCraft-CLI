"""AuditCraft — CLI for Fix-Review Delta Report (diff between two source trees)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from auditcraft.core import diff_engine

console = Console()


def run(
    old_path: Path,
    new_path: Path,
    output: Path | None = None,
    rules: list[str] | None = None,
    min_severity: str | None = None,
    json_output: bool = False,
) -> None:
    """Compare OLD vs NEW source trees and render Fix-Review Delta Report."""
    if not old_path.exists():
        console.print(f"[red]Old path not found:[/] {old_path}")
        raise typer.Exit(code=1)
    if not new_path.exists():
        console.print(f"[red]New path not found:[/] {new_path}")
        raise typer.Exit(code=1)

    report = diff_engine.build_delta(
        old_path, new_path, rules=rules, min_severity=min_severity
    )

    if json_output:
        import json

        payload = {
            "old_path": report.old_path,
            "new_path": report.new_path,
            "files_changed": report.total_files_changed,
            "files_added": [d.path for d in report.files_added],
            "files_removed": [d.path for d in report.files_removed],
            "files_modified": [d.path for d in report.files_modified],
            "lines_added": report.total_lines_added,
            "lines_removed": report.total_lines_removed,
            "new_functions": report.total_new_functions,
            "fixed": [
                {"rule_id": f.rule_id, "path": f.path, "line": f.line, "message": f.message}
                for f in report.fixed
            ],
            "still_open": [
                {"rule_id": f.rule_id, "path": f.path, "line": f.line, "message": f.message}
                for f in report.still_open
            ],
            "new": [
                {"rule_id": f.rule_id, "path": f.path, "line": f.line, "message": f.message}
                for f in report.new
            ],
        }
        typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    md = diff_engine.render_markdown(report)

    if output is not None:
        dest = Path(output)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(md, encoding="utf-8")
        console.print(f"[green]Delta report written:[/] {dest}")
    else:
        console.print(md)

    summary = (
        f"[bold]Files changed:[/] {report.total_files_changed} "
        f"([green]+{len(report.files_added)}[/] / [red]-{len(report.files_removed)}[/] / [yellow]~{len(report.files_modified)}[/])\n"
        f"[bold]Lines:[/] [green]+{report.total_lines_added}[/] / [red]-{report.total_lines_removed}[/]\n"
        f"[bold]Findings:[/] fixed=[green]{len(report.fixed)}[/] "
        f"still_open=[yellow]{len(report.still_open)}[/] new=[red]{len(report.new)}[/]"
    )
    console.print(Panel.fit(summary, title="Fix-Review Delta", border_style="cyan"))
