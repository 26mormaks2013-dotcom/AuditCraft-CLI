"""``auditcraft check`` — run static security checks."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table

from auditcraft.core.static_checker import list_rules, run_checks

console = Console()
console_err = Console(stderr=True)

SEVERITY_ORDER = ("info", "warning", "critical")
SEVERITY_STYLE = {
    "info": "cyan",
    "warning": "yellow",
    "critical": "bold red",
}


def _render_table(result) -> None:  # noqa: ANN001
    if not result.findings:
        console.print("[bold green]No issues found.[/bold green]")
    else:
        table = Table(title="AuditCraft — static check results", show_lines=False)
        table.add_column("Rule", style="bold cyan", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("File", overflow="fold")
        table.add_column("Line", justify="right")
        table.add_column("Message", overflow="fold")
        for finding in result.findings:
            style = SEVERITY_STYLE.get(finding.severity.value, "white")
            table.add_row(
                finding.rule_id,
                f"[{style}]{finding.severity.value}[/{style}]",
                str(finding.path),
                str(finding.line),
                finding.message,
            )
        console.print(table)

    summary = Table(title="Summary", show_lines=False)
    summary.add_column("Severity", style="bold cyan")
    summary.add_column("Count", justify="right")
    for sev in SEVERITY_ORDER:
        summary.add_row(sev, str(result.counts.get(sev, 0)))
    summary.add_row("[bold]Total[/bold]", f"[bold]{len(result.findings)}[/bold]")
    console.print(summary)


def run(
    path: Path = Path("."),
    rules: Optional[List[str]] = None,
    min_severity: Optional[str] = None,
    json_output: bool = False,
) -> None:
    """Run static security checks on Solidity/Rust sources under PATH."""
    if min_severity is not None and min_severity not in SEVERITY_ORDER:
        console_err.print(
            f"[bold red]Invalid --min-severity:[/bold red] {min_severity!r}. "
            f"Expected one of: {', '.join(SEVERITY_ORDER)}."
        )
        raise SystemExit(2)

    result = run_checks(path, rules=rules, min_severity=min_severity)

    if json_output:
        console.print_json(result.model_dump_json())
    else:
        _render_table(result)


def list_rules_cmd() -> None:
    """List all registered rules."""
    table = Table(title="AuditCraft — available rules")
    table.add_column("Rule", style="bold cyan", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Languages", no_wrap=True)
    table.add_column("Description", overflow="fold")
    for r in list_rules():
        table.add_row(r.rule_id, r.severity, ", ".join(r.languages), r.description)
    console.print(table)
