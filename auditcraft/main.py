"""AuditCraft CLI entry point.

Registers the three MVP commands: ``scope``, ``report`` and ``check``.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel

from auditcraft import __version__
from auditcraft.cli import check as check_mod
from auditcraft.cli import poc as poc_mod
from auditcraft.cli import report as report_mod
from auditcraft.cli import scope as scope_mod

app = typer.Typer(
    name="auditcraft",
    help="Automation toolkit for smart contract auditors (nSLOC scope, reports, static checks).",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()


@app.command("scope")
def scope_cmd(
    path: str | None = typer.Argument(None, help="Root directory to scan (default: current dir)."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
    include: list[str] | None = typer.Option(None, "--include", help="Extensions to include (repeatable)."),
    exclude: list[str] | None = typer.Option(None, "--exclude", help="Directory names to exclude (repeatable)."),
    complexity: bool = typer.Option(False, "--complexity", help="Report cyclomatic complexity per Solidity function."),
) -> None:
    """Count nSLOC (or cyclomatic complexity) for Solidity/Rust sources under PATH."""
    from pathlib import Path

    scope_mod.run(
        path=Path(path) if path else Path("."),
        json_output=json_output,
        include=include,
        exclude=exclude,
        complexity=complexity,
    )


@app.command("check")
def check_cmd(
    path: str | None = typer.Argument(None, help="Root directory to scan (default: current dir)."),
    rules: list[str] | None = typer.Option(None, "--rules", help="Only run these rule ids (repeatable)."),
    min_severity: str | None = typer.Option(None, "--min-severity", help="Minimum severity: info|warning|critical."),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
) -> None:
    """Run static security checks on Solidity/Rust sources under PATH."""
    from pathlib import Path

    check_mod.run(
        path=Path(path) if path else Path("."),
        rules=rules,
        min_severity=min_severity,
        json_output=json_output,
    )


@app.command("list-rules")
def list_rules_cmd() -> None:
    """List all registered static-check rules."""
    check_mod.list_rules_cmd()


report_app = typer.Typer(
    name="report",
    help="Create and build structured audit reports.",
    no_args_is_help=True,
)
app.add_typer(report_app, name="report")


@report_app.command("init")
def report_init(
    project: str = typer.Argument(..., help="Project / protocol name."),
    auditor: str | None = typer.Option(None, "--auditor", help="Lead auditor name."),
    output: str | None = typer.Option(None, "--output", "-o", help="Where to write the summary JSON."),
) -> None:
    """Initialize an empty audit summary JSON."""
    from pathlib import Path

    report_mod.init_cmd(
        project=project,
        auditor=auditor,
        output=Path(output) if output else None,
    )


@report_app.command("add")
def report_add(
    title: str = typer.Argument(..., help="Finding title."),
    severity: str = typer.Option("medium", "--severity", "-s", help="high|medium|low|nc|gas."),
    description: str = typer.Option("", "--description", "-d", help="Short description."),
    recommendation: str = typer.Option("", "--recommendation", "-r", help="Recommended fix."),
    location: str | None = typer.Option(None, "--location", "-l", help="File/line reference."),
    summary_path: str | None = typer.Option(None, "--summary", help="Path to summary JSON."),
    non_interactive: bool = typer.Option(False, "--non-interactive", help="Do not prompt for missing fields."),
) -> None:
    """Append a finding to the summary JSON."""
    from pathlib import Path

    report_mod.add_cmd(
        title=title,
        severity=severity,
        description=description,
        recommendation=recommendation,
        location=location,
        summary_path=Path(summary_path) if summary_path else None,
        non_interactive=non_interactive,
    )


@report_app.command("build")
def report_build(
    summary_path: str | None = typer.Option(None, "--summary", help="Path to summary JSON."),
    output: str | None = typer.Option(None, "--output", "-o", help="Where to write the Markdown report."),
    json_output: bool = typer.Option(False, "--json", help="Print summary JSON instead of writing report."),
    report_format: str = typer.Option(
        "markdown", "--format", "-f",
        help="Report style: markdown | c4 | cantina.",
    ),
) -> None:
    """Render the Markdown audit report from the summary JSON."""
    from pathlib import Path

    report_mod.build_cmd(
        summary_path=Path(summary_path) if summary_path else None,
        output=Path(output) if output else None,
        json_output=json_output,
        report_format=report_format,
    )


poc_app = typer.Typer(
    name="poc",
    help="Generate Foundry / Anchor Proof-of-Concept (PoC) test scaffolds.",
    no_args_is_help=True,
)
app.add_typer(poc_app, name="poc")


@poc_app.command("generate")
def poc_generate(
    target: str = typer.Argument(..., help="Target contract / program name."),
    kind: str = typer.Option(
        "custom", "--type", "-t",
        help="reentrancy | flashloan | access-control | custom.",
    ),
    language: str = typer.Option(
        "solidity", "--language", "-L",
        help="solidity (Foundry .t.sol) | anchor (TypeScript).",
    ),
    output: str | None = typer.Option(
        None, "--output", "-o",
        help="Output directory (default: ./poc).",
    ),
    print_only: bool = typer.Option(
        False, "--print", help="Print to stdout instead of writing a file.",
    ),
) -> None:
    """Generate a PoC scaffold for TARGET."""
    from pathlib import Path

    poc_mod.generate_cmd(
        kind=kind,
        target=target,
        language=language,
        output=Path(output) if output else None,
        print_only=print_only,
    )


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    version: bool | None = typer.Option(
        None,
        "--version",
        "-V",
        help="Show AuditCraft version and exit.",
        is_eager=True,
    ),
) -> None:
    """AuditCraft — smart contract audit automation."""
    if version:
        console.print(Panel.fit(f"[bold cyan]AuditCraft[/bold cyan] v{__version__}", border_style="cyan"))
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        console.print(
            Panel.fit(
                "[bold cyan]AuditCraft[/bold cyan] — smart contract audit toolkit\n\n"
                "Use [green]--help[/green] to list available commands.",
                title=f"v{__version__}",
                border_style="cyan",
            )
        )


if __name__ == "__main__":  # pragma: no cover
    app()
