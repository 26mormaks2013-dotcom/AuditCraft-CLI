"""AuditCraft — CLI for Call Graph generation (DOT / Mermaid)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from auditcraft.core import graph_builder

console = Console()

graph_app = typer.Typer(help="Build Call Graph for Solidity sources (DOT / Mermaid).")


@graph_app.command("generate")
def generate_cmd(
    path: Path = typer.Argument(Path("."), help="File or directory with Solidity sources."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write graph to this file (default: callgraph.dot)."
    ),
    mermaid: bool = typer.Option(
        False, "--mermaid", help="Render Mermaid.js instead of Graphviz DOT."
    ),
    output_dir: Path | None = typer.Option(
        None, "--output-dir", help="Directory for default output file name."
    ),
    hotspots: bool = typer.Option(
        True, "--hotspots/--no-hotspots", help="Print hot spots table."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Do not print graph to stdout."),
) -> None:
    """Build a Call Graph and identify hot spots (unprotected external calls)."""
    if not path.exists():
        console.print(f"[red]Path not found:[/] {path}")
        raise typer.Exit(code=1)

    graph = graph_builder.build_call_graph(path)
    if not graph.contracts:
        console.print(f"[yellow]No Solidity contracts found in:[/] {path}")
        raise typer.Exit(code=1)

    text = graph_builder.to_mermaid(graph) if mermaid else graph_builder.to_dot(graph)

    if output is not None:
        dest = Path(output)
    else:
        base = Path(output_dir) if output_dir else Path(".")
        base.mkdir(parents=True, exist_ok=True)
        name = "callgraph.mermaid.md" if mermaid else "callgraph.dot"
        dest = base / name

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")

    if not quiet:
        console.print(text)

    console.print(
        f"[green]Graph written:[/] {dest} "
        f"([cyan]{len(graph.contracts)}[/] contracts, [cyan]{len(graph.edges)}[/] edges)"
    )

    if hotspots:
        spots = graph_builder.find_hotspots(graph)
        if not spots:
            console.print("[green]No hot spots detected.[/]")
            return
        order = {"critical": 0, "warning": 1, "info": 2}
        spots.sort(key=lambda h: order.get(h.severity, 9))
        table = Table(title=f"Hot Spots ({len(spots)})")
        table.add_column("Severity", style="bold")
        table.add_column("Function")
        table.add_column("Reason")
        for h in spots:
            color = {"critical": "red", "warning": "yellow", "info": "cyan"}.get(h.severity, "white")
            table.add_row(f"[{color}]{h.severity}[/]", h.function.fully_qualified, h.reason)
        console.print(table)
