"""``auditcraft poc`` — generate Foundry/Anchor Proof-of-Concept scaffolds."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from auditcraft.core.poc_generator import LANGUAGES, POC_TYPES, generate

console = Console()
console_err = Console(stderr=True)

DEFAULT_DIR = Path("poc")


def generate_cmd(
    kind: str,
    target: str,
    language: str = "solidity",
    output: Path | None = None,
    print_only: bool = False,
) -> None:
    """Generate a PoC test scaffold for ``target``.

    ``kind`` is one of reentrancy | flashloan | access-control | custom.
    ``language`` is one of solidity (Foundry .t.sol) | anchor (TypeScript).
    """
    if kind not in POC_TYPES:
        console_err.print(
            f"[bold red]Invalid --type:[/bold red] {kind!r}. "
            f"Expected one of: {', '.join(POC_TYPES)}."
        )
        raise SystemExit(2)

    if language not in LANGUAGES:
        console_err.print(
            f"[bold red]Invalid --language:[/bold red] {language!r}. "
            f"Expected one of: {', '.join(LANGUAGES)}."
        )
        raise SystemExit(2)

    try:
        result = generate(kind=kind, target=target, language=language)
    except ValueError as exc:
        console_err.print(f"[bold red]PoC generation failed:[/bold red] {exc}")
        raise SystemExit(2)

    if print_only:
        console.print(
            Panel.fit(
                f"[bold cyan]{result.filename}[/bold cyan] "
                f"({result.language})",
                border_style="cyan",
            )
        )
        console.print(Syntax(result.content, result.language, line_numbers=True))
        return

    out_dir = output if output is not None else DEFAULT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / result.filename
    out_path.write_text(result.content, encoding="utf-8")
    console.print(
        f"[bold green]Generated PoC:[/bold green] {out_path} "
        f"([cyan]{result.language}[/cyan])"
    )
