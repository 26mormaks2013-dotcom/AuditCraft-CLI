# AuditCraft CLI

Cross-platform CLI toolkit for smart contract auditors: normalized SLOC scope with Cyclomatic Complexity, structured multi-format audit reports, 13 regex-based static security detectors (Solidity + Rust/Anchor), and a Foundry/Anchor proof-of-concept generator.

[![CI](https://github.com/auditcraft/auditcraft-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/auditcraft/auditcraft-cli/actions/workflows/ci.yml)

## Features

- **scope** — recursive normalized line counting (nSLOC = Total - Comments - Blank) for `.sol` and `.rs` files. Rich table or `--json`. Optional `--complexity` adds a Cyclomatic Complexity table (base 1 + `if`/`for`/`while`/`require`/`assert`/`catch`/ternary/`&&`/`||`) and highlights the most complex functions.
- **check** — 13 static security detectors for Solidity and Rust/Anchor, with severity filtering (`--min-severity`) and rule selection (`--rules`). Rich table or `--json`.
- **list-rules** — print all registered detectors with severity and target languages.
- **report** — three-step audit workflow: `init` (create summary), `add` (append a finding), `build` (render). Three output styles: `markdown` (default), `c4` (Code4rena), `cantina`.
- **poc** — generate exploit proof-of-concept scaffolding: Foundry `.t.sol` (forge-std `Test`, forking template) or Anchor TypeScript test (`@coral-xyz/anchor`).

## Installation

Python 3.10+ required.

    cd auditcraft
    pip install -e .

For development (tests + linter + coverage):

    pip install -e .[dev]

## Quick start

### Scope and complexity

    auditcraft scope path/to/contracts
    auditcraft scope path/to/contracts --complexity
    auditcraft scope path/to/contracts --json

The complexity table prints functions with `CC >= 5` (yellow), `>= 10` (bold yellow), `>= 15` (bold red), and an aggregate summary (functions / max / avg).

### Static security checks

    auditcraft check path/to/contracts
    auditcraft check . --rules SC001,SC003 --min-severity warning --json
    auditcraft list-rules

#### Bundled rules (v0.2.0)

Solidity:

| ID    | Severity | Description |
|-------|----------|-------------|
| SC001 | info     | Floating pragma (should be pinned to an exact version). |
| SC002 | warning  | Return value of low-level `call`/`transfer` is ignored. |
| SC003 | critical | `selfdestruct` without an access-control guard. |
| SC004 | critical | `delegatecall` to an untrusted target. |
| SC005 | warning  | Address parameter missing a zero-address check. |
| SC006 | critical | Reentrancy risk: state change after an external call (CEI violation). |
| SC007 | critical | Unprotected initializer: `initialize()` without `initializer`/`onlyInitializing`. |
| SC008 | warning  | Unchecked ERC20 transfer: use `SafeERC20.safeTransfer` instead of `transfer()`. |
| SC009 | warning  | Centralization risk: privileged function with a critical operation and no timelock. |

Rust / Anchor:

| ID    | Severity | Description |
|-------|----------|-------------|
| RS001 | warning  | Anchor instruction uses `.unwrap()`/`.expect()` on deserialization. |
| RS002 | critical | Anchor instruction without an owner/authority constraint. |
| RS003 | warning  | Anchor Accounts struct without `has_one`/`constraint` annotations. |
| RS004 | critical | Missing Signer check: account declared as `AccountInfo` instead of `Signer`. |

### Audit report

    auditcraft report init MyProtocol --auditor Alice
    auditcraft report add Floating-pragma -s high -d Pragma-not-pinned. -r Pin-0.8.20. --non-interactive
    auditcraft report build

The default output is `AUDIT_REPORT.md` in the current directory. Override with `-o`.

Choose a platform-specific style with `--format/-f`:

    auditcraft report build --summary summary.json --format c4 -o REPORT_C4.md
    auditcraft report build --summary summary.json --format cantina -o REPORT_CANTINA.md
    auditcraft report build --summary summary.json --format markdown -o REPORT.md

Supported formats: `markdown` (generic), `c4` (Code4rena-style findings with Impact/Recommendation), `cantina` (Cantina-style with Risk Summary + Description/Recommendation). An unknown format exits with code 2.

### Proof-of-concept generator

    auditcraft poc generate MyToken --type reentrancy --print
    auditcraft poc generate MyProgram --type custom --language anchor --print
    auditcraft poc generate Vault --type flashloan --output test/Vault.t.sol

Options:

- `--type/-t` — `reentrancy` | `flashloan` | `access-control` | `custom`.
- `--language/-L` — `foundry` (default) | `anchor`.
- `--output/-o` — write to file (default: derived from target).
- `--print` — print to stdout instead of writing.

Invalid `--type`/`--language` values exit with code 2.

## Project layout

    auditcraft/
      auditcraft/
        cli/          # scope.py, check.py, report.py, poc.py (pure functions)
        core/         # sloc_counter, static_checker, report_builder, poc_generator
        models/       # Pydantic models (Finding, ReportSummary, Severity)
        templates/    # Jinja2 report templates (markdown/c4/cantina)
        main.py       # Typer app and command registration
      tests/          # pytest suite
      .github/workflows/ci.yml     # lint + test matrix + coverage
      .github/workflows/publish.yml # PyPI trusted publishing
      pyproject.toml

## Extending detectors

New rules are added in `auditcraft/core/static_checker.py` via the registry — a 10-15 line change:

    @rule("SC010", "Short description.", "warning", ["solidity"])
    def _sc010(path: Path, text: str):
        for line_no, line in _iter_lines(text):
            if "suspicious_pattern" in line:
                yield line_no, "Detailed message."

The `check` and `list-rules` commands pick up new rules automatically. Severity must be one of `info`, `warning`, `critical`.

## Tests and linter

    python -m pytest -q
    ruff check .

## Ignored directories

Scanning skips `node_modules`, `lib`, `target`, `out`, `test`, `mock` (plus any `--exclude` values).

## Continuous integration and publishing

- `.github/workflows/ci.yml` — ruff lint + pytest with coverage across Ubuntu/Windows/macOS on Python 3.10/3.11/3.12.
- `.github/workflows/publish.yml` — builds sdist + wheel and publishes to PyPI on GitHub Release via [trusted publishing](https://docs.pypi.org/trusted-publishers/).

## License

MIT.
