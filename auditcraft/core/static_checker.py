"""Regex-based static security checks for Solidity and Rust/Anchor sources.

Rules register themselves via the :func:`rule` decorator into the global
``RULES`` list. Each rule is a tiny function ``(path, text) -> Iterable[(line, message)]``
which makes adding a new detector a 10-15 line change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional, Sequence

from auditcraft.core.sloc_counter import DEFAULT_EXCLUDES, SUPPORTED_EXTS
from auditcraft.models.issue import CheckFinding, CheckResult, Severity

SEVERITY_ORDER: tuple[str, ...] = ("info", "warning", "critical")


@dataclass(frozen=True)
class Rule:
    """Metadata + implementation for a single static rule."""

    rule_id: str
    description: str
    severity: str
    languages: tuple[str, ...]
    detector: Callable[[Path, str], Iterable[tuple[int, str]]]


RULES: list[Rule] = []


def rule(
    rule_id: str,
    description: str,
    severity: str,
    languages: Sequence[str],
) -> Callable[[Callable[[Path, str], Iterable[tuple[int, str]]]], Callable[[Path, str], Iterable[tuple[int, str]]]]:
    """Decorator registering a detector function into :data:`RULES`."""

    if severity not in SEVERITY_ORDER:
        raise ValueError(f"Unknown severity {severity!r}; expected one of {SEVERITY_ORDER}")

    def decorator(fn):
        RULES.append(
            Rule(
                rule_id=rule_id,
                description=description,
                severity=severity,
                languages=tuple(languages),
                detector=fn,
            )
        )
        return fn

    return decorator


def _language_of(path: Path) -> Optional[str]:
    ext = path.suffix.lower()
    if ext == ".sol":
        return "solidity"
    if ext == ".rs":
        return "rust"
    return None


def _iter_lines(text: str) -> Iterator[tuple[int, str]]:
    for idx, line in enumerate(text.splitlines(), start=1):
        yield idx, line


# ---------------------------------------------------------------------------
# Solidity rules
# ---------------------------------------------------------------------------

_FLOATING_PRAGMA = re.compile(r"^\s*pragma\s+solidity\s+(\^|>=|>|<|<=|~)")


@rule("SC001", "Floating pragma (should be pinned to an exact version).", "info", ["solidity"])
def _sc001(path: Path, text: str) -> Iterable[tuple[int, str]]:
    for line_no, line in _iter_lines(text):
        if _FLOATING_PRAGMA.search(line):
            yield line_no, "Pragma uses a floating version specifier."


_UNCHECKED_CALL = re.compile(r"\.call\s*(\{[^}]*\})?\s*\(")
_TRANSFER = re.compile(r"\.transfer\s*\(")


@rule("SC002", "Return value of low-level call/transfer is ignored.", "warning", ["solidity"])
def _sc002(path: Path, text: str) -> Iterable[tuple[int, str]]:
    for line_no, line in _iter_lines(text):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if _UNCHECKED_CALL.search(line) and not re.search(r"\b(require|assert|bool\s+\w+\s*=)", line):
            yield line_no, "Low-level call result is not checked."
        if _TRANSFER.search(line):
            yield line_no, "transfer() return value is ignored (use call + require)."


@rule("SC003", "selfdestruct without an access-control guard.", "critical", ["solidity"])
def _sc003(path: Path, text: str) -> Iterable[tuple[int, str]]:
    guarded = re.search(r"\b(onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender)", text)
    if guarded:
        return
    for line_no, line in _iter_lines(text):
        if "selfdestruct" in line:
            yield line_no, "selfdestruct() reached without visible access control."


@rule("SC004", "delegatecall to an untrusted target.", "critical", ["solidity"])
def _sc004(path: Path, text: str) -> Iterable[tuple[int, str]]:
    guarded = re.search(r"\b(onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender)", text)
    if guarded:
        return
    for line_no, line in _iter_lines(text):
        if ".delegatecall(" in line:
            yield line_no, "delegatecall() without visible access control on target."


_ZERO_ADDR_PARAM = re.compile(r"address\s+(?:payable\s+)?\w+")
_ZERO_ADDR_CHECK = re.compile(r"!=\s*address\(0\)|==\s*address\(0\)|address\(0\)\s*!=")


@rule("SC005", "Address parameter missing a zero-address check.", "warning", ["solidity"])
def _sc005(path: Path, text: str) -> Iterable[tuple[int, str]]:
    has_check = bool(_ZERO_ADDR_CHECK.search(text))
    if has_check:
        return
    for line_no, line in _iter_lines(text):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if "function " in line and _ZERO_ADDR_PARAM.search(line):
            yield line_no, "Address parameter without a zero-address check in the file."
            break


# ---------------------------------------------------------------------------
# Rust / Anchor rules
# ---------------------------------------------------------------------------


@rule("RS001", "Anchor instruction uses .unwrap()/expect() on deserialization.", "warning", ["rust"])
def _rs001(path: Path, text: str) -> Iterable[tuple[int, str]]:
    for line_no, line in _iter_lines(text):
        if ".unwrap()" in line or ".expect(" in line:
            yield line_no, "Potential panic via unwrap()/expect()."


_ANCHOR_INSTR = re.compile(r"pub\s+fn\s+\w+\s*\(\s*ctx\s*:\s*Context\s*<")
_OWNER_GUARD = re.compile(r"has_one\s*=\s*owner|constraint\s*=\s*.*owner|require_keys_eq!")


@rule("RS002", "Anchor instruction without an owner/authority constraint.", "critical", ["rust"])
def _rs002(path: Path, text: str) -> Iterable[tuple[int, str]]:
    has_guard = bool(_OWNER_GUARD.search(text))
    if has_guard:
        return
    for line_no, line in _iter_lines(text):
        if _ANCHOR_INSTR.search(line):
            yield line_no, "Anchor instruction lacks an owner/authority constraint."


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def list_rules() -> list[Rule]:
    """Return all registered rules (sorted by rule_id)."""
    return sorted(RULES, key=lambda r: r.rule_id)


def _iter_source_files(root: Path, exclude: Optional[Sequence[str]] = None) -> Iterator[Path]:
    exclude_set = set(DEFAULT_EXCLUDES) | {e for e in (exclude or [])}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if set(p.parts) & exclude_set:
            continue
        if p.suffix.lower() not in SUPPORTED_EXTS:
            continue
        yield p


def _scan_file(path: Path, active_rules: list[Rule]) -> list[CheckFinding]:
    language = _language_of(path)
    if language is None:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="utf-8", errors="ignore")

    findings: list[CheckFinding] = []
    for r in active_rules:
        if language not in r.languages:
            continue
        try:
            hits = list(r.detector(path, text))
        except Exception as exc:  # pragma: no cover - defensive
            hits = [(1, f"Rule {r.rule_id} crashed: {exc}")]
        for line_no, message in hits:
            findings.append(
                CheckFinding(
                    rule_id=r.rule_id,
                    severity=Severity(r.severity),
                    path=str(path),
                    line=int(line_no),
                    message=message,
                )
            )
    return findings


def run_checks(
    root: Path,
    rules: Optional[Sequence[str]] = None,
    min_severity: Optional[str] = None,
) -> CheckResult:
    """Run all (or selected) rules under ``root`` and return a CheckResult."""
    root = Path(root)

    if min_severity is not None and min_severity not in SEVERITY_ORDER:
        raise ValueError(f"Unknown severity {min_severity!r}")

    selected = {r.rule_id for r in RULES} if not rules else set(rules)
    active = [r for r in RULES if r.rule_id in selected]

    files: list[Path]
    if root.is_file():
        files = [root] if _language_of(root) is not None else []
    else:
        files = list(_iter_source_files(root))

    findings: list[CheckFinding] = []
    for f in files:
        findings.extend(_scan_file(f, active))

    if min_severity is not None:
        threshold = SEVERITY_ORDER.index(min_severity)
        findings = [
            fnd
            for fnd in findings
            if SEVERITY_ORDER.index(fnd.severity.value) >= threshold
        ]

    findings.sort(key=lambda fnd: (SEVERITY_ORDER.index(fnd.severity.value), fnd.path, fnd.line))

    counts: dict[str, int] = {sev: 0 for sev in SEVERITY_ORDER}
    for fnd in findings:
        counts[fnd.severity.value] = counts.get(fnd.severity.value, 0) + 1

    return CheckResult(
        findings=findings,
        counts={k: v for k, v in counts.items() if v > 0},
        files_scanned=len(files),
    )
