"""Fix-Review Delta Report: compare two source trees and their static findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from auditcraft.core.static_checker import run_checks
from auditcraft.models.issue import CheckFinding


_FUNC_SOL = re.compile(r"\bfunction\s+(\w+)\s*\(")
_FUNC_RS = re.compile(r"\bpub\s+fn\s+(\w+)\s*\(")
_SOL_EXTS = {".sol"}
_RS_EXTS = {".rs"}
_SUPPORTED = _SOL_EXTS | _RS_EXTS


@dataclass
class FileDelta:
    path: str
    status: str  # added | removed | modified | unchanged
    lines_added: int = 0
    lines_removed: int = 0
    functions_added: list[str] = field(default_factory=list)
    functions_removed: list[str] = field(default_factory=list)


@dataclass
class DeltaReport:
    old_path: str
    new_path: str
    files_added: list[FileDelta] = field(default_factory=list)
    files_removed: list[FileDelta] = field(default_factory=list)
    files_modified: list[FileDelta] = field(default_factory=list)
    total_lines_added: int = 0
    total_lines_removed: int = 0
    total_new_functions: int = 0
    fixed: list[CheckFinding] = field(default_factory=list)
    still_open: list[CheckFinding] = field(default_factory=list)
    new: list[CheckFinding] = field(default_factory=list)

    @property
    def total_files_changed(self) -> int:
        return len(self.files_added) + len(self.files_removed) + len(self.files_modified)



def _iter_source(root: Path) -> dict[str, Path]:
    """Map relative POSIX path -> absolute file for .sol/.rs under root."""
    result: dict[str, Path] = {}
    if root.is_file():
        if root.suffix.lower() in _SUPPORTED:
            result[root.name] = root
        return result
    if not root.exists():
        return result
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in _SUPPORTED:
            rel = p.relative_to(root).as_posix()
            result[rel] = p
    return result


def _read(p: Path) -> list[str]:
    try:
        return p.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        return p.read_text(encoding="utf-8", errors="ignore").splitlines()


def _extract_functions(lines: list[str], path: str) -> set[str]:
    ext = Path(path).suffix.lower()
    regex = _FUNC_SOL if ext in _SOL_EXTS else _FUNC_RS
    out: set[str] = set()
    for line in lines:
        for m in regex.finditer(line):
            out.add(m.group(1))
    return out


def _line_diff(old_lines: list[str], new_lines: list[str]) -> tuple[int, int]:
    """Cheap LCS-free diff: length delta + count of lines not in other side's set."""
    old_set = set(old_lines)
    new_set = set(new_lines)
    added = sum(1 for l in new_lines if l not in old_set)
    removed = sum(1 for l in old_lines if l not in new_set)
    return added, removed


def _file_delta(rel: str, old_p: Path | None, new_p: Path | None) -> FileDelta | None:
    if old_p is None and new_p is None:
        return None
    if old_p is None:
        new_lines = _read(new_p)  # type: ignore[arg-type]
        return FileDelta(
            path=rel,
            status="added",
            lines_added=len(new_lines),
            lines_removed=0,
            functions_added=sorted(_extract_functions(new_lines, rel)),
        )
    if new_p is None:
        old_lines = _read(old_p)
        return FileDelta(
            path=rel,
            status="removed",
            lines_added=0,
            lines_removed=len(old_lines),
            functions_removed=sorted(_extract_functions(old_lines, rel)),
        )
    old_lines = _read(old_p)
    new_lines = _read(new_p)
    if old_lines == new_lines:
        return None
    added, removed = _line_diff(old_lines, new_lines)
    old_funcs = _extract_functions(old_lines, rel)
    new_funcs = _extract_functions(new_lines, rel)
    return FileDelta(
        path=rel,
        status="modified",
        lines_added=added,
        lines_removed=removed,
        functions_added=sorted(new_funcs - old_funcs),
        functions_removed=sorted(old_funcs - new_funcs),
    )


def _finding_key(f: CheckFinding) -> tuple[str, int, str]:
    return (f.rule_id, f.line, f.message)


def build_delta(
    old_root: Path,
    new_root: Path,
    rules: list[str] | None = None,
    min_severity: str | None = None,
) -> DeltaReport:
    """Build a DeltaReport comparing old_root vs new_root (source + findings)."""
    old_root = Path(old_root)
    new_root = Path(new_root)
    report = DeltaReport(old_path=str(old_root), new_path=str(new_root))

    old_files = _iter_source(old_root)
    new_files = _iter_source(new_root)
    all_keys = sorted(set(old_files) | set(new_files))
    for rel in all_keys:
        delta = _file_delta(rel, old_files.get(rel), new_files.get(rel))
        if delta is None:
            continue
        if delta.status == "added":
            report.files_added.append(delta)
        elif delta.status == "removed":
            report.files_removed.append(delta)
        else:
            report.files_modified.append(delta)
        report.total_lines_added += delta.lines_added
        report.total_lines_removed += delta.lines_removed
        report.total_new_functions += len(delta.functions_added)

    old_result = run_checks(old_root, rules=rules, min_severity=min_severity)
    new_result = run_checks(new_root, rules=rules, min_severity=min_severity)

    old_map: dict[tuple[str, int, str], CheckFinding] = {_finding_key(f): f for f in old_result.findings}
    new_map: dict[tuple[str, int, str], CheckFinding] = {_finding_key(f): f for f in new_result.findings}

    for key, f in old_map.items():
        if key in new_map:
            report.still_open.append(f)
        else:
            report.fixed.append(f)
    for key, f in new_map.items():
        if key not in old_map:
            report.new.append(f)

    return report


def render_markdown(report: DeltaReport) -> str:
    """Render a Fix-Review Delta Report as Markdown."""
    lines: list[str] = []
    lines.append("# Fix Review Delta Report")
    lines.append("")
    lines.append(f"- **Old:** `{report.old_path}`")
    lines.append(f"- **New:** `{report.new_path}`")
    lines.append(f"- **Files changed:** {report.total_files_changed} "
                 f"(+{len(report.files_added)} / -{len(report.files_removed)} / ~{len(report.files_modified)})")
    lines.append(f"- **Lines:** +{report.total_lines_added} / -{report.total_lines_removed}")
    lines.append(f"- **New functions:** {report.total_new_functions}")
    lines.append("")

    if report.files_added or report.files_removed or report.files_modified:
        lines.append("## File changes")
        for d in report.files_added:
            lines.append(f"- `{d.path}` — added (+{d.lines_added} lines)")
            if d.functions_added:
                lines.append(f"  - new functions: {', '.join(d.functions_added)}")
        for d in report.files_removed:
            lines.append(f"- `{d.path}` — removed (-{d.lines_removed} lines)")
        for d in report.files_modified:
            lines.append(f"- `{d.path}` — modified (+{d.lines_added} / -{d.lines_removed})")
            if d.functions_added:
                lines.append(f"  - new functions: {', '.join(d.functions_added)}")
            if d.functions_removed:
                lines.append(f"  - removed functions: {', '.join(d.functions_removed)}")
        lines.append("")

    lines.append("## Findings delta")
    lines.append("")
    lines.append(f"### Fixed ({len(report.fixed)})")
    if report.fixed:
        for f in report.fixed:
            lines.append(f"- `{f.rule_id}` {f.path}:{f.line} — {f.message}")
    else:
        lines.append("_None._")
    lines.append("")
    lines.append(f"### Still open ({len(report.still_open)})")
    if report.still_open:
        for f in report.still_open:
            lines.append(f"- `{f.rule_id}` {f.path}:{f.line} — {f.message}")
    else:
        lines.append("_None._")
    lines.append("")
    lines.append(f"### New ({len(report.new)})")
    if report.new:
        for f in report.new:
            lines.append(f"- `{f.rule_id}` {f.path}:{f.line} — {f.message}")
    else:
        lines.append("_None._")
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "FileDelta",
    "DeltaReport",
    "build_delta",
    "render_markdown",
]
