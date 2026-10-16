"""nSLOC counter for Solidity and Rust sources.

nSLOC = Total lines − Comment lines − Blank lines.

Only full-line comments count as comment lines. Inline trailing comments do not
reduce the line count; the line is still treated as source.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_EXCLUDES: tuple[str, ...] = (
    "node_modules",
    "lib",
    "target",
    "out",
    "test",
    "mock",
)

SOLIDITY_EXTS: tuple[str, ...] = (".sol",)
RUST_EXTS: tuple[str, ...] = (".rs",)
SUPPORTED_EXTS: tuple[str, ...] = SOLIDITY_EXTS + RUST_EXTS


def _ext_to_language(path: Path) -> str | None:
    ext = path.suffix.lower()
    if ext in SOLIDITY_EXTS:
        return "solidity"
    if ext in RUST_EXTS:
        return "rust"
    return None


@dataclass
class FileScope:
    """Per-file nSLOC stats."""

    path: Path
    language: str
    total: int = 0
    comments: int = 0
    blank: int = 0

    @property
    def nsloc(self) -> int:
        return max(self.total - self.comments - self.blank, 0)


@dataclass
class ScopeReport:
    """Aggregate nSLOC report across many files."""

    files: int = 0
    total: int = 0
    comments: int = 0
    blank: int = 0
    per_file: list[FileScope] = field(default_factory=list)

    @property
    def nsloc(self) -> int:
        return max(self.total - self.comments - self.blank, 0)

    def finalize(self) -> ScopeReport:
        self.files = len(self.per_file)
        self.total = sum(f.total for f in self.per_file)
        self.comments = sum(f.comments for f in self.per_file)
        self.blank = sum(f.blank for f in self.per_file)
        self.per_file.sort(key=lambda f: str(f.path).lower())
        return self


def _strip_strings(line: str, in_block_comment: bool) -> str:
    """Return the line with the string-literal bodies stripped so that comment
    markers inside strings are ignored.

    ``in_block_comment`` tells us whether we are currently inside a /* ... */
    block. If so, we skip any code until we find the closing ``*/``.
    """
    out: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        nxt = line[i + 1] if i + 1 < n else ""

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue

        if ch == "/" and nxt == "/":
            break

        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
            while i < n:
                c = line[i]
                out.append(c)
                if c == "\\" and i + 1 < n:
                    out.append(line[i + 1])
                    i += 2
                    continue
                if c == quote:
                    i += 1
                    break
                i += 1
            continue

        out.append(ch)
        i += 1
    return "".join(out)


def count_text(text: str, language: str = "solidity") -> FileScope:
    """Count nSLOC for a string of source code."""
    total = 0
    comments = 0
    blank = 0
    in_block_comment = False

    for raw_line in text.splitlines():
        total += 1
        stripped = raw_line.strip()

        if not stripped and not in_block_comment:
            blank += 1
            continue

        # Fast path for languages with // line comments.
        code_part = _strip_strings(raw_line, in_block_comment) if not in_block_comment else ""

        # If still in block comment, the whole (non-blank) line counts as comment.
        # Recompute by walking the raw line to know whether the block ended.
        line_was_block_only = False
        if in_block_comment:
            line_was_block_only = True
            # Advance the block state through this line.
            idx = raw_line.find("*/")
            if idx != -1:
                in_block_comment = False

        # Detect a brand-new block comment starting on this line, if we are not
        # already inside one.
        if not in_block_comment and not line_was_block_only:
            # If the line (after stripping strings) is empty or contains only
            # whitespace, it is a pure comment (e.g. `// foo`).
            if code_part.strip() == "":
                if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                    comments += 1
                    # Enter block comment if this line opened one.
                    if "/*" in raw_line and "*/" not in raw_line.split("/*", 1)[1]:
                        in_block_comment = True
                    continue

        if line_was_block_only:
            comments += 1
            continue

        # After `_strip_strings`, the remaining code may still contain `/*`
        # opening a block. Track that.
        if "/*" in raw_line and "*/" not in raw_line.split("/*", 1)[1]:
            # Only count as pure comment when nothing before /* remains.
            pre = raw_line.split("/*", 1)[0]
            if pre.strip() == "":
                comments += 1
                in_block_comment = True
                continue

    scope = FileScope(path=Path("<text>"), language=language, total=total, comments=comments, blank=blank)
    return scope


def count_file(path: Path) -> FileScope:
    """Count nSLOC for a single file."""
    language = _ext_to_language(path) or "unknown"
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="utf-8", errors="ignore")

    scope = count_text(text, language=language)
    scope.path = path
    return scope


def _iter_source_files(root: Path, include: Sequence[str] | None, exclude: Sequence[str] | None) -> Iterable[Path]:
    exclude_set = set(DEFAULT_EXCLUDES) | {e for e in (exclude or [])}
    include_exts = tuple(include) if include else SUPPORTED_EXTS

    for p in root.rglob("*"):
        if not p.is_file():
            continue
        parts = set(p.parts)
        if parts & exclude_set:
            continue
        if p.suffix.lower() not in include_exts:
            continue
        yield p


def count_scope(
    root: Path,
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
) -> ScopeReport:
    """Recursively count nSLOC under ``root``."""
    root = Path(root)
    report = ScopeReport()

    if root.is_file():
        if _ext_to_language(root) is not None:
            report.per_file.append(count_file(root))
        return report.finalize()

    for path in _iter_source_files(root, include, exclude):
        report.per_file.append(count_file(path))

    return report.finalize()


def report_to_json(report: ScopeReport) -> str:
    """Serialize a ScopeReport to a JSON string."""
    payload = {
        "files": report.files,
        "total": report.total,
        "comments": report.comments,
        "blank": report.blank,
        "nsloc": report.nsloc,
        "per_file": [
            {
                "path": str(f.path),
                "language": f.language,
                "total": f.total,
                "comments": f.comments,
                "blank": f.blank,
                "nsloc": f.nsloc,
            }
            for f in report.per_file
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Cyclomatic complexity (v0.2.0)
# ---------------------------------------------------------------------------

_FUNC_SIG = re.compile(
    r"^\s*function\s+([A-Za-z_]\w*)\s*\([^)]*\)[^{;]*\{"
)
_DECISION_KEYWORDS = re.compile(r"\b(if|for|while|require|assert|catch)\b")
_TERNARY = re.compile(r"\?")
_BOOL_AND_OR = re.compile(r"&&|\|\|")


@dataclass
class FunctionComplexity:
    """Cyclomatic complexity of a single function."""

    name: str
    path: Path
    line: int
    complexity: int


@dataclass
class ComplexityReport:
    """Aggregate cyclomatic complexity report."""

    functions: list[FunctionComplexity] = field(default_factory=list)

    def finalize(self) -> ComplexityReport:
        self.functions.sort(key=lambda f: (-f.complexity, str(f.path).lower(), f.line))
        return self

    @property
    def max_complexity(self) -> int:
        return max((f.complexity for f in self.functions), default=0)

    @property
    def avg_complexity(self) -> float:
        if not self.functions:
            return 0.0
        return sum(f.complexity for f in self.functions) / len(self.functions)


def _strip_comments(text: str) -> str:
    """Naive comment remover used only for complexity heuristics."""
    out_lines: list[str] = []
    in_block = False
    for line in text.splitlines():
        buf: list[str] = []
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            nxt = line[i + 1] if i + 1 < n else ""
            if in_block:
                if ch == "*" and nxt == "/":
                    in_block = False
                    i += 2
                    continue
                i += 1
                continue
            if ch == "/" and nxt == "*":
                in_block = True
                i += 2
                continue
            if ch == "/" and nxt == "/":
                break
            buf.append(ch)
            i += 1
        out_lines.append("".join(buf))
    return "\n".join(out_lines)


def _extract_functions(text: str) -> list[tuple[int, str, list[str]]]:
    """Yield (start_line, name, body_lines) for each Solidity function."""
    lines = text.splitlines()
    funcs: list[tuple[int, str, list[str]]] = []
    i = 0
    while i < len(lines):
        m = _FUNC_SIG.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        start = i + 1
        depth = 0
        body: list[str] = []
        j = i
        while j < len(lines):
            depth += lines[j].count("{") - lines[j].count("}")
            body.append(lines[j])
            if depth <= 0 and j > i:
                break
            j += 1
        funcs.append((start, name, body))
        i = j + 1
    return funcs


def count_function_complexity(text: str, path: Path) -> list[FunctionComplexity]:
    """Compute cyclomatic complexity for Solidity functions in ``text``."""
    stripped = _strip_comments(text)
    results: list[FunctionComplexity] = []
    for start, name, body in _extract_functions(stripped):
        cc = 1
        for line in body:
            cc += len(_DECISION_KEYWORDS.findall(line))
            cc += len(_TERNARY.findall(line))
            cc += len(_BOOL_AND_OR.findall(line))
        results.append(
            FunctionComplexity(name=name, path=path, line=start, complexity=cc)
        )
    return results


def count_scope_complexity(
    root: Path,
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
) -> ComplexityReport:
    """Compute cyclomatic complexity for Solidity sources under ``root``."""
    root = Path(root)
    report = ComplexityReport()

    paths: list[Path]
    if root.is_file():
        paths = [root] if root.suffix.lower() in SOLIDITY_EXTS else []
    else:
        paths = [p for p in _iter_source_files(root, include, exclude) if p.suffix.lower() in SOLIDITY_EXTS]

    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="utf-8", errors="ignore")
        report.functions.extend(count_function_complexity(text, path))
    return report.finalize()


def complexity_to_json(report: ComplexityReport) -> str:
    """Serialize a ComplexityReport to a JSON string."""
    payload = {
        "max_complexity": report.max_complexity,
        "avg_complexity": round(report.avg_complexity, 2),
        "count": len(report.functions),
        "functions": [
            {
                "name": f.name,
                "path": str(f.path),
                "line": f.line,
                "complexity": f.complexity,
            }
            for f in report.functions
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
