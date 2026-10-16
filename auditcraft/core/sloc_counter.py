"""nSLOC counter for Solidity and Rust sources.

nSLOC = Total lines − Comment lines − Blank lines.

Only full-line comments count as comment lines. Inline trailing comments do not
reduce the line count; the line is still treated as source.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Sequence

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


def _ext_to_language(path: Path) -> Optional[str]:
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

    def finalize(self) -> "ScopeReport":
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


def _iter_source_files(root: Path, include: Optional[Sequence[str]], exclude: Optional[Sequence[str]]) -> Iterable[Path]:
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
    include: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
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
