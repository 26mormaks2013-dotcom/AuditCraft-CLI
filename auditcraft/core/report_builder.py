"""Build a Markdown audit report from a persisted summary JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from auditcraft.models.issue import ReportSummary

TEMPLATE_NAME = "report_template.md.j2"


def _env() -> Environment:
    return Environment(
        loader=PackageLoader("auditcraft", "templates"),
        autoescape=select_autoescape(enabled_extensions=()),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        undefined=StrictUndefined,
    )


def _coerce_summary(data: Any) -> ReportSummary:
    """Coerce arbitrary JSON-like data into a ReportSummary."""
    if isinstance(data, ReportSummary):
        return data
    if isinstance(data, dict):
        return ReportSummary.model_validate(data)
    raise TypeError(f"Cannot coerce {type(data)!r} into ReportSummary")


def save_summary(summary: ReportSummary, path: Path) -> None:
    """Persist a ReportSummary to JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        summary.model_dump_json(indent=2),
        encoding="utf-8",
    )


def load_summary(path: Path) -> ReportSummary:
    """Load a ReportSummary from a JSON file."""
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    return _coerce_summary(raw)


def build_report(summary: ReportSummary) -> str:
    """Render the Markdown report for a ReportSummary object."""
    env = _env()
    template = env.get_template(TEMPLATE_NAME)
    counts = summary.counts_by_severity()
    return template.render(summary=summary, counts=counts)


def build_report_from_file(path: Path) -> str:
    """Load a summary JSON and render the Markdown report."""
    return build_report(load_summary(path))
