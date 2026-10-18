"""Export findings as a contest-ready ZIP (Sherlock / Code4rena / Cantina)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from auditcraft.models.issue import CheckFinding, CheckResult


_SEVERITY_TO_GROUP: dict[str, str] = {
    "critical": "H",
    "high": "H",
    "warning": "M",
    "medium": "M",
    "low": "L",
    "info": "L",
    "nc": "L",
    "gas": "G",
}

_GROUP_LABEL: dict[str, str] = {
    "H": "High",
    "M": "Medium",
    "L": "Low",
    "G": "Gas",
}

_PLATFORMS = {"sherlock", "code4rena", "cantina"}


# ---------------------------------------------------------------------------
# Severity grouping
# ---------------------------------------------------------------------------


def _group_of(severity: str) -> str:
    return _SEVERITY_TO_GROUP.get(str(severity).lower(), "L")


def _group_findings(findings: list[CheckFinding]) -> dict[str, list[CheckFinding]]:
    grouped: dict[str, list[CheckFinding]] = {"H": [], "M": [], "L": [], "G": []}
    for f in findings:
        grouped[_group_of(f.severity.value)].append(f)
    return grouped


# ---------------------------------------------------------------------------
# Rendering per finding
# ---------------------------------------------------------------------------


def _impact_for(rule_id: str, group: str) -> str:
    if group == "H":
        return f"Critical security impact detected by rule `{rule_id}`."
    if group == "M":
        return f"Medium-severity issue detected by rule `{rule_id}`."
    if group == "G":
        return f"Gas optimization opportunity flagged by rule `{rule_id}`."
    return f"Low/informational issue detected by rule `{rule_id}`."


def _recommendation_for(rule_id: str) -> str:
    return (
        f"Review and remediate the pattern flagged by rule `{rule_id}` "
        f"per the audit guidelines."
    )


def _tool_used_for(finding: CheckFinding, platform: str) -> str:
    if platform == "sherlock":
        return "Manual review"
    if platform == "cantina":
        return f"AuditCraft (rule `{finding.rule_id}`)"
    return f"AuditCraft — static rule `{finding.rule_id}`"


def _render_finding(
    finding: CheckFinding, group: str, index: int, platform: str
) -> str:
    prefix = f"{group}-{index:02d}"
    lines: list[str] = []
    lines.append(f"# [{prefix}] {finding.message}")
    lines.append("")
    lines.append("## Vulnerability Detail")
    lines.append("")
    lines.append(
        f"Rule `{finding.rule_id}` triggered at `{finding.path}:{finding.line}`."
    )
    lines.append("")
    lines.append("## Impact")
    lines.append("")
    lines.append(_impact_for(finding.rule_id, group))
    lines.append("")
    lines.append("## Code Snippet")
    lines.append("")
    lines.append(f"Location: `{finding.path}:{finding.line}`")
    lines.append("")
    lines.append("## Tool used")
    lines.append("")
    lines.append(_tool_used_for(finding, platform))
    lines.append("")
    lines.append("## Recommendation")
    lines.append("")
    lines.append(_recommendation_for(finding.rule_id))
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Summary + manifest
# ---------------------------------------------------------------------------


def _render_summary(
    result: CheckResult,
    grouped: dict[str, list[CheckFinding]],
    project: str,
    platform: str,
) -> str:
    lines: list[str] = []
    lines.append(f"# {project} — {platform} Submission")
    lines.append("")
    lines.append(f"- **Total findings:** {len(result.findings)}")
    lines.append(f"- **Files scanned:** {result.files_scanned}")
    lines.append("")
    lines.append("## Counts by group")
    for g, label in _GROUP_LABEL.items():
        items = grouped.get(g, [])
        if items:
            lines.append(f"- **{label}:** {len(items)}")
    lines.append("")
    lines.append("## Findings index")
    for g, label in _GROUP_LABEL.items():
        items = grouped.get(g, [])
        for idx, f in enumerate(items, start=1):
            lines.append(
                f"- `{g}-{idx:02d}` ({f.rule_id}) `{f.path}:{f.line}` — {f.message}"
            )
    lines.append("")
    return "\n".join(lines)


def _render_manifest(
    result: CheckResult,
    grouped: dict[str, list[CheckFinding]],
    project: str,
    platform: str,
) -> str:
    manifest = {
        "platform": platform,
        "project": project,
        "total_findings": len(result.findings),
        "files_scanned": result.files_scanned,
        "counts": {g: len(items) for g, items in grouped.items() if items},
    }
    return json.dumps(manifest, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def export_findings(
    result: CheckResult,
    output: Path,
    platform: str = "sherlock",
    project: str = "auditcraft",
) -> Path:
    """
    Export ``result.findings`` to a ZIP organised by severity groups.

    Layout inside the archive:

        {platform}/
            summary.md
            findings.json
            H-01.md, H-02.md, ...
            M-01.md, ...
            L-01.md, ...

    Raises ``ValueError`` for an unknown platform.
    """
    platform = platform.lower()
    if platform not in _PLATFORMS:
        raise ValueError(
            f"Unknown platform {platform!r}; expected one of {sorted(_PLATFORMS)}"
        )

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)

    grouped = _group_findings(result.findings)

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        base = f"{platform}/"
        zf.writestr(base + "findings.json", _render_manifest(result, grouped, project, platform))
        zf.writestr(base + "summary.md", _render_summary(result, grouped, project, platform))

        for group, items in grouped.items():
            for idx, finding in enumerate(items, start=1):
                body = _render_finding(finding, group, idx, platform)
                zf.writestr(base + f"{group}-{idx:02d}.md", body)

    return output


__all__ = ["export_findings"]
