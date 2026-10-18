"""AuditCraft -- build Call Graph (DOT / Mermaid) for Solidity sources.

Extracts contract declarations + inheritance, per-function visibility and
access-control modifiers, external calls and internal calls. Renders as
Graphviz DOT or Mermaid.js. Also identifies hot spots.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_EXTERNAL_CALL = re.compile(r"\.(?:call|transfer|transferFrom|send|delegatecall)\s*[\(\{]")
_VISIBILITY = re.compile(r"\b(public|external|internal|private)\b")
_CONTRACT_DECL = re.compile(
    r"\b(?:abstract\s+)?(?:contract|library|interface)\s+(\w+)(?:\s+is\s+([\w,\s]+?))?\s*\{"
)
_FUNCTION_DECL = re.compile(r"\bfunction\s+(\w+)\s*\(([^)]*)\)\s*([^{;]*)\{")

_SKIP_KW = {
    "public", "external", "internal", "private",
    "view", "pure", "payable", "virtual", "override",
    "returns", "memory", "calldata", "storage",
}
_ACCESS_MOD_PREFIX = ("only", "when")


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", "", text)
    return text


@dataclass
class FunctionNode:
    contract: str
    name: str
    visibility: str
    modifiers: list[str]
    has_external_call: bool
    line: int = 0

    @property
    def fully_qualified(self) -> str:
        return f"{self.contract}.{self.name}"

    @property
    def is_entry(self) -> bool:
        return self.visibility in ("public", "external")

    @property
    def is_protected(self) -> bool:
        return any(m.startswith(_ACCESS_MOD_PREFIX) for m in self.modifiers)


@dataclass
class ContractNode:
    name: str
    inherits: list[str] = field(default_factory=list)
    functions: list[FunctionNode] = field(default_factory=list)
    path: str = ""


@dataclass
class CallEdge:
    src: str
    dst: str
    kind: str


@dataclass
class GraphData:
    contracts: list[ContractNode] = field(default_factory=list)
    edges: list[CallEdge] = field(default_factory=list)


@dataclass
class HotSpot:
    function: FunctionNode
    reason: str
    severity: str


def _brace_block_end(text: str, start: int) -> int:
    depth = 1
    i = start
    while i < len(text) and depth > 0:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    return i


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _parse_functions(body: str, contract: str, stripped: str, base_offset: int) -> list[FunctionNode]:
    out: list[FunctionNode] = []
    for m in _FUNCTION_DECL.finditer(body):
        name = m.group(1)
        sig = m.group(3) or ""
        vis_m = _VISIBILITY.search(sig)
        visibility = vis_m.group(1) if vis_m else "internal"
        raw = [tok for tok in re.findall(r"\b\w+\b", sig) if tok not in _SKIP_KW]
        mods: list[str] = []
        seen: set[str] = set()
        for tok in raw:
            if tok not in seen:
                seen.add(tok)
                mods.append(tok)

        block_start = m.end()
        block_end = _brace_block_end(body, block_start)
        fbody = body[block_start:block_end - 1]
        has_ext = bool(_EXTERNAL_CALL.search(fbody))

        line = _line_of(stripped, base_offset + m.start())
        out.append(FunctionNode(
            contract=contract, name=name, visibility=visibility,
            modifiers=mods, has_external_call=has_ext, line=line,
        ))
    return out


def parse_solidity_file(path: Path) -> tuple[list[ContractNode], str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    stripped = _strip_comments(text)
    contracts: list[ContractNode] = []
    for m in _CONTRACT_DECL.finditer(stripped):
        name = m.group(1)
        raw_inh = m.group(2) or ""
        inherits = [x.strip() for x in raw_inh.split(",") if x.strip()]
        body_start = m.end()
        body_end = _brace_block_end(stripped, body_start)
        body = stripped[body_start:body_end - 1]
        funcs = _parse_functions(body, name, stripped, body_start)
        contracts.append(ContractNode(
            name=name, inherits=inherits, functions=funcs, path=str(path),
        ))
    return contracts, stripped


def _iter_sol_files(root: Path) -> list[Path]:
    root = Path(root)
    if root.is_file():
        return [root] if root.suffix.lower() == ".sol" else []
    return sorted(p for p in root.rglob("*.sol") if p.is_file())


def build_call_graph(root: Path) -> GraphData:
    graph = GraphData()
    for f in _iter_sol_files(Path(root)):
        try:
            contracts, _ = parse_solidity_file(f)
        except OSError:
            continue
        graph.contracts.extend(contracts)

    by_name: dict[str, list[FunctionNode]] = {}
    for c in graph.contracts:
        for fn in c.functions:
            by_name.setdefault(fn.name, []).append(fn)

    for c in graph.contracts:
        try:
            text = Path(c.path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        stripped = _strip_comments(text)
        for fn in c.functions:
            pattern = re.compile(r"\bfunction\s+" + re.escape(fn.name) + r"\s*\([^)]*\)\s*[^{;]*\{")
            fm = pattern.search(stripped)
            if not fm:
                continue
            start = fm.end()
            end = _brace_block_end(stripped, start)
            fbody = stripped[start:end - 1]

            if fn.has_external_call:
                graph.edges.append(CallEdge(src=fn.fully_qualified, dst="__external__", kind="external_call"))

            seen_targets: set[str] = set()
            for callee in re.findall(r"\b(\w+)\s*\(", fbody):
                if callee == fn.name:
                    continue
                candidates = by_name.get(callee)
                if not candidates:
                    continue
                same = [x for x in candidates if x.contract == fn.contract]
                target = (same or candidates)[0].fully_qualified
                if target in seen_targets:
                    continue
                seen_targets.add(target)
                graph.edges.append(CallEdge(src=fn.fully_qualified, dst=target, kind="internal_call"))
    return graph


def find_hotspots(graph: GraphData) -> list[HotSpot]:
    out: list[HotSpot] = []
    for c in graph.contracts:
        for fn in c.functions:
            if fn.is_entry and fn.has_external_call and not fn.is_protected:
                out.append(HotSpot(fn, "entry point with external call and no access control", "critical"))
            elif fn.has_external_call and not fn.is_protected:
                out.append(HotSpot(fn, "external call without visible access control", "warning"))
            elif fn.visibility == "external" and not fn.is_protected:
                out.append(HotSpot(fn, "external entry point without access control", "info"))
    return out


def _q(s: str) -> str:
    return '"' + s.replace('"', '\\"') + '"'


def to_dot(graph: GraphData) -> str:
    lines: list[str] = ["digraph CallGraph {", "  rankdir=LR;", "  node [fontname=\"Helvetica\"];"]
    for c in graph.contracts:
        lines.append(f"  {_q(c.name)} [shape=folder, style=filled, fillcolor=lightyellow];")
    for c in graph.contracts:
        for parent in c.inherits:
            lines.append(f"  {_q(parent)} -> {_q(c.name)} [style=dotted, arrowhead=empty, label=\"inherits\"];")
    for c in graph.contracts:
        for fn in c.functions:
            color = "lightcoral" if (fn.has_external_call and not fn.is_protected) else "white"
            lines.append(
                f"  {_q(fn.fully_qualified)} [shape=box, style=filled, fillcolor={color}, "
                f"label={_q(fn.name + '()')}];"
            )
            lines.append(f"  {_q(c.name)} -> {_q(fn.fully_qualified)} [arrowhead=none];")
    ext_seen: set[str] = set()
    for e in graph.edges:
        if e.dst == "__external__":
            ext_node = "EXTERNAL_" + e.src
            ext_seen.add(ext_node)
            lines.append(f"  {_q(e.src)} -> {_q(ext_node)} [style=dashed, color=red, label=\"external call\"];")
        else:
            lines.append(f"  {_q(e.src)} -> {_q(e.dst)} [label=\"calls\"];")
    for node in sorted(ext_seen):
        lines.append(
            f"  {_q(node)} [shape=ellipse, style=filled, fillcolor=red, fontcolor=white, label=\"external\"];"
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def _mid(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", s)


FENCE = chr(96) * 3


def to_mermaid(graph: GraphData) -> str:
    lines: list[str] = [FENCE + "mermaid", "graph LR"]
    for c in graph.contracts:
        lines.append(f"  {_mid(c.name)}[\"{c.name}\"]")
    for c in graph.contracts:
        for parent in c.inherits:
            lines.append(f"  {_mid(parent)} -.->|inherits| {_mid(c.name)}")
    for c in graph.contracts:
        for fn in c.functions:
            label = fn.name + "()"
            if fn.has_external_call and not fn.is_protected:
                lines.append(f"  {_mid(fn.fully_qualified)}[\"{label}\"]:::danger")
            elif fn.visibility == "external" and not fn.is_protected:
                lines.append(f"  {_mid(fn.fully_qualified)}[\"{label}\"]:::warn")
            else:
                lines.append(f"  {_mid(fn.fully_qualified)}[\"{label}\"]")
            lines.append(f"  {_mid(c.name)} --> {_mid(fn.fully_qualified)}")
    for e in graph.edges:
        if e.dst == "__external__":
            ext = _mid("EXTERNAL_" + e.src)
            lines.append(f"  {_mid(e.src)} -.->|external| {ext}((\"external\")):::danger")
        else:
            lines.append(f"  {_mid(e.src)} -->|calls| {_mid(e.dst)}")
    lines.append("  classDef danger fill:#fca5a5,stroke:#b91c1c,color:#111;")
    lines.append("  classDef warn fill:#fde68a,stroke:#b45309,color:#111;")
    lines.append(FENCE)
    return "\n".join(lines) + "\n"


def generate(
    root: Path,
    output: Path | None = None,
    mermaid: bool = False,
    output_dir: Path | None = None,
) -> tuple[str, str]:
    graph = build_call_graph(Path(root))
    text = to_mermaid(graph) if mermaid else to_dot(graph)

    if output is not None:
        dest = Path(output)
    else:
        base = Path(output_dir) if output_dir else Path(".")
        base.mkdir(parents=True, exist_ok=True)
        name = "callgraph.mermaid.md" if mermaid else "callgraph.dot"
        dest = base / name

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    return text, str(dest)


__all__ = [
    "FunctionNode", "ContractNode", "CallEdge", "GraphData", "HotSpot",
    "parse_solidity_file", "build_call_graph", "find_hotspots",
    "to_dot", "to_mermaid", "generate",
]
