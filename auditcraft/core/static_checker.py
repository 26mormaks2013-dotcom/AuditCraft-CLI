"""Regex-based static security checks for Solidity and Rust/Anchor sources.

Rules register themselves via the :func:`rule` decorator into the global
``RULES`` list. Each rule is a tiny function ``(path, text) -> Iterable[(line, message)]``
which makes adding a new detector a 10-15 line change.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

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


def _language_of(path: Path) -> str | None:
    ext = path.suffix.lower()
    if ext == ".sol":
        return "solidity"
    if ext == ".rs":
        return "rust"
    return None


def _iter_lines(text: str) -> Iterator[tuple[int, str]]:
    for idx, line in enumerate(text.splitlines(), start=1):
        yield idx, line


def _strip_comments(text: str) -> str:
    """Remove // line comments and /* */ block comments from source text.

    File-wide guard heuristics scan the returned string for tokens such as
    ``onlyOwner``, ``SafeERC20``, ``timelock`` or ``has_one``. When those
    tokens appear only inside comments / documentation (typical for our
    demonstration contracts, which describe what's missing), the guard
    would silently suppress a real finding. Stripping comments first
    ensures only executable code is searched. Line numbers in the result
    are NOT preserved — use this only for boolean presence checks.
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", "", text)
    return text


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
        if _UNCHECKED_CALL.search(line) and not re.search(r"\b(require|assert|bool\s+\w+\s*[,)=])", line):
            yield line_no, "Low-level call result is not checked."
        if _TRANSFER.search(line) and not re.search(r"\b(require|assert|bool\s+\w+\s*[,)=])", line):
            yield line_no, "transfer() return value is ignored (use call + require)."


@rule("SC003", "selfdestruct without an access-control guard.", "critical", ["solidity"])
def _sc003(path: Path, text: str) -> Iterable[tuple[int, str]]:
    code = _strip_comments(text)
    guarded = re.search(r"\b(onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender)", code)
    if guarded:
        return
    for line_no, line in _iter_lines(text):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if "selfdestruct" in line:
            yield line_no, "selfdestruct() reached without visible access control."


@rule("SC004", "delegatecall to an untrusted target.", "critical", ["solidity"])
def _sc004(path: Path, text: str) -> Iterable[tuple[int, str]]:
    code = _strip_comments(text)
    guarded = re.search(r"\b(onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender)", code)
    if guarded:
        return
    for line_no, line in _iter_lines(text):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
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
    code = _strip_comments(text)
    has_guard = bool(_OWNER_GUARD.search(code))
    if has_guard:
        return
    for line_no, line in _iter_lines(text):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if _ANCHOR_INSTR.search(line):
            yield line_no, "Anchor instruction lacks an owner/authority constraint."


# ---------------------------------------------------------------------------
# Extended Solidity rules (v0.2.0)
# ---------------------------------------------------------------------------

_EXTERNAL_CALL = re.compile(r"\.(?:call|transfer|send)\s*[\\({]")
_STATE_WRITE = re.compile(r"^\s*(?:[A-Za-z_]\w*\s*(?:\[[^\]]*\])?\s*(?:=|\+=|-=|\*=|/=|\+\+|--))")
_NON_REENTRANT = re.compile(r"\bnonReentrant\b")


@rule(
    "SC006",
    "Reentrancy risk: state-change after an external call (CEI violation).",
    "critical",
    ["solidity"],
)
def _sc006(path: Path, text: str) -> Iterable[tuple[int, str]]:
    if _NON_REENTRANT.search(text):
        return
    lines = list(_iter_lines(text))
    for idx, (line_no, line) in enumerate(lines):
        if not _EXTERNAL_CALL.search(line):
            continue
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        for _, next_line in lines[idx + 1 : idx + 20]:
            s = next_line.strip()
            if not s or s.startswith("//") or s.startswith("*"):
                continue
            if s == "}" or s.startswith("function ") or s.startswith("modifier "):
                break
            if _STATE_WRITE.match(next_line):
                yield line_no, "State change after external call (potential reentrancy)."
                break


_INIT_FUNC = re.compile(r"function\s+initialize\s*\(")
_INIT_GUARD = re.compile(r"\b(initializer|onlyInitializing|reinitializer)\b")


@rule(
    "SC007",
    "Unprotected initializer: initialize() without initializer/onlyInitializing.",
    "critical",
    ["solidity"],
)
def _sc007(path: Path, text: str) -> Iterable[tuple[int, str]]:
    for line_no, line in _iter_lines(text):
        if _INIT_FUNC.search(line) and not _INIT_GUARD.search(line):
            yield line_no, "initialize() lacks an initializer/onlyInitializing modifier."


_RAW_TRANSFER = re.compile(r"(?<!safe)\.(transfer|transferFrom)\s*\(")
_SAFE_ERC20_IMPORT = re.compile(r"SafeERC20|using\s+SafeERC20")


@rule(
    "SC008",
    "Unchecked ERC20 transfer: use SafeERC20.safeTransfer instead of transfer().",
    "warning",
    ["solidity"],
)
def _sc008(path: Path, text: str) -> Iterable[tuple[int, str]]:
    code = _strip_comments(text)
    if _SAFE_ERC20_IMPORT.search(code):
        return
    for line_no, line in _iter_lines(text):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if _RAW_TRANSFER.search(line):
            yield line_no, "Direct ERC20 transfer()/transferFrom(); prefer SafeERC20."


_ONLY_PRIV = re.compile(r"\bonlyOwner\b|\bonlyRole\s*\(")
_CRITICAL_OP = re.compile(
    r"\b(withdraw|withdrawAll|pause|unpause|setFee|setOwner|transferOwnership|"
    r"upgradeTo|upgradeToAndCall|sweep|emergencyWithdraw|rescue)\b"
)
_TIMELOCK_HINT = re.compile(r"\b(Timelock|timelock|_delay|delay\s*=|MIN_DELAY)\b")


@rule(
    "SC009",
    "Centralization risk: privileged function with a critical operation and no timelock.",
    "warning",
    ["solidity"],
)
def _sc009(path: Path, text: str) -> Iterable[tuple[int, str]]:
    code = _strip_comments(text)
    if _TIMELOCK_HINT.search(code):
        return
    for line_no, line in _iter_lines(text):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if _ONLY_PRIV.search(line) and _CRITICAL_OP.search(line):
            yield line_no, "Privileged function performs a critical op without a timelock."


# ---------------------------------------------------------------------------
# Extended Rust / Anchor rules (v0.2.0)
# ---------------------------------------------------------------------------

_ANCHOR_DERIVE = re.compile(r"#\[derive\s*\(\s*Accounts\s*\)\]")
_ACCOUNT_ANNOT = re.compile(r"#\[account\s*\(")
_ACCOUNT_FIELD = re.compile(r"\bpub\s+\w+\s*:\s*(?:AccountInfo|UncheckedAccount|Account)\s*<")


@rule(
    "RS003",
    "Anchor Accounts struct without has_one/constraint annotations.",
    "warning",
    ["rust"],
)
def _rs003(path: Path, text: str) -> Iterable[tuple[int, str]]:
    lines = list(_iter_lines(text))
    for idx, (line_no, line) in enumerate(lines):
        if not _ANCHOR_DERIVE.search(line):
            continue
        # Locate the body of the Accounts struct: start at the first '{' after
        # the derive attribute, end when brace depth returns to 0.
        depth = 0
        in_body = False
        body_start = -1
        body_end = -1
        saw_field = False
        for j in range(idx + 1, min(len(lines), idx + 200)):
            nline = lines[j][1]
            depth += nline.count("{") - nline.count("}")
            if not in_body and "{" in nline:
                in_body = True
                body_start = j
            if not in_body:
                continue
            if _ACCOUNT_FIELD.search(nline):
                saw_field = True
            if depth <= 0:
                body_end = j
                break
        if body_start < 0 or body_end < 0 or not saw_field:
            continue
        # Look for has_one / constraint inside any #[account(...)] attribute
        # within the struct body. Plain #[account(mut)] does NOT count.
        saw_constraint = False
        i = body_start
        while i < body_end:
            sline = lines[i][1]
            if re.search(r"#\[account\s*\(", sline):
                buf = sline
                pdepth = sline.count("(") - sline.count(")")
                k = i + 1
                while pdepth > 0 and k < body_end:
                    buf += "\n" + lines[k][1]
                    pdepth += lines[k][1].count("(") - lines[k][1].count(")")
                    k += 1
                if re.search(r"\bhas_one\b|\bconstraint\b", buf):
                    saw_constraint = True
                    break
                i = k
            else:
                i += 1
        if not saw_constraint:
            yield line_no, "Accounts struct has no has_one/constraint annotations."


_SIGNER_TYPE = re.compile(r"Signer\s*<\s*'info\s*>")
_ACCOUNT_INFO_TYPE = re.compile(r":\s*AccountInfo\s*<\s*'info\s*>")


@rule(
    "RS004",
    "Missing Signer check: account declared as AccountInfo instead of Signer.",
    "critical",
    ["rust"],
)
def _rs004(path: Path, text: str) -> Iterable[tuple[int, str]]:
    for line_no, line in _iter_lines(text):
        if _ACCOUNT_INFO_TYPE.search(line) and not _SIGNER_TYPE.search(line):
            yield line_no, "Account declared as AccountInfo; consider Signer<'info>'."


# ---------------------------------------------------------------------------
# Extended Solidity rules (v0.4.0): storage collision & cross-function reentrancy
# ---------------------------------------------------------------------------

_STATE_VAR = re.compile(
    r"^\s*(?:public\s+|private\s+|internal\s+|constant\s+|immutable\s+|override\s+|virtual\s+)*"
    r"(?:uint\d*|int\d*|address(?:\s+payable)?|bool|bytes\d*|string|mapping\s*\([^)]*\)|[A-Z]\w*)\s+"
    r"(?:public\s+|private\s+|internal\s+|constant\s+|immutable\s+|override\s+|virtual\s+)*"
    r"(\w+)\s*(?:=|;)"
)

_CONTRACT_OPEN = re.compile(r"\b(?:abstract\s+)?contract\s+(\w+)(?:\s+is\s+[\w,\s]+)?\s*\{")
_PROXY_HINT = re.compile(r"\bdelegatecall\b|\bProxy\b|\bUpgradeable\b")
_GAP_HINT = re.compile(r"\b__gap\b")
_EIP1967_HINT = re.compile(r"\b(?:eip1967|IMPLEMENTATION_SLOT|ADMIN_SLOT)\b")


def _contract_body_end(lines: list[tuple[int, str]], start: int) -> int:
    depth = 0
    started = False
    for j in range(start, len(lines)):
        depth += lines[j][1].count("{") - lines[j][1].count("}")
        if not started and "{" in lines[j][1]:
            started = True
        if started and depth <= 0:
            return j
    return len(lines) - 1


@rule(
    "SC012",
    "Storage collision risk in proxy/upgradeable contract without EIP-1967 slots.",
    "warning",
    ["solidity"],
)
def _sc012(path: Path, text: str) -> Iterable[tuple[int, str]]:
    code = _strip_comments(text)
    if _GAP_HINT.search(code) or _EIP1967_HINT.search(code):
        return
    lines = list(_iter_lines(code))
    i = 0
    n = len(lines)
    while i < n:
        m = _CONTRACT_OPEN.search(lines[i][1])
        if not m:
            i += 1
            continue
        body_start = i
        body_end = _contract_body_end(lines, i)
        body_text = "\n".join(l for _, l in lines[body_start : body_end + 1])
        if not _PROXY_HINT.search(body_text):
            i = body_end + 1
            continue
        in_block = False
        bdepth = 0
        for j in range(body_start + 1, body_end):
            raw = lines[j][1]
            stripped = raw.strip()
            if not stripped:
                continue
            if not in_block and re.match(r"(?:function|modifier|constructor)\b", stripped):
                in_block = True
                bdepth = 0
            if in_block:
                bdepth += raw.count("{") - raw.count("}")
                if bdepth <= 0 and "}" in raw:
                    in_block = False
                continue
            if _STATE_VAR.match(raw):
                yield lines[j][0], (
                    "State variable in proxy/upgradeable contract without EIP-1967 storage slot."
                )
                break
        i = body_end + 1


_FUNC_DECL2 = re.compile(r"\bfunction\s+(\w+)\s*\([^)]*\)\s*([^{;]*)\{")
_EXT_CALL2 = re.compile(r"\.(?:call|transfer|transferFrom|send|delegatecall)\s*[\(\{]")
_STATE_WRITE2 = re.compile(r"^\s*(\w+)\s*(?:\[[^\]]*\])?\s*(?:=|\+=|-=|\*=|/=|\+\+|--)")


def _extract_state_vars(code: str) -> set[str]:
    state_vars: set[str] = set()
    depth = 0
    for _, l in _iter_lines(code):
        opens = l.count("{")
        closes = l.count("}")
        if depth == 1 and opens == 0:
            m = _STATE_VAR.match(l)
            if m:
                state_vars.add(m.group(1))
        depth += opens - closes
    return state_vars


@rule(
    "SC013",
    "Cross-function reentrancy: shared state touched across external-call boundary.",
    "warning",
    ["solidity"],
)
def _sc013(path: Path, text: str) -> Iterable[tuple[int, str]]:
    code = _strip_comments(text)
    if re.search(r"\bnonReentrant\b", code):
        return
    state_vars = _extract_state_vars(code)
    if not state_vars:
        return
    lines = list(_iter_lines(code))
    n = len(lines)
    funcs: list[tuple[str, int, int, bool, set[str], set[str]]] = []
    i = 0
    while i < n:
        m = _FUNC_DECL2.search(lines[i][1])
        if not m:
            i += 1
            continue
        name = m.group(1)
        depth = lines[i][1].count("{") - lines[i][1].count("}")
        j = i
        while j < n and depth > 0:
            j += 1
            if j >= n:
                break
            depth += lines[j][1].count("{") - lines[j][1].count("}")
        body_lines = lines[i : j + 1]
        body_text = "\n".join(l for _, l in body_lines)
        has_call = bool(_EXT_CALL2.search(body_text))
        writes: set[str] = set()
        for _, l in body_lines:
            wm = _STATE_WRITE2.match(l)
            if wm and wm.group(1) in state_vars:
                writes.add(wm.group(1))
        reads = {sv for sv in state_vars if re.search(rf"\b{re.escape(sv)}\b", body_text)}
        funcs.append((name, i, j, has_call, writes, reads))
        i = j + 1
    for a_name, a_s, _, a_call, a_writes, _ in funcs:
        if a_call or not a_writes:
            continue
        for b_name, _, _, b_call, b_writes, b_reads in funcs:
            if a_name == b_name or not b_call:
                continue
            shared = a_writes & (b_reads | b_writes)
            if shared:
                yield lines[a_s][0], (
                    f"Cross-function reentrancy: '{a_name}' writes {sorted(shared)}; "
                    f"'{b_name}' performs external call and touches same state."
                )
                break


# ---------------------------------------------------------------------------
# Extended Solana / Anchor rules (v0.4.0)
# ---------------------------------------------------------------------------


def _iter_account_attrs(lines: list[tuple[int, str]]) -> Iterator[tuple[int, str, str]]:
    """Yield (line_no, full_attr_text, following_field_line) for every #[account(...)]."""
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i][1]
        if "#[account" not in raw:
            i += 1
            continue
        buf = raw
        pdepth = raw.count("(") - raw.count(")")
        j = i
        while pdepth > 0 and j + 1 < n:
            j += 1
            buf += "\n" + lines[j][1]
            pdepth += lines[j][1].count("(") - lines[j][1].count(")")
        field_line = ""
        k = j + 1
        while k < n and not lines[k][1].strip():
            k += 1
        if k < n:
            field_line = lines[k][1]
        yield lines[i][0], buf, field_line
        i = j + 1


_INIT_IF_NEEDED = re.compile(r"\binit_if_needed\b")
_ACCOUNT_INIT = re.compile(r"\binit\b")
_CLOSE_GUARD = re.compile(r"\bclose\s*=")
_HAS_ONE_GUARD = re.compile(r"\bhas_one\b|\bconstraint\s*=")


@rule(
    "RS005",
    "Account Reinitialization: init_if_needed without reinit guard / has_one.",
    "critical",
    ["rust"],
)
def _rs005(path: Path, text: str) -> Iterable[tuple[int, str]]:
    code = _strip_comments(text)
    if _HAS_ONE_GUARD.search(code):
        return
    for line_no, attr, field in _iter_account_attrs(list(_iter_lines(code))):
        if _INIT_IF_NEEDED.search(attr) and not _CLOSE_GUARD.search(attr):
            yield line_no, (
                "Account uses init_if_needed without has_one/close; "
                "reinitialization attack possible."
            )
            continue
        if _ACCOUNT_INIT.search(attr) and "init_if_needed" not in attr:
            if "payer" not in attr and "space" not in attr and field.strip():
                yield line_no, (
                    "Account declared init without payer/space; "
                    "may be reinitialized if the account already exists."
                )


@rule(
    "RS006",
    "Duplicate Account Pass: same account used for two distinct roles.",
    "warning",
    ["rust"],
)
def _rs006(path: Path, text: str) -> Iterable[tuple[int, str]]:
    code = _strip_comments(text)
    lines = list(_iter_lines(code))
    i = 0
    n = len(lines)
    while i < n:
        if not _ANCHOR_DERIVE.search(lines[i][1]):
            i += 1
            continue
        depth = 0
        started = False
        fields: list[tuple[int, str, str]] = []
        j = i + 1
        while j < n:
            raw = lines[j][1]
            depth += raw.count("{") - raw.count("}")
            if not started and "{" in raw:
                started = True
            if started:
                m = re.search(r"\bpub\s+(\w+)\s*:\s*([A-Za-z_]\w*(?:\s*<[^>]*>)?)", raw)
                if m:
                    fields.append((lines[j][0], m.group(1), m.group(2)))
            if started and depth <= 0:
                break
            j += 1
        by_type: dict[str, list[tuple[int, str]]] = {}
        for line_no, name, ftype in fields:
            base = re.split(r"\s*<", ftype, 1)[0].strip()
            if base in {"Signer", "AccountInfo", "UncheckedAccount"}:
                continue
            by_type.setdefault(base, []).append((line_no, name))
        for base, occurrences in by_type.items():
            if len(occurrences) >= 2 and base in {"Account", "Program", "SystemAccount", "InterfaceAccount", "Interface"}:
                first_line = occurrences[0][0]
                window_start = max(0, first_line - 25)
                window = "\n".join(l for _, l in lines[window_start:first_line + 5])
                if re.search(r"\bconstraint\s*=\s*[^,)]*!=\s*[^,)]*key\(\)", window):
                    continue
                yield first_line, (
                    f"Duplicate account type {base} used for roles: "
                    f"{', '.join(name for _, name in occurrences)}; add constraint !="
                )
        i = j + 1


_SEED_LITERAL = re.compile(r"\bseeds\s*=\s*\[([^\]]*)\]")


@rule(
    "RS007",
    "PDA Sharing: seeds do not include a unique discriminator (state/user).",
    "warning",
    ["rust"],
)
def _rs007(path: Path, text: str) -> Iterable[tuple[int, str]]:
    code = _strip_comments(text)
    lines = list(_iter_lines(code))
    for line_no, attr, field in _iter_account_attrs(lines):
        if "seeds" not in attr:
            continue
        m = _SEED_LITERAL.search(attr)
        if not m:
            continue
        seed_body = m.group(1)
        parts = [p.strip() for p in seed_body.split(",") if p.strip()]
        if len(parts) <= 1:
            if parts and re.fullmatch(r'"[^"]*"|b"[^"]*"', parts[0]):
                yield line_no, (
                    "PDA seeds contain only a single literal; use a state/user-specific key."
                )
            continue
        has_key = any(".key()" in p or "as_ref()" in p for p in parts)
        if not has_key and all(re.fullmatch(r'"[^"]*"|b"[^"]*"|bump', p) for p in parts):
            yield line_no, (
                "PDA seeds contain only literals/bump; "
                "shared across instructions — PDA sharing risk."
            )


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def list_rules() -> list[Rule]:
    """Return all registered rules (sorted by rule_id)."""
    return sorted(RULES, key=lambda r: r.rule_id)


def _iter_source_files(root: Path, exclude: Sequence[str] | None = None) -> Iterator[Path]:
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
    rules: Sequence[str] | None = None,
    min_severity: str | None = None,
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
