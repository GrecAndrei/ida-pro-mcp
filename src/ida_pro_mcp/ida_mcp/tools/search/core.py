"""SEARCH.CORE — shared utilities, constants, and response normalization."""

import re as _re  # import first so wildcard can't shadow it
import time as _time
from collections import OrderedDict
from typing import Optional

try:
    from .._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

# Use _re throughout to guarantee stdlib re even if a module in the
# wildcard chain pollutes the local ``re`` binding (e.g. MagicMock in CI).
re = _re

try:
    from ...support.semantic_matching import (  # noqa: F401
        DEFAULT_RESCORE_TOP_N,
        normalize_action,
        semantic_score_cheap,
        semantic_scores,
        semantic_tokens,
    )
except ImportError:
    from support.semantic_matching import (  # type: ignore[import-not-found]
        DEFAULT_RESCORE_TOP_N,
        semantic_score_cheap,
        semantic_scores,
    )

# ============================================================================
# Module-Level Caches
# ============================================================================

_SEARCH_CACHE: OrderedDict[str, object] = OrderedDict()
_MAX_CACHE_SIZE = 64

# Database-level caches (invalidated when the IDB changes)
_MAX_DB_CACHE_ITEMS = 50000
_CONSTANT_DB_CACHE: Optional[dict] = None
_IMPORTS_CACHE: Optional[list] = None
_STRINGS_CACHE: Optional[list] = None
_DB_FINGERPRINT: Optional[str] = None


def _cache_key(prefix: str, *args) -> str:
    return f"{prefix}:{':'.join(str(a) for a in args)}"


def _cache_get(key: str):
    if key in _SEARCH_CACHE:
        _SEARCH_CACHE.move_to_end(key)
        return _SEARCH_CACHE[key]
    return None


def _cache_set(key: str, value) -> None:
    _SEARCH_CACHE[key] = value
    if len(_SEARCH_CACHE) > _MAX_CACHE_SIZE:
        _SEARCH_CACHE.popitem(last=False)



class SearchTimeout:
    """Simple timeout helper for long-running search loops."""
    def __init__(self, timeout_ms: int):
        self.deadline = _time.time() + (max(0, timeout_ms) / 1000.0) if timeout_ms > 0 else None

    def is_expired(self) -> bool:
        if self.deadline is None:
            return False
        return _time.time() >= self.deadline

    def check(self):
        if self.is_expired():
            raise TimeoutError("Search timeout exceeded")


def _get_db_fingerprint() -> str:
    """Generate a fingerprint for the current database state."""
    try:
        md5 = ida_nalt.retrieve_input_file_md5()
        if md5:
            # IDAPython returns the input-file MD5 as a lowercase hex string;
            # older bindings may yield bytes. Normalize so this fast path
            # actually runs instead of silently falling through to a full-DB
            # scan of every function, segment, and name on each access.
            return md5.decode("ascii") if isinstance(md5, bytes) else str(md5)
    except Exception:
        pass
    # Fallback: count functions + segments + total names
    func_count = sum(1 for _ in idautils.Functions())
    seg_count = sum(1 for _ in idautils.Segments())
    name_count = sum(1 for _ in idautils.Names())
    return f"fallback:{func_count}:{seg_count}:{name_count}"


def _db_changed() -> bool:
    """Check if the database has changed since our last cache."""
    global _DB_FINGERPRINT
    current = _get_db_fingerprint()
    if _DB_FINGERPRINT is None or current != _DB_FINGERPRINT:
        _DB_FINGERPRINT = current
        return True
    return False


def get_cached_constant_db() -> dict[int, str]:
    """Return cached constant DB, rebuilding if the database changed."""
    global _CONSTANT_DB_CACHE
    if _CONSTANT_DB_CACHE is None or _db_changed():
        _CONSTANT_DB_CACHE = build_constant_db()
    return _CONSTANT_DB_CACHE


def get_cached_imports() -> list[dict]:
    """Return cached import list, rebuilding if the database changed.

    Capped at _MAX_DB_CACHE_ITEMS to prevent memory bombs on huge databases.
    """
    global _IMPORTS_CACHE
    if _IMPORTS_CACHE is not None and not _db_changed():
        return _IMPORTS_CACHE
    imports = []
    for mod_idx in range(ida_nalt.get_import_module_qty()):
        mod_name = ida_nalt.get_import_module_name(mod_idx) or f"mod_{mod_idx}"

        def make_cb(mod, _imports=imports):
            def cb(ea, name, ordinal, _imports_inner=_imports):
                if name:
                    _imports_inner.append({"ea": ea, "name": name, "module": mod, "ordinal": ordinal})
                return True
            return cb

        ida_nalt.enum_import_names(mod_idx, make_cb(mod_name))
        if len(imports) >= _MAX_DB_CACHE_ITEMS:
            imports = imports[:_MAX_DB_CACHE_ITEMS]
            break
    _IMPORTS_CACHE = imports
    return imports


def get_cached_strings() -> list[dict]:
    """Return cached string list, rebuilding if the database changed.

    Capped at _MAX_DB_CACHE_ITEMS to prevent memory bombs on huge databases.
    """
    global _STRINGS_CACHE
    if _STRINGS_CACHE is not None and not _db_changed():
        return _STRINGS_CACHE
    strings = []
    for sc in safe_get_strlist_items():
        if len(strings) >= _MAX_DB_CACHE_ITEMS:
            break
        try:
            s = safe_get_strlit_contents(sc.ea)
            if s is not None:
                strings.append({"ea": sc.ea, "string": s})
        except Exception:
            pass
    _STRINGS_CACHE = strings
    return strings


# ============================================================================
# Configuration
# ============================================================================

_CANONICAL_TAGS = frozenset({
    "crypto", "network", "file_io", "registry", "process",
    "string_decode", "allocator", "exception_handler",
    "obfuscation", "compression", "hashing", "encoding",
    "parser", "main", "init", "cleanup", "loop",
    "recursive", "thunk", "library", "data",
})

MAX_LIMIT = 500
LINE_MAX = 240
_FIND_INSTRUCTION_CAP = 2000
_FIND_INSTRUCTION_LIMIT_MULTIPLIER = 40

SCORE_EXACT = 120.0
SCORE_SUBSTRING = 60.0
SCORE_TOKEN_OVERLAP = 45.0
SCORE_FUZZY = 20.0

MNEMONIC_BASE_SCORE = 95.0
MNEMONIC_GROUP_SCORE = 120.0
MNEMONIC_TOKEN_WEIGHT = 14.0
MNEMONIC_CAP = 160.0
MNEMONIC_THRESHOLD = 82.0

INSTRUCTION_CAP = 175.0
INSTRUCTION_TOKEN_WEIGHT = 10.0
INSTRUCTION_BASE_SCORE = 90.0
INSTRUCTION_THRESHOLD = 90.0
FIND_INSTRUCTION_MIN_SCORE = 88.0

def _get_xref_type(name: str, default: int) -> int:
    val = getattr(idaapi, name, default)
    return val if isinstance(val, int) else default

CALL_XREF_TYPES = frozenset([
    _get_xref_type("fl_CN", 17),
    _get_xref_type("fl_CF", 18),
    _get_xref_type("fl_JN", 19),
    _get_xref_type("fl_JF", 20),
    _get_xref_type("fl_F", 21)
])

SEARCH_ACTIONS = {
    "bytes", "string", "immediate", "name", "insns", "mnemonic", "instruction",
    "text", "operand", "comment", "data_ref", "code_ref", "regex", "func_by_sig",
    "find", "callers", "callees", "api", "vulnerable", "constants", "decompiled", "structured",
    "type", "export", "summary", "query_lang", "nl", "behavior",
    "bool", "neighborhood", "outlier", "fingerprint", "path", "reach", "noreach",
    "symbol", "symbol_info", "demangle", "xrefs_to_string",
}

SEARCH_ALIASES = {
    "byte": "bytes", "bytesearch": "bytes",
    "str": "string", "strings": "string", "literal": "string",
    "imm": "immediate", "constant": "immediate",
    "names": "name",
    "instruction_seq": "insns", "instruction_sequence": "insns",
    "instructions": "instruction", "mnemonics": "mnemonic", "mnem": "mnemonic",
    "opcode": "mnemonic", "opcodes": "mnemonic",
    "insn_text": "instruction", "instruction_text": "instruction",
    "asm_text": "instruction", "semantic_instruction": "instruction",
    "disasm": "text", "disassembly": "text",
    "ops": "operand", "operands": "operand",
    "comments": "comment",
    "xref": "code_ref", "xrefs": "code_ref",
    "datarefs": "data_ref", "coderefs": "code_ref",
    "function_signature": "func_by_sig", "signature": "func_by_sig",
    "lookup": "find", "discover": "find",
    # nl/natural_language → real nl action (bge-code-v1 embeddings)
    "natural_language": "nl", "embedding_search": "nl", "vector_search": "nl",
    "caller": "callers", "callee": "callees",
    "imports": "api", "import": "api", "apis": "api",
    "vuln": "vulnerable", "vulns": "vulnerable",
    "crypto_constants": "constants", "magic_constants": "constants",
    "pseudo": "decompiled", "pseudocode": "decompiled",
    "types": "type", "typedef": "type", "typeinfo": "type",
    "exports": "export", "exported": "export",
    "overview": "summary", "count": "summary", "stats": "summary",
    "tag": "behavior", "tags": "behavior", "classify": "behavior",
    # Combinator aliases
    "boolean": "bool", "query": "bool", "and_or": "bool",

    "context": "neighborhood", "neighbors": "neighborhood", "around": "neighborhood",
    "anomaly": "outlier", "anomalies": "outlier", "unusual": "outlier",
    "struct_sim": "fingerprint", "structural": "fingerprint", "similar_struct": "fingerprint",
    "shortest_path": "path", "callgraph_path": "path", "chain": "path",
    "reachable": "reach", "forward": "reach", "fanout": "reach",
    "unreachable": "noreach", "dead_code": "noreach", "orphan_reach": "noreach",
}

SEARCH_INTENT_PATTERNS = [
    (re.compile(r"^\s*(?:who\s+)?(?:callers?|calls?)\s+(?:of\s+)?(.+)$", re.IGNORECASE), "callers"),
    (re.compile(r"^\s*(?:what\s+)?callees?\s+(?:of\s+)?(.+)$", re.IGNORECASE), "callees"),
    (re.compile(r"^\s*(?:api|import)s?(?:\s+usage|\s+calls?)?\s+(?:of|for)?\s+(.+)$", re.IGNORECASE), "api"),
    (re.compile(r"^\s*(?:code\s+)?xrefs?\s+(?:to|for)\s+(.+)$", re.IGNORECASE), "code_ref"),
    (re.compile(r"^\s*data\s+xrefs?\s+(?:to|for)\s+(.+)$", re.IGNORECASE), "data_ref"),
    (re.compile(r"^\s*(?:decompiled|pseudocode)\s+(?:search\s+)?(?:for|of)?\s+(.+)$", re.IGNORECASE), "decompiled"),
    (re.compile(r"^\s*(?:mnemonic|opcode)s?\s+(?:search\s+)?(?:for|of)?\s+(.+)$", re.IGNORECASE), "mnemonic"),
    (re.compile(r"^\s*(?:instruction|assembly|asm)\s+(?:search\s+)?(?:for|of)?\s+(.+)$", re.IGNORECASE), "instruction"),
    (re.compile(r"^\s*(?:type|struct|typedef|union|enum)\s+(?:search\s+)?(?:for|of)?\s+(.+)$", re.IGNORECASE), "type"),
    (re.compile(r"^\s*(?:export|exported)\s+(?:search\s+)?(?:for|of)?\s+(.+)$", re.IGNORECASE), "export"),
    (re.compile(r"^\s*(?:summary|overview|count|stats)\s+(?:of|for)?\s+(.+)$", re.IGNORECASE), "summary"),
]

MNEMONIC_GROUPS = {
    "call": ("call", "bl", "blx", "jal", "jsr"),
    "branch": ("j", "b", "cb", "tb", "br"),
    "jump": ("j", "b", "br"),
    "return": ("ret", "retn", "bx", "jr", "blr"),
    "compare": ("cmp", "test", "cmn", "tst"),
    "move": ("mov", "lea", "ld", "st", "ldr", "str"),
    "arithmetic": ("add", "sub", "mul", "imul", "div", "idiv", "adc", "sbb"),
    "logic": ("and", "or", "xor", "not", "shl", "shr", "rol", "ror"),
    "stack": ("push", "pop", "enter", "leave"),
    "syscall": ("syscall", "sysenter", "svc", "ecall", "int"),
}

# ============================================================================
# Shared Helpers
# ============================================================================


def clip_text(text: Optional[str], max_len: int = LINE_MAX) -> str:
    if text is None:
        return ""
    compact = " ".join(str(text).split())
    if len(compact) <= max_len:
        return compact
    return compact[: max_len - 3] + "..."


def paginate_records(records, offset: int, limit: int, sort_key=None, reverse: bool = True):
    rows = list(records)
    if sort_key is not None:
        rows.sort(key=sort_key, reverse=reverse)
    total = len(rows)
    page = rows[offset : offset + limit]
    is_truncated = (offset + len(page)) < total
    return page, total, is_truncated


def _match_size_rule(size: int, op: str, val1: int, val2) -> bool:
    """True if a function of ``size`` bytes satisfies one parsed size rule.

    A parsed size rule is ``(op, val1, val2)`` where ``op`` is one of
    ``"==", ">", "<"`` and ``val2`` is an upper bound for range rules or
    ``None``.  Range bounds only apply when no comparator is present, so a
    comparator is never silently dropped (e.g. ``>100-200`` stays a ``>``
    rule spanning ``(val1, val2)``).
    """
    if op == ">":
        if val2 is not None:
            return val1 < size < val2
        return size > val1
    if op == "<":
        if val2 is not None:
            return val2 < size < val1
        return size < val1
    if val2 is not None:
        return val1 <= size <= val2
    return size == val1


def xref_count_limited(ea: int, max_count: int = 256) -> int:
    count = 0
    for _ in idautils.XrefsTo(ea, 0):
        count += 1
        if count >= max_count:
            break
    return count


def iter_segments(range_start=None, range_end=None, require_exec: bool = True):
    """Yield (seg_start, seg_end) for searchable segments."""
    if range_start is not None and range_end is not None:
        seg = idaapi.getseg(range_start)
        while seg and seg.start_ea < range_end:
            if not require_exec or (seg.perm & idaapi.SEGPERM_EXEC):
                yield (max(seg.start_ea, range_start), min(seg.end_ea, range_end))
            seg = idaapi.get_next_seg(seg.end_ea)
    else:
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg:
                continue
            if not require_exec or (seg.perm & idaapi.SEGPERM_EXEC):
                yield (seg.start_ea, seg.end_ea)


def iter_code(seg_start, seg_end):
    """Yield executable addresses within segment bounds."""
    ea = seg_start
    while ea < seg_end:
        if ida_bytes.is_code(ida_bytes.get_flags(ea)):
            yield ea
        ea = idc.next_head(ea, seg_end)
        if ea == idaapi.BADADDR:
            break


def build_response(matches, offset: int, limit: int, total_matches: int, truncated: bool, **extra):
    """Unified response builder for all search actions."""
    text = "\n".join(str(m) for m in matches)
    response = {
        "ok": True,
        "results": text,
        "count": len(matches),
        "total": total_matches,
        "offset": offset,
        "truncated": truncated,
    }
    response.update(extra)
    return response


def make_item(
    *,
    addr: str | int | None = None,
    name: str = "",
    type: str = "",
    score: float | None = None,
    snippet: str = "",
    **extra,
) -> dict:
    """Canonical structured hit for agents (always has ``addr`` as hex string when possible)."""
    if isinstance(addr, int):
        addr_s = hex(addr)
    else:
        addr_s = str(addr or "")
    item = {"addr": addr_s}
    if name:
        item["name"] = name
    if type:
        item["type"] = type
    if score is not None:
        try:
            item["score"] = round(float(score), 4)
        except (TypeError, ValueError):
            item["score"] = score
    if snippet:
        item["snippet"] = clip_text(snippet, LINE_MAX)
    item.update({k: v for k, v in extra.items() if v is not None})
    return item


_ADDR_RE = re.compile(r"^(0x[0-9A-Fa-f]+)")


def _item_from_text_line(line: str) -> dict:
    """Create a synthetic item dict from a text result line.

    Extracts the leading hex address (if present) as ``addr`` and
    keeps the full line as ``line``.
    """
    m = _ADDR_RE.match(line.strip())
    if m:
        return {"addr": m.group(1), "line": line.strip()}
    return {"line": line.strip()}


def normalize_search_result(response: dict, *, action: str = "", query: str = "") -> dict:
    """Normalize any search action payload for agent consumption.

    - Ensures ``ok``, ``action``, ``query``
    - Aliases ``matches`` ↔ ``results``
    - Ensures each item has ``addr`` (from address/ea)
    - Sets ``count`` from items when missing
    """
    if not isinstance(response, dict) or response.get("error"):
        return response
    out = dict(response)
    if action and not out.get("action"):
        out["action"] = action
    if query and not out.get("query") and not out.get("pattern"):
        out["query"] = query

    text = out.get("results")
    if text is None:
        text = out.get("matches")
    if text is not None:
        out["results"] = text
        out["matches"] = text

    items = out.get("items")
    if isinstance(items, list):
        fixed = []
        for it in items:
            if not isinstance(it, dict):
                continue
            row = dict(it)
            addr = row.get("addr") or row.get("address") or row.get("ea")
            if addr is not None and "addr" not in row:
                row["addr"] = hex(addr) if isinstance(addr, int) else str(addr)
            # drop redundant aliases once addr is set
            if row.get("addr"):
                row.setdefault("address", row["addr"])
            fixed.append(row)
        out["items"] = fixed
        if "count" not in out:
            out["count"] = len(fixed)
    elif isinstance(out.get("results"), str) and out["results"].strip():
        # Wrap text-only results into items[] so every action returns structured data.
        lines = [ln for ln in out["results"].splitlines() if ln.strip()]
        synthetic = []
        for ln in lines:
            item = _item_from_text_line(ln)
            if item:
                synthetic.append(item)
        if synthetic:
            out["items"] = synthetic
            if "count" not in out:
                out["count"] = len(synthetic)
    return out


def looks_like_identifier(pattern: str) -> bool:
    """True if pattern is name/import-like (not free-form NL or long text)."""
    p = (pattern or "").strip()
    if not p or len(p) > 96:
        return False
    if looks_like_address(p):
        return True
    # hex bytes pattern "48 89 e5" etc.
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}|\?\?|\?)(?:\s+(?:[0-9A-Fa-f]{2}|\?\?|\?)){1,}", p):
        return False
    if " " in p and not any(c in p for c in ("::", "(", "<")):
        # multi-word NL → not identifier
        return False
    return bool(re.match(r"^[\w@?$*.:<>~]+$", p))


def demangle_safe(name: str) -> str:
    if not name:
        return ""
    try:
        flags = idc.get_inf_attr(idc.INF_SHORT_DN)
    except Exception:
        flags = 0
    try:
        d = idc.demangle_name(name, flags)
        return d or name
    except Exception:
        return name


# ============================================================================
# Semantic Target Resolution
# ============================================================================


def resolve_target(
    raw_target: Optional[str],
    *,
    require_function: bool = False,
    include_imports: bool = False,
    semantic_min_score: float = 0.0,
    include_alternatives: bool = False,
):
    """Resolve a target name/address with short-circuiting."""
    if raw_target is None:
        return idaapi.BADADDR, "target is required", {}

    target = str(raw_target).strip()
    if not target:
        return idaapi.BADADDR, "target is required", {}

    # Fast path: exact address
    if looks_like_address(target):
        ea, err = validate_addr(target)
        if not err and ea != idaapi.BADADDR:
            if require_function and not idaapi.get_func(ea):
                return idaapi.BADADDR, f"No function at {hex(ea)}", {}
            return ea, None, {"match": "address"}

    # Fast path: exact name
    exact_ea = idc.get_name_ea_simple(target)
    if exact_ea != idaapi.BADADDR:
        if require_function and not idaapi.get_func(exact_ea):
            return idaapi.BADADDR, f"No function at {hex(exact_ea)}", {}
        return exact_ea, None, {"match": "exact_name"}

    # Fast path: substring unique name (case-insensitive)
    target_l = target.lower()
    substr_hits = []
    for sym_ea, sym_name in idautils.Names():
        if not sym_name:
            continue
        if target_l == sym_name.lower():
            if require_function and not idaapi.get_func(sym_ea):
                continue
            return sym_ea, None, {"match": "exact_name_ci", "resolved_name": sym_name}
        if target_l in sym_name.lower():
            if require_function and not idaapi.get_func(sym_ea):
                continue
            substr_hits.append((sym_ea, sym_name))
            if len(substr_hits) > 8:
                break
    if len(substr_hits) == 1:
        ea, nm = substr_hits[0]
        return ea, None, {"match": "unique_substring", "resolved_name": nm}

    # Fast path: demangled name exact / unique substring
    demangle_hits = []
    for sym_ea, sym_name in idautils.Names():
        if not sym_name or not (sym_name.startswith(("_Z", "?"))):
            continue
        dem = demangle_safe(sym_name)
        if not dem or dem == sym_name:
            continue
        if dem.lower() == target_l or target_l in dem.lower():
            if require_function and not idaapi.get_func(sym_ea):
                continue
            demangle_hits.append((sym_ea, sym_name, dem))
            if len(demangle_hits) > 8:
                break
    if len(demangle_hits) == 1:
        ea, nm, dem = demangle_hits[0]
        return ea, None, {"match": "demangled", "resolved_name": nm, "demangled": dem}

    # Fast path: blackboard custom name lookup (broader limit)
    try:
        from blackboard import BlackboardStore  # type: ignore
        store = BlackboardStore()
        bb_entries = store.list(limit=50, include_resolved=False) or []
        for entry in bb_entries:
            title = entry.get("title", "") or ""
            addr = entry.get("addr") or entry.get("address", "")
            if title and addr and target_l in title.lower():
                try:
                    bb_ea = int(addr, 16) if isinstance(addr, str) else int(addr)
                    if bb_ea != idaapi.BADADDR:
                        if require_function and not idaapi.get_func(bb_ea):
                            continue
                        return bb_ea, None, {"match": "blackboard_name", "blackboard_title": title}
                except Exception:
                    pass
    except Exception:
        pass

    # Slow path: semantic matching (names + demangled + imports)
    matcher = compile_smart_pattern(target, case_sensitive=False)
    prelim = []
    max_candidates = 512

    def record_candidate(ea, raw_name, display_name, kind, module_name=None, exact_bonus=0.0):
        quick_score = semantic_score_cheap(
            target, raw_name, substring_bonus=SCORE_SUBSTRING, include_fuzzy=False
        )
        if raw_name.lower() == target.lower():
            quick_score += exact_bonus
        prelim.append((quick_score, ea, raw_name, display_name, kind, module_name))

    for sym_ea, sym_name in idautils.Names():
        if not sym_name:
            continue
        dem = demangle_safe(sym_name)
        if not matcher(sym_name) and not (dem and matcher(dem)):
            continue
        is_func = bool(idaapi.get_func(sym_ea))
        if require_function and not is_func:
            continue
        display = dem if dem and dem != sym_name else sym_name
        record_candidate(sym_ea, sym_name, display, "function" if is_func else "symbol", exact_bonus=40.0)

    if include_imports:
        for mod_idx in range(ida_nalt.get_import_module_qty()):
            mod_name = ida_nalt.get_import_module_name(mod_idx) or f"mod_{mod_idx}"

            def make_cb(mod):
                def cb(import_ea, import_name, _ordinal):
                    if not import_name or not matcher(import_name):
                        return True
                    record_candidate(import_ea, import_name, f"{mod}!{import_name}", "import", mod, exact_bonus=45.0)
                    return True
                return cb

            ida_nalt.enum_import_names(mod_idx, make_cb(mod_name))

    if not prelim:
        return idaapi.BADADDR, f"Target '{target}' not found", {}

    prelim.sort(key=lambda r: (r[0], r[1]), reverse=True)
    pool = prelim[:max_candidates]
    scores = semantic_scores(
        target,
        [r[2] for r in pool],
        top_n=DEFAULT_RESCORE_TOP_N,
        substring_bonus=SCORE_SUBSTRING,
    )
    ranked = []
    for (_, cand_ea, raw_name, display_name, kind, module_name), final_score in zip(pool, scores, strict=False):
        if raw_name.lower() == target.lower():
            final_score += 45.0 if kind == "import" else 40.0
        ranked.append((final_score, cand_ea, display_name, kind, module_name))

    ranked.sort(key=lambda r: (r[0], r[1]), reverse=True)
    top_score, top_ea, top_name, top_kind, top_module = ranked[0]

    if require_function:
        top_func = idaapi.get_func(top_ea)
        if top_func:
            top_ea = top_func.start_ea

    if top_score < semantic_min_score:
        return idaapi.BADADDR, (
            f"Target '{target}' best semantic match below threshold "
            f"({top_score:.2f} < {semantic_min_score:.2f})"
        ), {}

    details = {
        "match": "semantic",
        "semantic_target": top_name,
        "semantic_kind": top_kind,
        "semantic_score": round(top_score, 2),
    }
    if top_kind == "import" and top_module:
        details["semantic_module"] = top_module
    if include_alternatives and len(ranked) > 1:
        details["semantic_alternatives"] = [
            {"name": r[2], "address": hex(r[1]), "kind": r[3], "score": round(r[0], 2)}
            for r in ranked[1:6]
        ]
    return top_ea, None, details


# ============================================================================
# Constant Database Builder
# ============================================================================


# ============================================================================
# IDA API Compatibility Wrappers
# ============================================================================


def safe_generate_disasm_line(ea):
    """Generate disassembly line with fallback for API changes across IDA versions."""
    if ea == idaapi.BADADDR:
        return None
    for fn in (
        lambda: ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_FORCE_CODE),
        lambda: ida_lines.generate_disasm_line(ea, 0),
        lambda: idc.generate_disasm_line(ea, 0),
    ):
        try:
            result = fn()
            if result:
                return result
        except Exception:
            continue
    return None


def safe_get_strlist_items():
    """Yield string info objects, using ida_strlist if available."""
    try:
        import ida_strlist
        for i in range(ida_strlist.get_strlist_qty()):
            si = ida_strlist.string_info_t()
            if ida_strlist.get_strlist_item(si, i):
                yield si
    except (ImportError, AttributeError):
        for i in range(idaapi.get_strlist_qty()):
            sc = idaapi.string_info_t()
            if idaapi.get_strlist_item(sc, i):
                yield sc


def safe_get_strlit_contents(ea):
    """Get string literal contents with version-agnostic fallback."""
    try:
        stype = idc.get_str_type(ea)
        if stype is not None and stype >= 0:
            s = idc.get_strlit_contents(ea, -1, stype)
            if s:
                return s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
    except Exception:
        pass
    try:
        s = idc.get_strlit_contents(ea)
        if s:
            return s.decode("utf-8", errors="replace") if isinstance(s, bytes) else s
    except Exception:
        pass
    return None


def build_constant_db() -> dict[int, str]:
    """Build dynamic constant database from _api_categories and crypto_id."""
    db = {}
    # Magic constants from _api_categories (imported via _common)
    if "MAGIC_CONSTANTS" in globals():
        db.update(MAGIC_CONSTANTS)

    # Crypto init constants
    from ida_pro_mcp.ida_mcp.support.crypto_registry import CRYPTO_CONSTANT_NAMES
    crypto_inits = CRYPTO_CONSTANT_NAMES
    db.update(crypto_inits)
    return db
