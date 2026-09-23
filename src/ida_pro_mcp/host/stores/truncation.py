import base64
import contextlib
import copy
import json
import os
import re
import secrets
import threading
import time
from collections import deque
from typing import Any

from ..errors import MCPError, make_error

# Minimum sensible token limit to prevent degenerate truncation
_MIN_MAX_TOKENS = 500
_DEFAULT_MAX_TRUNCATION_STORE = 500
_DEFAULT_TOKEN_TTL_SEC = 3600  # 1 hour (sliding window)

try:
    _MAX_TRUNCATION_STORE = int(
        os.environ.get("IDA_MCP_MAX_TRUNCATION_STORE", str(_DEFAULT_MAX_TRUNCATION_STORE))
    )
except Exception:
    _MAX_TRUNCATION_STORE = _DEFAULT_MAX_TRUNCATION_STORE

try:
    _TOKEN_TTL_SEC = float(
        os.environ.get("IDA_MCP_TRUNCATION_TTL", str(_DEFAULT_TOKEN_TTL_SEC))
    )
except Exception:
    _TOKEN_TTL_SEC = float(_DEFAULT_TOKEN_TTL_SEC)

# Recursion guard for _truncate_recursive: a pathologically deep (or
# self-referential) response must not blow the interpreter stack and be
# misreported by the dispatcher as an IDA/connection failure.
_MAX_TRUNCATION_DEPTH = 64
# Per-value cap on the text search_truncated scans. Regexes run on the request
# thread against the FULL stored response, so a multi-MB value plus a hostile
# pattern could stall the call; bound the scanned window per value.
_SEARCH_MAX_CHARS = 1_000_000

# Proof / evidence keys must never be soft-truncated (verifier lock).
# reason=policy_risk means refuse-to-truncate these fields, not drop them.
_PROOF_KEY_ALLOWLIST = frozenset({
    "risk_ack",
    "evidence",
    "policy",
    "proof",
    "governance",
    "policy_decision",
    "required_ack",
    "ack_required",
    "acks",
})

# Multi-field budget priority: lower number is protected longer / truncated later.
# Proof keys are hard-protected separately; this ranks everything else.
_FIELD_PRIORITY = {
    "code": 10,
    "annotated_code": 10,
    "disasm": 15,
    "disassembly": 15,
    "bytes": 20,
    "data": 25,
    "items": 30,
    "results": 30,
    "matches": 30,
    "xrefs": 30,
    "findings": 5,
    "traceback": 90,
    "raw_bytes": 95,
    "hexdump_full": 95,
}

_DETAIL_SCALE = {"triage": 0.5, "normal": 1.0, "deep": 2.0}

# Per-tool string char budgets (normal detail). detail scales ×0.5/1/2.
_TOOL_STRING_BUDGET = {
    "ida_decompile": 12_000,
    "decompile": 12_000,
    "code": 12_000,
    "ida_disassemble": 12_000,
    "disassemble": 12_000,
    "disasm": 12_000,
    "ida_read_bytes": 4_000,
    "read_bytes": 4_000,
    "bytes": 4_000,
}

# Per-tool list item budgets (normal detail).
_TOOL_LIST_BUDGET = {
    "ida_xrefs_to": 100,
    "ida_xrefs_from": 100,
    "xrefs": 100,
    "ida_search": 100,
    "search": 100,
    "ida_find": 100,
    "find": 100,
    "list": 100,
}

_DEFAULT_STRING_BUDGET = 4_000
_DEFAULT_LIST_BUDGET = 100


_TRUNCATION_STORE: dict[str, dict[str, Any]] = {}
_TRUNCATION_ORDER: deque[str] = deque()
# Guards the two module-level stores above.  Truncation tokens are created and
# consumed from concurrently dispatched tool calls (ida_continue / search),
# so mutation must be serialized to avoid lost updates and partial entries.
_STORE_LOCK = threading.Lock()


def _detail_scale(detail: str | None) -> float:
    key = str(detail or "normal").strip().lower()
    return _DETAIL_SCALE.get(key, 1.0)


def _resolve_budgets(
    tool_name: str = "",
    detail: str = "normal",
    max_tokens: int | None = None,
) -> tuple[int, int, int]:
    """Return (char_budget, list_budget, string_chunk) for this tool/detail."""
    scale = _detail_scale(detail)
    tool = str(tool_name or "").strip()
    # Prefer explicit max_tokens as the overall char envelope.
    base_chars = _TOOL_STRING_BUDGET.get(tool, _DEFAULT_STRING_BUDGET)
    base_list = _TOOL_LIST_BUDGET.get(tool, _DEFAULT_LIST_BUDGET)
    string_chunk = max(_MIN_MAX_TOKENS, int(base_chars * scale))
    list_budget = max(1, int(base_list * scale))
    if max_tokens is not None:
        char_budget = max(_MIN_MAX_TOKENS, int(max_tokens))
        # Explicit max_tokens also caps the string page size.
        string_chunk = min(string_chunk, char_budget)
    else:
        char_budget = string_chunk
    return char_budget, list_budget, string_chunk


def _is_proof_path(path: str) -> bool:
    if not path:
        return False
    parts = path.split(".")
    return any(p in _PROOF_KEY_ALLOWLIST for p in parts)


def _field_priority(path: str) -> int:
    if _is_proof_path(path):
        return -100  # never prefer truncating proof
    leaf = path.rsplit(".", maxsplit=1)[-1] if path else ""
    return _FIELD_PRIORITY.get(leaf, 50)


def _encode_cursor(token: str, field: str, offset: int) -> str:
    """Opaque store-bound cursor: token+field+offset (no HMAC theater)."""
    payload = {"t": token, "f": field, "o": int(offset)}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str) -> dict[str, Any] | None:
    if not cursor or not isinstance(cursor, str):
        return None
    try:
        pad = "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(cursor + pad)
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    token = data.get("t")
    field = data.get("f")
    offset = data.get("o")
    if not isinstance(token, str) or not isinstance(field, str):
        return None
    try:
        offset_i = int(offset)
    except Exception:
        return None
    if offset_i < 0:
        return None
    return {"token": token, "field": field, "offset": offset_i}


def _infer_reason(truncated_fields: dict[str, dict[str, Any]], refused_proof: bool) -> str:
    if refused_proof and not truncated_fields:
        return "policy_risk"
    types = {info.get("type") for info in truncated_fields.values()}
    if types == {"list"}:
        return "budget_items"
    if types == {"string"}:
        return "budget_chars"
    if "list" in types and "string" in types:
        return "budget_chars"
    return "budget_chars"


def _prune_expired() -> None:
    """Remove tokens older than _TOKEN_TTL_SEC since creation or last access."""
    with _STORE_LOCK:
        now = time.time()
        expired = []
        for tok, entry in _TRUNCATION_STORE.items():
            created_at = entry.get("created_at", 0)
            last_accessed = entry.get("last_accessed")
            if last_accessed is not None and last_accessed >= created_at:
                active_time = last_accessed
            else:
                active_time = created_at
            if now - active_time > _TOKEN_TTL_SEC:
                expired.append(tok)
        for tok in expired:
            _TRUNCATION_STORE.pop(tok, None)
            with contextlib.suppress(ValueError):
                _TRUNCATION_ORDER.remove(tok)


def _store_truncation(
    response: dict[str, Any],
    fields: dict[str, dict[str, Any]],
    session_id: str = "",
    owner_id: str = "",
) -> str:
    _prune_expired()
    token = secrets.token_urlsafe(16)
    # Store only the full originals of the fields that were actually truncated
    # (plus their metadata), not the whole response dict: continuation/search
    # re-slice exactly these values, and the pruned envelope (with the slices)
    # is what was already returned to the caller. Holding the full response
    # here kept every non-truncated key — including already-sliced payloads and
    # big metadata blobs — alive for the token's TTL.
    values: dict[str, Any] = {}
    for path in fields:
        value = _get_nested(response, path)
        if value is not None:
            values[path] = value
    now = time.time()
    with _STORE_LOCK:
        _TRUNCATION_STORE[token] = {
            "values": values,
            "fields": fields,
            "session_id": session_id or "",
            "owner_id": owner_id or "",
            "created_at": now,
            "last_accessed": None,
        }
        _TRUNCATION_ORDER.append(token)
        while len(_TRUNCATION_ORDER) > _MAX_TRUNCATION_STORE:
            oldest = _TRUNCATION_ORDER.popleft()
            _TRUNCATION_STORE.pop(oldest, None)
    return token


def _get_entry(token: str, session_id: str = "", owner_id: str = "") -> dict[str, Any] | None:
    """Retrieve a token entry, checking TTL, session, and owner scope."""
    _prune_expired()
    with _STORE_LOCK:
        entry = _TRUNCATION_STORE.get(token)
        if not entry:
            return None
        # Session scoping: when the entry was stored under a session, require an
        # exact match. Empty caller session_id must not unlock foreign tokens.
        entry_sid = entry.get("session_id", "")
        entry_owner = entry.get("owner_id", "")
        if entry_sid or entry_owner:
            # Scoped entry: require exact matches on whichever scope is bound.
            if entry_sid and session_id != entry_sid:
                return None
            if entry_owner and owner_id != entry_owner:
                return None
        elif session_id or owner_id:
            # Fail closed: a token stored with NO scope (private host-internal
            # path) must not be unlocked by a scoped caller. Only an equally
            # unscoped caller — the same private path that minted it — may
            # continue it, so a leaked token cannot be replayed across sessions.
            return None

        # Refresh sliding-window access time and maintain LRU order
        now = time.time()
        entry["last_accessed"] = now
        with contextlib.suppress(ValueError):
            _TRUNCATION_ORDER.remove(token)
        _TRUNCATION_ORDER.append(token)
        return entry


def _get_nested(container: Any, field: str) -> Any:
    """Resolve a dotted field path inside a nested response structure.

    ``field`` may be a top-level key (``"code"``) or a dotted path into nested
    lists and dicts (``"results.3.code"``).  List indices are parsed as ints;
    any unresolvable hop returns None rather than raising, so callers degrade
    to a clean "field not found" error instead of a 500.
    """
    if not isinstance(container, (dict, list)) or not field:
        return None
    if isinstance(container, dict) and field in container:
        return container[field]
    parts = field.split(".")
    current: Any = container
    for part in parts:
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError, TypeError):
                return None
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _resolve_field(
    entry: dict[str, Any], field: str | None
) -> tuple[str | None, dict[str, Any] | None, Any]:
    """Resolve field name, info dict, and value from an entry.

    Returns (field_name, field_info, value) or (None, error_dict, None).
    """
    fields = entry.get("fields", {})
    if not fields:
        return None, make_error(
            MCPError.TRUNCATION_TOKEN_INVALID,
            "No truncated fields available for this token",
        ), None

    if field is None:
        if len(fields) == 1:
            field = next(iter(fields))
        else:
            return None, make_error(
                MCPError.TRUNCATION_FIELD_MISSING,
                "field is required when multiple truncated fields exist",
                hint=(
                    "Pass field=<one of the listed fields> to ida_continue "
                    "using the exact name from _continue.fields."
                ),
                details={"fields": sorted(fields.keys()), "required_argument": "field"},
            ), None

    info = fields.get(field)
    if not info:
        return None, make_error(
            MCPError.TRUNCATION_FIELD_MISSING,
            f"Unknown field: {field}",
            hint=(
                "Pass field=<one of the listed fields> to ida_continue "
                "using the exact name from _continue.fields."
            ),
            details={"fields": sorted(fields.keys()), "required_argument": "field"},
        ), None

    # Resolve the value from the stored truncated-field originals first; the
    # dotted fallback covers entries minted before the slice-only store.
    values = entry.get("values", {})
    response = entry.get("response", {})
    if field in values:
        value = values[field]
    else:
        # Dotted-path resolution: the continuation field may name a nested list
        # element (e.g. "results.3.code") rather than a bare top-level key.
        value = _get_nested(response, field)
    if value is None:
        return None, make_error(
            MCPError.TRUNCATION_FIELD_MISSING,
            f"Field not found in response: {field}",
        ), None

    return field, None, value


def continue_truncated(
    token: str,
    field: str | None = None,
    offset: int | None = None,
    count: int | None = None,
    cursor: str | None = None,
    session_id: str = "",
    owner_id: str = "",
) -> dict[str, Any]:
    """Page truncated content.

    Prefer an opaque ``cursor`` (token+field+offset bound in the store entry).
    Pages are pure functions of the cursor — no shared ``next_offset`` mutation
    on the cursor path. Legacy offset / auto-advance still works without a cursor.
    """
    decoded = _decode_cursor(cursor) if cursor else None
    if cursor and decoded is None:
        return make_error(
            MCPError.TRUNCATION_TOKEN_INVALID,
            "Invalid continuation cursor",
            hint="Re-run the original operation to get a fresh _continue.cursor.",
        )
    if decoded is not None:
        if decoded["token"] != token:
            return make_error(
                MCPError.TRUNCATION_TOKEN_INVALID,
                "Cursor does not match continuation token",
                hint="Pass the token and cursor from the same _continue envelope.",
            )
        field = decoded["field"]
        offset = decoded["offset"]

    entry = _get_entry(token, session_id, owner_id=owner_id)
    if not entry:
        return make_error(
            MCPError.TRUNCATION_TOKEN_INVALID,
            "Unknown or expired continuation token",
            hint=(
                "Continuation tokens expire after 1 hour of inactivity or when the host server restarts. "
                "Re-run the original operation to get a fresh token."
            ),
        )

    field, err, value = _resolve_field(entry, field)
    if err:
        return err

    info = entry["fields"][field]
    use_cursor_path = decoded is not None or offset is not None

    if info.get("type") == "list" and isinstance(value, list):
        chunk = count if count is not None else info.get("chunk_size", 0)
        if chunk <= 0:
            return make_error(
                MCPError.INVALID_ARGS,
                "Invalid count for continuation",
                hint="Pass count=N with N>0.",
            )
        if use_cursor_path:
            start = max(0, int(offset or 0))
            items = value[start : start + chunk]
            next_offset = start + len(items)
            # Pure page: do not mutate shared next_offset.
        else:
            # Legacy auto-advance for callers that omit cursor/offset.
            with _STORE_LOCK:
                raw_next = info.get("next_offset", 0)
                start = max(0, int(raw_next)) if raw_next is not None else 0
                items = value[start : start + chunk]
                next_offset = start + len(items)
                info["next_offset"] = next_offset
        total = info.get("total", len(value))
        has_more = next_offset < total
        next_cursor = _encode_cursor(token, field, next_offset) if has_more else None
        return {
            "ok": True,
            "token": token,
            "field": field,
            "cursor": _encode_cursor(token, field, start),
            "items": items,
            "offset": start,
            "visible_offset": start,
            "visible_count": len(items),
            "count": len(items),
            "total": total,
            "next_offset": next_offset if has_more else None,
            "next_cursor": next_cursor,
            "has_more": has_more,
            "done": not has_more,
            "_continue": (
                {
                    "token": token,
                    "cursor": next_cursor,
                    "reason": "budget_items",
                    "fields": [
                        {
                            "path": field,
                            "type": "list",
                            "shown": len(items),
                            "total": total,
                            "unit": "items",
                        }
                    ],
                    "next": {
                        "tool": "ida_continue",
                        "args": {"token": token, "cursor": next_cursor, "field": field},
                    },
                }
                if has_more and next_cursor
                else None
            ),
        }

    if info.get("type") == "string" and isinstance(value, str):
        chunk = count if count is not None else info.get("chunk_size", 0)
        if chunk <= 0:
            return make_error(
                MCPError.INVALID_ARGS,
                "Invalid count for continuation",
                hint="Pass count=N with N>0.",
            )
        if use_cursor_path:
            start = max(0, int(offset or 0))
            page_text = value[start : start + chunk]
            next_offset = start + len(page_text)
        else:
            with _STORE_LOCK:
                raw_next = info.get("next_offset", 0)
                start = max(0, int(raw_next)) if raw_next is not None else 0
                page_text = value[start : start + chunk]
                next_offset = start + len(page_text)
                info["next_offset"] = next_offset
        total = info.get("total", len(value))
        has_more = next_offset < total
        text_bytes = page_text.encode("utf-8")
        prefix_bytes = len(value[:start].encode("utf-8"))
        next_offset_bytes = len(value[:next_offset].encode("utf-8")) if has_more else None
        next_cursor = _encode_cursor(token, field, next_offset) if has_more else None
        return {
            "ok": True,
            "token": token,
            "field": field,
            "cursor": _encode_cursor(token, field, start),
            "text": page_text,
            "offset": start,
            "visible_offset": start,
            "visible_count": len(page_text),
            "visible_offset_bytes": prefix_bytes,
            "visible_count_bytes": len(text_bytes),
            "total_bytes": len(value.encode("utf-8")),
            "next_offset_bytes": next_offset_bytes,
            "count": len(page_text),
            "total": total,
            "next_offset": next_offset if has_more else None,
            "next_cursor": next_cursor,
            "has_more": has_more,
            "done": not has_more,
            "_continue": (
                {
                    "token": token,
                    "cursor": next_cursor,
                    "reason": "budget_chars",
                    "fields": [
                        {
                            "path": field,
                            "type": "string",
                            "shown": len(page_text),
                            "total": total,
                            "unit": "chars",
                        }
                    ],
                    "next": {
                        "tool": "ida_continue",
                        "args": {"token": token, "cursor": next_cursor, "field": field},
                    },
                }
                if has_more and next_cursor
                else None
            ),
        }

    return make_error(
        MCPError.TRUNCATION_FIELD_MISSING,
        f"Field {field} is not a supported truncated type",
    )


def peek_truncated(
    token: str,
    session_id: str = "",
    owner_id: str = "",
) -> dict[str, Any]:
    """Show truncation metadata without consuming data."""
    entry = _get_entry(token, session_id, owner_id=owner_id)
    if not entry:
        return make_error(
            MCPError.TRUNCATION_TOKEN_INVALID,
            "Unknown or expired continuation token",
            hint=(
                "Continuation tokens expire after 1 hour of inactivity or when the host server restarts. "
                "Re-run the original operation to get a fresh token."
            ),
        )

    fields = entry.get("fields", {})
    meta = {}
    for fname, finfo in fields.items():
        ftype = finfo.get("type", "unknown")
        total = finfo.get("total", 0)
        chunk = finfo.get("chunk_size", 0)
        next_off = finfo.get("next_offset")
        meta[fname] = {
            "type": ftype,
            "total": total,
            "chunk_size": chunk,
            "next_offset": next_off,
            "remaining": max(0, total - (next_off or 0)) if next_off is not None else 0,
        }

    created_at = entry.get("created_at", 0)
    last_accessed = entry.get("last_accessed")
    active_time = last_accessed if (last_accessed is not None and last_accessed >= created_at) else created_at
    return {
        "ok": True,
        "token": token,
        "fields": meta,
        "created_at": created_at,
        "last_accessed": active_time,
        "ttl_remaining_sec": max(0, int(_TOKEN_TTL_SEC - (time.time() - active_time))),
    }


def _is_catastrophic_regex(pattern: str) -> bool:
    """Best-effort ReDoS guard for caller-supplied regex patterns.

    A quantified group that itself contains a quantifier (``(a+)+``, ``(a*)*``,
    ``(ab+)+``) can backtrack exponentially against adversarial text and would
    stall the request thread. Return True so the caller can reject the pattern
    up front with a clear error instead of timing out.
    """
    i = 0
    n = len(pattern)
    stack: list[bool] = []  # per open group: whether it already holds a quantifier
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            # Character classes make parens/quantifiers literal; skip them.
            i += 1
            while i < n and pattern[i] != "]":
                i += 2 if pattern[i] == "\\" else 1
            continue
        if ch == "(":
            stack.append(False)
        elif ch == ")":
            if not stack:
                return False
            has_quant = stack.pop()
            if i + 1 < n and pattern[i + 1] in "*+?":
                if has_quant:
                    return True
                if stack:
                    stack[-1] = True
        elif ch in "*+":
            if stack:
                stack[-1] = True
        i += 1
    return False


def search_truncated(
    token: str,
    pattern: str,
    field: str | None = None,
    is_regex: bool = False,
    case_sensitive: bool = False,
    limit: int = 50,
    session_id: str = "",
    owner_id: str = "",
) -> dict[str, Any]:
    """Grep within the full original content without materializing it all."""
    entry = _get_entry(token, session_id, owner_id=owner_id)
    if not entry:
        return make_error(
            MCPError.TRUNCATION_TOKEN_INVALID,
            "Unknown or expired continuation token",
            hint=(
                "Continuation tokens expire after 1 hour of inactivity or when the host server restarts. "
                "Re-run the original operation to get a fresh token."
            ),
        )

    if not pattern:
        return make_error(MCPError.INVALID_ARGS, "pattern required")

    fields = entry.get("fields", {})
    values = entry.get("values", {})
    response = entry.get("response", {})

    # Determine which fields to search
    search_fields = {}
    if field:
        if field not in fields:
            return make_error(
                MCPError.TRUNCATION_FIELD_MISSING,
                f"Unknown field: {field}",
                details={"fields": sorted(fields.keys())},
            )
        search_fields[field] = fields[field]
    else:
        search_fields = fields

    # Compile pattern
    if is_regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            rx = re.compile(pattern, flags)
        except re.error as e:
            return make_error(MCPError.INVALID_ARGS, f"Invalid regex: {e}")
        if _is_catastrophic_regex(pattern):
            return make_error(
                MCPError.INVALID_ARGS,
                "Regex pattern rejected: nested quantifiers can backtrack exponentially",
                hint="Simplify the pattern (avoid a quantified group inside another quantified group, e.g. `(a+)+`).",
            )
        def match_fn(text: str) -> bool:
            return bool(rx.search(text))
    else:
        needle = pattern if case_sensitive else pattern.lower()
        def match_fn(text: str) -> bool:
            t = text if case_sensitive else text.lower()
            return needle in t

    def _bounded(text: str) -> str:
        return text if len(text) <= _SEARCH_MAX_CHARS else text[:_SEARCH_MAX_CHARS]

    matches = []
    for fname in search_fields:
        if fname in values:
            value = values[fname]
        else:
            value = _get_nested(response, fname)
        if value is None:
            continue
        if isinstance(value, list):
            for idx, item in enumerate(value):
                if len(matches) >= limit:
                    break
                text = _bounded(json.dumps(item, ensure_ascii=False) if not isinstance(item, str) else item)
                if match_fn(text):
                    matches.append({
                        "field": fname,
                        "index": idx,
                        "item": item if isinstance(item, (str, int, float, bool)) else item,
                    })
        elif isinstance(value, str):
            flags_re = 0 if case_sensitive else re.IGNORECASE
            search_text = _bounded(value)
            for m in re.finditer(re.escape(pattern) if not is_regex else pattern, search_text, flags_re):
                if len(matches) >= limit:
                    break
                start = max(0, m.start() - 40)
                end = min(len(search_text), m.end() + 40)
                matches.append({
                    "field": fname,
                    "offset": m.start(),
                    "context": search_text[start:end],
                })

    return {
        "ok": True,
        "token": token,
        "pattern": pattern,
        "match_count": len(matches),
        "matches": matches,
        "truncated": len(matches) >= limit,
    }


def summary_truncated(
    token: str,
    field: str | None = None,
    limit: int = 20,
    session_id: str = "",
    owner_id: str = "",
) -> dict[str, Any]:
    """Generate a compact summary of truncated content."""
    entry = _get_entry(token, session_id, owner_id=owner_id)
    if not entry:
        return make_error(
            MCPError.TRUNCATION_TOKEN_INVALID,
            "Unknown or expired continuation token",
            hint=(
                "Continuation tokens expire after 1 hour of inactivity or when the host server restarts. "
                "Re-run the original operation to get a fresh token."
            ),
        )

    field_name, err, value = _resolve_field(entry, field)
    if err:
        return err

    if isinstance(value, list):
        total = len(value)
        # Category breakdown
        categories: dict[str, int] = {}
        sample_items = []
        for item in value:
            cat = "other"
            if isinstance(item, dict):
                cat = item.get("category") or item.get("type") or item.get("kind") or "dict"
                if not sample_items and item.get("addr"):
                    sample_items.append(item)
            elif isinstance(item, str):
                cat = "string"
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "ok": True,
            "token": token,
            "field": field_name,
            "type": "list",
            "total": total,
            "categories": categories,
            "sample": sample_items[:limit],
            "hint": f"Use truncation(action='continue', token='{token}', field='{field_name}') or search to explore.",
        }

    if isinstance(value, str):
        total_len = len(value)
        lines = value.splitlines()
        line_count = len(lines)
        # First/last lines as context
        first_lines = lines[:5]
        last_lines = lines[-5:] if line_count > 10 else []
        return {
            "ok": True,
            "token": token,
            "field": field_name,
            "type": "string",
            "total_chars": total_len,
            "total_lines": line_count,
            "first_lines": first_lines,
            "last_lines": last_lines,
            "hint": f"Use truncation(action='continue', token='{token}', field='{field_name}') or search to explore.",
        }

    return make_error(
        MCPError.TRUNCATION_FIELD_MISSING,
        f"Field {field_name} is not a supported truncated type",
    )


# ─── Nested truncation helper ────────────────────────────────────────────────


def _estimate_size(obj: Any, cap: int, _depth: int = 0) -> int:
    """Cheap O(n) serialized-size estimate that stops once *cap* is exceeded.

    Replaces the old ``len(json.dumps(response))`` probe, which allocated the
    full multi-MB JSON string for every response before deciding it was small.
    Walks the structure summing ``len()`` of strings and list/dict sizes, and
    bails out early once the caller's budget is exceeded (the common case for
    a large response that is about to be truncated anyway).
    """
    if _depth > _MAX_TRUNCATION_DEPTH:
        return 0
    if isinstance(obj, str):
        return len(obj) + 2  # approximates the two JSON quotes
    if isinstance(obj, dict):
        total = 2
        first = True
        for k, v in obj.items():
            if not first:
                total += 2  # `", "` separator
            first = False
            total += len(str(k)) + 4  # quotes + `": `
            total += _estimate_size(v, cap, _depth + 1)
            if total >= cap:
                return total
        return total
    if isinstance(obj, (list, tuple)):
        total = 2
        first = True
        for v in obj:
            if not first:
                total += 2  # `", "` separator
            first = False
            total += _estimate_size(v, cap, _depth + 1)
            if total >= cap:
                return total
        return total
    if obj is None:
        return 4
    return len(str(obj))


def _truncate_recursive(
    obj: Any,
    max_tokens: int,
    truncated_fields: dict[str, dict[str, Any]],
    path: str = "",
    trunc_offset: int | None = None,
    trunc_limit: int | None = None,
    list_budget: int | None = None,
    string_budget: int | None = None,
    _depth: int = 0,
) -> Any:
    """Recursively truncate large lists and strings in nested structures."""
    if _is_proof_path(path):
        # Never soft-truncate proof/evidence fields.
        return obj

    if isinstance(obj, list) and len(obj) > 10:
        original_len = len(obj)
        keep_count = list_budget if list_budget is not None else max(32, max_tokens // 200)
        # Cap by character budget so a tight max_tokens still pages fat item lists.
        keep_count = min(keep_count, max(1, max_tokens // 50))
        if trunc_limit is not None and trunc_limit > 0:
            keep_count = min(keep_count, trunc_limit)
        if original_len > keep_count or trunc_offset is not None:
            start = max(0, trunc_offset or 0)
            end = start + keep_count
            sliced = obj[start:end] if start < original_len else []
            visible_count = len(sliced)
            next_off = min(end, original_len) if end < original_len else None
            truncated_fields[path] = {
                "type": "list",
                "total": original_len,
                "chunk_size": keep_count,
                "offset": start,
                "visible_offset": start,
                "visible_count": visible_count,
                "next_offset": next_off,
                "unit": "items",
            }
            return sliced
        return obj

    string_limit = string_budget if string_budget is not None else max_tokens
    if isinstance(obj, str) and len(obj) > string_limit:
        chunk_size = trunc_limit if trunc_limit is not None and trunc_limit > 0 else string_limit
        start = max(0, trunc_offset or 0)
        end = start + chunk_size
        sliced = obj[start:end] if start < len(obj) else ""
        visible_count = len(sliced)
        next_off = min(end, len(obj)) if end < len(obj) else None
        truncated_fields[path] = {
            "type": "string",
            "unit": "chars",
            "total": len(obj),
            "total_bytes": len(obj.encode("utf-8")),
            "chunk_size": chunk_size,
            "offset": start,
            "visible_offset": start,
            "visible_count": visible_count,
            "visible_offset_bytes": len(obj[:start].encode("utf-8")),
            "visible_count_bytes": len(sliced.encode("utf-8")),
            "next_offset": next_off,
            "next_offset_bytes": len(obj[:next_off].encode("utf-8")) if next_off is not None else None,
        }
        return sliced

    if isinstance(obj, dict):
        if _depth >= _MAX_TRUNCATION_DEPTH:
            return obj
        # Truncate low-priority fields first so evidence/code keep budget longer.
        keys = sorted(obj, key=lambda k: _field_priority(f"{path}.{k}" if path else k), reverse=True)
        out: dict[str, Any] = {}
        for k in keys:
            child_path = f"{path}.{k}" if path else k
            out[k] = _truncate_recursive(
                obj[k], max_tokens, truncated_fields,
                path=child_path,
                trunc_offset=trunc_offset,
                trunc_limit=trunc_limit,
                list_budget=list_budget,
                string_budget=string_budget,
                _depth=_depth + 1,
            )
        # Preserve original key order in the returned dict.
        return {k: out[k] for k in obj}

    return obj


# ─── Main truncation entry point ─────────────────────────────────────────────


def truncate_response(
    response: dict[str, Any],
    max_tokens: int = 4000,
    trunc_offset: int | None = None,
    trunc_limit: int | None = None,
    session_id: str = "",
    owner_id: str = "",
    tool_name: str = "",
    detail: str = "normal",
) -> dict[str, Any]:
    """
    Intelligently truncate large MCP responses to fit within LLM context windows.

    Args:
        response: The original tool response dictionary.
        max_tokens: Approximate character limit (roughly 1 char = 1 token for simplicity).
            Must be >= 500. Explicit override still wins over per-tool budgets.
        trunc_offset: Start offset for paginating through truncated content.
        trunc_limit: Max items/chars to return when paginating.
        session_id: Scope the continuation token to this session.
        owner_id: Scope the continuation token to this MCP client connection.
        tool_name: Calling tool (ida_decompile, list/xref tools, …) for per-tool budgets.
        detail: Shared dial with Jev profiles — triage|normal|deep scales budgets.

    Returns:
        A pruned response with truncation markers. Original dict is never modified.
    """
    char_budget, list_budget, string_budget = _resolve_budgets(
        tool_name=tool_name, detail=detail, max_tokens=max_tokens
    )
    max_tokens = max(char_budget, _MIN_MAX_TOKENS)

    if _estimate_size(response, max_tokens) < max_tokens and trunc_offset is None and trunc_limit is None:
        return response

    pruned = copy.deepcopy(response)
    pruned["_truncated"] = True
    truncated_fields: dict[str, dict[str, Any]] = {}
    refused_proof = False

    # 1. Strip verbose metadata first (never proof keys)
    _LOW_VALUE_KEYS = {"traceback", "raw_bytes", "hexdump_full"}
    for key in list(pruned):
        if key in _PROOF_KEY_ALLOWLIST:
            continue
        if key in _LOW_VALUE_KEYS and isinstance(pruned[key], str) and len(pruned[key]) > 200:
            pruned[key] = pruned[key][:200] + "... [stripped for context economy]"

    # 2. Recursively truncate nested lists and strings (priority-ordered).
    # Process low-priority keys first so proof/findings/code keep budget.
    keys = sorted(
        [k for k in pruned if not str(k).startswith("_")],
        key=_field_priority,
        reverse=True,
    )
    for key in keys:
        if key in _PROOF_KEY_ALLOWLIST:
            # Detect oversized proof fields but refuse to truncate them.
            val = pruned[key]
            if (
                isinstance(val, str) and len(val) > string_budget
            ) or (isinstance(val, list) and len(val) > list_budget):
                refused_proof = True
            continue
        value = pruned[key]
        pruned[key] = _truncate_recursive(
            value, max_tokens, truncated_fields,
            path=key,
            trunc_offset=trunc_offset,
            trunc_limit=trunc_limit,
            list_budget=list_budget,
            string_budget=string_budget,
        )

    if truncated_fields:
        token = _store_truncation(
            response,
            truncated_fields,
            session_id=session_id,
            owner_id=owner_id,
        )
        field_list = []
        primary_cursor = None
        primary_field = None
        for path, info in truncated_fields.items():
            ftype = info.get("type", "string")
            unit = info.get("unit") or ("items" if ftype == "list" else "chars")
            shown = int(info.get("visible_count") or 0)
            total = int(info.get("total") or 0)
            start = int(info.get("offset") or 0)
            cursor = _encode_cursor(token, path, start)
            if primary_cursor is None:
                primary_cursor = cursor
                primary_field = path
            field_list.append(
                {
                    "path": path,
                    "type": ftype,
                    "shown": shown,
                    "total": total,
                    "unit": unit,
                    "cursor": cursor,
                }
            )
        reason = _infer_reason(truncated_fields, refused_proof=refused_proof)
        next_args: dict[str, Any] = {"token": token, "cursor": primary_cursor}
        if primary_field and len(field_list) > 1:
            next_args["field"] = primary_field
        pruned["_continue"] = {
            "token": token,
            "cursor": primary_cursor,
            "reason": reason,
            "fields": field_list,
            # Legacy dict shape kept for older clients/tests that key by path.
            "fields_by_path": truncated_fields,
            "next": {"tool": "ida_continue", "args": next_args},
            "hint": (
                f"Call ida_continue(token='{token}', cursor='…') or pass field when "
                "multiple fields are listed. Expired cursor → re-run the original."
            ),
        }
    elif refused_proof:
        # Oversized proof-only payload: do not strip; mark why we refused.
        pruned["_continue"] = {
            "token": None,
            "cursor": None,
            "reason": "policy_risk",
            "fields": [],
            "next": None,
            "hint": "Proof/evidence fields are never soft-truncated; raise max_tokens or page upstream.",
        }

    return pruned
