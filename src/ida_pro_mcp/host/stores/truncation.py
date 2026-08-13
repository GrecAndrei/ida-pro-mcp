import contextlib
import copy
import json
import re
import secrets
import threading
import time
from collections import deque
from typing import Any

from ..errors import MCPError, make_error

# Minimum sensible token limit to prevent degenerate truncation
_MIN_MAX_TOKENS = 500
_MAX_TRUNCATION_STORE = 50
_TOKEN_TTL_SEC = 600  # 10 minutes
# Recursion guard for _truncate_recursive: a pathologically deep (or
# self-referential) response must not blow the interpreter stack and be
# misreported by the dispatcher as an IDA/connection failure.
_MAX_TRUNCATION_DEPTH = 64
# Per-value cap on the text search_truncated scans. Regexes run on the request
# thread against the FULL stored response, so a multi-MB value plus a hostile
# pattern could stall the call; bound the scanned window per value.
_SEARCH_MAX_CHARS = 1_000_000

_TRUNCATION_STORE: dict[str, dict[str, Any]] = {}
_TRUNCATION_ORDER: deque[str] = deque()
# Guards the two module-level stores above.  Truncation tokens are created and
# consumed from concurrently dispatched tool calls (ida_continue / search),
# so mutation must be serialized to avoid lost updates and partial entries.
_STORE_LOCK = threading.Lock()


def _prune_expired() -> None:
    """Remove tokens older than _TOKEN_TTL_SEC."""
    with _STORE_LOCK:
        now = time.time()
        expired = []
        for tok, entry in _TRUNCATION_STORE.items():
            if now - entry.get("created_at", 0) > _TOKEN_TTL_SEC:
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
    # big metadata blobs — alive for the token's 10-minute TTL.
    values: dict[str, Any] = {}
    for path in fields:
        value = _get_nested(response, path)
        if value is not None:
            values[path] = value
    with _STORE_LOCK:
        _TRUNCATION_STORE[token] = {
            "values": values,
            "fields": fields,
            "session_id": session_id or "",
            "owner_id": owner_id or "",
            "created_at": time.time(),
        }
        _TRUNCATION_ORDER.append(token)
        while len(_TRUNCATION_ORDER) > _MAX_TRUNCATION_STORE:
            oldest = _TRUNCATION_ORDER.popleft()
            _TRUNCATION_STORE.pop(oldest, None)
    return token


def _get_entry(token: str, session_id: str = "", owner_id: str = "") -> dict[str, Any] | None:
    """Retrieve a token entry, checking TTL, session, and owner scope."""
    _prune_expired()
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
    session_id: str = "",
    owner_id: str = "",
) -> dict[str, Any]:
    entry = _get_entry(token, session_id, owner_id=owner_id)
    if not entry:
        return make_error(
            MCPError.TRUNCATION_TOKEN_INVALID,
            "Unknown or expired continuation token",
        )

    field, err, value = _resolve_field(entry, field)
    if err:
        return err

    info = entry["fields"][field]

    if info.get("type") == "list" and isinstance(value, list):
        # The cursor (next_offset) is shared live state in the module-level
        # store; read-advance-write must be atomic so concurrent ida_continue
        # calls on the same token emit disjoint pages instead of overlapping
        # chunks with a lost update.
        with _STORE_LOCK:
            raw_next = info.get("next_offset", 0)
            start = max(0, int(raw_next)) if raw_next is not None and offset is None else max(0, int(offset or 0))
            chunk = count if count is not None else info.get("chunk_size", 0)
            if chunk <= 0:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "Invalid count for continuation",
                    hint="Pass count=N with N>0.",
                )
            items = value[start : start + chunk]
            next_offset = start + len(items)
            info["next_offset"] = next_offset
        return {
            "ok": True,
            "token": token,
            "field": field,
            "items": items,
            "offset": start,
            "count": len(items),
            "total": info.get("total", len(value)),
            "next_offset": next_offset if next_offset < info.get("total", len(value)) else None,
        }

    if info.get("type") == "string" and isinstance(value, str):
        with _STORE_LOCK:
            raw_next = info.get("next_offset", 0)
            start = max(0, int(raw_next)) if raw_next is not None and offset is None else max(0, int(offset or 0))
            chunk = count if count is not None else info.get("chunk_size", 0)
            if chunk <= 0:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "Invalid count for continuation",
                    hint="Pass count=N with N>0.",
                )
            text = value[start : start + chunk]
            next_offset = start + len(text)
            info["next_offset"] = next_offset
        return {
            "ok": True,
            "token": token,
            "field": field,
            "text": text,
            "offset": start,
            "count": len(text),
            "total": info.get("total", len(value)),
            "next_offset": next_offset if next_offset < info.get("total", len(value)) else None,
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

    return {
        "ok": True,
        "token": token,
        "fields": meta,
        "created_at": entry.get("created_at", 0),
        "ttl_remaining_sec": max(0, _TOKEN_TTL_SEC - (time.time() - entry.get("created_at", 0))),
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
    _depth: int = 0,
) -> Any:
    """Recursively truncate large lists and strings in nested structures."""
    if isinstance(obj, list) and len(obj) > 10:
        original_len = len(obj)
        keep_count = max(32, max_tokens // 200)
        if trunc_limit is not None and trunc_limit > 0:
            keep_count = min(keep_count, trunc_limit)
        if original_len > keep_count or trunc_offset is not None:
            start = max(0, trunc_offset or 0)
            end = start + keep_count
            truncated_fields[path] = {
                "type": "list",
                "total": original_len,
                "chunk_size": keep_count,
                "next_offset": min(end, original_len) if end < original_len else None,
            }
            return obj[start:end] if start < original_len else []
        return obj

    if isinstance(obj, str) and len(obj) > max_tokens:
        chunk_size = trunc_limit if trunc_limit is not None and trunc_limit > 0 else max_tokens
        start = max(0, trunc_offset or 0)
        end = start + chunk_size
        truncated_fields[path] = {
            "type": "string",
            "total": len(obj),
            "chunk_size": chunk_size,
            "next_offset": min(end, len(obj)) if end < len(obj) else None,
        }
        return obj[start:end] if start < len(obj) else ""

    if isinstance(obj, dict):
        # Bound descent so a pathologically deep (or self-referential)
        # response raises RecursionError instead of being misreported by the
        # dispatcher as an IDA/connection failure. Beyond the limit the subtree
        # is returned as-is; outer truncation already bounded the top level.
        if _depth >= _MAX_TRUNCATION_DEPTH:
            return obj
        return {
            k: _truncate_recursive(
                v, max_tokens, truncated_fields,
                path=f"{path}.{k}" if path else k,
                trunc_offset=trunc_offset,
                trunc_limit=trunc_limit,
                _depth=_depth + 1,
            )
            for k, v in obj.items()
        }

    return obj


# ─── Main truncation entry point ─────────────────────────────────────────────


def truncate_response(
    response: dict[str, Any],
    max_tokens: int = 4000,
    trunc_offset: int | None = None,
    trunc_limit: int | None = None,
    session_id: str = "",
    owner_id: str = "",
) -> dict[str, Any]:
    """
    Intelligently truncate large MCP responses to fit within LLM context windows.

    Args:
        response: The original tool response dictionary.
        max_tokens: Approximate character limit (roughly 1 char = 1 token for simplicity).
            Must be >= 500.
        trunc_offset: Start offset for paginating through truncated content.
        trunc_limit: Max items/chars to return when paginating.
        session_id: Scope the continuation token to this session.
        owner_id: Scope the continuation token to this MCP client connection.

    Returns:
        A pruned response with truncation markers. Original dict is never modified.
    """
    max_tokens = max(max_tokens, _MIN_MAX_TOKENS)

    if _estimate_size(response, max_tokens) < max_tokens and trunc_offset is None and trunc_limit is None:
        return response

    pruned = copy.deepcopy(response)
    pruned["_truncated"] = True
    truncated_fields: dict[str, dict[str, Any]] = {}

    # 1. Strip verbose metadata first
    _LOW_VALUE_KEYS = {"traceback", "raw_bytes", "hexdump_full"}
    for key in list(pruned.keys()):
        if key in _LOW_VALUE_KEYS and isinstance(pruned[key], str) and len(pruned[key]) > 200:
            pruned[key] = pruned[key][:200] + "... [stripped for context economy]"

    # 2. Recursively truncate nested lists and strings
    for key in list(pruned.keys()):
        value = pruned[key]
        pruned[key] = _truncate_recursive(
            value, max_tokens, truncated_fields,
            path=key,
            trunc_offset=trunc_offset,
            trunc_limit=trunc_limit,
        )

    if truncated_fields:
        token = _store_truncation(
            response,
            truncated_fields,
            session_id=session_id,
            owner_id=owner_id,
        )
        pruned["_continue"] = {
            "token": token,
            "fields": truncated_fields,
            "hint": (
                f"Call ida_continue(token='{token}', field='<field name>') when "
                "multiple fields are listed; use the exact key from fields. "
                "With one field, field is optional."
            ),
        }

    return pruned
