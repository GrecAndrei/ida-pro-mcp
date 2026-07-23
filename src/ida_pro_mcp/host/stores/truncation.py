import contextlib
import copy
import json
import re
import time
import uuid
from collections import deque
from typing import Any

from ..errors import MCPError, make_error

# Minimum sensible token limit to prevent degenerate truncation
_MIN_MAX_TOKENS = 500
_MAX_TRUNCATION_STORE = 50
_TOKEN_TTL_SEC = 600  # 10 minutes

_TRUNCATION_STORE: dict[str, dict[str, Any]] = {}
_TRUNCATION_ORDER: deque[str] = deque()


def _prune_expired() -> None:
    """Remove tokens older than _TOKEN_TTL_SEC."""
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
) -> str:
    _prune_expired()
    token = uuid.uuid4().hex[:8].upper()
    _TRUNCATION_STORE[token] = {
        "response": response,
        "fields": fields,
        "session_id": session_id or "",
        "created_at": time.time(),
    }
    _TRUNCATION_ORDER.append(token)
    while len(_TRUNCATION_ORDER) > _MAX_TRUNCATION_STORE:
        oldest = _TRUNCATION_ORDER.popleft()
        _TRUNCATION_STORE.pop(oldest, None)
    return token


def _get_entry(token: str, session_id: str = "") -> dict[str, Any] | None:
    """Retrieve a token entry, checking TTL and session scope."""
    _prune_expired()
    entry = _TRUNCATION_STORE.get(token)
    if not entry:
        return None
    # Session scoping: when the entry was stored under a session, require an
    # exact match. Empty caller session_id must not unlock foreign tokens.
    entry_sid = entry.get("session_id", "")
    if entry_sid and session_id != entry_sid:
        return None
    return entry


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

    response = entry.get("response", {})
    value = response.get(field)
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
) -> dict[str, Any]:
    entry = _get_entry(token, session_id)
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
) -> dict[str, Any]:
    """Show truncation metadata without consuming data."""
    entry = _get_entry(token, session_id)
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


def search_truncated(
    token: str,
    pattern: str,
    field: str | None = None,
    is_regex: bool = False,
    case_sensitive: bool = False,
    limit: int = 50,
    session_id: str = "",
) -> dict[str, Any]:
    """Grep within the full original content without materializing it all."""
    entry = _get_entry(token, session_id)
    if not entry:
        return make_error(
            MCPError.TRUNCATION_TOKEN_INVALID,
            "Unknown or expired continuation token",
        )

    if not pattern:
        return make_error(MCPError.INVALID_ARGS, "pattern required")

    fields = entry.get("fields", {})
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
        def match_fn(text: str) -> bool:
            return bool(rx.search(text))
    else:
        needle = pattern if case_sensitive else pattern.lower()
        def match_fn(text: str) -> bool:
            t = text if case_sensitive else text.lower()
            return needle in t

    matches = []
    for fname in search_fields:
        value = response.get(fname)
        if value is None:
            continue
        if isinstance(value, list):
            for idx, item in enumerate(value):
                if len(matches) >= limit:
                    break
                text = json.dumps(item, ensure_ascii=False) if not isinstance(item, str) else item
                if match_fn(text):
                    matches.append({
                        "field": fname,
                        "index": idx,
                        "item": item if isinstance(item, (str, int, float, bool)) else item,
                    })
        elif isinstance(value, str):
            flags_re = 0 if case_sensitive else re.IGNORECASE
            for m in re.finditer(re.escape(pattern) if not is_regex else pattern, value, flags_re):
                if len(matches) >= limit:
                    break
                start = max(0, m.start() - 40)
                end = min(len(value), m.end() + 40)
                matches.append({
                    "field": fname,
                    "offset": m.start(),
                    "context": value[start:end],
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
) -> dict[str, Any]:
    """Generate a compact summary of truncated content."""
    entry = _get_entry(token, session_id)
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


def _truncate_recursive(
    obj: Any,
    max_tokens: int,
    truncated_fields: dict[str, dict[str, Any]],
    path: str = "",
    trunc_offset: int | None = None,
    trunc_limit: int | None = None,
) -> Any:
    """Recursively truncate large lists and strings in nested structures."""
    if isinstance(obj, list) and len(obj) > 10:
        original_len = len(obj)
        keep_count = max(5, max_tokens // 200)
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
        return {
            k: _truncate_recursive(
                v, max_tokens, truncated_fields,
                path=f"{path}.{k}" if path else k,
                trunc_offset=trunc_offset,
                trunc_limit=trunc_limit,
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

    Returns:
        A pruned response with truncation markers. Original dict is never modified.
    """
    max_tokens = max(max_tokens, _MIN_MAX_TOKENS)

    resp_str = json.dumps(response)
    if len(resp_str) < max_tokens and trunc_offset is None and trunc_limit is None:
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
        token = _store_truncation(response, truncated_fields, session_id=session_id)
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
