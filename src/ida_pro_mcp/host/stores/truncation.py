
import copy
import json
import uuid
from collections import deque
from typing import Any

from ..errors import MCPError, make_error

# Minimum sensible token limit to prevent degenerate truncation
_MIN_MAX_TOKENS = 500
_MAX_TRUNCATION_STORE = 20
_TRUNCATION_STORE: dict[str, dict[str, Any]] = {}
_TRUNCATION_ORDER: deque[str] = deque()

def _store_truncation(response: dict[str, Any], fields: dict[str, dict[str, Any]]) -> str:
    token = uuid.uuid4().hex[:8].upper()
    _TRUNCATION_STORE[token] = {"response": response, "fields": fields}
    _TRUNCATION_ORDER.append(token)
    while len(_TRUNCATION_ORDER) > _MAX_TRUNCATION_STORE:
        oldest = _TRUNCATION_ORDER.popleft()
        _TRUNCATION_STORE.pop(oldest, None)
    return token

def continue_truncated(
    token: str,
    field: str | None = None,
    offset: int | None = None,
    count: int | None = None,
) -> dict[str, Any]:
    entry = _TRUNCATION_STORE.get(token)
    if not entry:
        return make_error(
            MCPError.TRUNCATION_TOKEN_INVALID,
            "Unknown or expired continuation token",
        )

    fields = entry.get("fields", {})
    if not fields:
        return make_error(
            MCPError.TRUNCATION_TOKEN_INVALID,
            "No truncated fields available for this token",
        )

    if field is None:
        if len(fields) == 1:
            field = next(iter(fields))
        else:
            err = make_error(
                MCPError.TRUNCATION_FIELD_MISSING,
                "field is required when multiple truncated fields exist",
            )
            err["fields"] = sorted(fields.keys())
            return err

    info = fields.get(field)
    if not info:
        err = make_error(MCPError.TRUNCATION_FIELD_MISSING, f"Unknown field: {field}")
        err["fields"] = sorted(fields.keys())
        return err

    response = entry.get("response", {})
    value = response.get(field)
    if value is None:
        return make_error(
            MCPError.TRUNCATION_FIELD_MISSING,
            f"Field not found in response: {field}",
        )

    if info.get("type") == "list" and isinstance(value, list):
        start = info.get("next_offset", 0) if offset is None else max(0, int(offset))
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
        start = info.get("next_offset", 0) if offset is None else max(0, int(offset))
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

def truncate_response(response: dict[str, Any], max_tokens: int = 4000) -> dict[str, Any]:
    """
    Intelligently truncate large MCP responses to fit within LLM context windows.

    Args:
        response: The original tool response dictionary.
        max_tokens: Approximate character limit (roughly 1 char = 1 token for simplicity).
            Must be >= 500.

    Returns:
        A pruned response with truncation markers. Original dict is never modified.
    """
    max_tokens = max(max_tokens, _MIN_MAX_TOKENS)

    # 1. Check if the total size is already within limits
    resp_str = json.dumps(response)
    if len(resp_str) < max_tokens:
        return response

    pruned = copy.deepcopy(response)
    pruned["_truncated"] = True
    truncated_fields: dict[str, dict[str, Any]] = {}

    # 2. Strip verbose metadata first (low-value fields for LLMs)
    _LOW_VALUE_KEYS = {"traceback", "raw_bytes", "hexdump_full"}
    for key in list(pruned.keys()):
        if key in _LOW_VALUE_KEYS and isinstance(pruned[key], str) and len(pruned[key]) > 200:
            pruned[key] = pruned[key][:200] + "... [stripped for context economy]"

    # 3. Target high-frequency list keys (functions, strings, matches, etc.)
    # We look for lists that are likely the source of the bloat
    for key in list(pruned.keys()):
        value = pruned[key]
        if isinstance(value, list) and len(value) > 10:
            # We found a large list. Prune it.
            original_len = len(value)

            # Keep the first N items until we hit the limit
            # We estimate 200 chars per item for safety
            keep_count = max(5, (max_tokens // 200))

            if original_len > keep_count:
                pruned[key] = value[:keep_count]
                pruned[f"{key}_total_count"] = original_len
                pruned[f"{key}_note"] = f"Showing first {keep_count} of {original_len} items. Use truncation(action='continue', token='...', field='{key}') to read more, or use offset/count parameters on the original tool call."
                truncated_fields[key] = {
                    "type": "list",
                    "total": original_len,
                    "chunk_size": keep_count,
                    "next_offset": keep_count,
                }

    # 4. Handle massive single strings (e.g. decompilation, logs)
    for key in list(pruned.keys()):
        value = pruned[key]
        if isinstance(value, str) and len(value) > max_tokens:
            pruned[key] = value[:max_tokens] + "... [TRUNCATED]"
            pruned[f"{key}_original_size"] = len(value)
            truncated_fields[key] = {
                "type": "string",
                "total": len(value),
                "chunk_size": max_tokens,
                "next_offset": max_tokens,
            }

    if truncated_fields:
        token = _store_truncation(response, truncated_fields)
        pruned["_continue"] = {
            "token": token,
            "fields": truncated_fields,
            "hint": f"Use truncation(action='continue', token='{token}', field='...') to read more. Or re-run with offset/count params.",
        }

    return pruned
