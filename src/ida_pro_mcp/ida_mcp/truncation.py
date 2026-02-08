
import copy
import json
import uuid
from collections import deque
from typing import Any, Dict, List, Union

# Minimum sensible token limit to prevent degenerate truncation
_MIN_MAX_TOKENS = 500
_MAX_TRUNCATION_STORE = 20
_TRUNCATION_STORE: Dict[str, Dict[str, Any]] = {}
_TRUNCATION_ORDER: deque[str] = deque()

def _store_truncation(response: Dict[str, Any], fields: Dict[str, Dict[str, Any]]) -> str:
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
) -> Dict[str, Any]:
    entry = _TRUNCATION_STORE.get(token)
    if not entry:
        return {"error": True, "message": "Unknown or expired continuation token"}

    fields = entry.get("fields", {})
    if not fields:
        return {"error": True, "message": "No truncated fields available for this token"}

    if field is None:
        if len(fields) == 1:
            field = next(iter(fields))
        else:
            return {
                "error": True,
                "message": "field is required when multiple truncated fields exist",
                "fields": sorted(fields.keys()),
            }

    info = fields.get(field)
    if not info:
        return {"error": True, "message": f"Unknown field: {field}", "fields": sorted(fields.keys())}

    response = entry.get("response", {})
    value = response.get(field)
    if value is None:
        return {"error": True, "message": f"Field not found in response: {field}"}

    if info.get("type") == "list" and isinstance(value, list):
        start = info.get("next_offset", 0) if offset is None else max(0, int(offset))
        chunk = count if count is not None else info.get("chunk_size", 0)
        if chunk <= 0:
            return {"error": True, "message": "Invalid count for continuation"}
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
            return {"error": True, "message": "Invalid count for continuation"}
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

    return {"error": True, "message": f"Field {field} is not a supported truncated type"}

def truncate_response(response: Dict[str, Any], max_tokens: int = 4000) -> Dict[str, Any]:
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
    truncated_fields: Dict[str, Dict[str, Any]] = {}
    
    # 2. Target high-frequency list keys (functions, strings, matches, etc.)
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
                pruned[f"{key}_note"] = f"Showing first {keep_count} of {original_len} items. Use 'offset' and 'count' parameters to read more."
                truncated_fields[key] = {
                    "type": "list",
                    "total": original_len,
                    "chunk_size": keep_count,
                    "next_offset": keep_count,
                }

    # 3. Handle massive single strings (e.g. decompilation, logs)
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
            "hint": "Use truncation(action='continue', token=..., field=...) to read more.",
        }

    return pruned
