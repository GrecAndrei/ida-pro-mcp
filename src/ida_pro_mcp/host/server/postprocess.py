"""Post-processing filter pipeline for tool results.

Applied AFTER normal tool execution. Filters are orthogonal to tool
actions — they are parameters, not actions.

Usage from any tool call:
    search(action="find", pattern="recv", grep="memcpy", limit=5)
    data(action="functions", head=10, field="functions")
    code(action="callers", addr="0x401000", pick=["items", "count"])
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..config import _bounded_int, _coerce_bool
from ..errors import MCPError, is_error_result, make_error

# Keys recognized as post-processing parameters.
PP_KEYS = frozenset({
    "grep", "grep_regex", "grep_invert", "grep_case",
    "head", "tail", "offset", "limit",
    "pick", "field", "next_token",
})

# Preferred fields for auto-detecting the "list" to operate on in a response.
_PREFERRED_LIST_FIELDS = (
    "items", "results", "matches", "functions", "findings", "usages",
    "callers", "callees", "content", "sections", "names", "strings",
    "imports", "code_refs", "data_refs", "sessions", "bookmarks", "macros",
)


def extract_post_process_params(args: dict) -> tuple[dict, dict]:
    """Split *args* into ``(tool_args, pp_params)``.

    Removes post-processing keys from ``tool_args`` so they are not sent
    to IDA.
    """
    tool_args = dict(args)
    pp_params = {}
    for key in PP_KEYS:
        if key in tool_args:
            pp_params[key] = tool_args.pop(key)
    return tool_args, pp_params


def has_post_process(pp_params: dict) -> bool:
    """True if any post-processing is requested."""
    return bool(pp_params)


def resolve_list_field(
    payload: Any, explicit_field: str | None
) -> tuple[list, str]:
    """Find the best list in *payload* to operate on.

    Returns ``(items, field_name)``.  Prefers *explicit_field*, then
    auto-detects from ``_PREFERRED_LIST_FIELDS``, then falls back to the
    largest list in the dict.
    """
    if not isinstance(payload, dict):
        if isinstance(payload, list):
            return list(payload), "payload"
        return [], "payload"

    # Explicit field
    if explicit_field:
        value = payload.get(explicit_field)
        if isinstance(value, list):
            return list(value), explicit_field
        if isinstance(value, str):
            return [ln for ln in value.splitlines() if ln.strip()], explicit_field
        return [], explicit_field

    # Auto-detect from preferred fields
    for key in _PREFERRED_LIST_FIELDS:
        if key not in payload:
            continue
        value = payload.get(key)
        if isinstance(value, list) and value:
            return list(value), key
        if isinstance(value, str) and value.strip():
            return [ln for ln in value.splitlines() if ln.strip()], key

    # Fallback: largest list
    best_key = "payload"
    best_list: list = []
    for key, value in payload.items():
        if isinstance(value, list) and len(value) > len(best_list):
            best_key, best_list = key, list(value)
    return best_list, best_key


def item_search_text(item: Any) -> list[str]:
    """Recursively extract all string values from a structured item."""
    out: list[str] = []
    stack: list[Any] = [item]
    while stack:
        cur = stack.pop()
        if isinstance(cur, str):
            if cur.strip():
                out.append(cur)
        elif isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, (list, tuple)):
            stack.extend(cur)
        else:
            s = str(cur)
            if s:
                out.append(s)
    return out


def apply_grep(items: list, pp: dict) -> list:
    """Filter *items* by grep pattern."""
    pattern = pp.get("grep")
    if not pattern:
        return items

    is_regex = _coerce_bool(pp.get("grep_regex"), False)
    case_sensitive = _coerce_bool(pp.get("grep_case"), False)
    invert = _coerce_bool(pp.get("grep_invert"), False)

    if is_regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            rx = re.compile(pattern, flags)
        except re.error as e:
            raise ValueError(f"Invalid grep regex: {e}") from e
        def match_fn(texts):
            return any(rx.search(t) for t in texts)
    else:
        # Case sensitivity is fully handled below (needle is pre-lowered and
        # texts are lowered when not case-sensitive), so a single matcher
        # serves both branches.
        needle = pattern if case_sensitive else pattern.lower()

        def match_fn(texts):
            return any(needle in t for t in texts)

    result = []
    for item in items:
        texts = item_search_text(item)
        if not case_sensitive and not is_regex:
            texts = [t.lower() for t in texts]
        matched = match_fn(texts)
        if matched != invert:
            result.append(item)
    return result


def apply_head_tail(items: list, pp: dict) -> tuple[list, int]:
    """Apply head/tail/offset slicing.

    Returns ``(sliced_items, effective_offset)``.
    """
    head_n = pp.get("head") or pp.get("limit")
    tail_n = pp.get("tail")
    offset = _bounded_int(pp.get("offset"), 0, min_value=0, max_value=500_000)

    if offset > 0:
        items = items[offset:]

    if tail_n is not None:
        tail_n = _bounded_int(tail_n, 20, min_value=1, max_value=5000)
        if len(items) > tail_n:
            return items[-tail_n:], offset + max(0, len(items) - tail_n)
        return items, offset

    if head_n is not None:
        head_n = _bounded_int(head_n, 20, min_value=1, max_value=5000)
        return items[:head_n], offset

    return items, offset


def apply_pick(payload: Any, pp: dict) -> Any:
    """Project top-level fields from a dict payload."""
    pick_fields = pp.get("pick")
    if not pick_fields or not isinstance(payload, dict):
        return payload
    if isinstance(pick_fields, str):
        pick_fields = [f.strip() for f in pick_fields.split(",") if f.strip()]
    if not isinstance(pick_fields, list):
        return payload

    result = {}
    for key in pick_fields:
        if key in payload:
            result[key] = payload[key]
    return result


def _lineify(item: Any) -> str:
    if isinstance(item, str):
        return item
    return json.dumps(item, ensure_ascii=False, separators=(",", ":"))


def apply_post_processing(
    payload: Any,
    pp_params: dict,
) -> dict:
    """Full post-processing pipeline.  Returns a new result dict.

    Pipeline order:
    1. Resolve target field (auto-detect or explicit)
    2. Grep filter
    3. Head/tail + offset
    4. Pick (field projection)
    5. Build response envelope
    """
    # Pass through error results unchanged. The canonical error envelope from
    # make_error() is {"error": True, "code": ..., ...} — the old guards tested
    # `ok is False` and `error` as a dict, neither of which matches, so a real
    # error envelope would have been stamped ok:True and post-processed.
    if isinstance(payload, dict) and is_error_result(payload):
        return payload

    # If no filtering is requested, return as-is (don't add metadata).
    has_filters = any(
        pp_params.get(k) for k in ("grep", "head", "tail", "limit", "offset", "pick", "field")
    )
    if not has_filters:
        return payload

    if not isinstance(payload, dict):
        payload = {"ok": True, "data": payload}
    elif "ok" not in payload:
        payload = {**payload, "ok": True}

    field = pp_params.get("field")
    items, used_field = resolve_list_field(payload, field)

    if (
        field
        and isinstance(payload, dict)
        and used_field in payload
        and not isinstance(payload[used_field], (list, str))
    ):
        # The explicit field exists but is not list-shaped (e.g. a dict or an
        # int). There is nothing to post-process; leave the payload untouched
        # rather than overwriting the value with an empty list.
        return payload

    # 1. Grep
    if pp_params.get("grep"):
        try:
            items = apply_grep(items, pp_params)
        except ValueError as e:
            # An invalid grep regex is a caller error, not a silent pass-through
            # of the unfiltered result (the previous behavior: the caller's
            # broad except swallowed it at debug level and returned everything).
            return make_error(
                MCPError.INVALID_ARGS,
                f"Invalid grep pattern: {e}",
                hint="Check the grep pattern syntax (or set grep_regex=false for a plain substring match).",
            )

    # Pre-slice total: the number of items before head/tail/offset slicing.
    # Used by pagination continuation to decide whether more pages exist
    # without misreading the post-slice `_count` as the whole result.
    pre_slice_total = len(items)
    # When the tool already sliced server-side (data/list_* with a forwarded
    # offset/count), len(items) is the page length, not the whole result. The
    # tool's own `total` field is the authoritative pre-slice count, so prefer
    # it when present and numeric.
    payload_total = payload.get("total")
    if (
        isinstance(payload_total, (int, float))
        and not isinstance(payload_total, bool)
        and payload_total >= 0
        and used_field != "total"
    ):
        pre_slice_total = int(payload_total)

    # 2. Head/tail + offset
    items, offset = apply_head_tail(items, pp_params)

    # 3. Pick (field projection)
    pick_fields = pp_params.get("pick")
    if pick_fields:
        projected = apply_pick(payload, pp_params)
        if isinstance(projected, dict):
            projected[used_field] = items
            projected["_post_processed"] = True
            projected["_field"] = used_field
            projected["_count"] = len(items)
            projected["_total"] = pre_slice_total
            return projected

    # 4. Build standard envelope
    result = {**payload}
    result[used_field] = items
    result["_post_processed"] = True
    result["_field"] = used_field
    result["_count"] = len(items)
    result["_total"] = pre_slice_total
    result["_text"] = "\n".join(_lineify(it) for it in items)
    return result
