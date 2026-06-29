"""
Server argument normalization and wrapper parsing helpers.

Extracted from host/server.py so the main JSON-RPC server file is less monolithic.
"""

from __future__ import annotations

import contextlib
import json
import re
import shlex
import time
import uuid
from typing import Any, Dict, List, Optional

from ..config import _coerce_bool
from ..errors import MCPError, is_error_result, make_error
from ..schemas import (
    ACTION_ALIASES_BY_TOOL,
    ACTION_PREFIX_RE,
    ACTION_STRIP_CHARS,
    ARG_ALIASES_BY_TOOL,
    TOOL_ACTIONS,
    TOOL_ARG_SCHEMAS,
    WRAPPER_ACTIONS,
    _normalize_alias_lookup_key,
    _strip_balanced_wrappers,
)


class ServerArgsMixin:
    """Mixin for noisy-client argument normalization and wrapper helpers."""

    def _prune_next_cache(self):
        if not self._next_cache:
            return
        now = time.time()
        expired = [
            token
            for token, row in self._next_cache.items()
            if (now - float(row.get("created_at", 0.0)))
            > float(self._next_cache_ttl_seconds)
        ]
        for token in expired:
            self._next_cache.pop(token, None)

    def _parse_action_tail_tokens(self, tail: str) -> dict:
        parsed: Dict[str, Any] = {}
        if not tail:
            return parsed
        try:
            tokens = shlex.split(tail)
        except Exception:
            tokens = tail.split()
        positional: List[str] = []
        for token in tokens:
            if "=" in token:
                k, v = token.split("=", 1)
                key = _normalize_alias_lookup_key(k)
                val = _strip_balanced_wrappers(v)
                if key and key not in parsed:
                    parsed[key] = val
            else:
                cleaned = _strip_balanced_wrappers(token)
                if cleaned:
                    positional.append(cleaned)
        if positional:
            parsed.setdefault("_positional", " ".join(positional).strip())
        return parsed

    def _clean_action_text(self, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        text = ACTION_PREFIX_RE.sub("", text)
        text = text.strip().strip(",").strip()
        # Handle malformed fragments like action\":\"lookup addr=0x...
        text = text.strip(ACTION_STRIP_CHARS)
        text = ACTION_PREFIX_RE.sub("", text)
        text = text.strip().strip(",")
        # Keep multi-token action strings intact here so key=value tails survive tokenization;
        # individual tokens are cleaned in _parse_action_tail_tokens().
        if re.search(r"\s", text):
            return text
        return _strip_balanced_wrappers(text)

    def _normalize_field_variants(self, tool_name: str, out: dict) -> dict:
        """Accept high-noise LLM value wrappers for known fields without changing caller intent."""
        if not isinstance(out, dict):
            return out
        normalized = dict(out)
        int_like_fields = {
            "baseaddr",
            "start_ea",
            "min_ea",
            "max_ea",
            "limit",
            "offset",
            "head_n",
            "tail_n",
            "grep_limit",
            "grep_offset",
            "max_items",
        }
        wrapper_fields = {
            "action",
            "legacy_tool",
            "legacy_action",
            "profile",
            "scan_profile",
            "query",
            "pattern",
            "addr",
            "addrs",
            "session_id",
            "binary_path",
            "name",
            "tag",
            "snapshot_id",
            "source_id",
            "target_id",
            "field_name",
            "target",
        }
        schema = TOOL_ARG_SCHEMAS.get(tool_name, {})
        wrapper_fields.update(str(k) for k in schema.keys())
        for key, value in list(normalized.items()):
            if key not in wrapper_fields:
                continue
            if not isinstance(value, str):
                continue
            text = value.strip()
            if not text:
                continue
            cleaned = _strip_balanced_wrappers(text)
            if cleaned and cleaned != text:
                normalized[key] = cleaned
                value = cleaned
            # Accept bracketed list-like singletons such as "[0x401000]" as scalar.
            if key in {"addr", "pattern", "query", "session_id", "binary_path"} and (
                isinstance(value, str)
                and value.startswith("[")
                and value.endswith("]")
            ):
                inner = value[1:-1].strip()
                if inner and "," not in inner:
                    normalized[key] = _strip_balanced_wrappers(inner)
            if key in int_like_fields and isinstance(value, str):
                with contextlib.suppress(Exception):
                    normalized[key] = int(value, 0)
        # For array-like address fields, gracefully normalize common malformed scalar wrappers.
        if "addrs" in normalized and isinstance(normalized["addrs"], str):
            text = normalized["addrs"].strip()
            if "," in text and not (text.startswith("{") and text.endswith("}")):
                normalized["addrs"] = [
                    _strip_balanced_wrappers(part.strip())
                    for part in text.split(",")
                    if part.strip()
                ]
                return normalized
            if text.startswith("[") and text.endswith("]"):
                inner = text[1:-1].strip()
                if inner:
                    if "," in inner:
                        normalized["addrs"] = [
                            _strip_balanced_wrappers(part.strip())
                            for part in inner.split(",")
                            if part.strip()
                        ]
                    else:
                        normalized["addrs"] = _strip_balanced_wrappers(inner)
        return normalized

    def _normalize_tool_call_args(self, tool_name: str, args: dict) -> dict:
        out = dict(args or {})
        valid_actions = TOOL_ACTIONS.get(tool_name, [])
        lower_map = {a.lower(): a for a in valid_actions}
        lower_map.update(ACTION_ALIASES_BY_TOOL.get(tool_name, {}))

        arg_aliases = ARG_ALIASES_BY_TOOL.get(tool_name, {})
        if arg_aliases:
            for raw_key in list(out.keys()):
                if not isinstance(raw_key, str):
                    continue
                normalized_key = _normalize_alias_lookup_key(raw_key)
                canonical_key = arg_aliases.get(normalized_key)
                if canonical_key and canonical_key not in out:
                    out[canonical_key] = out.pop(raw_key)

        action = out.get("action")
        if isinstance(action, dict):
            nested = dict(action)
            out.pop("action", None)
            for k, v in nested.items():
                out.setdefault(k, v)
            action = out.get("action")

        if isinstance(action, str):
            action_text = self._clean_action_text(action)
            if action_text.startswith("{") and action_text.endswith("}"):
                try:
                    payload = json.loads(action_text)
                except Exception:
                    payload = None
                if isinstance(payload, dict):
                    for k, v in payload.items():
                        out.setdefault(k, v)
                    action_text = self._clean_action_text(payload.get("action", ""))

            if action_text:
                parts = action_text.split(None, 1)
                base = self._clean_action_text(parts[0])
                if base.endswith("()"):
                    base = base[:-2]
                base = _strip_balanced_wrappers(base)
                mapped = lower_map.get(base.lower(), base)
                out["action"] = mapped
                if len(parts) > 1:
                    parsed_tail = self._parse_action_tail_tokens(parts[1].strip())
                    if arg_aliases:
                        normalized_tail = {}
                        for key, value in parsed_tail.items():
                            if isinstance(key, str):
                                canonical_key = arg_aliases.get(
                                    _normalize_alias_lookup_key(key), key
                                )
                            else:
                                canonical_key = key
                            normalized_tail[canonical_key] = value
                        parsed_tail = normalized_tail
                    for k, v in parsed_tail.items():
                        out.setdefault(k, v)
                    positional = parsed_tail.get("_positional")
                    if isinstance(positional, str) and positional:
                        schema = TOOL_ARG_SCHEMAS.get(tool_name, {})
                        if mapped in ("read", "sections") and tool_name == "wiki":
                            out.setdefault("topic", positional)
                        elif mapped == "search":
                            out.setdefault("query", positional)
                        # setdefault preserves any explicit addr/addrs supplied by the caller
                        # and only fills the positional fallback when those keys are absent.
                        elif "addrs" in schema:
                            out.setdefault("addrs", positional)
                        elif "addr" in schema:
                            out.setdefault("addr", positional)
                        elif "pattern" in schema:
                            out.setdefault("pattern", positional)
                    out.pop("_positional", None)
            else:
                out.pop("action", None)
        elif action is not None and valid_actions:
            out.pop("action", None)

        if "action" not in out and valid_actions:
            for candidate_key in ("subaction",):
                candidate = out.get(candidate_key)
                if isinstance(candidate, str):
                    mapped = lower_map.get(self._clean_action_text(candidate).lower())
                    if mapped:
                        out["action"] = mapped
                        break

        # Compatibility cleanup: many clients send wrapper/meta keys to direct
        # tool actions. Keep them for wrapper actions, otherwise drop unknown
        # wrapper noise so strict tool signatures don't fail with INVALID_ARGS.
        action_name = out.get("action")
        if not (isinstance(action_name, str) and action_name in WRAPPER_ACTIONS):
            # Always strip wrapper-only helper keys for direct actions, even if
            # a broad schema includes them. This keeps noisy client payloads
            # (empty grep/pick/head/next fields) from polluting tool calls.
            wrapper_noise = {
                "source_action", "target_action", "on", "subaction",
                "grep", "grep_pattern", "grep_regex", "grep_case_sensitive",
                "grep_invert", "grep_field", "grep_limit", "grep_offset",
                "pick_fields", "pick_omit", "head_n", "tail_n",
                "next_token", "token", "cursor", "stats_include_payload",
            }
            for k in tuple(wrapper_noise):
                if k == "subaction" and tool_name == "query":
                    continue
                if tool_name == "truncation" and k in {"token", "next_token", "cursor"}:
                    continue
                out.pop(k, None)
        return self._normalize_field_variants(tool_name, out)

    def _wrapper_source_action(
        self, tool_name: str, args: dict, wrapper_action: str
    ) -> tuple[Optional[str], Optional[dict]]:
        native_actions = set(TOOL_ACTIONS.get(tool_name, []) or [])
        source_action = (
            args.get("source_action")
            or args.get("target_action")
            or args.get("on")
            or args.get("subaction")
        )
        if not source_action or not isinstance(source_action, str):
            # Prefer list-style source if available, so head/grep/pick can be used tersely.
            if "list" in native_actions:
                return "list", None
            return None, make_error(
                MCPError.INVALID_ARGS,
                f"action='{wrapper_action}' requires source_action",
                hint=(
                    f"Example: {tool_name}(action='{wrapper_action}', source_action='list'). "
                    "Aliases: on, target_action, subaction."
                ),
            )
        source_action = source_action.strip()
        if not source_action:
            return None, make_error(
                MCPError.INVALID_ARGS, "source_action cannot be empty"
            )
        if source_action in WRAPPER_ACTIONS and source_action not in native_actions:
            return None, make_error(
                MCPError.INVALID_ARGS,
                f"source_action cannot be '{source_action}'",
                hint=f"Use a concrete tool action first, then action='{wrapper_action}'.",
            )
        return source_action, None

    def _strip_wrapper_args(self, args: dict) -> dict:
        child_args = dict(args or {})
        for key in (
            "source_action",
            "target_action",
            "on",
            "subaction",
            "grep",
            "grep_pattern",
            "grep_regex",
            "grep_case_sensitive",
            "grep_invert",
            "grep_field",
            "grep_limit",
            "grep_offset",
            "pick_fields",
            "pick_omit",
            "head_n",
            "tail_n",
            "next_token",
            "token",
            "cursor",
            "stats_include_payload",
        ):
            child_args.pop(key, None)
        return child_args

    def _lineify_item(self, item: Any) -> str:
        if isinstance(item, str):
            return item.strip()
        if isinstance(item, dict):
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if item is None:
            return ""
        return str(item).strip()

    def _collect_wrapper_items(
        self, payload: Any, field: Optional[str] = None
    ) -> tuple[list[Any], str, str]:
        if isinstance(payload, dict):
            if field:
                value = payload.get(field)
                if isinstance(value, str):
                    return (
                        [line for line in value.splitlines() if line.strip()],
                        field,
                        "string",
                    )
                if isinstance(value, list):
                    return list(value), field, "list"
                if value is None:
                    return [], field, "list"
                return [value], field, "list"
            for key in (
                "sessions",
                "bookmarks",
                "macros",
                "items",
                "results",
                "matches",
                "functions",
                "findings",
                "usages",
                "callers",
                "callees",
                "content",
                "sections",
                "names",
                "strings",
                "imports",
                "code_refs",
                "data_refs",
            ):
                if key not in payload:
                    continue
                value = payload.get(key)
                if isinstance(value, str):
                    return (
                        [line for line in value.splitlines() if line.strip()],
                        key,
                        "string",
                    )
                if isinstance(value, list):
                    return list(value), key, "list"
            return [payload], "payload", "list"
        if isinstance(payload, list):
            return list(payload), "payload", "list"
        if isinstance(payload, str):
            return (
                [line for line in payload.splitlines() if line.strip()],
                "payload",
                "string",
            )
        if payload is None:
            return [], "payload", "list"
        return [payload], "payload", "list"

    def _cache_next_page(self, tool_name: str, args: dict, payload: Any) -> Any:
        if not isinstance(payload, dict) or is_error_result(payload):
            return payload
        if not _coerce_bool(payload.get("truncated"), False):
            return payload
        try:
            offset = int(payload.get("offset", args.get("offset", 0)) or 0)
            count = int(payload.get("count", 0) or 0)
            total = int(payload.get("total", 0) or 0)
        except Exception:
            return payload
        next_offset = payload.get("next_offset")
        if next_offset is None and total > (offset + count):
            next_offset = offset + count
        try:
            next_offset = int(next_offset)
        except Exception:
            return payload
        if next_offset <= offset:
            return payload

        self._prune_next_cache()
        token = uuid.uuid4().hex[:12].upper()
        action = args.get("action")
        if not isinstance(action, str) or not action.strip():
            return payload
        cache_args = dict(args)
        cache_args.pop("next_token", None)
        cache_args.pop("token", None)
        cache_args.pop("cursor", None)
        self._next_cache[token] = {
            "tool": tool_name,
            "action": action,
            "args": cache_args,
            "next_offset": next_offset,
            "created_at": time.time(),
        }
        out = dict(payload)
        out["next_token"] = token
        out["next_offset"] = next_offset
        return out
