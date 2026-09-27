"""
Server argument normalization helpers.

Extracted from host/server.py so the main JSON-RPC server file is less monolithic.
"""

from __future__ import annotations

import json
import math
import re
import shlex
import threading
import time
import uuid
from typing import Any

from ..config import _coerce_bool
from ..errors import MCPError, is_error_result, make_error
from ..schemas import (
    ACTION_ALIASES_BY_TOOL,
    ACTION_PREFIX_RE,
    ACTION_STRIP_CHARS,
    ARG_ALIASES_BY_TOOL,
    TOOL_ACTIONS,
    TOOL_ARG_SCHEMAS,
    _normalize_alias_lookup_key,
    _strip_balanced_wrappers,
)


class ServerArgsMixin:
    """Mixin for noisy-client argument normalization."""

    def _next_cache_lock(self) -> threading.Lock:
        """Per-instance lock guarding the next_token continuation cache.

        The cache is written/read from request threads, batch workers and
        daemon connections concurrently; a prune iterating the dict while
        another thread inserts would raise RuntimeError and could evict a
        just-inserted token, breaking the continuation contract.

        Stored under ``_next_cache_lock_obj`` — never shadowing this method
        name, or ``getattr(self, ...)`` would resolve to the bound method and
        return it as the "lock".
        """
        lock = getattr(self, "_next_cache_lock_obj", None)
        if lock is None:
            lock = threading.Lock()
            self._next_cache_lock_obj = lock
        return lock

    def _prune_next_cache(self):
        if not self._next_cache:
            return
        now = time.time()
        with self._next_cache_lock():
            expired = []
            for token, row in list(self._next_cache.items()):
                if not isinstance(row, dict):
                    expired.append(token)
                    continue
                try:
                    created_at = float(row.get("created_at", 0.0))
                    ttl = float(self._next_cache_ttl_seconds)
                except (TypeError, ValueError, OverflowError):
                    expired.append(token)
                    continue
                if not math.isfinite(created_at) or not math.isfinite(ttl) or (
                    now - created_at
                ) > ttl:
                    expired.append(token)
            for token in expired:
                self._next_cache.pop(token, None)

    def _next_cache_scope(self, args: dict | None = None) -> tuple[str, str]:
        """Return the connection/agent and session scope for a page token.

        ``_next_cache`` is shared by all daemon connections on one server, so
        a token must carry the same isolation boundary as truncation tokens.
        Resolve an explicit ``idb`` target first; otherwise use the active
        connection/agent session.  Focused mixin tests and compatibility
        callers may not expose the full client-state mixin, so missing scope
        information remains empty and is handled fail-closed at lookup time.
        """
        owner_id = ""
        owner_fn = getattr(self, "_truncation_owner_id", None)
        if callable(owner_fn):
            try:
                owner_id = str(owner_fn() or "")
            except Exception:
                owner_id = ""

        session_id = ""
        if isinstance(args, dict) and args.get("idb"):
            resolver = getattr(self, "_resolve_session_from_idb_ref", None)
            if callable(resolver):
                try:
                    target = resolver(args.get("idb"))
                except Exception:
                    target = None
                if target is not None:
                    session_id = str(getattr(target, "session_id", "") or "")
        if not session_id:
            try:
                current = getattr(self, "current_session", None)
                session_id = str(getattr(current, "session_id", "") or "")
            except Exception:
                session_id = ""
        return session_id, owner_id

    def _parse_action_tail_tokens(self, tail: str) -> dict:
        parsed: dict[str, Any] = {}
        if not tail:
            return parsed
        try:
            tokens = shlex.split(tail)
        except Exception:
            tokens = tail.split()
        positional: list[str] = []
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
        # Preserve a JSON action object for the parser below.  Stripping
        # balanced wrappers first would turn {"action":"find",...} into a
        # fragment and make the action tail parser consume the remainder as a
        # malformed action name.
        if text.startswith("{") and text.endswith("}"):
            return text
        # Handle malformed fragments like action\":\"lookup addr=0x...
        if not re.search(r"\s", text):
            text = text.strip(ACTION_STRIP_CHARS)
        text = ACTION_PREFIX_RE.sub("", text)
        text = text.strip().strip(",")
        # Preserve a complete JSON object for the caller below.  The generic
        # balanced-wrapper cleanup would otherwise remove the outer braces,
        # making the explicit JSON-action parser unreachable.
        if text.startswith("{") and text.endswith("}"):
            return text
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
        wrapper_fields.update(str(k) for k in schema)
        # C-declaration fields legitimately end with ';' (and may contain ';'
        # internally); the wrapper stripper would eat the trailing ';' and the
        # IDA parser would reject the declaration. Never touch their text.
        _decl_like = {"decl", "type_str", "declaration", "prototype"}
        for key, value in list(normalized.items()):
            if key in _decl_like or key not in wrapper_fields:
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
                # Parse as decimal, except explicit 0x/0X hex (addresses like
                # baseaddr="0x401000"). int(value, 0) would silently reinterpret
                # a leading-zero numeric string as octal ("010" -> 8, "08" -> ValueError).
                try:
                    text_value = value.strip()
                    if text_value.lower().startswith("0x"):
                        normalized[key] = int(text_value, 16)
                    else:
                        normalized[key] = int(text_value, 10)
                except (ValueError, TypeError):
                    # Some schemas explicitly admit string values for a field
                    # (e.g. session baseaddr/start_ea are typed 'string'|'integer').
                    # Respect that union and keep the raw string for the tool to
                    # interpret; otherwise the unparseable value is a caller bug
                    # and forwarding it to the IDA bridge would fail obscurely —
                    # surface it instead of silently stripping/ignoring it.
                    _field_spec = schema.get(key) if isinstance(schema, dict) else None
                    _field_type = _field_spec.get("type") if isinstance(_field_spec, dict) else None
                    _allows_str = (
                        isinstance(_field_type, (list, tuple, set))
                        and "string" in _field_type
                    )
                    if _allows_str:
                        continue
                    return make_error(
                        MCPError.INVALID_ARGS,
                        f"Invalid integer for '{key}': {value!r}",
                        hint=(
                            f"Expected a decimal integer or 0x-hex value for "
                            f"'{key}' on tool '{tool_name}'."
                        ),
                    )
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
            # A non-string, non-dict action on a tool with a known action list
            # is malformed. Silently dropping it would run the tool's default
            # with no action and hide the caller's mistake — reject it instead,
            # consistent with the module's "reject unknown, don't silently
            # strip" rule.
            preview = ", ".join(str(a) for a in list(valid_actions)[:24])
            return make_error(
                MCPError.INVALID_ARGS,
                f"action must be a string for tool '{tool_name}', got {type(action).__name__}",
                hint=f"Valid actions: {preview}{'…' if len(valid_actions) > 24 else ''}",
            )

        if "action" not in out and valid_actions:
            for candidate_key in ("subaction",):
                candidate = out.get(candidate_key)
                if isinstance(candidate, str):
                    mapped = lower_map.get(self._clean_action_text(candidate).lower())
                    if mapped:
                        out["action"] = mapped
                        break

        return self._normalize_field_variants(tool_name, out)

    def _cache_next_page(
        self,
        tool_name: str,
        args: dict,
        payload: Any,
        *,
        scope: tuple[str, str] | None = None,
    ) -> Any:
        if not isinstance(payload, dict) or is_error_result(payload):
            return payload
        if not _coerce_bool(payload.get("truncated"), False):
            return payload
        # Post-processed results already have their continuation token managed
        # by _cache_post_process_next, which is PP-aware (slices the fetched
        # list rather than trusting the tool's raw pre-slice counters). A raw
        # tool-level token computed here from count/total would clobber that
        # token or double-mint one, silently skipping items. The same applies
        # to any payload that already carries a token.
        if payload.get("_post_processed"):
            return payload
        existing_token = payload.get("next_token")
        if isinstance(existing_token, str) and existing_token.strip():
            return payload
        try:
            # `dict.get` returns the args fallback only when the key is absent;
            # a tool that echoes ``"offset": null`` (JSON null for "no offset")
            # must not collapse the caller's real page offset to 0.
            offset_v = payload.get("offset")
            if offset_v is None:
                offset_v = args.get("offset", 0)
            count_v = payload.get("count")
            total_v = payload.get("total")
            offset = int(offset_v or 0)
            count = int(count_v or 0)
            total = int(total_v or 0)
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
        session_id, owner_id = scope or self._next_cache_scope(cache_args)
        with self._next_cache_lock():
            self._next_cache[token] = {
                "tool": tool_name,
                "action": action,
                "args": cache_args,
                "next_offset": next_offset,
                "session_id": session_id,
                "owner_id": owner_id,
                "created_at": time.time(),
            }
        out = dict(payload)
        out["next_token"] = token
        out["next_offset"] = next_offset
        return out
