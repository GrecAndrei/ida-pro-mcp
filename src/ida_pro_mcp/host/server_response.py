"""
Server response compaction, filtering, and enrichment helpers.

Extracted from host/server.py to reduce the size of the main JSON-RPC server
class while keeping the same response behavior.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Optional

from .config import (
    _bounded_int,
    _coerce_bool,
    _parse_str_list,
    CONTEXT_DENSITY_DEFAULT_BUDGET,
    CONTEXT_DENSITY_COMPACT_THRESHOLD,
    CONTEXT_DENSITY_MAX_CODE_PREVIEW,
    CONTEXT_DENSITY_MAX_HEX_PREVIEW,
    CONTEXT_DENSITY_MAX_XREF_ITEMS,
    LLM_POINTER_SAFETY_NOTE,
    _POINTER_NOTE_HEX_RE,
    _POINTER_NOTE_MATH_RE,
    _POINTER_NOTE_SIGNAL_KEYWORDS,
    _POINTER_NOTE_SIGNAL_MAX_DEPTH,
    _POINTER_NOTE_SIGNAL_MAX_DICT_ITEMS,
    _POINTER_NOTE_SIGNAL_MAX_LIST_ITEMS,
    _POINTER_NOTE_SIGNAL_TOOLS_HINT,
    _POINTER_NOTE_SIGNAL_TOOLS_STRONG,
    _POINTER_NOTE_MAX_SIGNAL_MULTIPLIER,
    _COMPACT_DETAIL_LIST_KEYS,
    _COMPACT_DROP,
    _COMPACT_META_KEYS,
)
try:
    from ida_pro_mcp.ida_mcp.truncation import truncate_response
except ImportError:
    try:
        import importlib.util
        import os as _os
        _trunc_path = _os.path.join(
            _os.path.dirname(_os.path.abspath(__file__)), "..", "ida_mcp", "truncation.py"
        )
        _spec = importlib.util.spec_from_file_location("ida_mcp_truncation", _trunc_path)
        if _spec and _spec.loader:
            _module = importlib.util.module_from_spec(_spec)
            _spec.loader.exec_module(_module)
            truncate_response = _module.truncate_response
        else:
            raise ImportError("Unable to load truncation module")
    except Exception:
        def truncate_response(resp, **kwargs):
            return resp


class ServerResponseMixin:
    """Mixin for output compaction, pointer notes, and response enrichment."""

    def _extract_response_options(self, args: Any) -> tuple[dict, dict]:
        if not isinstance(args, dict):
            return {}, self._default_response_options()

        exec_args = dict(args)
        opts = self._default_response_options()

        qol_mode = self._pop_first(exec_args, ["_qol_mode", "qol_mode"], None)
        if isinstance(qol_mode, str):
            qol_mode = qol_mode.strip().lower()
        if qol_mode in {"tiny", "balanced", "debug"}:
            profile = self._qol_profiles.get(qol_mode, {})
            if profile:
                opts.update(profile)
        else:
            qol_mode = self.default_qol_mode
            profile = self._qol_profiles.get(qol_mode, {})
            if profile:
                opts.update(profile)
        opts["qol_mode"] = qol_mode

        mode = self._pop_first(exec_args, ["_response_mode", "response_mode"], None)
        compact_toggle = self._pop_first(exec_args, ["_compact", "compact"], None)
        if compact_toggle is not None:
            mode = "compact" if _coerce_bool(compact_toggle, True) else "full"
        if isinstance(mode, str):
            mode = mode.strip().lower()
        if mode not in {"compact", "full"}:
            mode = opts.get("mode", self.default_response_mode)
        opts["mode"] = mode
        compact_mode = mode == "compact"

        detail_level = self._pop_first(exec_args, ["_error_details"], None)
        if detail_level is None:
            detail_level = (
                opts.get("error_details", self.default_error_detail_level)
                if compact_mode
                else "full"
            )
        if isinstance(detail_level, str):
            detail_level = detail_level.strip().lower()
        if detail_level not in {"none", "basic", "full"}:
            detail_level = "basic" if compact_mode else "full"
        opts["error_details"] = detail_level

        opts["fields"] = _parse_str_list(
            self._pop_first(exec_args, ["_response_fields"], None)
        )
        opts["omit"] = _parse_str_list(
            self._pop_first(exec_args, ["_response_omit"], None)
        )

        max_items_raw = self._pop_first(exec_args, ["_response_max_items"], None)
        max_string_raw = self._pop_first(exec_args, ["_response_max_string"], None)
        char_budget_raw = self._pop_first(exec_args, ["_response_char_budget"], None)

        opts["max_items"] = (
            _bounded_int(
                max_items_raw,
                int(opts.get("max_items", self.default_compact_max_items)),
                min_value=1,
                max_value=10_000,
            )
            if compact_mode or max_items_raw is not None
            else 10_000
        )
        opts["max_string"] = (
            _bounded_int(
                max_string_raw,
                int(opts.get("max_string", self.default_compact_max_string)),
                min_value=64,
                max_value=500_000,
            )
            if compact_mode or max_string_raw is not None
            else 500_000
        )
        opts["char_budget"] = (
            _bounded_int(
                char_budget_raw,
                int(opts.get("char_budget", self.default_compact_char_budget)),
                min_value=500,
                max_value=2_000_000,
            )
            if compact_mode or char_budget_raw is not None
            else 0
        )

        opts["drop_empty"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_drop_empty"], None),
            bool(opts.get("drop_empty", compact_mode)),
        )
        opts["drop_false"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_drop_false"], None),
            bool(opts.get("drop_false", compact_mode)),
        )
        opts["drop_ok"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_drop_ok"], None),
            bool(opts.get("drop_ok", compact_mode)),
        )
        opts["dedupe_counts"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_dedupe_counts"], None),
            bool(opts.get("dedupe_counts", compact_mode)),
        )
        opts["strip_meta"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_strip_meta"], None),
            bool(opts.get("strip_meta", compact_mode)),
        )
        opts["table_mode"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_table"], None),
            bool(
                opts.get(
                    "table_mode", self.default_table_mode if compact_mode else False
                )
            ),
        )
        opts["batch_compact"] = _coerce_bool(
            self._pop_first(exec_args, ["_response_batch_compact"], None),
            bool(
                opts.get(
                    "batch_compact",
                    self.default_batch_compact if compact_mode else False,
                )
            ),
        )
        # Universal output filtering (applies to ALL tools)
        opts["output_grep"] = self._pop_first(exec_args, ["output_grep"], None)
        opts["output_head"] = self._pop_first(exec_args, ["output_head"], None)
        opts["output_tail"] = self._pop_first(exec_args, ["output_tail"], None)
        opts["output_skip"] = self._pop_first(exec_args, ["output_skip"], None)
        opts["output_path"] = self._pop_first(exec_args, ["output_path"], None)
        opts["output_pluck"] = self._pop_first(exec_args, ["output_pluck"], None)
        return exec_args, opts

    def _default_response_options(self) -> dict:
        return {
            "mode": self.default_response_mode,
            "fields": [],
            "omit": [],
            "max_items": self.default_compact_max_items,
            "max_string": self.default_compact_max_string,
            "char_budget": self.default_compact_char_budget,
            "drop_empty": True,
            "drop_false": True,
            "drop_ok": False,
            "dedupe_counts": True,
            "strip_meta": True,
            "table_mode": self.default_table_mode,
            "batch_compact": self.default_batch_compact,
            "error_details": self.default_error_detail_level,
            "output_grep": None,
            "output_head": None,
            "output_tail": None,
            "output_skip": None,
            "output_path": None,
            "output_pluck": None,
        }

    def _compact_error_details(self, details: Any, opts: dict) -> Any:
        level = opts.get("error_details", "basic")
        if level == "full":
            return details
        if level == "none":
            return None
        if not isinstance(details, dict):
            return details
        max_items = max(1, int(opts.get("max_items", 20)))
        max_string = max(64, int(opts.get("max_string", 512)))
        out = {}
        for key, value in details.items():
            if key in _COMPACT_META_KEYS:
                continue
            if isinstance(value, str):
                if len(value) > max_string:
                    out[key] = (
                        f"{value[:max_string]}...(+{len(value) - max_string} chars)"
                    )
                else:
                    out[key] = value
                continue
            if isinstance(value, list):
                keep = value[:max_items]
                out[key] = keep
                if len(value) > len(keep):
                    out[f"{key}_more"] = len(value) - len(keep)
                continue
            out[key] = value

        for key in _COMPACT_DETAIL_LIST_KEYS:
            value = out.get(key)
            if isinstance(value, list) and len(value) > max_items:
                out[key] = value[:max_items]
                out[f"{key}_more"] = len(value) - max_items
        return out or None

    def _maybe_tableify(self, value: Any, opts: dict) -> Any:
        if not opts.get("table_mode"):
            return value
        if not isinstance(value, list):
            return value
        if len(value) < 4:
            return value
        rows = [item for item in value if isinstance(item, dict)]
        if len(rows) != len(value):
            return value
        common = None
        for row in rows:
            keys = tuple(row.keys())
            if common is None:
                common = keys
            elif keys != common:
                return value
        if not common:
            return value
        if len(common) > 24:
            return value
        max_items = max(1, int(opts.get("max_items", len(rows))))
        sliced = rows[:max_items]
        table_rows = [[row.get(col) for col in common] for row in sliced]
        table = {"columns": list(common), "rows": table_rows, "count": len(table_rows)}
        if len(rows) > len(sliced):
            table["total"] = len(rows)
        return table

    def _compact_value(self, value: Any, opts: dict) -> Any:
        max_items = max(1, int(opts.get("max_items", 10_000)))
        max_string = max(64, int(opts.get("max_string", 500_000)))

        if isinstance(value, dict):
            out = {}
            for key, raw in value.items():
                if opts.get("strip_meta") and key in _COMPACT_META_KEYS:
                    continue
                if key == "ok" and raw is True and opts.get("drop_ok"):
                    continue
                if key == "details":
                    compact_details = self._compact_error_details(raw, opts)
                    if compact_details is None and opts.get("drop_empty"):
                        continue
                    out[key] = compact_details
                    continue
                compacted = self._compact_value(raw, opts)
                if compacted is _COMPACT_DROP and raw is False and key == "firmware_detected":
                    # Keep explicit false for workflow metadata contracts.
                    compacted = False
                if compacted is _COMPACT_DROP:
                    continue
                out[key] = compacted

            if opts.get("dedupe_counts"):
                list_lengths = [len(v) for v in out.values() if isinstance(v, list)]
                if (
                    "count" in out
                    and isinstance(out["count"], int)
                    and out["count"] in list_lengths
                ):
                    out.pop("count", None)
                if out.get("offset") == 0:
                    out.pop("offset", None)
                if isinstance(out.get("count"), int) and out.get("total") == out.get(
                    "count"
                ):
                    out.pop("total", None)
                if isinstance(out.get("count"), int) and out.get("limit") == out.get(
                    "count"
                ):
                    out.pop("limit", None)
                if isinstance(out.get("items"), list) and out.get("next_offset") == len(
                    out["items"]
                ):
                    out.pop("next_offset", None)
                if isinstance(out.get("results"), list) and out.get("count") == len(
                    out["results"]
                ):
                    out.pop("count", None)
                # Prefer compact text form when both are present unless caller explicitly requests items.
                requested_fields = set(opts.get("fields") or [])
                if (
                    "functions" in out
                    and isinstance(out.get("functions"), str)
                    and isinstance(out.get("items"), list)
                    and "items" not in requested_fields
                ):
                    out.pop("items", None)
            if not out and opts.get("drop_empty"):
                return _COMPACT_DROP
            return out

        if isinstance(value, list):
            value = self._maybe_tableify(value, opts)
            if isinstance(value, dict):
                return self._compact_value(value, opts)
            trimmed = value[:max_items]
            out = []
            for item in trimmed:
                compacted = self._compact_value(item, opts)
                if compacted is _COMPACT_DROP:
                    continue
                out.append(compacted)
            if not out and opts.get("drop_empty"):
                return _COMPACT_DROP
            return out

        if isinstance(value, str):
            if len(value) > max_string:
                return f"{value[:max_string]}...(+{len(value) - max_string} chars)"
            if value == "" and opts.get("drop_empty"):
                return _COMPACT_DROP
            return value
        if value is None and opts.get("drop_empty"):
            return _COMPACT_DROP
        if value is False and opts.get("drop_false"):
            return _COMPACT_DROP
        return value

    def _project_top_level_fields(self, payload: Any, opts: dict) -> Any:
        if not isinstance(payload, dict):
            return payload
        fields = set(opts.get("fields") or [])
        omit = set(opts.get("omit") or [])
        always_keep = {
            "error",
            "code",
            "message",
            "hint",
            "_truncated",
            "_continue",
            "workflow_meta",
        }
        if fields:
            keep = fields.union(always_keep)
            projected = {k: v for k, v in payload.items() if k in keep}
        else:
            projected = dict(payload)
        for key in omit:
            if key in always_keep:
                continue
            projected.pop(key, None)
        return projected

    def _compact_batch_result(self, payload: Any, opts: dict) -> Any:
        if not opts.get("batch_compact"):
            return payload
        if not isinstance(payload, dict):
            return payload
        results = payload.get("results")
        if not isinstance(results, list):
            return payload
        compact_results = []
        for item in results:
            if not isinstance(item, dict):
                compact_results.append(item)
                continue
            raw_result = item.get("result")
            is_error = bool(isinstance(raw_result, dict) and raw_result.get("error"))
            entry = {
                # Keep compact external key as `tool` for readability (source batch rows use `name`).
                "tool": item.get("name"),
                "ok": not is_error,
                "data": raw_result,
            }
            compact_results.append(entry)
        out = {"results": compact_results}
        if isinstance(payload.get("summary"), dict):
            out["summary"] = payload.get("summary")
        if payload.get("error"):
            out["error"] = payload.get("error")
        # Preserve additional top-level metadata (for example workflow_meta)
        # so callers can still reason about execution path in compact mode.
        for k, v in payload.items():
            if k in {"results", "summary", "error"}:
                continue
            out.setdefault(k, v)
        return out

    def _pointer_note_signal_from_text(self, text: str) -> float:
        if not text:
            return 0.0
        s = text.strip()
        if not s:
            return 0.0
        lowered = s.lower()
        score = 0.0
        hex_matches = list(_POINTER_NOTE_HEX_RE.finditer(s))
        if hex_matches:
            score += 1.0
        if _POINTER_NOTE_MATH_RE.search(s):
            score += 2.0
        if len(hex_matches) >= 2:
            score += 1.0
        if any(k in lowered for k in _POINTER_NOTE_SIGNAL_KEYWORDS):
            score += 1.0
        return score

    def _pointer_note_signal_from_value(self, value: Any, depth: int = 0) -> float:
        if depth > _POINTER_NOTE_SIGNAL_MAX_DEPTH:
            return 0.0
        if isinstance(value, str):
            return self._pointer_note_signal_from_text(value)
        if isinstance(value, int):
            return 0.5 if value >= 0x1000 else 0.0
        if isinstance(value, list):
            return sum(
                self._pointer_note_signal_from_value(v, depth + 1)
                for v in value[:_POINTER_NOTE_SIGNAL_MAX_LIST_ITEMS]
            )
        if isinstance(value, dict):
            score = 0.0
            for idx, (k, v) in enumerate(value.items()):
                if idx >= _POINTER_NOTE_SIGNAL_MAX_DICT_ITEMS:
                    break
                child_score = self._pointer_note_signal_from_value(v, depth + 1)
                if isinstance(k, str):
                    kl = k.lower()
                    if child_score > 0 and any(
                        sig in kl for sig in _POINTER_NOTE_SIGNAL_KEYWORDS
                    ):
                        score += 1.0
                score += child_score
            return score
        return 0.0

    def _compute_pointer_note_signal(
        self, tool_name: str, call_args: Any, payload: Any
    ) -> float:
        score = 0.0
        tn = str(tool_name or "").strip().lower()
        if tn in _POINTER_NOTE_SIGNAL_TOOLS_STRONG:
            score += 2.0
        elif tn in _POINTER_NOTE_SIGNAL_TOOLS_HINT:
            score += 1.0
        if isinstance(call_args, dict):
            for idx, (k, v) in enumerate(call_args.items()):
                if idx >= 20:
                    break
                if isinstance(k, str):
                    kl = k.lower()
                    if kl.startswith("_"):
                        continue
                    if any(sig in kl for sig in _POINTER_NOTE_SIGNAL_KEYWORDS):
                        score += 1.0
                score += self._pointer_note_signal_from_value(v)
        if isinstance(payload, dict):
            payload_focus: Dict[str, Any] = {}
            for key in (
                "address",
                "addr",
                "target",
                "query",
                "pattern",
                "matches",
                "items",
            ):
                if key in payload:
                    val = payload.get(key)
                    if val not in (None, "", [], {}):
                        payload_focus[key] = val
            score += self._pointer_note_signal_from_value(payload_focus)
        return min(score, 10.0)

    def _should_include_pointer_note(
        self, tool_name: str, call_args: Any, payload: Any
    ) -> bool:
        if isinstance(payload, dict) and payload.get("error"):
            return False
        signal = self._compute_pointer_note_signal(tool_name, call_args, payload)
        if signal > 0:
            self._pointer_note_pending_signal = min(
                float(self._pointer_note_min_signal)
                * _POINTER_NOTE_MAX_SIGNAL_MULTIPLIER,
                self._pointer_note_pending_signal + signal,
            )
        else:
            self._pointer_note_pending_signal = max(
                0.0, self._pointer_note_pending_signal - 0.25
            )
            return False
        if self._pointer_note_pending_signal < float(self._pointer_note_min_signal):
            return False
        now = time.time()
        if self._pointer_note_last_shown_at > 0 and (
            now - self._pointer_note_last_shown_at
        ) < float(self._pointer_note_interval_seconds):
            return False
        self._pointer_note_last_shown_at = now
        self._pointer_note_pending_signal = 0.0
        return True

    def _validate_address_lockstep(self, call_args: Any, payload: Any) -> list[dict]:
        """Detect addresses in call_args that do not appear in previous payload output."""
        if not isinstance(call_args, dict):
            return []
        requested = self._collect_hex_addresses(call_args, max_items=12)
        if not requested:
            return []
        available = self._collect_hex_addresses(payload, max_items=50)
        available_set = set(available)
        warnings: list[dict] = []
        for addr in requested:
            if addr not in available_set:
                warnings.append(
                    {
                        "addr": addr,
                        "warning": "This address was not present in the previous tool output. Verify with calc/memory before reasoning.",
                        "suggested_verification": {
                            "tool": "calc",
                            "arguments": {"action": "deref", "addr": addr, "type": "u32"},
                        },
                    }
                )
        return warnings

    def _assemble_and_inject_context(
        self,
        tool_name: str,
        action: str,
        payload: dict,
        addr: str,
        opts: Optional[dict] = None,
    ) -> None:
        """
        Build a context_pack via the intelligence layer (bge-code-v1) and inject
        it into the payload so the LLM receives relevant context alongside results.
        Replaces the cartographer + attention_kernel + cognitive_layer pipeline.
        """
        if not isinstance(payload, dict) or payload.get("error"):
            return
        if tool_name in {"session", "blackboard", "batch", "truncation", "wiki",
                         "predictor", "workflow"}:
            return

        try:
            session_id = (
                getattr(self.current_session, "session_id", None)
                if self.current_session else "default"
            )
            idb_path = (
                getattr(self.current_session, "idb_path", None)
                if self.current_session else None
            )
            bb_store = self._get_blackboard_store()
            pack = self.assembler.assemble(
                tool=tool_name,
                action=action,
                payload=payload,
                addr=addr,
                session_id=session_id or "default",
                idb_path=idb_path or "",
                bb_store=bb_store,
            )
            if pack:
                mode = str((opts or {}).get("mode") or "").strip().lower()
                # Only inject context_pack in full mode — it's verbose
                if mode == "full":
                    payload["context_pack"] = pack
                elif pack.get("top_entries"):
                    # In compact mode, only inject the top entry titles (not full content)
                    payload["_context"] = [e.get("title", "") for e in pack["top_entries"][:3] if e.get("title")]
        except Exception:
            pass

    def _observe_memrl(self, tool_name: str, action: str, payload: dict) -> None:
        """No-op stub — MemRL feedback now runs via auto_reward_for_addr in _record_activity."""
        pass

    def _collect_hex_addresses(self, value: Any, max_items: int = 8) -> list[str]:
        found: list[str] = []

        def _push(addr_text: str) -> None:
            if not addr_text:
                return
            norm = addr_text.lower()
            if not norm.startswith("0x"):
                return
            if norm in found:
                return
            found.append(norm)

        def _walk(v: Any, depth: int = 0) -> None:
            if len(found) >= max_items or depth > 3:
                return
            if isinstance(v, str):
                for m in _POINTER_NOTE_HEX_RE.finditer(v):
                    _push(m.group(0))
            elif isinstance(v, int):
                if v >= 0x1000:
                    _push(hex(v))
            elif isinstance(v, list):
                for item in v[:12]:
                    _walk(item, depth + 1)
                    if len(found) >= max_items:
                        break
            elif isinstance(v, dict):
                for idx, (_, item) in enumerate(v.items()):
                    if idx >= 24:
                        break
                    _walk(item, depth + 1)
                    if len(found) >= max_items:
                        break

        _walk(value)
        return found[:max_items]

    def _guardrail_mode_from_args(self, call_args: Any) -> str:
        """Resolve per-call guardrail mode: assist|enforce|off."""
        mode = ""
        if isinstance(call_args, dict):
            mode = str(call_args.get("_guardrail_mode") or "").strip().lower()
        if mode in {"off", "none", "disable", "disabled"}:
            return "off"
        if mode in {"enforce", "strict", "block"}:
            return "enforce"
        return "assist"

    def _guardrail_reason_tags(self, tool_name: str, call_args: Any, payload: Any) -> list[str]:
        tags: list[str] = []
        tn = str(tool_name or "").lower()
        if tn in {"code", "xref_analysis", "graph", "ctree", "static_trace", "memory", "calc"}:
            tags.append("address-heavy-tool")
        if isinstance(call_args, dict):
            keys = {str(k).lower() for k in call_args.keys()}
            if {"addr", "address", "target"} & keys:
                tags.append("explicit-address-arg")
            if {"offset", "offsets", "base", "size"} & keys:
                tags.append("offset-arithmetic")
        addrs = self._collect_hex_addresses(call_args)
        if len(addrs) < 2:
            addrs.extend([a for a in self._collect_hex_addresses(payload) if a not in addrs])
        if len(addrs) >= 2:
            tags.append("multiple-hex-addresses")
        return tags

    def _apply_output_filters(self, payload: Any, opts: dict) -> Any:
        """Apply universal output filtering (grep, head, tail, skip, path, pluck)."""
        import re as _re

        # Path extraction: extract a nested field from a dict
        path = opts.get("output_path")
        if path and isinstance(payload, dict):
            current = payload
            for part in str(path).split("."):
                if isinstance(current, dict):
                    current = current.get(part)
                elif isinstance(current, list) and part.isdigit():
                    idx = int(part)
                    current = current[idx] if 0 <= idx < len(current) else None
                else:
                    current = None
                if current is None:
                    break
            payload = current if current is not None else {}

        # If payload is a list, apply head/tail/skip/grep/pluck
        if isinstance(payload, list):
            skip = opts.get("output_skip")
            if skip is not None:
                try:
                    payload = payload[int(skip):]
                except Exception:
                    pass

            head = opts.get("output_head")
            if head is not None:
                try:
                    payload = payload[:int(head)]
                except Exception:
                    pass

            tail = opts.get("output_tail")
            if tail is not None:
                try:
                    payload = payload[-int(tail):]
                except Exception:
                    pass

            grep = opts.get("output_grep")
            if grep:
                try:
                    pattern = _re.compile(str(grep), _re.IGNORECASE)
                    payload = [x for x in payload if pattern.search(str(x))]
                except Exception:
                    pass

            pluck = opts.get("output_pluck")
            if pluck:
                try:
                    key = str(pluck)
                    payload = [
                        x.get(key) if isinstance(x, dict) else x
                        for x in payload
                    ]
                except Exception:
                    pass

        # If payload is a dict with a list inside, try to apply grep to common list fields
        elif isinstance(payload, dict) and opts.get("output_grep"):
            pattern_str = opts.get("output_grep")
            try:
                pattern = _re.compile(str(pattern_str), _re.IGNORECASE)
                for k, v in list(payload.items()):
                    if isinstance(v, list):
                        payload[k] = [x for x in v if pattern.search(str(x))]
            except Exception:
                pass

        return payload

    def _build_llm_execution_directive(self, payload: dict) -> Optional[str]:
        """Build a compact directive from tool-first gating fields."""
        if not isinstance(payload, dict):
            return None
        must_call = bool(payload.get("must_call_before_answer"))
        req = payload.get("required_followup_call")
        if not isinstance(req, dict):
            req = None
        if not must_call and not req:
            return None

        call_txt = "code.callers"
        if req:
            tool = str(req.get("tool") or "").strip()
            action = str(req.get("action") or "").strip()
            if tool and action:
                call_txt = f"{tool}.{action}"

        if must_call:
            return (
                f"MCP_REQUIRED_CALL: Execute `{call_txt}` before concluding. "
                "Do not finalize claims until new tool evidence is incorporated."
            )
        return (
            f"MCP_RECOMMENDED_CALL: Prefer `{call_txt}` before final answer "
            "and cite returned evidence."
        )

    def _prepare_response_payload(
        self,
        payload: Any,
        opts: dict,
        *,
        tool_name: str = "",
        call_args: Any = None,
    ) -> Any:
        include_pointer_note = self._should_include_pointer_note(
            tool_name, call_args, payload
        )
        action_name = ""
        if isinstance(call_args, dict):
            action_name = str(call_args.get("action") or "")
        if not action_name:
            action_name = str(opts.get("action") or "")
        # Apply universal output filters first
        payload = self._apply_output_filters(payload, opts)
        payload = self._json_safe_value(payload)
        full_mode = opts.get("mode") == "full"
        if full_mode:
            if isinstance(payload, dict):
                payload = dict(payload)
                if include_pointer_note:
                    reason_tags = self._guardrail_reason_tags(tool_name, call_args, payload)
                    guardrail_mode = self._guardrail_mode_from_args(call_args)
                    payload.setdefault("llm_pointer_note", LLM_POINTER_SAFETY_NOTE)
                    payload.setdefault("llm_guardrail_mode", guardrail_mode)
                    payload.setdefault("llm_guardrail_reason_tags", reason_tags)
                    # Address lockstep: warn about unseen addresses
                    lockstep_warnings = self._validate_address_lockstep(call_args, payload)
                    if lockstep_warnings:
                        payload.setdefault("llm_address_lockstep_warnings", lockstep_warnings)
            compacted = payload
        else:
            projected = self._project_top_level_fields(payload, opts)
            compacted = self._compact_value(projected, opts)
            if compacted is _COMPACT_DROP:
                compacted = {}
            compacted = self._compact_batch_result(compacted, opts)
            budget = int(opts.get("char_budget", 0) or 0)
            if budget > 0 and isinstance(compacted, dict):
                compacted = truncate_response(compacted, max_tokens=budget)

        # ---- Context Density Auto-Compaction Middleware ----
        # Skip if the caller explicitly requests raw output.
        raw_requested = False
        if isinstance(call_args, dict):
            raw_requested = _coerce_bool(call_args.get("raw"), False)
        if not raw_requested and compacted is not None:
            try:
                serialized_size = len(
                    json.dumps(compacted, ensure_ascii=False, separators=(",", ":"))
                )
                if serialized_size > CONTEXT_DENSITY_COMPACT_THRESHOLD:
                    compacted = self._context_density_optimizer.compact_response(
                        compacted,
                        budget_tokens=opts.get(
                            "char_budget", CONTEXT_DENSITY_DEFAULT_BUDGET
                        ),
                    )
            except Exception:
                # Fail-safe: never let compaction break the response path
                pass
        # ------------------------------------------------------

        if isinstance(compacted, dict):
            compacted = dict(compacted)
            if include_pointer_note:
                reason_tags = self._guardrail_reason_tags(tool_name, call_args, compacted)
                guardrail_mode = self._guardrail_mode_from_args(call_args)
                compacted.setdefault("llm_pointer_note", LLM_POINTER_SAFETY_NOTE)
                compacted.setdefault("llm_guardrail_mode", guardrail_mode)
                compacted.setdefault("llm_guardrail_reason_tags", reason_tags)
            if self.enable_response_enrichment:
                # ---- Auto-Nudge Injection ----
                try:
                    nudge = None
                    ui = getattr(self, "_usage_intel", None)
                    if ui:
                        # Primary: UsageIntelligence predictions (trained on real audit data)
                        preds = ui.predict_next(tool_name, action_name, top_k=4)
                        if preds:
                            from .auto_nudge import suggest_smart_tools
                            behavior_tags = (compacted.get("behavior_tags") or
                                             compacted.get("tags") or [])
                            static = suggest_smart_tools(tool_name, action_name,
                                                         compacted, behavior_tags)
                            # Merge: UI predictions first, then static suggestions not already covered
                            ui_set = {f"{p['tool']}:{p['action']}" for p in preds}
                            merged = [f"{p['tool']}:{p['action']}  p={p['probability']:.2f}  eff={p['effectiveness']:.2f}"
                                      for p in preds]
                            for s in static[:3]:
                                ta = s.split("=")[0] if "=" in s else s
                                if ta not in ui_set:
                                    merged.append(s)
                            nudge = {"suggested_next": merged[:5], "source": "usage_intelligence"}
                    else:
                        from .auto_nudge import get_nudge
                        idb_key = (self.current_session.idb_path if self.current_session else "")
                        nudge = get_nudge(
                            idb_key,
                            tool_name,
                            action_name,
                            compacted,
                            call_args if isinstance(call_args, dict) else {},
                        )
                    if nudge:
                        compacted["_nudge"] = nudge
                except Exception:
                    pass

            # ---- Signal-Specific Directives ----
            # Precise, copy-pasteable tool calls based on what was found in this response.
            try:
                from .response_enrichment import build_signal_directives
                func_addr = ""
                if isinstance(call_args, dict):
                    func_addr = str(call_args.get("addr") or call_args.get("addrs") or "")
                    if isinstance(func_addr, list):
                        func_addr = func_addr[0] if func_addr else ""
                directives = build_signal_directives(
                    tool_name, action_name, compacted, func_addr=func_addr
                )
                if directives:
                    # High-priority directives become the execution directive
                    high = [d for d in directives if d["priority"] == "high"]
                    if high:
                        top = high[0]
                        compacted["llm_execution_directive"] = (
                            f"REQUIRED: {top['call']}  ← {top['reason']}"
                        )
                    compacted["_next_calls"] = directives
            except Exception:
                pass

            # ---- Explicit tool-first directive ----
            try:
                directive = self._build_llm_execution_directive(compacted)
                if directive:
                    compacted.setdefault("llm_execution_directive", directive)
            except Exception:
                pass
            
            # ---- Address Patching ----
            try:
                if tool_name == "code" and action_name in ("decompile", "semantic_decompile", "disasm"):
                    from .response_enrichment import patch_addresses
                    if "pseudocode" in compacted:
                        pseudo_key = "pseudocode"
                    elif "code" in compacted:
                        pseudo_key = "code"
                    else:
                        pseudo_key = "disassembly"
                    if pseudo_key in compacted:
                        compacted[pseudo_key] = patch_addresses(compacted[pseudo_key])
            except Exception:
                pass
            
            if self.enable_response_enrichment:
                # ---- Auto-Digest ----
                try:
                    if tool_name == "code" and action_name in ("decompile", "semantic_decompile"):
                        from .response_enrichment import digest_decompiled
                        if "pseudocode" in compacted:
                            pseudo_key = "pseudocode"
                        elif "code" in compacted:
                            pseudo_key = "code"
                        else:
                            pseudo_key = "output"
                        if pseudo_key in compacted and isinstance(compacted[pseudo_key], str):
                            addr = (call_args or {}).get("addr", "") if isinstance(call_args, dict) else ""
                            # Try to get SchemaBoot attributes for richer classification
                            schema_attrs = None
                            try:
                                if addr and hasattr(self, '_insight_index') and self._insight_index:
                                    func_data = self._insight_index.get_function(addr) if hasattr(self._insight_index, 'get_function') else None
                                    if func_data:
                                        schema_attrs = func_data
                            except Exception:
                                pass
                            digest = digest_decompiled(compacted[pseudo_key], func_addr=addr, schema_attrs=schema_attrs)
                            if digest and any(digest.values()):
                                compacted["_digest"] = digest
                except Exception:
                    pass
            
            if self.enable_response_enrichment:
                # ---- Session Resume ----
                try:
                    if hasattr(self, 'session_mgr') and self.current_session:
                        from .response_enrichment import build_session_resume
                        sid = self.current_session.session_id
                        # Only inject on first few calls
                        if call_args and isinstance(call_args, dict):
                            call_count = call_args.get("_call_seq", 0)
                            if not isinstance(call_count, int) or call_count <= 2:
                                resume = build_session_resume(self.session_mgr, sid)
                                if resume:
                                    compacted["_session_resume"] = resume
                except Exception:
                    pass
            
            if self.enable_response_enrichment:
                # ---- Ghost Chain Inlining ----
                try:
                    addr = (call_args or {}).get("addr", "") if isinstance(call_args, dict) else ""
                    ghost_action = action_name
                    from .response_enrichment import GHOST_CHAINS
                    ghost_results = {}
                    ghost_key = (tool_name, ghost_action)
                    chain = GHOST_CHAINS.get(ghost_key, [])
                    
                    # Phase 1: Basic companions (callers, callees, strings)
                    for ghost_tool, ghost_args_template in chain:
                        ghost_args = dict(ghost_args_template)
                        for k, v in ghost_args.items():
                            if isinstance(v, str):
                                v = v.replace("__ADDR__", str(addr))
                                ghost_args[k] = v
                        try:
                            ghost_res = self._execute_tool(ghost_tool, ghost_args)
                            if isinstance(ghost_res, dict) and ghost_res.get("ok"):
                                key_name = ghost_args.get("action", ghost_tool)
                                if "callers" in key_name:
                                    items = ghost_res.get("callers", ghost_res.get("matches", ghost_res.get("results", [])))
                                    ghost_results["callers"] = items[:5] if isinstance(items, list) else str(items)[:200]
                                elif "callees" in key_name:
                                    items = ghost_res.get("callees", ghost_res.get("matches", ghost_res.get("results", [])))
                                    ghost_results["callees"] = items[:5] if isinstance(items, list) else str(items)[:200]
                                elif "strings" in key_name:
                                    items = ghost_res.get("strings", ghost_res.get("matches", ghost_res.get("results", [])))
                                    ghost_results["strings"] = items[:5] if isinstance(items, list) else str(items)[:200]
                                elif "calls" in key_name:
                                    items = ghost_res.get("calls", ghost_res.get("results", []))
                                    ghost_results["api_calls"] = items[:5] if isinstance(items, list) else str(items)[:200]
                                else:
                                    ghost_results[key_name] = str(ghost_res)[:200]
                        except Exception:
                            pass
                    
                    # Phase 2: BridgeRAG multi-hop relation discovery
                    if addr and tool_name in ("code", "data", "search"):
                        try:
                            bridge_res = self._execute_tool("bridgerag", {
                                "action": "bridges",
                                "func_ea": addr,
                                "bridge_types": ["apis", "strings"],
                            })
                            if isinstance(bridge_res, dict) and bridge_res.get("ok"):
                                bridges = bridge_res.get("bridges", {})
                                if bridges:
                                    ghost_results["bridge_entities"] = {
                                        "apis": bridges.get("apis", [])[:5],
                                        "strings": bridges.get("strings", [])[:5],
                                        "note": "Shared APIs/strings with other functions. Use bridgerag.search for full discovery."
                                    }
                        except Exception:
                            pass
                    
                    # Phase 3: MbaGCN structural similarity
                    if addr and tool_name in ("code", "data", "search"):
                        try:
                            mbagcn_res = self._execute_tool("mbagcn", {
                                "action": "similar",
                                "addr": addr,
                                "top_k": 3,
                            })
                            if isinstance(mbagcn_res, dict) and mbagcn_res.get("ok"):
                                similar = mbagcn_res.get("results", [])
                                if similar:
                                    ghost_results["structurally_similar"] = [
                                        {"addr": s.get("ea", ""), "name": s.get("name", ""),
                                         "similarity": s.get("similarity", 0)}
                                        for s in similar[:3]
                                    ]
                                    ghost_results["structurally_similar_note"] = (
                                        "These functions have similar CFG structure. They may share behavior. "
                                        "Use code.decompile on them to investigate."
                                    )
                        except Exception:
                            pass
                    
                    # Phase 4: InsightIndex behavior-tag discovery
                    if addr and tool_name in ("code", "data", "search"):
                        try:
                            idx = getattr(self, '_insight_index', None)
                            if idx and hasattr(idx, 'query_by_tags'):
                                # Try to get tags for this function
                                func_attrs = idx.get_function(addr) if hasattr(idx, 'get_function') else None
                                tags = func_attrs.get("behavior_tags", []) if func_attrs else []
                                if not tags:
                                    # Fall back to L2 global facts
                                    if hasattr(self, '_global_facts'):
                                        tags = []
                                if tags:
                                    related = idx.query_by_tags(tags[:3], mode="or") if hasattr(idx, 'query_by_tags') else []
                                    if related:
                                        ghost_results["same_behavior_tags"] = {
                                            "tags": tags,
                                            "functions": [str(r)[:80] for r in related[:5]],
                                            "note": "Other functions with the same behavior tags. May be part of the same component."
                                        }
                        except Exception:
                            pass
                    
                    # Phase 5: L2 GlobalFactsDatabase compiler/API pattern lookup
                    try:
                        gf = getattr(self, '_global_facts', None)
                        if gf and hasattr(gf, 'query_facts'):
                            # Query for compiler signatures
                            compiler_facts = gf.query_facts(category="compiler_signature", limit=3)
                            api_facts = gf.query_facts(category="common_api", limit=5)
                            if compiler_facts:
                                ghost_results["compiler_info"] = [f.get("fact_value", "")[:100] for f in compiler_facts]
                            if api_facts:
                                ghost_results["known_api_patterns"] = [f.get("fact_key", "")[:80] for f in api_facts]
                    except Exception:
                        pass
                    
                    # Phase 6: TurboQuant embedding similarity
                    try:
                        tq_res = self._execute_tool("turboquant", {
                            "action": "query",
                            "query_key": addr,
                            "top_k": 3,
                        })
                        if isinstance(tq_res, dict) and tq_res.get("ok"):
                            tq_similar = tq_res.get("results", [])
                            if tq_similar:
                                ghost_results["embedding_similar"] = [
                                    {"key": s.get("key", ""), "score": s.get("score", 0)}
                                    for s in tq_similar[:3]
                                ]
                    except Exception:
                        pass
                    
                    # Phase 7: C2 risk scoring (ML-powered, deterministic)
                    try:
                        c2_res = self._execute_tool("string_ops", {
                            "action": "score_c2",
                            "addr": addr,
                        })
                        if isinstance(c2_res, dict) and c2_res.get("ok"):
                            c2_risk = c2_res.get("c2_risk")
                            if isinstance(c2_risk, dict) and c2_risk.get("overall_score", 0) > 0:
                                ghost_results["c2_risk"] = c2_risk
                    except Exception:
                        pass
                    
                    if ghost_results:
                        compacted["_inline"] = ghost_results
                except Exception:
                    pass
            
            # ---- Auto-Advance Phase ----
            try:
                if hasattr(self, 'session_mgr') and self.current_session:
                    sid = self.current_session.session_id
                    data = self.session_mgr._load_skills(sid)
                    activity_log = data.get("activity_log", [])
                    # Count decompiles, imports analyzed, xrefs traced
                    decompile_count = sum(1 for e in activity_log if e.get("action") in ("decompile", "semantic_decompile"))
                    import_count = sum(1 for e in activity_log if e.get("tool") == "imports_deep" or e.get("tool") == "data" and e.get("action") == "imports")
                    # Check phase thresholds
                    from .session import _ANALYSIS_PHASES
                    session = self.session_mgr.sessions.get(sid)
                    if session:
                        current_phase = session.phase
                        phases = sorted(_ANALYSIS_PHASES.keys(), key=lambda p: _ANALYSIS_PHASES[p]["order"])
                        try:
                            idx = phases.index(current_phase)
                            if idx < len(phases) - 1:
                                next_phase = phases[idx + 1]
                                threshold = _ANALYSIS_PHASES[next_phase].get("threshold", {})
                                if (decompile_count >= threshold.get("functions_decompiled", 999) and
                                    import_count >= threshold.get("imports_analyzed", 999)):
                                    session.phase = next_phase
                                    self.session_mgr._save_metadata(session)
                        except (ValueError, IndexError):
                            pass
            except Exception:
                pass
            
            # ---- Auto-Blackboard ----
            try:
                from .response_enrichment import auto_blackboard_write
                addr = (call_args or {}).get("addr", "") if isinstance(call_args, dict) else ""
                bb_entries = auto_blackboard_write(tool_name, str(action_name or ""), compacted, addr)
                bb_written = 0
                if bb_entries:
                    # Write to blackboard with dedup check: skip entries whose
                    # addr+category+title already exist to avoid unbounded noise.
                    try:
                        bb_store = self._get_blackboard_store()
                        for entry in bb_entries:
                            e_addr = str(entry.get("addr", addr) or "")
                            e_title = str(entry.get("name") or entry.get("title") or "")
                            e_category = str(entry.get("category") or "general")
                            if not e_title:
                                continue
                            # Skip if identical entry already exists
                            if bb_store and bb_store.exists(e_addr, e_category, e_title):
                                continue
                            wr = self._execute_tool("blackboard", {
                                "action": "write",
                                "addr": e_addr,
                                "title": e_title,
                                "content": str(entry.get("notes") or entry.get("content") or ""),
                                "category": e_category,
                                "tags": entry.get("tags") or [],
                                "confidence": float(entry.get("confidence", 0.6)),
                            })
                            if isinstance(wr, dict) and wr.get("ok"):
                                bb_written += 1
                    except Exception:
                        pass

                # LLM-visible state-sync guidance: make blackboard usage explicit.
                if isinstance(compacted, dict):
                    if bb_entries:
                        compacted.setdefault(
                            "llm_state_sync",
                            {
                                "blackboard_entries_suggested": len(bb_entries),
                                "blackboard_entries_written": bb_written,
                                "recommended_next": {
                                    "tool": "blackboard",
                                    "arguments": {"action": "list"},
                                },
                            },
                        )
                    else:
                        # Periodic reminder for long analysis chains to externalize state.
                        if tool_name in {"code", "search", "xref_analysis", "threat_hunt", "predictor"}:
                            compacted.setdefault(
                                "llm_state_sync_hint",
                                {
                                    "message": "Persist important findings to blackboard to avoid context-loss.",
                                    "tool": "blackboard",
                                    "arguments": {
                                        "action": "write",
                                        "name": "finding_summary",
                                        "notes": "<concise finding>",
                                        "category": "analysis",
                                        "priority": 3,
                                    },
                                },
                            )
            except Exception:
                pass

            # ---- State Contract Enforcement ----
            try:
                if (
                    hasattr(self, "session_mgr")
                    and self.current_session
                    and tool_name not in {"session", "blackboard", "batch", "predictor", "workflow"}
                ):
                    sid = self.current_session.session_id
                    contract = self.session_mgr.check_state_contract(sid, window=16)
                    if isinstance(contract, dict) and contract.get("ok") and not contract.get("contract_met"):
                        # Only show reminder every 16 calls to reduce bloat
                        compacted.setdefault(
                            "llm_state_contract_reminder",
                            {
                                "message": f"No blackboard write in last {contract.get('window_size', 16)} calls. Persist findings to maintain state.",
                                "recommended_action": contract.get("recommended_action"),
                                "contract_met": False,
                            },
                        )
            except Exception:
                pass

            # ---- Confidence Gate ----
            try:
                if isinstance(compacted, dict):
                    conf = compacted.get("confidence")
                    if conf is not None:
                        try:
                            conf_val = float(conf)
                            if conf_val < 0.5:
                                compacted.setdefault(
                                    "llm_low_confidence_gate",
                                    {
                                        "confidence": conf_val,
                                        "threshold": 0.5,
                                        "message": "Result confidence is below threshold. Verify before acting.",
                                        "verification_actions": [
                                            {"tool": "calc", "arguments": {"action": "eval", "expr": "1+1"}},
                                            {"tool": "memory", "arguments": {"action": "read", "addr": "0x0", "size": 16}},
                                        ],
                                    },
                                )
                        except Exception:
                            pass
            except Exception:
                pass

            # ---- Intelligence Layer: assemble real context and inject ----
            try:
                if isinstance(compacted, dict):
                    addr = ""
                    if isinstance(call_args, dict):
                        addr = str(call_args.get("addr") or call_args.get("addrs") or "")
                    self._assemble_and_inject_context(
                        tool_name, action_name, compacted, addr, opts=opts
                    )
            except Exception:
                pass
        return compacted
