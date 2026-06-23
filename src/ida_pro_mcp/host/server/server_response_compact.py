"""Response compaction/option helpers for ServerResponseMixin."""

from __future__ import annotations

from typing import Any

from ..config import (
    _bounded_int,
    _coerce_bool,
    _parse_str_list,
    _COMPACT_DETAIL_LIST_KEYS,
    _COMPACT_DROP,
    _COMPACT_META_KEYS,
)
from ..errors import is_error_result


class ServerResponseCompactMixin:
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
                if key == "ok" and raw is False:
                    out[key] = False
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
            is_error = is_error_result(raw_result)
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
