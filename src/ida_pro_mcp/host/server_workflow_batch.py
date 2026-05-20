#!/usr/bin/env python3
"""Batch normalization/execution helpers for workflow mixin."""

from __future__ import annotations

import json
from typing import Any, Optional

from .config import MAX_BATCH_CALLS, MAX_BATCH_PAYLOAD_BYTES
from .errors import MCPError, make_error
from .schemas import TOOLS, _resolve_tool_alias


class ServerWorkflowBatchMixin:
    def _normalize_batch_call(
        self, call: Any, idx: int
    ) -> tuple[Optional[str], Any, Optional[dict]]:
        """
        Normalize one batch entry.
        Supported forms:
        - "tool:action" / "tool"
        - {"name": "...", "arguments": {...}} (or args)
        - {"tool": "...", "action": "...", ...inline_args}
        """
        if isinstance(call, str):
            raw = call.strip()
            if not raw:
                return (
                    None,
                    {},
                    make_error(MCPError.INVALID_ARGS, f"Call at index {idx} is empty"),
                )
            if ":" in raw:
                name, action = raw.split(":", 1)
                name = name.strip()
                action = action.strip()
                if not name:
                    return (
                        None,
                        {},
                        make_error(
                            MCPError.INVALID_ARGS,
                            f"Call at index {idx} missing tool name",
                        ),
                    )
                call_args = {"action": action} if action else {}
                return name, call_args, None
            return raw, {}, None
        if not isinstance(call, dict):
            return (
                None,
                {},
                make_error(
                    MCPError.INVALID_ARGS,
                    f"Call at index {idx} must be an object or string",
                ),
            )

        name = call.get("name", call.get("tool"))
        call_args = call.get("arguments", call.get("args"))
        if call_args is None:
            call_args = {}
        if not isinstance(call_args, dict):
            return name, call_args, None

        if "action" not in call_args and isinstance(call.get("action"), str):
            call_args = dict(call_args)
            call_args["action"] = call.get("action")
        passthrough = {
            k: v
            for k, v in call.items()
            if k not in {"name", "tool", "arguments", "args", "action"}
        }
        if passthrough:
            call_args = dict(call_args)
            for k, v in passthrough.items():
                call_args.setdefault(k, v)
        return name, call_args, None


    def _handle_batch(self, args):
        calls = args.get("calls", [])
        if not isinstance(calls, list):
            return make_error(
                MCPError.INVALID_ARGS,
                "calls must be a list of call objects or 'tool:action' strings",
            )
        if not calls:
            return make_error(
                MCPError.BATCH_EMPTY,
                "No calls provided in batch",
                hint="Provide at least one call: batch(calls=[{name: 'tool', arguments: {...}}])",
            )
        if len(calls) > MAX_BATCH_CALLS:
            return make_error(
                MCPError.BATCH_TOO_LARGE,
                f"Too many batch calls ({len(calls)}, max {MAX_BATCH_CALLS})",
                hint=f"Split into multiple batch requests of {MAX_BATCH_CALLS} or fewer calls.",
            )

        try:
            payload_size = len(json.dumps(calls, separators=(",", ":")))
        except Exception:
            payload_size = MAX_BATCH_PAYLOAD_BYTES + 1
        if payload_size > MAX_BATCH_PAYLOAD_BYTES:
            return make_error(
                MCPError.INVALID_ARGS,
                f"Batch payload too large ({payload_size} bytes, max {MAX_BATCH_PAYLOAD_BYTES})",
            )

        continue_on_error = bool(args.get("continue_on_error", False))
        results = []
        for idx, call in enumerate(calls):
            name, call_args, normalize_err = self._normalize_batch_call(call, idx)
            if normalize_err:
                res = normalize_err
            resolved_name = _resolve_tool_alias(name)

            if normalize_err:
                results.append({"index": idx, "name": name, "result": res})
                if res.get("error") and not continue_on_error:
                    break
                continue
            elif not name:
                res = make_error(
                    MCPError.INVALID_ARGS,
                    f"Call at index {idx} missing name field",
                    hint="Each batch call must have a name field specifying the tool.",
                )
            elif not isinstance(name, str):
                res = make_error(
                    MCPError.INVALID_ARGS, f"Call at index {idx} has non-string name"
                )
            elif resolved_name == "batch":
                res = make_error(
                    MCPError.INVALID_ARGS, "Nested batch calls are not allowed"
                )
            elif resolved_name not in TOOLS:
                res = make_error(
                    MCPError.INVALID_ARGS,
                    f"Unknown tool {name} in batch call at index {idx}",
                    hint=f"Valid tools include: {', '.join(TOOLS[:10])}... Use tools/list for full list.",
                )
            elif call_args is None:
                call_args = {}
                res = self._execute_tool(name, call_args)
            elif not isinstance(call_args, dict):
                res = make_error(
                    MCPError.INVALID_ARGS,
                    f"Call at index {idx} has non-object arguments",
                )
            else:
                cleaned_args, _ = self._extract_response_options(call_args)
                res = self._execute_tool(name, cleaned_args)
                if isinstance(cleaned_args, dict):
                    res = self._cache_next_page(
                        resolved_name or name, cleaned_args, res
                    )
                    self._record_activity(resolved_name or name, cleaned_args, res)
            results.append({"index": idx, "name": name, "result": res})
            if res.get("error") and not continue_on_error:
                break
        errors = sum(
            1
            for item in results
            if isinstance(item.get("result"), dict) and item["result"].get("error")
        )
        return {
            "ok": True,
            "results": results,
            "count": len(results),
            "summary": {
                "total": len(results),
                "ok": len(results) - errors,
                "errors": errors,
                "stopped_on_error": bool(
                    errors and not continue_on_error and len(results) < len(calls)
                ),
            },
        }

