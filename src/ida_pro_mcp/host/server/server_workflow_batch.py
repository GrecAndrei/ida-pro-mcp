#!/usr/bin/env python3
"""Batch normalization/execution helpers for workflow mixin."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from ..config import MAX_BATCH_CALLS, MAX_BATCH_PAYLOAD_BYTES, _coerce_bool
from ..errors import MCPError, is_error_result, make_error
from ..policy import PolicyDecision, evaluate_policy
from ..schemas import TOOLS, _resolve_tool_alias
from .postprocess import (
    apply_post_processing,
    has_post_process,
    prepare_args_for_postprocess,
)
from .rate_limit import is_rate_limit_exempt
from .server_response import truncate_response

# Keys that workflow composition/prioritization annotate onto planned calls
# for the human reader (sources/source_count/index, priority_index/priority_mode)
# plus the batch chaining directive (output_key). They are not tool arguments:
# merging them into call_args through the passthrough would have every step
# rejected by RPC argument admission.
_NON_ARG_ANNOTATION_KEYS = {
    "sources",
    "source_count",
    "index",
    "priority_index",
    "priority_mode",
    "output_key",
    "_precomputed_error",
}

# D5: tools that never take the single-list-RPC fast path. They are either
# host-only (no IDA RPC at all), exec-heavy (misc scripts), or embedding-heavy
# (intelligence) where a list-shaped RPC would serialize one slow job behind
# the rest. Read eligibility for everything else is decided by policy risk:
# a call is fast-path-eligible only when evaluate_policy classifies it as a
# pure READ (ALLOW, no ack, no flags).
_BATCH_FAST_PATH_EXCLUDED_TOOLS = frozenset({
    "batch",
    "session",
    "blackboard",
    "background",
    "bookmarks",
    "truncation",
    "wiki",
    "multi_session",
    "workflow",
    "misc",
    "intelligence",
    "r2",
})


class ServerWorkflowBatchMixin:
    def _normalize_batch_call(
        self, call: Any, idx: int
    ) -> tuple[str | None, Any, dict | None]:
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
            and k not in _NON_ARG_ANNOTATION_KEYS
        }
        if passthrough:
            call_args = dict(call_args)
            for k, v in passthrough.items():
                call_args.setdefault(k, v)
        return name, call_args, None


    def _try_batch_fast_path(self, calls, continue_on_error):
        """D5: serve the whole batch with ONE list-shaped RPC.

        The IDA-side bridge (server_script.run_server) already accepts a JSON
        array request and maps each element through process_single; the host's
        _send_rpc_raw only injects the session token into dict payloads, so
        each array item carries its own token.

        Returns a complete batch envelope, or None when any call is ineligible
        — the caller then runs the existing per-call loop, which preserves
        exact behavior for host-only tools, writes, policy-blocked reads,
        safe mode, and rate-limit denials. Eligibility is intentionally
        narrow; nothing is sent until every call has passed.
        """
        entries = []  # (idx, name, resolved_name, cleaned_args, opts)
        target_session = None
        for idx, call in enumerate(calls):
            name, call_args, normalize_err = self._normalize_batch_call(call, idx)
            if normalize_err or not name:
                return None
            if isinstance(call, dict) and call.get("_precomputed_error") is not None:
                return None
            resolved_name = _resolve_tool_alias(name)
            if resolved_name == "batch" or resolved_name not in TOOLS:
                return None
            if not isinstance(call_args, dict):
                return None
            cleaned_args, opts = self._extract_response_options(call_args)
            if not isinstance(cleaned_args, dict):
                return None

            # Single RPC goes to exactly one runtime: every call must target
            # the same session (explicit idb ref, or the shared active default).
            idb_ref = cleaned_args.get("idb")
            sess = None
            if idb_ref:
                try:
                    sess = self._resolve_session_from_idb_ref(idb_ref)
                except Exception:
                    return None
                if sess is None:
                    return None
            else:
                sess = self.current_session
            if sess is None:
                return None
            if target_session is None:
                target_session = sess
            elif sess.session_id != target_session.session_id:
                return None

            action = str(cleaned_args.get("action", "") or "")
            if resolved_name in _BATCH_FAST_PATH_EXCLUDED_TOOLS:
                return None
            # Pure-read gate: policy must allow as a read with no ack, no
            # reasons, and no flags. This is the same classification the
            # per-call path enforces in _execute_tool_inner.
            try:
                pr = evaluate_policy(
                    resolved_name,
                    action,
                    mode=self._resolve_policy_mode(),
                    purpose=cleaned_args.get("_purpose"),
                )
            except Exception:
                return None
            if (
                pr.decision != PolicyDecision.ALLOW
                or pr.risk.value != "read"
                or pr.reasons
                or pr.flags
            ):
                return None
            # Safe mode blocks full-binary analysis even for reads.
            if (
                self._safe_mode_gate(
                    target_session.session_id, resolved_name, action
                )
                is not None
            ):
                return None
            entries.append((idx, name, resolved_name, cleaned_args, opts))

        if len(entries) < 2:
            return None

        runtime = self._runtime_record(target_session.session_id)
        if not isinstance(runtime, dict):
            return None
        port = runtime.get("port")
        if (
            not isinstance(port, int)
            or port <= 0
            or not self._runtime_alive(runtime)
        ):
            return None
        auth_token = str(runtime.get("auth_token") or "")

        # Preserve the rate-limit contract: consume a token per call the same
        # way the per-call loop would. Consumption happens only now, after
        # every eligibility check passed, so a fallback never double-consumes
        # (a denial here falls back and the loop returns the canonical
        # RATE_LIMIT envelope).
        reserved_tools: list[str] = []
        for _idx, _name, _resolved, _cleaned, _opts in entries:
            _action = str(_cleaned.get("action", "") or "")
            if is_rate_limit_exempt(_resolved, _action):
                continue
            allowed, _reason = self.rate_limiter.check(_resolved)
            if not allowed:
                refund = getattr(self.rate_limiter, "refund", None)
                if callable(refund):
                    for tool in reserved_tools:
                        refund(tool)
                return None
            reserved_tools.append(_resolved)

        # Build one list-shaped payload. Mirror _execute_tool_inner's pre-RPC
        # steps per call: strip PP keys and truncation controls so they never
        # reach IDA; inject the session token per item.
        rpc_items = []
        per_entry = []
        recv_timeout = None
        for idx, name, resolved_name, cleaned_args, opts in entries:
            rpc_args = dict(cleaned_args)
            rpc_args, pp = prepare_args_for_postprocess(resolved_name, rpc_args)
            tc = {
                "no_truncate": _coerce_bool(
                    rpc_args.pop("no_truncate", None), False
                ),
                "max_tokens": rpc_args.pop("max_tokens", None),
                "trunc_offset": rpc_args.pop("trunc_offset", None),
                "trunc_limit": rpc_args.pop("trunc_limit", None),
            }
            rpc_args.pop("_purpose", None)
            rpc_args.pop("_risk_ack", None)
            rpc_args.pop("_guardrail_ack", None)
            try:
                _to = self._long_running_sock_timeout(resolved_name, rpc_args)
            except Exception:
                _to = -1
            if _to is not None and _to > 0:
                recv_timeout = _to if recv_timeout is None else max(recv_timeout, _to)
            rpc_items.append(
                {
                    "tool": name,
                    "args": rpc_args,
                    "session_token": auth_token,
                }
            )
            per_entry.append((idx, name, resolved_name, cleaned_args, opts, pp, tc))

        try:
            rpc_res = self._send_rpc_with_retry(
                rpc_items, port, auth_token=auth_token, recv_timeout=recv_timeout
            )
        except Exception:
            # The normal per-call loop will check rate limits again. Return the
            # reservations made above so a fallback is not charged twice.
            refund = getattr(self.rate_limiter, "refund", None)
            if callable(refund):
                for tool in reserved_tools:
                    refund(tool)
            return None

        if not isinstance(rpc_res, list) or len(rpc_res) != len(rpc_items):
            # Malformed/odd response after a successful send: surface per-item
            # errors rather than silently dropping or re-sending.
            results = [
                {
                    "index": idx,
                    "name": name,
                    "result": make_error(
                        MCPError.RPC_CONNECTION_ERROR,
                        "Batch RPC returned a malformed response",
                    ),
                }
                for idx, name, _r, _c, _o, _p, _t in per_entry
            ]
            return {
                "ok": False,
                "results": results,
                "count": len(results),
                "summary": {
                    "total": len(results),
                    "ok": 0,
                    "errors": len(results),
                    "stopped_on_error": False,
                },
            }

        # Each item result runs the same tail pipeline call_tool + _execute_tool
        # apply to a single call: truncation, post-processing (+ next token),
        # tool-level next page, and activity recording.
        results = []
        for i, (idx, name, resolved_name, cleaned_args, _opts, pp, tc) in enumerate(
            per_entry
        ):
            res = rpc_res[i]
            if isinstance(res, dict) and "error" not in res and "ok" not in res:
                res = {"ok": True, **res}
            # Truncation (mirror call_tool's per-call override block).
            if not tc.get("no_truncate"):
                try:
                    _budget = tc.get("max_tokens") or self.default_truncate_tokens
                    _owner = ""
                    if hasattr(self, "_truncation_owner_id"):
                        _owner = self._truncation_owner_id()
                    res = truncate_response(
                        res,
                        max_tokens=_budget,
                        trunc_offset=tc.get("trunc_offset"),
                        trunc_limit=tc.get("trunc_limit"),
                        session_id=target_session.session_id,
                        owner_id=_owner,
                    )
                except Exception:
                    pass
            # Post-processing + PP continuation token (mirror _execute_tool).
            if pp and has_post_process(pp) and not is_error_result(res):
                try:
                    if not (isinstance(res, dict) and res.get("_post_processed")):
                        res = apply_post_processing(res, pp)
                    res = self._cache_post_process_next(
                        resolved_name, rpc_args, pp, res
                    )
                except Exception as _pp_err:
                    import logging

                    logging.getLogger(__name__).debug(
                        "batch fast-path post-process failed: %s", _pp_err
                    )
            if isinstance(cleaned_args, dict):
                res = self._cache_next_page(resolved_name or name, cleaned_args, res)
                self._record_activity(resolved_name or name, cleaned_args, res)
            results.append({"index": idx, "name": name, "result": res})
            if is_error_result(res) and not continue_on_error:
                break

        errors = sum(
            1 for item in results if is_error_result(item.get("result"))
        )
        return {
            "ok": errors == 0,
            "results": results,
            "count": len(results),
            "summary": {
                "total": len(results),
                "ok": len(results) - errors,
                "errors": errors,
                "stopped_on_error": bool(
                    errors
                    and not continue_on_error
                    and len(results) < len(calls)
                ),
            },
        }

    def _extract_batch_bindings(self, args) -> tuple[dict, dict | None]:
        """Read the optional static ``bindings`` {param: value} map.

        ``bindings`` feeds ``$param`` references in later call arguments. It is
        a plain static map, never resolved against step results itself. A
        non-object value is a hard INVALID_ARGS error (never silently ignored).
        """
        bindings = args.get("bindings") if isinstance(args, dict) else None
        if bindings is None:
            return {}, None
        if not isinstance(bindings, dict):
            return None, make_error(
                MCPError.INVALID_ARGS,
                "bindings must be an object mapping names to values",
                hint="Example: batch(calls=[...], bindings={'base_addr': '0x401000'})",
            )
        return dict(bindings), None

    def _step_output_key(self, call: Any, idx: int) -> str:
        """The name a step's result is stored under for later steps.

        A step may declare ``output_key`` (a sibling of ``name``/``arguments``);
        the default is ``step{i}`` (its index). ``output_key`` is metadata and
        is stripped from tool arguments by ``_normalize_batch_call``.
        """
        if isinstance(call, dict):
            ok = call.get("output_key")
            if isinstance(ok, str) and ok.strip():
                return ok.strip()
        return f"step{idx}"

    def _batch_value_is_reference(self, value: Any, known_keys: set[str]) -> bool:
        """True when a string value would be treated as an output→input reference.

        Used only to decide fast-path eligibility, so it is deliberately
        conservative (a false positive falls back to the per-call loop, which
        stays correct; a false negative would send a raw ref string to IDA).
        """
        if isinstance(value, dict):
            return any(self._batch_value_is_reference(v, known_keys) for v in value.values())
        if isinstance(value, list):
            return any(self._batch_value_is_reference(v, known_keys) for v in value)
        if not isinstance(value, str) or not value:
            return False
        if re.match(r"^\$[A-Za-z_][A-Za-z0-9_]*$", value):
            return True
        # step{i}_{key} / step{i}.result{path} — including an index that has no
        # result yet (forward/out-of-range refs must still take the per-call
        # loop so they produce a real error instead of hitting the fast path).
        if re.match(r"^step\d+[._]", value):
            return True
        for key in known_keys:
            if value == key + ".result" or value.startswith((key + ".result.", key + "_")):
                return True
        return False

    def _batch_calls_use_chaining(self, calls) -> bool:
        """True when any step needs output→input chaining (a ``$param`` binding
        reference, a ``step{i}_{key}``/``step{i}.result{path}`` step reference,
        or a declared ``output_key`` naming a result for later steps)."""
        known_keys = {self._step_output_key(call, idx) for idx, call in enumerate(calls)}
        for call in calls:
            if not isinstance(call, dict):
                continue
            args = call.get("arguments", call.get("args"))
            if isinstance(args, dict) and self._batch_value_is_reference(args, known_keys):
                return True
            for k, v in call.items():
                if k in {"name", "tool", "arguments", "args", "action"} or k in _NON_ARG_ANNOTATION_KEYS:
                    continue
                if self._batch_value_is_reference(v, known_keys):
                    return True
        return False

    def _dotted_path_get(self, target: Any, path: str) -> tuple[Any, bool]:
        """Read ``path`` (dot-separated field/index segments) from a result."""
        value = target
        for part in path.split("."):
            if isinstance(value, dict):
                if part not in value:
                    return None, False
                value = value[part]
            elif isinstance(value, (list, tuple)):
                try:
                    value = value[int(part)]
                except (ValueError, IndexError, TypeError):
                    return None, False
            else:
                return None, False
        return value, True

    def _resolve_batch_value(self, value: Any, bindings: dict, results_map: dict, known_keys: set, idx: int) -> tuple[Any, dict | None]:
        """Resolve output→input references in one argument value.

        Precedence (lowest to highest): step refs ``step{i}_{key}`` /
        ``step{i}.result{path}``, then ``$param`` bindings, then a literal value
        the caller wrote directly. Resolution is recursive over dicts/lists.

        An unresolved reference is a clear INVALID_ARGS error, never a silent
        empty string or a raw passthrough of the reference text.
        """
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for k, v in value.items():
                rv, err = self._resolve_batch_value(v, bindings, results_map, known_keys, idx)
                if err is not None:
                    return None, err
                out[k] = rv
            return out, None
        if isinstance(value, list):
            out = []
            for v in value:
                rv, err = self._resolve_batch_value(v, bindings, results_map, known_keys, idx)
                if err is not None:
                    return None, err
                out.append(rv)
            return out, None
        if not isinstance(value, str) or not value:
            return value, None

        # $param binding reference.
        m = re.match(r"^\$([A-Za-z_][A-Za-z0-9_]*)$", value)
        if m:
            param = m.group(1)
            if param in bindings:
                return bindings[param], None
            return None, make_error(
                MCPError.INVALID_ARGS,
                f"Batch step {idx}: unresolved binding reference '{value}'",
                hint="Provide bindings={param: value} on the batch/execute request, or replace the reference with a literal value.",
            )

        # step{i}.result{path} / <output_key>.result{path} — nested reads.
        for key in sorted(results_map, key=len, reverse=True):
            if value == key + ".result" or value.startswith(key + ".result."):
                path = value[len(key) + len(".result"):].lstrip(".")
                target = results_map[key]
                if not path:
                    return target, None
                found, ok = self._dotted_path_get(target, path)
                if not ok:
                    return None, make_error(
                        MCPError.INVALID_ARGS,
                        f"Batch step {idx}: unresolved result reference '{value}'",
                        hint=f"Step '{key}' produced no nested field at '{path}'; reference an existing field.",
                    )
                return found, None

        # step{i}_{key} / <output_key>_{key} — top-level field of a prior result.
        for key in sorted(results_map, key=len, reverse=True):
            if value.startswith(key + "_"):
                field = value[len(key) + 1:]
                target = results_map[key]
                if isinstance(target, dict) and field in target:
                    return target[field], None
                return None, make_error(
                    MCPError.INVALID_ARGS,
                    f"Batch step {idx}: unresolved step reference '{value}'",
                    hint=f"Step '{key}' produced no '{field}' field; reference an existing result field.",
                )

        # A reference whose step is declared but produced no result yet (forward
        # reference, or the step errored) must error, not pass through raw.
        for key in sorted(known_keys, key=len, reverse=True):
            if value == key + ".result" or value.startswith((key + ".result.", key + "_")):
                return None, make_error(
                    MCPError.INVALID_ARGS,
                    f"Batch step {idx}: unresolved step reference '{value}'",
                    hint=f"Step '{key}' has no result yet (it is declared but has not produced one); only completed steps can feed later calls.",
                )

        # step{i}_{key} / step{i}.result{path} for an index with no result at
        # all (out-of-range or never-run) — still a hard error, never a silent
        # passthrough of the reference text.
        m = re.match(r"^step(\d+)(?:_|\.result)", value)
        if m:
            return None, make_error(
                MCPError.INVALID_ARGS,
                f"Batch step {idx}: unresolved step reference '{value}'",
                hint=f"Step 'step{m.group(1)}' produced no result; only completed steps can feed later calls.",
            )

        return value, None

    def _resolve_batch_step_args(self, call_args: dict, bindings: dict, results_map: dict, known_keys: set, idx: int) -> tuple[dict, dict | None]:
        """Resolve every output→input reference in a step's argument dict."""
        resolved, err = self._resolve_batch_value(call_args, bindings, results_map, known_keys, idx)
        if err is not None:
            return None, err
        if not isinstance(resolved, dict):
            return None, make_error(
                MCPError.INVALID_ARGS,
                f"Batch step {idx} arguments must be an object",
            )
        return resolved, None

    def _run_batch_steps(self, calls, continue_on_error, bindings=None, wrap_errors=False, validate_tools=True) -> list[dict]:
        """Execute a sequence of batch calls with output→input chaining.

        This is the shared step executor used by both ``_handle_batch`` and
        workflow ``execute_plan``. It normalizes each call, resolves output
        references (``$param``, ``step{i}_{key}``, ``step{i}.result{path}``)
        against ``bindings`` and the accumulated results map, executes via
        ``_execute_tool``, and returns one dict per executed step::

            {"index", "name", "resolved_name", "call_args", "result", "elapsed_ms"}

        ``call_args`` is the resolved, response-option-stripped argument dict
        actually handed to ``_execute_tool``. A step may declare ``output_key``
        (default ``step{i}``) to name its result for later steps. Steps that
        error are still returned; execution halts on the first error when
        ``continue_on_error`` is false. With ``wrap_errors`` a raised
        ``_execute_tool`` becomes an INTERNAL error envelope (execute_plan
        semantics); otherwise it propagates (``_handle_batch`` semantics).
        With ``validate_tools=False`` the nested-batch and unknown-tool
        admission checks are skipped and every name reaches ``_execute_tool``
        (execute_plan semantics — its plan normalization defers tool
        validation to dispatch; ``_handle_batch`` keeps the checks).
        """
        bindings = dict(bindings) if isinstance(bindings, dict) else {}
        known_keys = {self._step_output_key(call, idx) for idx, call in enumerate(calls)}
        results_map: dict[str, Any] = {}
        steps: list[dict] = []
        for idx, call in enumerate(calls):
            name, call_args, normalize_err = self._normalize_batch_call(call, idx)
            resolved_name = _resolve_tool_alias(name)
            res: dict | Any = None
            step_args: dict = {}
            elapsed_ms = 0
            pre_err = call.get("_precomputed_error") if isinstance(call, dict) else None
            if pre_err is not None:
                res = pre_err
            elif normalize_err:
                res = normalize_err
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
            elif validate_tools and resolved_name == "batch":
                res = make_error(
                    MCPError.INVALID_ARGS, "Nested batch calls are not allowed"
                )
            elif validate_tools and resolved_name not in TOOLS:
                res = make_error(
                    MCPError.INVALID_ARGS,
                    f"Unknown tool {name} in batch call at index {idx}",
                    hint="Use ida_help or tools/list for valid operation names.",
                )
            elif not isinstance(call_args, dict):
                res = make_error(
                    MCPError.INVALID_ARGS,
                    f"Call at index {idx} has non-object arguments",
                )
            else:
                resolved_args, resolve_err = self._resolve_batch_step_args(
                    call_args, bindings, results_map, known_keys, idx
                )
                if resolve_err is not None:
                    res = resolve_err
                    step_args = dict(call_args)
                else:
                    step_args, _ = self._extract_response_options(resolved_args)
                    t0 = time.perf_counter()
                    try:
                        res = self._execute_tool(name, step_args)
                    except Exception as e:
                        if not wrap_errors:
                            raise
                        res = make_error(
                            MCPError.INTERNAL,
                            f"Step execution failed for '{name}': {e}",
                            hint="Retry the step manually or check the tool arguments.",
                        )
                    elapsed_ms = int((time.perf_counter() - t0) * 1000)
            steps.append(
                {
                    "index": idx,
                    "name": name,
                    "resolved_name": resolved_name,
                    "call_args": step_args,
                    "result": res,
                    "elapsed_ms": elapsed_ms,
                }
            )
            if not is_error_result(res) and isinstance(res, dict):
                results_map[self._step_output_key(call, idx)] = res
            if is_error_result(res) and not continue_on_error:
                break
        return steps

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

        # _coerce_bool, not bool(): a caller passing the JSON string "false"
        # must get stop-on-error semantics, not continue-on-error.
        continue_on_error = _coerce_bool(args.get("continue_on_error"), False)

        bindings, bindings_err = self._extract_batch_bindings(args)
        if bindings_err is not None:
            return bindings_err

        # D5: try the single-list-RPC fast path. It is only valid when no step
        # needs output→input chaining (a bindings map or a step reference) —
        # those steps must run in order with the results map accumulating
        # between calls, so they take the per-call loop. When the fast path is
        # ineligible it returns None and the loop below runs unchanged.
        uses_chaining = bool(bindings) or self._batch_calls_use_chaining(calls)
        fast = None
        if not uses_chaining:
            fast = self._try_batch_fast_path(calls, continue_on_error)
        if fast is not None:
            return fast

        steps = self._run_batch_steps(calls, continue_on_error, bindings)
        results = []
        for step in steps:
            res = step["result"]
            step_args = step["call_args"]
            if isinstance(step_args, dict):
                res = self._cache_next_page(
                    step["resolved_name"] or step["name"], step_args, res
                )
                self._record_activity(step["resolved_name"] or step["name"], step_args, res)
            results.append({"index": step["index"], "name": step["name"], "result": res})
        errors = sum(
            1
            for item in results
            if is_error_result(item.get("result"))
        )
        return {
            "ok": errors == 0,
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
