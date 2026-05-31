#!/usr/bin/env python3
"""Generic dispatch helpers for IDAMCPServer."""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from ida_pro_mcp import __version__

from .config import _bounded_int, _coerce_bool, _is_writable_dir, log_rpc
from .errors import MCPError, make_error
from .policy import PolicyDecision, build_audit_record, evaluate_policy
from .schemas import (
    TOOL_ACTIONS,
    TOOL_ARG_SCHEMAS,
    TOOLS,
    WRAPPER_ACTIONS,
    _resolve_tool_alias,
)
from .server_response import truncate_response


class ServerDispatchMixin:
    def call_tool(self, tool_name, idb_path, **kwargs):
            session = self._resolve_session_from_idb_ref(idb_path)
            if not session:
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    f"No session found for idb reference: {idb_path}",
                    hint="Use session_id, SID_* IDB id, binary/idb path, or create/switch a session first.",
                )

            runtime = self.session_runtimes.get(session.session_id)
            if (
                not runtime
                or not runtime.get("process")
                or runtime["process"].poll() is not None
            ):
                log_rpc(
                    f"Session start/restart needed: {session.session_id} -> {session.idb_path}"
                )
                start_res = self._start_server(session)
                if "error" in start_res:
                    return start_res
                runtime = self.session_runtimes.get(session.session_id)

            try:
                rpc_args = {
                    k: v
                    for k, v in kwargs.items()
                    if not (isinstance(k, str) and k.startswith("_"))
                }
                try:
                    allowed = set((TOOL_ARG_SCHEMAS.get(tool_name) or {}).keys())
                    if allowed:
                        rpc_args = {k: v for k, v in rpc_args.items() if k in allowed}
                except Exception:
                    pass
                res = self._send_rpc_raw(
                    {"tool": tool_name, "args": rpc_args}, runtime["port"]
                )
                if isinstance(res, dict) and "error" not in res and "ok" not in res:
                    res = {"ok": True, **res}
                res = truncate_response(res, max_tokens=self.default_truncate_tokens)
                # MemRL observation for IDA-side tools
                if isinstance(res, dict):
                    self._observe_memrl(
                        tool_name,
                        str(kwargs.get("action") or ""),
                        res,
                    )
                return res
            except Exception as e:
                proc = runtime.get("process")
                exit_code = proc.poll() if proc else None
                if exit_code is not None:
                    return make_error(
                        MCPError.IDA_CRASHED,
                        f"IDA exited with code {exit_code}",
                        details={
                            "log": self._get_ida_diagnostics(
                                runtime.get("stdout_log"),
                                runtime.get("stderr_log"),
                            )
                        },
                    )
                return make_error(MCPError.IDA_CRASHED, str(e))

    def _handle_misc_health(self, args: dict) -> dict:
            verbose = bool(args.get("verbose", False))
            wiki_root = self._resolve_wiki_root()
            wiki_available = bool(wiki_root and os.path.isdir(wiki_root))
            idat_path = self.idat_exe or ""
            idat_exists = bool(idat_path and os.path.exists(idat_path))
            runtime_states = []
            running = 0
            stale = 0
            for sid, runtime in self.session_runtimes.items():
                alive = bool(runtime and runtime.is_alive())
                if alive:
                    running += 1
                else:
                    stale += 1
                if verbose:
                    runtime_states.append(
                        {
                            "session_id": sid,
                            "alive": alive,
                            "port": runtime.port if runtime else None,
                        }
                    )

            payload = {
                "ok": True,
                "action": "health",
                "server": {"name": "ida-pro-mcp", "version": __version__},
                "runtime": {
                    "cache_dir": self.cache_dir,
                    "cache_writable": _is_writable_dir(self.cache_dir),
                    "cache_exists": os.path.isdir(self.cache_dir),
                },
                "ida": {
                    "ida_dir": self.ida_dir,
                    "idat_path": idat_path or None,
                    "idat_found": idat_exists,
                },
                "sessions": {
                    "total": len(self.session_mgr.discover_sessions()),
                    "active": self.current_session.session_id
                    if self.current_session
                    else None,
                    "runtime_processes": {
                        "tracked": len(self.session_runtimes),
                        "running": running,
                        "stale": stale,
                    },
                },
                "wiki": {"root": wiki_root or None, "available": wiki_available},
                "tools": {"registered": len(TOOLS)},
            }
            if verbose:
                payload["sessions"]["runtimes"] = runtime_states
            return payload

    def _handle_bookmarks(self, args: dict) -> dict:
            if not self.current_session:
                return make_error(
                    MCPError.SESSION_REQUIRED,
                    "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
                )
            action = str(args.get("action") or "").strip().lower()
            sid = self.current_session.session_id
            mgr = getattr(self, "bookmark_mgr", None)
            if mgr is None:
                return make_error(MCPError.INVALID_ARGS, "Bookmark manager unavailable")
            if action == "add":
                return mgr.add(sid, args)
            if action == "list":
                filters = {
                    key: args.get(key)
                    for key in ("category", "tag", "priority", "query")
                    if args.get(key) is not None
                }
                res = mgr.list(sid, filters)
                return res
            if action == "delete":
                return mgr.delete(sid, args)
            if action == "update":
                return mgr.update(sid, args)
            if action == "clear":
                return mgr.clear(sid)
            if action == "find":
                query = str(args.get("query") or args.get("q") or "").strip()
                if not query:
                    return make_error(MCPError.INVALID_ARGS, "query required")
                return mgr.find(sid, query)
            if action == "export":
                return mgr.export(sid)
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported bookmarks action: '{action}'",
                hint="Use bookmarks(action='list'|'add'|'delete'|'update'|'clear'|'find'|'export').",
            )

    def _handle_truncation(self, args: dict) -> dict:
            action = str(args.get("action") or "").strip().lower()
            if action != "continue":
                return make_error(
                    MCPError.ACTION_NOT_FOUND,
                    f"Unsupported truncation action: '{action}'",
                    hint="Use truncation(action='continue', token='...').",
                )
            token = args.get("token") or args.get("next_token")
            if not isinstance(token, str) or not token.strip():
                return make_error(
                    MCPError.TRUNCATION_TOKEN_INVALID,
                    "Invalid continuation token. Check the token value.",
                )
            token = token.strip()
            field = args.get("field")
            offset = args.get("offset")
            count = args.get("count")
            from . import server as _server_mod

            result = _server_mod.continue_truncated(
                token,
                field=field if isinstance(field, str) else None,
                offset=_bounded_int(offset, 0, min_value=0, max_value=500000)
                if offset is not None
                else None,
                count=_bounded_int(count, 0, min_value=1, max_value=5000)
                if count is not None
                else None,
            )
            if isinstance(result, dict) and result.get("error") and "code" not in result:
                return make_error(
                    MCPError.TRUNCATION_TOKEN_INVALID,
                    result.get("message") or "Invalid continuation token. Check the token value.",
                )
            return result

    def _grep_value_lines(self, value: Any) -> list[str]:
            if value is None:
                return []
            if isinstance(value, str):
                return [line for line in value.splitlines() if line.strip()]
            if isinstance(value, list):
                out: list[str] = []
                for item in value:
                    if isinstance(item, str):
                        out.extend([line for line in item.splitlines() if line.strip()])
                    elif isinstance(item, dict):
                        out.append(
                            json.dumps(item, ensure_ascii=False, separators=(",", ":"))
                        )
                    else:
                        s = str(item).strip()
                        if s:
                            out.append(s)
                return out
            if isinstance(value, dict):
                out: list[str] = []
                for k, v in value.items():
                    if isinstance(v, str):
                        for line in v.splitlines():
                            line = line.strip()
                            if line:
                                out.append(line)
                    elif isinstance(v, list):
                        for item in v:
                            if isinstance(item, str) and item.strip():
                                out.append(item.strip())
                if out:
                    return out
                return [json.dumps(value, ensure_ascii=False, separators=(",", ":"))]
            s = str(value).strip()
            return [s] if s else []

    def _grep_collect_lines(
            self, payload: Any, field: Optional[str] = None
        ) -> tuple[list[str], str]:
            if field and isinstance(payload, dict):
                return self._grep_value_lines(payload.get(field)), field
            if isinstance(payload, dict):
                preferred_fields = (
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
                )
                for key in preferred_fields:
                    if key in payload:
                        lines = self._grep_value_lines(payload.get(key))
                        if lines:
                            return lines, key
                return self._grep_value_lines(payload), "payload"
            return self._grep_value_lines(payload), "payload"

    def _handle_tool_grep_action(self, tool_name: str, args: dict) -> dict:
            source_action, source_err = self._wrapper_source_action(tool_name, args, "grep")
            if source_err:
                return source_err

            explicit_pattern = args.get("grep") or args.get("grep_pattern")
            grep_pattern = explicit_pattern or args.get("pattern") or args.get("query")
            if not isinstance(grep_pattern, str) or not grep_pattern.strip():
                return make_error(
                    MCPError.INVALID_ARGS,
                    "grep pattern required",
                    hint="Set grep='...' (or grep_pattern/pattern/query) with action='grep'.",
                )
            grep_pattern = grep_pattern.strip()

            grep_regex = _coerce_bool(args.get("grep_regex"), False)
            grep_case_sensitive = _coerce_bool(args.get("grep_case_sensitive"), False)
            grep_invert = _coerce_bool(args.get("grep_invert"), False)
            grep_field = args.get("grep_field")
            if grep_field is not None and not isinstance(grep_field, str):
                return make_error(MCPError.INVALID_ARGS, "grep_field must be a string")
            grep_limit = _bounded_int(
                args.get("grep_limit", 200), 200, min_value=1, max_value=5000
            )
            grep_offset = _bounded_int(
                args.get("grep_offset", 0), 0, min_value=0, max_value=500000
            )

            child_args = self._strip_wrapper_args(args)
            if explicit_pattern is None:
                child_args.pop("pattern", None)
                child_args.pop("query", None)
            child_args["action"] = source_action

            source_payload = self._execute_tool(tool_name, child_args)
            if isinstance(source_payload, dict) and source_payload.get("error"):
                return source_payload

            lines, used_field = self._grep_collect_lines(source_payload, grep_field)
            if grep_regex:
                flags = 0 if grep_case_sensitive else re.IGNORECASE
                try:
                    rx = re.compile(grep_pattern, flags)
                except re.error as e:
                    return make_error(MCPError.INVALID_ARGS, f"Invalid grep regex: {e}")
                matched = [line for line in lines if bool(rx.search(line)) != grep_invert]
            else:
                needle = grep_pattern if grep_case_sensitive else grep_pattern.lower()
                matched = []
                for line in lines:
                    hay = line if grep_case_sensitive else line.lower()
                    found = needle in hay
                    if found != grep_invert:
                        matched.append(line)

            total = len(matched)
            page = matched[grep_offset : grep_offset + grep_limit]
            is_truncated = (grep_offset + len(page)) < total

            return {
                "ok": True,
                "action": "grep",
                "tool": tool_name,
                "source_action": source_action,
                "field": used_field,
                "pattern": grep_pattern,
                "matches": "\n".join(page),
                "source_count": len(lines),
                "count": len(page),
                "total": total,
                "offset": grep_offset,
                "truncated": is_truncated,
                "next_offset": (grep_offset + len(page)) if is_truncated else None,
            }

    def _handle_tool_pick_action(self, tool_name: str, args: dict) -> dict:
            source_action, source_err = self._wrapper_source_action(tool_name, args, "pick")
            if source_err:
                return source_err
            fields = _parse_str_list(args.get("pick_fields"))
            if not fields:
                fields = _parse_str_list(args.get("_response_fields"))
            if not fields:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "action='pick' requires pick_fields",
                    hint=f"Example: {tool_name}(action='pick', source_action='list', pick_fields='functions,count').",
                )
            omit = set(_parse_str_list(args.get("pick_omit")))

            child_args = self._strip_wrapper_args(args)
            child_args["action"] = source_action
            source_payload = self._execute_tool(tool_name, child_args)
            if isinstance(source_payload, dict) and source_payload.get("error"):
                return source_payload
            if not isinstance(source_payload, dict):
                return make_error(
                    MCPError.INVALID_ARGS,
                    "pick wrapper requires source payload object",
                    hint="Pick is top-level field projection; use grep/head/tail for line-oriented payloads.",
                )

            selected = {}
            missing: List[str] = []
            for key in fields:
                if key in source_payload:
                    selected[key] = source_payload.get(key)
                else:
                    missing.append(key)
            for key in omit:
                selected.pop(key, None)

            out = {
                "ok": True,
                "action": "pick",
                "tool": tool_name,
                "source_action": source_action,
                "picked": list(selected.keys()),
                **selected,
            }
            if missing:
                out["missing_fields"] = missing
            return out

    def _handle_tool_head_tail_action(
            self, tool_name: str, args: dict, *, tail: bool = False
        ) -> dict:
            wrapper_name = "tail" if tail else "head"
            source_action, source_err = self._wrapper_source_action(
                tool_name, args, wrapper_name
            )
            if source_err:
                return source_err

            default_n = 20
            n_key = "tail_n" if tail else "head_n"
            n = _bounded_int(
                args.get(n_key, default_n), default_n, min_value=1, max_value=5000
            )
            field = args.get("grep_field") or args.get("field")
            if field is not None and not isinstance(field, str):
                return make_error(MCPError.INVALID_ARGS, "field must be a string")

            child_args = self._strip_wrapper_args(args)
            child_args["action"] = source_action
            source_payload = self._execute_tool(tool_name, child_args)
            if isinstance(source_payload, dict) and source_payload.get("error"):
                return source_payload

            items, used_field, item_kind = self._collect_wrapper_items(
                source_payload, field
            )
            total = len(items)
            if tail:
                page = items[max(0, total - n) :]
                offset = max(0, total - len(page))
            else:
                page = items[:n]
                offset = 0

            lines = [self._lineify_item(item) for item in page]
            lines = [line for line in lines if line]
            is_truncated = len(page) < total
            out = {
                "ok": True,
                "action": wrapper_name,
                "tool": tool_name,
                "source_action": source_action,
                "field": used_field,
                "matches": "\n".join(lines),
                "count": len(page),
                "total": total,
                "offset": offset,
                "truncated": is_truncated,
                "next_offset": (offset + len(page))
                if (not tail and is_truncated)
                else None,
            }
            if _coerce_bool(args.get("include_items"), False):
                out["items"] = page if item_kind == "list" else lines
            return out

    def _handle_tool_next_action(self, tool_name: str, args: dict) -> dict:
            token = args.get("next_token") or args.get("token") or args.get("cursor")
            if not isinstance(token, str) or not token.strip():
                return make_error(
                    MCPError.INVALID_ARGS,
                    "action='next' requires next_token (or token/cursor)",
                    hint=f"Use the next_token returned by {tool_name} or wrapper actions with truncated=true.",
                )
            token = token.strip()
            self._prune_next_cache()
            entry = self._next_cache.get(token)
            if not entry:
                return make_error(
                    MCPError.TRUNCATION_TOKEN_INVALID,
                    f"next token '{token}' not found or expired",
                    hint="Re-run the original paginated call to get a fresh next_token.",
                )
            cached_tool = str(entry.get("tool") or "")
            if cached_tool and cached_tool != tool_name:
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"next token belongs to tool '{cached_tool}', not '{tool_name}'",
                )

            child_args = dict(entry.get("args") or {})
            child_args["action"] = entry.get("action")
            child_args["offset"] = entry.get("next_offset", child_args.get("offset", 0))

            overrides = dict(args or {})
            for key in ("action", "next_token", "token", "cursor"):
                overrides.pop(key, None)
            child_args.update(overrides)
            result = self._execute_tool(tool_name, child_args)
            if isinstance(result, dict):
                result = dict(result)
                result["continued_from"] = token
            return result

    def _handle_tool_stats_action(self, tool_name: str, args: dict) -> dict:
            source_action, source_err = self._wrapper_source_action(
                tool_name, args, "stats"
            )
            if source_err:
                return source_err
            include_payload = _coerce_bool(args.get("stats_include_payload"), False)

            child_args = self._strip_wrapper_args(args)
            child_args["action"] = source_action
            source_payload = self._execute_tool(tool_name, child_args)
            if isinstance(source_payload, dict) and source_payload.get("error"):
                return source_payload

            try:
                serialized = json.dumps(
                    source_payload, ensure_ascii=False, separators=(",", ":")
                )
            except Exception:
                serialized = str(source_payload)
            items, used_field, item_kind = self._collect_wrapper_items(source_payload)
            top_keys: List[str] = []
            if isinstance(source_payload, dict):
                top_keys = list(source_payload.keys())[:64]
            stats = {
                "type": type(source_payload).__name__,
                "top_level_keys": top_keys,
                "line_count": len(
                    [line for line in serialized.splitlines() if line.strip()]
                ),
                "char_count": len(serialized),
                "item_count": len(items),
                "item_field": used_field,
                "item_kind": item_kind,
                "has_error": bool(
                    isinstance(source_payload, dict) and source_payload.get("error")
                ),
                "truncated": bool(
                    isinstance(source_payload, dict) and source_payload.get("truncated")
                ),
            }
            out = {
                "ok": True,
                "action": "stats",
                "tool": tool_name,
                "source_action": source_action,
                "stats": stats,
            }
            if include_payload:
                out["payload"] = source_payload
            return out

    def _execute_tool(self, tool_name, args):
            start_ts = time.perf_counter()
            original_tool_name = tool_name
            resolved_tool = _resolve_tool_alias(tool_name)

            # ---- Rate Limiting ----
            allowed, reason = self.rate_limiter.check(resolved_tool)
            if not allowed:
                self.audit.log(
                    tool=resolved_tool,
                    action=str(args.get("action", "")) if isinstance(args, dict) else "",
                    args=args if isinstance(args, dict) else {},
                    result=None,
                    latency_ms=0.0,
                    session_id=getattr(self.current_session, "session_id", None) if self.current_session else None,
                    error=f"rate_limited: {reason}",
                )
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"Rate limit exceeded: {reason}",
                    hint="Reduce call frequency or increase limits via IDA_MCP_RATE_LIMIT_* env vars.",
                )

            result = self._execute_tool_inner(resolved_tool, original_tool_name, args)
            sid = getattr(self.current_session, "session_id", None) if self.current_session else None
            latency_ms = (time.perf_counter() - start_ts) * 1000.0
            action_name = str(args.get("action", "")) if isinstance(args, dict) else ""
            guardrail_mode = self._guardrail_mode_from_args(args) if isinstance(args, dict) else "assist"
            guardrail_blocked = False
            error_str = None
            if isinstance(result, dict):
                err = result.get("error")
                if isinstance(err, dict):
                    guardrail_blocked = (
                        err.get("code") == MCPError.INVALID_ARGS
                        and "guardrail" in str(err.get("message", "")).lower()
                    )
                    error_str = str(err)[:500]
                elif err is not None:
                    error_str = str(err)[:500]
            self.audit.log(
                tool=resolved_tool,
                action=action_name,
                args=args if isinstance(args, dict) else {},
                result=result,
                latency_ms=latency_ms,
                session_id=sid,
                guardrail_mode=guardrail_mode,
                guardrail_blocked=guardrail_blocked,
                error=error_str,
            )
            # Live observation for usage intelligence
            if self._usage_intel and sid:
                try:
                    addr = (args.get("addr") or args.get("address")) if isinstance(args, dict) else None
                    self._usage_intel.observe(
                        resolved_tool, action_name, sid,
                        latency_ms=latency_ms, error=error_str, addr=addr,
                    )
                except Exception:
                    pass
            return result

    def _execute_tool_inner(self, tool_name, original_tool_name, args):
            if tool_name not in TOOLS:
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"Unknown tool '{tool_name}'",
                    hint="Call tools/list to see available tools.",
                )
            if args is None:
                args = {}
            if not isinstance(args, dict):
                return make_error(MCPError.INVALID_ARGS, "arguments must be an object")
            args = self._normalize_tool_call_args(tool_name, args)
            sid = getattr(self.current_session, "session_id", None) if self.current_session else None

            # ---- Deterministic policy preflight ----
            if tool_name != "blackboard":
                try:
                    policy_result = evaluate_policy(
                        tool_name,
                        args.get("action"),
                        mode=os.environ.get("IDA_MCP_POLICY_MODE", "assist"),
                        purpose=args.get("_purpose"),
                        ack=args.get("_risk_ack") or args.get("_guardrail_ack"),
                    )
                    policy_audit = build_audit_record(policy_result, session_id=sid)
                    if (
                        policy_result.decision != PolicyDecision.ALLOW
                        or policy_result.risk.value != "read"
                        or policy_result.reasons
                        or policy_result.flags
                    ):
                        try:
                            self.audit.log(
                                tool=tool_name,
                                action=str(args.get("action") or ""),
                                args=policy_audit,
                                result=policy_audit,
                                latency_ms=0.0,
                                session_id=sid,
                            )
                        except Exception:
                            pass
                    if policy_result.decision == PolicyDecision.BLOCK:
                        return make_error(
                            getattr(MCPError, "GOVERNANCE_BLOCKED", MCPError.INVALID_ARGS),
                            "Policy blocked this tool action",
                            hint="Use an allowed purpose and verify the workflow is authorized.",
                            details=policy_result.to_dict(),
                        )
                    if policy_result.decision == PolicyDecision.REQUIRE_ACK:
                        return make_error(
                            getattr(MCPError, "GOVERNANCE_BLOCKED", MCPError.INVALID_ARGS),
                            "Policy requires explicit acknowledgement for this tool action",
                            hint="Retry with _risk_ack=true after verifying the action is authorized.",
                            details=policy_result.to_dict(),
                        )
                except Exception:
                    pass
            args.pop("_purpose", None)
            args.pop("_risk_ack", None)

            # ---- Blackboard strict policy preflight (global tool boundary) ----
            try:
                if tool_name != "blackboard" and hasattr(self, "_bb_policy_bump") and hasattr(self, "_bb_policy_check"):
                    bb_state = self._bb_policy_bump()
                    exempt_tools = {
                        "session",
                        "bookmarks",
                        "batch",
                        "truncation",
                        "blackboard",
                        "misc",
                    }
                    phase_name = "scout"
                    if hasattr(self, "_phase_state"):
                        try:
                            phase_name = str((self._phase_state() or {}).get("phase") or "scout")
                        except Exception:
                            phase_name = "scout"
                    should_enforce = bool(bb_state.get("strict_mode"))
                    if hasattr(self, "_bb_policy_enforced_for_phase"):
                        should_enforce = bool(self._bb_policy_enforced_for_phase(bb_state, phase_name))
                    if should_enforce and tool_name not in exempt_tools:
                        check = self._bb_policy_check(bb_state)
                        if not check.get("ok"):
                            return make_error(
                                MCPError.INVALID_ARGS,
                                "Strict blackboard policy gate failed before tool execution",
                                hint=json.dumps(
                                    {
                                        "tool": tool_name,
                                        "reasons": check.get("reasons", []),
                                        "recommendation": check.get("recommendation", ""),
                                    },
                                    ensure_ascii=True,
                                ),
                                details={"policy": check.get("policy", {})},
                            )
            except Exception:
                pass

            # ---- Phase-state preflight (adaptive choreography) ----
            try:
                if tool_name != "blackboard" and hasattr(self, "_phase_preflight_for_tool"):
                    phase_block = self._phase_preflight_for_tool(tool_name, args if isinstance(args, dict) else {})
                    if isinstance(phase_block, dict) and phase_block.get("error"):
                        return phase_block
            except Exception:
                pass

            # ---- Active Blackboard Kernel (preflight) ----
            pre = {"decision": "allow"}

            high_impact_tools = {
                "modify",
                "funcs",
                "segments",
                "bulk",
                "annotation",
                "memory",
                "patch",
                "edit",
            }
            # Never block state-persistence helpers; they are the mechanism to satisfy obligations.
            if tool_name in {"blackboard", "session", "bookmarks", "batch", "predictor", "workflow"}:
                pre = {"decision": "allow"}
            if pre.get("decision") == "block_high_impact":
                # Guardrail should only hard-block high-impact write surfaces.
                if tool_name not in high_impact_tools:
                    pre = {"decision": "allow"}
            if pre.get("decision") == "block_high_impact":
                hint = pre.get("hint", "Resolve required receipts via supporting read/exploration actions before high-impact writes.")
                return make_error(
                    MCPError.INVALID_ARGS,
                    "Action blocked by active blackboard obligations (session state contract)",
                    hint=hint,
                    details={
                        "blocked_by": pre.get("blocked_by", []),
                        "required_receipts": pre.get("required_receipts", []),
                        "attention_debt": pre.get("debt", 0.0),
                    },
                )

            # ---- Silent Tool Rerouting ----
            action = args.get("action", "")
            reroute_applied = False
            try:
                from .auto_nudge import get_reroute
                reroute = get_reroute(tool_name, str(action) if action else "", args)
                if reroute:
                    new_tool, new_args = reroute
                    new_args["_rerouted_from"] = f"{tool_name}.{action}"
                    tool_name = new_tool
                    args = new_args
                    action = new_args.get("action", "")
                    reroute_applied = True
                    # Wire MemRL feedback: mark this reroute as successful
                    try:
                        from .auto_nudge import record_tool_call as nudge_record
                        idb_key = (self.current_session.idb_path if self.current_session else "")
                        nudge_record(idb_key, "_reroute", f"{tool_name}.{action}", 
                                    addr=args.get("addr"), query=args.get("query"))
                    except Exception:
                        pass
            except Exception:
                pass

            # ---- Stuck Detection (UsageIntelligence DriftDetector) ----
            action = args.get("action", "")
            try:
                sid_for_drift = (getattr(self.current_session, "session_id", None)
                                 if self.current_session else None)
                ui = getattr(self, "_usage_intel", None)
                if sid_for_drift and ui and ui.is_running():
                    signals = ui.drift.check(sid_for_drift)
                    # Only block on LOOP — other signals are warnings, not blockers
                    for sig in signals:
                        if sig.get("type") == "LOOP" and sig.get("severity") == "warning":
                            return {
                                "ok": False,
                                "error": {"code": "STUCK_LOOP", "message": sig["message"]},
                                "_nudge": {
                                    "type": "stuck",
                                    "signal": sig["type"],
                                    "suggestion": "Try a different approach. Read ida://state for orientation.",
                                },
                            }
            except Exception:
                pass

            action = args.get("action")
            if isinstance(action, str):
                action = action.strip()
                args["action"] = action
                native_actions = set(TOOL_ACTIONS.get(tool_name, []) or [])
                has_wrapper_source = any(
                    key in args
                    for key in ("source_action", "target_action", "on", "subaction")
                )
                if action in WRAPPER_ACTIONS:
                    use_wrapper = action not in native_actions
                    if action in ("grep", "pick", "head", "tail", "stats"):
                        use_wrapper = use_wrapper or has_wrapper_source
                    elif action == "next":
                        use_wrapper = use_wrapper or any(
                            key in args for key in ("next_token", "token", "cursor")
                        )
                    if use_wrapper:
                        if action == "grep":
                            return self._handle_tool_grep_action(tool_name, args)
                        if action == "pick":
                            return self._handle_tool_pick_action(tool_name, args)
                        if action == "head":
                            return self._handle_tool_head_tail_action(
                                tool_name, args, tail=False
                            )
                        if action == "tail":
                            return self._handle_tool_head_tail_action(
                                tool_name, args, tail=True
                            )
                        if action == "next":
                            return self._handle_tool_next_action(tool_name, args)
                        if action == "stats":
                            return self._handle_tool_stats_action(tool_name, args)

            guardrail_mode = self._guardrail_mode_from_args(args)
            strict_guardrails = self._guardrail_strict_writes or guardrail_mode == "enforce"
            if strict_guardrails:
                risky_tools = {"modify", "bulk", "annotation", "funcs", "segments", "memory", "data_ops"}
                risky_actions = {
                    "patch_asm",
                    "rename",
                    "set_type",
                    "comment",
                    "apply_type",
                    "rename_stack",
                    "write",
                    "make_code",
                    "make_data",
                    "delete",
                    "set_name",
                    "set_attr",
                    "set_perms",
                    "set_flags",
                }
                ack = _coerce_bool(args.get("_guardrail_ack"), False)
                signal = self._compute_pointer_note_signal(tool_name, args, {})
                act = str(args.get("action") or "").strip().lower()
                if (
                    not ack
                    and tool_name in risky_tools
                    and (act in risky_actions or signal >= 2.0)
                ):
                    return make_error(
                        MCPError.INVALID_ARGS,
                        "Guardrail strict mode blocked a risky write without acknowledgement",
                        hint="Retry with _guardrail_ack=true or disable IDA_MCP_GUARDRAIL_STRICT_WRITES.",
                        details={
                            "tool": tool_name,
                            "action": act,
                            "signal": round(signal, 3),
                            "guardrail_mode": guardrail_mode,
                        },
                    )
                if ack:
                    pass  # guardrail ack noted
            if tool_name == "wiki":
                return self._handle_wiki(args)
            if tool_name == "misc":
                action = args.get("action")
                if action == "health":
                    return self._handle_misc_health(args)
                # New plugin actions under misc.
                if action == "plugin_list":
                    args["action"] = "list"
                    tool_name = "plugins"
                elif action == "plugin_run":
                    args["action"] = "run"
                    tool_name = "plugins"
                # Backward compatibility for callers still using plugins(...).
                elif original_tool_name == "plugins":
                    if action in ("list", "run"):
                        tool_name = "plugins"
                    else:
                        return make_error(
                            MCPError.ACTION_NOT_FOUND,
                            f"Unsupported plugins action: '{action}'",
                            hint="Use misc(action='plugin_list') or misc(action='plugin_run', name='...', arg=0).",
                        )
            if tool_name == "project":
                action = args.get("action")
                # Consolidate generic host file I/O into misc.
                if action == "read":
                    args["action"] = "read_file"
                    tool_name = "misc"
                elif action == "write":
                    args["action"] = "write_file"
                    tool_name = "misc"
                elif action == "sessions":
                    return make_error(
                        MCPError.NOT_IMPLEMENTED,
                        "Use 'session' tool for session management",
                        hint="sessions/list is handled by the host-level session tool.",
                    )
                elif action == "batch":
                    return make_error(
                        MCPError.NOT_IMPLEMENTED,
                        "Use host-level batch/session orchestration for multi-file analysis",
                        hint="Use batch(calls=[...]) and session actions instead of project(action='batch').",
                    )
            if tool_name == "session":
                return self._handle_session(args)

            if tool_name == "threat_hunt":
                return self._handle_threat_hunt(args)

            if tool_name == "predictor":
                return self._handle_predictor(args)

            if tool_name == "workflow":
                return self._handle_workflow(args)

            if tool_name == "blackboard":
                return self._handle_blackboard(args)

            if tool_name == "gadgets" and str(args.get("action") or "").strip() == "semantic_find":
                return self._handle_gadgets_semantic_find(args)

            if tool_name == "bookmarks":
                return self._handle_bookmarks(args)

            if tool_name == "truncation":
                return self._handle_truncation(args)

            legacy_threat_tools = {
                "trace",
                "trace_analysis",
                "coverage",
                "agent",
            }
            if tool_name in legacy_threat_tools:
                bridged = dict(args or {})
                legacy_action = str(bridged.get("action") or "").strip()
                bridged["action"] = "legacy"
                bridged["legacy_tool"] = tool_name
                if legacy_action:
                    bridged["legacy_action"] = legacy_action
                bridged.setdefault("legacy_passthrough", True)
                bridged.setdefault("include_evidence", False)
                bridged.setdefault("profile", "balanced")
                result = self._handle_threat_hunt(bridged)
                if isinstance(result, dict) and result.get("ok"):
                    result = dict(result)
                    result["legacy_tool"] = tool_name
                    if legacy_action:
                        result["legacy_action"] = legacy_action
                return result

            ip = args.pop(
                "idb", self.current_session.idb_path if self.current_session else None
            )
            if not ip:
                return make_error(
                    MCPError.SESSION_REQUIRED,
                    "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
                )
            return self.call_tool(tool_name, ip, **args)
