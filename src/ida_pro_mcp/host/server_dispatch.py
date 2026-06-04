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
from .errors import MCPError, is_error_result, make_error
from .policy import PolicyDecision, build_audit_record, evaluate_policy
from .schemas import (
    ADVERTISED_TOOLS,
    HIDDEN_TOOLS_IN_LIST,
    TOOL_ACTIONS,
    TOOL_ARG_SCHEMAS,
    TOOLS,
    WRAPPER_ACTIONS,
    _resolve_tool_alias,
)
from .server_response import truncate_response


class ServerDispatchMixin:
    _SURVEY_GATE_EXEMPT_WORKFLOW_ACTIONS = frozenset(
        {
            "audit_plan",
            "catalog",
            "compose",
            "estimate",
            "explain",
            "plan",
            "prioritize",
        }
    )

    def _extract_addresses_from_args(self, args: Any) -> list[str]:
        addrs = []
        if isinstance(args, dict):
            for key in ("addr", "ea", "address", "addrs"):
                val = args.get(key)
                if val is not None:
                    if isinstance(val, list):
                        for item in val:
                            addrs.extend(self._extract_addresses_from_args(item))
                    elif isinstance(val, (int, str)):
                        try:
                            if isinstance(val, int):
                                addrs.append(hex(val))
                            else:
                                if val.lower().startswith("0x"):
                                    addrs.append(hex(int(val, 16)))
                                else:
                                    addrs.append(hex(int(val)))
                        except Exception:
                            pass
            for val in args.values():
                if isinstance(val, (dict, list)):
                    addrs.extend(self._extract_addresses_from_args(val))
        elif isinstance(args, list):
            for item in args:
                addrs.extend(self._extract_addresses_from_args(item))
        return list(set(addrs))

    def _promote_eligible_surveys(self, store):
        visited = set(store.get_visited_addresses())
        surveys = store.list_surveys()
        for s in surveys:
            status = s["status"]
            addr = s["addr"]
            if status == "DORMANT":
                deps = s.get("dependencies", [])
                if deps and any(d in visited for d in deps):
                    store.save_survey(
                        addr=addr,
                        status="ACTIVE",
                        variables=s["variables"],
                        dependencies=deps,
                        deferred_until=s.get("deferred_until", []),
                        reason=s.get("reason", "")
                    )
            elif status == "DEFERRED":
                deferred_until = s.get("deferred_until", [])
                if deferred_until and any(d in visited for d in deferred_until):
                    store.save_survey(
                        addr=addr,
                        status="ACTIVE",
                        variables=s["variables"],
                        dependencies=s["dependencies"],
                        deferred_until=deferred_until,
                        reason=s.get("reason", "")
                    )

    def _survey_context_key(self) -> Optional[str]:
        if self.current_session and getattr(self.current_session, "idb_path", None):
            return self.current_session.idb_path
        return None

    def _get_survey_store(self):
        from .survey_store import SurveyStore

        return SurveyStore(context_key=self._survey_context_key())

    def _get_active_survey(self) -> Optional[Dict[str, Any]]:
        try:
            store = self._get_survey_store()
            active_surveys = [s for s in store.list_surveys() if s["status"] == "ACTIVE"]
            if active_surveys:
                return active_surveys[0]
        except Exception as e:
            log_rpc(f"Survey lock check failed: {e}")
        return None

    def _survey_gate_exempt(self, tool_name: str, args: dict[str, Any]) -> bool:
        if tool_name in {"survey", "blackboard", "session"}:
            return True
        if tool_name == "workflow":
            action = str(args.get("action") or "").strip().lower()
            if action in self._SURVEY_GATE_EXEMPT_WORKFLOW_ACTIONS:
                return True
        return False

    @staticmethod
    def _runtime_alive(runtime: Any) -> bool:
        """Best-effort runtime liveness check for runtime dict records."""
        if not isinstance(runtime, dict):
            return False
        proc = runtime.get("process")
        if not proc:
            return False
        try:
            return proc.poll() is None
        except Exception:
            return False

    def call_tool(self, tool_name, idb_path, **kwargs):
            session = self._resolve_session_from_idb_ref(idb_path)
            if not session:
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    f"No session found for idb reference: {idb_path}",
                    hint="Use session_id, SID_* IDB id, binary/idb path, or create/switch a session first.",
                )

            runtime = self.session_runtimes.get(session.session_id)
            if not self._runtime_alive(runtime):
                log_rpc(
                    f"Session start/restart needed: {session.session_id} -> {session.idb_path}"
                )
                start_res = self._start_server(session)
                if "error" in start_res:
                    return start_res
                runtime = self.session_runtimes.get(session.session_id)
            if not isinstance(runtime, dict):
                return make_error(
                    MCPError.IDA_CRASHED,
                    "Runtime metadata unavailable after startup.",
                )
            port = runtime.get("port")
            if not self._runtime_alive(runtime) or not isinstance(port, int) or port <= 0:
                return make_error(
                    MCPError.IDA_CRASHED,
                    "Runtime metadata invalid or process not alive.",
                    details={"has_process": bool(runtime.get("process")), "port": port},
                )

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
                res = self._send_rpc_raw({"tool": tool_name, "args": rpc_args}, port)
                if isinstance(res, dict) and "error" not in res and "ok" not in res:
                    res = {"ok": True, **res}
                res = truncate_response(res, max_tokens=self.default_truncate_tokens)
                # Preference observation for IDA-side tools
                if isinstance(res, dict):
                    self._observe_preference(
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

    def _handle_session_health(self, args: dict) -> dict:
            verbose = bool(args.get("verbose", False))
            wiki_root = self._resolve_wiki_root()
            wiki_available = bool(wiki_root and os.path.isdir(wiki_root))
            idat_path = self.idat_exe or ""
            idat_exists = bool(idat_path and os.path.exists(idat_path))
            runtime_states = []
            running = 0
            stale = 0
            for sid, runtime in self.session_runtimes.items():
                alive = self._runtime_alive(runtime)
                if alive:
                    running += 1
                else:
                    stale += 1
                if verbose:
                    runtime_port = runtime.get("port") if isinstance(runtime, dict) else None
                    runtime_states.append(
                        {
                            "session_id": sid,
                            "alive": alive,
                            "port": runtime_port,
                        }
                    )

            action_counts = {
                str(tool): len(list(actions or []))
                for tool, actions in TOOL_ACTIONS.items()
            }
            max_actions_tool = ""
            max_actions_count = 0
            if action_counts:
                max_actions_tool = max(action_counts, key=action_counts.get)
                max_actions_count = int(action_counts.get(max_actions_tool, 0))
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
                "tools": {
                    "registered": len(TOOLS),
                    "advertised": len(ADVERTISED_TOOLS),
                    "hidden_from_tools_list": len(HIDDEN_TOOLS_IN_LIST),
                    "wrappers": list(WRAPPER_ACTIONS),
                    "action_surface": {
                        "tool_count_with_actions": len(action_counts),
                        "total_actions": sum(action_counts.values()),
                        "max_actions_tool": max_actions_tool or None,
                        "max_actions_count": max_actions_count,
                    },
                },
            }
            if verbose:
                payload["sessions"]["runtimes"] = runtime_states
                payload["tools"]["action_counts_by_tool"] = action_counts
            return payload

    def _handle_memory_filesystem(self, args: dict) -> dict:
            import os as _os
            import traceback as _tb
            action = str(args.get("action") or "").strip().lower()
            path = args.get("path")
            if not isinstance(path, str) or not path.strip():
                return make_error(MCPError.INVALID_ARGS, "path required")
            encoding = args.get("encoding") or "utf-8"
            try:
                if action == "read_file":
                    if not _os.path.exists(path):
                        return {"error": True, "message": f"File not found: {path}"}
                    if not _os.path.isfile(path):
                        return {"error": True, "message": f"Not a file: {path}"}
                    enc = str(encoding).strip().lower()
                    if enc == "binary":
                        with open(path, "rb") as f:
                            data = f.read()
                        return {
                            "ok": True,
                            "path": _os.path.abspath(path),
                            "size": len(data),
                            "content": data.hex(),
                            "encoding": "binary",
                        }
                    with open(path, "r", encoding=enc, errors="replace") as f:
                        text = f.read()
                    return {
                        "ok": True,
                        "path": _os.path.abspath(path),
                        "size": len(text),
                        "content": text,
                        "encoding": enc,
                    }
                if action == "write_file":
                    parent = _os.path.dirname(_os.path.abspath(path))
                    if parent and not _os.path.exists(parent):
                        _os.makedirs(parent, exist_ok=True)
                    content = args.get("content")
                    if content is None:
                        return make_error(MCPError.INVALID_ARGS, "content required for write_file")
                    enc = str(encoding).strip().lower()
                    if enc == "binary":
                        try:
                            raw = bytes.fromhex(str(content))
                        except ValueError as exc:
                            return {"error": True, "message": f"Invalid hex content: {exc}"}
                        with open(path, "wb") as f:
                            f.write(raw)
                        return {
                            "ok": True,
                            "path": _os.path.abspath(path),
                            "size": len(raw),
                            "encoding": "binary",
                        }
                    with open(path, "w", encoding=enc, errors="replace") as f:
                        f.write(str(content))
                    return {
                        "ok": True,
                        "path": _os.path.abspath(path),
                        "size": len(str(content)),
                        "encoding": enc,
                    }
            except Exception:
                return {"error": True, "message": _tb.format_exc()}
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported memory filesystem action: '{action}'",
                hint="Use memory(action='read_file'|'write_file').",
            )

    def _handle_analysis_plugin_run(self, args: dict) -> dict:
            name = args.get("name")
            if not isinstance(name, str) or not name.strip():
                return make_error(MCPError.INVALID_ARGS, "name required for plugin_run")
            arg = args.get("arg", 0)
            try:
                arg = int(arg) if arg is not None else 0
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, f"arg must be int, got {type(arg).__name__}")
            runtime = self.session_runtimes.get(self.current_session.session_id) if self.current_session else None
            if not self._runtime_alive(runtime):
                return make_error(
                    MCPError.IDA_CRASHED,
                    "plugin_run requires a live IDA session; none is active.",
                    hint="Open a session first with session(action='create', binary_path='...').",
                )
            return self._send_rpc_raw(
                {"tool": "analysis", "args": {"action": "plugin_run", "name": name, "arg": arg}},
                runtime.get("port"),
            )

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
            if (
                isinstance(result, dict)
                and result.get("error")
                and "code" not in result
            ):
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
            if is_error_result(source_payload):
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
            if is_error_result(source_payload):
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
            if is_error_result(source_payload):
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
            if is_error_result(source_payload):
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
                "has_error": is_error_result(source_payload),
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
            
            # Record visited addresses and promote surveys
            if isinstance(result, dict) and not is_error_result(result):
                try:
                    visited_addrs = self._extract_addresses_from_args(args)
                    if visited_addrs:
                        store = self._get_survey_store()
                        for addr in visited_addrs:
                            store.add_visited_address(addr)
                        self._promote_eligible_surveys(store)
                except Exception as e:
                    log_rpc(f"Survey visited address logging/promotion failed: {e}")

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
                elif result.get("ok") is False:
                    if (
                        result.get("code") == MCPError.INVALID_ARGS
                        and "guardrail" in str(result.get("message", "")).lower()
                    ):
                        guardrail_blocked = True
                    error_str = str(
                        {
                            "code": result.get("code"),
                            "message": result.get("message"),
                        }
                    )[:500]
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

            # ---- Active Survey Lock Check ----
            if not self._survey_gate_exempt(tool_name, args):
                s = self._get_active_survey()
                if s:
                    addr = s.get("addr", "unknown")
                    return make_error(
                        MCPError.SURVEY_REQUIRED,
                        f"ACTIVE SURVEY PENDING for {addr}. You must resolve or delay the survey first.",
                        details={
                            "addr": addr,
                            "reason": s.get("reason", ""),
                            "variables": s.get("variables", []),
                            "dependencies": s.get("dependencies", []),
                            "actions": {
                                "submit": f"survey(action='submit', addr='{addr}', renames={{...}})",
                                "delay": f"survey(action='delay', addr='{addr}', delay_until_any=[...], reason='...')"
                            }
                        }
                    )

            # ---- Deterministic policy preflight ----
            if tool_name != "blackboard":
                try:
                    policy_result = evaluate_policy(
                        tool_name,
                        args.get("action"),
                        mode=os.environ.get("IDA_MCP_POLICY_MODE", "assist"),
                        purpose=args.get("_purpose"),
                        ack=_coerce_bool(args.get("_risk_ack"), False)
                        or _coerce_bool(args.get("_guardrail_ack"), False),
                    )
                    policy_audit = build_audit_record(policy_result, session_id=sid)
                    policy_details = policy_result.to_dict()
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
                                result=policy_details,
                                latency_ms=0.0,
                                session_id=sid,
                            )
                        except Exception as e:
                            log_rpc(f"Policy audit logging failed for {tool_name}: {e}")
                    if policy_result.decision == PolicyDecision.BLOCK:
                        return make_error(
                            getattr(MCPError, "GOVERNANCE_BLOCKED", MCPError.INVALID_ARGS),
                            "Policy blocked this tool action",
                            hint="Use an allowed purpose and verify the workflow is authorized.",
                            details=policy_details,
                        )
                    if policy_result.decision == PolicyDecision.REQUIRE_ACK:
                        return make_error(
                            getattr(MCPError, "GOVERNANCE_BLOCKED", MCPError.INVALID_ARGS),
                            "Policy requires explicit acknowledgement for this tool action",
                            hint="Retry with _risk_ack=true after verifying the action is authorized.",
                            details=policy_details,
                        )
                except Exception as e:
                    log_rpc(f"Policy evaluation failed for {tool_name}: {e}")
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
                    # Wire preference feedback: mark this reroute as successful
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
                # Backward compatibility for callers still using plugins(...).
                # Route everything through misc to avoid maintaining a duplicate plugins tool.
                if original_tool_name == "plugins":
                    if action == "list":
                        args["action"] = "plugin_list"
                    elif action == "run":
                        return make_error(
                            MCPError.ACTION_NOT_FOUND,
                            "plugins(action='run') moved to analysis(action='plugin_run').",
                            hint="Use analysis(action='plugin_run', name='...', arg=0).",
                        )
                    else:
                        return make_error(
                            MCPError.ACTION_NOT_FOUND,
                            f"Unsupported plugins action: '{action}'",
                            hint="Use misc(action='plugin_list') or analysis(action='plugin_run', name='...', arg=0).",
                        )
            if tool_name == "session":
                return self._handle_session(args)

            if tool_name == "schemaboot":
                return self._handle_schemaboot(args)

            if tool_name == "intelligence" and str(args.get("action") or "").startswith("structural_"):
                return self._handle_intelligence_structural(args)

            if tool_name == "memory" and str(args.get("action") or "").strip() in ("read_file", "write_file"):
                return self._handle_memory_filesystem(args)

            if tool_name == "analysis" and str(args.get("action") or "").strip() == "plugin_run":
                return self._handle_analysis_plugin_run(args)

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

            ip = args.pop(
                "idb", self.current_session.idb_path if self.current_session else None
            )
            if not ip:
                return make_error(
                    MCPError.SESSION_REQUIRED,
                    "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
                )
            return self.call_tool(tool_name, ip, **args)

    def _handle_schemaboot(self, args: dict) -> dict:
        import os
        import sqlite3
        action = args.get("action")
        constraints = args.get("constraints") or {}
        addr = args.get("addr")
        limit = args.get("limit", 50)
        offset = args.get("offset", 0)
        order_by = args.get("order_by")
        include_apis = bool(args.get("include_apis", False))
        include_strings = bool(args.get("include_strings", False))

        session = self.current_session
        ip = args.get("idb") or (session.idb_path if session else None)
        if not ip:
            return make_error(
                MCPError.SESSION_REQUIRED,
                "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
            )

        from .intelligence.structural_index import (
            get_db_path, ensure_tables, upsert_functions_batch,
            execute_host_query, write_insight_index, add_global_facts,
            _detect_global_facts
        )

        db_path = get_db_path(ip)

        if action == "delete":
            if os.path.exists(db_path):
                try:
                    os.remove(db_path)
                    return {"ok": True, "deleted": db_path}
                except Exception as e:
                    return make_error(MCPError.DB_ERROR, f"Failed to delete database: {e}")
            return make_error(MCPError.FILE_NOT_FOUND, f"No index found at {db_path}")

        if action == "stats":
            if not os.path.exists(db_path):
                return make_error(MCPError.FILE_NOT_FOUND, "No index found. Run schemaboot(action='ingest') first.")
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM function_attrs")
                total_indexed = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(DISTINCT func_ea) FROM function_apis")
                funcs_with_apis = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(DISTINCT func_ea) FROM function_strings")
                funcs_with_strings = cursor.fetchone()[0]
                cursor.execute("SELECT AVG(size), AVG(entropy), AVG(bb_count), AVG(cyclomatic_complexity) FROM function_attrs")
                avg_size, avg_entropy, avg_bb, avg_cc = cursor.fetchone()
                cursor.execute("SELECT segment, COUNT(*) FROM function_attrs GROUP BY segment")
                segments = {row[0]: row[1] for row in cursor.fetchall()}
                conn.close()
                return {
                    "ok": True,
                    "db_path": db_path,
                    "total_indexed": total_indexed,
                    "funcs_with_apis": funcs_with_apis,
                    "funcs_with_strings": funcs_with_strings,
                    "avg_size": round(avg_size or 0, 1),
                    "avg_entropy": round(avg_entropy or 0, 2),
                    "avg_bb_count": round(avg_bb or 0, 1),
                    "avg_cyclomatic": round(avg_cc or 0, 1),
                    "segments": segments,
                }
            except Exception as e:
                return make_error(MCPError.DB_ERROR, f"Failed to retrieve stats: {e}")

        if action == "get":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for get")
            try:
                ea = int(addr, 0) if isinstance(addr, str) else addr
            except ValueError:
                return make_error(MCPError.INVALID_ARGS, f"Invalid address format: {addr}")

            if not os.path.exists(db_path):
                return make_error(MCPError.FILE_NOT_FOUND, "No index found")

            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM function_attrs WHERE ea=?", (ea,))
                row = cursor.fetchone()
                if not row:
                    conn.close()
                    return make_error(MCPError.NOT_FOUND, f"Function {addr} not in index")
                cols = [d[0] for d in cursor.description]
                result = dict(zip(cols, row))
                if include_apis:
                    cursor.execute("SELECT api_name FROM function_apis WHERE func_ea=?", (ea,))
                    result["apis"] = [r[0] for r in cursor.fetchall()]
                if include_strings:
                    cursor.execute("SELECT string_text, string_ea FROM function_strings WHERE func_ea=?", (ea,))
                    result["strings"] = [{"text": r[0], "ea": hex(r[1])} for r in cursor.fetchall()]
                conn.close()
                result["ea"] = hex(result["ea"])
                return {"ok": True, "function": result}
            except Exception as e:
                return make_error(MCPError.DB_ERROR, f"Failed to get function: {e}")

        if action == "query":
            return execute_host_query(
                db_path, constraints, limit=limit, offset=offset, order_by=order_by,
                include_apis=include_apis, include_strings=include_strings
            )

        if action == "ingest":
            # 1. Call the IDA process to run extraction
            extract_res = self.call_tool("schemaboot", ip, action="extract")
            if extract_res.get("error") or not extract_res.get("ok"):
                return extract_res

            funcs_data = extract_res.get("functions") or []

            # 2. Open DB and Upsert batch
            try:
                conn = sqlite3.connect(db_path)
                ensure_tables(conn)
                ingested = upsert_functions_batch(conn, funcs_data)
                conn.close()
            except Exception as e:
                return make_error(MCPError.DB_ERROR, f"Ingestion database error: {e}")

            # 3. Update L1 and L2 indexes on the host
            try:
                write_insight_index(funcs_data)
                all_facts = []
                for f in funcs_data:
                    all_facts.extend(_detect_global_facts(f))
                add_global_facts(all_facts)
                facts_count = len(all_facts)
            except Exception as e:
                log_rpc(f"Failed to update L1/L2 index during ingest: {e}")
                facts_count = 0

            return {
                "ok": True,
                "action": "ingest",
                "total_functions": len(funcs_data),
                "ingested": ingested,
                "db_path": db_path,
                "l1_indexed": len(funcs_data),
                "l2_facts_added": facts_count,
            }

        if action == "refresh":
            if addr:
                # Refresh single
                extract_res = self.call_tool("schemaboot", ip, action="extract_single", addr=addr)
                if extract_res.get("error") or not extract_res.get("ok"):
                    return extract_res
                func_data = extract_res.get("function")
                if not func_data:
                    return make_error(MCPError.NOT_FOUND, f"Failed to extract function at {addr}")

                try:
                    conn = sqlite3.connect(db_path)
                    ensure_tables(conn)
                    upsert_functions_batch(conn, [func_data])
                    conn.close()
                except Exception as e:
                    return make_error(MCPError.DB_ERROR, f"Refresh database error: {e}")

                try:
                    write_insight_index([func_data])
                    add_global_facts(_detect_global_facts(func_data))
                except Exception as e:
                    log_rpc(f"Failed to update L1/L2 index during refresh: {e}")

                return {"ok": True, "refreshed": 1, "ea": addr}
            else:
                # Refresh all = Ingest
                return self._handle_schemaboot({"action": "ingest"})

        return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    def _handle_intelligence_structural(self, args: dict) -> dict:
        import os
        import sqlite3
        action = args.get("action")
        constraints = args.get("constraints") or {}
        addr = args.get("addr")
        limit = args.get("limit", 50)
        offset = args.get("offset", 0)
        order_by = args.get("order_by")
        include_apis = bool(args.get("include_apis", False))
        include_strings = bool(args.get("include_strings", False))

        session = self.current_session
        ip = args.get("idb") or (session.idb_path if session else None)
        if not ip:
            return make_error(
                MCPError.SESSION_REQUIRED,
                "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
            )

        from .intelligence.structural_index import (
            get_db_path, ensure_tables, upsert_functions_batch,
            execute_host_query, write_insight_index, add_global_facts,
            _detect_global_facts
        )

        db_path = get_db_path(ip)

        if action == "structural_delete":
            if os.path.exists(db_path):
                try:
                    os.remove(db_path)
                    return {"ok": True, "deleted": db_path}
                except Exception as e:
                    return make_error(MCPError.DB_ERROR, f"Failed to delete database: {e}")
            return make_error(MCPError.FILE_NOT_FOUND, f"No index found at {db_path}")

        if action == "structural_stats":
            if not os.path.exists(db_path):
                return make_error(MCPError.FILE_NOT_FOUND, "No index found. Run structural_ingest first.")
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM function_attrs")
                total_indexed = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(DISTINCT func_ea) FROM function_apis")
                funcs_with_apis = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(DISTINCT func_ea) FROM function_strings")
                funcs_with_strings = cursor.fetchone()[0]
                cursor.execute("SELECT AVG(size), AVG(entropy), AVG(bb_count), AVG(cyclomatic_complexity) FROM function_attrs")
                avg_size, avg_entropy, avg_bb, avg_cc = cursor.fetchone()
                cursor.execute("SELECT segment, COUNT(*) FROM function_attrs GROUP BY segment")
                segments = {row[0]: row[1] for row in cursor.fetchall()}
                conn.close()
                return {
                    "ok": True,
                    "db_path": db_path,
                    "total_indexed": total_indexed,
                    "funcs_with_apis": funcs_with_apis,
                    "funcs_with_strings": funcs_with_strings,
                    "avg_size": round(avg_size or 0, 1),
                    "avg_entropy": round(avg_entropy or 0, 2),
                    "avg_bb_count": round(avg_bb or 0, 1),
                    "avg_cyclomatic": round(avg_cc or 0, 1),
                    "segments": segments,
                }
            except Exception as e:
                return make_error(MCPError.DB_ERROR, f"Failed to retrieve stats: {e}")

        if action == "structural_get":
            if not addr:
                return make_error(MCPError.INVALID_ARGS, "addr required for structural_get")
            try:
                ea = int(addr, 0) if isinstance(addr, str) else addr
            except ValueError:
                return make_error(MCPError.INVALID_ARGS, f"Invalid address format: {addr}")

            if not os.path.exists(db_path):
                return make_error(MCPError.FILE_NOT_FOUND, "No index found")

            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM function_attrs WHERE ea=?", (ea,))
                row = cursor.fetchone()
                if not row:
                    conn.close()
                    return make_error(MCPError.NOT_FOUND, f"Function {addr} not in index")
                cols = [d[0] for d in cursor.description]
                result = dict(zip(cols, row))
                if include_apis:
                    cursor.execute("SELECT api_name FROM function_apis WHERE func_ea=?", (ea,))
                    result["apis"] = [r[0] for r in cursor.fetchall()]
                if include_strings:
                    cursor.execute("SELECT string_text, string_ea FROM function_strings WHERE func_ea=?", (ea,))
                    result["strings"] = [{"text": r[0], "ea": hex(r[1])} for r in cursor.fetchall()]
                conn.close()
                result["ea"] = hex(result["ea"])
                return {"ok": True, "function": result}
            except Exception as e:
                return make_error(MCPError.DB_ERROR, f"Failed to get function: {e}")

        if action == "structural_query":
            return execute_host_query(
                db_path, constraints, limit=limit, offset=offset, order_by=order_by,
                include_apis=include_apis, include_strings=include_strings
            )

        if action == "structural_ingest":
            extract_res = self.call_tool("intelligence", ip, action="structural_extract")
            if extract_res.get("error") or not extract_res.get("ok"):
                return extract_res

            funcs_data = extract_res.get("functions") or []

            try:
                conn = sqlite3.connect(db_path)
                ensure_tables(conn)
                ingested = upsert_functions_batch(conn, funcs_data)
                conn.close()
            except Exception as e:
                return make_error(MCPError.DB_ERROR, f"Ingestion database error: {e}")

            try:
                write_insight_index(funcs_data)
                all_facts = []
                for f in funcs_data:
                    all_facts.extend(_detect_global_facts(f))
                add_global_facts(all_facts)
                facts_count = len(all_facts)
            except Exception as e:
                log_rpc(f"Failed to update L1/L2 index during structural_ingest: {e}")
                facts_count = 0

            return {
                "ok": True,
                "action": "structural_ingest",
                "total_functions": len(funcs_data),
                "ingested": ingested,
                "db_path": db_path,
                "l1_indexed": len(funcs_data),
                "l2_facts_added": facts_count,
            }

        if action == "structural_refresh":
            if addr:
                extract_res = self.call_tool("intelligence", ip, action="structural_extract_single", addr=addr)
                if extract_res.get("error") or not extract_res.get("ok"):
                    return extract_res
                func_data = extract_res.get("function")
                if not func_data:
                    return make_error(MCPError.NOT_FOUND, f"Failed to extract function at {addr}")

                try:
                    conn = sqlite3.connect(db_path)
                    ensure_tables(conn)
                    upsert_functions_batch(conn, [func_data])
                    conn.close()
                except Exception as e:
                    return make_error(MCPError.DB_ERROR, f"Refresh database error: {e}")

                try:
                    write_insight_index([func_data])
                    add_global_facts(_detect_global_facts(func_data))
                except Exception as e:
                    log_rpc(f"Failed to update L1/L2 index during structural_refresh: {e}")

                return {"ok": True, "refreshed": 1, "ea": addr}
            else:
                return self._handle_intelligence_structural({"action": "structural_ingest", "idb": ip})

        return make_error(MCPError.INVALID_ARGS, f"Unknown structural action: {action}")
