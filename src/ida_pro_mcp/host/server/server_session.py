#!/usr/bin/env python3
"""Session tool dispatch helpers for IDAMCPServer."""

from __future__ import annotations

import contextlib
import os
import re
import threading
import time
from datetime import datetime
from typing import Any

from ..analysis.arch_profile import infer_binary_arch_profile, normalize_arch_options
from ..config import (
    LARGE_BINARY_THRESHOLD_BYTES,
    MAX_BATCH_CALLS,
    MAX_LIST_LIMIT,
    MAX_LIST_OFFSET,
    MAX_NAME_LEN,
    MAX_NOTE_LEN,
    MAX_TAG_LEN,
    MAX_TAGS_PER_SESSION,
    SAFE_MODE_POLL_SECONDS,
    SAFE_MODE_WATCH_SECONDS,
    _bounded_int,
    _coerce_bool,
    _normalize_session_id,
    log_rpc,
)
from ..errors import MCPError, is_error_result, make_error
from ..intelligence.helpers import parse_str_list
from ..schemas import TOOL_ACTIONS
from .server_client_state import ServerClientStateMixin
from .server_session_bootstrap import ServerSessionBootstrapMixin
from .tool_registry import register_tool_actions

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# TTL cache for the `ida_session_state` coverage block (expensive: calls
# data/functions). The cache dict is instance- and session-scoped and
# lock-guarded (see _get_cached_coverage); this constant is just the TTL.
_SESSION_STATE_CACHE_TTL = 30.0  # seconds

# In-flight session-diff dedup: pair -> active diff thread, guarded by a
# module lock. See _trigger_session_diff.
_SESSION_DIFF_INFLIGHT: set[tuple[str, str]] = set()
_SESSION_DIFF_LOCK = threading.Lock()

# Keys that count as an architecture/loader preload request when opening a
# binary; shared by the reuse-decision logic in create/create_background.
_OPEN_PRELOAD_KEYS = ("processor", "bitness", "endian", "loader", "flags", "loader_options", "value")

# ---------------------------------------------------------------------------
# Declarative session-action dispatch.
#
# Most session actions follow one of three trivial shapes:
#   "dict" -> resolve sid, call mgr.<m>(sid, **kw); None => SESSION_NOT_FOUND,
#             return {"ok": True, "session": r.to_dict()}
#   "list" -> call mgr.<m>(**kw), return {"ok": True, "sessions": [...], "count": n}
#   "raw"  -> resolve sid, return mgr.<m>(sid, **kw) unchanged
#
# Each coerce function returns (kwargs, error): kwargs is the dict of keyword
# args forwarded to the SessionManager method; error is a ready-to-return
# capsule (or None). Actions needing bespoke control flow stay as explicit
# _session_action_* methods and map to a method-name string in _SESSION_ACTIONS.
# ---------------------------------------------------------------------------

def _sess_coerce_none(args):
    return {}, None

def _sess_coerce_rename(args):
    name = args.get("name") or args.get("new_name")
    if not name:
        return None, make_error(MCPError.INVALID_ARGS, "name required")
    return {"new_name": str(name).strip()[:MAX_NAME_LEN]}, None

def _sess_coerce_tag(args):
    tag = args.get("tag")
    if not tag:
        return None, make_error(MCPError.INVALID_ARGS, "tag required")
    tag = str(tag).strip()[:MAX_TAG_LEN]
    if not tag:
        return None, make_error(MCPError.INVALID_ARGS, "tag required")
    return {"tag": tag}, None

def _sess_coerce_untag(args):
    tag = args.get("tag")
    if not tag:
        return None, make_error(MCPError.INVALID_ARGS, "tag required")
    return {"tag": tag}, None

def _sess_coerce_note(args):
    note = args.get("note", "")
    if not note:
        return None, make_error(MCPError.INVALID_ARGS, "note required")
    return {"note": str(note)[:MAX_NOTE_LEN]}, None

def _sess_coerce_query(args):
    query = args.get("query", "")
    if not query:
        return None, make_error(MCPError.INVALID_ARGS, "query required")
    return {"query": query}, None

def _substitute_params(obj, params: dict):
    """Recursively substitute $param placeholders in a value.

    For strings: replaces "$name" with params["name"] or params["$name"].
    For dicts: recursively substitutes values.
    For lists: recursively substitutes items.
    """
    if isinstance(obj, str):
        for k, v in params.items():
            key = k.lstrip("$")
            obj = obj.replace(f"${key}", str(v))
        return obj
    if isinstance(obj, dict):
        return {k: _substitute_params(v, params) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute_params(item, params) for item in obj]
    return obj

class ServerSessionMixin(ServerSessionBootstrapMixin, ServerClientStateMixin):
    @staticmethod
    def _trigger_session_diff(old_idb: str, new_idb: str) -> None:
        import threading

        def _diff():
            try:
                from ida_pro_mcp.host.intelligence.core import BgeCodeEmbedder, FunctionEmbeddingIndex
            except ImportError:
                return
            try:
                embedder = BgeCodeEmbedder()
                new_idx = FunctionEmbeddingIndex(new_idb + ".embeddings.db", embedder)
                old_idx = FunctionEmbeddingIndex(old_idb + ".embeddings.db", embedder)
                if new_idx.size == 0 or old_idx.size == 0:
                    return
                new_only = []
                for ea, vec in list(new_idx._cache.items())[:200]:
                    matches = old_idx.similar_vec(vec, top_k=1, threshold=0.0)
                    if not matches:
                        new_only.append(ea)
                if new_only:
                    log_rpc(f"[session-diff] {len(new_only)} new functions in rebuilt IDB")
            except Exception:
                pass
            finally:
                with _SESSION_DIFF_LOCK:
                    _SESSION_DIFF_INFLIGHT.discard((old_idb, new_idb))

        # Dedup concurrent identical diffs: frequent session switches each
        # start a thread that builds two embedding indexes into RAM, so two
        # rapid A->B->A switches must not run three overlapping diffs.
        with _SESSION_DIFF_LOCK:
            if (old_idb, new_idb) in _SESSION_DIFF_INFLIGHT:
                return
            _SESSION_DIFF_INFLIGHT.add((old_idb, new_idb))
        threading.Thread(target=_diff, daemon=True).start()

    _SESSION_ACTIONS: dict[str, Any] = {
        "health": "_session_action_health",
        "create": "_session_action_create",
        "create_background": "_session_action_create_background",
        "get": "_session_action_get",
        "list": "_session_action_list",
        "switch": "_session_action_switch",
        "close": "_session_action_close",
        "status": "_session_action_status",
        "rebuild": "_session_action_rebuild",
        "update": "_session_action_update",
        "rename": ("dict", "rename_session", _sess_coerce_rename),
        "duplicate": ("dict", "duplicate_session", _sess_coerce_none),
        "archive": ("dict", "archive_session", _sess_coerce_none),
        "unarchive": ("dict", "unarchive_session", _sess_coerce_none),
        "tag": ("dict", "tag_session", _sess_coerce_tag),
        "untag": ("dict", "untag_session", _sess_coerce_untag),
        "add_note": ("dict", "add_note", _sess_coerce_note),
        "clear_notes": ("dict", "clear_notes", _sess_coerce_none),
        "search_notes": "_session_action_search_notes",
        "snapshot": "_session_action_snapshot",
        "restore_snapshot": "_session_action_restore_snapshot",
        "kill": "_session_action_kill",
        "state": "_session_action_state",
        "logs": "_session_action_logs",
        "cleanup_stale": "_session_action_cleanup_stale",
        "idle_purge": "_session_action_idle_purge",
        "sso_activate": "_session_action_sso_activate",
        "agent_login": "_session_action_agent_login",
        "agent_logout": "_session_action_agent_logout",
        # Local-skills / strategy session actions
        "rate_skill": "_session_action_rate_skill",
        "list_skills": "_session_action_list_skills",
        "suggest_triage": "_session_action_suggest_triage",
        "suggest_strategy": "_session_action_suggest_strategy",
        "get_phase": "_session_action_get_phase",
        "dashboard": "_session_action_dashboard",
    }

    def _handle_session(self, args: dict) -> dict:
        action = args.get("action")
        spec = self._SESSION_ACTIONS.get(action)
        if spec is not None:
            if isinstance(spec, str):
                return getattr(self, spec)(args)
            return self._run_session_spec(spec, args)
        if action and action.startswith("bootstrap_"):
            result = self._handle_session_bootstrap(action, args, lambda: self._resolve_session_id(args))
            if result is not None:
                return result
        return make_error(
            MCPError.ACTION_NOT_FOUND,
            f"Unsupported session action: '{action}'",
            hint=f"Valid session actions: {', '.join(TOOL_ACTIONS['session'])}",
        )

    def _require_session_sid(self, args: dict) -> tuple[str | None, dict | None]:
        """Resolve the target session_id, returning (sid, error_dict).

        On success sid is set and error is None. On any failure sid is None and
        error is a ready-to-return error dict (format error or 'session_id
        required'). Handles the resolve→validate boilerplate shared by every
        sid-requiring session action.
        """
        sid, err = self._resolve_session_id(args)
        if err:
            return None, err
        if not sid:
            return None, make_error(MCPError.INVALID_ARGS, "session_id required")
        return sid, None

    def _run_session_spec(self, spec: tuple, args: dict) -> dict:
        """Execute a declarative session action spec.

        spec is (kind, mgr_method, coerce_fn) where kind is one of the three
        trivial shapes documented above _SESSION_ACTIONS. Behavior matches the
        former per-action handler bodies exactly.
        """
        kind, mgr_method, coerce = spec
        sid = None
        if kind in ("dict", "raw"):
            sid, err = self._require_session_sid(args)
            if err:
                return err
        coerced, cerr = coerce(args)
        if cerr:
            return cerr
        # Defensive: if the SessionManager doesn't expose the method,
        # surface a clear NOT_IMPLEMENTED rather than an AttributeError
        # that callers can't classify.
        mgr_call = getattr(self.session_mgr, mgr_method, None)
        if mgr_call is None:
            return make_error(
                MCPError.NOT_IMPLEMENTED,
                f"Session action {mgr_method!r} is not implemented in this build",
                hint="Check the package version; this action may have been removed or is gated on a feature flag.",
                details={"method": mgr_method, "kind": kind},
            )
        if kind == "dict":
            result = mgr_call(sid, **coerced)
            if result is None:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found")
            return {"ok": True, "session": result.to_dict()}
        if kind == "list":
            sessions = [s.to_dict() for s in mgr_call(**coerced)]
            return {"ok": True, "sessions": sessions, "count": len(sessions)}
        # raw: return the manager result unchanged.
        return mgr_call(sid, **coerced)

    def _resolve_session_id(self, args: dict, key: str = "session_id", allow_current: bool = True) -> tuple[str | None, dict | None]:
        raw_sid = args.get(key)
        if raw_sid is None and allow_current and self.current_session:
            raw_sid = self.current_session.session_id
        if raw_sid is None:
            return None, None
        sid = _normalize_session_id(raw_sid)
        if sid:
            return sid, None
        # Compatibility: treat short/simple alnum values as "not found",
        # while still rejecting clearly malformed/path-like payloads.
        raw_txt = str(raw_sid).strip()
        if raw_txt and re.fullmatch(r"[A-Za-z0-9]+", raw_txt):
            return raw_txt.upper(), None
        return None, make_error(
            MCPError.INVALID_ARGS, "Invalid session_id format"
        )

    def _require_owned_session_id(self, sid: str) -> dict | None:
        """Reject mutating session actions against another client's session."""
        session = self.session_mgr.get_session(sid)
        if not session:
            return make_error(
                MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
            )
        return self._ensure_client_owns_session(session)

    def _session_action_health(self, args: dict) -> dict:
        return self._handle_session_health(args)

    def _session_action_sso_activate(self, args: dict) -> dict:
        """Enable the agent SSO realm and pre-register the allowed agents.

        Orchestrator-only bootstrap: no session is targeted, so this never
        touches ``current_session``. Existing connection-level sessions stay
        unbound (legacy) — new subagents log in and get isolated after this."""
        ok, err = self._sso_activate_realm(args.get("agents"), args.get("secret"))
        if err is not None:
            return err
        return ok

    def _session_action_agent_login(self, args: dict) -> dict:
        """Validate a signed ticket and log the subagent in on this connection."""
        ok, err = self._sso_agent_login(args.get("name"), args.get("ticket"))
        if err is not None:
            return err
        return ok

    def _session_action_agent_logout(self, args: dict) -> dict:
        """Log a subagent out and tear down only its runtimes/leases."""
        ok, err = self._sso_agent_logout(args.get("name"))
        if err is not None:
            return err
        return ok

    def _session_action_create(self, args: dict) -> dict:
        binary_path, analysis_options, arch_meta, force_new, ida_args, prep_error = (
            self._prepare_open_args(args)
        )
        if prep_error:
            return prep_error

        has_preload_request = any(
            k in analysis_options and analysis_options.get(k) is not None
            for k in _OPEN_PRELOAD_KEYS
        )

        existing = self._select_reuse_candidate(
            binary_path, analysis_options, force_new
        )

        # Even when the caller passes loader/architecture preload options,
        # reuse the existing session if those options already match — this
         # stops smoke runs from spawning a new idat child for the same
         # binary on every restart. force_new=true still wins.
        if existing and not force_new and has_preload_request and analysis_options:
            if self._preloads_match(existing, analysis_options):
                # Pretend preload request was absent so the existing reuse
                # branch runs.
                has_preload_request = False

        # Auto-background: a large binary whose analysis would actually run
        # (no completed IDB to reuse) must not stall this request. Route to
        # the background path — the agent is informed via background +
        # safe_mode in the response and polls ida_session_status. Re-opening
        # the same binary cannot escape safe mode this way: the background
        # path marks the session pending again.
        if self._is_large_binary(binary_path) and not (
            existing and not force_new and existing.idb_on_disk()
        ):
            bg_args = dict(args)
            bg_args["_auto_backgrounded"] = True
            return self._session_action_create_background(bg_args)

        if existing and not force_new and not has_preload_request:
            # Update the REAL session through the manager, not the shallow copy
            update_kwargs = {"analysis_applied": False}
            if analysis_options:
                merged_opts = dict(existing.analysis_options)
                merged_opts.update(analysis_options)
                update_kwargs["analysis_options"] = merged_opts
            if ida_args is not None:
                update_kwargs["ida_args"] = ida_args
            updated = self.session_mgr.update_session(
                existing.session_id, **update_kwargs
            )
            if updated is None:
                return make_error(
                    MCPError.SESSION_NOT_FOUND,
                    f"Session '{existing.session_id}' disappeared during reuse",
                )
            self.current_session = updated
            # Safe mode starts the moment we may have to (re)analyze; it is
            # lifted below only if a live runtime confirms completion.
            self._mark_analysis_pending(updated)
            out = self._open_result(
                updated,
                reused=True,
                note="Reusing existing session. Use force_new=true to create a new session.",
            )
            # If the runtime for this session is dead, spawn a fresh
            # idat and block until the IDB is on disk. The caller then
            # gets a usable session without extra round-trips.
            self._ensure_runtime_and_idb(updated)
            out["idb_exists"] = bool(
                updated.idb_path and os.path.isfile(updated.idb_path)
            )
            out["is_running"] = self._session_is_running(updated.session_id)
            analysis_state = self._open_analysis_state(updated)
            if analysis_state.get("analysis_complete") is True:
                self._mark_analysis_complete(updated)
                out["analysis_functions"] = analysis_state.get(
                    "analysis_functions"
                )
            out["analysis_complete"] = self._analysis_is_complete(
                updated.session_id
            )
            out["safe_mode"] = self._safe_mode_active(updated.session_id)
            return out

        create_note = None
        if existing and not force_new and has_preload_request:
            create_note = (
                "Created a fresh session because architecture/loader options were provided; "
                "reusing an old IDB can preserve previous metapc/default analysis state."
            )

        if not analysis_options:
            analysis_options = None

        tags = args.get("tags", [])
        if isinstance(tags, str):
            tags = parse_str_list(tags)
        tags = tags[:MAX_TAGS_PER_SESSION]
        notes = str(args.get("notes", ""))[:MAX_NOTE_LEN]

        inferred = (arch_meta.get("inferred_profile") or {}) if isinstance(arch_meta, dict) else {}
        is_packed_idb = isinstance(inferred, dict) and inferred.get("file_kind") == "packed_idb"

        # Deliberately no policy_mode here: the policy engine is configured by
        # the operator through IDA_MCP_POLICY_MODE or the policy config file.
        # Honouring a caller-supplied mode would let a single session(create)
        # call — which classifies as a read and so needs no acknowledgement —
        # turn the whole engine off for the session.
        self.current_session = self.session_mgr.create_session(
            binary_path or "",
            analysis_options=analysis_options,
            ida_args=ida_args,
            tags=tags,
            notes=notes,
            packed_idb=is_packed_idb,
        )
        # Safe mode starts on every fresh open; only a live runtime's
        # explicit analysis_complete=True lifts it.
        self._mark_analysis_pending(self.current_session)
        out = self._open_result(self.current_session)
        if create_note:
            out["note"] = create_note
        if arch_meta:
            inferred = arch_meta.get("inferred_profile") if isinstance(arch_meta, dict) else None
            if isinstance(inferred, dict):
                candidates = inferred.get("candidates") if isinstance(inferred.get("candidates"), list) else []
                if candidates:
                    out["architecture_recommendations"] = [
                        {
                            "tool": "analysis",
                            "arguments": {
                                "action": "set_architecture",
                                "processor": c.get("processor"),
                                "bitness": c.get("bitness"),
                                "endian": c.get("endian"),
                            },
                            "confidence": c.get("confidence"),
                            "reason": c.get("reason"),
                        }
                        for c in candidates[:3]
                        if isinstance(c, dict) and c.get("processor")
                    ]
                elif not candidates:
                    out["architecture_recommendations"] = [
                        {
                            "tool": "analysis",
                            "arguments": {
                                "action": "set_architecture",
                                "processor": "arm",
                                "bitness": 32,
                                "endian": "little",
                            },
                            "confidence": 0.2,
                            "reason": "raw binary ambiguous; apply explicit architecture before deep analysis",
                        }
                    ]
        with contextlib.suppress(Exception):
            self._import_cross_session_hypotheses(self.current_session)

        # Spawn idat and wait for the IDB so the caller gets a usable
        # session on the first call.
        self._ensure_runtime_and_idb(self.current_session)
        out["idb_exists"] = bool(
            self.current_session.idb_path
            and os.path.isfile(self.current_session.idb_path)
        )
        out["is_running"] = self._session_is_running(self.current_session.session_id)

        # Check analysis state via lightweight RPC (always, not blocking);
        # confirm completion when the runtime says so.
        analysis_state = self._open_analysis_state(self.current_session)
        if analysis_state.get("analysis_complete") is True:
            self._mark_analysis_complete(self.current_session)
            out["analysis_functions"] = analysis_state.get("analysis_functions")
        out["analysis_complete"] = self._analysis_is_complete(
            self.current_session.session_id
        )
        out["safe_mode"] = self._safe_mode_active(self.current_session.session_id)
        return out

    @staticmethod
    def _preloads_match(existing, analysis_options: dict) -> bool:
        """True when the existing session's arch/loader options match the request."""
        if not analysis_options:
            return True
        existing_opts = dict(existing.analysis_options or {})
        return not any(
            str(existing_opts.get(k) or "") != str(analysis_options.get(k) or "")
            for k in _OPEN_PRELOAD_KEYS
            if k in analysis_options
        )

    def _session_is_running(self, sid: str) -> bool:
        """True when the session has a live IDA runtime process."""
        runtime = self.session_runtimes.get(sid)
        return bool(
            runtime and runtime.get("process") and runtime["process"].poll() is None
        )

    def _open_result(
        self,
        session,
        *,
        background: bool = False,
        reused: bool = False,
        note: str | None = None,
        extra: dict | None = None,
    ) -> dict:
        """Build the minimal 'session opened' response.

        The open operations report a flat summary — session_id plus
        readiness flags — instead of dumping the full session record and
        implementation bookkeeping (import counters, bootstrap reports,
        architecture dumps). Details are one ida_session_get away.
        """
        out = {
            "ok": True,
            "session_id": session.session_id,
            "binary_path": session.binary_path or "",
            "idb_path": session.idb_path or "",
            "idb_exists": bool(
                session.idb_path and os.path.isfile(session.idb_path)
            ),
            "is_running": self._session_is_running(session.session_id),
            "safe_mode": self._safe_mode_active(session.session_id),
            "analysis_complete": self._analysis_is_complete(session.session_id),
        }
        if reused:
            out["reused_existing_session"] = True
        if background:
            out["background"] = True
        if note:
            out["note"] = note
        if extra:
            out.update(extra)
        return out

    def _open_analysis_state(self, session) -> dict:
        """Read analysis progress from a live runtime, if any.

        Returns {} when the runtime is not alive or does not answer, so
        callers can attach analysis_complete/analysis_functions when known.
        """
        sid = session.session_id
        runtime = self.session_runtimes.get(sid)
        if not (runtime and self._runtime_alive(runtime)):
            return {}
        port = runtime.get("port")
        if not (isinstance(port, int) and port > 0):
            return {}
        try:
            state_res = self._send_rpc_raw(
                {"tool": "analysis", "args": {"action": "state"}},
                port,
                recv_timeout=10,
            )
            if (
                isinstance(state_res, dict)
                and "error" not in state_res
                # Only an explicit True counts as complete; a missing or
                # ambiguous field must never lift safe mode.
                and state_res.get("analysis_complete") is True
            ):
                return {
                    "analysis_complete": True,
                    "analysis_functions": int(state_res.get("functions") or 0),
                }
        except Exception:
            pass
        return {}

    def _prepare_open_args(self, args: dict) -> tuple:
        """Validate and normalize ida_open_binary-style arguments.

        Shared by the blocking create action and the non-blocking
        create_background action. Returns
        (binary_path, analysis_options, arch_meta, force_new, ida_args, error)
        where error is None on success.
        """
        binary_path = args.get("binary_path")
        if "idb_path" in args or "use_existing" in args:
            return (
                None, None, None, False, None,
                make_error(
                    MCPError.INVALID_ARGS,
                    "The idb_path and use_existing parameters were removed from session create",
                    details={
                        "hint": "Use ida_open_binary(binary_path='...') instead; IDB creation/reuse is automatic."
                    },
                ),
            )
        force_new = bool(args.get("force_new"))

        if binary_path is not None and not isinstance(binary_path, str):
            return (
                None, None, None, False, None,
                make_error(
                    MCPError.INVALID_ARGS,
                    "binary_path must be a string",
                    details={
                        "hint": "Provide a path string, e.g. ida_open_binary(binary_path='/abs/path/to/binary')."
                    },
                ),
            )

        analysis_options = {}
        raw_analysis_options = args.get("analysis_options")
        if raw_analysis_options is not None and not isinstance(raw_analysis_options, dict):
            return (
                None, None, None, False, None,
                make_error(
                    MCPError.INVALID_ARGS,
                    "analysis_options must be an object",
                    details={"analysis_options_type": type(raw_analysis_options).__name__},
                ),
            )
        if isinstance(raw_analysis_options, dict):
            analysis_options.update(raw_analysis_options or {})

        architecture = args.get("architecture")
        if architecture is not None and not isinstance(architecture, dict):
            return (
                None, None, None, False, None,
                make_error(
                    MCPError.INVALID_ARGS,
                    "architecture must be an object",
                    details={"architecture_type": type(architecture).__name__},
                ),
            )
        if isinstance(architecture, dict):
            arch_aliases = {
                "arch": "processor",
                "proc": "processor",
                "architecture": "processor",
                "bits": "bitness",
                "endianness": "endian",
            }
            for k, v in architecture.items():
                canon = arch_aliases.get(str(k), str(k))
                if canon in ("processor", "bitness", "endian", "loader", "flags", "loader_options", "value"):
                    if canon in analysis_options and analysis_options[canon] != v:
                        return (
                            None, None, None, False, None,
                            make_error(
                                MCPError.INVALID_ARGS,
                                f"Conflicting architecture value for '{canon}'",
                                details={"analysis_options": analysis_options.get(canon), "architecture": v},
                            ),
                        )
                    analysis_options[canon] = v

        merged_keys = (
            "processor",
            "flags",
            "loader",
            "value",
            "loader_options",
            "bitness",
            "endian",
            "reanalyze",
            "options",
            "start",
            "end",
            "analysis_actions",
            "apply_once",
            "recover",
            "backup_on_recover",
            "aggressive_cleanup",
            "baseaddr",
            "start_ea",
            "min_ea",
            "max_ea",
            "input_format",
            "processor_options",
            "rebase_to",
            "entry_point",
            "stack_size",
            "memory_model",
            "skip_analysis",
            "no_analysis",
        )
        for key in merged_keys:
            if key in args:
                top_val = args.get(key)
                if key in analysis_options and analysis_options[key] != top_val:
                    return (
                        None, None, None, False, None,
                        make_error(
                            MCPError.INVALID_ARGS,
                            f"Conflicting value for '{key}' between top-level and analysis_options/architecture",
                            details={"top_level": top_val, "analysis_options": analysis_options.get(key)},
                        ),
                    )
                analysis_options[key] = top_val

        analysis_options, arch_meta = normalize_arch_options(analysis_options)

        ida_args = None
        if "ida_args" in args:
            try:
                ida_args = self._normalize_ida_args(args.get("ida_args"))
            except ValueError as e:
                return (None, None, None, False, None, make_error(MCPError.INVALID_ARGS, str(e)))

        if binary_path:
            if not os.path.isabs(binary_path):
                binary_path = os.path.abspath(binary_path)
            args["binary_path"] = binary_path
            if not os.path.exists(binary_path):
                return (
                    None, None, None, False, None,
                    make_error(
                        MCPError.FILE_NOT_FOUND,
                        f"Binary not found: {binary_path}",
                        details={
                            "binary_path": binary_path,
                            "hint": "Provide an absolute path to an existing binary file.",
                        },
                    ),
                )
            arch_meta = dict(arch_meta or {})
            arch_meta["inferred_profile"] = infer_binary_arch_profile(binary_path)
            arch_meta["inference_applied"] = True

        if not binary_path:
            return (
                None, None, None, False, None,
                make_error(
                    MCPError.INVALID_ARGS,
                    "binary_path is required",
                    details={
                        "hint": "Provide a binary path, e.g. ida_open_binary(binary_path='/abs/path/to/binary')."
                    },
                ),
            )
        return binary_path, analysis_options, arch_meta, force_new, ida_args, None

    def _select_reuse_candidate(self, binary_path: str, analysis_options: dict, force_new: bool):
        """Pick the best persisted session for the same binary to reuse.

        Among all sessions on this binary, prefer one whose recorded arch
        options match the requested ones. Only sessions this connection
        owns, or that nobody is actively running, qualify — a live foreign
        session is never silently shared.
        """
        if not binary_path or force_new:
            return None
        candidates = self.session_mgr.find_sessions_by_path(binary_path)
        candidates = [
            cand for cand in candidates
            if self._client_owns_session(cand.session_id)
            or not self._session_is_busy(cand.session_id)
        ]
        existing = None
        for cand in candidates:
            if not cand.analysis_options:
                existing = cand
                break
            cand_opts = dict(cand.analysis_options or {})
            mismatch = any(
                str(cand_opts.get(k) or "") != str((analysis_options or {}).get(k) or "")
                for k in _OPEN_PRELOAD_KEYS
                if k in (analysis_options or {})
            )
            if not mismatch:
                existing = cand
                break
        if not existing and candidates:
            existing = candidates[0]
        return existing

    @staticmethod
    def _is_large_binary(binary_path: str) -> bool:
        """True when *binary_path* is large enough to auto-background."""
        if not binary_path:
            return False
        try:
            with open(binary_path, "rb") as _fh:
                if _fh.read(4) == b"IDA2":
                    return False  # packed IDB — already analyzed, never background
            return os.path.getsize(binary_path) >= LARGE_BINARY_THRESHOLD_BYTES
        except OSError:
            return False

    # ------------------------------------------------------------------
    # Safe mode: while IDA auto-analysis is still completing, full-binary
    # analysis / indexing / script execution is gated. Safe mode is a
    # host-side, in-memory property of the session; it is marked pending on
    # every open/rebuild that leaves analysis incomplete and is lifted only
    # when a live runtime confirms analysis_complete. Re-opening the same
    # binary (reuse or force_new), killing the runtime mid-build, or
    # rebuilding the IDB cannot escape the gate — every path re-enters
    # pending state.
    # ------------------------------------------------------------------

    def _safe_mode_active(self, sid: str) -> bool:
        """True while *sid*'s IDA auto-analysis is still completing."""
        pending = getattr(self, "_pending_analysis", None)
        return isinstance(pending, set) and sid in pending

    def _analysis_is_complete(self, sid: str) -> bool:
        """True when a live runtime confirmed *sid*'s analysis completed."""
        complete = getattr(self, "_analysis_complete_sessions", None)
        return isinstance(complete, set) and sid in complete

    def _mark_analysis_pending(self, session) -> None:
        """Enter safe mode for *session* and start watching for completion."""
        sid = session.session_id
        pending = getattr(self, "_pending_analysis", None)
        if not isinstance(pending, set):
            self._pending_analysis = set()
            pending = self._pending_analysis
        pending.add(sid)
        complete = getattr(self, "_analysis_complete_sessions", None)
        if isinstance(complete, set):
            complete.discard(sid)
        if not getattr(session, "idb_on_disk", lambda: False)():
            no_idb = getattr(self, "_analysis_pending_no_idb", None)
            if not isinstance(no_idb, set):
                self._analysis_pending_no_idb = set()
                no_idb = self._analysis_pending_no_idb
            no_idb.add(sid)
        self._spawn_analysis_watcher(sid)

    def _mark_analysis_complete(self, session) -> None:
        """Lift safe mode for *session* and remember it as confirmed."""
        sid = session.session_id
        pending = getattr(self, "_pending_analysis", None)
        if isinstance(pending, set):
            pending.discard(sid)
        complete = getattr(self, "_analysis_complete_sessions", None)
        if not isinstance(complete, set):
            self._analysis_complete_sessions = set()
            complete = self._analysis_complete_sessions
        complete.add(sid)

    def _forget_analysis_state(self, sid: str) -> None:
        """Drop safe-mode tracking when a session is closed or killed."""
        for attr in (
            "_pending_analysis",
            "_analysis_complete_sessions",
            "_analysis_pending_no_idb",
            "_reloading_sessions",
        ):
            coll = getattr(self, attr, None)
            if isinstance(coll, set):
                coll.discard(sid)
            elif isinstance(coll, dict):
                coll.pop(sid, None)
        bg_loads = getattr(self, "_background_loads", None)
        if isinstance(bg_loads, dict):
            bg_loads.pop(sid, None)
        notices = getattr(self, "_pending_session_notices", None)
        if isinstance(notices, dict):
            notices.pop(sid, None)
        watchers = getattr(self, "_analysis_watchers", None)
        if isinstance(watchers, set):
            watchers.discard(sid)

    def _spawn_analysis_watcher(self, sid: str) -> None:
        """Start the single analysis-completion watcher for *sid*."""
        watchers = getattr(self, "_analysis_watchers", None)
        if not isinstance(watchers, set):
            self._analysis_watchers = set()
            watchers = self._analysis_watchers
        if sid in watchers:
            return
        watchers.add(sid)
        threading.Thread(
            target=self._watch_analysis_completion,
            args=(sid,),
            daemon=True,
            name=f"ida-an-{sid}",
        ).start()

    def _watch_analysis_completion(self, sid: str) -> None:
        """Poll analysis(action='state') until complete, then lift safe mode.

        Background-loaded sessions are reloaded against the completed IDB so
        the agent's session is backed by a fresh, fully-analyzed database
        (the 'auto move to the new one' step). A runtime that dies before
        analysis completes does NOT lift safe mode — the half-analyzed IDB
        must not be trusted — instead the interruption is surfaced via
        ida_session_status.background_error.
        """
        try:
            poll_sec = max(1.0, float(getattr(self, "safe_mode_poll_seconds", SAFE_MODE_POLL_SECONDS)))
            deadline = time.time() + max(
                60.0, float(getattr(self, "safe_mode_watch_seconds", SAFE_MODE_WATCH_SECONDS))
            )
            while time.time() < deadline:
                if not self._safe_mode_active(sid):
                    return  # lifted by another path (e.g. a status confirm)
                session = self.session_mgr.get_session(sid) if hasattr(self, "session_mgr") else None
                if session is None:
                    return
                runtime = self.session_runtimes.get(sid)
                if not (runtime and self._runtime_alive(runtime)):
                    # Runtime gone. If this process was building the IDB
                    # from scratch (background load or fresh pending open),
                    # the analysis was interrupted: keep safe mode ON and
                    # surface the failure. Otherwise the IDB pre-existed a
                    # completed run, so the session is usable.
                    bg_loads = getattr(self, "_background_loads", {}) or {}
                    build_interrupted = bool(
                        bg_loads.get(sid, False)
                        or sid in getattr(self, "_analysis_pending_no_idb", set())
                    )
                    if build_interrupted:
                        errors = getattr(self, "_background_load_errors", None)
                        if not isinstance(errors, dict):
                            self._background_load_errors = {}
                            errors = self._background_load_errors
                        errors.setdefault(
                            sid,
                            make_error(
                                MCPError.IDA_CRASHED,
                                "IDA runtime exited before auto-analysis completed; "
                                "safe mode stays on",
                                details={"session_id": sid},
                            ),
                        )
                        return
                    if getattr(session, "idb_on_disk", lambda: False)():
                        self._on_analysis_complete(session, reload=False)
                    return
                port = runtime.get("port")
                if isinstance(port, int) and port > 0:
                    try:
                        state_res = self._send_rpc_raw(
                            {"tool": "analysis", "args": {"action": "state"}},
                            port,
                            recv_timeout=10,
                        )
                        if (
                            isinstance(state_res, dict)
                            and "error" not in state_res
                            and state_res.get("analysis_complete") is True
                        ):
                            bg_loads = getattr(self, "_background_loads", {}) or {}
                            self._on_analysis_complete(
                                session,
                                reload=bool(bg_loads.get(sid, False)),
                            )
                            return
                    except Exception:
                        pass
                time.sleep(poll_sec)
        finally:
            watchers = getattr(self, "_analysis_watchers", None)
            if isinstance(watchers, set):
                watchers.discard(sid)

    def _on_analysis_complete(self, session, reload: bool) -> None:
        """Lift safe mode and, for background loads, reload against the IDB."""
        sid = session.session_id
        if reload:
            reloading = getattr(self, "_reloading_sessions", None)
            if not isinstance(reloading, set):
                self._reloading_sessions = set()
                reloading = self._reloading_sessions
            reloading.add(sid)
            try:
                with self._runtime_lock:
                    with contextlib.suppress(Exception):
                        self._cleanup_runtime(sid)
                    start_res = self._start_server(session)
                    if isinstance(start_res, dict) and "error" in start_res:
                        log_rpc(
                            f"Safe-mode reload of {sid} failed: "
                            f"{start_res.get('message') or start_res.get('code')}"
                        )
                    else:
                        self._wait_for_idb(session, timeout=120)
            finally:
                reloading.discard(sid)
            # The background load is done — clear the flag so a later status
            # poll (which may confirm completion before/after the watcher)
            # does not trigger a second reload, and so _maybe_resolve_analysis_state
            # uses the same reload decision the watcher made.
            bg_loads = getattr(self, "_background_loads", None)
            if isinstance(bg_loads, dict):
                bg_loads[sid] = False
        self._mark_analysis_complete(session)
        notices = getattr(self, "_pending_session_notices", None)
        if not isinstance(notices, dict):
            self._pending_session_notices = {}
            notices = self._pending_session_notices
        notices[sid] = {
            "code": "analysis_complete",
            "message": (
                "IDA auto-analysis completed; the session was reloaded against "
                "the fully analyzed IDB."
                if reload
                else "IDA auto-analysis completed."
            ),
            "suggestion": (
                "Safe mode is lifted: decompilation, semantic search, and "
                "indexing are now available."
            ),
        }

    def _maybe_resolve_analysis_state(self, session) -> None:
        """Opportunistically confirm analysis completion from a live runtime.

        Called from status/state so an agent polling for progress never gets
        stuck in safe mode because the watcher missed the transition. Only a
        live runtime's explicit analysis_complete=True lifts the gate.
        """
        sid = session.session_id
        if not self._safe_mode_active(sid):
            return
        runtime = self.session_runtimes.get(sid)
        if not (runtime and self._runtime_alive(runtime)):
            return
        port = runtime.get("port")
        if not (isinstance(port, int) and port > 0):
            return
        try:
            state_res = self._send_rpc_raw(
                {"tool": "analysis", "args": {"action": "state"}},
                port,
                recv_timeout=10,
            )
            if (
                isinstance(state_res, dict)
                and "error" not in state_res
                and state_res.get("analysis_complete") is True
            ):
                # Match the watcher's decision: background-load sessions are
                # reloaded against the completed IDB, everything else just has
                # safe mode lifted. Hardcoding reload=False here would lift the
                # gate on the pre-reload runtime while the watcher kills and
                # restarts it underneath the agent.
                bg_loads = getattr(self, "_background_loads", {}) or {}
                self._on_analysis_complete(
                    session,
                    reload=bool(bg_loads.get(sid, False)),
                )
        except Exception:
            pass

    def _spawn_runtime_background(self, session: Any) -> None:
        """Start idat for *session* without blocking the current request.

        The IDA runtime registers itself in session_runtimes when ready; a
        later ida_session_status / ida_session_state call reports progress.
        Failures are recorded in _background_load_errors and surfaced by
        status.
        """
        if not isinstance(getattr(self, "_background_load_errors", None), dict):
            self._background_load_errors = {}

        def _run():
            try:
                self._ensure_runtime_and_idb(session)
            except Exception as exc:  # pragma: no cover - exercised at runtime
                self._background_load_errors[session.session_id] = make_error(
                    MCPError.IDA_CRASHED,
                    f"Background IDA start failed: {exc}",
                    details={"session_id": session.session_id},
                )

        threading.Thread(
            target=_run, daemon=True, name=f"ida-bg-{session.session_id}"
        ).start()

    def _session_action_create_background(self, args: dict) -> dict:
        """Create/open a session without blocking on IDA analysis.

        For large binaries the upfront (blocking) load in ida_open_binary can
        stall the caller for the whole analysis. This action returns as soon
        as the session exists and the idat launch is dispatched; progress is
        reported through ida_session_status.
        """
        binary_path, analysis_options, arch_meta, force_new, ida_args, prep_error = (
            self._prepare_open_args(args)
        )
        if prep_error:
            return prep_error

        has_preload_request = any(
            k in analysis_options and analysis_options.get(k) is not None
            for k in _OPEN_PRELOAD_KEYS
        )
        existing = self._select_reuse_candidate(
            binary_path, analysis_options, force_new
        )
        auto = bool(args.get("_auto_backgrounded"))
        if existing and not force_new and (
            not has_preload_request or self._preloads_match(existing, analysis_options)
        ):
            update_kwargs = {"analysis_applied": False}
            if analysis_options:
                merged_opts = dict(existing.analysis_options)
                merged_opts.update(analysis_options)
                update_kwargs["analysis_options"] = merged_opts
            if ida_args is not None:
                update_kwargs["ida_args"] = ida_args
            updated = self.session_mgr.update_session(
                existing.session_id, **update_kwargs
            )
            if updated is None:
                return make_error(
                    MCPError.SESSION_NOT_FOUND,
                    f"Session '{existing.session_id}' disappeared during reuse",
                )
            self.current_session = updated
            bg_loads = getattr(self, "_background_loads", None)
            if not isinstance(bg_loads, dict):
                self._background_loads = {}
                bg_loads = self._background_loads
            bg_loads[updated.session_id] = not updated.idb_on_disk()
            self._mark_analysis_pending(updated)
            note = (
                "Binary is large; opened in background automatically. "
                "Safe mode is on until analysis completes — poll ida_session_status."
                if auto
                else (
                    "Reusing existing session; its runtime is starting in the "
                    "background. Poll ida_session_status for progress."
                )
            )
            out = self._open_result(
                updated,
                background=True,
                reused=True,
                note=note,
            )
            if auto:
                out["auto_backgrounded"] = True
            self._spawn_runtime_background(updated)
            return out

        if not analysis_options:
            analysis_options = None
        tags = args.get("tags", [])
        if isinstance(tags, str):
            tags = parse_str_list(tags)
        tags = tags[:MAX_TAGS_PER_SESSION]
        notes = str(args.get("notes", ""))[:MAX_NOTE_LEN]
        inferred = (arch_meta.get("inferred_profile") or {}) if isinstance(arch_meta, dict) else {}
        is_packed_idb = isinstance(inferred, dict) and inferred.get("file_kind") == "packed_idb"

        self.current_session = self.session_mgr.create_session(
            binary_path or "",
            analysis_options=analysis_options,
            ida_args=ida_args,
            tags=tags,
            notes=notes,
            packed_idb=is_packed_idb,
        )
        bg_loads = getattr(self, "_background_loads", None)
        if not isinstance(bg_loads, dict):
            self._background_loads = {}
            bg_loads = self._background_loads
        bg_loads[self.current_session.session_id] = True
        self._mark_analysis_pending(self.current_session)
        note = (
            "Binary is large; opened in background automatically. "
            "Safe mode is on until analysis completes — poll ida_session_status."
            if auto
            else (
                "Analysis started in the background; this call did not wait "
                "for IDA. Poll ida_session_status for progress."
            )
        )
        out = self._open_result(
            self.current_session,
            background=True,
            note=note,
        )
        if auto:
            out["auto_backgrounded"] = True
        self._spawn_runtime_background(self.current_session)
        return out

    def _session_action_discover(self, args: dict) -> dict:
        self.session_mgr._load_orphaned_idbs()
        q = args.get("query", "")
        binary_name = args.get("binary_name", "")
        sessions = [
            s.to_dict() for s in self.session_mgr.discover_sessions(
                query=q, binary_name=binary_name
            )
        ]
        return {"ok": True, "sessions": sessions, "count": len(sessions)}

    def _session_action_get(self, args: dict) -> dict:
        raw_sid = args.get("session_id")
        if not raw_sid:
            return make_error(
                MCPError.INVALID_ARGS,
                "session_id required",
                hint="Provide a session_id. Use ida_session_list to see available sessions.",
            )
        sid = _normalize_session_id(raw_sid)
        if not sid:
            raw_txt = str(raw_sid).strip()
            if raw_txt and re.fullmatch(r"[A-Za-z0-9]+", raw_txt):
                sid = raw_txt.upper()
            else:
                return make_error(
                    MCPError.INVALID_ARGS, "Invalid session_id format"
                )
        session = self.session_mgr.get_session(sid)
        if not session:
            return make_error(
                MCPError.SESSION_NOT_FOUND,
                f"Session '{sid}' not found",
                hint="Use ida_session_list to see available sessions.",
            )
        runtime = self.session_runtimes.get(sid)
        is_running = bool(
            runtime
            and runtime.get("process")
            and runtime["process"].poll() is None
        )
        result = session.to_dict()
        result["is_running"] = is_running
        result["safe_mode"] = self._safe_mode_active(sid)
        result["analysis_complete"] = self._analysis_is_complete(sid)
        if is_running:
            result["port"] = runtime.get("port")
        report = self._session_ownership_report(sid)
        result["locked"] = report.get("locked", False)
        result["holder"] = report.get("holder")
        result["owner_id"] = report.get("owner_id")
        result["owner_pid"] = report.get("owner_pid")
        result["owner_alive"] = report.get("owner_alive")
        result["idat_pid"] = report.get("idat_pid")
        result["lease_age_seconds"] = report.get("lease_age_seconds")
        return {"ok": True, "session": result}

    def _session_action_list(self, args: dict) -> dict:
        # Use locked manager method instead of direct dict access
        limit = _bounded_int(
            args.get("limit", 50), 50, min_value=0, max_value=MAX_LIST_LIMIT
        )
        offset = _bounded_int(
            args.get("offset", 0), 0, min_value=0, max_value=MAX_LIST_OFFSET
        )
        q = args.get("query", "")
        binary_name = args.get("binary_name", "")
        result = self.session_mgr.list_sessions(
            query=q, offset=offset, limit=limit, binary_name=binary_name
        )

        # Augment with runtime status and ownership forensics so a busy
        # session is identifiable (who holds it, and whether that owner is
        # alive) instead of an opaque locked flag.
        session_dicts = []
        for d in result["sessions"]:
            runtime = self.session_runtimes.get(d["session_id"])
            d["is_running"] = bool(
                runtime
                and runtime.get("process")
                and runtime["process"].poll() is None
            )
            d["safe_mode"] = self._safe_mode_active(d["session_id"])
            d["analysis_complete"] = self._analysis_is_complete(d["session_id"])
            report = self._session_ownership_report(d["session_id"])
            d["locked"] = report.get("locked", False)
            d["holder"] = report.get("holder")
            d["owner_id"] = report.get("owner_id")
            d["owner_pid"] = report.get("owner_pid")
            d["owner_alive"] = report.get("owner_alive")
            d["idat_pid"] = report.get("idat_pid")
            d["lease_age_seconds"] = report.get("lease_age_seconds")
            session_dicts.append(d)

        return {
            "ok": True,
            "sessions": session_dicts,
            "total": result["total"],
            "count": len(session_dicts),
            "offset": offset,
            "limit": limit,
        }

    def _session_action_search_notes(self, args: dict) -> dict:
        """Search session notes, scoped to sessions this connection may see.

        ``search_notes`` is the only bulk session read that enumerates every
        session's notes, so on a multiplexed connection it must honor the
        ownership model every other session read applies: only sessions this
        client owns, or that no live owner is running, are returned — an agent
        must never read another agent's notes by search.
        """
        query = args.get("query", "")
        if not query:
            return make_error(MCPError.INVALID_ARGS, "query required")
        owned = getattr(self, "_client_owns_session", None)
        busy = getattr(self, "_session_is_busy", None)
        visible = []
        for s in self.session_mgr.search_notes(query):
            sid = getattr(s, "session_id", None)
            if not sid:
                continue
            if callable(owned) and owned(sid):
                visible.append(s)
                continue
            if callable(busy) and not busy(sid):
                visible.append(s)
        return {"ok": True, "sessions": [s.to_dict() for s in visible], "count": len(visible)}

    def _session_action_switch(self, args: dict) -> dict:
        old_idb = getattr(self.current_session, "idb_path", None) if self.current_session else None
        reopen = bool(args.get("reopen") or args.get("restart"))
        sid = args.get("session_id")
        if not sid:
            # Try to find by binary_path among sessions this connection owns.
            path = args.get("binary_path")
            if path:
                owns = getattr(self, "_client_owns_session", None)
                candidates = self.session_mgr.find_sessions_by_path(path)
                candidates = [
                    c for c in candidates
                    if (callable(owns) and owns(c.session_id))
                    or not self._session_is_busy(c.session_id)
                ]
                found = candidates[0] if candidates else None
                if found:
                    sid = found.session_id
        if not sid:
            return make_error(
                MCPError.INVALID_ARGS,
                "session_id or binary_path required",
                hint="Provide session_id or binary_path. Use ida_session_list to see available sessions.",
            )
        normalized_sid = _normalize_session_id(sid)
        if normalized_sid:
            sid = normalized_sid
        else:
            raw_txt = str(sid).strip()
            if raw_txt and re.fullmatch(r"[A-Za-z0-9]+", raw_txt):
                sid = raw_txt.upper()
            else:
                return make_error(
                    MCPError.INVALID_ARGS, "Invalid session_id format"
                )
        session = self.session_mgr.get_session(sid)
        if not session:
            return make_error(
                MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
            )
        ownership_error = self._ensure_client_owns_session(session)
        if ownership_error:
            return ownership_error

        self.current_session = session
        new_idb = getattr(session, "idb_path", None)
        if old_idb and new_idb and old_idb != new_idb:
            self._trigger_session_diff(old_idb, new_idb)

        # Decide if we need to spawn/replace the IDA runtime for this session.
        runtime = self.session_runtimes.get(sid) if hasattr(self, "session_runtimes") else None
        runtime_alive = bool(runtime) and bool(self._runtime_alive(runtime))
        should_spawn = (
            reopen or not runtime_alive
        ) and os.path.isfile(getattr(session, "binary_path", "") or "")
        if should_spawn and hasattr(self, "_start_server"):
            # A fresh idat runs auto-analysis from the moment it spawns; re-enter
            # safe mode so full-binary operations stay gated until a live
            # runtime confirms completion. Every open/rebuild path re-enters
            # pending state (see the module comment on safe mode); switch with a
            # dead runtime or reopen=true is no exception.
            self._mark_analysis_pending(session)
            try:
                start_res = self._start_server(session)
                if isinstance(start_res, dict) and "error" not in start_res:
                    runtime = self.session_runtimes.get(sid)
                    runtime_alive = bool(runtime) and bool(self._runtime_alive(runtime))
                    # Block until the IDB is on disk so callers don't need to
                    # poll or manually trigger analysis.
                    if runtime_alive and os.path.isfile(getattr(session, "binary_path", "") or ""):
                        idb_path = getattr(session, "idb_path", None)
                        if idb_path and not os.path.isfile(idb_path):
                            self._wait_for_idb(session, timeout=120.0)
                            runtime = self.session_runtimes.get(sid)
                            runtime_alive = bool(runtime) and bool(self._runtime_alive(runtime))
                else:
                    # Surface the failure but keep the switch logically valid.
                    self._last_spawn_error = start_res
            except Exception as exc:  # pragma: no cover - exercised only at runtime
                self._last_spawn_error = make_error(
                    MCPError.IDA_CRASHED,
                    f"Runtime spawn failed: {exc}",
                    details={"exception_type": type(exc).__name__},
                )

        runtime_attached = runtime_alive
        response = {
            "ok": True,
            "session": self.current_session.to_dict(),
            "runtime_attached": runtime_attached,
            "safe_mode": self._safe_mode_active(sid),
            "analysis_complete": self._analysis_is_complete(sid),
        }
        idb_path = getattr(session, "idb_path", None)
        if idb_path and not os.path.isfile(idb_path) and not runtime_attached:
            response["idb_exists"] = False
            response["hint"] = (
                "IDB file not on disk at the recorded path. Try "
                "ida_session_switch(session_id='...', reopen=true) "
                "to spawn a new IDA runtime."
            )
        spawn_error = getattr(self, "_last_spawn_error", None)
        if isinstance(spawn_error, dict):
            response["spawn_error"] = spawn_error
            self._last_spawn_error = None
        return response

    def _ensure_runtime_and_idb(self, session: Any, timeout: float = 120.0) -> None:
        """Spawn idat for *session* if its runtime is dead and wait for the IDB.

        Used by the reuse path so a session restored from disk without a
        live runtime is immediately usable. No-op if the runtime is already
        attached and the IDB exists."""
        if not hasattr(self, "_start_server") or not hasattr(self, "session_runtimes"):
            return
        sid = session.session_id
        runtime = self.session_runtimes.get(sid)
        if runtime and self._runtime_alive(runtime):
            # Runtime is alive — just make sure the IDB is on disk
            idb_path = getattr(session, "idb_path", None)
            if idb_path and not os.path.isfile(idb_path):
                self._wait_for_idb(session, timeout=timeout)
            return
        # Runtime is dead or missing — spawn a replacement
        try:
            start_res = self._start_server(session)
            if isinstance(start_res, dict) and "error" not in start_res:
                runtime = self.session_runtimes.get(sid)
                if runtime and self._runtime_alive(runtime):
                    self._wait_for_idb(session, timeout=timeout)
        except Exception:
            pass  # Surface via the caller's spawn_error if needed

    def _wait_for_idb(self, session: Any, timeout: float = 120.0) -> bool:
        """Block until the IDB for *session* is written to disk.

        idat runs auto-analysis + targeted reanalysis asynchronously after
        spawn. Instead of making the caller poll or manually re-trigger
        analysis, session(action='create') blocks here so the returned
        session has a useful IDB.

        Checks three locations:
        1. session.idb_path (from metadata).
        2. <binary_path>.i64 next to the source binary — the default
           save path used by IDA's save_database when no explicit
           IDA_MCP_IDB_PATH is set.
        3. Legacy component files alongside session.idb_path.

        If an IDB is found at a different path than session.idb_path, the
        session object is updated so subsequent tool calls use the
        correct path.

        Returns True if the IDB appeared within *timeout* seconds."""
        if not hasattr(session, "idb_path"):
            return False
        idb_path = getattr(session, "idb_path", None) or ""
        binary_path = getattr(session, "binary_path", None) or ""

        def _find_idb() -> str | None:
            # 1. idb_path from metadata
            if idb_path and os.path.isfile(idb_path):
                return idb_path
            # 2. Next to the source binary
            if binary_path:
                for suffix in (".i64", ".idb"):
                    candidate = binary_path + suffix
                    if os.path.isfile(candidate):
                        return candidate
            # 3. Legacy component-file layout
            if idb_path:
                idb_dir = os.path.dirname(idb_path)
                sid_prefix = f"SID_{session.session_id}"
                try:
                    for name in os.listdir(idb_dir or "."):
                        if name.startswith(sid_prefix) and (
                            name.endswith((".id0", ".nam"))
                        ):
                            # Absolute path, not the bare listdir entry: the
                            # callers below test os.path.isfile(existing) and
                            # store the result back into session.idb_path.
                            return os.path.join(idb_dir or ".", name)
                except OSError:
                    pass
            return None

        existing = _find_idb()
        if existing and existing != idb_path:
            # Fix up session metadata so tool calls target the right path
            if not idb_path or os.path.dirname(existing) != os.path.dirname(idb_path):
                try:
                    session.idb_path = existing if os.path.isfile(existing) else idb_path
                    if hasattr(self, "session_mgr"):
                        self.session_mgr.update_session(session.session_id, idb_path=session.idb_path)
                except Exception:
                    pass
        if existing:
            return True
        deadline = time.time() + timeout
        while time.time() < deadline:
            found = _find_idb()
            if found:
                if found != idb_path:
                    try:
                        session.idb_path = found if os.path.isfile(found) else idb_path
                        if hasattr(self, "session_mgr"):
                            self.session_mgr.update_session(session.session_id, idb_path=session.idb_path)
                    except Exception:
                        pass
                return True
            time.sleep(0.5)
            runtime = self.session_runtimes.get(session.session_id) if hasattr(self, "session_runtimes") else None
            if runtime and not self._runtime_alive(runtime):
                return False
        return bool(_find_idb())

    def _session_action_close(self, args: dict) -> dict:
        sid, sid_err = self._resolve_session_id(args)
        if sid_err:
            return sid_err
        if not sid:
            return make_error(
                MCPError.INVALID_ARGS,
                "session_id required (or have an active session)",
                hint="Provide session_id or create/switch to a session first.",
            )
        owned_err = self._require_owned_session_id(sid)
        if owned_err:
            return owned_err
        self._export_session_hypotheses_to_symbol_db(sid)
        self._forget_analysis_state(sid)
        self._cleanup_runtime(sid)
        closed = self.session_mgr.delete_session(sid)
        if (
            closed
            and self.current_session
            and self.current_session.session_id == sid
        ):
            self.current_session = None
        if closed:
            self._drop_sid_from_groups(sid)
        return {"ok": closed, "session_id": sid}

    def _session_target(self, args: dict) -> tuple[Any, dict | None]:
        """Resolve an explicit session target from ``idb``/``session_id`` args.

        Several agents can be multiplexed over one MCP connection (opencode
        subagents share the connection, and MCP carries no per-agent
        identity), so the "active session" default reflects whoever opened a
        binary last. Naming a session here steers the call at that session —
        and, subject to the ownership guard, makes it this connection's
        active session so later calls keep targeting it.
        """
        raw = str(args.get("idb") or args.get("session_id") or "").strip()
        if not raw:
            return self.current_session, None
        sid = _normalize_session_id(raw)
        if not sid:
            return None, make_error(
                MCPError.INVALID_ARGS, "Invalid session idb reference"
            )
        try:
            session = self.session_mgr.get_session(sid)
        except Exception:
            session = None
        if not session:
            return None, make_error(
                MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
            )
        ownership_error = self._ensure_client_owns_session(session)
        if ownership_error:
            return None, ownership_error
        self.current_session = session
        return session, None

    def _session_action_state(self, args: dict) -> dict:
        """Return the analysis state — binary identity, coverage, blackboard,
        knowledge graph, and next-action guidance (the `ida_session_state`
        operation)."""
        session, target_error = self._session_target(args)
        if target_error:
            return target_error
        if session is None:
            # No active session and no explicit target: an empty state payload
            # would mislead a caller into thinking a session is open.
            return make_error(
                MCPError.SESSION_NOT_FOUND,
                "No active session to report state for",
                hint="Create or switch to a session first, or pass session_id/idb to target one.",
            )
        try:
            state_value = self._build_state_payload()
            # Always wrap in a uniform envelope so callers can reliably
            # check `ok` and find the state under a known key.
            if isinstance(state_value, dict):
                state_value["safe_mode"] = self._safe_mode_active(
                    getattr(self.current_session, "session_id", None) or ""
                )
                state_value["analysis_complete"] = self._analysis_is_complete(
                    getattr(self.current_session, "session_id", None) or ""
                )
                report = self._session_ownership_report(
                    getattr(self.current_session, "session_id", None) or ""
                )
                for _k in (
                    "locked", "holder", "owner_id", "owner_pid",
                    "owner_alive", "idat_pid", "lease_age_seconds",
                ):
                    state_value[_k] = report.get(_k)
            return {"ok": True, "state": state_value}
        except Exception as e:
            return make_error(MCPError.IDA_ERROR, f"state failed: {e}")

    def _get_cached_coverage(self, sid: str) -> dict:
        """Coverage for *sid*, cached with a 30s TTL.

        The ``data/{action:functions}`` RPC is expensive on large binaries, so
        ``ida_session_state`` caches the result. The cache is per-instance,
        keyed by session id, and lock-guarded: the former module-level cache
        was keyed by ``id(self._execute_tool)`` — a freshly-allocated bound
        method on every access — so it never hit (re-running the RPC each
        call) while growing a new entry per call, and it served coverage
        computed for a different session when ids collided. ``data`` returns
        the compact text under ``functions`` and the structured records under
        ``items`` only when ``structured=True`` is requested, so this passes
        it and parses the text as a fallback for older IDA-side builds.
        """
        cache = getattr(self, "_session_state_cache", None)
        if not isinstance(cache, dict):
            self._session_state_cache = {}
            cache = self._session_state_cache
        lock = getattr(self, "_session_state_cache_lock", None)
        # ``threading.RLock`` is a factory function on some CPython builds,
        # so isinstance() against it is not portable; probe the protocol instead.
        if not (lock is not None and hasattr(lock, "acquire") and hasattr(lock, "release")):
            self._session_state_cache_lock = threading.RLock()
            lock = self._session_state_cache_lock
        now = time.time()
        with lock:
            cached = cache.get(sid)
            if cached and now - cached["_ts"] < _SESSION_STATE_CACHE_TTL:
                return cached["coverage"]
        try:
            funcs = self._execute_tool(
                "data", {"action": "functions", "count": 5000, "structured": True}
            )
            func_list = funcs.get("items") if isinstance(funcs, dict) else []
            if not func_list and isinstance(funcs, dict):
                # Older build without structured items: parse the compact
                # newline-joined text (fields: addr  size  xrefs=N  name).
                func_list = []
                for line in str(funcs.get("functions") or "").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split()
                    func_list.append(
                        {"addr": parts[0] if parts else "", "name": parts[-1] if parts else ""}
                    )
            total = len(func_list)
            named = sum(
                1 for f in func_list
                if not (str(f.get("name", "")).startswith("sub_")
                        or str(f.get("name", "")).startswith("j_")))
            coverage = {
                "total_functions": total,
                "named_functions": named,
                "unnamed_functions": total - named,
                "pct_named": round(named / total * 100, 1) if total else 0,
            }
        except Exception:
            coverage = {}
        with lock:
            cache[sid] = {"coverage": coverage, "_ts": time.time()}
            if len(cache) > 128:
                # Bound the cache against session churn; never evict the
                # just-written entry for the session being served.
                overflow = [s for s in cache if s != sid][:len(cache) - 128]
                for old_sid in overflow:
                    cache.pop(old_sid, None)
        return coverage

    def _build_state_payload(self):
        """Build the analysis-state payload for `ida_session_state`.

        Returns the state dict, or a narrative text string when a long
        blackboard narrative is available.
        """
        state: dict[str, Any] = {}

        # 1. Binary identity
        try:
            overview = self._execute_tool("idb", {"action": "overview"})
            meta = overview.get("meta", {}) if isinstance(overview, dict) else {}
            summary = overview.get("summary", {}) if isinstance(overview, dict) else {}
            arch_profile = overview.get("architecture_profile", {}) if isinstance(overview, dict) else {}
            is_firmware = bool(
                (overview.get("firmware_detected") if isinstance(overview, dict) else False)
                or (arch_profile.get("raw_binary_mode") if isinstance(arch_profile, dict) else False)
            )
            if not is_firmware:
                # Fallback heuristic for older/partial IDB metadata payloads.
                ft_info = meta.get("file_type_info") if isinstance(meta.get("file_type_info"), dict) else {}
                ft_name = str(meta.get("file_type_effective") or ft_info.get("effective") or meta.get("file_type") or "").strip().lower()
                ft_id = meta.get("file_type_id")
                try:
                    ft_num = int(ft_id) if ft_id is not None else None
                except Exception:
                    ft_num = None
                proc = str(meta.get("processor") or meta.get("arch") or "").strip().lower()
                imports = (
                    summary.get("imports")
                    if isinstance(summary, dict) and summary.get("imports") is not None
                    else meta.get("import_count", 0)
                )
                try:
                    imports = int(imports or 0)
                except Exception:
                    imports = 0
                is_firmware = bool(
                    ft_name in {"", "raw", "unknown", "bin", "binary", "obj"}
                    or ft_num in {0, 2, 17}
                    or (proc in ("arm", "mips", "ppc", "msp430", "avr", "xtensa") and imports == 0)
                )
            state["binary"] = {
                "name": meta.get("binary_path") or meta.get("filename") or meta.get("input_file", ""),
                "arch": meta.get("processor") or meta.get("arch", ""),
                "bits": meta.get("bitness") or meta.get("bits", 0),
                "size": meta.get("image_size") or meta.get("file_size", 0),
                "imports": summary.get("imports", 0),
                "is_firmware": is_firmware,
            }
            if is_firmware:
                state["binary"]["firmware"] = True
        except Exception:
            state["binary"] = {}
            is_firmware = False

        # 2. Coverage (cached with 30s TTL — expensive on large binaries)
        state["coverage"] = self._get_cached_coverage(
            getattr(self.current_session, "session_id", None) or ""
        )

        # 3. Blackboard summary
        try:
            bb = self._bb_store()
            if bb:
                stats = bb.stats()
                targets = bb.next_target(limit=5)
                hypotheses = bb.list(category="hypothesis", limit=5,
                                     include_resolved=False, include_contradicted=False)
                iocs = bb.list(category="ioc", limit=10, include_resolved=True)
                vulns = bb.list(category="vuln", limit=5, include_resolved=False)
                state["blackboard"] = {
                    "stats": stats,
                    "next_targets": targets,
                    "top_hypotheses": [
                        {"title": h["title"], "addr": h.get("addr"),
                         "confidence": h.get("confidence")}
                        for h in hypotheses
                    ],
                    "iocs": [
                        {"type": i.get("ioc_type"), "value": i.get("ioc_value"),
                         "addr": i.get("addr")}
                        for i in iocs
                    ],
                    "vulns": [
                        {"title": v["title"], "addr": v.get("addr"),
                         "confidence": v.get("confidence")}
                        for v in vulns
                    ],
                }
        except Exception:
            state["blackboard"] = {}

        # 4. Session info
        try:
            if self.session_mgr:
                active = getattr(self.session_mgr, "active_session_id", None)
                state["session"] = {"active_session_id": active}
        except Exception:
            state["session"] = {}

        # 5. KnowledgeGraph summary
        try:
            import importlib.util as _ilu
            _kg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", "stores", "knowledge_graph.py")
            _spec = _ilu.spec_from_file_location("_state_kg", _kg_path)
            _kgmod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_kgmod)
            bb_path = self._session_blackboard_path(session_obj=self.current_session) \
                if hasattr(self, "_session_blackboard_path") else None
            kg = _kgmod.KnowledgeGraph(bb_path) if bb_path else None
            if kg:
                state["knowledge_graph"] = kg.summary()
                # Open gaps
                gaps = kg.list_gaps(resolved=False)
                if gaps:
                    state["knowledge_graph"]["top_gaps"] = [
                        {"expected": g["expected"],
                         "candidates": g.get("candidates", [])[:2],
                         "priority": g.get("priority")}
                        for g in gaps[:5]
                    ]
                # Systems
                systems = kg.list_systems()
                if systems:
                    state["knowledge_graph"]["systems"] = [
                        {"name": s["name"],
                         "members": len(s.get("members", [])),
                         "coverage_pct": s.get("coverage_pct", 0)}
                        for s in systems[:8]
                    ]
        except Exception:
            pass

        # 6. Narrative — if a long blackboard narrative exists, return it as
        # plain text (with a compact JSON header) instead of the JSON dict.
        try:
            bb = self._bb_store()
            if bb:
                narratives = bb.list(category="narrative", limit=1,
                                     include_resolved=True)
                if narratives:
                    narrative_text = narratives[0].get("content", "")
                    if narrative_text and len(narrative_text) > 50:
                        import json as _json
                        header = _json.dumps({
                            "binary": state.get("binary", {}),
                            "coverage": state.get("coverage", {}),
                            "knowledge_graph": state.get("knowledge_graph", {}),
                        }, separators=(",", ":"))
                        return f"<!-- state:{header} -->\n\n{narrative_text}"
        except Exception:
            pass

        # 7. Actionable guidance based on current state
        actions = []
        bb_state = state.get("blackboard", {})
        cov = state.get("coverage", {})
        binary = state.get("binary", {})

        if binary.get("is_firmware"):
            actions.append("firmware_view(action='triage_snapshot')")

        next_targets = bb_state.get("next_targets", [])
        if next_targets:
            top = next_targets[0]
            top_addr = top.get("addr", "")
            top_title = top.get("title", top_addr)[:50]
            actions.append(f"code(action='smart_decompile', addrs='{top_addr}') — {top_title}")

        vulns = bb_state.get("vulns", [])
        if vulns:
            v_addr = vulns[0].get("addr", "")
            actions.append(f"llm_helpers(action='dangerous_pattern_explainer', addr='{v_addr}')")

        pct = cov.get("pct_named", 100)
        total = cov.get("total_functions", 0)
        if total > 20 and pct < 40:
            actions.append(f"blackboard(action='frontier', limit=10) — {pct}% named, {total} functions")

        if not actions:
            actions.append("idb(action='summary')")
            actions.append("data(action='imports')")

        state["_next_actions"] = actions
        return state

    def _bb_store(self):
        """Load BlackboardStore without IDA deps (stubbed IDA modules)."""
        try:
            import importlib.util
            import sys as _sys
            import types as _types
            path = os.path.join(SCRIPT_DIR, "..", "..", "ida_mcp", "tools", "blackboard.py")
            path = os.path.abspath(path)
            spec = importlib.util.spec_from_file_location("_res_bb", path)
            mod = importlib.util.module_from_spec(spec)
            mod.__dict__.update({"tool": lambda f: f, "idaread": lambda f: f,
                                  "idawrite": lambda f: f, "IDAError": Exception})
            _stubs = ["idaapi","idc","idautils","ida_funcs","ida_bytes","ida_segment",
                      "ida_name","ida_typeinf","ida_nalt","ida_hexrays","ida_frame",
                      "ida_struct","ida_lines"]
            _saved = {m: _sys.modules.get(m) for m in _stubs}
            for m in _stubs:
                if m not in _sys.modules:
                    _sys.modules[m] = _types.ModuleType(m)
            if not hasattr(_sys.modules["idaapi"], "BADADDR"):
                _sys.modules["idaapi"].BADADDR = 0xFFFFFFFFFFFFFFFF
            try:
                spec.loader.exec_module(mod)
            finally:
                for m, orig in _saved.items():
                    if orig is None:
                        _sys.modules.pop(m, None)
                    else:
                        _sys.modules[m] = orig
            bb_path = self._session_blackboard_path(session_obj=self.current_session) \
                if hasattr(self, "_session_blackboard_path") else None
            return mod.BlackboardStore(db_path=bb_path)
        except Exception:
            return None

    def _session_action_logs(self, args: dict) -> dict:
        """Return recent IDA log lines — reads the -L log file directly, no IDA RPC."""
        session = self.current_session
        if not session:
            return make_error(MCPError.SESSION_REQUIRED, "No active session.")
        runtime = self.session_runtimes.get(session.session_id) if hasattr(self, "session_runtimes") else None
        if not isinstance(runtime, dict):
            return make_error(MCPError.IDA_ERROR, "No runtime record for current session.")
        try:
            lines = int(args.get("lines") or args.get("tail") or 80)
        except Exception:
            lines = 80
        lines = max(1, min(lines, 500))
        # ida_log = IDA's -L log file (actual IDA output, including analysis progress)
        # stdout_log/stderr_log = IDA process stdout/stderr (empty in headless mode)
        ida_log = runtime.get("ida_log")
        stdout_log = runtime.get("stdout_log")
        stderr_log = runtime.get("stderr_log")
        if not stderr_log and stdout_log:
            err_guess = stdout_log.replace("ida_stdout_", "ida_stderr_")
            if err_guess != stdout_log:
                stderr_log = err_guess
        ida_text = self._tail_text_file(ida_log, tail_lines=lines) if ida_log else ""
        out_text = self._tail_text_file(stdout_log, tail_lines=lines) if stdout_log else ""
        err_text = self._tail_text_file(stderr_log, tail_lines=lines) if stderr_log else ""
        alive = False
        if runtime.get("process"):
            with contextlib.suppress(Exception):
                alive = runtime["process"].poll() is None
        return {
            "ok": True,
            "session_id": session.session_id,
            "ida_alive": alive,
            "ida_log": ida_log,
            "ida_log_tail": ida_text or "(empty)",
            "stdout_log": stdout_log,
            "stderr_log": stderr_log,
            "stdout_tail": out_text or "(empty)",
            "stderr_tail": err_text or "(empty)",
            "lines_requested": lines,
        }

    def _session_action_status(self, args: dict) -> dict:
        _target, target_error = self._session_target(args)
        if target_error:
            return target_error
        if self.current_session:
            fresh_session = self.session_mgr.get_session(self.current_session.session_id) or self.current_session
            result = fresh_session.to_dict()
            runtime = self.session_runtimes.get(fresh_session.session_id)
            result["is_running"] = bool(
                runtime
                and runtime.get("process")
                and runtime["process"].poll() is None
            )
            result["safe_mode"] = self._safe_mode_active(fresh_session.session_id)
            result["analysis_complete"] = self._analysis_is_complete(
                fresh_session.session_id
            )
            # A polling agent must never be stuck in safe mode because the
            # watcher missed the transition: confirm from a live runtime.
            self._maybe_resolve_analysis_state(fresh_session)
            result["safe_mode"] = self._safe_mode_active(fresh_session.session_id)
            result["analysis_complete"] = self._analysis_is_complete(
                fresh_session.session_id
            )
            bg_errors = getattr(self, "_background_load_errors", None)
            if isinstance(bg_errors, dict) and fresh_session.session_id in bg_errors:
                result["background_error"] = bg_errors[fresh_session.session_id]
            session_meta = getattr(fresh_session, "metadata", None) or {}
            if not isinstance(session_meta, dict):
                session_meta = {}

            # --- Honest analysis state, sourced from IDA's own auto_is_ok()
            # via idb(action='state'), NOT from the host's idle-indexing worker
            # (which is an orthogonal process whose state was previously
            # misreported as "analysis_ready"). The watchdog thread keeps a
            # per-session verdict in metadata; we also take a fresh sample
            # when the runtime is alive so a status call is never stale. ---
            sid = fresh_session.session_id
            is_running = bool(result.get("is_running", False))
            fresh_state = self._query_ida_state(sid) if is_running else None
            wd_is_ok = bool(session_meta.get("analysis_is_ok"))
            wd_verdict = str(session_meta.get("analysis_state") or "").strip().lower()
            if isinstance(fresh_state, dict):
                analysis = fresh_state.get("analysis") or {}
                inventory = fresh_state.get("inventory") or {}
                result["analysis_ready"] = bool(analysis.get("is_ok"))
                result["analysis_active"] = bool(analysis.get("active"))
                fqty = inventory.get("functions_qty")
                try:
                    result["analysis_functions_qty"] = (
                        int(fqty) if fqty is not None else None
                    )
                except Exception:
                    result["analysis_functions_qty"] = None
            else:
                # Runtime gone or RPC failed — fall back to the watchdog's
                # last known verdict so status still reflects history.
                result["analysis_ready"] = wd_is_ok
            if wd_verdict:
                result["analysis_state"] = wd_verdict
            try:
                stall = session_meta.get("analysis_stall_seconds")
                if stall is not None:
                    result["analysis_stall_seconds"] = round(float(stall), 1)
            except Exception:
                pass
            if result.get("analysis_state") == "stalled":
                result["analysis_stalled"] = True

            # --- Host-side structural-index warmup is a SEPARATE concern
            # from IDA analysis. Report it under its own name so it can no
            # longer be mistaken for analysis readiness. ---
            indexing_state = str(session_meta.get("indexing_state") or "").strip().lower()
            hot_indexed_count = 0
            try:
                hot_indexed_count = int(session_meta.get("hot_indexed_count") or 0)
            except Exception:
                hot_indexed_count = 0
            if indexing_state:
                result["indexing_state"] = indexing_state
            if session_meta.get("indexing_mode"):
                result["indexing_mode"] = session_meta.get("indexing_mode")
            if hot_indexed_count > 0:
                result["hot_indexed_count"] = hot_indexed_count

            # Surface the most recent apply transcript (what the black-box
            # startup actually did) so a caller can see it after the fact.
            last_apply = session_meta.get("last_apply_steps")
            if isinstance(last_apply, list) and last_apply:
                result["apply_steps"] = last_apply
                result["steps_done"] = len(last_apply)
            live_progress = session_meta.get("apply_progress")
            if isinstance(live_progress, dict) and live_progress:
                result["apply_in_progress"] = live_progress
            # Inject recent blackboard into session status so LLM sees it by default
            try:
                import importlib.util
                # SCRIPT_DIR is host/server/; blackboard.py is at ida_pro_mcp/ida_mcp/tools/.
                bb_path = os.path.join(SCRIPT_DIR, "..", "..", "ida_mcp", "tools", "blackboard.py")
                bb_path = os.path.abspath(bb_path)
                spec = importlib.util.spec_from_file_location("_host_blackboard_status", bb_path)
                mod = importlib.util.module_from_spec(spec)
                mod.__dict__["tool"] = lambda f: f
                mod.__dict__["idaread"] = lambda f: f
                mod.__dict__["idawrite"] = lambda f: f
                mod.__dict__["IDAError"] = Exception
                spec.loader.exec_module(mod)
                bb_p = self._session_blackboard_path(session_obj=self.current_session) if self.current_session else None
                store = mod.BlackboardStore(db_path=bb_p)
                entries = store.list(limit=8)
                if entries:
                    result["working_memory"] = entries
                    result["working_memory_count"] = len(entries)
            except Exception:
                pass
        else:
            result = None
        return {
            "ok": True,
            "session": result,
            # Use the locked manager method, not direct dict access (the
            # list action documents the same convention).
            "total_sessions": self.session_mgr.count(),
        }

    def _session_action_kill(self, args: dict) -> dict:
        """
        Forcefully terminate the IDA process for the active (or specified) session.
        Tries SIGTERM, then SIGKILL after grace_sec. Use when a tool call is
        stuck and you want to recover without restarting the bridge.
        """
        sid, sid_err = self._resolve_session_id(args)
        if sid_err:
            return sid_err
        if not sid and self.current_session:
            sid = self.current_session.session_id
        if not sid:
            return make_error(
                MCPError.INVALID_ARGS,
                "session_id required (or create/switch to a session first)",
            )
        owned_err = self._require_owned_session_id(sid)
        if owned_err:
            return owned_err
        runtime = self.session_runtimes.get(sid)
        if not isinstance(runtime, dict):
            return make_error(
                MCPError.SESSION_NOT_FOUND,
                f"No runtime for session {sid}",
            )
        try:
            grace_sec = float((args or {}).get("grace_sec") or 3.0)
        except Exception:
            grace_sec = 3.0
        grace_sec = max(0.5, min(grace_sec, 30.0))
        # NOTE: analysis/safe-mode state is deliberately NOT forgotten here.
        # Killing the runtime mid-build must not lift safe mode — the
        # watcher detects the dead runtime and records the interruption
        # (background_error) while keeping the half-analyzed IDB gated.
        result = self._kill_ida_process(runtime, grace_sec=grace_sec)
        result["session_id"] = sid
        snapshot = self._collect_ida_state_snapshot(
            runtime=runtime,
            tail_lines=5,
            include_process_stats=False,
        )
        result["post_kill_state"] = snapshot
        with contextlib.suppress(Exception):
            log_rpc(
                f"session.kill sid={sid} signaled={result.get('signaled')} "
                f"terminated={result.get('terminated')} exit={result.get('exit_code')}"
            )
        # Drop stale runtime metadata so the next tool call can respawn cleanly.
        with contextlib.suppress(Exception):
            self._cleanup_runtime(sid)
        if not result.get("terminated"):
            # The process outlived SIGTERM and SIGKILL, so it may still hold
            # the IDB lock. Reporting ok here would tell the caller the
            # session is safe to reopen when it is not.
            return make_error(
                MCPError.IDA_ERROR,
                f"Failed to terminate the IDA process for session '{sid}'.",
                hint=(
                    "The process may still hold the IDB lock. Check the "
                    "reported pid and terminate it manually before reopening."
                ),
                details=result,
            )
        return {"ok": True, **result}

    def _session_action_rebuild(self, args: dict) -> dict:
        sid, sid_err = self._resolve_session_id(args)
        if sid_err:
            return sid_err
        if not sid:
            return make_error(
                MCPError.INVALID_ARGS,
                "session_id required",
                hint="Provide session_id or create/switch to a session first.",
            )
        owned_err = self._require_owned_session_id(sid)
        if owned_err:
            return owned_err
        session = self.session_mgr.get_session(sid)
        if not session:
            return make_error(
                MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
            )

        analysis_options = {}
        for key in (
            "processor",
            "flags",
            "loader",
            "value",
            "bitness",
            "endian",
            "reanalyze",
        ):
            if key in args:
                analysis_options[key] = args.get(key)
        if not analysis_options:
            analysis_options = None

        self._cleanup_runtime(sid)
        if os.path.exists(session.idb_path):
            try:
                os.remove(session.idb_path)
            except Exception as e:
                return make_error(
                    MCPError.FILE_LOCKED, f"Failed to remove IDB: {e}"
                )

        # Update the REAL session via manager, not the deepcopy
        self.session_mgr.update_session(
            sid, analysis_options=analysis_options or {}, analysis_applied=False
        )
        # Refetch so we have the canonical object for _start_server
        session = self.session_mgr.get_session(sid)
        if session is None:
            return make_error(
                MCPError.SESSION_NOT_FOUND,
                f"Session '{sid}' disappeared during rebuild",
            )

        start_res = self._start_server(session)
        if "error" in start_res:
            return start_res
        self.current_session = session
        # A rebuild deletes the IDB and re-runs auto-analysis: the session
        # re-enters safe mode and the watcher lifts it when the rebuild
        # completes. Rebuild is another route into pending, so it can never
        # be used to escape the gate.
        self._mark_analysis_pending(session)
        return {
            "ok": True,
            "session_id": session.session_id,
            "idb_path": session.idb_path,
            "safe_mode": True,
            "analysis_complete": False,
            "current_options": start_res.get("current_options"),
            "bootstrap_report": start_res.get("bootstrap_report"),
        }

    def _session_action_update(self, args: dict) -> dict:
        sid, sid_err = self._resolve_session_id(args)
        if sid_err:
            return sid_err
        if not sid:
            return make_error(MCPError.INVALID_ARGS, "session_id required")
        update_kwargs = {
            k: v for k, v in args.items() if k not in ("action", "session_id")
        }
        if "tags" in update_kwargs and isinstance(update_kwargs["tags"], str):
            update_kwargs["tags"] = [
                t.strip() for t in update_kwargs["tags"].split(",") if t.strip()
            ]
        if "notes" in update_kwargs:
            update_kwargs["notes"] = str(update_kwargs.get("notes", ""))[
                :MAX_NOTE_LEN
            ]
        if "auto_name" in update_kwargs:
            update_kwargs["auto_name"] = str(
                update_kwargs.get("auto_name", "")
            ).strip()[:MAX_NAME_LEN]
        result = self.session_mgr.update_session(sid, **update_kwargs)
        if result is None:
            return make_error(
                MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
            )
        return {
            "ok": True,
            "session": result.to_dict(),
        }

    # rename, duplicate, archive, unarchive, tag, untag, find_by_tag, add_note,
    # clear_notes, search_notes, recent, oldest, suggest_strategy,
    # get_activity_log, notebook_append/read/section, list_hypotheses,
    # dashboard, get_phase, advance_phase, link_session,
    # cross_reference_sessions, list_snapshots: declarative — see
    # _SESSION_ACTIONS + _run_session_spec.

    def _session_action_export_session(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        exported_hypotheses = self._export_session_hypotheses_to_symbol_db(sid)
        result = self.session_mgr.export_session(sid)
        if result is None:
            return make_error(
                MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
            )
        return {"ok": True, "exported": result, "exported_hypotheses": int(exported_hypotheses)}

    def _session_action_import_session(self, args: dict) -> dict:
        data = args.get("data")
        if not data or not isinstance(data, dict):
            return make_error(MCPError.INVALID_ARGS, "data dict required")
        data = dict(data)
        # Sanitize agent-supplied ida_args through the same CLI guard used by
        # create/create_background: it rejects server-reserved flags (-S/-L/-o),
        # null bytes, control characters and empty entries before the values
        # could ever be stitched into an idat Popen launch on the next tool
        # call. binary_path/idb_path/analysis_options are validated downstream
        # when the imported session is opened.
        if "ida_args" in data:
            normalize = getattr(self, "_normalize_ida_args", None)
            if callable(normalize):
                try:
                    data["ida_args"] = normalize(data.get("ida_args"))
                except ValueError as e:
                    return make_error(MCPError.INVALID_ARGS, str(e))
        result = self.session_mgr.import_session(data)
        return {"ok": True, "session": result.to_dict()}

    def _session_action_cleanup_stale(self, args: dict) -> dict:
        max_age = _bounded_int(
            args.get("max_age_days", 30), 30, min_value=1, max_value=3650
        )
        deleted = self.session_mgr.cleanup_stale(
            max_age_days=max_age,
            runtime_alive=lambda sid: bool(
                self.session_runtimes.get(sid) and self._runtime_alive(self.session_runtimes.get(sid))
            ),
        )

        # Also prune sessions whose binary path no longer exists — those
        # are "stale-by-evidence" rather than age-stale, and they're usually
        # the bulk of clutter when /tmp scratch paths get reaped.
        also_pruned_orphans: list[str] = []
        if bool(args.get("prune_orphans", True)):
            sessions = self.session_mgr.list_sessions(offset=0, limit=10_000).get("sessions", [])
            for raw in sessions:
                sid = _normalize_session_id(raw.get("session_id") or "")
                if not sid:
                    sid = raw.get("session_id") or ""
                    if isinstance(sid, str) and re.fullmatch(r"[A-Za-z0-9]+", sid):
                        sid = sid.upper()
                    else:
                        continue
                # Never delete another client's session (multiplexed
                # connections enforce subagent isolation) — only sessions this
                # connection owns qualify for orphan pruning.
                if self._require_owned_session_id(sid):
                    continue
                binary = raw.get("binary_path") or ""
                idb = raw.get("idb_path") or ""
                bin_missing = bool(binary) and not os.path.isfile(binary)
                idb_missing = bool(idb) and not os.path.isfile(idb)
                # Only prune when both reference paths have gone; we don't
                # want to nuke a session that's mid-save. Tear down any
                # runtime first so we don't orphan a live idat whose scratch
                # paths were reaped.
                if bin_missing and idb_missing:
                    with contextlib.suppress(Exception):
                        self._cleanup_runtime(sid)
                    if self.session_mgr.delete_session(sid):
                        also_pruned_orphans.append(sid)
                        self._drop_sid_from_groups(sid)
        # Keep _session_groups consistent with the age-stale deletions too.
        for sid in deleted:
            self._drop_sid_from_groups(sid)

        return {
            "ok": True,
            "deleted_sids": deleted,
            "orphan_sids": also_pruned_orphans,
            "count": len(deleted),
            "deleted_count": len(deleted),
            "orphan_count": len(also_pruned_orphans),
        }

    def _session_action_idle_purge(self, args: dict) -> dict:
        """Close sessions (and their live IDA runtimes) that haven't been
        touched within ``idle_seconds``. ``idle_seconds`` is required and
        must be a positive integer; pass 1 to mean "close anything not
        used in the last second" (effectively close-all-else).

        Sessions tracked here are real entries in session_mgr whose
        ``last_accessed`` timestamp is older than ``now - idle_seconds``. We
        only act on sessions that ALSO have a live runtime attached —
        pre-existing cleanup_stale handles db-only stale rows.

        Args:
            idle_seconds: int (required) — age threshold in seconds.
            prune_orphans: bool (default True) — also drop sessions whose
                binary + idb paths no longer exist on disk.

        Returns:
            ok envelope with closed_sids / orphan_sids lists and counts,
            matching the existing cleanup_stale shape.
        """
        raw_age = args.get("idle_seconds")
        if raw_age is None:
            return make_error(
                MCPError.INVALID_ARGS,
                "idle_seconds is required",
                details={"hint": "Pass an integer number of seconds, e.g. session(action='idle_purge', idle_seconds=1800)."},
            )
        try:
            idle_seconds = int(raw_age)
        except (TypeError, ValueError):
            return make_error(
                MCPError.INVALID_ARGS,
                "idle_seconds must be an integer",
                details={"got": str(raw_age), "type": type(raw_age).__name__},
            )
        if idle_seconds <= 0:
            return make_error(
                MCPError.INVALID_ARGS,
                "idle_seconds must be a positive integer",
                details={"got": idle_seconds},
            )

        prune_orphans = bool(args.get("prune_orphans", True))

        # ``last_accessed`` is stored as ISO 8601 via Session.to_dict /
        # Session.update_access; parse it to epoch so we don't fight
        # the timezone layer. Unknown / unparseable timestamps are
        # treated as "fresh" and skipped.
        now_epoch = datetime.now().timestamp()
        cutoff_epoch = now_epoch - idle_seconds

        closed_sids: list[str] = []
        skipped_sids: list[str] = []
        # Snapshot first so we don't mutate sessions we are iterating.
        snapshot = self.session_mgr.list_sessions(offset=0, limit=10_000).get("sessions", [])
        for raw in snapshot:
            sid = _normalize_session_id(raw.get("session_id") or "")
            if not sid:
                continue
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                skipped_sids.append(sid)
                continue
            last_accessed = raw.get("last_accessed") or raw.get("last_used")
            if not last_accessed:
                # Unknown liveness — leave it alone so a brand-new session
                # doesn't get killed before its first touch.
                skipped_sids.append(sid)
                continue
            try:
                parsed = datetime.fromisoformat(last_accessed.replace("Z", "+00:00"))
                last_used_epoch = parsed.timestamp()
            except Exception:
                skipped_sids.append(sid)
                continue
            if last_used_epoch > cutoff_epoch:
                continue
            # Only kill live sessions + their runtimes. Skipping the no-
            # runtime path here avoids racing with cleanup_stale, which is
            # the canonical owner of stale-metadata pruning.
            has_runtime = (
                hasattr(self, "session_runtimes")
                and isinstance(self.session_runtimes, dict)
                and sid in self.session_runtimes
            )
            if not has_runtime:
                skipped_sids.append(sid)
                continue
            with contextlib.suppress(Exception):
                self._export_session_hypotheses_to_symbol_db(sid)
            try:
                self._cleanup_runtime(sid)
            except Exception as e:
                return make_error(
                    MCPError.IDA_ERROR,
                    f"Failed to clean up runtime for session {sid}",
                    details={"session_id": sid, "exception": type(e).__name__, "message": str(e)},
                )
            deleted = self.session_mgr.delete_session(sid)
            if deleted:
                if (
                    self.current_session
                    and self.current_session.session_id == sid
                ):
                    self.current_session = None
                closed_sids.append(sid)

        orphan_sids: list[str] = []
        if prune_orphans:
            snapshot2 = self.session_mgr.list_sessions(offset=0, limit=10_000).get("sessions", [])
            for raw in snapshot2:
                sid = _normalize_session_id(raw.get("session_id") or "")
                if not sid:
                    continue
                # Same ownership rule as the closed loop above.
                if self._require_owned_session_id(sid):
                    continue
                binary = raw.get("binary_path") or ""
                idb = raw.get("idb_path") or ""
                bin_missing = bool(binary) and not os.path.isfile(binary)
                idb_missing = bool(idb) and not os.path.isfile(idb)
                if bin_missing and idb_missing:
                    try:
                        with contextlib.suppress(Exception):
                            self._cleanup_runtime(sid)
                        if self.session_mgr.delete_session(sid):
                            orphan_sids.append(sid)
                            self._drop_sid_from_groups(sid)
                    except Exception:
                        continue
        # Keep _session_groups consistent with the closed sessions too.
        for sid in closed_sids:
            self._drop_sid_from_groups(sid)

        return {
            "ok": True,
            "closed_sids": closed_sids,
            "orphan_sids": orphan_sids,
            "skipped_sids": skipped_sids,
            "count": len(closed_sids),
            "closed_count": len(closed_sids),
            "orphan_count": len(orphan_sids),
            "skipped_count": len(skipped_sids),
            "idle_seconds": idle_seconds,
        }

    def _session_action_stats(self, args: dict) -> dict:
        return {"ok": True, "stats": self.session_mgr.get_stats()}

    def _session_action_narrative(self, args: dict) -> dict:
        """Return a structured analysis narrative — chronological log of tool calls and key findings."""
        limit = int(args.get("limit", 50) or 50)
        limit = max(1, min(limit, 200))
        log = list(self._activity_log)[-limit:] if hasattr(self, "_activity_log") else []
        turns = []
        for i, entry in enumerate(log):
            tool = entry.get("tool", "")
            action = entry.get("action", "")
            addrs = entry.get("addresses", [])
            topic = entry.get("topic")
            target = entry.get("target")
            ts = entry.get("ts", "")
            turn = {
                "turn": i + 1,
                "ts": ts,
                "tool": tool,
                "action": action,
            }
            if addrs:
                turn["addresses"] = addrs
            if topic:
                turn["topic"] = topic
            if target:
                turn["target"] = target
            turns.append(turn)
        # Session summary
        session_info = {}
        if self.current_session:
            session_info = {
                "session_id": self.current_session.session_id,
                "binary": getattr(self.current_session, "binary_path", ""),
                "created": getattr(self.current_session, "created_at", ""),
            }
        return {
            "ok": True,
            "session": session_info,
            "turn_count": len(turns),
            "turns": turns,
            "hint": "This is the chronological analysis narrative. Use it to maintain context across turns.",
        }

    def _session_action_validate(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        result = self.session_mgr.validate_session(sid)
        if result is None:
            return make_error(
                MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
            )
        return {"ok": True, "validation": result}

    def _session_action_bulk_delete(self, args: dict) -> dict:
        sids = args.get("session_ids", [])
        if not sids:
            return make_error(
                MCPError.INVALID_ARGS, "session_ids list required"
            )
        if not isinstance(sids, list):
            return make_error(
                MCPError.INVALID_ARGS, "session_ids must be a list"
            )
        cleaned_sids = []
        for raw_sid in sids[:MAX_BATCH_CALLS]:
            sid = _normalize_session_id(raw_sid)
            if not sid:
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"Invalid session_id in list: {raw_sid}",
                )
            owned_err = self._require_owned_session_id(sid)
            if owned_err:
                return owned_err
            cleaned_sids.append(sid)
        # Tear down live IDA runtimes before deleting metadata.
        for sid in cleaned_sids:
            with contextlib.suppress(Exception):
                self._cleanup_runtime(sid)
        results = self.session_mgr.bulk_delete(cleaned_sids)
        # Clear current session if it was deleted
        if (
            self.current_session
            and self.current_session.session_id in cleaned_sids
        ):
            self.current_session = None
        # Keep multi-session groups consistent with the deletions.
        for sid in cleaned_sids:
            self._drop_sid_from_groups(sid)
        return {"ok": True, "results": results}

    def _session_action_bulk_tag(self, args: dict) -> dict:
        sids = args.get("session_ids", [])
        tag = args.get("tag")
        if not sids:
            return make_error(
                MCPError.INVALID_ARGS, "session_ids list required"
            )
        if not tag:
            return make_error(MCPError.INVALID_ARGS, "tag required")
        if not isinstance(sids, list):
            return make_error(
                MCPError.INVALID_ARGS, "session_ids must be a list"
            )
        cleaned_sids = []
        for raw_sid in sids[:MAX_BATCH_CALLS]:
            sid = _normalize_session_id(raw_sid)
            if not sid:
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"Invalid session_id in list: {raw_sid}",
                )
            cleaned_sids.append(sid)
        tag = str(tag).strip()[:MAX_TAG_LEN]
        if not tag:
            return make_error(MCPError.INVALID_ARGS, "tag required")
        results = self.session_mgr.bulk_tag(cleaned_sids, tag)
        return {"ok": True, "results": results}

    def _session_action_snapshot(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        snapshot_res = self.session_mgr.snapshot_session(sid)
        if snapshot_res is None:
            return make_error(
                MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
            )
        return {"ok": True, "session_id": sid, "snapshot_id": snapshot_res.get("snapshot_id"), "message": snapshot_res.get("message", "")}

    def _session_action_restore_snapshot(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        snapshot_id = args.get("snapshot_id")
        if not snapshot_id:
            return make_error(MCPError.INVALID_ARGS, "snapshot_id required")
        if not self.session_mgr.session_exists(sid):
            return make_error(
                MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
            )
        result = self.session_mgr.restore_snapshot(sid, snapshot_id)
        if result is None:
            return make_error(
                MCPError.NOT_FOUND,
                f"Snapshot '{snapshot_id}' not found for session '{sid}'",
            )
        return {"ok": True, "session": result.to_dict()}

    def _session_action_merge(self, args: dict) -> dict:
        sid1 = _normalize_session_id(
            args.get("session_id") or args.get("target_id")
        )
        sid2 = _normalize_session_id(args.get("source_id"))
        if not sid1 or not sid2:
            return make_error(
                MCPError.INVALID_ARGS,
                "session_id (or target_id) and source_id required",
            )
        result = self.session_mgr.merge_sessions(sid1, sid2)
        if result is None:
            return make_error(
                MCPError.SESSION_NOT_FOUND, "One or both sessions not found"
            )
        return {"ok": True, "session": result.to_dict()}

    def _session_action_rate_skill(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        skill_id = str(args.get("skill_id") or "").strip()
        if not skill_id:
            return make_error(MCPError.INVALID_ARGS, "skill_id required")
        reward = args.get("reward")
        try:
            reward_f = float(reward)
        except (TypeError, ValueError):
            return make_error(MCPError.INVALID_ARGS, "reward must be a number")
        return self.session_mgr.rate_skill(sid, skill_id=skill_id, reward=reward_f)

    def _session_action_list_skills(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        min_q = args.get("min_q", 0.0)
        try:
            min_q = float(min_q)
        except (TypeError, ValueError):
            return make_error(MCPError.INVALID_ARGS, "min_q must be a number")
        include_global = _coerce_bool(args.get("global_skills"), True)
        return self.session_mgr.list_skills(
            sid,
            min_q=min_q,
            global_skills=include_global,
        )

    def _session_action_suggest_triage(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        context = args.get("context")
        if context is not None:
            context = str(context)
        limit = args.get("limit")
        if limit is not None:
            try:
                limit = int(limit)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "limit must be an integer")
        else:
            limit = 5
        return self.session_mgr.suggest_triage(sid, context=context, limit=limit)

    def _session_action_suggest_strategy(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        context = args.get("context")
        if context is not None:
            context = str(context)
        return self.session_mgr.suggest_strategy(sid, context=context)

    def _session_action_get_phase(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        return self.session_mgr.get_phase(sid)

    def _session_action_dashboard(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        return self.session_mgr.dashboard(sid)

    def _session_action_suggest_analogy(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        library_idbs = args.get("library_idbs")
        if library_idbs is not None:
            if not isinstance(library_idbs, list):
                return make_error(MCPError.INVALID_ARGS, "library_idbs must be a list of strings")
            library_idbs = [str(x) for x in library_idbs]

        threshold_cosine = args.get("threshold_cosine", 0.85)
        try:
            threshold_cosine = float(threshold_cosine)
        except (TypeError, ValueError):
            return make_error(MCPError.INVALID_ARGS, "threshold_cosine must be a float")

        threshold_structural = args.get("threshold_structural", 0.70)
        try:
            threshold_structural = float(threshold_structural)
        except (TypeError, ValueError):
            return make_error(MCPError.INVALID_ARGS, "threshold_structural must be a float")

        limit = args.get("limit")
        if limit is not None:
            try:
                limit = int(limit)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "limit must be an integer")
        else:
            limit = 10

        return self.session_mgr.suggest_analogy(
            sid,
            library_idbs=library_idbs,
            threshold_cosine=threshold_cosine,
            threshold_structural=threshold_structural,
            limit=limit,
        )

    def _session_action_apply_analogy(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        mappings = args.get("mappings")
        if not mappings:
            return make_error(MCPError.INVALID_ARGS, "mappings list required")
        if not isinstance(mappings, list):
            return make_error(MCPError.INVALID_ARGS, "mappings must be a list of mapping objects")

        session = self.session_mgr.get_session(sid)
        if not session or not session.idb_path:
            return make_error(
                MCPError.INVALID_ARGS,
                f"Session {sid} has no active IDB path associated with it.",
            )
        ip = session.idb_path

        results = []
        for item in mappings:
            if not isinstance(item, dict):
                results.append({"ok": False, "error": "Mapping entry must be a dictionary"})
                continue
            addr = item.get("addr")
            name = item.get("name")
            comment = item.get("comment")

            if not addr:
                results.append({"ok": False, "error": "Mapping entry requires 'addr'"})
                continue

            mapping_res = {"addr": addr, "rename": None, "comment": None}
            if name:
                rename_res = self.call_tool("modify", ip, action="rename", addr=addr, value=name)
                mapping_res["rename"] = rename_res
            if comment:
                comment_res = self.call_tool(
                    "modify",
                    ip,
                    action="comment",
                    addr=addr,
                    value=comment,
                    comment_type="repeatable",
                )
                mapping_res["comment"] = comment_res
            results.append(mapping_res)

        return {
            "ok": True,
            "session_id": sid,
            "applied": len(results),
            "results": results,
        }

    def _session_action_log_activity(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        tool = str(args.get("tool") or "").strip()
        tool_action = str(args.get("tool_action") or args.get("activity_action") or args.get("activity") or "").strip()
        if not tool_action:
            tool_action = str(args.get("action_name") or args.get("name") or "").strip()
        if not tool_action:
            tool_action = str(args.get("log_action") or "").strip()
        if not tool_action:
            tool_action = str(args.get("event") or "").strip()
        # Preferred field name is 'activity_action', but keep compatibility.
        if not tool:
            return make_error(MCPError.INVALID_ARGS, "tool required")
        if not tool_action:
            return make_error(MCPError.INVALID_ARGS, "activity_action required")
        result = str(args.get("result") or "")
        return self.session_mgr.log_activity(sid, tool=tool, action=tool_action, result=result)

    def _session_action_track_hypothesis(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        statement = str(args.get("statement") or "").strip()
        if not statement:
            return make_error(MCPError.INVALID_ARGS, "statement required")
        evidence_for = args.get("evidence_for")
        if isinstance(evidence_for, str):
            evidence_for = parse_str_list(evidence_for)
        evidence_against = args.get("evidence_against")
        if isinstance(evidence_against, str):
            evidence_against = parse_str_list(evidence_against)
        confidence = args.get("confidence", 0.5)
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            return make_error(MCPError.INVALID_ARGS, "confidence must be a number")
        return self.session_mgr.track_hypothesis(
            sid,
            statement=statement,
            evidence_for=evidence_for,
            evidence_against=evidence_against,
            confidence=confidence,
        )

    def _session_action_confirm_hypothesis(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        hid = str(args.get("hypothesis_id") or args.get("id") or "").strip()
        if not hid:
            return make_error(MCPError.INVALID_ARGS, "hypothesis_id required")
        evidence = args.get("evidence")
        if isinstance(evidence, str):
            evidence = parse_str_list(evidence)
        return self.session_mgr.confirm_hypothesis(sid, hid=hid, evidence=evidence)

    def _session_action_refute_hypothesis(self, args: dict) -> dict:
        sid, sid_err = self._require_session_sid(args)
        if sid_err:
            return sid_err
        hid = str(args.get("hypothesis_id") or args.get("id") or "").strip()
        if not hid:
            return make_error(MCPError.INVALID_ARGS, "hypothesis_id required")
        reason = str(args.get("reason") or "").strip()
        if not reason:
            return make_error(MCPError.INVALID_ARGS, "reason required")
        evidence = args.get("evidence")
        if isinstance(evidence, str):
            evidence = parse_str_list(evidence)
        return self.session_mgr.refute_hypothesis(
            sid,
            hid=hid,
            reason=reason,
            evidence=evidence,
        )

    def _session_action_macro_set(self, args: dict) -> dict:
        macro_name = self._normalize_macro_name(
            args.get("name") or args.get("macro")
        )
        if not macro_name:
            return make_error(
                MCPError.INVALID_ARGS, "name required for macro_set"
            )
        macro_payload = args.get("data")
        if macro_payload is None:
            macro_payload = args.get("macro_data")
        if macro_payload is None:
            macro_payload = {
                k: v
                for k, v in args.items()
                if k
                not in (
                    "action",
                    "name",
                    "macro",
                    "data",
                    "macro_data",
                    "run_action",
                )
            }
        if not isinstance(macro_payload, dict):
            return make_error(
                MCPError.INVALID_ARGS, "macro payload must be an object"
            )
        macro_key = macro_name.lower()
        self._session_macros[macro_key] = {
            "name": macro_name,
            "data": macro_payload,
            "updated_at": datetime.now().isoformat(timespec="seconds"),
        }
        self._save_session_macros()
        return {
            "ok": True,
            "action": "macro_set",
            "name": macro_name,
            "data": macro_payload,
        }

    def _session_action_macro_get(self, args: dict) -> dict:
        macro_name = self._normalize_macro_name(
            args.get("name") or args.get("macro")
        )
        if not macro_name:
            return make_error(
                MCPError.INVALID_ARGS, "name required for macro_get"
            )
        entry = self._session_macros.get(macro_name.lower())
        if not entry:
            return make_error(
                MCPError.FILE_NOT_FOUND, f"Macro '{macro_name}' not found"
            )
        return {"ok": True, "action": "macro_get", **entry}

    def _session_action_macro_list(self, args: dict) -> dict:
        macros = sorted(
            [
                {
                    "name": entry.get("name") or key,
                    "updated_at": entry.get("updated_at"),
                    "keys": sorted((entry.get("data") or {}).keys())[:32],
                }
                for key, entry in self._session_macros.items()
                if isinstance(entry, dict)
            ],
            key=lambda m: str(m.get("name", "")).lower(),
        )
        return {
            "ok": True,
            "action": "macro_list",
            "macros": macros,
            "count": len(macros),
        }

    def _session_action_macro_delete(self, args: dict) -> dict:
        macro_name = self._normalize_macro_name(
            args.get("name") or args.get("macro")
        )
        if not macro_name:
            return make_error(
                MCPError.INVALID_ARGS, "name required for macro_delete"
            )
        removed = self._session_macros.pop(macro_name.lower(), None)
        if removed is None:
            return make_error(
                MCPError.FILE_NOT_FOUND, f"Macro '{macro_name}' not found"
            )
        self._save_session_macros()
        return {"ok": True, "action": "macro_delete", "name": macro_name}

    def _session_action_macro_run(self, args: dict) -> dict:
        macro_name = self._normalize_macro_name(
            args.get("name") or args.get("macro")
        )
        if not macro_name:
            return make_error(
                MCPError.INVALID_ARGS, "name required for macro_run"
            )
        entry = self._session_macros.get(macro_name.lower())
        if not entry:
            return make_error(
                MCPError.FILE_NOT_FOUND, f"Macro '{macro_name}' not found"
            )
        base_args = dict(entry.get("data") or {})
        # Check if this is a workflow (sequence of calls)
        calls = base_args.get("calls")
        if isinstance(calls, list) and calls:
            return self._run_workflow_sequence(macro_name, calls, args)
        # Single-call macro with $param substitution
        run_action = (
            args.get("run_action") or base_args.get("action") or "create"
        )
        if not isinstance(run_action, str) or not run_action.strip():
            return make_error(
                MCPError.INVALID_ARGS, "invalid run_action for macro_run"
            )
        run_action = run_action.strip()
        if run_action.startswith("macro_"):
            return make_error(
                MCPError.INVALID_ARGS,
                "macro_run cannot execute macro_* actions",
            )
        # Build run_args: start from macro data, overlay caller args
        run_args = dict(base_args)
        # Collect $param substitutions from caller
        params = {}
        for k, v in args.items():
            if k in ("action", "name", "macro", "run_action"):
                continue
            run_args[k] = v
            if k.startswith("$") or isinstance(v, (str, int, float, bool)):
                params[k] = v
        run_args["action"] = run_action
        # Apply $param substitution to string values
        if params:
            run_args = _substitute_params(run_args, params)
        # Dispatch to any tool (not just session)
        tool_name = base_args.get("_tool") or "session"
        run_result = self._execute_tool(tool_name, run_args)
        if isinstance(run_result, dict) and not is_error_result(run_result):
            run_result = dict(run_result)
            run_result["macro"] = macro_name
            run_result["run_action"] = run_action
        return run_result

    def _run_workflow_sequence(self, name: str, calls: list, args: dict) -> dict:
        """Execute a workflow — a sequence of tool calls with $param substitution."""
        # Collect params from caller
        params = {}
        for k, v in args.items():
            if k in ("action", "name", "macro"):
                continue
            params[k] = v
        results = []
        for i, call in enumerate(calls):
            if not isinstance(call, dict):
                results.append({
                    "step": i,
                    "result": make_error(MCPError.INVALID_ARGS, "step must be a dict"),
                })
                continue
            # Check conditional
            condition = call.get("if")
            if condition is not None:
                # Evaluate: truthy if param is set and not false/0/empty
                cond_key = str(condition).lstrip("$")
                cond_val = params.get(cond_key) or params.get(f"${cond_key}")
                if not cond_val or str(cond_val).lower() in ("false", "0", ""):
                    # Run else branch if present
                    else_call = call.get("else")
                    if isinstance(else_call, dict):
                        call = else_call
                    else:
                        results.append({"step": i, "skipped": True, "reason": f"condition ${cond_key} is falsy"})
                        continue
                else:
                    # Run then branch
                    then_call = call.get("then")
                    if isinstance(then_call, dict):
                        call = then_call
                    else:
                        results.append({"step": i, "skipped": True, "reason": "then branch not a dict"})
                        continue
            tool = str(_substitute_params(call.get("tool", "session"), params))
            action = str(_substitute_params(call.get("action", ""), params))
            if not action:
                results.append({
                    "step": i,
                    "result": make_error(MCPError.INVALID_ARGS, "action required"),
                })
                continue
            call_args = {"action": action}
            for k, v in call.items():
                if k in ("tool", "action", "if", "then", "else"):
                    continue
                call_args[k] = _substitute_params(v, params)
            result = self._execute_tool(tool, call_args)
            results.append({"step": i, "tool": tool, "action": action, "result": result})
            # Store result fields as params for next steps (prefix with step number)
            if isinstance(result, dict) and not is_error_result(result):
                for rk, rv in result.items():
                    if isinstance(rv, (str, int, float, bool)):
                        params[f"step{i}_{rk}"] = rv
        return {"ok": True, "workflow": name, "step_count": len(results), "steps": results}

    def _session_action_recent_workset(self, args: dict) -> dict:
        sid, sid_err = self._resolve_session_id(args)
        if sid_err:
            return sid_err
        if not sid:
            return make_error(
                MCPError.INVALID_ARGS,
                "session_id required (or have an active session)",
            )
        if not self.session_mgr.session_exists(sid):
            return make_error(
                MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
            )
        n = _bounded_int(args.get("n", 20), 20, min_value=1, max_value=200)
        include_bookmarks = _coerce_bool(args.get("include_bookmarks"), True)
        include_items = _coerce_bool(args.get("include_items"), False)
        return self._build_recent_workset(
            sid,
            n=n,
            include_bookmarks=include_bookmarks,
            include_items=include_items,
        )

# Register session actions so the tool registry can derive TOOL_ACTIONS
# without duplicating the literal in schemas_data.py.
register_tool_actions("session", list(ServerSessionMixin._SESSION_ACTIONS.keys()))
