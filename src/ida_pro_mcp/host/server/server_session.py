#!/usr/bin/env python3
"""Session tool dispatch helpers for IDAMCPServer."""

from __future__ import annotations

import contextlib
import os
import re
from datetime import datetime
from typing import Any

from ..analysis.arch_profile import normalize_arch_options
from ..config import (
    MAX_BATCH_CALLS,
    MAX_LIST_LIMIT,
    MAX_LIST_OFFSET,
    MAX_NAME_LEN,
    MAX_NOTE_LEN,
    MAX_TAG_LEN,
    MAX_TAGS_PER_SESSION,
    _bounded_int,
    _coerce_bool,
    _normalize_session_id,
    log_rpc,
)
from ..errors import MCPError, is_error_result, make_error
from ..intelligence.helpers import parse_str_list
from ..schemas import TOOL_ACTIONS
from ..stores.chip_db import find_chip_profile
from ..stores.symbol_db import SymbolDB
from .server_session_bootstrap import ServerSessionBootstrapMixin
from .tool_registry import register_tool_actions

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


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


def _sess_coerce_find_tag(args):
    tag = args.get("tag")
    if not tag:
        return None, make_error(MCPError.INVALID_ARGS, "tag required")
    return {"tag": tag}, None


def _sess_coerce_query(args):
    query = args.get("query", "")
    if not query:
        return None, make_error(MCPError.INVALID_ARGS, "query required")
    return {"query": query}, None


def _sess_coerce_n_default5(args):
    return {"n": _bounded_int(args.get("n", 5), 5, min_value=1, max_value=MAX_LIST_LIMIT)}, None


def _sess_coerce_link(args):
    other = _normalize_session_id(
        args.get("other_session_id") or args.get("other_sid") or args.get("target_session_id")
    )
    if not other:
        return None, make_error(MCPError.INVALID_ARGS, "other_session_id required")
    return {"other_sid": other}, None


def _sess_coerce_nb_append(args):
    entry = str(args.get("note") or args.get("entry") or "").strip()
    if not entry:
        return None, make_error(MCPError.INVALID_ARGS, "entry (or note) required")
    section = str(args.get("section") or "").strip() or None
    return {"entry": entry, "section": section}, None


def _sess_coerce_nb_read(args):
    lines = args.get("lines")
    return {"lines": str(lines).strip() if lines is not None else None}, None


def _sess_coerce_nb_section(args):
    name = str(args.get("section") or args.get("name") or "").strip()
    if not name:
        return None, make_error(MCPError.INVALID_ARGS, "section required")
    return {"section_name": name}, None


def _sess_coerce_strategy(args):
    return {"context": str(args.get("context") or "")}, None


def _sess_coerce_activity_limit(args):
    return {"limit": _bounded_int(args.get("limit", 20), 20, min_value=1, max_value=500)}, None


def _sess_coerce_hyp_status(args):
    return {"status": str(args.get("status") or "").strip() or None}, None


class ServerSessionMixin(ServerSessionBootstrapMixin):
    def _resolve_session_capsule(self, sid: str, requested: Any = None) -> str:
        sid_norm = _normalize_session_id(sid) or str(sid or "").strip().upper()
        explicit = str(requested or "").strip()
        if explicit:
            resolved = os.path.abspath(os.path.expanduser(explicit))
            self._session_capsules[sid_norm] = resolved
            os.environ["IDA_MCP_CAPSULE"] = resolved
            return resolved
        mapped = str(getattr(self, "_session_capsules", {}).get(sid_norm, "") or "").strip()
        if mapped:
            os.environ["IDA_MCP_CAPSULE"] = mapped
            return mapped
        env_path = str(os.environ.get("IDA_MCP_CAPSULE", "") or "").strip()
        if env_path:
            resolved = os.path.abspath(os.path.expanduser(env_path))
            self._session_capsules[sid_norm] = resolved
            return resolved

        # Try to resolve session to retrieve idb_path / binary_path
        session = None
        if self.current_session and (_normalize_session_id(self.current_session.session_id) == sid_norm):
            session = self.current_session
        else:
            with contextlib.suppress(Exception):
                session = self.session_mgr.get_session(sid_norm)

        idb_path = ""
        if session:
            idb_path = getattr(session, "idb_path", "")
            if not idb_path and hasattr(session, "to_dict"):
                with contextlib.suppress(Exception):
                    idb_path = session.to_dict().get("idb_path", "")
            if not idb_path:
                binary_path = getattr(session, "binary_path", "")
                if not binary_path and hasattr(session, "to_dict"):
                    with contextlib.suppress(Exception):
                        binary_path = session.to_dict().get("binary_path", "")
                if binary_path:
                    idb_path = binary_path

        if idb_path:
            resolved = os.path.abspath(f"{os.path.splitext(idb_path)[0]}.sideband")
            self._session_capsules[sid_norm] = resolved
            os.environ["IDA_MCP_CAPSULE"] = resolved
            return resolved

        return ""


    def _sync_session_to_capsule(
        self,
        session,
        *,
        requested_capsule: Any = None,
        event_type: str = "session_update",
        event: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        sid = getattr(session, "session_id", "") if session else ""
        if not sid:
            return {"enabled": False, "persisted": False, "capsule": ""}
        capsule_path = self._resolve_session_capsule(sid, requested=requested_capsule)
        if not capsule_path:
            return {"enabled": False, "persisted": False, "capsule": ""}
        try:
            from ida_pro_mcp.capsule import CapsuleStore

            payload = session.to_dict() if hasattr(session, "to_dict") else {}
            with CapsuleStore.open(capsule_path) as cap:
                if not cap.is_initialized():
                    project_name = os.path.basename(str(payload.get("binary_path") or "")) or "ida-session"
                    cap.init(project_name=project_name, created_by="ida-pro-mcp-session")
                cap.upsert_session(str(sid), payload)
                cap.add_audit_event(
                    str(event_type or "session_update"),
                    event or {"session_id": sid, "idb_path": payload.get("idb_path", "")},
                    session_id=str(sid),
                )
            return {
                "enabled": True,
                "persisted": True,
                "capsule": capsule_path,
                "event_type": event_type,
            }
        except Exception as exc:
            return {
                "enabled": True,
                "persisted": False,
                "capsule": capsule_path,
                "event_type": event_type,
                "error": str(exc),
            }

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
                    print(f"[session-diff] {len(new_only)} new functions in rebuilt IDB")
            except Exception:
                pass
        threading.Thread(target=_diff, daemon=True).start()


    _SESSION_ACTIONS: dict[str, Any] = {
        "health": "_session_action_health",
        "create": "_session_action_create",
        "discover": "_session_action_discover",
        "get": "_session_action_get",
        "list": "_session_action_list",
        "switch": "_session_action_switch",
        "close": "_session_action_close",
        "status": "_session_action_status",
        "rebuild": "_session_action_rebuild",
        "update": "_session_action_update",
        # Declarative (kind, mgr_method, coerce_fn) specs — see _run_session_spec.
        "rename": ("dict", "rename_session", _sess_coerce_rename),
        "duplicate": ("dict", "duplicate_session", _sess_coerce_none),
        "export_session": "_session_action_export_session",
        "import_session": "_session_action_import_session",
        "archive": ("dict", "archive_session", _sess_coerce_none),
        "unarchive": ("dict", "unarchive_session", _sess_coerce_none),
        "tag": ("dict", "tag_session", _sess_coerce_tag),
        "untag": ("dict", "untag_session", _sess_coerce_untag),
        "find_by_tag": ("list", "find_by_tag", _sess_coerce_find_tag),
        "add_note": ("dict", "add_note", _sess_coerce_note),
        "clear_notes": ("dict", "clear_notes", _sess_coerce_none),
        "cleanup_stale": "_session_action_cleanup_stale",
        "idle_purge": "_session_action_idle_purge",
        "stats": "_session_action_stats",
        "validate": "_session_action_validate",
        "bulk_delete": "_session_action_bulk_delete",
        "bulk_tag": "_session_action_bulk_tag",
        "search_notes": ("list", "search_notes", _sess_coerce_query),
        "recent": ("list", "get_recent", _sess_coerce_n_default5),
        "oldest": ("list", "get_oldest", _sess_coerce_n_default5),
        "snapshot": "_session_action_snapshot",
        "restore_snapshot": "_session_action_restore_snapshot",
        "merge": "_session_action_merge",
        "rate_skill": "_session_action_rate_skill",
        "list_skills": "_session_action_list_skills",
        "suggest_strategy": ("raw", "suggest_strategy", _sess_coerce_strategy),
        "suggest_triage": "_session_action_suggest_triage",
        "suggest_analogy": "_session_action_suggest_analogy",
        "apply_analogy": "_session_action_apply_analogy",
        "log_activity": "_session_action_log_activity",
        "get_activity_log": ("raw", "get_activity_log", _sess_coerce_activity_limit),
        "notebook_append": ("raw", "notebook_append", _sess_coerce_nb_append),
        "notebook_read": ("raw", "notebook_read", _sess_coerce_nb_read),
        "notebook_section": ("raw", "notebook_section", _sess_coerce_nb_section),
        "track_hypothesis": "_session_action_track_hypothesis",
        "confirm_hypothesis": "_session_action_confirm_hypothesis",
        "refute_hypothesis": "_session_action_refute_hypothesis",
        "list_hypotheses": ("raw", "list_hypotheses", _sess_coerce_hyp_status),
        "dashboard": ("raw", "dashboard", _sess_coerce_none),
        "get_phase": ("raw", "get_phase", _sess_coerce_none),
        "advance_phase": ("raw", "advance_phase", _sess_coerce_none),
        "link_session": ("raw", "link_session", _sess_coerce_link),
        "cross_reference_sessions": ("raw", "cross_reference_sessions", _sess_coerce_none),
        "list_snapshots": ("raw", "list_snapshots", _sess_coerce_none),
        "macro_set": "_session_action_macro_set",
        "macro_get": "_session_action_macro_get",
        "macro_list": "_session_action_macro_list",
        "macro_delete": "_session_action_macro_delete",
        "macro_run": "_session_action_macro_run",
        "recent_workset": "_session_action_recent_workset",
        "kill": "_session_action_kill",
        "state": "_session_action_state",
        "logs": "_session_action_logs",
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
        """Resolve the target session_id, returning (sid, error_capsule).

        On success sid is set and error is None. On any failure sid is None and
        error is a ready-to-return capsule (format error or 'session_id
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

    def _session_action_health(self, args: dict) -> dict:
        return self._handle_session_health(args)

    def _session_action_create(self, args: dict) -> dict:
        binary_path = args.get("binary_path")
        if "idb_path" in args or "use_existing" in args:
            return make_error(
                MCPError.INVALID_ARGS,
                "The idb_path and use_existing parameters were removed from session create",
                details={
                    "hint": "Use session(action='create', binary_path='...') instead; IDB creation/reuse is automatic."
                },
            )
        force_new = bool(args.get("force_new"))

        if binary_path is not None and not isinstance(binary_path, str):
            return make_error(
                MCPError.INVALID_ARGS,
                "binary_path must be a string",
                details={
                    "hint": "Provide a path string, e.g. session(action='create', binary_path='/abs/path/to/binary')."
                },
            )

        analysis_options = {}
        raw_analysis_options = args.get("analysis_options")
        if raw_analysis_options is not None and not isinstance(raw_analysis_options, dict):
            return make_error(
                MCPError.INVALID_ARGS,
                "analysis_options must be an object",
                details={"analysis_options_type": type(raw_analysis_options).__name__},
            )
        if isinstance(raw_analysis_options, dict):
            analysis_options.update(raw_analysis_options or {})

        architecture = args.get("architecture")
        if architecture is not None and not isinstance(architecture, dict):
            return make_error(
                MCPError.INVALID_ARGS,
                "architecture must be an object",
                details={"architecture_type": type(architecture).__name__},
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
                        return make_error(
                            MCPError.INVALID_ARGS,
                            f"Conflicting architecture value for '{canon}'",
                            details={"analysis_options": analysis_options.get(canon), "architecture": v},
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
        )
        for key in merged_keys:
            if key in args:
                top_val = args.get(key)
                if key in analysis_options and analysis_options[key] != top_val:
                    return make_error(
                        MCPError.INVALID_ARGS,
                        f"Conflicting value for '{key}' between top-level and analysis_options/architecture",
                        details={"top_level": top_val, "analysis_options": analysis_options.get(key)},
                    )
                analysis_options[key] = top_val

        analysis_options, arch_meta = normalize_arch_options(analysis_options)

        preload_keys = {"processor", "bitness", "endian", "loader", "value", "loader_options", "flags"}
        has_preload_request = any(k in analysis_options and analysis_options.get(k) is not None for k in preload_keys)

        ida_args = None
        if "ida_args" in args:
            try:
                ida_args = self._normalize_ida_args(args.get("ida_args"))
            except ValueError as e:
                return make_error(MCPError.INVALID_ARGS, str(e))

        if binary_path:
            if not os.path.isabs(binary_path):
                binary_path = os.path.abspath(binary_path)
            args["binary_path"] = binary_path
            if not os.path.exists(binary_path):
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    f"Binary not found: {binary_path}",
                    details={
                        "binary_path": binary_path,
                        "hint": "Provide an absolute path to an existing binary file.",
                    },
                )
            arch_meta = dict(arch_meta or {})
            arch_meta["inference_applied"] = False

        if not binary_path:
            return make_error(
                MCPError.INVALID_ARGS,
                "binary_path is required",
                details={
                    "hint": "Provide a binary path, e.g. session(action='create', binary_path='/abs/path/to/binary')."
                },
            )

        existing = None
        if binary_path:
            existing = self.session_mgr.find_session_by_path(binary_path)
        # Even when the caller passes loader/architecture preload options,
        # reuse the existing session if those options already match — this
        # stops smoke runs from spawning a new idat child for the same
        # binary on every restart. force_new=true still wins.
        if existing and not force_new and has_preload_request and analysis_options:
            existing_opts = dict(existing.analysis_options or {})
            preload_keys = ("processor", "bitness", "endian", "loader", "flags", "loader_options", "value")
            mismatch = any(
                str(existing_opts.get(k) or "") != str(analysis_options.get(k) or "")
                for k in preload_keys
                if k in analysis_options
            )
            if not mismatch:
                # Pretend preload request was absent so the existing reuse
                # branch runs.
                has_preload_request = False
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
            out = {
                "ok": True,
                "session": updated.to_dict(),
                "note": "Reusing existing session. Use force_new=true to create a new session.",
            }
            out["capsule"] = self._sync_session_to_capsule(
                updated,
                requested_capsule=args.get("capsule"),
                event_type="session_reuse",
                event={"binary_path": binary_path, "reuse": True},
            )
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

        self.current_session = self.session_mgr.create_session(
            binary_path or "",
            analysis_options=analysis_options,
            ida_args=ida_args,
            tags=tags,
            notes=notes,
            packed_idb=is_packed_idb,
        )
        out = {"ok": True, "session": self.current_session.to_dict()}
        out["capsule"] = self._sync_session_to_capsule(
            self.current_session,
            requested_capsule=args.get("capsule"),
            event_type="session_create",
            event={"binary_path": binary_path, "analysis_options": bool(analysis_options)},
        )
        imported_symbol_count = 0
        cross_session_imported = 0
        try:
            inferred = arch_meta.get("inferred_profile") if isinstance(arch_meta, dict) else {}
            chip = str((inferred or {}).get("chip_family") or (arch_meta or {}).get("chip_family") or "").strip()
            if chip:
                sdb = SymbolDB()
                imported_symbol_count = sum(
                    int(row.get("symbol_count") or 0)
                    for row in sdb.stats_by_chip()
                    if str(row.get("chip_family") or "").strip().lower() == chip.lower()
                )
        except Exception:
            imported_symbol_count = 0
        try:
            cross_session_imported = self._import_cross_session_hypotheses(self.current_session)
        except Exception:
            cross_session_imported = 0
        if create_note:
            out["note"] = create_note
        if arch_meta:
            out["architecture_profile"] = arch_meta
            chip_family = arch_meta.get("chip_family")
            if chip_family:
                out["chip_family"] = chip_family
                prof = find_chip_profile(str(chip_family)) or {}
                out["bootstrap_report"] = {
                    "status": "scheduled",
                    "chip_family": chip_family,
                    "post_load_actions": prof.get("post_load_actions", []),
                    "note": "Bootstrap runs automatically when the IDA session runtime is started.",
                }
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
        out["imported_symbol_count"] = int(imported_symbol_count)
        out["cross_session_imported"] = int(cross_session_imported)
        return out

    def _session_action_discover(self, args: dict) -> dict:
        self.session_mgr._load_orphaned_idbs()
        q = args.get("query", "")
        sessions = [
            s.to_dict() for s in self.session_mgr.discover_sessions(query=q)
        ]
        return {"ok": True, "sessions": sessions, "count": len(sessions)}

    def _session_action_get(self, args: dict) -> dict:
        raw_sid = args.get("session_id")
        if not raw_sid:
            return make_error(
                MCPError.INVALID_ARGS,
                "session_id required",
                hint="Provide a session_id. Use session(action='list') to see available sessions.",
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
                hint="Use session(action='list') to see available sessions.",
            )
        runtime = self.session_runtimes.get(sid)
        is_running = bool(
            runtime
            and runtime.get("process")
            and runtime["process"].poll() is None
        )
        result = session.to_dict()
        result["is_running"] = is_running
        if is_running:
            result["port"] = runtime.get("port")
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
        result = self.session_mgr.list_sessions(
            query=q, offset=offset, limit=limit
        )

        # Augment with runtime status
        session_dicts = []
        for d in result["sessions"]:
            runtime = self.session_runtimes.get(d["session_id"])
            d["is_running"] = bool(
                runtime
                and runtime.get("process")
                and runtime["process"].poll() is None
            )
            session_dicts.append(d)

        return {
            "ok": True,
            "sessions": session_dicts,
            "total": result["total"],
            "count": len(session_dicts),
            "offset": offset,
            "limit": limit,
        }

    def _session_action_switch(self, args: dict) -> dict:
        old_idb = getattr(self.current_session, "idb_path", None) if self.current_session else None
        reopen = bool(args.get("reopen") or args.get("restart"))
        sid = args.get("session_id")
        if not sid:
            # Try to find by binary_path
            path = args.get("binary_path")
            if path:
                found = self.session_mgr.find_session_by_path(path)
                if found:
                    sid = found.session_id
        if not sid:
            return make_error(
                MCPError.INVALID_ARGS,
                "session_id or binary_path required",
                hint="Provide session_id or binary_path. Use session(action='list') to see available sessions.",
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
            try:
                start_res = self._start_server(session)
                if isinstance(start_res, dict) and "error" not in start_res:
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
            "capsule": self._sync_session_to_capsule(
                self.current_session,
                event_type="session_switch",
                event={"from_idb": old_idb or "", "to_idb": new_idb or ""},
            ),
        }
        idb_path = getattr(session, "idb_path", None)
        if idb_path and not os.path.isfile(idb_path) and not runtime_attached:
            response["idb_exists"] = False
            response["hint"] = (
                "IDB file not on disk at the recorded path. Try "
                "session(action='switch', session_id='...', reopen=true) "
                "to spawn a new IDA runtime."
            )
        spawn_error = getattr(self, "_last_spawn_error", None)
        if isinstance(spawn_error, dict):
            response["spawn_error"] = spawn_error
            self._last_spawn_error = None
        return response

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
        self._export_session_hypotheses_to_symbol_db(sid)
        sess_for_capsule = self.session_mgr.get_session(sid)
        capsule_info = (
            self._sync_session_to_capsule(
                sess_for_capsule,
                event_type="session_close",
                event={"session_id": sid, "closed": True},
            )
            if sess_for_capsule
            else {"enabled": False, "persisted": False, "capsule": ""}
        )
        self._cleanup_runtime(sid)
        closed = self.session_mgr.delete_session(sid)
        if (
            closed
            and self.current_session
            and self.current_session.session_id == sid
        ):
            self.current_session = None
        if closed:
            self._session_capsules.pop(str(sid).upper(), None)
        return {"ok": closed, "session_id": sid, "capsule": capsule_info}

    def _session_action_state(self, args: dict) -> dict:
        """Return the analysis state — same data as the ida://state resource."""
        try:
            import json as _json

            from .resources import ResourceResolver
            resolver = ResourceResolver(
                self._execute_tool,
                session_mgr=getattr(self, "session_mgr", None),
                engine=getattr(self, "_analysis_engines", {}).get(
                    getattr(self.current_session, "session_id", "") or ""
                ),
                bb_path=self._session_blackboard_path(session_obj=self.current_session)
                    if hasattr(self, "_session_blackboard_path") else None,
            )
            resource = resolver.read("ida://state")
            if resource is None:
                return make_error(MCPError.IDA_ERROR, "state resource unavailable")
            content = resource.get("text") or resource.get("blob") or ""
            state_value: object = content
            if isinstance(content, str):
                try:
                    state_value = _json.loads(content)
                except Exception:
                    state_value = content
            # Always wrap in a uniform envelope so callers can reliably
            # check `ok` and find the state under a known key.
            return {"ok": True, "state": state_value}
        except Exception as e:
            return make_error(MCPError.IDA_ERROR, f"state failed: {e}")

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
        if self.current_session:
            fresh_session = self.session_mgr.get_session(self.current_session.session_id) or self.current_session
            result = fresh_session.to_dict()
            runtime = self.session_runtimes.get(fresh_session.session_id)
            result["is_running"] = bool(
                runtime
                and runtime.get("process")
                and runtime["process"].poll() is None
            )
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
            "total_sessions": len(self.session_mgr.sessions),
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
        return {
            "ok": True,
            "session": session.to_dict(),
            "idb_path": session.idb_path,
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
            "capsule": self._sync_session_to_capsule(
                result,
                requested_capsule=args.get("capsule"),
                event_type="session_update",
                event={"updated_fields": sorted(update_kwargs.keys())},
            ),
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
        result = self.session_mgr.import_session(data)
        return {"ok": True, "session": result.to_dict()}

    def _session_action_cleanup_stale(self, args: dict) -> dict:
        max_age = _bounded_int(
            args.get("max_age_days", 30), 30, min_value=1, max_value=3650
        )
        deleted = self.session_mgr.cleanup_stale(max_age_days=max_age)

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
                binary = raw.get("binary_path") or ""
                idb = raw.get("idb_path") or ""
                bin_missing = bool(binary) and not os.path.isfile(binary)
                idb_missing = bool(idb) and not os.path.isfile(idb)
                # Only prune when both reference paths have gone; we don't
                # want to nuke a session that's mid-save.
                if bin_missing and idb_missing:
                    if self.session_mgr.delete_session(sid):
                        also_pruned_orphans.append(sid)

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
        ``last_used`` timestamp is older than ``now - idle_seconds``. We
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

        # ``last_used`` is stored as ISO 8601 in self.sessions[*] via
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
            last_used = raw.get("last_used")
            if not last_used:
                # Unknown liveness — leave it alone so a brand-new session
                # doesn't get killed before its first touch.
                skipped_sids.append(sid)
                continue
            try:
                parsed = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
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
                binary = raw.get("binary_path") or ""
                idb = raw.get("idb_path") or ""
                bin_missing = bool(binary) and not os.path.isfile(binary)
                idb_missing = bool(idb) and not os.path.isfile(idb)
                if bin_missing and idb_missing:
                    try:
                        if self.session_mgr.delete_session(sid):
                            orphan_sids.append(sid)
                    except Exception:
                        continue

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
            cleaned_sids.append(sid)
        results = self.session_mgr.bulk_delete(cleaned_sids)
        # Clear current session if it was deleted
        if (
            self.current_session
            and self.current_session.session_id in cleaned_sids
        ):
            self.current_session = None
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
        result = self.session_mgr.restore_snapshot(sid, snapshot_id)
        if result is None:
            return make_error(
                MCPError.SESSION_NOT_FOUND,
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
        if run_action not in TOOL_ACTIONS["session"]:
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported run_action '{run_action}' for macro_run",
                hint=f"Valid session actions: {', '.join(TOOL_ACTIONS['session'])}",
            )
        run_args = dict(base_args)
        for k, v in args.items():
            if k in ("action", "name", "macro", "run_action"):
                continue
            run_args[k] = v
        run_args["action"] = run_action
        run_result = self._execute_tool("session", run_args)
        if isinstance(run_result, dict) and not is_error_result(run_result):
            run_result = dict(run_result)
            run_result["macro"] = macro_name
            run_result["run_action"] = run_action
        return run_result

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
