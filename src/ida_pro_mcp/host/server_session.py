#!/usr/bin/env python3
"""Session tool dispatch helpers for IDAMCPServer."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from .arch_profile import infer_binary_arch_profile, normalize_arch_options
from .chip_db import find_chip_profile
from .config import (
    MAX_BATCH_CALLS,
    MAX_LIST_LIMIT,
    MAX_LIST_OFFSET,
    MAX_NAME_LEN,
    MAX_NOTE_LEN,
    MAX_TAGS_PER_SESSION,
    MAX_TAG_LEN,
    _bounded_int,
    _coerce_bool,
    _normalize_session_id,
)
from .errors import MCPError, make_error
from .schemas import TOOL_ACTIONS
from .server_session_bootstrap import ServerSessionBootstrapMixin
from .symbol_db import SymbolDB
from .intelligence_helpers import parse_str_list


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class ServerSessionMixin(ServerSessionBootstrapMixin):
    def _resolve_session_capsule(self, sid: str, requested: Any = None) -> str:
        sid_norm = _normalize_session_id(sid) or str(sid or "").strip().upper()
        explicit = str(requested or "").strip()
        if explicit:
            resolved = os.path.abspath(os.path.expanduser(explicit))
            self._session_capsules[sid_norm] = resolved
            return resolved
        mapped = str(getattr(self, "_session_capsules", {}).get(sid_norm, "") or "").strip()
        if mapped:
            return mapped
        env_path = str(os.environ.get("IDA_MCP_CAPSULE", "") or "").strip()
        if env_path:
            resolved = os.path.abspath(os.path.expanduser(env_path))
            self._session_capsules[sid_norm] = resolved
            return resolved
        return ""

    def _sync_session_to_capsule(
        self,
        session,
        *,
        requested_capsule: Any = None,
        event_type: str = "session_update",
        event: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
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
                from ida_pro_mcp.host.intelligence_core import BgeCodeEmbedder, FunctionEmbeddingIndex
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

    def _handle_session(self, args: dict) -> dict:
        action = args.get("action")

        if action == "health":
            return self._handle_session_health(args)

        def _sid_arg(
            key: str = "session_id", allow_current: bool = True
        ) -> tuple[Optional[str], Optional[dict]]:
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

        if action == "create":
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
                # Raw-binary profile inference to avoid metapc/default dead-ends.
                if analysis_options.get("processor") is None:
                    inferred = infer_binary_arch_profile(binary_path)
                    arch_meta = dict(arch_meta or {})
                    arch_meta["inferred_profile"] = inferred
                    if inferred.get("memory_map"):
                        arch_meta["memory_map"] = inferred.get("memory_map")
                    if inferred.get("peripheral_addresses"):
                        arch_meta["peripheral_addresses"] = inferred.get("peripheral_addresses")
                    if inferred.get("processor"):
                        # Deterministic inference from explicit profile (e.g. known headers/vector table).
                        arch_meta["inference_applied"] = True
                        analysis_options["processor"] = inferred.get("processor")
                        if inferred.get("bitness") is not None:
                            analysis_options.setdefault("bitness", inferred.get("bitness"))
                        if inferred.get("endian"):
                            analysis_options.setdefault("endian", inferred.get("endian"))
                        if inferred.get("loader"):
                            analysis_options.setdefault("loader", inferred.get("loader"))
                        # Apply load base for chip-specific formats (e.g. AIC WFFW at 0x120000).
                        if inferred.get("load_base") is not None:
                            analysis_options.setdefault("baseaddr", inferred["load_base"])
                            arch_meta["load_base_applied"] = True
                            arch_meta["load_base"] = hex(inferred["load_base"])
                        if inferred.get("chip_family"):
                            arch_meta["chip_family"] = inferred["chip_family"]
                            analysis_options.setdefault("chip_family", inferred.get("chip_family"))
                            if inferred.get("memory_map"):
                                analysis_options.setdefault("memory_map", inferred.get("memory_map"))
                            if inferred.get("peripheral_addresses"):
                                analysis_options.setdefault("peripheral_addresses", inferred.get("peripheral_addresses"))
                            prof = find_chip_profile(str(inferred.get("chip_family") or "")) or {}
                            if prof.get("post_load_actions"):
                                analysis_options.setdefault("post_load_actions", prof.get("post_load_actions"))
                    else:
                        # For raw blobs with no deterministic header/vector-table, apply the
                        # top-ranked candidate. Any heuristic recommendation beats IDA's
                        # metapc/64 default on a raw binary. Gate only on the candidate
                        # having valid processor/bitness/endian fields.
                        candidates = inferred.get("candidates") if isinstance(inferred.get("candidates"), list) else []
                        top = candidates[0] if candidates and isinstance(candidates[0], dict) else {}
                        nxt = candidates[1] if len(candidates) > 1 and isinstance(candidates[1], dict) else {}
                        try:
                            top_conf = float(top.get("confidence", 0.0) or 0.0)
                        except Exception:
                            top_conf = 0.0
                        try:
                            next_conf = float(nxt.get("confidence", 0.0) or 0.0)
                        except Exception:
                            next_conf = 0.0
                        margin = max(0.0, top_conf - next_conf)
                        can_apply = bool(
                            top.get("processor")
                            and top.get("bitness") in {16, 32, 64}
                            and str(top.get("endian") or "").lower() in {"little", "big"}
                            and inferred.get("file_kind") == "raw"
                        )
                        if can_apply:
                            analysis_options["processor"] = top.get("processor")
                            analysis_options.setdefault("bitness", top.get("bitness"))
                            analysis_options.setdefault("endian", top.get("endian"))
                            arch_meta["inference_applied"] = True
                            arch_meta["inference_apply_reason"] = "raw_binary_top_candidate"
                            arch_meta["inference_apply_confidence"] = round(top_conf, 3)
                            arch_meta["inference_apply_margin"] = round(margin, 3)
                        else:
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

            self.current_session = self.session_mgr.create_session(
                binary_path or "",
                analysis_options=analysis_options,
                ida_args=ida_args,
                tags=tags,
                notes=notes,
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
        if action == "discover":
            self.session_mgr._load_orphaned_idbs()
            q = args.get("query", "")
            sessions = [
                s.to_dict() for s in self.session_mgr.discover_sessions(query=q)
            ]
            return {"ok": True, "sessions": sessions, "count": len(sessions)}
        if action == "get":
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
        if action == "list":
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
        if action == "switch":
            old_idb = getattr(self.current_session, "idb_path", None) if self.current_session else None
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
                    hint="Provide session_id or binary_path. Use session(action='list') to see sessions.",
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
            if session:
                self.current_session = session
                new_idb = getattr(session, "idb_path", None)
                if old_idb and new_idb and old_idb != new_idb:
                    _trigger_session_diff(old_idb, new_idb)
                return {
                    "ok": True,
                    "session": self.current_session.to_dict(),
                    "capsule": self._sync_session_to_capsule(
                        self.current_session,
                        event_type="session_switch",
                        event={"from_idb": old_idb or "", "to_idb": new_idb or ""},
                    ),
                }
            return make_error(
                MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
            )
        if action == "close":
            sid, sid_err = _sid_arg()
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
        if action == "status":
            if self.current_session:
                result = self.current_session.to_dict()
                runtime = self.session_runtimes.get(self.current_session.session_id)
                result["is_running"] = bool(
                    runtime
                    and runtime.get("process")
                    and runtime["process"].poll() is None
                )
                session_meta = getattr(self.current_session, "metadata", None) or {}
                result["analysis_ready"] = bool(
                    isinstance(session_meta, dict)
                    and session_meta.get("indexing_complete")
                )
                # Inject recent blackboard into session status so LLM sees it by default
                try:
                    import importlib.util
                    bb_path = os.path.join(SCRIPT_DIR, "..", "ida_mcp", "tools", "blackboard.py")
                    bb_path = os.path.abspath(bb_path)
                    spec = importlib.util.spec_from_file_location("_host_blackboard_status", bb_path)
                    mod = importlib.util.module_from_spec(spec)
                    mod.__dict__["tool"] = lambda f: f
                    mod.__dict__["idaread"] = lambda f: f
                    mod.__dict__["idawrite"] = lambda f: f
                    mod.__dict__["IDAError"] = Exception
                    spec.loader.exec_module(mod)
                    idb_p = getattr(self.current_session, "idb_path", None) if self.current_session else None
                    bb_p = (idb_p + ".blackboard.db") if idb_p else None
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
        if action == "rebuild":
            sid, sid_err = _sid_arg()
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
        if action == "update":
            sid, sid_err = _sid_arg()
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
                    event={"updated_fields": sorted([k for k in update_kwargs.keys()])},
                ),
            }
        if action == "rename":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            new_name = args.get("name") or args.get("new_name")
            if not new_name:
                return make_error(MCPError.INVALID_ARGS, "name required")
            new_name = str(new_name).strip()[:MAX_NAME_LEN]
            result = self.session_mgr.rename_session(sid, new_name)
            if result is None:
                return make_error(
                    MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                )
            return {"ok": True, "session": result.to_dict()}
        if action == "duplicate":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            result = self.session_mgr.duplicate_session(sid)
            if result is None:
                return make_error(
                    MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                )
            return {"ok": True, "session": result.to_dict()}
        if action == "export_session":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            exported_hypotheses = self._export_session_hypotheses_to_symbol_db(sid)
            result = self.session_mgr.export_session(sid)
            if result is None:
                return make_error(
                    MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                )
            return {"ok": True, "exported": result, "exported_hypotheses": int(exported_hypotheses)}
        if action == "import_session":
            data = args.get("data")
            if not data or not isinstance(data, dict):
                return make_error(MCPError.INVALID_ARGS, "data dict required")
            result = self.session_mgr.import_session(data)
            return {"ok": True, "session": result.to_dict()}
        if action == "archive":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            result = self.session_mgr.archive_session(sid)
            if result is None:
                return make_error(
                    MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                )
            return {"ok": True, "session": result.to_dict()}
        if action == "unarchive":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            result = self.session_mgr.unarchive_session(sid)
            if result is None:
                return make_error(
                    MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                )
            return {"ok": True, "session": result.to_dict()}
        if action == "tag":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            tag = args.get("tag")
            if not tag:
                return make_error(MCPError.INVALID_ARGS, "tag required")
            tag = str(tag).strip()[:MAX_TAG_LEN]
            if not tag:
                return make_error(MCPError.INVALID_ARGS, "tag required")
            result = self.session_mgr.tag_session(sid, tag)
            if result is None:
                return make_error(
                    MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                )
            return {"ok": True, "session": result.to_dict()}
        if action == "untag":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            tag = args.get("tag")
            if not tag:
                return make_error(MCPError.INVALID_ARGS, "tag required")
            result = self.session_mgr.untag_session(sid, tag)
            if result is None:
                return make_error(
                    MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                )
            return {"ok": True, "session": result.to_dict()}
        if action == "find_by_tag":
            tag = args.get("tag")
            if not tag:
                return make_error(MCPError.INVALID_ARGS, "tag required")
            sessions = [s.to_dict() for s in self.session_mgr.find_by_tag(tag)]
            return {"ok": True, "sessions": sessions, "count": len(sessions)}
        if action == "add_note":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            note = args.get("note", "")
            if not note:
                return make_error(MCPError.INVALID_ARGS, "note required")
            note = str(note)[:MAX_NOTE_LEN]
            result = self.session_mgr.add_note(sid, note)
            if result is None:
                return make_error(
                    MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                )
            return {"ok": True, "session": result.to_dict()}
        if action == "clear_notes":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            result = self.session_mgr.clear_notes(sid)
            if result is None:
                return make_error(
                    MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                )
            return {"ok": True, "session": result.to_dict()}
        if action == "cleanup_stale":
            max_age = _bounded_int(
                args.get("max_age_days", 30), 30, min_value=1, max_value=3650
            )
            deleted = self.session_mgr.cleanup_stale(max_age_days=max_age)
            return {"ok": True, "deleted_sids": deleted, "count": len(deleted)}
        if action == "stats":
            return {"ok": True, "stats": self.session_mgr.get_stats()}
        if action == "validate":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            result = self.session_mgr.validate_session(sid)
            if result is None:
                return make_error(
                    MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                )
            return {"ok": True, "validation": result}
        if action == "bulk_delete":
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
        if action == "bulk_tag":
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
        if action == "search_notes":
            query = args.get("query", "")
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required")
            sessions = [s.to_dict() for s in self.session_mgr.search_notes(query)]
            return {"ok": True, "sessions": sessions, "count": len(sessions)}
        if action == "recent":
            n = _bounded_int(
                args.get("n", 5), 5, min_value=1, max_value=MAX_LIST_LIMIT
            )
            sessions = [s.to_dict() for s in self.session_mgr.get_recent(n)]
            return {"ok": True, "sessions": sessions, "count": len(sessions)}
        if action == "oldest":
            n = _bounded_int(
                args.get("n", 5), 5, min_value=1, max_value=MAX_LIST_LIMIT
            )
            sessions = [s.to_dict() for s in self.session_mgr.get_oldest(n)]
            return {"ok": True, "sessions": sessions, "count": len(sessions)}
        if action == "snapshot":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            snapshot_res = self.session_mgr.snapshot_session(sid)
            if snapshot_res is None:
                return make_error(
                    MCPError.SESSION_NOT_FOUND, f"Session '{sid}' not found"
                )
            return {"ok": True, "session_id": sid, "snapshot_id": snapshot_res.get("snapshot_id"), "message": snapshot_res.get("message", "")}
        if action == "restore_snapshot":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
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
        if action == "merge":
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
        if action == "crystallize_skill":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            name = str(args.get("name") or "").strip()
            description = str(args.get("description") or "").strip()
            if not name:
                return make_error(MCPError.INVALID_ARGS, "name required")
            if not description:
                return make_error(MCPError.INVALID_ARGS, "description required")
            steps = args.get("steps")
            if not isinstance(steps, list) or not steps:
                return make_error(MCPError.INVALID_ARGS, "steps must be a non-empty list")
            tags = args.get("tags")
            if isinstance(tags, str):
                tags = parse_str_list(tags)
            if tags is not None and not isinstance(tags, list):
                return make_error(MCPError.INVALID_ARGS, "tags must be a list or comma-separated string")
            memrl_reward = args.get("memrl_reward")
            if memrl_reward is not None:
                try:
                    memrl_reward = float(memrl_reward)
                except (TypeError, ValueError):
                    return make_error(MCPError.INVALID_ARGS, "memrl_reward must be a number")
            return self.session_mgr.crystallize_skill(
                sid,
                name=name,
                description=description,
                steps=steps,
                tags=tags,
                memrl_reward=memrl_reward,
            )
        if action == "rate_skill":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            skill_id = str(args.get("skill_id") or "").strip()
            if not skill_id:
                return make_error(MCPError.INVALID_ARGS, "skill_id required")
            reward = args.get("reward")
            try:
                reward_f = float(reward)
            except (TypeError, ValueError):
                return make_error(MCPError.INVALID_ARGS, "reward must be a number")
            return self.session_mgr.rate_skill(sid, skill_id=skill_id, reward=reward_f)
        if action == "list_skills":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
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
        if action == "suggest_strategy":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            context = str(args.get("context") or "")
            return self.session_mgr.suggest_strategy(sid, context=context)
        if action == "log_activity":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
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
        if action == "get_activity_log":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            limit = _bounded_int(args.get("limit", 20), 20, min_value=1, max_value=500)
            return self.session_mgr.get_activity_log(sid, limit=limit)
        if action == "notebook_append":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            entry = str(args.get("note") or args.get("entry") or "").strip()
            if not entry:
                return make_error(MCPError.INVALID_ARGS, "entry (or note) required")
            section = str(args.get("section") or "").strip() or None
            return self.session_mgr.notebook_append(sid, entry=entry, section=section)
        if action == "notebook_read":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            lines = args.get("lines")
            lines = str(lines).strip() if lines is not None else None
            return self.session_mgr.notebook_read(sid, lines=lines)
        if action == "notebook_section":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            section_name = str(args.get("section") or args.get("name") or "").strip()
            if not section_name:
                return make_error(MCPError.INVALID_ARGS, "section required")
            return self.session_mgr.notebook_section(sid, section_name=section_name)
        if action == "track_hypothesis":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
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
        if action == "confirm_hypothesis":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            hid = str(args.get("hypothesis_id") or args.get("id") or "").strip()
            if not hid:
                return make_error(MCPError.INVALID_ARGS, "hypothesis_id required")
            evidence = args.get("evidence")
            if isinstance(evidence, str):
                evidence = parse_str_list(evidence)
            return self.session_mgr.confirm_hypothesis(sid, hid=hid, evidence=evidence)
        if action == "refute_hypothesis":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
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
        if action == "list_hypotheses":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            status = str(args.get("status") or "").strip() or None
            return self.session_mgr.list_hypotheses(sid, status=status)
        if action == "dashboard":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            return self.session_mgr.dashboard(sid)
        if action == "get_phase":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            return self.session_mgr.get_phase(sid)
        if action == "advance_phase":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            return self.session_mgr.advance_phase(sid)
        if action == "link_session":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            other_sid = _normalize_session_id(args.get("other_session_id") or args.get("other_sid") or args.get("target_session_id"))
            if not other_sid:
                return make_error(MCPError.INVALID_ARGS, "other_session_id required")
            return self.session_mgr.link_session(sid, other_sid=other_sid)
        if action == "cross_reference_sessions":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            return self.session_mgr.cross_reference_sessions(sid)
        if action == "list_snapshots":
            sid, sid_err = _sid_arg()
            if sid_err:
                return sid_err
            if not sid:
                return make_error(MCPError.INVALID_ARGS, "session_id required")
            return self.session_mgr.list_snapshots(sid)
        bootstrap_result = self._handle_session_bootstrap(action, args, _sid_arg)
        if bootstrap_result is not None:
            return bootstrap_result
        if action == "macro_set":
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
        if action == "macro_get":
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
        if action == "macro_list":
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
        if action == "macro_delete":
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
        if action == "macro_run":
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
            if isinstance(run_result, dict) and not run_result.get("error"):
                run_result = dict(run_result)
                run_result["macro"] = macro_name
                run_result["run_action"] = run_action
            return run_result
        if action == "recent_workset":
            sid, sid_err = _sid_arg()
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
        return make_error(
            MCPError.ACTION_NOT_FOUND,
            f"Unsupported session action: '{action}'",
            hint=f"Valid session actions: {', '.join(TOOL_ACTIONS['session'])}",
        )
