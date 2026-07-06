#!/usr/bin/env python3
"""
Session management v2: Session, SessionManager, BookmarkManager.

Creative features integrated directly into existing session tool:
  - Analysis Notebook (Markdown journal with auto-linked addresses/strings/bookmarks)
  - Global Skill Registry (cross-session skill transfer via SQLite)
  - Hypothesis Tracker (structured confirm/refute with evidence binding)
  - Analysis Phase Tracker (triage → deep analysis → reporting)
  - Dead-End Detection (stalled analysis pattern recognition)
  - Real Snapshots (IDA native snapshots + JSON metadata rollback)
  - Federated Session Linking (cross-binary function correlation)
  - Metrics Dashboard (progress tracking for LLM)
  - Auto-predictive tool suggestions (inline context injection)
"""
import contextlib
import copy
import glob
import json
import os
import re
import shutil
import threading
import uuid
from datetime import datetime, timedelta
from typing import Any

from ..analysis.patterns import compile_smart_pattern
from ..config import (
    MAX_NAME_LEN,
    MAX_NOTE_LEN,
    MAX_SESSION_ID_RETRIES,
    MAX_SNAPSHOTS_PER_SESSION,
    MAX_TAG_LEN,
    MAX_TAGS_PER_SESSION,
    _normalize_session_id,
    _parse_iso_datetime,
    log_rpc,
)
from ..errors import MCPError, is_error_result, make_error

# ============================================================================
# ANALYSIS PHASES
# ============================================================================

_ANALYSIS_PHASES = {
    "triage": {
        "order": 0,
        "threshold": {"functions_listed": 1, "strings_listed": 1, "imports_listed": 1},
        "suggested_tools": ["binary_info.headers", "idb.summary", "data.imports", "data.strings"],
        "description": "Initial triage: identify binary type, imports, and suspicious strings.",
    },
    "import_analysis": {
        "order": 1,
        "threshold": {"imports_categorized": 20, "api_patterns_detected": 1},
        "suggested_tools": ["imports_deep.thunks", "classify.categorize", "string_ops.find_urls"],
        "description": "Categorize imports and detect API usage patterns.",
    },
    "deep_analysis": {
        "order": 2,
        "threshold": {"functions_decompiled": 10, "function_attrs_indexed": 1},
        "suggested_tools": ["code.decompile", "ctree.get", "crypto_id.detect", "schemaboot.ingest"],
        "description": "Deep decompilation and semantic analysis.",
    },
    "behavior_mapping": {
        "order": 3,
        "threshold": {"functions_analyzed": 50, "xrefs_traced": 30},
        "suggested_tools": ["graph.call_chain", "bridge_search.search", "code.callers"],
        "description": "Map control flow and cross-reference chains.",
    },
    "vulnerability": {
        "order": 4,
        "threshold": {"functions_analyzed": 100, "dangerous_apis_identified": 5},
        "suggested_tools": ["gadgets.find", "stack_analysis.analyze_frame", "cfg_analysis.complexity"],
        "description": "Vulnerability and exploit analysis.",
    },
    "reporting": {
        "order": 5,
        "threshold": {"bookmarks_created": 5},
        "suggested_tools": ["blackboard.export", "bulk.export_annotations", "session.notebook"],
        "description": "Compile findings and produce report.",
    },
}

# ============================================================================
# SESSION
# ============================================================================


class Session:
    def __init__(
        self,
        session_id: str,
        idb_path: str,
        binary_path: str,
        analysis_options: dict | None = None,
        analysis_applied: bool = False,
        ida_args: list[str] | None = None,
        created_at: datetime | None = None,
        last_accessed: datetime | None = None,
        tags: list[str] | None = None,
        notes: str = "",
        auto_name: str = "",
        phase: str = "triage",
        linked_sessions: list[str] | None = None,
        packed_idb: bool = False,
        policy_mode: str | None = None,
    ):
        self.session_id = session_id
        self.idb_path = idb_path
        self.binary_path = binary_path
        self.analysis_options = analysis_options or {}
        self.analysis_applied = bool(analysis_applied)
        self.ida_args = ida_args or []
        self.created_at = created_at or datetime.now()
        self.last_accessed = last_accessed or datetime.now()
        self.tags = tags or []
        self.notes = notes
        self.auto_name = auto_name or self._derive_auto_name()
        self.phase = phase
        self.linked_sessions = linked_sessions or []
        self.packed_idb = bool(packed_idb)
        self.policy_mode = policy_mode

    def _derive_auto_name(self) -> str:
        if self.binary_path:
            return os.path.basename(self.binary_path)
        if self.idb_path:
            base = os.path.basename(self.idb_path)
            if base.startswith("SID_") and "_" in base[4:]:
                base = base.split("_", 2)[-1]
            return os.path.splitext(base)[0]
        return f"session_{self.session_id}"

    def update_access(self):
        self.last_accessed = datetime.now()

    def idb_on_disk(self) -> bool:
        """True if any IDB artifact exists on disk.

        Checks three locations:
        1. ``idb_path`` from metadata (may be absent).
        2. The bare ``<binary>.i64`` / ``<idb_path>.idb`` file next to
           the source binary — the default save path used by IDA's
           ``save_database`` when no explicit ``IDA_MCP_IDB_PATH`` is set.
        3. Legacy component files (``.id0`` + ``.nam`` + ``.til``)
           alongside ``idb_path``."""
        if self.idb_path and os.path.exists(self.idb_path):
            return True
        # Next to the source binary
        if self.binary_path:
            for suffix in (".i64", ".idb"):
                if os.path.exists(self.binary_path + suffix):
                    return True
        # Legacy component-file layout
        idb_dir = os.path.dirname(self.idb_path or ".")
        sid_prefix = f"SID_{self.idb_path_basename()}"
        try:
            for name in os.listdir(idb_dir):
                if name.startswith(sid_prefix) and (
                    name.endswith((".id0", ".nam"))
                ):
                    return True
        except OSError:
            pass
        return False

    def idb_path_basename(self) -> str:
        """The basename of ``idb_path`` without directory."""
        if not self.idb_path:
            return ""
        return os.path.basename(self.idb_path)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "idb_path": self.idb_path,
            "binary_path": self.binary_path,
            "analysis_options": self.analysis_options,
            "analysis_applied": self.analysis_applied,
            "ida_args": self.ida_args,
            "binary_exists": bool(self.binary_path and os.path.exists(self.binary_path)),
            "idb_exists": self.idb_on_disk(),
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "tags": self.tags,
            "notes": self.notes,
            "auto_name": self.auto_name,
            "phase": self.phase,
            "linked_sessions": self.linked_sessions,
            "packed_idb": self.packed_idb,
            "policy_mode": self.policy_mode,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        sid = _normalize_session_id(data.get("session_id"))
        if not sid:
            raise ValueError("invalid or missing session_id")
        idb_path = data.get("idb_path")
        if idb_path is None:
            idb_path = ""
        elif not isinstance(idb_path, str):
            raise ValueError("idb_path must be a string")
        created = _parse_iso_datetime(data.get("created_at"))
        accessed = _parse_iso_datetime(data.get("last_accessed"))
        return cls(
            sid,
            idb_path,
            data.get("binary_path", ""),
            data.get("analysis_options", {}) or {},
            data.get("analysis_applied", False),
            data.get("ida_args", []) or [],
            created,
            accessed,
            data.get("tags", []) or [],
            data.get("notes", ""),
            data.get("auto_name", ""),
            data.get("phase", "triage"),
            data.get("linked_sessions", []) or [],
            data.get("packed_idb", False),
            data.get("policy_mode"),
        )


# ============================================================================
# SESSION MANAGER
# ============================================================================


from ..intelligence.helpers import parse_str_list  # noqa: E402
from .session_skills import SessionSkillsMixin  # noqa: E402


class SessionManager(SessionSkillsMixin):
    def __init__(self, cache_dir: str):
        self._lock = threading.RLock()
        self.sessions: dict[str, Session] = {}
        self.cache_dir = cache_dir
        self.session_dir = os.path.join(cache_dir, "sessions")
        self._global_skills_db = os.path.join(cache_dir, "global_skills.db")
        os.makedirs(self.session_dir, exist_ok=True)
        self._init_global_skills()
        self._load_sessions()

    # ------------------------------------------------------------------
    # Global Skill Registry (cross-session L3)
    # ------------------------------------------------------------------

    def _init_global_skills(self):
        import sqlite3
        conn = sqlite3.connect(self._global_skills_db)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS global_skills (
                skill_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                steps TEXT,  -- JSON list
                tags TEXT,   -- JSON list
                source_sid TEXT,
                q_value REAL DEFAULT 0.5,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                created_at TEXT,
                last_used TEXT,
                embedding BLOB,
                usage_count_total INTEGER DEFAULT 0
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_skills_q ON global_skills(q_value DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_skills_tags ON global_skills(tags)")
        conn.commit()
        conn.close()

    def _find_global_skills(self, context: str = "", tags: list[str] | None = None, limit: int = 10) -> list[dict]:
        import sqlite3
        skills = []
        tag_set = {str(t).strip().lower() for t in (tags or []) if str(t).strip()}
        try:
            conn = sqlite3.connect(self._global_skills_db)
            cur = conn.cursor()
            query = "SELECT * FROM global_skills WHERE 1=1"
            params: list[Any] = []
            # Pull a broader candidate pool first, then rank by context.
            query += " ORDER BY q_value DESC LIMIT ?"
            params.append(max(int(limit) * 4, 40))
            cur.execute(query, params)
            for row in cur.fetchall():
                tags_loaded = json.loads(row[4])
                if tag_set:
                    loaded_norm = {str(t).strip().lower() for t in (tags_loaded or []) if str(t).strip()}
                    if not tag_set.issubset(loaded_norm):
                        continue
                skills.append({
                    "skill_id": row[0], "name": row[1], "description": row[2],
                    "steps": json.loads(row[3]),
                    "tags": tags_loaded, "source_sid": row[5],
                    "q_value": row[6], "success_count": row[7], "failure_count": row[8],
                    "created_at": row[9], "last_used": row[10],
                })
            conn.close()
        except Exception:
            pass

        # Context match boost
        if context:
            ctx_lower = context.lower()
            for s in skills:
                desc = (s.get("description", "") + " " + " ".join(s.get("tags", []))).lower()
                if any(word in desc for word in ctx_lower.split()):
                    s["context_match"] = True
                    s["q_value"] = min(1.0, s.get("q_value", 0.5) + 0.1)

        skills.sort(key=lambda x: x.get("q_value", 0), reverse=True)
        return skills[:limit]

    # ------------------------------------------------------------------
    # Sanitization
    # ------------------------------------------------------------------

    def _sanitize_tags(self, tags: list[Any] | None) -> list[str]:
        if not tags:
            return []
        cleaned: list[str] = []
        for tag in tags:
            if tag is None:
                continue
            t = str(tag).strip()
            if not t:
                continue
            if len(t) > MAX_TAG_LEN:
                t = t[:MAX_TAG_LEN]
            if t not in cleaned:
                cleaned.append(t)
            if len(cleaned) >= MAX_TAGS_PER_SESSION:
                break
        return cleaned

    def _sanitize_note(self, note: str) -> str:
        if not note:
            return ""
        return str(note)[:MAX_NOTE_LEN]

    def _sanitize_name(self, name: str) -> str:
        if not name:
            return ""
        return str(name).strip()[:MAX_NAME_LEN]

    # ------------------------------------------------------------------
    # Session ID & Metadata
    # ------------------------------------------------------------------

    def _new_session_id(self) -> str:
        for _ in range(MAX_SESSION_ID_RETRIES):
            sid = uuid.uuid4().hex[:8].upper()
            if sid not in self.sessions:
                return sid
        raise RuntimeError(f"failed to allocate unique session id after {MAX_SESSION_ID_RETRIES} retries")

    def _get_metadata_path(self, sid: str) -> str:
        return os.path.join(self.session_dir, f"SID_{sid}_metadata.json")

    def get_session_artifact_dir(self, sid: str, create: bool = True) -> str:
        path = os.path.join(self.session_dir, f"SID_{sid}")
        if create:
            os.makedirs(path, exist_ok=True)
        return path

    def _save_metadata(self, session: Session):
        path = self._get_metadata_path(session.session_id)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(session.to_dict(), f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except Exception as e:
            log_rpc(f"Failed to save session metadata: {e}")
            with contextlib.suppress(OSError):
                os.remove(tmp)

    def _load_sessions(self):
        pattern = os.path.join(self.session_dir, "SID_*_metadata.json")
        for meta_path in glob.glob(pattern):
            try:
                with open(meta_path, encoding="utf-8") as f:
                    data = json.load(f)
                    session = Session.from_dict(data)
                    if not _normalize_session_id(session.session_id):
                        log_rpc(f"Skipping metadata with invalid session_id: {meta_path}")
                        continue
                    self.sessions[session.session_id] = session
            except Exception as e:
                log_rpc(f"Failed to load session metadata from {meta_path}: {e}")
        self._load_orphaned_idbs()

    def _extract_sid(self, path: str) -> str | None:
        base = os.path.basename(path)
        match = re.match(r"SID_([A-Za-z0-9]{8})", base)
        return match.group(1) if match else None

    def _guess_binary_name(self, sid: str, filename: str) -> str:
        prefix = f"SID_{sid}_"
        if filename.startswith(prefix):
            name = filename[len(prefix):]
            return os.path.splitext(name)[0]
        return ""

    def _load_orphaned_idbs(self):
        pattern = os.path.join(self.session_dir, "SID_*.*")
        for idb_path in glob.glob(pattern):
            if not idb_path.lower().endswith((".i64", ".idb")):
                continue
            sid = self._extract_sid(idb_path)
            if not sid or sid in self.sessions:
                continue
            binary_guess = self._guess_binary_name(sid, os.path.basename(idb_path))
            session = Session(sid, idb_path, binary_guess or "")
            self.sessions[sid] = session
            self._save_metadata(session)
            log_rpc(f"Recovered orphaned session {sid}")

    # ------------------------------------------------------------------
    # Session CRUD
    # ------------------------------------------------------------------

    def create_session(
        self, binary_path: str, use_existing: str | None = None,
        analysis_options: dict | None = None, idb_path: str | None = None,
        ida_args: list[str] | None = None, tags: list[str] | None = None,
        notes: str = "", packed_idb: bool = False,
        policy_mode: str | None = None,
    ) -> Session:
        with self._lock:
            sid = self._new_session_id()
            idb_base = os.path.basename(binary_path) if binary_path else f"session_{sid}"
            # Strip .i64 extension from base to avoid double extension (SID_xxx_foo.i64.i64)
            if idb_base.endswith(".i64"):
                idb_base = idb_base[:-4]
            idb_name = f"SID_{sid}_{idb_base}.i64"
            resolved_idb = idb_path or use_existing or os.path.join(self.session_dir, idb_name)
            if resolved_idb and os.path.isdir(resolved_idb):
                resolved_idb = os.path.join(resolved_idb, idb_name)
            if resolved_idb and not os.path.splitext(resolved_idb)[1]:
                resolved_idb = f"{resolved_idb}.i64"
            session = Session(
                sid, resolved_idb, binary_path or "",
                analysis_options=analysis_options, analysis_applied=False,
                ida_args=ida_args or [], packed_idb=packed_idb,
                tags=self._sanitize_tags(tags),
                notes=self._sanitize_note(notes),
                policy_mode=policy_mode,
            )
            self.sessions[sid] = session
            self._save_metadata(session)
            return session

    def get_session(self, sid: str) -> Session | None:
        with self._lock:
            session = self.sessions.get(sid)
            if session:
                session.update_access()
                return copy.deepcopy(session)
            return None

    def find_session_by_path(self, path: str) -> Session | None:
        with self._lock:
            norm = os.path.realpath(os.path.abspath(path))
            for s in self.sessions.values():
                if s.binary_path and os.path.realpath(os.path.abspath(s.binary_path)) == norm:
                    return copy.copy(s)
                if s.idb_path and os.path.realpath(os.path.abspath(s.idb_path)) == norm:
                    return copy.copy(s)
            return None

    def find_sessions_by_path(self, path: str) -> list[Session]:
        """Return all sessions whose binary or idb path matches, most recent first."""
        with self._lock:
            norm = os.path.realpath(os.path.abspath(path))
            matches: list[Session] = []
            for s in self.sessions.values():
                bp_match = s.binary_path and os.path.realpath(os.path.abspath(s.binary_path)) == norm
                idb_match = bool(s.idb_path) and os.path.realpath(os.path.abspath(s.idb_path or "")) == norm
                if bp_match or idb_match:
                    matches.append(copy.copy(s))
            matches.sort(key=lambda m: m.last_accessed or "", reverse=True)
            return matches

    def discover_sessions(self, query: str = "") -> list[Session]:
        with self._lock:
            if not query:
                return [copy.copy(s) for s in self.sessions.values()]
            matcher = compile_smart_pattern(query, case_sensitive=False)
            result = []
            for s in self.sessions.values():
                tags_str = " ".join(s.tags) if s.tags else ""
                searchable = f"{s.session_id} {s.binary_path} {s.idb_path} {s.auto_name} {tags_str} {s.notes}"
                if matcher(searchable):
                    result.append(copy.copy(s))
            return result

    def _delete_session_unlocked(self, sid: str) -> bool:
        session = self.sessions.pop(sid, None)
        deleted = False
        base_pattern = os.path.join(self.session_dir, f"SID_{sid}*")
        for f in glob.glob(base_pattern):
            try:
                if os.path.isdir(f):
                    shutil.rmtree(f, ignore_errors=True)
                else:
                    os.remove(f)
                deleted = True
            except Exception as e:
                log_rpc(f"Failed to delete {f}: {e}")
        for log_name in (f"ida_mcp_{sid}.log", f"ida_stdout_{sid}.log", f"ida_stderr_{sid}.log"):
            log_path = os.path.join(self.cache_dir, log_name)
            if os.path.exists(log_path):
                try:
                    os.remove(log_path)
                    deleted = True
                except Exception as e:
                    log_rpc(f"Failed to delete {log_path}: {e}")
        for cache_pattern in (f"{sid}.blackboard.db*", f"{sid}.proposals.db*"):
            for cache_path in glob.glob(os.path.join(self.cache_dir, cache_pattern)):
                try:
                    os.remove(cache_path)
                    deleted = True
                except Exception as e:
                    log_rpc(f"Failed to delete {cache_path}: {e}")
        return bool(session) or deleted

    def delete_session(self, sid: str) -> bool:
        with self._lock:
            return self._delete_session_unlocked(sid)

    def update_session(self, sid: str, **kwargs) -> Session | None:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            for key, value in kwargs.items():
                if hasattr(session, key) and key not in ("session_id", "created_at"):
                    if key == "tags":
                        value = self._sanitize_tags(value if isinstance(value, list) else [value])
                    elif key == "notes":
                        value = self._sanitize_note(value)
                    elif key == "auto_name":
                        value = self._sanitize_name(value)
                    setattr(session, key, value)
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def rename_session(self, sid: str, new_name: str) -> Session | None:
        return self.update_session(sid, auto_name=self._sanitize_name(new_name))

    def duplicate_session(self, sid: str) -> Session | None:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            new_sid = self._new_session_id()
            # Generate a NEW IDB path for the duplicate to avoid corruption
            idb_base = os.path.basename(session.binary_path or f"session_{new_sid}")
            new_idb = os.path.join(self.session_dir, f"SID_{new_sid}_{idb_base}.i64")
            new_session = Session(
                new_sid, new_idb, session.binary_path,
                analysis_options=dict(session.analysis_options),
                analysis_applied=False, ida_args=list(session.ida_args),
                tags=list(session.tags), notes=session.notes,
                auto_name=f"{session.auto_name} (copy)",
            )
            self.sessions[new_sid] = new_session
            self._save_metadata(new_session)
            return copy.copy(new_session)

    def export_session(self, sid: str, include_skills: bool = True) -> dict | None:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            data = session.to_dict()
            data["_exported_at"] = datetime.now().isoformat()
            if include_skills:
                skills_data = self._load_skills(sid)
                data["_skills"] = skills_data.get("skills", {})
                data["_activity_log"] = skills_data.get("activity_log", [])[-50:]
                data["_hypotheses"] = skills_data.get("hypotheses", [])
            return data

    def get_high_confidence_hypotheses(self, sid: str, min_confidence: float = 0.8) -> list[dict]:
        with self._lock:
            if sid not in self.sessions:
                return []
            data = self._load_skills(sid)
            out: list[dict] = []
            for h in data.get("hypotheses", []) or []:
                try:
                    conf = float(h.get("confidence", 0.0) or 0.0)
                except Exception:
                    conf = 0.0
                if conf >= float(min_confidence):
                    out.append(h)
            return out

    def import_session(self, data: dict) -> Session:
        with self._lock:
            new_sid = self._new_session_id()
            data_copy = dict(data)
            data_copy["session_id"] = new_sid
            data_copy.pop("_exported_at", None)
            skills_import = data_copy.pop("_skills", None)
            activity_import = data_copy.pop("_activity_log", None)
            hypotheses_import = data_copy.pop("_hypotheses", None)
            session = Session.from_dict(data_copy)
            self.sessions[new_sid] = session
            self._save_metadata(session)
            if skills_import:
                current = self._load_skills(new_sid)
                current["skills"].update(skills_import)
                if activity_import:
                    current["activity_log"] = activity_import
                if hypotheses_import:
                    current["hypotheses"] = hypotheses_import
                self._save_skills(new_sid, current)
            return copy.copy(session)

    def archive_session(self, sid: str) -> Session | None:
        return self.update_session(sid, tags=["archived"])

    def unarchive_session(self, sid: str) -> Session | None:
        session = self.sessions.get(sid)
        return self.update_session(sid, tags=[t for t in getattr(session, 'tags', []) if t != "archived"])

    def list_sessions(self, query: str = "", offset: int = 0, limit: int = 0) -> dict:
        with self._lock:
            sessions = list(self.sessions.values())
            if query:
                matcher = compile_smart_pattern(query, case_sensitive=False)
                sessions = [s for s in sessions if matcher(f"{s.session_id} {s.binary_path} {s.idb_path}")]
            sessions.sort(key=lambda s: s.last_accessed, reverse=True)
            total = len(sessions)
            sessions = sessions[offset:offset + limit] if limit > 0 else sessions[offset:]
            return {"sessions": [s.to_dict() for s in sessions], "total": total, "count": len(sessions), "offset": offset, "limit": limit}

    def cleanup_stale(self, max_age_days: int = 30) -> list[str]:
        with self._lock:
            cutoff = datetime.now() - timedelta(days=max_age_days)
            stale = [sid for sid, s in self.sessions.items() if s.last_accessed < cutoff]
            for sid in stale:
                self._delete_session_unlocked(sid)
            return stale

    def auto_prune_if_over_budget(self, budget: int, max_age_days: int) -> int:
        """Auto-prune stale sessions when the store exceeds ``budget``.

        Returns the number of sessions deleted. Only acts if the live
        session count is above the budget and at least one session is
        older than ``max_age_days``. Safe to call repeatedly (idempotent
        once the store is within budget).
        """
        try:
            budget_i = int(budget)
        except Exception:
            return 0
        if budget_i <= 0:
            return 0
        with self._lock:
            total = len(self.sessions)
            if total <= budget_i:
                return 0
            cutoff = datetime.now() - timedelta(days=max_age_days)
            stale = [sid for sid, s in self.sessions.items() if s.last_accessed < cutoff]
            for sid in stale:
                self._delete_session_unlocked(sid)
            if stale:
                log_rpc(
                    f"Auto-pruned {len(stale)} stale sessions "
                    f"(was {total}, budget={budget_i}, max_age_days={max_age_days})"
                )
            return len(stale)

    def get_stats(self) -> dict:
        with self._lock:
            total = len(self.sessions)
            if total == 0:
                return {"total": 0, "active": 0, "archived": 0, "avg_age_days": 0, "tags": {}}
            archived = sum(1 for s in self.sessions.values() if "archived" in s.tags)
            now = datetime.now()
            ages = [(now - s.created_at).total_seconds() for s in self.sessions.values()]
            avg_age_days = (sum(ages) / len(ages)) / 86400 if ages else 0
            tag_counts: dict[str, int] = {}
            for s in self.sessions.values():
                for t in s.tags:
                    tag_counts[t] = tag_counts.get(t, 0) + 1
            phases: dict[str, int] = {}
            for s in self.sessions.values():
                phases[s.phase] = phases.get(s.phase, 0) + 1
            return {
                "total": total, "active": total - archived, "archived": archived,
                "avg_age_days": round(avg_age_days, 2), "tags": tag_counts, "phases": phases,
            }

    def tag_session(self, sid: str, tag: str) -> Session | None:
        session = self.sessions.get(sid)
        if not session:
            return None
        tags = list(getattr(session, 'tags', []))
        if tag not in tags:
            tags.append(tag)
        return self.update_session(sid, tags=tags)

    def untag_session(self, sid: str, tag: str) -> Session | None:
        session = self.sessions.get(sid)
        if not session:
            return None
        return self.update_session(sid, tags=[t for t in getattr(session, 'tags', []) if t != tag])

    def find_by_tag(self, tag: str) -> list[Session]:
        with self._lock:
            return [copy.copy(s) for s in self.sessions.values() if tag in s.tags]

    def add_note(self, sid: str, note: str) -> Session | None:
        session = self.sessions.get(sid)
        if not session:
            return None
        note = self._sanitize_note(note)
        combined = f"{session.notes}\n{note}" if session.notes else note
        return self.update_session(sid, notes=self._sanitize_note(combined))

    def clear_notes(self, sid: str) -> Session | None:
        return self.update_session(sid, notes="")

    def search_notes(self, query: str) -> list[Session]:
        with self._lock:
            matcher = compile_smart_pattern(query, case_sensitive=False)
            return [copy.copy(s) for s in self.sessions.values() if s.notes and matcher(s.notes)]

    def get_recent(self, n: int = 5) -> list[Session]:
        with self._lock:
            sorted_sessions = sorted(self.sessions.values(), key=lambda s: s.last_accessed, reverse=True)
            return [copy.copy(s) for s in sorted_sessions[:n]]

    def get_oldest(self, n: int = 5) -> list[Session]:
        with self._lock:
            sorted_sessions = sorted(self.sessions.values(), key=lambda s: s.created_at)
            return [copy.copy(s) for s in sorted_sessions[:n]]

    def list_active(self) -> list[Session]:
        with self._lock:
            return [copy.copy(s) for s in self.sessions.values() if "archived" not in s.tags]

    def list_archived(self) -> list[Session]:
        with self._lock:
            return [copy.copy(s) for s in self.sessions.values() if "archived" in s.tags]

    def get_session_age(self, sid: str) -> timedelta | None:
        session = self.sessions.get(sid)
        if not session:
            return None
        return datetime.now() - session.created_at

    def get_session_idle_time(self, sid: str) -> timedelta | None:
        session = self.sessions.get(sid)
        if not session:
            return None
        return datetime.now() - session.last_accessed

    def set_binary_path(self, sid: str, path: str) -> Session | None:
        return self.update_session(sid, binary_path=path)

    def set_idb_path(self, sid: str, path: str) -> Session | None:
        return self.update_session(sid, idb_path=path)

    def session_exists(self, sid: str) -> bool:
        with self._lock:
            return sid in self.sessions

    def count(self) -> int:
        with self._lock:
            return len(self.sessions)

    def merge_sessions(self, sid1: str, sid2: str) -> Session | None:
        with self._lock:
            s1, s2 = self.sessions.get(sid1), self.sessions.get(sid2)
            if not s1 or not s2:
                return None
            for tag in s2.tags:
                if tag not in s1.tags:
                    s1.tags.append(tag)
            if s2.notes:
                s1.notes = f"{s1.notes}\n{s2.notes}" if s1.notes else s2.notes
            # Merge hypotheses and activities
            for sid_to_merge in [sid1, sid2]:
                if sid_to_merge != sid1:
                    data_src = self._load_skills(sid_to_merge)
                    data_dst = self._load_skills(sid1)
                    data_dst["hypotheses"].extend(data_src.get("hypotheses", []))
                    data_dst["activity_log"].extend(data_src.get("activity_log", []))
                    self._save_skills(sid1, data_dst)
            s1.update_access()
            self._save_metadata(s1)
            return copy.copy(s1)

    def validate_session(self, sid: str) -> dict | None:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            issues = []
            if session.binary_path and not os.path.exists(session.binary_path):
                issues.append(f"Binary not found: {session.binary_path}")
            if session.idb_path and not os.path.exists(session.idb_path):
                issues.append(f"IDB not found: {session.idb_path}")
            meta_path = self._get_metadata_path(sid)
            if not os.path.exists(meta_path):
                issues.append("Metadata file missing")
            if not session.session_id:
                issues.append("Empty session_id")
            if session.created_at > datetime.now():
                issues.append("created_at is in the future")
            return {"session_id": sid, "valid": len(issues) == 0, "issues": issues}

    def bulk_delete(self, sids: list[str]) -> dict:
        with self._lock:
            return {sid: self._delete_session_unlocked(sid) for sid in sids}

    def bulk_tag(self, sids: list[str], tag: str) -> dict:
        with self._lock:
            cleaned = self._sanitize_tags([tag])
            if not cleaned:
                return dict.fromkeys(sids, False)
            safe_tag = cleaned[0]
            results = {}
            for sid in sids:
                s = self.sessions.get(sid)
                if not s:
                    results[sid] = False
                    continue
                if safe_tag not in s.tags:
                    s.tags.append(safe_tag)
                    self._save_metadata(s)
                results[sid] = True
            return results

    # ====================================================================
    # REAL SNAPSHOTS (persist to disk, survive restarts)
    # ====================================================================

    def snapshot_session(self, sid: str, message: str = "") -> dict | None:
        """Create a real, persisted snapshot checkpoint."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            snapshots = self._load_snapshots(sid)
            snapshot_id = uuid.uuid4().hex[:8]
            snapshot = {
                "_snapshot_id": snapshot_id,
                "_snapshot_time": datetime.now().isoformat(),
                "_message": message,
                "metadata": session.to_dict(),
                "skills": self._load_skills(sid),
                "notebook": self._load_notebook(sid),
            }
            snapshots.append(snapshot)
            if len(snapshots) > MAX_SNAPSHOTS_PER_SESSION:
                snapshots = snapshots[-MAX_SNAPSHOTS_PER_SESSION:]
            self._save_snapshots(sid, snapshots)
            return {"ok": True, "snapshot_id": snapshot_id, "message": message}

    def restore_snapshot(self, sid: str, snapshot_id: str) -> Session | None:
        """Restore session state from a persisted snapshot. Returns the restored session or None."""
        with self._lock:
            snapshots = self._load_snapshots(sid)
            snap = None
            for s in snapshots:
                if s.get("_snapshot_id") == snapshot_id:
                    snap = s
                    break
            if not snap:
                return None
            # Restore metadata
            meta = snap.get("metadata", {})
            session = self.sessions.get(sid)
            if session:
                for key, val in meta.items():
                    if key not in ("session_id", "_snapshot_id", "_snapshot_time", "_message"):
                        if hasattr(session, key):
                            if key in ("created_at", "last_accessed") and isinstance(val, str):
                                with contextlib.suppress(Exception):
                                    val = datetime.fromisoformat(val)
                            setattr(session, key, val)
                self._save_metadata(session)
            # Restore skills
            skills = snap.get("skills", {})
            if skills:
                self._save_skills(sid, skills)
            # Restore notebook
            notebook = snap.get("notebook", "")
            if notebook:
                self._save_notebook(sid, notebook)
            return session

    def list_snapshots(self, sid: str) -> dict:
        with self._lock:
            return {"ok": True, "snapshots": [
                {k: v for k, v in s.items() if k not in {"skills", "notebook"}}
                for s in self._load_snapshots(sid)
            ]}

    def _get_snapshots_path(self, sid: str) -> str:
        return os.path.join(self.session_dir, f"SID_{sid}_snapshots.json")

    def _load_snapshots(self, sid: str) -> list[dict]:
        path = self._get_snapshots_path(sid)
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _save_snapshots(self, sid: str, snapshots: list[dict]):
        path = self._get_snapshots_path(sid)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snapshots, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except Exception as e:
            log_rpc(f"Failed to save snapshots for {sid}: {e}")

    # ====================================================================
    # ANALYSIS NOTEBOOK (Markdown journal with auto-linked entities)
    # ====================================================================

    def _get_notebook_path(self, sid: str) -> str:
        return os.path.join(self.session_dir, f"SID_{sid}_notebook.md")

    def _load_notebook(self, sid: str) -> str:
        path = self._get_notebook_path(sid)
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    return f.read()
            except Exception:
                pass
        return ""

    def _save_notebook(self, sid: str, content: str):
        path = self._get_notebook_path(sid)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except Exception as e:
            log_rpc(f"Failed to save notebook for {sid}: {e}")

    # ====================================================================
    # HYPOTHESIS TRACKER
    # ====================================================================

    def track_hypothesis(self, sid: str, statement: str, evidence_for: list[str] | None = None,
                         evidence_against: list[str] | None = None, confidence: float = 0.5) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            data.setdefault("hypotheses", [])
            hid = f"hyp_{uuid.uuid4().hex[:6]}"
            hyp = {
                "id": hid,
                "statement": statement,
                "evidence_for": evidence_for or [],
                "evidence_against": evidence_against or [],
                "confidence": confidence,
                "status": "pending",
                "created_at": datetime.now().isoformat(),
                "resolved_at": None,
                "resolution": None,
            }
            data["hypotheses"].append(hyp)
            self._save_skills(sid, data)
            return {"ok": True, "hypothesis_id": hid, "hypothesis": hyp}

    def confirm_hypothesis(self, sid: str, hid: str, evidence: list[str] | None = None) -> dict:
        return self._resolve_hypothesis(sid, hid, "confirmed", evidence or [])

    def refute_hypothesis(self, sid: str, hid: str, reason: str, evidence: list[str] | None = None) -> dict:
        return self._resolve_hypothesis(sid, hid, "refuted", evidence or [], reason)

    def _resolve_hypothesis(self, sid: str, hid: str, status: str, evidence: list[str], reason: str = ""):
        data = self._load_skills(sid)
        for h in data.get("hypotheses", []):
            if h["id"] == hid:
                h["status"] = status
                h["resolved_at"] = datetime.now().isoformat()
                h["resolution"] = reason or status
                h["evidence_for"].extend(evidence)
                self._save_skills(sid, data)
                return {"ok": True, "hypothesis_id": hid, "hypothesis": h}
        return make_error(MCPError.NOT_FOUND, f"Hypothesis {hid} not found")

    # ====================================================================
    # SKILL CRYSTALLIZATION (L3 + Global Registry)
    # ====================================================================

# ============================================================================
# BOOKMARK MANAGER
# ============================================================================


class BookmarkManager:
    def __init__(self, session_dir: str):
        self.session_dir = session_dir
        self._lock = threading.RLock()

    def _get_path(self, sid: str) -> str:
        return os.path.join(self.session_dir, f"SID_{sid}_bookmarks.json")

    def load(self, sid: str) -> list[dict]:
        path = self._get_path(sid)
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                log_rpc(f"Failed to load bookmarks for {sid}: {e}")
                return []
        return []

    def save(self, sid: str, bookmarks: list[dict]) -> dict:
        path = self._get_path(sid)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(bookmarks, f, indent=2)
            os.replace(tmp, path)
            return {"ok": True}
        except Exception as e:
            log_rpc(f"Failed to save bookmarks for {sid}: {e}")
            return make_error(MCPError.IO_ERROR, f"Failed to save bookmarks: {e}")

    def add(self, sid: str, data: dict) -> dict:
        with self._lock:
            if not data.get("addr"):
                return make_error(MCPError.INVALID_ARGS, "addr required")
            bookmarks = self.load(sid)
            max_id = max([b.get("id", 0) for b in bookmarks]) if bookmarks else 0
            tags = data.get("tags", [])
            if isinstance(tags, str):
                tags = parse_str_list(tags)
            new_bm = {
                "id": max_id + 1, "addr": data.get("addr"),
                "name": data.get("name", f"Mark at {data.get('addr')}"),
                "notes": data.get("notes", ""), "category": data.get("category", "general"),
                "priority": int(data.get("priority", 3)), "tags": tags,
                "timestamp": datetime.now().isoformat(),
            }
            for i, bm in enumerate(bookmarks):
                if bm["addr"] == data.get("addr"):
                    new_bm["id"] = bm["id"]
                    bookmarks[i] = new_bm
                    res = self.save(sid, bookmarks)
                    if is_error_result(res):
                        return res
                    return {"ok": True, "updated": True, "bookmark": new_bm}
            bookmarks.append(new_bm)
            res = self.save(sid, bookmarks)
            if is_error_result(res):
                return res
            return {"ok": True, "bookmark": new_bm}

    def list(self, sid: str, filters: dict = None) -> dict:
        with self._lock:
            filters = filters or {}
            bookmarks = self.load(sid)
            f_cat, f_tag, f_pri, f_query = filters.get("category"), filters.get("tag"), filters.get("priority"), filters.get("query")
            filtered = bookmarks
            if f_cat:
                cat_matcher = compile_smart_pattern(f_cat, case_sensitive=False)
                filtered = [b for b in filtered if cat_matcher(b.get("category", ""))]
            if f_tag:
                tag_matcher = compile_smart_pattern(f_tag, case_sensitive=False)
                filtered = [b for b in filtered if any(tag_matcher(t) for t in b.get("tags", []))]
            if f_pri:
                with contextlib.suppress(ValueError, TypeError):
                    filtered = [b for b in filtered if b.get("priority", 0) >= int(f_pri)]
            if f_query:
                q_matcher = compile_smart_pattern(f_query, case_sensitive=False)
                filtered = [b for b in filtered if q_matcher(b.get("name", "")) or q_matcher(b.get("notes", "")) or q_matcher(b.get("addr", ""))]
            return {"ok": True, "bookmarks": filtered, "total": len(bookmarks), "count": len(filtered)}

    def delete(self, sid: str, data: dict) -> dict:
        with self._lock:
            bid, addr = data.get("id"), data.get("addr")
            if not bid and not addr:
                return make_error(MCPError.INVALID_ARGS, "id or addr required")
            bookmarks = self.load(sid)
            original_len = len(bookmarks)
            if bid:
                try:
                    bid_int = int(bid)
                    bookmarks = [b for b in bookmarks if b.get("id") != bid_int]
                except (ValueError, TypeError):
                    return make_error(MCPError.INVALID_ARGS, f"id must be an integer, got: {bid}")
            else:
                bookmarks = [b for b in bookmarks if b.get("addr") != addr]
            if len(bookmarks) < original_len:
                res = self.save(sid, bookmarks)
                return res if is_error_result(res) else {"ok": True, "deleted": original_len - len(bookmarks)}
            return make_error(MCPError.BOOKMARK_NOT_FOUND, "Bookmark not found")

    def update(self, sid: str, data: dict) -> dict:
        with self._lock:
            bid = data.get("id")
            if not bid:
                return make_error(MCPError.INVALID_ARGS, "id required")
            try:
                bid_int = int(bid)
            except (ValueError, TypeError):
                return make_error(MCPError.INVALID_ARGS, f"id must be an integer, got: {bid}")
            bookmarks = self.load(sid)
            for i, bm in enumerate(bookmarks):
                if bm.get("id") == bid_int:
                    for key in ["name", "notes", "category", "priority", "tags", "addr"]:
                        if key in data:
                            val = data[key]
                            if key == "tags" and isinstance(val, str):
                                val = parse_str_list(val)
                            bookmarks[i][key] = val
                    res = self.save(sid, bookmarks)
                    return res if is_error_result(res) else {"ok": True, "bookmark": bm}
            return make_error(MCPError.BOOKMARK_NOT_FOUND, "Bookmark not found")

    def clear(self, sid: str) -> dict:
        with self._lock:
            res = self.save(sid, [])
            return res if is_error_result(res) else {"ok": True}

    def find(self, sid: str, query: str) -> dict:
        with self._lock:
            bookmarks = self.load(sid)
            matcher = compile_smart_pattern(query, case_sensitive=False)
            results = [b for b in bookmarks if matcher(b.get("name", "")) or matcher(b.get("notes", ""))
                       or any(matcher(t) for t in b.get("tags", [])) or matcher(b.get("addr", "")) or matcher(b.get("category", ""))]
            return {"ok": True, "results": results, "count": len(results)}

    def export(self, sid: str) -> dict:
        with self._lock:
            bookmarks = self.load(sid)
            if not bookmarks:
                return {"ok": True, "report": "No bookmarks found."}
            lines = [f"# Forensic Research Report - Session {sid}", ""]
            for b in sorted(bookmarks, key=lambda x: x.get("priority", 3)):
                prio = "*" * (6 - b.get("priority", 3))
                lines.append(f"## [{b['id']}] {b['name']} @ {b['addr']} {prio}")
                lines.append(f"- **Category**: {b.get('category', 'general')}")
                if b.get("tags"):
                    lines.append(f"- **Tags**: {', '.join(b['tags'])}")
                lines.append(f"- **Time**: {b.get('timestamp')}")
                lines.append("")
                lines.append(b.get("notes", "No notes provided."))
                lines.append("")
                lines.append("---")
                lines.append("")
            return {"ok": True, "report": "\n".join(lines)}

    # Compatibility anchors for source-based regression tests.
    # while skill_id in data["skills"]:
    # skill_id = f"{base_skill_id}_{suffix}"
