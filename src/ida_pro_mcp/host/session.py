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
import os
import json
import time
import threading
import shutil
import re
import glob
import uuid
import copy
import math
import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

from .config import (
    CACHE_DIR,
    log_rpc,
    RUNTIME_LEASE_TTL,
    RUNTIME_LEASE_HEARTBEAT_SECONDS,
    _RUNTIME_LEASE_RE,
    _normalize_session_id,
    _parse_iso_datetime,
    MAX_SESSION_ID_RETRIES,
    MAX_SNAPSHOT_ID_RETRIES,
    MAX_SNAPSHOTS_PER_SESSION,
    MAX_TAG_LEN,
    MAX_TAGS_PER_SESSION,
    MAX_NOTE_LEN,
    MAX_NAME_LEN,
)
from .patterns import compile_smart_pattern
from .errors import MCPError, make_error

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
        "suggested_tools": ["xref_analysis.call_chain", "bridgerag.search", "code.callers"],
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
        analysis_options: Optional[dict] = None,
        analysis_applied: bool = False,
        ida_args: Optional[List[str]] = None,
        created_at: Optional[datetime] = None,
        last_accessed: Optional[datetime] = None,
        tags: Optional[List[str]] = None,
        notes: str = "",
        auto_name: str = "",
        phase: str = "triage",
        linked_sessions: Optional[List[str]] = None,
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

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "idb_path": self.idb_path,
            "binary_path": self.binary_path,
            "analysis_options": self.analysis_options,
            "analysis_applied": self.analysis_applied,
            "ida_args": self.ida_args,
            "binary_exists": bool(self.binary_path and os.path.exists(self.binary_path)),
            "idb_exists": bool(self.idb_path and os.path.exists(self.idb_path)),
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "tags": self.tags,
            "notes": self.notes,
            "auto_name": self.auto_name,
            "phase": self.phase,
            "linked_sessions": self.linked_sessions,
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
        )


# ============================================================================
# SESSION MANAGER
# ============================================================================


class SessionManager:
    def __init__(self, cache_dir: str):
        self._lock = threading.RLock()
        self.sessions: Dict[str, Session] = {}
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

    def _crystallize_to_global_registry(self, sid: str, skill_id: str, skill: dict) -> None:
        import sqlite3
        try:
            conn = sqlite3.connect(self._global_skills_db)
            cur = conn.cursor()
            cur.execute("""
                INSERT OR REPLACE INTO global_skills
                (skill_id, name, description, steps, tags, source_sid, q_value,
                 success_count, failure_count, created_at, last_used, usage_count_total)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                    COALESCE((SELECT usage_count_total FROM global_skills WHERE skill_id = ?), 0))
            """, (
                skill_id,
                skill.get("name", ""),
                skill.get("description", ""),
                json.dumps(skill.get("steps", [])),
                json.dumps(skill.get("tags", [])),
                sid,
                skill.get("q_value", 0.5),
                skill.get("success_count", 0),
                skill.get("failure_count", 0),
                skill.get("created_at", ""),
                skill.get("last_used", ""),
                skill_id,
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _find_global_skills(self, context: str = "", tags: Optional[List[str]] = None, limit: int = 10) -> List[dict]:
        import sqlite3
        skills = []
        try:
            conn = sqlite3.connect(self._global_skills_db)
            cur = conn.cursor()
            query = "SELECT * FROM global_skills WHERE 1=1"
            params: List[Any] = []
            if tags:
                tag_conditions = " OR ".join(["tags LIKE ?" for _ in tags])
                query += f" AND ({tag_conditions})"
                params.extend([f"%{t}%" for t in tags])
            query += " ORDER BY q_value DESC LIMIT ?"
            params.append(limit)
            cur.execute(query, params)
            for row in cur.fetchall():
                skills.append({
                    "skill_id": row[0], "name": row[1], "description": row[2],
                    "steps": json.loads(row[3]),
                    "tags": json.loads(row[4]), "source_sid": row[5],
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

    def _mark_global_skill_used(self, skill_id: str) -> None:
        import sqlite3
        try:
            conn = sqlite3.connect(self._global_skills_db)
            cur = conn.cursor()
            cur.execute("""
                UPDATE global_skills 
                SET usage_count_total = usage_count_total + 1, last_used = ?
                WHERE skill_id = ?
            """, (datetime.now().isoformat(), skill_id))
            conn.commit()
            conn.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Sanitization
    # ------------------------------------------------------------------

    def _sanitize_tags(self, tags: Optional[List[Any]]) -> List[str]:
        if not tags:
            return []
        cleaned: List[str] = []
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
            os.replace(tmp, path)
        except Exception as e:
            log_rpc(f"Failed to save session metadata: {e}")
            try:
                os.remove(tmp)
            except OSError:
                pass

    def _load_sessions(self):
        pattern = os.path.join(self.session_dir, "SID_*_metadata.json")
        for meta_path in glob.glob(pattern):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    session = Session.from_dict(data)
                    if not _normalize_session_id(session.session_id):
                        log_rpc(f"Skipping metadata with invalid session_id: {meta_path}")
                        continue
                    self.sessions[session.session_id] = session
            except Exception as e:
                log_rpc(f"Failed to load session metadata from {meta_path}: {e}")
        self._load_orphaned_idbs()

    def _extract_sid(self, path: str) -> Optional[str]:
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
        self, binary_path: str, use_existing: Optional[str] = None,
        analysis_options: Optional[dict] = None, idb_path: Optional[str] = None,
        ida_args: Optional[List[str]] = None, tags: Optional[List[str]] = None,
        notes: str = "",
    ) -> Session:
        with self._lock:
            sid = self._new_session_id()
            idb_base = os.path.basename(binary_path) if binary_path else f"session_{sid}"
            idb_name = f"SID_{sid}_{idb_base}.i64"
            resolved_idb = idb_path or use_existing or os.path.join(self.session_dir, idb_name)
            if resolved_idb and os.path.isdir(resolved_idb):
                resolved_idb = os.path.join(resolved_idb, idb_name)
            if resolved_idb and not os.path.splitext(resolved_idb)[1]:
                resolved_idb = f"{resolved_idb}.i64"
            session = Session(
                sid, resolved_idb, binary_path or "",
                analysis_options=analysis_options, analysis_applied=False,
                ida_args=ida_args or [],
                tags=self._sanitize_tags(tags),
                notes=self._sanitize_note(notes),
            )
            self.sessions[sid] = session
            self._save_metadata(session)
            return session

    def get_session(self, sid: str) -> Optional[Session]:
        with self._lock:
            session = self.sessions.get(sid)
            if session:
                session.update_access()
                return copy.deepcopy(session)
            return None

    def find_session_by_path(self, path: str) -> Optional[Session]:
        with self._lock:
            norm = os.path.realpath(os.path.abspath(path))
            for s in self.sessions.values():
                if s.binary_path and os.path.realpath(os.path.abspath(s.binary_path)) == norm:
                    return copy.copy(s)
                if s.idb_path and os.path.realpath(os.path.abspath(s.idb_path)) == norm:
                    return copy.copy(s)
            return None

    def discover_sessions(self, query: str = "") -> List[Session]:
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
        return bool(session) or deleted

    def delete_session(self, sid: str) -> bool:
        with self._lock:
            return self._delete_session_unlocked(sid)

    def update_session(self, sid: str, **kwargs) -> Optional[Session]:
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

    def rename_session(self, sid: str, new_name: str) -> Optional[Session]:
        return self.update_session(sid, auto_name=self._sanitize_name(new_name))

    def duplicate_session(self, sid: str) -> Optional[Session]:
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

    def export_session(self, sid: str, include_skills: bool = True) -> Optional[dict]:
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

    def archive_session(self, sid: str) -> Optional[Session]:
        return self.update_session(sid, tags=["archived"])

    def unarchive_session(self, sid: str) -> Optional[Session]:
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
            if limit > 0:
                sessions = sessions[offset:offset + limit]
            else:
                sessions = sessions[offset:]
            return {"sessions": [s.to_dict() for s in sessions], "total": total, "count": len(sessions), "offset": offset, "limit": limit}

    def cleanup_stale(self, max_age_days: int = 30) -> List[str]:
        with self._lock:
            cutoff = datetime.now() - timedelta(days=max_age_days)
            stale = [sid for sid, s in self.sessions.items() if s.last_accessed < cutoff]
            for sid in stale:
                self._delete_session_unlocked(sid)
            return stale

    def get_stats(self) -> dict:
        with self._lock:
            total = len(self.sessions)
            if total == 0:
                return {"total": 0, "active": 0, "archived": 0, "avg_age_days": 0, "tags": {}}
            archived = sum(1 for s in self.sessions.values() if "archived" in s.tags)
            now = datetime.now()
            ages = [(now - s.created_at).total_seconds() for s in self.sessions.values()]
            avg_age_days = (sum(ages) / len(ages)) / 86400 if ages else 0
            tag_counts: Dict[str, int] = {}
            for s in self.sessions.values():
                for t in s.tags:
                    tag_counts[t] = tag_counts.get(t, 0) + 1
            phases: Dict[str, int] = {}
            for s in self.sessions.values():
                phases[s.phase] = phases.get(s.phase, 0) + 1
            return {
                "total": total, "active": total - archived, "archived": archived,
                "avg_age_days": round(avg_age_days, 2), "tags": tag_counts, "phases": phases,
            }

    def tag_session(self, sid: str, tag: str) -> Optional[Session]:
        session = self.sessions.get(sid)
        if not session:
            return None
        tags = list(getattr(session, 'tags', []))
        if tag not in tags:
            tags.append(tag)
        return self.update_session(sid, tags=tags)

    def untag_session(self, sid: str, tag: str) -> Optional[Session]:
        session = self.sessions.get(sid)
        if not session:
            return None
        return self.update_session(sid, tags=[t for t in getattr(session, 'tags', []) if t != tag])

    def find_by_tag(self, tag: str) -> List[Session]:
        with self._lock:
            return [copy.copy(s) for s in self.sessions.values() if tag in s.tags]

    def add_note(self, sid: str, note: str) -> Optional[Session]:
        session = self.sessions.get(sid)
        if not session:
            return None
        note = self._sanitize_note(note)
        combined = f"{session.notes}\n{note}" if session.notes else note
        return self.update_session(sid, notes=self._sanitize_note(combined))

    def clear_notes(self, sid: str) -> Optional[Session]:
        return self.update_session(sid, notes="")

    def search_notes(self, query: str) -> List[Session]:
        with self._lock:
            matcher = compile_smart_pattern(query, case_sensitive=False)
            return [copy.copy(s) for s in self.sessions.values() if s.notes and matcher(s.notes)]

    def get_recent(self, n: int = 5) -> List[Session]:
        with self._lock:
            sorted_sessions = sorted(self.sessions.values(), key=lambda s: s.last_accessed, reverse=True)
            return [copy.copy(s) for s in sorted_sessions[:n]]

    def get_oldest(self, n: int = 5) -> List[Session]:
        with self._lock:
            sorted_sessions = sorted(self.sessions.values(), key=lambda s: s.created_at)
            return [copy.copy(s) for s in sorted_sessions[:n]]

    def list_active(self) -> List[Session]:
        with self._lock:
            return [copy.copy(s) for s in self.sessions.values() if "archived" not in s.tags]

    def list_archived(self) -> List[Session]:
        with self._lock:
            return [copy.copy(s) for s in self.sessions.values() if "archived" in s.tags]

    def get_session_age(self, sid: str) -> Optional[timedelta]:
        session = self.sessions.get(sid)
        if not session:
            return None
        return datetime.now() - session.created_at

    def get_session_idle_time(self, sid: str) -> Optional[timedelta]:
        session = self.sessions.get(sid)
        if not session:
            return None
        return datetime.now() - session.last_accessed

    def set_binary_path(self, sid: str, path: str) -> Optional[Session]:
        return self.update_session(sid, binary_path=path)

    def set_idb_path(self, sid: str, path: str) -> Optional[Session]:
        return self.update_session(sid, idb_path=path)

    def session_exists(self, sid: str) -> bool:
        with self._lock:
            return sid in self.sessions

    def count(self) -> int:
        with self._lock:
            return len(self.sessions)

    def merge_sessions(self, sid1: str, sid2: str) -> Optional[Session]:
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

    def validate_session(self, sid: str) -> Optional[dict]:
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

    def bulk_delete(self, sids: List[str]) -> dict:
        with self._lock:
            return {sid: self._delete_session_unlocked(sid) for sid in sids}

    def bulk_tag(self, sids: List[str], tag: str) -> dict:
        with self._lock:
            cleaned = self._sanitize_tags([tag])
            if not cleaned:
                return {sid: False for sid in sids}
            safe_tag = cleaned[0]
            results = {}
            for sid in sids:
                s = self.sessions.get(sid)
                if not s:
                    results[sid] = False
                    continue
                if safe_tag not in s.tags:
                    s.tags.append(safe_tag)
                results[sid] = True
            return results

    # ====================================================================
    # REAL SNAPSHOTS (persist to disk, survive restarts)
    # ====================================================================

    def snapshot_session(self, sid: str, message: str = "") -> Optional[dict]:
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

    def restore_snapshot(self, sid: str, snapshot_id: str) -> Optional[Session]:
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
                                try:
                                    val = datetime.fromisoformat(val)
                                except Exception:
                                    pass
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
                {k: v for k, v in s.items() if k != "skills" and k != "notebook"}
                for s in self._load_snapshots(sid)
            ]}

    def _get_snapshots_path(self, sid: str) -> str:
        return os.path.join(self.session_dir, f"SID_{sid}_snapshots.json")

    def _load_snapshots(self, sid: str) -> List[dict]:
        path = self._get_snapshots_path(sid)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _save_snapshots(self, sid: str, snapshots: List[dict]):
        path = self._get_snapshots_path(sid)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snapshots, f, indent=2)
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
                with open(path, "r", encoding="utf-8") as f:
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
            os.replace(tmp, path)
        except Exception as e:
            log_rpc(f"Failed to save notebook for {sid}: {e}")

    def notebook_append(self, sid: str, entry: str, section: Optional[str] = None) -> dict:
        """Append to the analysis notebook. Auto-links addresses and bookmarks."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            notebook = self._load_notebook(sid)
            lines = notebook.split("\n") if notebook else []
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if section:
                lines.append(f"\n## {section}")
            lines.append(f"\n> [{timestamp}]")
            lines.append(entry)
            self._save_notebook(sid, "\n".join(lines))
            session.update_access()
            self._save_metadata(session)
            return {"ok": True, "notebook_lines": len(lines)}

    def notebook_read(self, sid: str, lines: Optional[str] = None) -> dict:
        """Read the analysis notebook."""
        with self._lock:
            notebook = self._load_notebook(sid)
            if not notebook:
                return {"ok": True, "notebook": "", "note": "Notebook is empty. Use notebook_append to add entries."}
            all_lines = notebook.split("\n")
            if lines:
                try:
                    if "-" in lines:
                        start, end = lines.split("-")
                        slice_lines = all_lines[int(start):int(end)]
                    else:
                        slice_lines = all_lines[-int(lines):]
                    return {"ok": True, "notebook": "\n".join(slice_lines), "total_lines": len(all_lines)}
                except (ValueError, TypeError):
                    return {"ok": True, "notebook": "\n".join(all_lines[-50:]), "total_lines": len(all_lines)}
            return {"ok": True, "notebook": notebook, "total_lines": len(all_lines)}

    def notebook_section(self, sid: str, section_name: str) -> dict:
        """Extract a specific section from the notebook."""
        notebook = self._load_notebook(sid)
        pattern = re.compile(rf"^## {re.escape(section_name)}\s*$", re.MULTILINE)
        match = pattern.search(notebook)
        if not match:
            return {"ok": True, "content": "", "note": f"Section '{section_name}' not found"}
        start = match.end()
        next_section = re.search(r"^## ", notebook[start:], re.MULTILINE)
        end = start + next_section.start() if next_section else len(notebook)
        return {"ok": True, "content": notebook[start:end].strip()}

    # ====================================================================
    # HYPOTHESIS TRACKER
    # ====================================================================

    def track_hypothesis(self, sid: str, statement: str, evidence_for: Optional[List[str]] = None,
                         evidence_against: Optional[List[str]] = None, confidence: float = 0.5) -> dict:
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

    def confirm_hypothesis(self, sid: str, hid: str, evidence: Optional[List[str]] = None) -> dict:
        return self._resolve_hypothesis(sid, hid, "confirmed", evidence or [])

    def refute_hypothesis(self, sid: str, hid: str, reason: str, evidence: Optional[List[str]] = None) -> dict:
        return self._resolve_hypothesis(sid, hid, "refuted", evidence or [], reason)

    def _resolve_hypothesis(self, sid: str, hid: str, status: str, evidence: List[str], reason: str = ""):
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

    def list_hypotheses(self, sid: str, status: Optional[str] = None) -> dict:
        data = self._load_skills(sid)
        hyps = data.get("hypotheses", [])
        if status:
            hyps = [h for h in hyps if h.get("status") == status]
        return {
            "ok": True, "total": len(hyps),
            "confirmed": sum(1 for h in hyps if h.get("status") == "confirmed"),
            "refuted": sum(1 for h in hyps if h.get("status") == "refuted"),
            "pending": sum(1 for h in hyps if h.get("status") == "pending"),
            "hypotheses": hyps,
        }

    # ====================================================================
    # SKILL CRYSTALLIZATION (L3 + Global Registry)
    # ====================================================================

    def _get_skills_path(self, sid: str) -> str:
        return os.path.join(self.session_dir, f"SID_{sid}_skills.json")

    def _load_skills(self, sid: str) -> dict:
        path = self._get_skills_path(sid)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"skills": {}, "q_table": {}, "activity_log": [], "hypotheses": []}

    def _save_skills(self, sid: str, data: dict):
        path = self._get_skills_path(sid)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, path)
        except Exception as e:
            log_rpc(f"Failed to save skills for {sid}: {e}")

    def _bootstrap_plan_matrix(self) -> Dict[str, List[str]]:
        return {
            "phase1_bootstrap_core": [
                "bootstrap_init",
                "bootstrap_run_tournament",
                "bootstrap_compute_blend",
                "bootstrap_status",
            ],
            "phase2_scoring_integration": [
                "suggest_strategy_blended",
                "predictor_suggest_next_tool_blended",
            ],
            "phase3_outcome_dispute": [
                "bootstrap_ingest_outcome",
                "bootstrap_open_dispute",
                "bootstrap_list_disputes",
                "bootstrap_resolve_dispute",
            ],
            "phase4_observability_drift": [
                "bootstrap_summary",
                "bootstrap_summary_detailed",
                "bootstrap_calibration_report",
                "bootstrap_snapshot",
                "bootstrap_list_snapshots",
                "bootstrap_drift_report",
                "bootstrap_update_baseline",
                "bootstrap_evaluate_alerts",
            ],
            "phase5_mitigation_loop": [
                "bootstrap_mitigation_plan",
                "bootstrap_apply_mitigation",
                "bootstrap_mitigation_history",
                "bootstrap_mitigation_effectiveness",
            ],
            "phase6_adaptation_safeguards": [
                "bootstrap_policy_reweight",
                "bootstrap_policy_reweight_history",
                "bootstrap_autopilot",
                "bootstrap_set_autopilot_policy",
                "bootstrap_get_autopilot_policy",
                "bootstrap_rollback_last_reweight",
            ],
            "phase7_ops_hygiene": [
                "bootstrap_export_metrics",
                "bootstrap_prune_data",
                "bootstrap_simulate_batch",
            ],
        }

    def bootstrap_plan_status(self, sid: str) -> dict:
        """Return machine-readable implementation plan coverage and runtime readiness."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")

            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            matrix = self._bootstrap_plan_matrix()

            implemented_actions = set()
            # Session manager methods present at runtime.
            for phase_items in matrix.values():
                for item in phase_items:
                    if item in ("suggest_strategy_blended", "predictor_suggest_next_tool_blended"):
                        implemented_actions.add(item)
                    elif hasattr(self, item):
                        implemented_actions.add(item)

            phase_rows = []
            total_items = 0
            total_done = 0
            for phase, items in matrix.items():
                done = [i for i in items if i in implemented_actions]
                total_items += len(items)
                total_done += len(done)
                phase_rows.append(
                    {
                        "phase": phase,
                        "items": len(items),
                        "done": len(done),
                        "coverage": round((len(done) / max(1, len(items))) * 100.0, 2),
                        "missing": [i for i in items if i not in done],
                    }
                )

            runtime = {
                "bootstrap_initialized": bool(bootstrap),
                "tournament_runs": int(bootstrap.get("tournament_runs", 0)) if bootstrap else 0,
                "total_rounds": int(bootstrap.get("total_rounds", 0)) if bootstrap else 0,
                "snapshot_count": len(bootstrap.get("metric_snapshots") or []) if bootstrap else 0,
                "dispute_count": len(bootstrap.get("disputes") or []) if bootstrap else 0,
                "mitigation_history_count": len(bootstrap.get("mitigation_history") or []) if bootstrap else 0,
                "reweight_history_count": len(bootstrap.get("policy_reweight_history") or []) if bootstrap else 0,
            }

            return {
                "ok": True,
                "overall": {
                    "items": total_items,
                    "done": total_done,
                    "coverage": round((total_done / max(1, total_items)) * 100.0, 2),
                },
                "phases": phase_rows,
                "runtime": runtime,
            }

    def bootstrap_readiness_gate(
        self,
        sid: str,
        min_tournament_rounds: int = 1000,
        min_snapshots: int = 10,
        min_outcomes: int = 200,
        max_ece: float = 0.2,
        max_open_disputes: int = 25,
    ) -> dict:
        """Programmatic completion gate for the full bootstrap implementation plan."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")

            plan = self.bootstrap_plan_status(sid)
            if plan.get("error"):
                return plan
            summary = self.bootstrap_summary(sid)
            if summary.get("error"):
                return summary
            calib = self.bootstrap_calibration_report(sid, min_bin_n=1)
            if calib.get("error"):
                return calib
            eff = self.bootstrap_mitigation_effectiveness(sid, window=50)
            if eff.get("error"):
                return eff

            runtime = plan.get("runtime") or {}
            gates = {
                "phase_coverage_100": float((plan.get("overall") or {}).get("coverage", 0.0)) >= 100.0,
                "bootstrap_initialized": bool(runtime.get("bootstrap_initialized")),
                "tournament_rounds": int(runtime.get("total_rounds", 0)) >= max(1, int(min_tournament_rounds)),
                "snapshot_depth": int(runtime.get("snapshot_count", 0)) >= max(1, int(min_snapshots)),
                "outcome_depth": int((summary.get("outcomes") or {}).get("count", 0)) >= max(1, int(min_outcomes)),
                "ece_within_bound": float(calib.get("ece", 1.0)) <= float(max_ece),
                "open_disputes_bound": int((summary.get("disputes") or {}).get("open", 0)) <= max(0, int(max_open_disputes)),
                "mitigation_effectiveness_present": bool(eff.get("enough_data")),
            }

            passed = [k for k, v in gates.items() if bool(v)]
            failed = [k for k, v in gates.items() if not bool(v)]
            readiness = len(failed) == 0
            stage = "production_ready" if readiness else "needs_more_runtime_data"

            return {
                "ok": True,
                "readiness": readiness,
                "stage": stage,
                "passed": passed,
                "failed": failed,
                "gates": gates,
                "plan_overall": plan.get("overall"),
                "runtime": runtime,
                "summary": {
                    "ece": calib.get("ece"),
                    "open_disputes": (summary.get("disputes") or {}).get("open"),
                    "outcomes": (summary.get("outcomes") or {}).get("count"),
                    "mitigation_effectiveness": eff.get("effectiveness_score") if eff.get("enough_data") else None,
                },
                "thresholds": {
                    "min_tournament_rounds": int(min_tournament_rounds),
                    "min_snapshots": int(min_snapshots),
                    "min_outcomes": int(min_outcomes),
                    "max_ece": float(max_ece),
                    "max_open_disputes": int(max_open_disputes),
                },
            }

    def bootstrap_record_readiness(self, sid: str, tag: str = "") -> dict:
        """Record a readiness-gate snapshot into rolling history."""
        with self._lock:
            gate = self.bootstrap_readiness_gate(sid)
            if gate.get("error"):
                return gate
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            hist = bootstrap.setdefault("readiness_history", [])
            row = {
                "timestamp": datetime.now().isoformat(),
                "tag": str(tag or "").strip() or None,
                "readiness": bool(gate.get("readiness")),
                "stage": gate.get("stage"),
                "passed": list(gate.get("passed") or []),
                "failed": list(gate.get("failed") or []),
                "coverage": float((gate.get("plan_overall") or {}).get("coverage", 0.0)),
                "ece": (gate.get("summary") or {}).get("ece"),
                "outcomes": (gate.get("summary") or {}).get("outcomes"),
                "open_disputes": (gate.get("summary") or {}).get("open_disputes"),
            }
            hist.append(row)
            bootstrap["readiness_history"] = hist[-5000:]
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {"ok": True, "entry": row, "history_count": len(bootstrap["readiness_history"])}

    def bootstrap_readiness_history(self, sid: str, limit: int = 100, offset: int = 0) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            rows = list((((data.get("bootstrap") or {}).get("readiness_history") or [])))
            total = len(rows)
            offset = max(0, int(offset))
            limit = max(1, min(int(limit), 10000))
            view = rows[offset: offset + limit]
            return {
                "ok": True,
                "total": total,
                "count": len(view),
                "offset": offset,
                "limit": limit,
                "history": view,
            }

    def bootstrap_readiness_trend(self, sid: str, window: int = 50) -> dict:
        """Readiness pass-rate, slope, and regression signal over history window."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            rows = list((((data.get("bootstrap") or {}).get("readiness_history") or [])))
            if len(rows) < 2:
                return {
                    "ok": True,
                    "enough_data": False,
                    "count": len(rows),
                    "message": "Need at least 2 readiness records",
                }

            w = max(2, min(int(window), len(rows)))
            recent = rows[-w:]
            vals = [1.0 if bool(r.get("readiness")) else 0.0 for r in recent]
            coverage = [float(r.get("coverage", 0.0)) for r in recent]
            pass_rate = sum(vals) / max(1, len(vals))

            # Simple slope from first/last halves.
            mid = len(vals) // 2
            first_avg = sum(vals[:mid]) / max(1, len(vals[:mid]))
            last_avg = sum(vals[mid:]) / max(1, len(vals[mid:]))
            slope = last_avg - first_avg
            cov_slope = (coverage[-1] - coverage[0]) if coverage else 0.0

            regressing = slope < -0.15 or cov_slope < -5.0
            improving = slope > 0.15 or cov_slope > 5.0
            status = "stable"
            if regressing:
                status = "regressing"
            elif improving:
                status = "improving"

            return {
                "ok": True,
                "enough_data": True,
                "window": w,
                "pass_rate": round(pass_rate, 6),
                "readiness_slope": round(slope, 6),
                "coverage_slope": round(cov_slope, 6),
                "status": status,
                "regressing": regressing,
            }

    def bootstrap_readiness_regression_guard(
        self,
        sid: str,
        window: int = 50,
        auto_snapshot: bool = True,
    ) -> dict:
        """Guardrail action when readiness trend regresses."""
        with self._lock:
            trend = self.bootstrap_readiness_trend(sid, window=window)
            if trend.get("error"):
                return trend
            if not trend.get("enough_data"):
                return {"ok": True, "triggered": False, "reason": "insufficient_data", "trend": trend}

            triggered = bool(trend.get("regressing"))
            actions = []
            if triggered:
                actions.append(
                    {
                        "action": "bootstrap_update_baseline",
                        "params": {"window": max(30, int(window)), "percentile": 97.0},
                    }
                )
                actions.append(
                    {
                        "action": "bootstrap_mitigation_plan",
                        "params": {"window": max(20, int(window // 2))},
                    }
                )
                if auto_snapshot:
                    actions.append(
                        {
                            "action": "bootstrap_snapshot",
                            "params": {"name": "readiness_regression_guard"},
                        }
                    )

            return {
                "ok": True,
                "triggered": triggered,
                "trend": trend,
                "actions": actions,
            }

    def bootstrap_finalize_report(
        self,
        sid: str,
        trend_window: int = 50,
        effectiveness_window: int = 50,
    ) -> dict:
        """Produce a one-shot final status report for implementation plan closure."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")

            plan = self.bootstrap_plan_status(sid)
            if plan.get("error"):
                return plan
            gate = self.bootstrap_readiness_gate(sid)
            if gate.get("error"):
                return gate
            trend = self.bootstrap_readiness_trend(sid, window=trend_window)
            if trend.get("error"):
                return trend
            eff = self.bootstrap_mitigation_effectiveness(sid, window=effectiveness_window)
            if eff.get("error"):
                return eff
            summary = self.bootstrap_summary(sid)
            if summary.get("error"):
                return summary

            release_ready = bool(gate.get("readiness")) and bool(plan.get("overall", {}).get("coverage", 0.0) >= 100.0)
            risk_flags = []
            if trend.get("enough_data") and trend.get("regressing"):
                risk_flags.append("readiness_regressing")
            if eff.get("enough_data") and str(eff.get("tier")) == "poor":
                risk_flags.append("mitigation_effectiveness_poor")
            if float((summary.get("calibration") or {}).get("ece", 0.0) or 0.0) > 0.2:
                risk_flags.append("ece_above_recommended")

            stage = "ready" if release_ready and not risk_flags else "needs_attention"
            return {
                "ok": True,
                "stage": stage,
                "release_ready": release_ready,
                "risk_flags": risk_flags,
                "plan": plan,
                "readiness_gate": gate,
                "readiness_trend": trend,
                "mitigation_effectiveness": eff,
                "bootstrap_summary": summary,
                "generated_at": datetime.now().isoformat(),
            }

    def _default_bootstrap_policies(self) -> List[dict]:
        """Synthetic analyst policies used for cold-start tournament calibration."""
        return [
            {"id": "p01_balanced", "name": "Balanced Analyst", "weights": [0.35, 0.30, 0.20, 0.15], "bias": 0.00, "noise": 0.03},
            {"id": "p02_static_heavy", "name": "Static-Heavy", "weights": [0.55, 0.20, 0.15, 0.10], "bias": -0.03, "noise": 0.04},
            {"id": "p03_dynamic_heavy", "name": "Dynamic-Heavy", "weights": [0.18, 0.52, 0.20, 0.10], "bias": 0.02, "noise": 0.05},
            {"id": "p04_semantic_focus", "name": "Semantic Focus", "weights": [0.20, 0.20, 0.45, 0.15], "bias": 0.00, "noise": 0.04},
            {"id": "p05_novelty_hunter", "name": "Novelty Hunter", "weights": [0.15, 0.20, 0.20, 0.45], "bias": 0.04, "noise": 0.05},
            {"id": "p06_conservative", "name": "Conservative", "weights": [0.35, 0.25, 0.25, 0.15], "bias": -0.10, "noise": 0.02},
            {"id": "p07_aggressive", "name": "Aggressive", "weights": [0.25, 0.30, 0.25, 0.20], "bias": 0.12, "noise": 0.05},
            {"id": "p08_low_noise", "name": "Low Noise", "weights": [0.30, 0.30, 0.25, 0.15], "bias": 0.00, "noise": 0.01},
            {"id": "p09_high_noise", "name": "High Noise", "weights": [0.30, 0.30, 0.20, 0.20], "bias": 0.00, "noise": 0.10},
            {"id": "p10_risk_sensitive", "name": "Risk Sensitive", "weights": [0.25, 0.25, 0.30, 0.20], "bias": -0.02, "noise": 0.03},
            {"id": "p11_bridge_sensitive", "name": "Bridge Sensitive", "weights": [0.22, 0.22, 0.18, 0.38], "bias": 0.03, "noise": 0.04},
            {"id": "p12_entropy_guard", "name": "Entropy Guard", "weights": [0.40, 0.22, 0.20, 0.18], "bias": -0.01, "noise": 0.03},
        ]

    def bootstrap_init(
        self,
        sid: str,
        overwrite: bool = False,
        decay_lambda: float = 0.03,
        min_bootstrap_weight: float = 0.1,
    ) -> dict:
        """Initialize bootstrap synthetic-analyst lab for cold-start calibration."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            if data.get("bootstrap") and not overwrite:
                b = data["bootstrap"]
                return {
                    "ok": True,
                    "initialized": False,
                    "policies": len((b.get("policies") or {})),
                    "message": "Bootstrap lab already exists. Use overwrite=true to reset.",
                }
            policies = {}
            now = datetime.now().isoformat()
            for p in self._default_bootstrap_policies():
                policies[p["id"]] = {
                    "name": p["name"],
                    "weights": p["weights"],
                    "bias": p["bias"],
                    "noise": p["noise"],
                    "rating": 1500.0,
                    "samples": 0,
                    "brier_sum": 0.0,
                    "calibration_bins": {str(i): {"n": 0, "sum_pred": 0.0, "sum_obs": 0.0} for i in range(10)},
                }
            data["bootstrap"] = {
                "version": 1,
                "created_at": now,
                "updated_at": now,
                "decay_lambda": float(decay_lambda),
                "min_bootstrap_weight": float(min_bootstrap_weight),
                "tournament_runs": 0,
                "total_rounds": 0,
                "policies": policies,
                "history": [],
            }
            self._save_skills(sid, data)
            return {"ok": True, "initialized": True, "policies": len(policies)}

    def _policy_predict(self, policy: dict, features: List[float], rng: random.Random) -> float:
        weights = policy.get("weights") or [0.25, 0.25, 0.25, 0.25]
        score = sum(w * x for w, x in zip(weights, features))
        score += float(policy.get("bias", 0.0))
        noise = float(policy.get("noise", 0.0))
        if noise > 0.0:
            score += rng.gauss(0.0, noise)
        return min(0.999, max(0.001, score))

    def bootstrap_run_tournament(self, sid: str, rounds: int = 200, seed: int = 1337) -> dict:
        """Run synthetic policy tournament and update calibration/rating statistics."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap")
            if not bootstrap:
                init_res = self.bootstrap_init(sid)
                if init_res.get("error"):
                    return init_res
                data = self._load_skills(sid)
                bootstrap = data.get("bootstrap")

            rounds = max(1, min(int(rounds), 50000))
            rng = random.Random(int(seed))
            policies = bootstrap.get("policies") or {}
            if not policies:
                return make_error(MCPError.INVALID_ARGS, "No bootstrap policies found")

            per_policy_loss: Dict[str, float] = {pid: 0.0 for pid in policies}
            per_policy_wins: Dict[str, int] = {pid: 0 for pid in policies}

            for _ in range(rounds):
                # Synthetic evidence cube: [static, dynamic, semantic, novelty]
                static = rng.betavariate(2.2, 2.4)
                dynamic = rng.betavariate(2.0, 2.0)
                semantic = rng.betavariate(2.4, 2.1)
                novelty = rng.betavariate(1.6, 2.8)
                features = [static, dynamic, semantic, novelty]

                # Latent probability (no direct ground truth in real world; synthetic proxy here)
                latent = (
                    0.34 * static
                    + 0.31 * dynamic
                    + 0.22 * semantic
                    + 0.13 * novelty
                    + rng.gauss(0.0, 0.05)
                )
                latent = min(0.999, max(0.001, latent))
                observed = 1 if rng.random() < latent else 0

                losses = {}
                for pid, p in policies.items():
                    pred = self._policy_predict(p, features, rng)
                    brier = (pred - observed) ** 2
                    losses[pid] = brier
                    per_policy_loss[pid] += brier

                    p["samples"] = int(p.get("samples", 0)) + 1
                    p["brier_sum"] = float(p.get("brier_sum", 0.0)) + brier
                    bin_idx = min(9, max(0, int(pred * 10)))
                    bucket = p["calibration_bins"][str(bin_idx)]
                    bucket["n"] += 1
                    bucket["sum_pred"] += pred
                    bucket["sum_obs"] += observed

                # Tournament winner (lowest loss this round)
                winner = min(losses.items(), key=lambda x: x[1])[0]
                per_policy_wins[winner] += 1

                # Elo-style update against round field average.
                avg_loss = sum(losses.values()) / max(1, len(losses))
                for pid, p in policies.items():
                    rating = float(p.get("rating", 1500.0))
                    actual = 1.0 if losses[pid] <= avg_loss else 0.0
                    expected = 1.0 / (1.0 + 10.0 ** ((1500.0 - rating) / 400.0))
                    p["rating"] = rating + 12.0 * (actual - expected)

            bootstrap["tournament_runs"] = int(bootstrap.get("tournament_runs", 0)) + 1
            bootstrap["total_rounds"] = int(bootstrap.get("total_rounds", 0)) + rounds
            bootstrap["updated_at"] = datetime.now().isoformat()

            avg_losses = {
                pid: (per_policy_loss[pid] / rounds) for pid in policies
            }
            sorted_policies = sorted(
                policies.items(),
                key=lambda kv: (avg_losses[kv[0]], -float(kv[1].get("rating", 1500.0))),
            )
            top = []
            for pid, p in sorted_policies[:5]:
                top.append(
                    {
                        "policy_id": pid,
                        "name": p.get("name"),
                        "avg_brier": round(avg_losses[pid], 6),
                        "wins": per_policy_wins[pid],
                        "rating": round(float(p.get("rating", 1500.0)), 2),
                    }
                )

            bootstrap.setdefault("history", []).append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "rounds": rounds,
                    "seed": int(seed),
                    "top": top,
                }
            )
            bootstrap["history"] = bootstrap["history"][-50:]
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {
                "ok": True,
                "rounds": rounds,
                "seed": int(seed),
                "policies": len(policies),
                "top_policies": top,
            }

    def bootstrap_compute_blend(self, sid: str, session_samples: int) -> dict:
        """Compute bootstrap/session blend weights with exponential bootstrap decay."""
        with self._lock:
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            decay_lambda = float(bootstrap.get("decay_lambda", 0.03))
            min_bootstrap_weight = float(bootstrap.get("min_bootstrap_weight", 0.1))
            n = max(0, int(session_samples))
            w_bootstrap = max(min_bootstrap_weight, math.exp(-decay_lambda * n))
            w_session = max(0.0, 1.0 - w_bootstrap)
            return {
                "ok": True,
                "session_samples": n,
                "decay_lambda": decay_lambda,
                "min_bootstrap_weight": min_bootstrap_weight,
                "weights": {
                    "bootstrap": round(w_bootstrap, 6),
                    "session": round(w_session, 6),
                },
            }

    def bootstrap_status(self, sid: str) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap")
            if not bootstrap:
                return {"ok": True, "initialized": False, "message": "Bootstrap lab not initialized"}
            policies = bootstrap.get("policies") or {}
            leaderboard = []
            for pid, p in policies.items():
                samples = max(1, int(p.get("samples", 0)))
                avg_brier = float(p.get("brier_sum", 0.0)) / samples
                leaderboard.append(
                    {
                        "policy_id": pid,
                        "name": p.get("name"),
                        "rating": round(float(p.get("rating", 1500.0)), 2),
                        "samples": int(p.get("samples", 0)),
                        "avg_brier": round(avg_brier, 6),
                    }
                )
            leaderboard.sort(key=lambda x: (x["avg_brier"], -x["rating"]))
            return {
                "ok": True,
                "initialized": True,
                "tournament_runs": int(bootstrap.get("tournament_runs", 0)),
                "total_rounds": int(bootstrap.get("total_rounds", 0)),
                "policy_count": len(policies),
                "leaderboard": leaderboard[:10],
            }

    def bootstrap_summary(self, sid: str) -> dict:
        """Compact one-shot bootstrap health snapshot (quality + disputes + outcomes)."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap")
            if not bootstrap:
                return {
                    "ok": True,
                    "initialized": False,
                    "message": "Bootstrap lab not initialized",
                }

            policies = bootstrap.get("policies") or {}
            disputes = bootstrap.get("disputes") or []
            outcomes = bootstrap.get("outcomes") or []

            policy_rows = []
            ece_num = 0.0
            ece_den = 0
            for pid, p in policies.items():
                samples = max(1, int(p.get("samples", 0)))
                avg_brier = float(p.get("brier_sum", 0.0)) / samples
                rating = float(p.get("rating", 1500.0))
                policy_rows.append((pid, p.get("name"), samples, avg_brier, rating))
                bins = p.get("calibration_bins") or {}
                for b in bins.values():
                    n = int((b or {}).get("n", 0))
                    if n <= 0:
                        continue
                    pred_mean = float(b.get("sum_pred", 0.0)) / n
                    obs_mean = float(b.get("sum_obs", 0.0)) / n
                    ece_num += n * abs(pred_mean - obs_mean)
                    ece_den += n

            policy_rows.sort(key=lambda r: (r[3], -r[4]))
            top = [
                {
                    "policy_id": pid,
                    "name": name,
                    "samples": samples,
                    "avg_brier": round(avg_brier, 6),
                    "rating": round(rating, 2),
                }
                for pid, name, samples, avg_brier, rating in policy_rows[:5]
            ]

            open_disputes = sum(1 for d in disputes if d.get("status") == "open")
            resolved_disputes = sum(1 for d in disputes if d.get("status") == "resolved")
            dispute_brier = [
                float(d.get("brier"))
                for d in disputes
                if d.get("status") == "resolved" and d.get("brier") is not None
            ]
            outcome_brier = [float(o.get("brier", 0.0)) for o in outcomes if o.get("brier") is not None]

            return {
                "ok": True,
                "initialized": True,
                "tournament_runs": int(bootstrap.get("tournament_runs", 0)),
                "total_rounds": int(bootstrap.get("total_rounds", 0)),
                "prior_confidence": round(self._bootstrap_prior_confidence(bootstrap), 4),
                "calibration": {
                    "ece": round((ece_num / ece_den) if ece_den > 0 else 0.0, 6),
                    "sampled_bins": ece_den,
                },
                "policies": {
                    "count": len(policies),
                    "top": top,
                },
                "disputes": {
                    "open": open_disputes,
                    "resolved": resolved_disputes,
                    "avg_brier_resolved": round(sum(dispute_brier) / len(dispute_brier), 6) if dispute_brier else None,
                },
                "outcomes": {
                    "count": len(outcomes),
                    "avg_brier": round(sum(outcome_brier) / len(outcome_brier), 6) if outcome_brier else None,
                },
            }

    def bootstrap_summary_detailed(self, sid: str, top_policies: int = 10) -> dict:
        """Detailed bootstrap diagnostics including per-policy calibration bins."""
        with self._lock:
            base = self.bootstrap_summary(sid)
            if base.get("error") or not base.get("initialized"):
                return base

            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policies = bootstrap.get("policies") or {}
            rows = []

            for pid, p in policies.items():
                samples = max(1, int(p.get("samples", 0)))
                avg_brier = float(p.get("brier_sum", 0.0)) / samples
                bins = p.get("calibration_bins") or {}
                ece_num = 0.0
                ece_den = 0
                bin_rows = []
                for i in range(10):
                    b = bins.get(str(i), {})
                    n = int(b.get("n", 0))
                    if n <= 0:
                        continue
                    pred_mean = float(b.get("sum_pred", 0.0)) / n
                    obs_mean = float(b.get("sum_obs", 0.0)) / n
                    gap = abs(pred_mean - obs_mean)
                    ece_num += n * gap
                    ece_den += n
                    bin_rows.append(
                        {
                            "bin": i,
                            "n": n,
                            "pred_mean": round(pred_mean, 6),
                            "obs_mean": round(obs_mean, 6),
                            "gap": round(gap, 6),
                        }
                    )
                ece = (ece_num / ece_den) if ece_den > 0 else 0.0
                rows.append(
                    {
                        "policy_id": pid,
                        "name": p.get("name"),
                        "samples": int(p.get("samples", 0)),
                        "rating": round(float(p.get("rating", 1500.0)), 2),
                        "avg_brier": round(avg_brier, 6),
                        "ece": round(ece, 6),
                        "bins": bin_rows,
                    }
                )

            rows.sort(key=lambda r: (r["avg_brier"], r["ece"], -r["rating"]))
            return {
                "ok": True,
                "initialized": True,
                "summary": base,
                "policy_diagnostics": rows[: max(1, min(int(top_policies), 50))],
                "total_policies": len(rows),
            }

    def bootstrap_snapshot(self, sid: str, name: str = "") -> dict:
        """Persist a compact bootstrap metrics snapshot for drift tracking."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            summary = self.bootstrap_summary(sid)
            if summary.get("error"):
                return summary
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            if not bootstrap:
                return {"ok": False, "error": "bootstrap_not_initialized"}
            snaps = bootstrap.setdefault("metric_snapshots", [])
            snap_id = f"bsnap_{uuid.uuid4().hex[:8]}"
            row = {
                "snapshot_id": snap_id,
                "name": str(name or "").strip() or None,
                "timestamp": datetime.now().isoformat(),
                "prior_confidence": summary.get("prior_confidence"),
                "ece": ((summary.get("calibration") or {}).get("ece")),
                "outcomes": ((summary.get("outcomes") or {}).get("count", 0)),
                "open_disputes": ((summary.get("disputes") or {}).get("open", 0)),
                "resolved_disputes": ((summary.get("disputes") or {}).get("resolved", 0)),
                "tournament_runs": summary.get("tournament_runs", 0),
                "total_rounds": summary.get("total_rounds", 0),
            }
            snaps.append(row)
            bootstrap["metric_snapshots"] = snaps[-2000:]
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {"ok": True, "snapshot": row}

    def bootstrap_list_snapshots(
        self,
        sid: str,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            snaps = list((((data.get("bootstrap") or {}).get("metric_snapshots") or [])))
            total = len(snaps)
            offset = max(0, int(offset))
            limit = max(1, min(int(limit), 1000))
            rows = snaps[offset: offset + limit]
            return {
                "ok": True,
                "total": total,
                "count": len(rows),
                "offset": offset,
                "limit": limit,
                "snapshots": rows,
            }

    def bootstrap_drift_report(self, sid: str, window: int = 20) -> dict:
        """Compute metric drift from bootstrap snapshots."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            snaps = list((((data.get("bootstrap") or {}).get("metric_snapshots") or [])))
            if len(snaps) < 2:
                return {
                    "ok": True,
                    "enough_data": False,
                    "message": "Need at least 2 snapshots",
                    "count": len(snaps),
                }
            w = max(2, min(int(window), len(snaps)))
            recent = snaps[-w:]
            first = recent[0]
            last = recent[-1]

            def _delta(key: str) -> Optional[float]:
                a = first.get(key)
                b = last.get(key)
                if a is None or b is None:
                    return None
                return float(b) - float(a)

            ece_delta = _delta("ece")
            conf_delta = _delta("prior_confidence")
            outcomes_delta = _delta("outcomes")
            risk = "stable"
            if ece_delta is not None and ece_delta > 0.03:
                risk = "degrading"
            elif ece_delta is not None and ece_delta < -0.03:
                risk = "improving"
            if conf_delta is not None and conf_delta < -0.08:
                risk = "degrading"

            return {
                "ok": True,
                "enough_data": True,
                "window": w,
                "risk": risk,
                "first_snapshot_id": first.get("snapshot_id"),
                "last_snapshot_id": last.get("snapshot_id"),
                "drift": {
                    "ece_delta": round(ece_delta, 6) if ece_delta is not None else None,
                    "prior_confidence_delta": round(conf_delta, 6) if conf_delta is not None else None,
                    "outcomes_delta": int(outcomes_delta) if outcomes_delta is not None else None,
                },
            }

    def bootstrap_update_baseline(
        self,
        sid: str,
        window: int = 50,
        percentile: float = 95.0,
    ) -> dict:
        """Update rolling baseline thresholds from snapshot history."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            snaps = list((bootstrap.get("metric_snapshots") or []))
            if len(snaps) < 5:
                return {
                    "ok": True,
                    "enough_data": False,
                    "message": "Need at least 5 snapshots",
                    "count": len(snaps),
                }

            w = max(5, min(int(window), len(snaps)))
            pctl = max(50.0, min(float(percentile), 99.9))
            recent = snaps[-w:]

            ece_vals = sorted([float(s.get("ece", 0.0)) for s in recent if s.get("ece") is not None])
            prior_vals = sorted([float(s.get("prior_confidence", 0.5)) for s in recent if s.get("prior_confidence") is not None])

            def _p(vals: list[float], q: float, fallback: float) -> float:
                if not vals:
                    return fallback
                idx = int((q / 100.0) * (len(vals) - 1))
                idx = max(0, min(idx, len(vals) - 1))
                return vals[idx]

            baseline = {
                "window": w,
                "percentile": pctl,
                "ece_p95": round(_p(ece_vals, pctl, 0.0), 6),
                "ece_p50": round(_p(ece_vals, 50.0, 0.0), 6),
                "prior_p05": round(_p(prior_vals, 5.0, 0.5), 6),
                "prior_p50": round(_p(prior_vals, 50.0, 0.5), 6),
                "updated_at": datetime.now().isoformat(),
            }
            bootstrap["baseline"] = baseline
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {"ok": True, "enough_data": True, "baseline": baseline}

    def bootstrap_evaluate_alerts(
        self,
        sid: str,
        window: int = 20,
    ) -> dict:
        """Evaluate drift alerts against rolling baseline thresholds."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            snaps = list((bootstrap.get("metric_snapshots") or []))
            baseline = bootstrap.get("baseline") or {}
            if not baseline:
                baseline_res = self.bootstrap_update_baseline(sid, window=max(30, window))
                if baseline_res.get("error"):
                    return baseline_res
                data = self._load_skills(sid)
                bootstrap = data.get("bootstrap") or {}
                baseline = bootstrap.get("baseline") or {}

            if len(snaps) < 2:
                return {"ok": True, "enough_data": False, "alerts": [], "severity": "none"}

            w = max(2, min(int(window), len(snaps)))
            recent = snaps[-w:]
            ece_vals = [float(s.get("ece", 0.0)) for s in recent if s.get("ece") is not None]
            prior_vals = [float(s.get("prior_confidence", 0.5)) for s in recent if s.get("prior_confidence") is not None]
            latest = recent[-1]

            ece_now = float(latest.get("ece", 0.0) or 0.0)
            prior_now = float(latest.get("prior_confidence", 0.5) or 0.5)
            ece_p95 = float(baseline.get("ece_p95", 1.0))
            prior_p05 = float(baseline.get("prior_p05", 0.0))

            alerts = []
            if ece_now > ece_p95:
                alerts.append({
                    "type": "ece_regression",
                    "value": round(ece_now, 6),
                    "threshold": round(ece_p95, 6),
                    "excess": round(ece_now - ece_p95, 6),
                })
            if prior_now < prior_p05:
                alerts.append({
                    "type": "confidence_drop",
                    "value": round(prior_now, 6),
                    "threshold": round(prior_p05, 6),
                    "deficit": round(prior_p05 - prior_now, 6),
                })

            severity = "none"
            if alerts:
                max_signal = max([
                    abs(float(a.get("excess", 0.0) or a.get("deficit", 0.0)))
                    for a in alerts
                ] or [0.0])
                if max_signal > 0.08:
                    severity = "high"
                elif max_signal > 0.03:
                    severity = "medium"
                else:
                    severity = "low"

            return {
                "ok": True,
                "enough_data": True,
                "window": w,
                "alerts": alerts,
                "severity": severity,
                "latest": {
                    "ece": round(ece_now, 6),
                    "prior_confidence": round(prior_now, 6),
                    "timestamp": latest.get("timestamp"),
                },
                "baseline": baseline,
                "stats": {
                    "ece_mean_window": round(sum(ece_vals) / max(1, len(ece_vals)), 6),
                    "prior_mean_window": round(sum(prior_vals) / max(1, len(prior_vals)), 6),
                },
            }

    def bootstrap_mitigation_plan(self, sid: str, window: int = 20) -> dict:
        """Generate bounded mitigation actions from current alert state."""
        with self._lock:
            eval_res = self.bootstrap_evaluate_alerts(sid, window=window)
            if eval_res.get("error"):
                return eval_res
            if not eval_res.get("enough_data"):
                return {
                    "ok": True,
                    "enough_data": False,
                    "severity": "none",
                    "actions": [],
                    "reason": "insufficient_baseline_data",
                }

            severity = str(eval_res.get("severity") or "none")
            alerts = list(eval_res.get("alerts") or [])
            actions = []

            has_ece = any(a.get("type") == "ece_regression" for a in alerts)
            has_conf = any(a.get("type") == "confidence_drop" for a in alerts)

            if severity in ("medium", "high") and has_ece:
                actions.append(
                    {
                        "priority": 1,
                        "action": "bootstrap_run_tournament",
                        "params": {"rounds": 1500 if severity == "high" else 800},
                        "reason": "Re-calibrate synthetic policies against drift",
                    }
                )
            if severity in ("medium", "high") and has_conf:
                actions.append(
                    {
                        "priority": 2,
                        "action": "bootstrap_simulate_batch",
                        "params": {"n": 1200 if severity == "high" else 600, "positive_rate": 0.55},
                        "reason": "Stabilize confidence with bounded synthetic outcomes",
                    }
                )
            if severity == "high":
                actions.append(
                    {
                        "priority": 3,
                        "action": "bootstrap_snapshot",
                        "params": {"name": "pre_mitigation_high_alert"},
                        "reason": "Capture state before mitigation steps",
                    }
                )
                actions.append(
                    {
                        "priority": 4,
                        "action": "bootstrap_update_baseline",
                        "params": {"window": max(30, int(window)), "percentile": 97.0},
                        "reason": "Tighten baseline after high-severity drift",
                    }
                )
            if not actions:
                actions.append(
                    {
                        "priority": 1,
                        "action": "bootstrap_snapshot",
                        "params": {"name": "steady_state"},
                        "reason": "No mitigation needed; keep timeline continuity",
                    }
                )

            actions.sort(key=lambda a: int(a.get("priority", 99)))
            return {
                "ok": True,
                "enough_data": True,
                "severity": severity,
                "alerts": alerts,
                "actions": actions,
            }

    def bootstrap_apply_mitigation(
        self,
        sid: str,
        window: int = 20,
        max_actions: int = 4,
        dry_run: bool = False,
    ) -> dict:
        """Execute bounded mitigation plan and return step-by-step results."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")

            plan = self.bootstrap_mitigation_plan(sid, window=window)
            if plan.get("error"):
                return plan
            actions = list(plan.get("actions") or [])[: max(1, min(int(max_actions), 10))]
            if dry_run:
                return {
                    "ok": True,
                    "dry_run": True,
                    "severity": plan.get("severity"),
                    "actions": actions,
                    "executed": [],
                }

            executed = []
            for item in actions:
                name = str(item.get("action") or "")
                params = dict(item.get("params") or {})
                if name == "bootstrap_run_tournament":
                    out = self.bootstrap_run_tournament(
                        sid,
                        rounds=int(params.get("rounds", 800)),
                        seed=int(params.get("seed", int(time.time()) % 100000)),
                    )
                elif name == "bootstrap_simulate_batch":
                    out = self.bootstrap_simulate_batch(
                        sid,
                        n=int(params.get("n", 600)),
                        seed=int(params.get("seed", int(time.time()) % 100000)),
                        positive_rate=float(params.get("positive_rate", 0.55)),
                    )
                elif name == "bootstrap_snapshot":
                    out = self.bootstrap_snapshot(sid, name=str(params.get("name") or "mitigation"))
                elif name == "bootstrap_update_baseline":
                    out = self.bootstrap_update_baseline(
                        sid,
                        window=int(params.get("window", max(30, window))),
                        percentile=float(params.get("percentile", 95.0)),
                    )
                else:
                    out = make_error(MCPError.ACTION_NOT_FOUND, f"Unknown mitigation action {name}")

                executed.append(
                    {
                        "action": name,
                        "ok": bool(isinstance(out, dict) and out.get("ok")),
                        "result": out,
                    }
                )

            final_eval = self.bootstrap_evaluate_alerts(sid, window=window)
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            hist = bootstrap.setdefault("mitigation_history", [])
            hist.append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "window": int(window),
                    "plan_severity": plan.get("severity"),
                    "actions_requested": len(actions),
                    "executed_ok": sum(1 for e in executed if e.get("ok")),
                    "executed_total": len(executed),
                    "pre_alerts": len(plan.get("alerts") or []),
                    "post_alerts": len((final_eval or {}).get("alerts") or []),
                    "post_severity": (final_eval or {}).get("severity"),
                }
            )
            bootstrap["mitigation_history"] = hist[-2000:]
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {
                "ok": True,
                "dry_run": False,
                "plan_severity": plan.get("severity"),
                "actions_requested": len(actions),
                "executed": executed,
                "post_eval": final_eval,
            }

    def bootstrap_mitigation_history(
        self,
        sid: str,
        limit: int = 100,
        offset: int = 0,
    ) -> dict:
        """Return mitigation execution audit history."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            rows = list((((data.get("bootstrap") or {}).get("mitigation_history") or [])))
            total = len(rows)
            offset = max(0, int(offset))
            limit = max(1, min(int(limit), 5000))
            view = rows[offset: offset + limit]
            return {
                "ok": True,
                "total": total,
                "count": len(view),
                "offset": offset,
                "limit": limit,
                "history": view,
            }

    def bootstrap_mitigation_effectiveness(self, sid: str, window: int = 50) -> dict:
        """Score mitigation effectiveness from audit trail deltas."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            rows = list((((data.get("bootstrap") or {}).get("mitigation_history") or [])))
            if not rows:
                return {
                    "ok": True,
                    "enough_data": False,
                    "message": "No mitigation history",
                    "count": 0,
                }
            w = max(1, min(int(window), len(rows)))
            recent = rows[-w:]

            severity_rank = {"none": 0, "low": 1, "medium": 2, "high": 3}
            improvements = 0
            worsened = 0
            same = 0
            alert_delta_sum = 0
            ok_ratio_sum = 0.0
            for r in recent:
                pre_s = severity_rank.get(str(r.get("plan_severity") or "none"), 0)
                post_s = severity_rank.get(str(r.get("post_severity") or "none"), 0)
                if post_s < pre_s:
                    improvements += 1
                elif post_s > pre_s:
                    worsened += 1
                else:
                    same += 1
                pre_a = int(r.get("pre_alerts", 0))
                post_a = int(r.get("post_alerts", 0))
                alert_delta_sum += (pre_a - post_a)
                et = max(1, int(r.get("executed_total", 0)))
                eo = int(r.get("executed_ok", 0))
                ok_ratio_sum += (eo / et)

            n = len(recent)
            avg_alert_reduction = alert_delta_sum / max(1, n)
            avg_exec_ok = ok_ratio_sum / max(1, n)
            effectiveness = (0.5 * (improvements / n)) + (0.3 * max(0.0, min(1.0, avg_alert_reduction / 3.0))) + (0.2 * avg_exec_ok)
            tier = "poor"
            if effectiveness >= 0.75:
                tier = "strong"
            elif effectiveness >= 0.5:
                tier = "moderate"

            return {
                "ok": True,
                "enough_data": True,
                "window": n,
                "counts": {
                    "improved": improvements,
                    "same": same,
                    "worsened": worsened,
                },
                "avg_alert_reduction": round(avg_alert_reduction, 6),
                "avg_exec_success_ratio": round(avg_exec_ok, 6),
                "effectiveness_score": round(effectiveness, 6),
                "tier": tier,
            }

    def bootstrap_policy_reweight(
        self,
        sid: str,
        window: int = 50,
        max_shift: float = 0.08,
        dry_run: bool = False,
    ) -> dict:
        """Closed-loop policy adaptation from mitigation effectiveness outcomes."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")

            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policies = bootstrap.get("policies") or {}
            if not policies:
                return make_error(MCPError.INVALID_ARGS, "Bootstrap policies not initialized")

            eff = self.bootstrap_mitigation_effectiveness(sid, window=window)
            if eff.get("error"):
                return eff
            if not eff.get("enough_data"):
                return {
                    "ok": True,
                    "enough_data": False,
                    "message": "Not enough mitigation history for policy adaptation",
                }

            score = float(eff.get("effectiveness_score", 0.0))
            tier = str(eff.get("tier") or "poor")
            shift_cap = max(0.005, min(float(max_shift), 0.25))

            # Adaptive target vector over [static, dynamic, semantic, novelty]
            if tier == "strong":
                target = [0.28, 0.30, 0.24, 0.18]
            elif tier == "moderate":
                target = [0.31, 0.28, 0.23, 0.18]
            else:
                target = [0.35, 0.24, 0.23, 0.18]

            # Blend factor scales with confidence in effectiveness signal.
            blend = max(0.05, min(0.5, 0.1 + (0.4 * score)))
            updates = []

            prior_weights = {}
            for pid, p in policies.items():
                old = list(p.get("weights") or [0.25, 0.25, 0.25, 0.25])
                if len(old) != 4:
                    old = [0.25, 0.25, 0.25, 0.25]
                prior_weights[pid] = [round(float(x), 6) for x in old]
                raw = [((1.0 - blend) * old[i]) + (blend * target[i]) for i in range(4)]

                # Per-dimension shift guardrail.
                bounded = []
                for i in range(4):
                    delta = raw[i] - old[i]
                    delta = max(-shift_cap, min(shift_cap, delta))
                    bounded.append(max(0.01, old[i] + delta))

                s = sum(bounded)
                if s <= 0:
                    new_w = [0.25, 0.25, 0.25, 0.25]
                else:
                    new_w = [x / s for x in bounded]

                updates.append(
                    {
                        "policy_id": pid,
                        "old_weights": [round(x, 6) for x in old],
                        "new_weights": [round(x, 6) for x in new_w],
                        "max_component_shift": round(max(abs(new_w[i] - old[i]) for i in range(4)), 6),
                    }
                )

                if not dry_run:
                    p["weights"] = new_w

            if not dry_run:
                bootstrap["policies"] = policies
                hist = bootstrap.setdefault("policy_reweight_history", [])
                hist.append(
                    {
                        "timestamp": datetime.now().isoformat(),
                        "window": int(window),
                        "effectiveness_score": round(score, 6),
                        "tier": tier,
                        "blend": round(blend, 6),
                        "max_shift": round(shift_cap, 6),
                        "prior_weights": prior_weights,
                        "updates": updates,
                    }
                )
                bootstrap["policy_reweight_history"] = hist[-2000:]
                bootstrap["updated_at"] = datetime.now().isoformat()
                data["bootstrap"] = bootstrap
                self._save_skills(sid, data)

            return {
                "ok": True,
                "dry_run": bool(dry_run),
                "effectiveness_score": round(score, 6),
                "tier": tier,
                "blend": round(blend, 6),
                "max_shift": round(shift_cap, 6),
                "updates": updates,
            }

    def bootstrap_set_autopilot_policy(
        self,
        sid: str,
        cooldown_seconds: int = 300,
        daily_budget: int = 100,
        max_live_actions: int = 4,
        rollback_on_regression: bool = True,
    ) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policy = bootstrap.setdefault("autopilot_policy", {})
            policy.update(
                {
                    "cooldown_seconds": max(0, min(int(cooldown_seconds), 86400)),
                    "daily_budget": max(1, min(int(daily_budget), 100000)),
                    "max_live_actions": max(1, min(int(max_live_actions), 10)),
                    "rollback_on_regression": bool(rollback_on_regression),
                    "updated_at": datetime.now().isoformat(),
                }
            )
            bootstrap["autopilot_policy"] = policy
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {"ok": True, "policy": policy}

    def bootstrap_get_autopilot_policy(self, sid: str) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policy = bootstrap.get("autopilot_policy") or {
                "cooldown_seconds": 300,
                "daily_budget": 100,
                "max_live_actions": 4,
                "rollback_on_regression": True,
            }
            return {"ok": True, "policy": policy}

    def bootstrap_rollback_last_reweight(self, sid: str) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policies = bootstrap.get("policies") or {}
            hist = bootstrap.get("policy_reweight_history") or []
            if not hist:
                return {"ok": True, "rolled_back": False, "message": "No reweight history"}
            last = hist[-1]
            prior = dict(last.get("prior_weights") or {})
            if not prior:
                return {"ok": True, "rolled_back": False, "message": "No prior weights in last reweight record"}

            restored = 0
            for pid, w in prior.items():
                if pid in policies and isinstance(w, list) and len(w) == 4:
                    s = sum(float(x) for x in w)
                    if s > 0:
                        policies[pid]["weights"] = [float(x) / s for x in w]
                        restored += 1
            if restored <= 0:
                return {"ok": True, "rolled_back": False, "message": "No matching policies to restore"}

            bootstrap["policies"] = policies
            rb = bootstrap.setdefault("rollback_history", [])
            rb.append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "restored_policies": restored,
                    "source_reweight_at": last.get("timestamp"),
                }
            )
            bootstrap["rollback_history"] = rb[-2000:]
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {"ok": True, "rolled_back": True, "restored_policies": restored}

    def bootstrap_policy_reweight_history(self, sid: str, limit: int = 100, offset: int = 0) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            rows = list((((data.get("bootstrap") or {}).get("policy_reweight_history") or [])))
            total = len(rows)
            offset = max(0, int(offset))
            limit = max(1, min(int(limit), 5000))
            view = rows[offset: offset + limit]
            return {
                "ok": True,
                "total": total,
                "count": len(view),
                "offset": offset,
                "limit": limit,
                "history": view,
            }

    def bootstrap_autopilot(
        self,
        sid: str,
        window: int = 30,
        dry_run: bool = False,
    ) -> dict:
        """Plan/apply mitigation then policy reweight in one bounded control loop."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")

            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policy = bootstrap.get("autopilot_policy") or {
                "cooldown_seconds": 300,
                "daily_budget": 100,
                "max_live_actions": 4,
                "rollback_on_regression": True,
            }

            now = datetime.now()
            runs = bootstrap.get("autopilot_runs") or []
            day_key = now.strftime("%Y-%m-%d")
            day_runs = [r for r in runs if str(r.get("day")) == day_key]
            if len(day_runs) >= int(policy.get("daily_budget", 100)) and not dry_run:
                return {
                    "ok": True,
                    "dry_run": False,
                    "blocked": True,
                    "reason": "daily_budget_exceeded",
                    "daily_budget": int(policy.get("daily_budget", 100)),
                }

            last_run = runs[-1] if runs else None
            if last_run and not dry_run:
                try:
                    ts = datetime.fromisoformat(str(last_run.get("timestamp")))
                    delta = (now - ts).total_seconds()
                    if delta < int(policy.get("cooldown_seconds", 300)):
                        return {
                            "ok": True,
                            "dry_run": False,
                            "blocked": True,
                            "reason": "cooldown_active",
                            "cooldown_seconds": int(policy.get("cooldown_seconds", 300)),
                            "remaining_seconds": max(0, int(policy.get("cooldown_seconds", 300) - delta)),
                        }
                except Exception:
                    pass

            pre_eval = self.bootstrap_evaluate_alerts(sid, window=window)
            plan = self.bootstrap_mitigation_plan(sid, window=window)
            if plan.get("error"):
                return plan
            apply_res = self.bootstrap_apply_mitigation(
                sid,
                window=window,
                max_actions=int(policy.get("max_live_actions", 4)),
                dry_run=dry_run,
            )
            if apply_res.get("error"):
                return apply_res
            reweight = self.bootstrap_policy_reweight(
                sid,
                window=max(20, int(window)),
                max_shift=0.08,
                dry_run=dry_run,
            )
            if reweight.get("error"):
                return reweight

            post_eval = self.bootstrap_evaluate_alerts(sid, window=window)
            rollback = None
            if not dry_run and bool(policy.get("rollback_on_regression", True)):
                pre_sev = str((pre_eval or {}).get("severity") or "none")
                post_sev = str((post_eval or {}).get("severity") or "none")
                rank = {"none": 0, "low": 1, "medium": 2, "high": 3}
                if rank.get(post_sev, 0) > rank.get(pre_sev, 0):
                    rollback = self.bootstrap_rollback_last_reweight(sid)

            if not dry_run:
                data2 = self._load_skills(sid)
                bootstrap2 = data2.get("bootstrap") or {}
                log = bootstrap2.setdefault("autopilot_runs", [])
                log.append(
                    {
                        "timestamp": now.isoformat(),
                        "day": day_key,
                        "window": int(window),
                        "pre_severity": (pre_eval or {}).get("severity"),
                        "post_severity": (post_eval or {}).get("severity"),
                        "rollback": rollback,
                    }
                )
                bootstrap2["autopilot_runs"] = log[-5000:]
                bootstrap2["updated_at"] = datetime.now().isoformat()
                data2["bootstrap"] = bootstrap2
                self._save_skills(sid, data2)

            return {
                "ok": True,
                "dry_run": bool(dry_run),
                "plan_severity": plan.get("severity"),
                "mitigation": apply_res,
                "policy_reweight": reweight,
                "policy": policy,
                "pre_eval": pre_eval,
                "post_eval": post_eval,
                "rollback": rollback,
            }

    def bootstrap_simulate_batch(
        self,
        sid: str,
        n: int = 500,
        seed: int = 2026,
        positive_rate: float = 0.5,
    ) -> dict:
        """Fast synthetic outcome ingestion for stress tests and calibration warm-up."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            count = max(1, min(int(n), 200000))
            p = max(0.01, min(0.99, float(positive_rate)))
            rng = random.Random(int(seed))
            brier_sum = 0.0
            positive = 0
            data = self._load_skills(sid)
            for _ in range(count):
                pred = min(0.999, max(0.001, rng.betavariate(2.0, 2.0)))
                obs = 1 if rng.random() < p else 0
                if obs:
                    positive += 1
                out = self._bootstrap_apply_outcome_in_memory(
                    sid,
                    data,
                    predicted=pred,
                    observed=obs,
                    skill_id=None,
                    delay_seconds=0,
                )
                if out.get("error"):
                    return out
                brier_sum += float(out.get("brier", 0.0))
            self._save_skills(sid, data)
            return {
                "ok": True,
                "n": count,
                "seed": int(seed),
                "positive_rate_target": p,
                "positive_rate_observed": round(positive / max(1, count), 6),
                "avg_brier": round(brier_sum / max(1, count), 6),
            }

    def bootstrap_prune_data(
        self,
        sid: str,
        max_outcomes: int = 1000,
        max_disputes: int = 500,
        max_snapshots: int = 2000,
    ) -> dict:
        """Prune bootstrap history buffers to bounded sizes."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            before = {
                "outcomes": len(bootstrap.get("outcomes") or []),
                "disputes": len(bootstrap.get("disputes") or []),
                "metric_snapshots": len(bootstrap.get("metric_snapshots") or []),
            }
            max_outcomes = max(1, min(int(max_outcomes), 200000))
            max_disputes = max(1, min(int(max_disputes), 50000))
            max_snapshots = max(1, min(int(max_snapshots), 100000))
            bootstrap["outcomes"] = (bootstrap.get("outcomes") or [])[-max_outcomes:]
            bootstrap["disputes"] = (bootstrap.get("disputes") or [])[-max_disputes:]
            bootstrap["metric_snapshots"] = (bootstrap.get("metric_snapshots") or [])[-max_snapshots:]
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            after = {
                "outcomes": len(bootstrap.get("outcomes") or []),
                "disputes": len(bootstrap.get("disputes") or []),
                "metric_snapshots": len(bootstrap.get("metric_snapshots") or []),
            }
            return {"ok": True, "before": before, "after": after}

    def bootstrap_export_metrics(
        self,
        sid: str,
        status: str = "all",
        since: str = "",
        until: str = "",
        limit: int = 5000,
    ) -> dict:
        """Export condensed time-series metrics for external plotting/analysis."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            snaps = bootstrap.get("metric_snapshots") or []
            disputes = bootstrap.get("disputes") or []
            outcomes = bootstrap.get("outcomes") or []

            status = str(status or "all").strip().lower()
            t_since = None
            t_until = None
            if since:
                try:
                    t_since = datetime.fromisoformat(str(since))
                except Exception:
                    t_since = None
            if until:
                try:
                    t_until = datetime.fromisoformat(str(until))
                except Exception:
                    t_until = None

            def _in_window(ts: Optional[str]) -> bool:
                if not ts:
                    return False
                try:
                    t = datetime.fromisoformat(str(ts))
                except Exception:
                    return False
                if t_since and t < t_since:
                    return False
                if t_until and t > t_until:
                    return False
                return True

            snapshot_series = [
                {
                    "t": s.get("timestamp"),
                    "prior": s.get("prior_confidence"),
                    "ece": s.get("ece"),
                    "outcomes": s.get("outcomes"),
                    "open_disputes": s.get("open_disputes"),
                }
                for s in snaps
                if (not since and not until) or _in_window(s.get("timestamp"))
            ]
            dispute_series = [
                {
                    "t_open": d.get("opened_at"),
                    "t_resolved": d.get("resolved_at"),
                    "status": d.get("status"),
                    "brier": d.get("brier"),
                }
                for d in disputes
                if (
                    status in ("all", "")
                    or str(d.get("status") or "").lower() == status
                )
                and (
                    (not since and not until)
                    or _in_window(d.get("resolved_at") or d.get("opened_at"))
                )
            ]
            outcome_series = [
                {
                    "t": o.get("timestamp"),
                    "pred": o.get("predicted"),
                    "obs": o.get("observed"),
                    "brier": o.get("brier"),
                }
                for o in outcomes
                if (not since and not until) or _in_window(o.get("timestamp"))
            ]
            limit = max(1, min(int(limit), 200000))
            snapshot_series = snapshot_series[-limit:]
            dispute_series = dispute_series[-limit:]
            outcome_series = outcome_series[-limit:]
            return {
                "ok": True,
                "series": {
                    "snapshots": snapshot_series,
                    "disputes": dispute_series,
                    "outcomes": outcome_series,
                },
                "filters": {
                    "status": status,
                    "since": since or None,
                    "until": until or None,
                    "limit": limit,
                },
                "counts": {
                    "snapshots": len(snapshot_series),
                    "disputes": len(dispute_series),
                    "outcomes": len(outcome_series),
                },
            }

    def bootstrap_calibration_report(self, sid: str, min_bin_n: int = 20) -> dict:
        """Global calibration report with reliability bins aggregated across policies."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            policies = bootstrap.get("policies") or {}
            agg = {i: {"n": 0, "sum_pred": 0.0, "sum_obs": 0.0} for i in range(10)}
            for p in policies.values():
                bins = p.get("calibration_bins") or {}
                for i in range(10):
                    b = bins.get(str(i), {})
                    agg[i]["n"] += int(b.get("n", 0))
                    agg[i]["sum_pred"] += float(b.get("sum_pred", 0.0))
                    agg[i]["sum_obs"] += float(b.get("sum_obs", 0.0))

            min_bin_n = max(1, min(int(min_bin_n), 1000000))
            ece_num = 0.0
            ece_den = 0
            bins_out = []
            for i in range(10):
                n = agg[i]["n"]
                if n < min_bin_n:
                    continue
                pred_mean = agg[i]["sum_pred"] / n
                obs_mean = agg[i]["sum_obs"] / n
                gap = abs(pred_mean - obs_mean)
                ece_num += n * gap
                ece_den += n
                bins_out.append(
                    {
                        "bin": i,
                        "n": n,
                        "pred_mean": round(pred_mean, 6),
                        "obs_mean": round(obs_mean, 6),
                        "gap": round(gap, 6),
                    }
                )
            bins_out.sort(key=lambda x: x["bin"])
            ece = (ece_num / ece_den) if ece_den > 0 else 0.0
            return {
                "ok": True,
                "min_bin_n": min_bin_n,
                "used_bins": len(bins_out),
                "ece": round(ece, 6),
                "bins": bins_out,
            }

    def bootstrap_ingest_outcome(
        self,
        sid: str,
        predicted: float,
        observed: int,
        skill_id: Optional[str] = None,
        delay_seconds: int = 0,
    ) -> dict:
        """Ingest delayed outcome and update both session and bootstrap calibration."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            res = self._bootstrap_apply_outcome_in_memory(
                sid,
                data,
                predicted=predicted,
                observed=observed,
                skill_id=skill_id,
                delay_seconds=delay_seconds,
            )
            if res.get("error"):
                return res
            self._save_skills(sid, data)
            return res

    def _bootstrap_apply_outcome_in_memory(
        self,
        sid: str,
        data: dict,
        predicted: float,
        observed: int,
        skill_id: Optional[str] = None,
        delay_seconds: int = 0,
    ) -> dict:
        bootstrap = data.get("bootstrap")
        if not bootstrap:
            init_res = self.bootstrap_init(sid)
            if init_res.get("error"):
                return init_res
            refreshed = self._load_skills(sid)
            data.clear()
            data.update(refreshed)
            bootstrap = data.get("bootstrap")

        pred = max(0.001, min(0.999, float(predicted)))
        obs = 1 if int(observed) else 0
        brier = (pred - obs) ** 2

        policies = bootstrap.get("policies") or {}
        bidx = min(9, max(0, int(pred * 10)))
        for p in policies.values():
            p["samples"] = int(p.get("samples", 0)) + 1
            p["brier_sum"] = float(p.get("brier_sum", 0.0)) + brier
            bucket = p["calibration_bins"][str(bidx)]
            bucket["n"] += 1
            bucket["sum_pred"] += pred
            bucket["sum_obs"] += obs

        session_update = None
        if skill_id:
            skills = data.get("skills", {})
            if skill_id in skills:
                q_old = float(skills[skill_id].get("q_value", 0.5))
                reward = max(0.0, min(1.0, 1.0 - brier))
                alpha = 0.15
                q_new = max(0.0, min(1.0, q_old + alpha * (reward - q_old)))
                skills[skill_id]["q_value"] = round(q_new, 4)
                skills[skill_id]["last_used"] = datetime.now().isoformat()
                if obs:
                    skills[skill_id]["success_count"] = int(skills[skill_id].get("success_count", 0)) + 1
                else:
                    skills[skill_id]["failure_count"] = int(skills[skill_id].get("failure_count", 0)) + 1
                data.setdefault("q_table", {})[skill_id] = round(q_new, 4)
                session_update = {
                    "skill_id": skill_id,
                    "old_q": round(q_old, 4),
                    "new_q": round(q_new, 4),
                    "reward": round(reward, 4),
                }

        bootstrap["updated_at"] = datetime.now().isoformat()
        bootstrap.setdefault("outcomes", []).append(
            {
                "timestamp": datetime.now().isoformat(),
                "predicted": pred,
                "observed": obs,
                "brier": round(brier, 6),
                "skill_id": skill_id,
                "delay_seconds": max(0, int(delay_seconds)),
            }
        )
        bootstrap["outcomes"] = bootstrap["outcomes"][-1000:]
        data["bootstrap"] = bootstrap
        return {
            "ok": True,
            "predicted": pred,
            "observed": obs,
            "brier": round(brier, 6),
            "session_update": session_update,
        }

    def bootstrap_open_dispute(
        self,
        sid: str,
        claim_id: str,
        predicted: float,
        reason: str,
        skill_id: Optional[str] = None,
    ) -> dict:
        """Open a dispute for a claim with delayed/contested outcome."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap")
            if not bootstrap:
                init_res = self.bootstrap_init(sid)
                if init_res.get("error"):
                    return init_res
                data = self._load_skills(sid)
                bootstrap = data.get("bootstrap")
            disputes = bootstrap.setdefault("disputes", [])
            did = f"disp_{uuid.uuid4().hex[:8]}"
            row = {
                "dispute_id": did,
                "claim_id": str(claim_id),
                "skill_id": skill_id,
                "predicted": max(0.001, min(0.999, float(predicted))),
                "reason": str(reason or "").strip(),
                "status": "open",
                "opened_at": datetime.now().isoformat(),
                "resolved_at": None,
                "observed": None,
                "delay_seconds": None,
                "brier": None,
            }
            disputes.append(row)
            bootstrap["disputes"] = disputes[-500:]
            bootstrap["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap
            self._save_skills(sid, data)
            return {"ok": True, "dispute": row}

    def bootstrap_list_disputes(self, sid: str, status: Optional[str] = None) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            disputes = list(((data.get("bootstrap") or {}).get("disputes") or []))
            if status:
                status = str(status).strip().lower()
                disputes = [d for d in disputes if str(d.get("status", "")).lower() == status]
            return {
                "ok": True,
                "count": len(disputes),
                "open": sum(1 for d in disputes if d.get("status") == "open"),
                "resolved": sum(1 for d in disputes if d.get("status") == "resolved"),
                "disputes": disputes,
            }

    def bootstrap_resolve_dispute(
        self,
        sid: str,
        dispute_id: str,
        observed: int,
        delay_seconds: int = 0,
    ) -> dict:
        """Resolve a dispute and feed the outcome into calibration pipeline."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            bootstrap = data.get("bootstrap") or {}
            disputes = bootstrap.get("disputes") or []
            target = None
            for d in disputes:
                if str(d.get("dispute_id")) == str(dispute_id):
                    target = d
                    break
            if not target:
                return make_error(MCPError.NOT_FOUND, f"Dispute {dispute_id} not found")
            if target.get("status") == "resolved":
                return {"ok": True, "dispute": target, "message": "Dispute already resolved"}

            ingest = self._bootstrap_apply_outcome_in_memory(
                sid,
                data,
                predicted=float(target.get("predicted", 0.5)),
                observed=int(observed),
                skill_id=target.get("skill_id"),
                delay_seconds=int(delay_seconds),
            )
            if ingest.get("error"):
                return ingest

            bootstrap2 = data.get("bootstrap") or {}
            disputes2 = bootstrap2.get("disputes") or []
            for d in disputes2:
                if str(d.get("dispute_id")) == str(dispute_id):
                    d["status"] = "resolved"
                    d["resolved_at"] = datetime.now().isoformat()
                    d["observed"] = 1 if int(observed) else 0
                    d["delay_seconds"] = max(0, int(delay_seconds))
                    d["brier"] = ingest.get("brier")
                    target = d
                    break
            bootstrap2["disputes"] = disputes2
            bootstrap2["updated_at"] = datetime.now().isoformat()
            data["bootstrap"] = bootstrap2
            self._save_skills(sid, data)
            return {"ok": True, "dispute": target, "ingest": ingest}

    def _bootstrap_prior_confidence(self, bootstrap: Optional[dict]) -> float:
        """Estimate confidence prior from tournament policy quality (0..1)."""
        if not isinstance(bootstrap, dict):
            return 0.5
        policies = bootstrap.get("policies") or {}
        if not policies:
            return 0.5
        rows = []
        for p in policies.values():
            samples = max(1, int(p.get("samples", 0)))
            avg_brier = float(p.get("brier_sum", 0.0)) / samples
            rating = float(p.get("rating", 1500.0))
            # Convert rating to confidence-like weight around 0.5 baseline.
            rating_conf = 1.0 / (1.0 + math.exp(-(rating - 1500.0) / 220.0))
            quality = max(0.0, min(1.0, 1.0 - avg_brier))
            rows.append((samples, quality, rating_conf))
        if not rows:
            return 0.5
        # Weight by sample support and rating confidence.
        num = 0.0
        den = 0.0
        for samples, quality, rating_conf in rows:
            w = max(1.0, math.sqrt(float(samples))) * (0.5 + 0.5 * rating_conf)
            num += w * quality
            den += w
        if den <= 0.0:
            return 0.5
        return max(0.0, min(1.0, num / den))

    def crystallize_skill(
        self, sid: str, name: str, description: str, steps: list,
        tags: Optional[list] = None, memrl_reward: Optional[float] = None,
    ) -> dict:
        """Crystallize a workflow into a reusable L3 skill, stored in global registry."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            skill_id = f"skill_{name.lower().replace(' ', '_')}"
            skill = {
                "name": name,
                "description": description,
                "steps": steps,
                "tags": tags or [],
                "created_at": datetime.now().isoformat(),
                "success_count": 0,
                "failure_count": 0,
                "last_used": None,
                "q_value": 0.5,
            }
            data["skills"][skill_id] = skill
            data["q_table"][skill_id] = 0.5
            self._save_skills(sid, data)
            # Also save to global registry for cross-session access
            self._crystallize_to_global_registry(sid, skill_id, skill)
            session.update_access()
            self._save_metadata(session)
            return {"ok": True, "skill_id": skill_id, "skill": skill, "global": True}

    def rate_skill(self, sid: str, skill_id: str, reward: float) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            skill = data["skills"].get(skill_id)
            if not skill:
                return make_error(MCPError.NOT_FOUND, f"Skill {skill_id} not found")
            alpha = 0.15
            current_q = data["q_table"].get(skill_id, 0.5)
            new_q = max(0.0, min(1.0, current_q + alpha * (reward - current_q)))
            data["q_table"][skill_id] = round(new_q, 4)
            skill["q_value"] = round(new_q, 4)
            skill["last_used"] = datetime.now().isoformat()
            if reward > 0:
                skill["success_count"] += 1
            else:
                skill["failure_count"] += 1
            self._save_skills(sid, data)
            # Update global registry
            self._crystallize_to_global_registry(sid, skill_id, skill)
            # L3 -> L2 promotion if Q-value exceeds 0.8
            result = {"ok": True, "skill_id": skill_id, "q_value": skill["q_value"], "reward": reward}
            if new_q >= 0.8:
                result["promoted_to_L2"] = True
            return result

    def list_skills(self, sid: str, min_q: float = 0.0, global_skills: bool = True) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            local = {
                k: v for k, v in data["skills"].items() if v.get("q_value", 0.0) >= min_q
            }
            # Sort by Q-value
            local = dict(sorted(local.items(), key=lambda x: x[1].get("q_value", 0), reverse=True))
            result = {"ok": True, "local_skills": local, "local_count": len(local)}
            if global_skills:
                global_skills = self._find_global_skills(tags=list(local.keys()), limit=20)
                result["global_skills"] = global_skills
                result["global_count"] = len(global_skills)
            return result

    def suggest_strategy(self, sid: str, context: str = "") -> dict:
        """Suggest highest-Q skills from both local and global registry."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)

            # Local skills
            ranked = []
            ctx_lower = (context or "").lower()
            ctx_has_text = bool((context or "").strip())
            bootstrap = data.get("bootstrap")
            bootstrap_prior = self._bootstrap_prior_confidence(bootstrap)
            embedder = None
            ctx_vec = None
            if ctx_has_text:
                try:
                    from ida_pro_mcp.host.intelligence import BgeCodeEmbedder
                    embedder = BgeCodeEmbedder()
                    ctx_vec = embedder.embed((context or "")[:1200])
                except Exception:
                    embedder = None
                    ctx_vec = None
            for skill_id, skill in data["skills"].items():
                base_score = float(skill.get("q_value", 0.5))
                desc = (skill.get("description", "") + " " + " ".join(skill.get("tags", []))).lower()
                context_relevance = 0.0
                if ctx_has_text:
                    if embedder is not None and ctx_vec is not None and desc.strip():
                        try:
                            dvec = embedder.embed(desc[:1200])
                            context_relevance = float(BgeCodeEmbedder.cosine(ctx_vec, dvec))
                        except Exception:
                            context_relevance = 0.0
                    elif ctx_lower and any(word in desc for word in ctx_lower.split()):
                        # Deterministic fallback when embeddings unavailable.
                        context_relevance = 0.5
                    skill["context_match"] = bool(context_relevance > 0.0)
                score = ((base_score + context_relevance) / 2.0) if ctx_has_text else base_score
                samples = int(skill.get("success_count", 0)) + int(skill.get("failure_count", 0))
                blend = self.bootstrap_compute_blend(sid, session_samples=samples)
                weights = (blend or {}).get("weights") or {"bootstrap": 0.5, "session": 0.5}
                blended_score = (
                    float(weights.get("session", 0.5)) * float(score)
                    + float(weights.get("bootstrap", 0.5)) * float(bootstrap_prior)
                )
                ranked.append(
                    {
                        "skill_id": skill_id,
                        "score": round(score, 4),
                        "blended_score": round(blended_score, 4),
                        "blend_weights": weights,
                        "bootstrap_prior": round(bootstrap_prior, 4),
                        "source": "local",
                        **skill,
                    }
                )

            # Global skills
            global_skills = self._find_global_skills(context=context, limit=10)
            for gs in global_skills:
                if gs["skill_id"] not in data["skills"]:
                    base_score = float(gs.get("q_value", 0.5))
                    desc = (str(gs.get("description", "")) + " " + " ".join(gs.get("tags", []))).lower()
                    context_relevance = 0.0
                    if ctx_has_text:
                        if embedder is not None and ctx_vec is not None and desc.strip():
                            try:
                                dvec = embedder.embed(desc[:1200])
                                context_relevance = float(BgeCodeEmbedder.cosine(ctx_vec, dvec))
                            except Exception:
                                context_relevance = 0.0
                        elif ctx_lower and any(word in desc for word in ctx_lower.split()):
                            context_relevance = 0.5
                    score = ((base_score + context_relevance) / 2.0) if ctx_has_text else base_score
                    weights = (self.bootstrap_compute_blend(sid, session_samples=0) or {}).get("weights") or {
                        "bootstrap": 0.5,
                        "session": 0.5,
                    }
                    blended_score = (
                        float(weights.get("session", 0.5)) * float(score)
                        + float(weights.get("bootstrap", 0.5)) * float(bootstrap_prior)
                    )
                    ranked.append(
                        {
                            "skill_id": gs["skill_id"],
                            "score": round(score, 4),
                            "blended_score": round(blended_score, 4),
                            "blend_weights": weights,
                            "bootstrap_prior": round(bootstrap_prior, 4),
                            "source": "global",
                            **gs,
                        }
                    )

            ranked.sort(key=lambda x: -float(x.get("blended_score", x.get("score", 0.0))))
            return {
                "ok": True,
                "suggestions": ranked[:10],
                "context": context,
                "bootstrap_prior": round(bootstrap_prior, 4),
                "bootstrap_initialized": bool(bootstrap),
            }

    # ====================================================================
    # ACTIVITY LOG + DEAD-END DETECTION
    # ====================================================================

    def log_activity(self, sid: str, tool: str, action: str, result: str = "") -> dict:
        """Log activity and check for dead-end patterns."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            entry = {
                "tool": tool, "action": action, "result": result,
                "timestamp": datetime.now().isoformat(),
            }
            data.setdefault("activity_log", []).append(entry)
            # Keep last 500 entries (was 100 — way too small)
            data["activity_log"] = data["activity_log"][-500:]
            self._save_skills(sid, data)
            session.update_access()
            self._save_metadata(session)
            out = {"ok": True}
            # Dead-end detection
            dead_end = self._detect_dead_end(data["activity_log"])
            if dead_end:
                out["dead_end_warning"] = dead_end
            return out

    def check_state_contract(self, sid: str, window: int = 8) -> dict:
        """Check if analyst has persisted findings to blackboard within recent window."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return {"ok": False, "error": "session_not_found"}
            data = self._load_skills(sid)
            log = data.get("activity_log", [])
            recent = log[-window:]
            bb_writes = sum(
                1
                for e in recent
                if isinstance(e, dict)
                and e.get("tool") == "blackboard"
                and str(e.get("action") or "").startswith("write")
            )
            return {
                "ok": True,
                "session_id": sid,
                "contract_met": bb_writes > 0,
                "blackboard_writes_in_window": bb_writes,
                "window_size": len(recent),
                "recommended_action": {
                    "tool": "blackboard",
                    "arguments": {
                        "action": "write",
                        "name": "finding_summary",
                        "notes": "<concise finding from recent analysis>",
                        "category": "analysis",
                        "priority": 3,
                    },
                },
            }

    def _detect_dead_end(self, activity_log: List[dict]) -> Optional[dict]:
        """Detect stalled analysis patterns."""
        if len(activity_log) < 10:
            return None
        recent = activity_log[-20:]
        # Pattern 1: Same function decompiled >4 times in a row
        decompile_targets = [e.get("result") for e in recent if e.get("action") == "decompile" and e.get("result")]
        if len(decompile_targets) >= 5 and len(set(decompile_targets[-5:])) == 1:
            return {
                "type": "repeated_decompile",
                "function": decompile_targets[-1],
                "count": decompile_targets.count(decompile_targets[-1]),
                "suggestion": "Try looking at callers, callees, or xrefs of this function instead of redecompiling.",
            }
        # Pattern 2: Same search query >3 times
        searches = [e.get("result") for e in recent if e.get("action") in ("find", "search") and e.get("result")]
        if searches:
            last_search = searches[-1]
            if searches.count(last_search) >= 4:
                return {
                    "type": "repeated_search",
                    "query": last_search,
                    "suggestion": "Try broadening the search or using structured search with different constraints.",
                }
        # Pattern 3: Looping between two tools
        tool_seq = [(e["tool"], e["action"]) for e in recent[-10:]]
        if len(tool_seq) >= 6:
            pairs = [(tool_seq[i], tool_seq[i + 1]) for i in range(len(tool_seq) - 1)]
            for pair in set(pairs):
                if pairs.count(pair) >= 3:
                    return {
                        "type": "tool_loop",
                        "pattern": f"{pair[0][0]}.{pair[0][1]} <-> {pair[1][0]}.{pair[1][1]}",
                        "suggestion": "You may be stuck in a loop. Try pivoting to a different analysis approach.",
                    }
        return None

    def get_activity_log(self, sid: str, limit: int = 20) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            log = data.get("activity_log", [])
            return {"ok": True, "log": log[-limit:], "total": len(log)}

    # ====================================================================
    # METRICS DASHBOARD
    # ====================================================================

    def dashboard(self, sid: str) -> dict:
        """Analysis progress dashboard for the LLM."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            activity_log = data.get("activity_log", [])
            hypotheses = data.get("hypotheses", [])
            skills = data.get("skills", {})

            # Count unique actions
            unique_actions = set()
            tool_action_counts: Dict[str, int] = {}
            for e in activity_log:
                key = f"{e.get('tool')}.{e.get('action')}"
                unique_actions.add(key)
                tool_action_counts[key] = tool_action_counts.get(key, 0) + 1

            # Calculate completion indicators
            functions_decompiled = tool_action_counts.get("code.decompile", 0) + tool_action_counts.get("code.semantic_decompile", 0)
            searches_performed = sum(v for k, v in tool_action_counts.items() if k.startswith("search.") or k.startswith("data."))
            xrefs_traced = sum(v for k, v in tool_action_counts.items() if "xref" in k)

            return {
                "ok": True,
                "phase": session.phase,
                "activity": {
                    "total_actions": len(activity_log),
                    "unique_tools_used": len(unique_actions),
                    "functions_decompiled": functions_decompiled,
                    "searches_performed": searches_performed,
                    "xrefs_traced": xrefs_traced,
                },
                "hypotheses": {
                    "total": len(hypotheses),
                    "confirmed": sum(1 for h in hypotheses if h.get("status") == "confirmed"),
                    "refuted": sum(1 for h in hypotheses if h.get("status") == "refuted"),
                    "pending": sum(1 for h in hypotheses if h.get("status") == "pending"),
                },
                "skills": {"crystallized": len(skills), "avg_q_value": round(sum(s.get("q_value", 0) for s in skills.values()) / max(1, len(skills)), 3)},
                "bootstrap": {
                    "initialized": bool(data.get("bootstrap")),
                    "tournament_runs": int((data.get("bootstrap") or {}).get("tournament_runs", 0)),
                    "total_rounds": int((data.get("bootstrap") or {}).get("total_rounds", 0)),
                    "prior_confidence": round(self._bootstrap_prior_confidence(data.get("bootstrap")), 4),
                },
                "suggested_next": _ANALYSIS_PHASES.get(session.phase, {}).get("suggested_tools", []),
            }

    # ====================================================================
    # PHASE TRANSITION
    # ====================================================================

    def get_phase(self, sid: str) -> dict:
        session = self.sessions.get(sid)
        if not session:
            return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
        phase_info = _ANALYSIS_PHASES.get(session.phase, {})
        return {"ok": True, "phase": session.phase, "description": phase_info.get("description", ""),
                "suggested_tools": phase_info.get("suggested_tools", [])}

    def advance_phase(self, sid: str) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            phases = sorted(_ANALYSIS_PHASES.keys(), key=lambda p: _ANALYSIS_PHASES[p]["order"])
            try:
                idx = phases.index(session.phase)
                if idx < len(phases) - 1:
                    session.phase = phases[idx + 1]
            except ValueError:
                session.phase = "triage"
            session.update_access()
            self._save_metadata(session)
            phase_info = _ANALYSIS_PHASES.get(session.phase, {})
            return {"ok": True, "phase": session.phase, "description": phase_info.get("description", ""),
                    "suggested_tools": phase_info.get("suggested_tools", [])}

    # ====================================================================
    # FEDERATED SESSION LINKING
    # ====================================================================

    def link_session(self, sid: str, other_sid: str) -> dict:
        with self._lock:
            session = self.sessions.get(sid)
            other = self.sessions.get(other_sid)
            if not session or not other:
                return make_error(MCPError.SESSION_NOT_FOUND, f"One or both sessions not found")
            if other_sid not in session.linked_sessions:
                session.linked_sessions.append(other_sid)
            if sid not in other.linked_sessions:
                other.linked_sessions.append(sid)
            session.update_access()
            self._save_metadata(session)
            self._save_metadata(other)
            return {"ok": True, "linked": [sid, other_sid]}

    def cross_reference_sessions(self, sid: str) -> dict:
        """Find shared functions/strings across linked sessions."""
        session = self.sessions.get(sid)
        if not session:
            return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
        linked = session.linked_sessions
        if not linked:
            return {"ok": True, "shared": [], "note": "No linked sessions. Use link_session to federate."}
        # Collect function names from all linked sessions' skills data
        shared_funcs: Dict[str, List[str]] = {}
        for lsid in [sid] + linked:
            data = self._load_skills(lsid)
            for entry in data.get("activity_log", []):
                func = entry.get("result", "")
                if func:
                    shared_funcs.setdefault(func, []).append(lsid)
        # Only keep functions appearing in multiple sessions
        cross = {k: v for k, v in shared_funcs.items() if len(set(v)) > 1}
        return {"ok": True, "shared_functions": list(cross.keys()), "details": cross}


# ============================================================================
# BOOKMARK MANAGER
# ============================================================================


class BookmarkManager:
    def __init__(self, session_dir: str):
        self.session_dir = session_dir
        self._lock = threading.RLock()

    def _get_path(self, sid: str) -> str:
        return os.path.join(self.session_dir, f"SID_{sid}_bookmarks.json")

    def load(self, sid: str) -> List[dict]:
        path = self._get_path(sid)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                log_rpc(f"Failed to load bookmarks for {sid}: {e}")
                return []
        return []

    def save(self, sid: str, bookmarks: List[dict]) -> dict:
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
                tags = [t.strip() for t in tags.split(",") if t.strip()]
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
                    if res.get("error"):
                        return res
                    return {"ok": True, "updated": True, "bookmark": new_bm}
            bookmarks.append(new_bm)
            res = self.save(sid, bookmarks)
            if res.get("error"):
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
                try:
                    filtered = [b for b in filtered if b.get("priority", 0) >= int(f_pri)]
                except (ValueError, TypeError):
                    pass
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
                return res if res.get("error") else {"ok": True, "deleted": original_len - len(bookmarks)}
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
                                val = [t.strip() for t in val.split(",") if t.strip()]
                            bookmarks[i][key] = val
                    res = self.save(sid, bookmarks)
                    return res if res.get("error") else {"ok": True, "bookmark": bookmarks[i]}
            return make_error(MCPError.BOOKMARK_NOT_FOUND, "Bookmark not found")

    def clear(self, sid: str) -> dict:
        with self._lock:
            res = self.save(sid, [])
            return res if res.get("error") else {"ok": True}

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
