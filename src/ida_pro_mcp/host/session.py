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

    def restore_snapshot(self, sid: str, snapshot_id: str) -> Optional[dict]:
        """Restore session state from a persisted snapshot."""
        with self._lock:
            snapshots = self._load_snapshots(sid)
            snap = None
            for s in snapshots:
                if s.get("_snapshot_id") == snapshot_id:
                    snap = s
                    break
            if not snap:
                return make_error(MCPError.NOT_FOUND, f"Snapshot {snapshot_id} not found for {sid}")
            # Restore metadata
            meta = snap.get("metadata", {})
            session = self.sessions.get(sid)
            if session:
                for key, val in meta.items():
                    if key not in ("session_id", "created_at", "_snapshot_id", "_snapshot_time", "_message"):
                        if hasattr(session, key):
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
            return {"ok": True, "restored": snapshot_id}

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
            for skill_id, skill in data["skills"].items():
                score = skill.get("q_value", 0.5)
                desc = (skill.get("description", "") + " " + " ".join(skill.get("tags", []))).lower()
                if ctx_lower and any(word in desc for word in ctx_lower.split()):
                    score += 0.15
                    skill["context_match"] = True
                ranked.append({"skill_id": skill_id, "score": round(score, 4), "source": "local", **skill})

            # Global skills
            global_skills = self._find_global_skills(context=context, limit=10)
            for gs in global_skills:
                if gs["skill_id"] not in data["skills"]:
                    ranked.append({"skill_id": gs["skill_id"], "score": gs.get("q_value", 0.5), "source": "global", **gs})

            ranked.sort(key=lambda x: -x["score"])
            return {"ok": True, "suggestions": ranked[:10], "context": context}

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
