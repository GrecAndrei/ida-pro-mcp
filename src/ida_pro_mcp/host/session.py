#!/usr/bin/env python3
"""
Session management: Session, SessionManager, BookmarkManager.
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

# =============================================================================
# SESSION MANAGEMENT
# =============================================================================


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

    def _derive_auto_name(self) -> str:
        """Derive a human-friendly name from the binary path."""
        if self.binary_path:
            return os.path.basename(self.binary_path)
        if self.idb_path:
            base = os.path.basename(self.idb_path)
            # Strip SID prefix if present
            if base.startswith("SID_") and "_" in base[4:]:
                base = base.split("_", 2)[-1]
            return os.path.splitext(base)[0]
        return f"session_{self.session_id}"

    def update_access(self):
        """Update last accessed timestamp"""
        self.last_accessed = datetime.now()

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "idb_path": self.idb_path,
            "binary_path": self.binary_path,
            "analysis_options": self.analysis_options,
            "analysis_applied": self.analysis_applied,
            "ida_args": self.ida_args,
            "binary_exists": bool(
                self.binary_path and os.path.exists(self.binary_path)
            ),
            "idb_exists": bool(self.idb_path and os.path.exists(self.idb_path)),
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "tags": self.tags,
            "notes": self.notes,
            "auto_name": self.auto_name,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        """Load session from metadata dict"""
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
        )


class SessionManager:
    def __init__(self, cache_dir: str):
        self._lock = threading.RLock()
        self.sessions: Dict[str, Session] = {}
        self.cache_dir = cache_dir
        self.session_dir = os.path.join(cache_dir, "sessions")
        self._snapshots: Dict[
            str, List[dict]
        ] = {}  # sid -> list (in-memory only, lost on restart)
        os.makedirs(self.session_dir, exist_ok=True)
        # Auto-load existing sessions on startup
        self._load_sessions()

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

    def _new_session_id(self) -> str:
        for _ in range(MAX_SESSION_ID_RETRIES):
            sid = uuid.uuid4().hex[:8].upper()
            if sid not in self.sessions:
                return sid
        raise RuntimeError(
            f"failed to allocate unique session id after {MAX_SESSION_ID_RETRIES} retries"
        )

    def _get_metadata_path(self, sid: str) -> str:
        """Get path to session metadata file"""
        return os.path.join(self.session_dir, f"SID_{sid}_metadata.json")

    def get_session_artifact_dir(self, sid: str, create: bool = True) -> str:
        path = os.path.join(self.session_dir, f"SID_{sid}")
        if create:
            os.makedirs(path, exist_ok=True)
        return path

    def _save_metadata(self, session: Session):
        """Persist session metadata to disk (atomic write)"""
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
        """Load all existing sessions from metadata files"""
        pattern = os.path.join(self.session_dir, "SID_*_metadata.json")
        for meta_path in glob.glob(pattern):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    session = Session.from_dict(data)
                    if not _normalize_session_id(session.session_id):
                        log_rpc(
                            f"Skipping metadata with invalid session_id: {meta_path}"
                        )
                        continue
                    # Always load the session - IDB might not exist yet if session is new
                    # We'll let IDA create it on first use
                    self.sessions[session.session_id] = session
                    log_rpc(f"Loaded session {session.session_id} from metadata")
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
            name = filename[len(prefix) :]
            return os.path.splitext(name)[0]
        return ""

    def _load_orphaned_idbs(self):
        """Recover sessions from IDB files missing metadata."""
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
            log_rpc(f"Recovered orphaned session {sid} from {idb_path}")

    def create_session(
        self,
        binary_path: str,
        use_existing: Optional[str] = None,
        analysis_options: Optional[dict] = None,
        idb_path: Optional[str] = None,
        ida_args: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        notes: str = "",
    ) -> Session:
        with self._lock:
            sid = self._new_session_id()
            # Use SID-specific name to avoid collisions and track metadata easily
            idb_base = (
                os.path.basename(binary_path) if binary_path else f"session_{sid}"
            )
            idb_name = f"SID_{sid}_{idb_base}.i64"
            resolved_idb = (
                idb_path or use_existing or os.path.join(self.session_dir, idb_name)
            )
            if resolved_idb and os.path.isdir(resolved_idb):
                resolved_idb = os.path.join(resolved_idb, idb_name)
            if resolved_idb and not os.path.splitext(resolved_idb)[1]:
                resolved_idb = f"{resolved_idb}.i64"
            session = Session(
                sid,
                resolved_idb,
                binary_path or "",
                analysis_options=analysis_options,
                analysis_applied=False,
                ida_args=ida_args or [],
                tags=self._sanitize_tags(tags),
                notes=self._sanitize_note(notes),
            )
            self.sessions[sid] = session
            # Persist metadata immediately
            self._save_metadata(session)
            return session

    def get_session(self, sid: str) -> Optional[Session]:
        """Get session and update last_accessed timestamp"""
        with self._lock:
            session = self.sessions.get(sid)
            if session:
                session.update_access()
                return copy.deepcopy(session)
            return None

    def find_session_by_path(self, path: str) -> Optional[Session]:
        """Find a session by binary_path or idb_path (normalized comparison)."""
        with self._lock:
            norm = os.path.realpath(os.path.abspath(path))
            for s in self.sessions.values():
                if (
                    s.binary_path
                    and os.path.realpath(os.path.abspath(s.binary_path)) == norm
                ):
                    return copy.copy(s)
                if s.idb_path and os.path.realpath(os.path.abspath(s.idb_path)) == norm:
                    return copy.copy(s)
            return None

    def discover_sessions(self, query: str = "") -> List[Session]:
        """Return all active sessions, optionally filtered by query.

        The *query* is matched against session_id, binary_path, idb_path,
        auto_name, tags, and notes using automatic regex / glob / substring detection.
        """
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
        """Delete a session without acquiring the lock (caller must hold _lock)."""
        session = self.sessions.pop(sid, None)
        self._snapshots.pop(sid, None)
        deleted = False
        base_pattern = os.path.join(self.session_dir, f"SID_{sid}*")
        for f in glob.glob(base_pattern):
            try:
                if os.path.isdir(f):
                    shutil.rmtree(f, ignore_errors=True)
                else:
                    os.remove(f)
                deleted = True
                log_rpc(f"Deleted session file: {f}")
            except Exception as e:
                log_rpc(f"Failed to delete {f}: {e}")
        for log_name in (
            f"ida_mcp_{sid}.log",
            f"ida_stdout_{sid}.log",
            f"ida_stderr_{sid}.log",
        ):
            log_path = os.path.join(self.cache_dir, log_name)
            if os.path.exists(log_path):
                try:
                    os.remove(log_path)
                    deleted = True
                    log_rpc(f"Deleted session log: {log_path}")
                except Exception as e:
                    log_rpc(f"Failed to delete {log_path}: {e}")
        return bool(session) or deleted

    def delete_session(self, sid: str) -> bool:
        with self._lock:
            return self._delete_session_unlocked(sid)

    # --- New feature methods ---

    def update_session(self, sid: str, **kwargs) -> Optional[Session]:
        """Update session fields."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            for key, value in kwargs.items():
                if hasattr(session, key) and key not in ("session_id", "created_at"):
                    if key == "tags":
                        value = self._sanitize_tags(
                            value if isinstance(value, list) else [value]
                        )
                    elif key == "notes":
                        value = self._sanitize_note(value)
                    elif key == "auto_name":
                        value = self._sanitize_name(value)
                    setattr(session, key, value)
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def rename_session(self, sid: str, new_name: str) -> Optional[Session]:
        """Set a custom auto_name."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            session.auto_name = self._sanitize_name(new_name)
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def duplicate_session(self, sid: str) -> Optional[Session]:
        """Clone a session with a new SID."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            new_sid = self._new_session_id()
            new_session = Session(
                new_sid,
                session.idb_path,
                session.binary_path,
                analysis_options=dict(session.analysis_options),
                analysis_applied=session.analysis_applied,
                ida_args=list(session.ida_args),
                tags=list(session.tags),
                notes=session.notes,
                auto_name=f"{session.auto_name} (copy)",
            )
            self.sessions[new_sid] = new_session
            self._save_metadata(new_session)
            return copy.copy(new_session)

    def export_session(self, sid: str) -> Optional[dict]:
        """Export session metadata as a portable dict."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            data = session.to_dict()
            data["_exported_at"] = datetime.now().isoformat()
            return data

    def import_session(self, data: dict) -> Session:
        """Import a session from exported dict."""
        with self._lock:
            # Generate a new SID to avoid collisions
            new_sid = self._new_session_id()
            data_copy = dict(data)
            data_copy["session_id"] = new_sid
            data_copy.pop("_exported_at", None)
            session = Session.from_dict(data_copy)
            self.sessions[new_sid] = session
            self._save_metadata(session)
            return copy.copy(session)

    def archive_session(self, sid: str) -> Optional[Session]:
        """Mark session as archived."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            if "archived" not in session.tags:
                session.tags.append("archived")
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def unarchive_session(self, sid: str) -> Optional[Session]:
        """Remove archived tag."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            session.tags = [t for t in session.tags if t != "archived"]
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def list_archived(self) -> List[Session]:
        """List archived sessions."""
        with self._lock:
            return [
                copy.copy(s) for s in self.sessions.values() if "archived" in s.tags
            ]

    def list_active(self) -> List[Session]:
        """List non-archived sessions."""
        with self._lock:
            return [
                copy.copy(s) for s in self.sessions.values() if "archived" not in s.tags
            ]

    def get_session_age(self, sid: str) -> Optional[timedelta]:
        """Return timedelta since creation."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            return datetime.now() - session.created_at

    def get_session_idle_time(self, sid: str) -> Optional[timedelta]:
        """Return timedelta since last access."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            return datetime.now() - session.last_accessed

    def cleanup_stale(self, max_age_days: int = 30) -> List[str]:
        """Delete sessions older than max_age_days. Returns list of deleted SIDs."""
        with self._lock:
            cutoff = datetime.now() - timedelta(days=max_age_days)
            stale = [
                sid for sid, s in self.sessions.items() if s.last_accessed < cutoff
            ]
            for sid in stale:
                self._delete_session_unlocked(sid)
            return stale

    def get_stats(self) -> dict:
        """Return statistics about sessions."""
        with self._lock:
            total = len(self.sessions)
            if total == 0:
                return {
                    "total": 0,
                    "active": 0,
                    "archived": 0,
                    "avg_age_days": 0,
                    "tags": {},
                }
            archived = sum(1 for s in self.sessions.values() if "archived" in s.tags)
            now = datetime.now()
            ages = [
                (now - s.created_at).total_seconds() for s in self.sessions.values()
            ]
            avg_age_days = (sum(ages) / len(ages)) / 86400 if ages else 0
            tag_counts: Dict[str, int] = {}
            for s in self.sessions.values():
                for t in s.tags:
                    tag_counts[t] = tag_counts.get(t, 0) + 1
            return {
                "total": total,
                "active": total - archived,
                "archived": archived,
                "avg_age_days": round(avg_age_days, 2),
                "tags": tag_counts,
            }

    def _tag_session_unlocked(self, sid: str, tag: str) -> Optional[Session]:
        """Add a tag without acquiring the lock (caller must hold _lock)."""
        session = self.sessions.get(sid)
        if not session:
            return None
        if tag not in session.tags:
            session.tags.append(tag)
        session.update_access()
        self._save_metadata(session)
        return copy.copy(session)

    def tag_session(self, sid: str, tag: str) -> Optional[Session]:
        """Add a tag to a session."""
        with self._lock:
            cleaned = self._sanitize_tags([tag])
            if not cleaned:
                return None
            return self._tag_session_unlocked(sid, cleaned[0])

    def untag_session(self, sid: str, tag: str) -> Optional[Session]:
        """Remove a tag from a session."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            session.tags = [t for t in session.tags if t != tag]
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def find_by_tag(self, tag: str) -> List[Session]:
        """Find sessions by tag."""
        with self._lock:
            return [copy.copy(s) for s in self.sessions.values() if tag in s.tags]

    def add_note(self, sid: str, note: str) -> Optional[Session]:
        """Append to notes."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            note = self._sanitize_note(note)
            if session.notes:
                combined = f"{session.notes}\n{note}"
            else:
                combined = note
            session.notes = self._sanitize_note(combined)
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def clear_notes(self, sid: str) -> Optional[Session]:
        """Clear notes."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            session.notes = ""
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def set_binary_path(self, sid: str, path: str) -> Optional[Session]:
        """Update binary path."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            session.binary_path = path
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def set_idb_path(self, sid: str, path: str) -> Optional[Session]:
        """Update IDB path."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            session.idb_path = path
            session.update_access()
            self._save_metadata(session)
            return copy.copy(session)

    def bulk_delete(self, sids: List[str]) -> dict:
        """Delete multiple sessions at once."""
        with self._lock:
            results = {}
            for sid in sids:
                results[sid] = self._delete_session_unlocked(sid)
            return results

    def bulk_tag(self, sids: List[str], tag: str) -> dict:
        """Tag multiple sessions."""
        with self._lock:
            cleaned = self._sanitize_tags([tag])
            if not cleaned:
                return {sid: False for sid in sids}
            safe_tag = cleaned[0]
            results = {}
            for sid in sids:
                result = self._tag_session_unlocked(sid, safe_tag)
                results[sid] = result is not None
            return results

    def search_notes(self, query: str) -> List[Session]:
        """Search across all session notes."""
        with self._lock:
            matcher = compile_smart_pattern(query, case_sensitive=False)
            return [
                copy.copy(s)
                for s in self.sessions.values()
                if s.notes and matcher(s.notes)
            ]

    def get_recent(self, n: int = 5) -> List[Session]:
        """Get N most recently accessed sessions."""
        with self._lock:
            sorted_sessions = sorted(
                self.sessions.values(), key=lambda s: s.last_accessed, reverse=True
            )
            return [copy.copy(s) for s in sorted_sessions[:n]]

    def get_oldest(self, n: int = 5) -> List[Session]:
        """Get N oldest sessions."""
        with self._lock:
            sorted_sessions = sorted(self.sessions.values(), key=lambda s: s.created_at)
            return [copy.copy(s) for s in sorted_sessions[:n]]

    def session_exists(self, sid: str) -> bool:
        """Check if a session exists."""
        with self._lock:
            return sid in self.sessions

    def count(self) -> int:
        """Return total session count."""
        with self._lock:
            return len(self.sessions)

    def merge_sessions(self, sid1: str, sid2: str) -> Optional[Session]:
        """Merge metadata (tags, notes) from sid2 into sid1."""
        with self._lock:
            s1 = self.sessions.get(sid1)
            s2 = self.sessions.get(sid2)
            if not s1 or not s2:
                return None
            for tag in s2.tags:
                if tag not in s1.tags:
                    s1.tags.append(tag)
            if s2.notes:
                if s1.notes:
                    s1.notes += "\n" + s2.notes
                else:
                    s1.notes = s2.notes
            s1.update_access()
            self._save_metadata(s1)
            return copy.copy(s1)

    def snapshot_session(self, sid: str) -> Optional[str]:
        """Save a point-in-time snapshot of session metadata. Returns snapshot_id.
        Note: Snapshots are stored in memory only and lost on process restart."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return None
            seen = {s.get("_snapshot_id") for s in self._snapshots.get(sid, [])}
            snapshot_id = None
            for _ in range(MAX_SNAPSHOT_ID_RETRIES):
                candidate = uuid.uuid4().hex[:8]
                if candidate not in seen:
                    snapshot_id = candidate
                    break
            if snapshot_id is None:
                log_rpc(
                    f"Failed to allocate snapshot id for session {sid} after {MAX_SNAPSHOT_ID_RETRIES} retries"
                )
                return None
            snapshot = session.to_dict()
            snapshot["_snapshot_id"] = snapshot_id
            snapshot["_snapshot_time"] = datetime.now().isoformat()
            if sid not in self._snapshots:
                self._snapshots[sid] = []
            self._snapshots[sid].append(snapshot)
            if len(self._snapshots[sid]) > MAX_SNAPSHOTS_PER_SESSION:
                self._snapshots[sid] = self._snapshots[sid][-MAX_SNAPSHOTS_PER_SESSION:]
            return snapshot_id

    def restore_snapshot(self, sid: str, snapshot_id: str) -> Optional[Session]:
        """Restore from a snapshot.
        Note: Snapshots are stored in memory only and lost on process restart."""
        with self._lock:
            snapshots = self._snapshots.get(sid, [])
            snap = None
            for s in snapshots:
                if s.get("_snapshot_id") == snapshot_id:
                    snap = s
                    break
            if not snap:
                return None
            data = {k: v for k, v in snap.items() if not k.startswith("_snapshot")}
            data["session_id"] = sid
            restored = Session.from_dict(data)
            self.sessions[sid] = restored
            self._save_metadata(restored)
            return copy.copy(restored)

    def validate_session(self, sid: str) -> Optional[dict]:
        """Validate session integrity (check paths, metadata)."""
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
            return {
                "session_id": sid,
                "valid": len(issues) == 0,
                "issues": issues,
            }


    # ============================================================================
    # VOERA: Task Skill Crystallization & Episodic Memory (MemRL-inspired)
    # ============================================================================

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
        return {"skills": {}, "q_table": {}, "activity_log": []}

    def _save_skills(self, sid: str, data: dict):
        path = self._get_skills_path(sid)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            log_rpc(f"Failed to save skills for {sid}: {e}")

    def crystallize_skill(
        self,
        sid: str,
        name: str,
        description: str,
        steps: list,
        tags: Optional[list] = None,
    ) -> dict:
        """Crystallize a successful workflow into a reusable L3 Task Skill."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            skill_id = f"skill_{name.lower().replace(' ', '_')}"
            data["skills"][skill_id] = {
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
            data["q_table"][skill_id] = 0.5
            self._save_skills(sid, data)
            session.update_access()
            self._save_metadata(session)
            return {"ok": True, "skill_id": skill_id, "skill": data["skills"][skill_id]}

    def rate_skill(self, sid: str, skill_id: str, reward: float) -> dict:
        """Update Q-value for a skill using TD-style update (MemRL-inspired)."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            skill = data["skills"].get(skill_id)
            if not skill:
                return make_error(MCPError.NOT_FOUND, f"Skill {skill_id} not found")

            alpha = 0.15  # Learning rate
            current_q = data["q_table"].get(skill_id, 0.5)
            new_q = current_q + alpha * (reward - current_q)
            new_q = max(0.0, min(1.0, new_q))

            data["q_table"][skill_id] = round(new_q, 4)
            skill["q_value"] = round(new_q, 4)
            skill["last_used"] = datetime.now().isoformat()
            if reward > 0:
                skill["success_count"] += 1
            else:
                skill["failure_count"] += 1

            self._save_skills(sid, data)
            session.update_access()
            self._save_metadata(session)
            return {
                "ok": True,
                "skill_id": skill_id,
                "q_value": skill["q_value"],
                "reward": reward,
                "success_count": skill["success_count"],
                "failure_count": skill["failure_count"],
            }

    def list_skills(self, sid: str, min_q: float = 0.0) -> dict:
        """List all skills for a session, optionally filtered by minimum Q-value."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            skills = {
                k: v
                for k, v in data["skills"].items()
                if v.get("q_value", 0.0) >= min_q
            }
            # Sort by Q-value descending
            sorted_skills = dict(
                sorted(skills.items(), key=lambda x: x[1].get("q_value", 0), reverse=True)
            )
            return {"ok": True, "skills": sorted_skills, "count": len(sorted_skills)}

    def suggest_strategy(self, sid: str, context: str = "") -> dict:
        """Suggest the highest-Q skill based on current context."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            if not data["skills"]:
                return {
                    "ok": True,
                    "suggestions": [],
                    "note": "No skills crystallized yet. Use crystallize_skill to save successful workflows.",
                }

            # Rank by Q-value; simple context matching could boost scores
            ranked = []
            ctx_lower = (context or "").lower()
            for skill_id, skill in data["skills"].items():
                score = skill.get("q_value", 0.5)
                desc = (skill.get("description", "") + " " + " ".join(skill.get("tags", []))).lower()
                if ctx_lower and any(word in desc for word in ctx_lower.split()):
                    score += 0.1
                ranked.append({"skill_id": skill_id, "score": round(score, 4), **skill})

            ranked.sort(key=lambda x: -x["score"])
            return {"ok": True, "suggestions": ranked[:5], "context": context}

    def log_activity(self, sid: str, tool: str, action: str, result: str = "") -> dict:
        """Log an activity for episodic memory tracking."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            entry = {
                "tool": tool,
                "action": action,
                "result": result,
                "timestamp": datetime.now().isoformat(),
            }
            data.setdefault("activity_log", []).append(entry)
            # Keep last 100 entries
            data["activity_log"] = data["activity_log"][-100:]
            self._save_skills(sid, data)
            return {"ok": True}

    def get_activity_log(self, sid: str, limit: int = 20) -> dict:
        """Get recent activity log for a session."""
        with self._lock:
            session = self.sessions.get(sid)
            if not session:
                return make_error(MCPError.SESSION_NOT_FOUND, f"Session {sid} not found")
            data = self._load_skills(sid)
            log = data.get("activity_log", [])
            return {"ok": True, "log": log[-limit:], "total": len(log)}


class BookmarkManager:
    def __init__(self, session_dir: str):
        self.session_dir = session_dir

    def _get_path(self, sid: str) -> str:
        return os.path.join(self.session_dir, f"SID_{sid}_bookmarks.json")

    def load(self, sid: str) -> List[dict]:
        path = self._get_path(sid)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def save(self, sid: str, bookmarks: List[dict]) -> dict:
        path = self._get_path(sid)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(bookmarks, f, indent=2)
            return {"ok": True}
        except Exception as e:
            return make_error(MCPError.IO_ERROR, f"Failed to save bookmarks: {e}")

    def add(self, sid: str, data: dict) -> dict:
        if not data.get("addr"):
            return make_error(MCPError.INVALID_ARGS, "addr required")
        bookmarks = self.load(sid)
        max_id = max([b.get("id", 0) for b in bookmarks]) if bookmarks else 0

        tags = data.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        new_bm = {
            "id": max_id + 1,
            "addr": data.get("addr"),
            "name": data.get("name", f"Mark at {data.get('addr')}"),
            "notes": data.get("notes", ""),
            "category": data.get("category", "general"),
            "priority": int(data.get("priority", 3)),
            "tags": tags,
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

    def list(self, sid: str, filters: dict) -> dict:
        filters = filters or {}
        bookmarks = self.load(sid)
        f_cat = filters.get("category")
        f_tag = filters.get("tag")
        f_pri = filters.get("priority")
        f_query = filters.get("query")

        filtered = bookmarks
        if f_cat:
            cat_matcher = compile_smart_pattern(f_cat, case_sensitive=False)
            filtered = [b for b in filtered if cat_matcher(b.get("category", ""))]
        if f_tag:
            tag_matcher = compile_smart_pattern(f_tag, case_sensitive=False)
            filtered = [
                b for b in filtered if any(tag_matcher(t) for t in b.get("tags", []))
            ]
        if f_pri:
            filtered = [b for b in filtered if b.get("priority", 0) >= int(f_pri)]
        if f_query:
            q_matcher = compile_smart_pattern(f_query, case_sensitive=False)
            filtered = [
                b
                for b in filtered
                if q_matcher(b.get("name", ""))
                or q_matcher(b.get("notes", ""))
                or q_matcher(b.get("addr", ""))
            ]

        return {
            "ok": True,
            "bookmarks": filtered,
            "total": len(bookmarks),
            "count": len(filtered),
        }

    def delete(self, sid: str, data: dict) -> dict:
        bid = data.get("id")
        addr = data.get("addr")
        if not bid and not addr:
            return make_error(MCPError.INVALID_ARGS, "id or addr required")

        bookmarks = self.load(sid)
        original_len = len(bookmarks)
        if bid:
            bookmarks = [b for b in bookmarks if b.get("id") != int(bid)]
        else:
            bookmarks = [b for b in bookmarks if b.get("addr") != addr]

        if len(bookmarks) < original_len:
            res = self.save(sid, bookmarks)
            if res.get("error"):
                return res
            return {"ok": True, "deleted": original_len - len(bookmarks)}
        return make_error(MCPError.BOOKMARK_NOT_FOUND, "Bookmark not found")

    def update(self, sid: str, data: dict) -> dict:
        bid = data.get("id")
        if not bid:
            return make_error(MCPError.INVALID_ARGS, "id required")

        bookmarks = self.load(sid)
        for i, bm in enumerate(bookmarks):
            if bm.get("id") == int(bid):
                for key in ["name", "notes", "category", "priority", "tags", "addr"]:
                    if key in data:
                        val = data[key]
                        if key == "tags" and isinstance(val, str):
                            val = [t.strip() for t in val.split(",") if t.strip()]
                        bookmarks[i][key] = val
                res = self.save(sid, bookmarks)
                if res.get("error"):
                    return res
                return {"ok": True, "bookmark": bookmarks[i]}
        return make_error(MCPError.BOOKMARK_NOT_FOUND, "Bookmark not found")

    def clear(self, sid: str) -> dict:
        res = self.save(sid, [])
        if res.get("error"):
            return res
        return {"ok": True}

    def find(self, sid: str, query: str) -> dict:
        bookmarks = self.load(sid)
        matcher = compile_smart_pattern(query, case_sensitive=False)
        results = []
        for b in bookmarks:
            if (
                matcher(b.get("name", ""))
                or matcher(b.get("notes", ""))
                or any(matcher(t) for t in b.get("tags", []))
                or matcher(b.get("addr", ""))
                or matcher(b.get("category", ""))
            ):
                results.append(b)
        return {"ok": True, "results": results, "count": len(results)}

    def export(self, sid: str) -> dict:
        bookmarks = self.load(sid)
        if not bookmarks:
            return {"ok": True, "report": "No bookmarks found."}

        lines = [f"# Forensic Research Report - Session {sid}", ""]
        for b in sorted(bookmarks, key=lambda x: x.get("priority", 3)):
            prio = "⭐" * (6 - b.get("priority", 3))
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



