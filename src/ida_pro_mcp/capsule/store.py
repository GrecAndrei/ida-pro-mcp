from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import (
    CapsuleNotInitializedError,
    CapsuleValidationError,
    CapsuleVerificationError,
)
from .manifest import default_manifest
from .migrations import initialize_schema
from .schema import (
    FORMAT_NAME,
    FORMAT_VERSION,
    REQUIRED_META_KEYS,
    SCHEMA_VERSION,
    TRUST_STATES,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CapsuleStore:
    def __init__(self, path: Path, conn: sqlite3.Connection):
        self.path = Path(path)
        self.conn = conn
        self.conn.row_factory = sqlite3.Row

    @classmethod
    def open(cls, path: Path | str) -> "CapsuleStore":
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(p))
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            pass
        return cls(p, conn)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "CapsuleStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _json_dumps(self, value: Any) -> str:
        try:
            return json.dumps(value, separators=(",", ":"), sort_keys=True)
        except TypeError as exc:
            raise CapsuleValidationError(f"value is not JSON serializable: {exc}") from exc

    def _set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            """
            INSERT INTO meta(key, value, updated_at) VALUES(?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """,
            (key, value, _now()),
        )

    def _get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return str(row["value"]) if row else None

    def init(self, project_name: str, created_by: str = "ida-pro-mcp", force: bool = False) -> None:
        if force:
            self.conn.execute("DROP TABLE IF EXISTS notes")
            self.conn.execute("DROP TABLE IF EXISTS audit_events")
            self.conn.execute("DROP TABLE IF EXISTS sessions")
            self.conn.execute("DROP TABLE IF EXISTS backend_profiles")
            self.conn.execute("DROP TABLE IF EXISTS client_profiles")
            self.conn.execute("DROP TABLE IF EXISTS install_reports")
            self.conn.execute("DROP TABLE IF EXISTS blobs")
            self.conn.execute("DROP TABLE IF EXISTS objects")
            self.conn.execute("DROP TABLE IF EXISTS manifest")
            self.conn.execute("DROP TABLE IF EXISTS meta")
            self.conn.commit()

        initialize_schema(self.conn)
        now = _now()
        self._set_meta("format_name", FORMAT_NAME)
        self._set_meta("format_version", str(FORMAT_VERSION))
        self._set_meta("schema_version", str(SCHEMA_VERSION))
        self._set_meta("created_at", now)
        self._set_meta("updated_at", now)
        self._set_meta("created_by", created_by)
        self._set_meta("project_name", project_name)

        manifest = default_manifest(project_name=project_name, created_by=created_by)
        self.conn.execute(
            """
            INSERT INTO manifest(id, json, updated_at) VALUES (1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at
            """,
            (self._json_dumps(manifest), now),
        )
        self.conn.commit()

    def _assert_initialized(self) -> None:
        row = self.conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='meta'").fetchone()
        if not row:
            raise CapsuleNotInitializedError("capsule schema is not initialized")

    def is_initialized(self) -> bool:
        try:
            self._assert_initialized()
        except CapsuleNotInitializedError:
            return False
        return self._get_meta("format_name") is not None

    def get_manifest(self) -> dict:
        self._assert_initialized()
        row = self.conn.execute("SELECT json FROM manifest WHERE id=1").fetchone()
        if not row:
            raise CapsuleNotInitializedError("manifest is missing")
        return json.loads(str(row["json"]))

    def update_manifest(self, manifest: dict) -> None:
        self._assert_initialized()
        if not isinstance(manifest, dict):
            raise CapsuleValidationError("manifest must be a JSON object")
        now = _now()
        payload = self._json_dumps(manifest)
        self.conn.execute(
            """
            INSERT INTO manifest(id, json, updated_at) VALUES(1, ?, ?)
            ON CONFLICT(id) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at
            """,
            (payload, now),
        )
        self._set_meta("updated_at", now)
        self.conn.commit()

    def add_install_report(self, report: dict, report_id: str | None = None) -> str:
        self._assert_initialized()
        payload = self._json_dumps(report)
        rid = report_id or str(uuid.uuid4())
        created_at = str(report.get("started_at") or report.get("created_at") or _now())
        status = str(report.get("status") or "unknown")
        self.conn.execute(
            "INSERT OR REPLACE INTO install_reports(id, created_at, status, json) VALUES(?, ?, ?, ?)",
            (rid, created_at, status, payload),
        )
        self.conn.commit()
        return rid

    def add_embedding_state(self, state: dict, state_id: str | None = None) -> str:
        self._assert_initialized()
        payload = self._json_dumps(state)
        sid = state_id or str(uuid.uuid4())
        created_at = str(state.get("created_at") or _now())
        updated_at = str(state.get("updated_at") or created_at)
        backend = str(state.get("backend") or "unknown")
        model_path = state.get("model_path")
        model_hash = state.get("model_hash")
        embedding_dim = int(state.get("embedding_dim") or 0)
        if embedding_dim <= 0:
            raise CapsuleValidationError("embedding_state.embedding_dim must be > 0")
        self.conn.execute(
            """
            INSERT OR REPLACE INTO embedding_states(
                id, created_at, updated_at, backend, model_path, model_hash, embedding_dim,
                index_metadata_json, anchor_metadata_json, last_indexed_functions_json, thresholds_json, json
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sid,
                created_at,
                updated_at,
                backend,
                str(model_path) if model_path else None,
                str(model_hash) if model_hash else None,
                embedding_dim,
                self._json_dumps(state.get("index_metadata") or {}),
                self._json_dumps(state.get("anchor_metadata") or {}),
                self._json_dumps(state.get("last_indexed_functions") or []),
                self._json_dumps(state.get("thresholds") or {}),
                payload,
            ),
        )
        self.conn.commit()
        return sid

    def add_audit_event(self, event_type: str, payload: dict, session_id: str | None = None) -> int:
        self._assert_initialized()
        data = self._json_dumps(payload)
        cur = self.conn.execute(
            "INSERT INTO audit_events(created_at, event_type, session_id, json) VALUES(?, ?, ?, ?)",
            (_now(), event_type, session_id, data),
        )
        self.conn.commit()
        if cur.lastrowid is None:
            raise CapsuleValidationError("failed to persist audit event")
        return int(cur.lastrowid)

    def upsert_session(self, session_id: str, state: dict) -> None:
        self._assert_initialized()
        payload = self._json_dumps(state)
        now = _now()
        self.conn.execute(
            """
            INSERT INTO sessions(session_id, created_at, updated_at, state_json)
            VALUES(?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET updated_at=excluded.updated_at, state_json=excluded.state_json
            """,
            (session_id, now, now, payload),
        )
        self.conn.commit()

    def add_note(
        self,
        kind: str,
        title: str,
        body: str,
        metadata: dict | None = None,
        note_id: str | None = None,
    ) -> str:
        self._assert_initialized()
        nid = note_id or str(uuid.uuid4())
        now = _now()
        self.conn.execute(
            """
            INSERT INTO notes(id, created_at, updated_at, kind, title, body, metadata_json)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (nid, now, now, kind, title, body, self._json_dumps(metadata or {})),
        )
        self.conn.commit()
        return nid

    def upsert_client_profile(self, name: str, kind: str, config: dict) -> None:
        self._assert_initialized()
        self.conn.execute(
            """
            INSERT INTO client_profiles(name, kind, config_json, updated_at)
            VALUES(?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, config_json=excluded.config_json, updated_at=excluded.updated_at
            """,
            (name, kind, self._json_dumps(config), _now()),
        )
        self.conn.commit()

    def upsert_backend_profile(self, name: str, kind: str, config: dict) -> None:
        self._assert_initialized()
        self.conn.execute(
            """
            INSERT INTO backend_profiles(name, kind, config_json, updated_at)
            VALUES(?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, config_json=excluded.config_json, updated_at=excluded.updated_at
            """,
            (name, kind, self._json_dumps(config), _now()),
        )
        self.conn.commit()

    def store_blob(self, data: bytes, kind: str, media_type: str | None = None, metadata: dict | None = None) -> str:
        self._assert_initialized()
        sha = hashlib.sha256(data).hexdigest()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO objects(sha256, kind, size, media_type, created_at, metadata_json)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            (sha, kind, len(data), media_type, _now(), self._json_dumps(metadata or {})),
        )
        self.conn.execute("INSERT OR REPLACE INTO blobs(sha256, data) VALUES(?, ?)", (sha, data))
        self.conn.commit()
        return sha

    def get_blob(self, sha256: str) -> bytes:
        self._assert_initialized()
        row = self.conn.execute("SELECT data FROM blobs WHERE sha256=?", (sha256,)).fetchone()
        if not row:
            raise CapsuleValidationError(f"blob not found: {sha256}")
        return bytes(row["data"])

    def inspect_summary(self) -> dict:
        self._assert_initialized()
        manifest = self.get_manifest()
        get_count = lambda table: int(self.conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"])
        return {
            "path": str(self.path),
            "format": f"{self._get_meta('format_name')}/v{self._get_meta('format_version')}",
            "schema_version": int(self._get_meta("schema_version") or 0),
            "project_name": self._get_meta("project_name") or "",
            "backends": sorted(list((manifest.get("backends") or {}).keys())),
            "trust_state": (manifest.get("trust") or {}).get("state", "unknown"),
            "contains_executable_payloads": bool(
                (manifest.get("trust") or {}).get("contains_executable_payloads", False)
            ),
            "sessions": get_count("sessions"),
            "audit_events": get_count("audit_events"),
            "objects": get_count("objects"),
        }

    def verify(self) -> dict:
        self._assert_initialized()
        row = self.conn.execute("PRAGMA integrity_check").fetchone()
        if not row or str(row[0]).lower() != "ok":
            raise CapsuleVerificationError("sqlite integrity_check failed")

        keys = {
            str(r["key"]) for r in self.conn.execute("SELECT key FROM meta").fetchall()
        }
        missing = REQUIRED_META_KEYS - keys
        if missing:
            raise CapsuleVerificationError(f"missing required meta keys: {sorted(missing)}")

        manifest = self.get_manifest()
        if manifest.get("format") != FORMAT_NAME:
            raise CapsuleVerificationError("manifest format mismatch")
        if int(manifest.get("format_version", -1)) != FORMAT_VERSION:
            raise CapsuleVerificationError("manifest format_version mismatch")
        if int(manifest.get("schema_version", -1)) != SCHEMA_VERSION:
            raise CapsuleVerificationError("manifest schema_version mismatch")

        trust = manifest.get("trust") or {}
        trust_state = trust.get("state")
        if trust_state not in TRUST_STATES:
            raise CapsuleVerificationError(f"invalid trust.state: {trust_state}")

        blob_rows = self.conn.execute(
            "SELECT o.sha256, b.data FROM objects o JOIN blobs b ON o.sha256=b.sha256"
        ).fetchall()
        for row in blob_rows:
            digest = hashlib.sha256(bytes(row["data"])).hexdigest()
            if digest != row["sha256"]:
                raise CapsuleVerificationError(f"blob hash mismatch for {row['sha256']}")

        verified_at = _now()
        trust["last_verified_at"] = verified_at
        manifest["trust"] = trust
        self.update_manifest(manifest)
        return {
            "ok": True,
            "verified_at": verified_at,
            "checks": {
                "integrity_check": "ok",
                "required_meta": True,
                "manifest": True,
                "blob_hashes": True,
            },
        }
