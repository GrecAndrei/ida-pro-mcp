from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
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


def _normalize_source_ref(ref: Any) -> dict:
    """Normalize source refs into backend-neutral semantic shape."""
    if not isinstance(ref, dict):
        ref = {}
    backend = str(ref.get("backend") or "ida")
    stable_ref = str(ref.get("stable_ref") or ref.get("addr") or "")
    object_kind = str(ref.get("object_kind") or ref.get("kind") or "function")
    return {
        "backend": backend,
        "binary_id": str(ref.get("binary_id") or ref.get("idb_path") or ""),
        "object_kind": object_kind,
        "stable_ref": stable_ref,
        "name": str(ref.get("name") or ""),
    }


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
        initialize_schema(conn)
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
            self.conn.execute("DROP TABLE IF EXISTS evidence_cards")
            self.conn.execute("DROP TABLE IF EXISTS behavior_hits")
            self.conn.execute("DROP TABLE IF EXISTS semantic_vectors")
            self.conn.execute("DROP TABLE IF EXISTS semantic_items")
            self.conn.execute("DROP TABLE IF EXISTS semantic_indexes")
            self.conn.execute("DROP TABLE IF EXISTS embedding_states")
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
        self._upgrade_schema_if_needed()

    def _upgrade_schema_if_needed(self) -> None:
        schema_ver = self._get_meta("schema_version")
        if schema_ver is None:
            return
        try:
            current = int(schema_ver)
        except ValueError:
            current = 0
        if current >= SCHEMA_VERSION:
            return
        initialize_schema(self.conn)
        now = _now()
        self._set_meta("schema_version", str(SCHEMA_VERSION))
        self._set_meta("updated_at", now)
        row = self.conn.execute("SELECT json FROM manifest WHERE id=1").fetchone()
        if row:
            manifest = json.loads(str(row["json"]))
            manifest["schema_version"] = SCHEMA_VERSION
            self.conn.execute(
                "UPDATE manifest SET json=?, updated_at=? WHERE id=1",
                (self._json_dumps(manifest), now),
            )
        self.conn.commit()


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

    def add_semantic_index(
        self,
        *,
        kind: str,
        backend: str,
        dim: int,
        model_id: str = "",
        model_fingerprint: dict | None = None,
        anchor_set_hash: str = "",
        source_fingerprint: str = "",
        metadata: dict | None = None,
        index_id: str | None = None,
    ) -> str:
        self._assert_initialized()
        sid = index_id or str(uuid.uuid4())
        now = _now()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO semantic_indexes(
                id, kind, backend, dim, model_id, model_fingerprint_json, anchor_set_hash,
                source_fingerprint, created_at, updated_at, metadata_json
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sid,
                kind,
                backend,
                int(dim),
                model_id or None,
                self._json_dumps(model_fingerprint or {}),
                anchor_set_hash or None,
                source_fingerprint or None,
                now,
                now,
                self._json_dumps(metadata or {}),
            ),
        )
        self.conn.commit()
        return sid

    def upsert_semantic_item(
        self,
        *,
        index_id: str,
        kind: str,
        stable_ref: str,
        text_hash: str,
        title: str = "",
        vector_sha256: str = "",
        metadata: dict | None = None,
        item_id: str | None = None,
    ) -> str:
        self._assert_initialized()
        sid = item_id or str(uuid.uuid4())
        now = _now()
        self.conn.execute(
            """
            INSERT INTO semantic_items(
                id, index_id, kind, stable_ref, title, text_hash, vector_sha256, metadata_json, created_at, updated_at
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(index_id, kind, stable_ref) DO UPDATE SET
                title=excluded.title,
                text_hash=excluded.text_hash,
                vector_sha256=excluded.vector_sha256,
                metadata_json=excluded.metadata_json,
                updated_at=excluded.updated_at
            """,
            (
                sid,
                index_id,
                kind,
                stable_ref,
                title or None,
                text_hash,
                vector_sha256 or None,
                self._json_dumps(metadata or {}),
                now,
                now,
            ),
        )
        row = self.conn.execute(
            "SELECT id FROM semantic_items WHERE index_id=? AND kind=? AND stable_ref=?",
            (index_id, kind, stable_ref),
        ).fetchone()
        self.conn.commit()
        return str(row["id"]) if row else sid

    def store_semantic_vector(self, data: bytes, dim: int, dtype: str = "float32") -> str:
        self._assert_initialized()
        sha = hashlib.sha256(data).hexdigest()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO semantic_vectors(vector_sha256, dim, dtype, data, created_at)
            VALUES(?, ?, ?, ?, ?)
            """,
            (sha, int(dim), dtype, data, _now()),
        )
        self.conn.commit()
        return sha

    def add_behavior_hit(
        self,
        *,
        item_id: str,
        behavior: str,
        confidence: float,
        anchor_set_hash: str = "",
        explain: list | None = None,
        hit_id: str | None = None,
    ) -> str:
        self._assert_initialized()
        hid = hit_id or str(uuid.uuid4())
        self.conn.execute(
            """
            INSERT INTO behavior_hits(id, item_id, behavior, confidence, anchor_set_hash, explain_json, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hid,
                item_id,
                behavior,
                float(confidence),
                anchor_set_hash or None,
                self._json_dumps(explain or []),
                _now(),
            ),
        )
        self.conn.commit()
        return hid

    def add_evidence_card(
        self,
        *,
        claim: str,
        claim_type: str,
        confidence: float = 0.0,
        evidence: list | None = None,
        source_refs: list | None = None,
        metadata: dict | None = None,
        card_id: str | None = None,
    ) -> str:
        self._assert_initialized()
        cid = card_id or str(uuid.uuid4())
        now = _now()
        normalized_source_refs = [_normalize_source_ref(r) for r in (source_refs or [])]
        self.conn.execute(
            """
            INSERT OR REPLACE INTO evidence_cards(
                id, created_at, updated_at, claim, claim_type, confidence, evidence_json, source_refs_json, metadata_json
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cid,
                now,
                now,
                claim,
                claim_type,
                float(confidence),
                self._json_dumps(evidence or []),
                self._json_dumps(normalized_source_refs),
                self._json_dumps(metadata or {}),
            ),
        )
        self.conn.commit()
        return cid

    def list_semantic_indexes(self) -> list[dict]:
        self._assert_initialized()
        rows = self.conn.execute(
            """
            SELECT id, kind, backend, dim, model_id, anchor_set_hash, source_fingerprint, created_at, updated_at
            FROM semantic_indexes
            ORDER BY created_at DESC
            """
        ).fetchall()
        return [dict(row) for row in rows]

    def list_evidence_cards(self, limit: int = 100, claim_type: str = "") -> list[dict]:
        self._assert_initialized()
        lim = max(1, min(int(limit or 100), 5000))
        params: list[Any] = []
        sql = (
            "SELECT id, created_at, updated_at, claim, claim_type, confidence, "
            "evidence_json, source_refs_json, metadata_json FROM evidence_cards"
        )
        if claim_type:
            sql += " WHERE claim_type=?"
            params.append(str(claim_type))
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(lim)
        rows = self.conn.execute(sql, tuple(params)).fetchall()
        out = []
        for row in rows:
            out.append(
                {
                    "id": str(row["id"]),
                    "created_at": str(row["created_at"]),
                    "updated_at": str(row["updated_at"]),
                    "claim": str(row["claim"]),
                    "claim_type": str(row["claim_type"]),
                    "confidence": float(row["confidence"]),
                    "evidence": json.loads(str(row["evidence_json"] or "[]")),
                    "source_refs": json.loads(str(row["source_refs_json"] or "[]")),
                    "metadata": json.loads(str(row["metadata_json"] or "{}")),
                }
            )
        return out

    def semantic_summary(self) -> dict:
        self._assert_initialized()
        get_count = lambda table: int(self.conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"])
        return {
            "semantic_indexes": get_count("semantic_indexes"),
            "semantic_items": get_count("semantic_items"),
            "semantic_vectors": get_count("semantic_vectors"),
            "behavior_hits": get_count("behavior_hits"),
            "evidence_cards": get_count("evidence_cards"),
        }

    def import_function_embedding_index(
        self,
        index_db_path: Path | str,
        *,
        mode: str = "metadata-only",
        index_id: str | None = None,
        max_items: int = 100_000,
    ) -> dict:
        self._assert_initialized()
        p = Path(index_db_path)
        if not p.exists():
            raise CapsuleValidationError(f"embedding index not found: {p}")
        if mode not in {"metadata-only", "with-vectors"}:
            raise CapsuleValidationError("mode must be 'metadata-only' or 'with-vectors'")

        src = sqlite3.connect(str(p))
        src.row_factory = sqlite3.Row
        try:
            meta_rows = {}
            try:
                for row in src.execute("SELECT key, value FROM embedding_meta"):
                    meta_rows[str(row["key"])] = str(row["value"])
            except sqlite3.DatabaseError:
                meta_rows = {}

            dim = int(meta_rows.get("embedding_dim") or 1536)
            sid = self.add_semantic_index(
                kind="function",
                backend=meta_rows.get("embedding_backend", "unknown"),
                dim=dim,
                model_id=meta_rows.get("model_path", ""),
                model_fingerprint={
                    "model_size": meta_rows.get("model_size", ""),
                    "model_sha256_head": meta_rows.get("model_sha256_head", ""),
                    "server_bin": meta_rows.get("server_bin", ""),
                    "server_sha256_head": meta_rows.get("server_sha256_head", ""),
                },
                anchor_set_hash=meta_rows.get("anchor_set_hash", ""),
                source_fingerprint=meta_rows.get("source_fingerprint", ""),
                metadata={
                    "source_index_path": str(p),
                    "source_idb_path": meta_rows.get("source_idb_path", ""),
                    "source_binary_path": meta_rows.get("source_binary_path", ""),
                    "mode": mode,
                },
                index_id=index_id,
            )

            imported_items = 0
            imported_vectors = 0
            available_cols = {
                str(r["name"])
                for r in src.execute("PRAGMA table_info(func_embeddings)").fetchall()
            }
            select_cols = [
                "ea",
                "name",
                "dim",
                "vec_blob",
                "pseudo_hash",
                "indexed_at",
                "source_kind" if "source_kind" in available_cols else "'function' AS source_kind",
                "source_hash" if "source_hash" in available_cols else "'' AS source_hash",
                "signature_hash" if "signature_hash" in available_cols else "'' AS signature_hash",
            ]
            query = f"SELECT {', '.join(select_cols)} FROM func_embeddings LIMIT ?"
            for row in src.execute(query, (int(max_items),)):
                vector_sha = ""
                row_dim = int(row["dim"] or dim)
                blob = bytes(row["vec_blob"]) if row["vec_blob"] is not None else b""
                if mode == "with-vectors" and blob:
                    vector_sha = self.store_semantic_vector(blob, dim=row_dim, dtype="float32")
                    imported_vectors += 1
                item_metadata = {
                    "name": str(row["name"] or row["ea"]),
                    "pseudo_hash": str(row["pseudo_hash"] or ""),
                    "indexed_at": row["indexed_at"],
                    "source_kind": str(row["source_kind"] or "function"),
                    "source_hash": str(row["source_hash"] or ""),
                    "signature_hash": str(row["signature_hash"] or ""),
                    "dim": row_dim,
                }
                self.upsert_semantic_item(
                    index_id=sid,
                    kind="function",
                    stable_ref=str(row["ea"]),
                    title=str(row["name"] or row["ea"]),
                    text_hash=str(row["pseudo_hash"] or row["signature_hash"] or ""),
                    vector_sha256=vector_sha,
                    metadata=item_metadata,
                )
                imported_items += 1

            return {
                "ok": True,
                "index_id": sid,
                "mode": mode,
                "imported_items": imported_items,
                "imported_vectors": imported_vectors,
                "source_index_path": str(p),
            }
        finally:
            src.close()

    def export_function_embedding_index(
        self,
        *,
        index_id: str,
        out_path: Path | str,
        mode: str = "metadata-only",
    ) -> dict:
        self._assert_initialized()
        if mode not in {"metadata-only", "with-vectors"}:
            raise CapsuleValidationError("mode must be 'metadata-only' or 'with-vectors'")
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.exists():
            out.unlink()

        row = self.conn.execute("SELECT * FROM semantic_indexes WHERE id=?", (index_id,)).fetchone()
        if not row:
            raise CapsuleValidationError(f"semantic index not found: {index_id}")
        if str(row["kind"]) != "function":
            raise CapsuleValidationError("export_function_embedding_index requires a function semantic index")

        dst = sqlite3.connect(str(out))
        try:
            dst.execute(
                """
                CREATE TABLE IF NOT EXISTS func_embeddings (
                    ea TEXT PRIMARY KEY,
                    name TEXT,
                    dim INTEGER,
                    vec_blob BLOB NOT NULL,
                    pseudo_hash TEXT,
                    indexed_at REAL,
                    source_kind TEXT DEFAULT 'function',
                    source_hash TEXT,
                    signature_text TEXT,
                    signature_hash TEXT
                )
                """
            )
            dst.execute("CREATE INDEX IF NOT EXISTS idx_fe_name ON func_embeddings(name)")
            dst.execute(
                """
                CREATE TABLE IF NOT EXISTS embedding_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            model_fp = json.loads(str(row["model_fingerprint_json"] or "{}"))
            meta_pairs = {
                "index_schema_version": "2",
                "embedding_backend": str(row["backend"]),
                "embedding_dim": str(row["dim"]),
                "model_path": str(row["model_id"] or ""),
                "model_size": str(model_fp.get("model_size", "")),
                "model_sha256_head": str(model_fp.get("model_sha256_head", "")),
                "server_bin": str(model_fp.get("server_bin", "")),
                "server_sha256_head": str(model_fp.get("server_sha256_head", "")),
                "anchor_set_hash": str(row["anchor_set_hash"] or ""),
                "source_fingerprint": str(row["source_fingerprint"] or ""),
                "source_idb_path": "",
                "source_binary_path": "",
                "exported_at": _now(),
                "export_mode": mode,
            }
            dst.executemany(
                "INSERT OR REPLACE INTO embedding_meta(key, value) VALUES(?, ?)",
                list(meta_pairs.items()),
            )

            items = self.conn.execute(
                """
                SELECT stable_ref, title, text_hash, vector_sha256, metadata_json
                FROM semantic_items
                WHERE index_id=? AND kind='function'
                ORDER BY created_at ASC
                """,
                (index_id,),
            ).fetchall()
            exported_items = 0
            exported_vectors = 0
            for item in items:
                md = json.loads(str(item["metadata_json"] or "{}"))
                dim = int(md.get("dim") or row["dim"] or 1536)
                blob = b""
                if mode == "with-vectors" and item["vector_sha256"]:
                    vrow = self.conn.execute(
                        "SELECT data FROM semantic_vectors WHERE vector_sha256=?",
                        (str(item["vector_sha256"]),),
                    ).fetchone()
                    if vrow:
                        blob = bytes(vrow["data"])
                        exported_vectors += 1
                dst.execute(
                    """
                    INSERT OR REPLACE INTO func_embeddings(
                        ea, name, dim, vec_blob, pseudo_hash, indexed_at, source_kind, source_hash, signature_text, signature_hash
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(item["stable_ref"]),
                        str(item["title"] or item["stable_ref"]),
                        dim,
                        blob,
                        str(md.get("pseudo_hash") or item["text_hash"] or ""),
                        md.get("indexed_at"),
                        str(md.get("source_kind") or "function"),
                        str(md.get("source_hash") or ""),
                        None,
                        str(md.get("signature_hash") or ""),
                    ),
                )
                exported_items += 1
            dst.commit()
            return {
                "ok": True,
                "index_id": index_id,
                "mode": mode,
                "out_path": str(out),
                "exported_items": exported_items,
                "exported_vectors": exported_vectors,
            }
        finally:
            dst.close()

    def export_analysis_capsule(
        self,
        *,
        out_path: Path | str,
        include_vectors: bool = False,
        include_notes: bool = True,
        include_audit: bool = False,
        include_experience: bool = True,
    ) -> dict:
        """Export an analysis-only capsule view without raw binary/blob payloads."""
        self._assert_initialized()
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.exists():
            out.unlink()

        manifest = self.get_manifest()
        trust = dict(manifest.get("trust") or {})
        trust["contains_executable_payloads"] = False
        trust.setdefault("state", "inspected")

        with CapsuleStore.open(out) as dst:
            dst.init(
                project_name=str(self._get_meta("project_name") or "analysis-export"),
                created_by="ida-pro-mcp-analysis-export",
                force=True,
            )

            exported_manifest = dict(manifest)
            exported_manifest["trust"] = trust
            exported_manifest.setdefault("analysis_export", {})
            exported_manifest["analysis_export"].update(
                {
                    "source_capsule": str(self.path),
                    "exported_at": _now(),
                    "mode": {
                        "include_vectors": bool(include_vectors),
                        "include_notes": bool(include_notes),
                        "include_audit": bool(include_audit),
                        "include_experience": bool(include_experience),
                    },
                }
            )
            dst.update_manifest(exported_manifest)

            # Profiles and sessions are metadata and safe to export.
            for row in self.conn.execute(
                "SELECT name, kind, config_json FROM backend_profiles ORDER BY name ASC"
            ).fetchall():
                dst.upsert_backend_profile(
                    str(row["name"]),
                    str(row["kind"]),
                    json.loads(str(row["config_json"] or "{}")),
                )
            for row in self.conn.execute(
                "SELECT name, kind, config_json FROM client_profiles ORDER BY name ASC"
            ).fetchall():
                dst.upsert_client_profile(
                    str(row["name"]),
                    str(row["kind"]),
                    json.loads(str(row["config_json"] or "{}")),
                )
            for row in self.conn.execute(
                "SELECT session_id, state_json FROM sessions ORDER BY created_at ASC"
            ).fetchall():
                dst.upsert_session(
                    str(row["session_id"]),
                    json.loads(str(row["state_json"] or "{}")),
                )

            if include_notes:
                for row in self.conn.execute(
                    "SELECT kind, title, body, metadata_json, id FROM notes ORDER BY created_at ASC"
                ).fetchall():
                    dst.add_note(
                        kind=str(row["kind"]),
                        title=str(row["title"]),
                        body=str(row["body"]),
                        metadata=json.loads(str(row["metadata_json"] or "{}")),
                        note_id=str(row["id"]),
                    )

            if include_audit:
                for row in self.conn.execute(
                    "SELECT event_type, session_id, json FROM audit_events ORDER BY id ASC"
                ).fetchall():
                    dst.add_audit_event(
                        str(row["event_type"]),
                        json.loads(str(row["json"] or "{}")),
                        session_id=str(row["session_id"] or "") or None,
                    )

            # Semantic indexes/items/hits/cards are exported. Vectors are optional.
            index_id_map: dict[str, str] = {}
            for row in self.conn.execute(
                "SELECT * FROM semantic_indexes ORDER BY created_at ASC"
            ).fetchall():
                src_id = str(row["id"])
                index_id_map[src_id] = dst.add_semantic_index(
                    kind=str(row["kind"]),
                    backend=str(row["backend"]),
                    dim=int(row["dim"]),
                    model_id=str(row["model_id"] or ""),
                    model_fingerprint=json.loads(str(row["model_fingerprint_json"] or "{}")),
                    anchor_set_hash=str(row["anchor_set_hash"] or ""),
                    source_fingerprint=str(row["source_fingerprint"] or ""),
                    metadata=json.loads(str(row["metadata_json"] or "{}")),
                    index_id=src_id,
                )

            item_id_map: dict[str, str] = {}
            vector_cache: set[str] = set()
            for row in self.conn.execute(
                "SELECT * FROM semantic_items ORDER BY created_at ASC"
            ).fetchall():
                src_vec = str(row["vector_sha256"] or "")
                vec_sha = ""
                if include_vectors and src_vec:
                    vrow = self.conn.execute(
                        "SELECT data, dim, dtype FROM semantic_vectors WHERE vector_sha256=?",
                        (src_vec,),
                    ).fetchone()
                    if vrow:
                        if src_vec not in vector_cache:
                            dst.store_semantic_vector(bytes(vrow["data"]), dim=int(vrow["dim"]), dtype=str(vrow["dtype"]))
                            vector_cache.add(src_vec)
                        vec_sha = src_vec
                src_item_id = str(row["id"])
                item_id_map[src_item_id] = dst.upsert_semantic_item(
                    index_id=index_id_map.get(str(row["index_id"]), str(row["index_id"])),
                    kind=str(row["kind"]),
                    stable_ref=str(row["stable_ref"]),
                    title=str(row["title"] or ""),
                    text_hash=str(row["text_hash"]),
                    vector_sha256=vec_sha,
                    metadata=json.loads(str(row["metadata_json"] or "{}")),
                    item_id=src_item_id,
                )

            for row in self.conn.execute(
                "SELECT * FROM behavior_hits ORDER BY created_at ASC"
            ).fetchall():
                src_item = str(row["item_id"])
                mapped_item = item_id_map.get(src_item, src_item)
                dst.add_behavior_hit(
                    item_id=mapped_item,
                    behavior=str(row["behavior"]),
                    confidence=float(row["confidence"]),
                    anchor_set_hash=str(row["anchor_set_hash"] or ""),
                    explain=json.loads(str(row["explain_json"] or "[]")),
                    hit_id=str(row["id"]),
                )

            for row in self.conn.execute(
                "SELECT * FROM evidence_cards ORDER BY created_at ASC"
            ).fetchall():
                dst.add_evidence_card(
                    claim=str(row["claim"]),
                    claim_type=str(row["claim_type"]),
                    confidence=float(row["confidence"]),
                    evidence=json.loads(str(row["evidence_json"] or "[]")),
                    source_refs=json.loads(str(row["source_refs_json"] or "[]")),
                    metadata=json.loads(str(row["metadata_json"] or "{}")),
                    card_id=str(row["id"]),
                )

            if include_experience:
                for row in self.conn.execute(
                    "SELECT intent_key, experience_key, intent_z, experience_meta, q_value, visit_count, last_updated FROM memrl_triplets ORDER BY id ASC"
                ).fetchall():
                    dst.conn.execute(
                        """
                        INSERT INTO memrl_triplets (intent_key, experience_key, intent_z, experience_meta, q_value, visit_count, last_updated)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            row["intent_key"],
                            row["experience_key"],
                            row["intent_z"],
                            row["experience_meta"],
                            row["q_value"],
                            row["visit_count"],
                            row["last_updated"],
                        ),
                    )
                for row in self.conn.execute(
                    "SELECT suggestion_id, intent_key, experience_key, source_tool, source_action, context_addr, experience_meta, q_value, initial_q, reward, feedback_type, feedback_timestamp, created_at, last_updated FROM memrl_suggestions ORDER BY created_at ASC"
                ).fetchall():
                    dst.conn.execute(
                        """
                        INSERT INTO memrl_suggestions (suggestion_id, intent_key, experience_key, source_tool, source_action, context_addr, experience_meta, q_value, initial_q, reward, feedback_type, feedback_timestamp, created_at, last_updated)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            row["suggestion_id"],
                            row["intent_key"],
                            row["experience_key"],
                            row["source_tool"],
                            row["source_action"],
                            row["context_addr"],
                            row["experience_meta"],
                            row["q_value"],
                            row["initial_q"],
                            row["reward"],
                            row["feedback_type"],
                            row["feedback_timestamp"],
                            row["created_at"],
                            row["last_updated"],
                        ),
                    )
                dst.conn.commit()

            verify = dst.verify()
            summary = dst.inspect_summary()

        return {
            "ok": True,
            "out_path": str(out),
            "source_capsule": str(self.path),
            "include_vectors": bool(include_vectors),
            "include_notes": bool(include_notes),
            "include_audit": bool(include_audit),
            "include_experience": bool(include_experience),
            "verification": verify,
            "summary": summary,
        }


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
            "semantic_indexes": get_count("semantic_indexes"),
            "semantic_items": get_count("semantic_items"),
            "semantic_vectors": get_count("semantic_vectors"),
            "behavior_hits": get_count("behavior_hits"),
            "evidence_cards": get_count("evidence_cards"),
            "memrl_triplets": get_count("memrl_triplets"),
            "memrl_suggestions": get_count("memrl_suggestions"),
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

        vec_rows = self.conn.execute("SELECT vector_sha256, data FROM semantic_vectors").fetchall()
        for row in vec_rows:
            digest = hashlib.sha256(bytes(row["data"])).hexdigest()
            if digest != row["vector_sha256"]:
                raise CapsuleVerificationError(f"semantic vector hash mismatch for {row['vector_sha256']}")

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
                "semantic_vector_hashes": True,
            },
        }

    def record_experience_triplet(
        self,
        intent_key: str,
        experience_key: str,
        intent_z: bytes | None = None,
        experience_meta: dict | None = None,
        initial_q: float = 0.5,
    ) -> None:
        self._assert_initialized()
        now_epoch = time.time()
        self.conn.execute(
            """
            INSERT INTO memrl_triplets
            (intent_key, experience_key, intent_z, experience_meta, q_value, visit_count, last_updated)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(intent_key, experience_key) DO UPDATE SET
                visit_count = visit_count + 1,
                last_updated = excluded.last_updated
            """,
            (
                intent_key,
                experience_key,
                intent_z,
                self._json_dumps(experience_meta) if experience_meta else None,
                initial_q,
                now_epoch,
            ),
        )
        self.conn.commit()

    def update_experience_q(
        self,
        intent_key: str,
        experience_key: str,
        reward: float,
        alpha: float = 0.15,
    ) -> float:
        self._assert_initialized()
        reward = max(-1.0, min(1.0, reward))
        cur = self.conn.cursor()
        cur.execute(
            "SELECT q_value FROM memrl_triplets WHERE intent_key = ? AND experience_key = ?",
            (intent_key, experience_key),
        )
        row = cur.fetchone()
        if row is None:
            new_q = reward
            self.record_experience_triplet(intent_key, experience_key, initial_q=new_q)
            return new_q
        old_q = float(row[0])
        new_q = max(-1.0, min(1.0, old_q + alpha * (reward - old_q)))
        now_epoch = time.time()
        cur.execute(
            """
            UPDATE memrl_triplets
            SET q_value = ?, last_updated = ?, visit_count = visit_count + 1
            WHERE intent_key = ? AND experience_key = ?
            """,
            (new_q, now_epoch, intent_key, experience_key),
        )
        self.conn.commit()
        return new_q

    def batch_update_experience_q(
        self,
        intent_key: str,
        experience_keys: list[str],
        rewards: list[float],
        alpha: float = 0.15,
    ) -> dict[str, float]:
        return {
            ek: self.update_experience_q(intent_key, ek, reward=r, alpha=alpha)
            for ek, r in zip(experience_keys, rewards)
        }

    def two_phase_retrieve_experiences(
        self,
        intent_key: str,
        candidate_pool: list[dict[str, Any]],
        top_k: int = 10,
        lambda_explore: float = 0.3,
        similarity_key: str = "score",
    ) -> list[dict[str, Any]]:
        self._assert_initialized()
        if not candidate_pool:
            return []
        cur = self.conn.cursor()
        sims = [float(c.get(similarity_key, 0.0) or 0.0) for c in candidate_pool]
        n = len(sims)
        sim_mean = sum(sims) / n if n else 0.0
        sim_std = math.sqrt(sum((s - sim_mean) ** 2 for s in sims) / n) if n > 1 else 1.0
        if sim_std < 1e-9:
            sim_std = 1.0
        q_vals: list[float] = []
        for c in candidate_pool:
            exp_key = c.get("ea", c.get("name", str(id(c))))
            cur.execute(
                "SELECT q_value FROM memrl_triplets WHERE intent_key = ? AND experience_key = ?",
                (intent_key, exp_key),
            )
            row = cur.fetchone()
            q_vals.append(float(row[0]) if row else 0.5)
        q_mean = sum(q_vals) / n if n else 0.0
        q_std = math.sqrt(sum((q - q_mean) ** 2 for q in q_vals) / n) if n > 1 else 1.0
        if q_std < 1e-9:
            q_std = 1.0
        scored: list[tuple[dict[str, Any], float, float]] = []
        for c, sim, q in zip(candidate_pool, sims, q_vals):
            norm_sim = (sim - sim_mean) / sim_std
            norm_q = (q - q_mean) / q_std
            final_score = (1.0 - lambda_explore) * norm_sim + lambda_explore * norm_q
            scored.append((c, final_score, q))
        scored.sort(key=lambda x: x[1], reverse=True)
        out: list[dict[str, Any]] = []
        for c, final_score, q in scored[:top_k]:
            merged = dict(c)
            merged["memrl_score"] = round(final_score, 4)
            merged["q_value"] = round(q, 4)
            out.append(merged)
        return out

    def get_experience_q(self, intent_key: str, experience_key: str) -> float:
        self._assert_initialized()
        row = self.conn.execute(
            "SELECT q_value FROM memrl_triplets WHERE intent_key = ? AND experience_key = ?",
            (intent_key, experience_key),
        ).fetchone()
        return float(row[0]) if row else 0.5

    def add_experience_suggestion(
        self,
        intent_key: str,
        experience_key: str,
        source_tool: str = "",
        source_action: str = "",
        context_addr: str = "",
        experience_meta: dict | None = None,
        initial_q: float = 0.5,
    ) -> str:
        self._assert_initialized()
        suggestion_id = uuid.uuid4().hex[:12]
        now_epoch = time.time()
        self.record_experience_triplet(
            intent_key=intent_key,
            experience_key=experience_key,
            experience_meta=experience_meta,
            initial_q=initial_q,
        )
        self.conn.execute(
            """
            INSERT INTO memrl_suggestions
            (suggestion_id, intent_key, experience_key, source_tool, source_action,
             context_addr, experience_meta, q_value, initial_q, created_at, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                suggestion_id,
                intent_key,
                experience_key,
                source_tool,
                source_action,
                context_addr,
                self._json_dumps(experience_meta) if experience_meta else None,
                initial_q,
                initial_q,
                now_epoch,
                now_epoch,
            ),
        )
        self.conn.commit()
        return suggestion_id

    def auto_reward_suggestions_for_addr(
        self,
        addr: str,
        reward: float = 0.7,
        alpha: float = 0.15,
        max_age_seconds: float = 1800.0,
    ) -> int:
        self._assert_initialized()
        cutoff = time.time() - max_age_seconds
        updated = 0
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT suggestion_id, intent_key, experience_key, q_value
            FROM memrl_suggestions
            WHERE context_addr = ?
              AND (feedback_type IS NULL OR feedback_type = 'neutral')
              AND created_at >= ?
            ORDER BY created_at DESC
            LIMIT 5
            """,
            (addr, cutoff),
        )
        rows = cur.fetchall()
        now_epoch = time.time()
        for suggestion_id, intent_key, experience_key, old_q in rows:
            old_q = float(old_q or 0.5)
            new_q = max(-1.0, min(1.0, old_q + alpha * (reward - old_q)))
            cur.execute(
                """
                UPDATE memrl_suggestions
                SET q_value = ?, reward = ?, feedback_type = 'auto_accept',
                    feedback_timestamp = ?, last_updated = ?
                WHERE suggestion_id = ?
                """,
                (new_q, reward, now_epoch, now_epoch, suggestion_id),
            )
            self.update_experience_q(intent_key, experience_key, reward, alpha)
            updated += 1
        self.conn.commit()
        return updated

    @staticmethod
    def _classify_experience_reward(reward: float) -> str:
        if reward >= 0.8:
            return "accept"
        if reward >= 0.3:
            return "partial"
        if reward >= -0.2:
            return "neutral"
        if reward >= -0.8:
            return "reject"
        return "dangerous"

    def process_suggestion_feedback(
        self,
        suggestion_id: str,
        reward: float,
        alpha: float = 0.15,
    ) -> dict[str, Any]:
        self._assert_initialized()
        reward = max(-1.0, min(1.0, reward))
        cur = self.conn.cursor()
        cur.execute(
            "SELECT intent_key, experience_key, q_value FROM memrl_suggestions WHERE suggestion_id = ?",
            (suggestion_id,),
        )
        row = cur.fetchone()
        if row is None:
            return {"ok": False, "error": f"Suggestion not found: {suggestion_id}"}
        intent_key, experience_key, old_q = str(row[0]), str(row[1]), float(row[2])
        td_error = reward - old_q
        new_q = max(-1.0, min(1.0, old_q + alpha * td_error))
        now_epoch = time.time()
        fb_type = self._classify_experience_reward(reward)
        cur.execute(
            """
            UPDATE memrl_suggestions
            SET q_value = ?, reward = ?, feedback_type = ?,
                feedback_timestamp = ?, last_updated = ?
            WHERE suggestion_id = ?
            """,
            (new_q, reward, fb_type, now_epoch, now_epoch, suggestion_id),
        )
        self.conn.commit()
        self.update_experience_q(intent_key, experience_key, reward, alpha)
        return {
            "ok": True,
            "suggestion_id": suggestion_id,
            "old_q": round(old_q, 4),
            "new_q": round(new_q, 4),
            "reward": reward,
            "td_error": round(td_error, 4),
            "alpha": alpha,
            "feedback_type": fb_type,
        }

    def suggest_best_experiences(
        self,
        candidate_pool: list[dict[str, Any]],
        intent_key: str = "",
        top_k: int = 10,
        lambda_explore: float = 0.3,
        similarity_key: str = "score",
        epsilon: float = 0.0,
    ) -> list[dict[str, Any]]:
        self._assert_initialized()
        if not candidate_pool:
            return []
        if epsilon > 0:
            bucket = int(hashlib.md5((str(time.time()) + intent_key).encode()).hexdigest(), 16) % 1000
            if bucket < int(epsilon * 1000):
                selected = candidate_pool[: min(top_k, len(candidate_pool))]
                for s in selected:
                    s["memrl_score"] = 0.0
                    s["q_value"] = self.get_experience_q(intent_key, s.get("ea", s.get("name", str(id(s)))))
                return selected
        return self.two_phase_retrieve_experiences(
            intent_key=intent_key,
            candidate_pool=candidate_pool,
            top_k=top_k,
            lambda_explore=lambda_explore,
            similarity_key=similarity_key,
        )

    def get_experience_suggestion(self, suggestion_id: str) -> dict[str, Any] | None:
        self._assert_initialized()
        row = self.conn.execute(
            """
            SELECT suggestion_id, intent_key, experience_key,
                   source_tool, source_action, context_addr,
                   experience_meta, q_value, initial_q,
                   reward, feedback_type, feedback_timestamp,
                   created_at, last_updated
            FROM memrl_suggestions WHERE suggestion_id = ?
            """,
            (suggestion_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "suggestion_id": row[0],
            "intent_key": row[1],
            "experience_key": row[2],
            "source_tool": row[3],
            "source_action": row[4],
            "context_addr": row[5],
            "experience_meta": json.loads(row[6]) if row[6] else None,
            "q_value": round(float(row[7]), 4),
            "initial_q": round(float(row[8]), 4),
            "reward": row[9],
            "feedback_type": row[10],
            "feedback_timestamp": row[11],
            "created_at": row[12],
            "last_updated": row[13],
        }

    def list_experience_suggestions(self, intent_key: str = "", limit: int = 50, offset: int = 0) -> dict[str, Any]:
        self._assert_initialized()
        cur = self.conn.cursor()
        if intent_key:
            cur.execute(
                """
                SELECT suggestion_id, intent_key, experience_key,
                       source_tool, source_action, context_addr,
                       q_value, feedback_type, created_at
                FROM memrl_suggestions WHERE intent_key = ?
                ORDER BY created_at DESC LIMIT ? OFFSET ?
                """,
                (intent_key, limit, offset),
            )
            rows = cur.fetchall()
            total = self.conn.execute(
                "SELECT COUNT(*) FROM memrl_suggestions WHERE intent_key = ?",
                (intent_key,),
            ).fetchone()[0] or 0
        else:
            cur.execute(
                """
                SELECT suggestion_id, intent_key, experience_key,
                       source_tool, source_action, context_addr,
                       q_value, feedback_type, created_at
                FROM memrl_suggestions ORDER BY created_at DESC LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
            rows = cur.fetchall()
            total = self.conn.execute("SELECT COUNT(*) FROM memrl_suggestions").fetchone()[0] or 0
        suggestions = [
            {
                "suggestion_id": r[0],
                "intent_key": r[1],
                "experience_key": r[2],
                "source_tool": r[3],
                "source_action": r[4],
                "context_addr": r[5],
                "q_value": round(float(r[6]), 4),
                "feedback_type": r[7],
                "created_at": r[8],
            }
            for r in rows
        ]
        return {"ok": True, "suggestions": suggestions, "total": int(total), "count": len(suggestions)}

    def get_experience_stats(self) -> dict[str, Any]:
        self._assert_initialized()
        cur = self.conn.cursor()
        total, avg_q, max_q, min_q = cur.execute(
            "SELECT COUNT(*), AVG(q_value), MAX(q_value), MIN(q_value) FROM memrl_triplets"
        ).fetchone()
        total_visits = cur.execute("SELECT SUM(visit_count) FROM memrl_triplets").fetchone()[0] or 0
        unique_intents = cur.execute("SELECT COUNT(DISTINCT intent_key) FROM memrl_triplets").fetchone()[0] or 0
        total_suggestions = cur.execute("SELECT COUNT(*) FROM memrl_suggestions").fetchone()[0] or 0
        feedback_count = cur.execute(
            "SELECT COUNT(*) FROM memrl_suggestions WHERE feedback_type IS NOT NULL"
        ).fetchone()[0] or 0
        feedback_dist = {
            r[0]: r[1]
            for r in cur.execute(
                "SELECT feedback_type, COUNT(*) FROM memrl_suggestions WHERE feedback_type IS NOT NULL GROUP BY feedback_type"
            ).fetchall()
        }
        top_q = [
            {
                "intent_key": r[0],
                "experience_key": r[1],
                "q_value": round(float(r[2]), 4),
                "visit_count": r[3],
            }
            for r in cur.execute(
                "SELECT intent_key, experience_key, q_value, visit_count FROM memrl_triplets ORDER BY q_value DESC LIMIT 5"
            ).fetchall()
        ]
        bottom_q = [
            {
                "intent_key": r[0],
                "experience_key": r[1],
                "q_value": round(float(r[2]), 4),
                "visit_count": r[3],
            }
            for r in cur.execute(
                "SELECT intent_key, experience_key, q_value, visit_count FROM memrl_triplets ORDER BY q_value ASC LIMIT 5"
            ).fetchall()
        ]
        recent_qs = [r[0] for r in cur.execute(
            "SELECT q_value FROM memrl_triplets ORDER BY last_updated DESC LIMIT 100"
        ).fetchall()]
        recent_n = len(recent_qs)
        recent_avg = sum(recent_qs) / recent_n if recent_n else 0.0
        recent_std = math.sqrt(sum((q - recent_avg) ** 2 for q in recent_qs) / recent_n) if recent_n > 1 else 0.0
        histogram = {"[-1.0, -0.5)": 0, "[-0.5, 0.0)": 0, "[0.0, 0.5)": 0, "[0.5, 1.0]": 0}
        for (qv,) in cur.execute("SELECT q_value FROM memrl_triplets").fetchall():
            if qv < -0.5:
                histogram["[-1.0, -0.5)"] += 1
            elif qv < 0.0:
                histogram["[-0.5, 0.0)"] += 1
            elif qv < 0.5:
                histogram["[0.0, 0.5)"] += 1
            else:
                histogram["[0.5, 1.0]"] += 1
        return {
            "ok": True,
            "total_triplets": int(total or 0),
            "unique_intents": int(unique_intents),
            "avg_q_value": round(float(avg_q), 4) if avg_q is not None else 0.0,
            "max_q_value": round(float(max_q), 4) if max_q is not None else 0.0,
            "min_q_value": round(float(min_q), 4) if min_q is not None else 0.0,
            "total_visits": int(total_visits),
            "total_suggestions": int(total_suggestions),
            "feedback_count": int(feedback_count),
            "feedback_rate": round(feedback_count / total_suggestions, 4) if total_suggestions else 0.0,
            "feedback_distribution": feedback_dist,
            "recent_q_avg": round(recent_avg, 4),
            "recent_q_std": round(recent_std, 4),
            "q_value_histogram": histogram,
            "top_q_memories": top_q,
            "bottom_q_memories": bottom_q,
        }

    def top_experience_memories(self, intent_key: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        self._assert_initialized()
        cur = self.conn.cursor()
        if intent_key:
            rows = cur.execute(
                """
                SELECT intent_key, experience_key, q_value, visit_count, experience_meta
                FROM memrl_triplets WHERE intent_key = ? ORDER BY q_value DESC LIMIT ?
                """,
                (intent_key, limit),
            ).fetchall()
        else:
            rows = cur.execute(
                """
                SELECT intent_key, experience_key, q_value, visit_count, experience_meta
                FROM memrl_triplets ORDER BY q_value DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "intent_key": r[0],
                "experience_key": r[1],
                "q_value": round(float(r[2]), 4),
                "visit_count": r[3],
                "meta": json.loads(r[4]) if r[4] else None,
            }
            for r in rows
        ]

    def prune_low_q_experiences(self, threshold: float = -0.5) -> int:
        self._assert_initialized()
        cur = self.conn.execute("DELETE FROM memrl_triplets WHERE q_value < ?", (threshold,))
        pruned = cur.rowcount
        self.conn.commit()
        return int(pruned)

    def clear_experience_memories(self) -> None:
        self._assert_initialized()
        self.conn.execute("DELETE FROM memrl_triplets")
        self.conn.execute("DELETE FROM memrl_suggestions")
        self.conn.commit()

    def run_vulnerability_reasoner(self) -> list[dict[str, Any]]:
        self._assert_initialized()
        from ida_pro_mcp.host.intelligence.reasoner import VulnerabilityReasoner
        reasoner = VulnerabilityReasoner()
        return reasoner.reason_on_capsule(self)


