from __future__ import annotations

import sqlite3


def initialize_schema(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.DatabaseError:
        pass

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS manifest (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS objects (
            sha256 TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            size INTEGER NOT NULL,
            media_type TEXT,
            created_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS blobs (
            sha256 TEXT PRIMARY KEY REFERENCES objects(sha256) ON DELETE CASCADE,
            data BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS install_reports (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL,
            json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS client_profiles (
            name TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            config_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS backend_profiles (
            name TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            config_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            state_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            session_id TEXT,
            json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS notes (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS embedding_states (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            backend TEXT NOT NULL,
            model_path TEXT,
            model_hash TEXT,
            embedding_dim INTEGER NOT NULL,
            index_metadata_json TEXT NOT NULL DEFAULT '{}',
            anchor_metadata_json TEXT NOT NULL DEFAULT '{}',
            last_indexed_functions_json TEXT NOT NULL DEFAULT '[]',
            thresholds_json TEXT NOT NULL DEFAULT '{}',
            json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS semantic_indexes (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            backend TEXT NOT NULL,
            dim INTEGER NOT NULL,
            model_id TEXT,
            model_fingerprint_json TEXT NOT NULL DEFAULT '{}',
            anchor_set_hash TEXT,
            source_fingerprint TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS semantic_items (
            id TEXT PRIMARY KEY,
            index_id TEXT NOT NULL REFERENCES semantic_indexes(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            stable_ref TEXT NOT NULL,
            title TEXT,
            text_hash TEXT NOT NULL,
            vector_sha256 TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(index_id, kind, stable_ref)
        );

        CREATE TABLE IF NOT EXISTS semantic_vectors (
            vector_sha256 TEXT PRIMARY KEY,
            dim INTEGER NOT NULL,
            dtype TEXT NOT NULL,
            data BLOB NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS behavior_hits (
            id TEXT PRIMARY KEY,
            item_id TEXT NOT NULL,
            behavior TEXT NOT NULL,
            confidence REAL NOT NULL,
            anchor_set_hash TEXT,
            explain_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS evidence_cards (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            claim TEXT NOT NULL,
            claim_type TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 0.0,
            evidence_json TEXT NOT NULL DEFAULT '[]',
            source_refs_json TEXT NOT NULL DEFAULT '[]',
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );

        """
    )

