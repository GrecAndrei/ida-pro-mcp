from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest

from ida_pro_mcp.host.stores.blackboard_store import (
    SCHEMA_VERSION,
    BlackboardStore,
)


def test_migration_from_v0_legacy_blackboard(tmp_path: Path) -> None:
    db_file = tmp_path / "legacy_v0.db"
    conn = sqlite3.connect(db_file)
    conn.execute(
        """
        CREATE TABLE blackboard (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            addr TEXT NOT NULL,
            title TEXT,
            content TEXT,
            confidence REAL DEFAULT 1.0,
            status TEXT DEFAULT 'confirmed',
            verdict TEXT,
            tags TEXT DEFAULT '[]',
            evidence TEXT DEFAULT '[]',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    now = time.time()
    conn.execute(
        """
        INSERT INTO blackboard (id, kind, addr, title, content, confidence, status, tags, evidence, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "f-001",
            "finding",
            "0x401000",
            "Buffer Overflow",
            "Unchecked strcpy in parse_header",
            0.9,
            "confirmed",
            json.dumps(["cve", "memory-safety"]),
            json.dumps([{"source": "ida", "address": "0x401000"}]),
            now,
            now,
        ),
    )
    conn.commit()
    conn.close()

    # Opening through BlackboardStore triggers migration
    store = BlackboardStore(str(db_file))
    finding = store.read("f-001")
    assert finding is not None
    assert finding["title"] == "Buffer Overflow"
    assert "cve" in finding["tags"]
    assert finding["addr"] == "0x401000"

    # Verify user_version is current
    conn2 = sqlite3.connect(db_file)
    cur_ver = conn2.execute("PRAGMA user_version").fetchone()[0]
    assert cur_ver == SCHEMA_VERSION

    # Verify blackboard compatibility view and INSTEAD OF UPDATE trigger
    conn2.execute("UPDATE blackboard SET title='Updated Title' WHERE id='f-001'")
    conn2.commit()
    conn2.close()

    finding_updated = store.read("f-001")
    assert finding_updated["title"] == "Updated Title"


def test_migration_from_v2_embedding_metadata(tmp_path: Path) -> None:
    db_file = tmp_path / "legacy_v2.db"
    store = BlackboardStore(str(db_file))
    # Write a finding
    store.write(
        title="AES S-Box",
        content="Lookup table for Rijndael",
        addr="0x402000",
        kind="finding",
        status="confirmed",
    )
    conn = sqlite3.connect(db_file)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(findings_embeddings)")}
    assert "embedding_dim" in cols
    assert "text_hash" in cols
    conn.close()


def test_transaction_rollback_safety(tmp_path: Path) -> None:
    db_file = tmp_path / "rollback_test.db"
    store = BlackboardStore(str(db_file))
    store.write(
        title="Initial API",
        addr="0x403000",
        kind="finding",
        status="open",
    )

    class CustomAbort(Exception):
        pass

    with pytest.raises(CustomAbort), store._tx() as conn:
        conn.execute("UPDATE findings SET title='Aborted Title' WHERE addr='0x403000'")
        raise CustomAbort("Roll back transaction")

    res = store.list(addr="0x403000")
    assert len(res) == 1
    assert res[0]["title"] == "Initial API"


def test_target_selection_strategies_and_parsing(tmp_path: Path) -> None:
    db_file = tmp_path / "targets_test.db"
    store = BlackboardStore(str(db_file))
    store.write(
        title="Main Entry",
        addr="0x401000",
        kind="finding",
        status="confirmed",
    )
    store.write(
        title="Unresolved Function",
        addr="0x401500",
        kind="finding",
        status="open",
    )

    unresolved_targets = store.targets(strategy="unresolved", limit=5)
    assert isinstance(unresolved_targets, dict)
    assert "targets" in unresolved_targets

    stale_targets = store.targets(strategy="stale", limit=5)
    assert isinstance(stale_targets, dict)
    assert "targets" in stale_targets

    with pytest.raises(ValueError, match="strategy must be one of"):
        store.targets(strategy="invalid_strategy")


def test_validation_guards(tmp_path: Path) -> None:
    db_file = tmp_path / "validation_test.db"
    store = BlackboardStore(str(db_file))

    with pytest.raises(ValueError, match="status must be proposed"):
        store.write(title="T", addr="0x1", status="invalid_status")

    with pytest.raises(ValueError, match="verdict must be interesting"):
        store.write(title="T", addr="0x1", verdict="invalid_verdict")


def test_pruning_and_confidence_decay(tmp_path: Path) -> None:
    db_file = tmp_path / "prune_test.db"
    store = BlackboardStore(str(db_file))
    e1 = store.write(title="Old Noise", addr="0x10", status="rejected", confidence=0.8)
    e2 = store.write(title="Fresh Noise", addr="0x20", status="rejected", confidence=0.8)

    thirty_days_ago = time.time() - (30 * 86400)
    with store._tx() as conn:
        conn.execute("UPDATE findings SET updated_at=? WHERE id=?", (thirty_days_ago, e1))

    prune_res = store.prune(older_than_days=15)
    assert isinstance(prune_res, dict)
    assert store.read(e1) is None
    assert store.read(e2) is not None

    decayed = store.decay_stale_confidence(half_life_days=10)
    assert isinstance(decayed, int)
