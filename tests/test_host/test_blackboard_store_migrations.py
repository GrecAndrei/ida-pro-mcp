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


def test_resolve_db_path_and_embedder_fallbacks(tmp_path: Path) -> None:
    import sys
    from unittest.mock import MagicMock, patch

    from ida_pro_mcp.host.stores.blackboard_store import (
        _create_blackboard_compat_view,
        _get_embedder,
        _resolve_db_path,
    )

    # 1. _resolve_db_path idc exception (hits lines 156-157)
    mock_idc = MagicMock()
    mock_idc.get_idb_path.side_effect = RuntimeError("idc failure")
    with patch.dict(sys.modules, {"idc": mock_idc}):
        p = _resolve_db_path(None)
        assert "blackboard.db" in p

    # 2. _get_embedder (hits line 180)
    emb = _get_embedder()
    assert emb is not None

    # 3. _create_blackboard_compat_view with empty table_info (hits line 468)
    conn = sqlite3.connect(":memory:")
    _create_blackboard_compat_view(conn)
    conn.close()

    # 4. _init_db failure + CACHE_DIR ImportError fallback (hits lines 568-572)
    with patch.object(BlackboardStore, "_init_db", side_effect=[sqlite3.OperationalError("locked"), None]), patch.dict(sys.modules, {"ida_pro_mcp.host.config": None}):
        bs = BlackboardStore(str(tmp_path / "init_err.db"))
        assert "fallback_indexes" in bs.db_path


def test_blackboard_store_hydration_and_embedding_edges(tmp_path: Path) -> None:
    from unittest.mock import MagicMock

    store = BlackboardStore(str(tmp_path / "embed_hydrate.db"))

    # 1. _embed_text when embedder returns None (hits line 713)
    mock_emb = MagicMock()
    mock_emb.embed_query.return_value = None
    mock_emb.embed_vector.return_value = None
    store._embedder = mock_emb
    assert store._embed_text("some text") is None

    # 2. _row_to_dict with None (hits line 754)
    assert store._row_to_dict(None) == {}

    # 3. _hydrate with own=True (conn=None) and non-empty rows (hits line 782)
    eid = store.write(title="Hydrate Test", addr="0x1000", content="c")
    rows = store._conn().execute("SELECT * FROM findings WHERE id=?", (eid,)).fetchall()
    hydrated = store._hydrate(rows, conn=None)
    assert len(hydrated) == 1
    assert hydrated[0]["id"] == eid


def test_blackboard_write_upsert_and_validation_guards(tmp_path: Path) -> None:
    from unittest.mock import patch

    store = BlackboardStore(str(tmp_path / "guards.db"))

    # 1. write invalid kind (hits line 962)
    with pytest.raises(ValueError, match="kind must be one of"):
        store.write(title="Bad Kind", addr="0x1", kind="invalid_kind")

    # 2. upsert_finding invalid status (hits line 1042)
    with pytest.raises(ValueError, match="status must be proposed"):
        store.upsert_finding(title="Bad Status", addr="0x1", status="invalid_status")

    # 3. upsert_finding sqlite3.IntegrityError retry branch (hits lines 1078-1081)
    orig_write = store.write
    attempts = [0]

    def flake_write(*args, **kwargs):
        attempts[0] += 1
        if attempts[0] == 1:
            raise sqlite3.IntegrityError("simulated duplicate entry_id collision")
        return orig_write(*args, **kwargs)

    with patch.object(store, "write", side_effect=flake_write):
        res = store.upsert_finding(title="Retry Collision", addr="0x2000", category="vuln")
        assert res.get("entry_id") is not None

    # 4. record_examination invalid addr / verdict (hits lines 1261, 1264)
    with pytest.raises(ValueError, match="address is required"):
        store.record_examination(addr="", verdict="boring")
    with pytest.raises(ValueError, match="verdict must be interesting"):
        store.record_examination(addr="0x3000", verdict="invalid_verdict")

    # 5. examination empty addr (hits line 1313)
    assert store.examination("") is None

    # 6. comment_for truncation (hits line 1386)
    c_long = store.comment_for({"title": "A" * 100, "content": "B" * 500, "id": "12345678"}, max_len=50)
    assert c_long.endswith("… [mcp:12345678]")

    # 7. adopt_annotation empty addr (hits line 1404)
    assert store.adopt_annotation(addr="", name="test") is None

    # 8. list ioc_type filter (hits lines 1575-1576)
    store.write(title="IOC", addr="0x4000", ioc_type="ipv4", ioc_value="1.2.3.4")
    ioc_hits = store.list(ioc_type="ipv4")
    assert len(ioc_hits) >= 1


def test_blackboard_link_conflict_and_semantic_search_edges(tmp_path: Path) -> None:
    from unittest.mock import MagicMock

    from ida_pro_mcp.host.intelligence.helpers import pack_floats
    from ida_pro_mcp.host.stores.blackboard_store import _Rollback

    store = BlackboardStore(str(tmp_path / "conflict_search.db"))

    vec_dim = 128
    dummy_vec = pack_floats([0.1] * vec_dim)
    mock_emb = MagicMock()
    mock_emb.backend = "test_backend"
    mock_emb.model_name = "test_model"
    mock_emb.embedding_format.return_value = "f32"
    mock_emb._model_path = "model"
    mock_emb.embed_query_vector.return_value = [0.1] * vec_dim
    mock_emb.embed_vector.return_value = [0.1] * vec_dim
    store._embedder = mock_emb
    store._get_embedder = lambda: mock_emb

    # 1. link_conflict invalid args (hits lines 1208, 1214)
    assert not store.link_conflict("same", "same")
    e1 = store.write(title="F1", addr="0x1000", content="c1", status="open", embed=False)
    assert not store.link_conflict(e1, "nonexistent")

    e2 = store.write(title="F2", addr="0x2000", content="c2", status="open", embed=False)
    assert store.link_conflict(e1, e2, reason="disputed logic")

    # 2. semantic_search edges
    # Create resolved and rejected findings to hit lines 1710, 1712
    e_res = store.write(title="Resolved Title", addr="0x3000", status="resolved", embed=False)
    e_rej = store.write(title="Rejected Title", addr="0x4000", status="rejected", embed=False)
    e_corrupt = store.write(title="Corrupt Vector Title", addr="0x5000", status="open", embed=False)
    e_empty = store.write(title="Empty Vector Title", addr="0x6000", status="open", embed=False)

    store._store_embedding(e_res, dummy_vec, "res")
    store._store_embedding(e_rej, dummy_vec, "rej")
    store._store_embedding(e_empty, b"", "empty")
    # corrupt blob (hits lines 1718-1719)
    expected_model = store._embedding_identity(mock_emb, vec_dim)
    with store._tx() as conn:
        conn.execute(
            "INSERT INTO findings_embeddings (entry_id, vector, model, embedding_dim, text_hash, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 'hash', 1, 1)",
            (e_corrupt, sqlite3.Binary(b"not_floats"), expected_model, vec_dim),
        )
    store._store_embedding(e1, dummy_vec, "text1")
    store._store_embedding(e2, dummy_vec, "text2")

    # Run semantic_search with include_resolved=False, include_contradicted=False (hits 1710, 1712, 1715, 1718-1719, 1777-1779)
    res = store.semantic_search(query="F1", top_k=10, include_resolved=False, include_contradicted=False, threshold=0.0)
    assert len(res) >= 1
    # Check that conflicts_with was populated (hits line 1777-1779)
    assert any(item.get("conflicts_with") for item in res)

    # Hybrid fallback branch: lexical item not in semantic_by_id (hits lines 1753-1756)
    e_lexical = store.write(title="HybridUniqueTerm Special", addr="0x7000", status="open", embed=False)
    res_hybrid = store.semantic_search(query="HybridUniqueTerm", top_k=10, threshold=0.99)
    assert any(item["id"] == e_lexical for item in res_hybrid)


def test_blackboard_update_lifecycle_and_confidence(tmp_path: Path) -> None:
    store = BlackboardStore(str(tmp_path / "lifecycle.db"))
    eid = store.write(title="Orig", addr="0x1000", content="orig content", confidence=0.4, priority=0.3)

    # 1. update resolved=True (hits lines 1806-1808)
    assert store.update(eid, resolved=True)
    assert store.read(eid)["status"] == "resolved"

    # 2. update with no allowed keys (hits line 1815)
    assert not store.update(eid, invalid_column_name="foo")

    # 3. update nonexistent id (hits line 1820)
    from ida_pro_mcp.host.stores.blackboard_store import _Rollback
    with pytest.raises(_Rollback):
        store.update("nonexistent", title="foo")

    # 4. update with invalid evidence item (hits line 1832)
    assert store.update(eid, evidence=["not a dict", {"source": "ida"}])
    assert len(store.read(eid)["evidence"]) == 1

    # 5. update addr (hits line 1839)
    assert store.update(eid, addr="0x2000")
    assert store.read(eid)["addr"] == "0x2000"

    # 6. transition invalid status (hits line 1903)
    with pytest.raises(ValueError, match="status must be proposed"):
        store.transition(eid, status="bogus_status")

    # 7. transition nonexistent (hits line 1906)
    assert store.transition("nonexistent", status="open") is None

    # 8. transition with content, confidence, priority, tags (hits lines 1912, 1914, 1916, 1918)
    up = store.transition(eid, status="open", content="new c", confidence=0.8, priority=0.9, tags=["tagA"])
    assert up["status"] == "open"
    assert up["content"] == "new c"
    assert up["confidence"] == 0.8
    assert up["priority"] == 0.9
    assert up["tags"] == ["tagA"]

    # 9. calibrate_confidence with empty evidence (hits line 1982)
    eid_no_ev = store.write(title="No Ev", addr="0x3000", confidence=0.6, evidence=[])
    assert store.calibrate_confidence(eid_no_ev) == 0.6

    # 10. decay_stale_confidence with None conf entry in loop (hits line 2012)
    from unittest.mock import MagicMock, patch
    with patch.object(store, "_tx") as mock_tx:
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchall.return_value = [
            {"id": "dummy", "confidence": None, "updated_at": 1, "decayed_at": None, "calibrated": 0, "evidence": "[]"}
        ]
        mock_tx.return_value.__enter__.return_value = mock_conn
        store.decay_stale_confidence(half_life_days=10)


def test_blackboard_targets_frontier_and_rpc_edges(tmp_path: Path) -> None:
    store = BlackboardStore(str(tmp_path / "targets.db"))

    # 1. _filter_by_query with empty query terms (hits line 2099)
    candidates = [{"title": "c1", "reason": "r1", "category": "cat1"}]
    assert store._filter_by_query(candidates, query="") == candidates

    # 2. _targets_unresolved unverified loop break on limit (hits line 2146)
    # Write 3 unverified low-confidence findings
    for i in range(3):
        store.write(title=f"Unverified {i}", addr=f"0x{i+1}000", kind="finding", status="open", confidence=0.3)
    unres = store._targets_unresolved(limit=1)
    assert len(unres) >= 1

    # 3. targets strategy="conflict" (hits lines 2162-2166)
    e1 = store.write(title="T1", addr="0x1000", status="open")
    e2 = store.write(title="T2", addr="0x1000", status="open")
    store.link_conflict(e1, e2, reason="conflict")
    conflicts = store.targets(strategy="conflict", limit=5)
    assert len(conflicts["targets"]) >= 1

    # 4. _targets_coverage break when out >= limit * 2 (hits line 2232)
    def mock_coverage_rpc(tool, args):
        return {
            "functions": [
                {"addr": f"0x10{i:02x}", "name": f"sub_10{i:02x}", "xref_count": 5}
                for i in range(10)
            ]
        }
    cov_targets = store.targets(strategy="coverage", limit=1, rpc_fn=mock_coverage_rpc)
    assert len(cov_targets["targets"]) >= 1

    # 5. _targets_frontier with confirmed anchor, callers/callees already seen / break on limit*2 (hits lines 2256, 2271-2272)
    store.write(title="Confirmed Anchor", addr="0x9000", status="confirmed", confidence=0.95)
    def mock_frontier_rpc(tool, args):
        # returns neighbours, some duplicate/known
        return {
            "functions": [{"addr": "0x9000"}, {"addr": "0x9000"}] + [
                {"addr": f"0x9{i:03x}"} for i in range(20)
            ]
        }
    front = store.targets(strategy="frontier", limit=1, rpc_fn=mock_frontier_rpc)
    assert len(front["targets"]) >= 1

    # 6. _neighbours non-dict (hits line 2300)
    assert store._neighbours(lambda t, a: "not a dict", "0x1000", "callers") == []

    # 7. _function_inventory None / exception (hits lines 2316, 2319-2320)
    assert store._function_inventory(None) == []
    def bad_rpc(t, a):
        raise RuntimeError("rpc down")
    assert store._function_inventory(bad_rpc) == []

    # 8. _function_inventory text output: short line + bad xrefs (hits lines 2341, 2347-2348)
    def text_rpc(t, a):
        return {
            "functions": "short line\n0x1000  int  ()  func_a  xrefs=not_int\n0x2000  void  ()  func_b  xrefs=10\n"
        }
    funcs = store._function_inventory(text_rpc)
    assert len(funcs) == 2
    assert funcs[0]["xref_count"] == 0
    assert funcs[1]["xref_count"] == 10

    # 9. next_target invalid strategy (hits line 2367)
    with pytest.raises(ValueError, match="strategy must be one of"):
        store.next_target(strategy="invalid_strat")


def test_blackboard_brief_markdown_and_pruning_auto_merge(tmp_path: Path) -> None:
    store = BlackboardStore(str(tmp_path / "brief_merge.db"))

    # 1. brief_markdown when all focus items are blocked on dependencies (hits line 2559)
    store.write(title="Blocked 1", addr="0x1000", status="open", depends_on="0x9999", confidence=0.5)
    store.write(title="Blocked 2", addr="0x2000", status="open", depends_on="0x8888", confidence=0.5)
    md = store.workspace_brief()["brief"]
    assert "every open item is blocked" in md

    # 2. prune_entries min_q_value, max_entries, no-op (hits lines 2691-2692, 2699-2709, 2714)
    # Write entries
    store.write(title="P1", addr="0x3000", confidence=0.2)
    store.write(title="P2", addr="0x4000", confidence=0.3)
    store.write(title="P3", addr="0x5000", confidence=0.8)

    # Prune with min_q_value condition (hits lines 2691-2692, 2699-2709)
    res_prune = store.prune(max_entries=1, min_q_value=0.5)
    assert res_prune["pruned"] >= 1

    # Prune with max_entries when nothing to delete (hits line 2714)
    res_noop = store.prune(max_entries=100)
    assert res_noop["pruned"] == 0

    # 3. auto_merge with duplicates and conflict guards (hits lines 2754, 2757)
    # Write e2, e1, e0 so e0 and e2 match, but e1 doesn't. When e0 deletes e2, next iteration e1 is not deleted and checks e2 (hits line 2754)
    store.write(title="Alpha Gamma", addr="0x6000", category="crypto", embed=False)
    store.write(title="Beta Delta", addr="0x6000", category="crypto", embed=False)
    store.write(title="Alpha Gamma", addr="0x6000", category="crypto", embed=False)
    # And a conflicted finding that should NOT be merged (hits line 2757)
    m_conf1 = store.write(title="Duplicate Title A", addr="0x6000", category="crypto", embed=False)
    m_conf2 = store.write(title="Other Title", addr="0x7000", category="crypto", embed=False)
    store.link_conflict(m_conf1, m_conf2, reason="disputed")

    merge_res = store.auto_merge(addr="0x6000", category="crypto")
    assert merge_res["merged"] >= 1
