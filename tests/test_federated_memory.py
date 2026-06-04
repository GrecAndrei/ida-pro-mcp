from __future__ import annotations

import pytest
from ida_pro_mcp.capsule import CapsuleStore
from ida_pro_mcp.host.intelligence_preference_store import PreferenceMemoryBank


def test_preference_memory_bank_merge_math(tmp_path):
    db_local = str(tmp_path / "local.db")
    bank = PreferenceMemoryBank(db_path=db_local)

    # Seed local database: Q=0.8, visits=4
    bank.record("intent_x", "exp_y", initial_q=0.8)
    # Perform updates to adjust visits to 4 (initial record sets visits=1, update_q adds 1, so let's update Q 3 times)
    # Or we can write a mock record update directly
    with bank._conn() as conn:
        conn.execute("UPDATE memrl_triplets SET q_value=0.8, visit_count=4 WHERE intent_key='intent_x'")
        conn.commit()

    # Define incoming preference: Q=0.2, visits=6
    incoming = [{
        "intent_key": "intent_x",
        "experience_key": "exp_y",
        "q_value": 0.2,
        "visit_count": 6,
        "experience_meta": {"remote_tag": "net_raw"}
    }]

    # Merge
    res = bank.merge_preferences(incoming)
    assert res["merged_triplets"] == 1

    # Mathematically merged Q: (4 * 0.8 + 6 * 0.2) / 10 = (3.2 + 1.2) / 10 = 0.44
    # Merged visits: 4 + 6 = 10
    with bank._conn() as conn:
        row = conn.execute("SELECT q_value, visit_count, experience_meta FROM memrl_triplets").fetchone()
    assert float(row[0]) == pytest.approx(0.44)
    assert int(row[1]) == 10


def test_capsule_store_preference_merging(tmp_path):
    cap_local_path = tmp_path / "local.sideband"
    cap_remote_path = tmp_path / "remote.sideband"

    with CapsuleStore.open(cap_local_path) as c_local:
        c_local.init(project_name="local")
        c_local.record_experience_triplet("intent_a", "exp_1", initial_q=0.6)
        with c_local.conn:
            c_local.conn.execute("UPDATE memrl_triplets SET visit_count=2")
            c_local.conn.commit()

    with CapsuleStore.open(cap_remote_path) as c_remote:
        c_remote.init(project_name="remote")
        c_remote.record_experience_triplet("intent_a", "exp_1", initial_q=0.3)
        # Verify remote can add a suggestion too
        c_remote.add_experience_suggestion(
            intent_key="intent_a",
            experience_key="exp_1",
            source_tool="annotator",
            initial_q=0.3
        )
        with c_remote.conn:
            c_remote.conn.execute("UPDATE memrl_triplets SET visit_count=3")
            c_remote.conn.commit()

    # Perform Capsule-level preference merge
    with CapsuleStore.open(cap_local_path) as c_local:
        with CapsuleStore.open(cap_remote_path) as c_remote:
            merge_res = c_local.merge_capsule_preferences(c_remote)
            
        assert merge_res["merged_triplets"] == 1
        assert merge_res["merged_suggestions"] == 1

        # Check local value after merge:
        # local: Q=0.6, V=2
        # remote: Q=0.3, V=3
        # Expected Q: (2 * 0.6 + 3 * 0.3) / 5 = (1.2 + 0.9) / 5 = 2.1 / 5 = 0.42
        # Expected V: 2 + 3 = 5
        assert c_local.get_experience_q("intent_a", "exp_1") == pytest.approx(0.42)
        row = c_local.conn.execute("SELECT visit_count FROM memrl_triplets").fetchone()
        assert int(row["visit_count"]) == 5
        
        # Verify suggestion got imported
        sug_rows = c_local.conn.execute("SELECT COUNT(*) AS cnt FROM memrl_suggestions").fetchone()
        assert int(sug_rows["cnt"]) == 1


def test_federated_preference_edge_cases(tmp_path):
    db_local = str(tmp_path / "local_edge.db")
    bank = PreferenceMemoryBank(db_path=db_local)

    # 1. Merge empty list -> 0 merged
    res_empty = bank.merge_preferences([])
    assert res_empty["merged_triplets"] == 0

    # 2. Merge triplet with missing key should be skipped
    res_skipped = bank.merge_preferences([
        {"intent_key": "", "experience_key": "exp_y", "q_value": 0.5}
    ])
    assert res_skipped["merged_triplets"] == 0


def test_federation_bridge_blackboard_merging(tmp_path):
    import time
    from ida_pro_mcp.host.blackboard_store import BlackboardStore
    from ida_pro_mcp.host.intelligence.federation import FederationBridge

    local_path = str(tmp_path / "local_bb.db")
    remote_path = str(tmp_path / "remote_bb.db")

    local_store = BlackboardStore(local_path)
    remote_store = BlackboardStore(remote_path)

    # 1. Seed local database
    id1 = local_store.write(title="Local Finding", content="Some text", category="hypothesis", confidence=0.5, embed=False)
    with local_store._conn() as conn:
        conn.execute("UPDATE blackboard SET version=1, updated_at=100.0 WHERE id=?", (id1,))
        conn.commit()

    # 2. Seed remote database with different conflict resolution scenarios
    # Scenario A: Completely new entry -> Inserted
    id2 = remote_store.write(title="New Remote Finding", content="New text", category="ioc", confidence=0.9, embed=False)
    
    # Scenario B: Conflicting entry with higher version -> Updated
    id1_remote_v2 = remote_store.write(title="Remote Finding v2", content="v2 text", category="hypothesis", confidence=0.5, embed=False)
    with remote_store._conn() as conn:
        conn.execute("UPDATE blackboard SET id=?, version=2, updated_at=120.0 WHERE id=?", (id1, id1_remote_v2))
        conn.commit()

    # Scenario C: Conflicting entry with same version but higher confidence -> Updated
    id3 = local_store.write(title="Confidence Conflict", content="text", category="hypothesis", confidence=0.3, embed=False)
    with local_store._conn() as conn:
        conn.execute("UPDATE blackboard SET version=1, updated_at=100.0 WHERE id=?", (id3,))
        conn.commit()
    id3_remote = remote_store.write(title="Confidence Conflict Improved", content="better text", category="hypothesis", confidence=0.8, embed=False)
    with remote_store._conn() as conn:
        conn.execute("UPDATE blackboard SET id=?, version=1, updated_at=100.0 WHERE id=?", (id3, id3_remote))
        conn.commit()

    # Scenario D: Conflicting entry with same version & confidence but newer timestamp -> Updated
    id4 = local_store.write(title="Time Conflict", content="text", category="hypothesis", confidence=0.5, embed=False)
    with local_store._conn() as conn:
        conn.execute("UPDATE blackboard SET version=1, updated_at=100.0 WHERE id=?", (id4,))
        conn.commit()
    id4_remote = remote_store.write(title="Time Conflict Newer", content="text newer", category="hypothesis", confidence=0.5, embed=False)
    with remote_store._conn() as conn:
        conn.execute("UPDATE blackboard SET id=?, version=1, updated_at=200.0 WHERE id=?", (id4, id4_remote))
        conn.commit()

    # Scenario E: Conflicting entry with lower version/confidence/timestamp -> Skipped
    id5 = local_store.write(title="Skip Conflict", content="text", category="hypothesis", confidence=0.7, embed=False)
    with local_store._conn() as conn:
        conn.execute("UPDATE blackboard SET version=2, updated_at=200.0 WHERE id=?", (id5,))
        conn.commit()
    id5_remote = remote_store.write(title="Skip Conflict Stale", content="stale text", category="hypothesis", confidence=0.5, embed=False)
    with remote_store._conn() as conn:
        conn.execute("UPDATE blackboard SET id=?, version=1, updated_at=100.0 WHERE id=?", (id5, id5_remote))
        conn.commit()

    # Perform federation
    bridge = FederationBridge(local_path)
    stats = bridge.federate_blackboards([remote_path])

    assert stats["inserted"] == 1
    assert stats["updated"] == 3
    assert stats["skipped"] == 1

    # Verify updates in local DB
    entry1 = local_store.read(id1)
    assert entry1["version"] == 2
    assert entry1["title"] == "Remote Finding v2"

    entry3 = local_store.read(id3)
    assert entry3["confidence"] == 0.8
    assert entry3["title"] == "Confidence Conflict Improved"

    entry4 = local_store.read(id4)
    assert entry4["updated_at"] == 200.0
    assert entry4["content"] == "text newer"

    entry5 = local_store.read(id5)
    assert entry5["version"] == 2
    assert entry5["confidence"] == 0.7


def test_federation_bridge_preferences_merging(tmp_path):
    from ida_pro_mcp.host.intelligence.federation import FederationBridge

    local_bb = str(tmp_path / "local.blackboard.db")
    remote_cap_path = str(tmp_path / "remote.sideband")
    local_cap_path = str(tmp_path / "local.sideband")

    # Create local and remote sideband capsules
    with CapsuleStore.open(local_cap_path) as c_local:
        c_local.init(project_name="local")
        c_local.record_experience_triplet("intent_x", "exp_1", initial_q=0.6)
        with c_local.conn:
            c_local.conn.execute("UPDATE memrl_triplets SET visit_count=2")
            c_local.conn.commit()

    with CapsuleStore.open(remote_cap_path) as c_remote:
        c_remote.init(project_name="remote")
        c_remote.record_experience_triplet("intent_x", "exp_1", initial_q=0.4)
        c_remote.add_experience_suggestion(
            intent_key="intent_x",
            experience_key="exp_1",
            source_tool="annotator",
            initial_q=0.4
        )
        with c_remote.conn:
            c_remote.conn.execute("UPDATE memrl_triplets SET visit_count=3")
            c_remote.conn.commit()

    bridge = FederationBridge(local_bb)
    stats = bridge.federate_preferences([remote_cap_path])

    assert stats["merged_triplets"] == 1
    assert stats["merged_suggestions"] == 1

    with CapsuleStore.open(local_cap_path) as c_local:
        assert c_local.get_experience_q("intent_x", "exp_1") == pytest.approx(0.48)
        row = c_local.conn.execute("SELECT visit_count FROM memrl_triplets").fetchone()
        assert int(row["visit_count"]) == 5
        sug_rows = c_local.conn.execute("SELECT COUNT(*) AS cnt FROM memrl_suggestions").fetchone()
        assert int(sug_rows["cnt"]) == 1


