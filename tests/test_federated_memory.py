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
