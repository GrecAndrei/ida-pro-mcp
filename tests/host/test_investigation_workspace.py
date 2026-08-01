from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from ida_pro_mcp.host.server.server_blackboard import ServerBlackboardMixin, _entry_brief
from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore


def test_repeated_observations_merge_evidence_instead_of_polluting_notebook(tmp_path):
    store = BlackboardStore(str(tmp_path / "workspace.db"))

    first = store.upsert_finding(
        "Packet length is unchecked",
        content="Length reaches memcpy.",
        category="vuln",
        addr="0x401000",
        kind="hypothesis",
        priority=0.9,
        confidence=0.6,
        tags=["parser"],
        evidence=[{"type": "decompile", "value": "memcpy(dst, src, len)"}],
    )
    repeated = store.upsert_finding(
        " packet LENGTH is unchecked ",
        content="Caller controls len.",
        category="vuln",
        addr="0X401000",
        kind="hypothesis",
        priority=0.7,
        confidence=0.85,
        tags=["input"],
        evidence=[{"type": "xref", "value": "recv caller"}],
    )

    assert repeated["entry_id"] == first["entry_id"]
    assert repeated["created"] is False
    assert store.stats()["total_entries"] == 1
    entry = store.read(first["entry_id"])
    assert entry["content"] == "Caller controls len."
    assert entry["confidence"] == 0.85
    assert entry["priority"] == 0.9
    assert entry["tags"] == ["input", "parser"]
    assert {item["type"] for item in entry["evidence"]} == {"decompile", "xref"}


def test_concurrent_clients_coalesce_the_same_claim(tmp_path):
    db_path = str(tmp_path / "workspace.db")
    BlackboardStore(db_path)

    def record(index: int):
        return BlackboardStore(db_path).upsert_finding(
            "Shared parser observation",
            category="parser",
            addr="0x401000",
            evidence=[{"type": "client", "value": str(index)}],
        )["entry_id"]

    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(record, range(16)))

    store = BlackboardStore(db_path)
    assert len(set(ids)) == 1
    assert store.stats()["total_entries"] == 1
    assert len(store.read(ids[0])["evidence"]) == 16


def test_workspace_brief_tracks_questions_transitions_conflicts_and_activity(tmp_path):
    store = BlackboardStore(str(tmp_path / "workspace.db"))
    question = store.upsert_finding(
        "Who controls the packet length?",
        kind="question",
        priority=1.0,
        confidence=0.4,
    )["entry_id"]
    fact = store.upsert_finding(
        "Length comes from recv buffer",
        kind="finding",
        status="confirmed",
        confidence=0.95,
    )["entry_id"]
    rejected = store.upsert_finding("Length is constant", kind="hypothesis")["entry_id"]
    store.transition(rejected, "rejected", reason="Caller passes a variable value")

    brief = store.workspace_brief()

    assert brief["focus"][0]["id"] == question
    assert brief["confirmed"][0]["id"] == fact
    assert brief["conflicts"][0]["id"] == rejected
    assert brief["counts"] == {
        "total": 3, "open": 1, "confirmed": 1, "conflicts": 1, "questions": 1,
        "stale": 0, "examined": 0,
    }
    assert any(event["event"] == "status:rejected" for event in brief["recent_activity"])
    assert "Established:" in brief["brief"]
    assert "Length comes from recv buffer" in brief["brief"]


def test_entry_brief_prefers_status_column_over_legacy_flags(tmp_path):
    store = BlackboardStore(str(tmp_path / "workspace.db"))
    entry_id = store.upsert_finding(
        "Confirmed parser length",
        kind="finding",
        status="confirmed",
    )["entry_id"]
    entry = store.read(entry_id)
    brief = _entry_brief(entry)
    assert brief["status"] == "confirmed"


def test_workspace_brief_hides_internal_auto_enrichment_rows(tmp_path):
    store = BlackboardStore(str(tmp_path / "workspace.db"))
    store.upsert_finding("User-visible hypothesis", kind="hypothesis")
    store.write(
        title="evidence gravity 0x401000",
        content="{}",
        category="evidence_gravity",
        addr="0x401000",
        source_type="gravity",
    )
    brief = store.workspace_brief()
    titles = [item["title"] for item in brief["focus"]]
    assert titles == ["User-visible hypothesis"]


def test_search_falls_back_to_keywords_when_embeddings_are_unavailable(tmp_path):
    script = """
import json
from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore
store = BlackboardStore(DB_PATH)
store.write('TLS certificate parser', 'validates an ASN.1 length', category='crypto')
print(json.dumps(store.semantic_search('certificate length', top_k=5, category='crypto')))
"""
    env = dict(os.environ)
    env["IDA_MCP_EMBED_DISABLED"] = "1"
    result = subprocess.run(
        [sys.executable, "-c", f"DB_PATH={str(tmp_path / 'workspace.db')!r}\n{script}"],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    results = json.loads(result.stdout)
    assert [item["title"] for item in results] == ["TLS certificate parser"]
    assert results[0]["similarity"] == 1.0


def test_empty_frontier_seeds_from_live_ida_function_inventory(tmp_path):
    store = BlackboardStore(str(tmp_path / "workspace.db"))

    def rpc(tool, arguments):
        assert (tool, arguments) == ("data", {"action": "functions", "count": 200})
        return {
            "functions": [
                {"addr": "0x401000", "name": "named_parser", "xref_count": 20},
                {"addr": "0x402000", "name": "sub_402000", "xref_count": 12},
            ]
        }

    targets = store.next_target(limit=5, rpc_fn=rpc)

    # Only the auto-named function is offered: a name means IDA matched a
    # library signature or someone already understood it.
    assert len(targets) == 1
    assert targets[0]["addr"] == "0x402000"
    assert targets[0]["source_type"] == "seed"
    assert targets[0]["reason"] == "12 callers, never examined"


def test_coverage_falls_back_to_named_functions_on_a_symbolised_binary(tmp_path):
    """A binary with full symbols must still produce coverage candidates."""
    store = BlackboardStore(str(tmp_path / "workspace.db"))

    def rpc(tool, arguments):
        return {
            "functions": [
                {"addr": "0x401000", "name": "parse_header", "xref_count": 3},
                {"addr": "0x402000", "name": "dispatch", "xref_count": 9},
            ]
        }

    result = store.targets("coverage", limit=5, rpc_fn=rpc)

    assert [t["address"] for t in result["targets"]] == ["0x402000", "0x401000"]
    assert "no auto-named functions left to prefer" in result["targets"][0]["reason"]


def test_blackboard_workspace_is_shared_across_sessions_for_same_binary(tmp_path):
    binary_a = tmp_path / "first.bin"
    binary_copy = tmp_path / "copy.bin"
    binary_b = tmp_path / "different.bin"
    binary_a.write_bytes(b"same binary")
    binary_copy.write_bytes(b"same binary")
    binary_b.write_bytes(b"different binary")

    server = object.__new__(ServerBlackboardMixin)
    server.cache_dir = str(tmp_path / "cache")
    server.current_session = None
    server.session_mgr = SimpleNamespace(get_session=lambda _sid: None)
    first = SimpleNamespace(binary_path=str(binary_a), idb_path=str(tmp_path / "one.i64"), session_id="one")
    copy = SimpleNamespace(binary_path=str(binary_copy), idb_path=str(tmp_path / "two.i64"), session_id="two")
    different = SimpleNamespace(binary_path=str(binary_b), idb_path=str(tmp_path / "three.i64"), session_id="three")

    first_path = server._session_blackboard_path(session_obj=first)
    copy_path = server._session_blackboard_path(session_obj=copy)
    different_path = server._session_blackboard_path(session_obj=different)

    # Findings must survive session changes: every session of the same
    # binary (even a byte-identical copy) shares one workspace.
    assert first_path == copy_path
    assert first_path != different_path
    assert first_path == server._session_blackboard_path(session_obj=first)
    assert "sha256-" in first_path
    assert not first_path.endswith("-one.db")


def test_blackboard_findings_survive_a_new_session_for_the_same_binary(tmp_path):
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"persist-me")
    server = object.__new__(ServerBlackboardMixin)
    server.cache_dir = str(tmp_path / "cache")
    server.current_session = None
    server.session_mgr = SimpleNamespace(get_session=lambda _sid: None)

    session_a = SimpleNamespace(binary_path=str(binary), idb_path=str(tmp_path / "a.i64"), session_id="aaaa1111")
    session_b = SimpleNamespace(binary_path=str(binary), idb_path=str(tmp_path / "b.i64"), session_id="bbbb2222")

    path_a = server._session_blackboard_path(session_obj=session_a)
    store_a = BlackboardStore(path_a)
    store_a.write(
        title="Relocation table at 0x401000",
        content="high-entropy, loader writes it",
        addr="0x401000",
        category="finding",
        confidence=0.9,
    )

    # A brand-new session of the same binary reads the same workspace.
    path_b = server._session_blackboard_path(session_obj=session_b)
    assert path_a == path_b
    store_b = BlackboardStore(path_b)
    found = [e for e in store_b.list(limit=50) if e["title"] == "Relocation table at 0x401000"]
    assert len(found) == 1
    assert found[0]["addr"] == "0x401000"
