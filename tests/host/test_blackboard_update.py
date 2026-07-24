from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore


def test_update_merges_evidence_and_tags_instead_of_replacing(tmp_path):
    store = BlackboardStore(str(tmp_path / "workspace.db"))
    entry_id = store.upsert_finding(
        "Length is attacker-controlled",
        category="vuln",
        addr="0x401000",
        tags=["parser"],
        evidence=[{"type": "decompile", "value": "memcpy"}],
    )["entry_id"]

    assert store.update(
        entry_id,
        tags=["input"],
        evidence=[{"type": "xref", "value": "recv"}],
        content="Caller passes unchecked len.",
    )

    entry = store.read(entry_id)
    assert entry["content"] == "Caller passes unchecked len."
    assert entry["tags"] == ["input", "parser"]
    assert {item["type"] for item in entry["evidence"]} == {"decompile", "xref"}
    assert entry["version"] == 2


def test_concurrent_updates_preserve_all_evidence(tmp_path):
    db_path = str(tmp_path / "workspace.db")
    entry_id = BlackboardStore(db_path).upsert_finding(
        "Shared claim",
        category="parser",
        addr="0x401000",
        evidence=[{"type": "seed", "value": "0"}],
    )["entry_id"]

    def patch(index: int) -> bool:
        return BlackboardStore(db_path).update(
            entry_id,
            evidence=[{"type": "client", "value": str(index)}],
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert all(pool.map(patch, range(16)))

    entry = BlackboardStore(db_path).read(entry_id)
    assert len(entry["evidence"]) == 17
    assert {item["value"] for item in entry["evidence"] if item["type"] == "client"} == {
        str(index) for index in range(16)
    }
