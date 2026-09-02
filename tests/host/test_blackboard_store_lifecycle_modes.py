"""Exercise durable blackboard CRUD, retrieval, lifecycle, and target modes."""

from __future__ import annotations

import time

from ida_pro_mcp.host.stores import blackboard_store as store_module
from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore


def test_embedded_crud_retrieval_and_lifecycle_compose(tmp_path, monkeypatch):
    store = BlackboardStore(str(tmp_path / "workspace.db"))
    model = tmp_path / "model.gguf"
    model.write_bytes(b"model")

    class Embedder:
        backend = "offline-test"
        _model_path = str(model)

        @staticmethod
        def embed_document_vector(_text):
            return [1.0, 0.0]

        @staticmethod
        def embed_query_vector(_text):
            return [1.0, 0.0]

    def get_embedder():
        return Embedder()

    monkeypatch.setattr(store, "_get_embedder", get_embedder)
    store.embed_enqueue = lambda *_args: (_ for _ in ()).throw(RuntimeError("worker offline"))
    entry_id = store.write(
        "Network parser",
        "checks packet length",
        category="analysis",
        addr="0X401000",
        tags=["network", "parser"],
        evidence=[{"type": "trace", "value": "recv"}],
        confidence=0.8,
        embed=True,
    )
    assert store.read(entry_id)["addr"] == "0x401000"
    semantic = store.semantic_search("packet length", top_k=3, threshold=0.1)
    assert semantic and semantic[0]["match"] == "semantic"
    assert semantic[0]["rank_reason"].startswith("semantic cosine")

    merged = store.upsert_finding(
        "Network parser",
        content="also checks bounds",
        category="analysis",
        addr="0x401000",
        tags=["bounds"],
        evidence=[{"type": "trace", "value": "recv"}, {"type": "review", "value": "manual"}],
        confidence=0.7,
        status="confirmed",
        priority=0.9,
    )
    assert merged["created"] is False
    current = store.read(entry_id)
    assert current["status"] == "confirmed"
    assert set(current["tags"]) == {"bounds", "network", "parser"}
    assert store.add_evidence(entry_id, "test", "bounded", weight=0.8) is True
    assert store.calibrate_confidence(entry_id) >= 0.1
    assert store.transition(entry_id, "rejected", reason="counterexample")["rejected_reason"] == "counterexample"
    assert store.contradict(entry_id, "second reason") is True
    assert store.mark_resolved(entry_id) is True
    assert store.mark_resolved("missing") is False


def test_filters_targets_publication_decay_and_merge_modes(tmp_path, monkeypatch):
    store = BlackboardStore(str(tmp_path / "workspace.db"))
    confirmed = store.upsert_finding(
        "Confirmed parser", addr="0x401000", category="analysis", status="confirmed", confidence=0.95,
        tags=["important"], evidence=[{"type": "static", "value": "check"}],
    )["entry_id"]
    open_id = store.upsert_finding(
        "Open packet question", addr="0x402000", category="analysis", kind="question", confidence=0.4,
    )["entry_id"]
    store.update(open_id, depends_on="0x403000")
    store.upsert_finding("Resolved dependency", addr="0x403000", status="resolved", confidence=0.9)
    examined = store.record_examination("0x404000", verdict="unclear", note="needs follow-up")

    filtered = store.list(category="analysis", tag="important", status="confirmed", include_contradicted=False)
    assert [row["id"] for row in filtered] == [confirmed]
    assert store.list(verdict="unclear")[0]["id"] == examined["entry_id"]
    assert store.publishable() and store.publishable()[0]["id"] == confirmed
    comment = store.comment_for(store.read(confirmed), max_len=80)
    assert "[mcp:" in comment
    assert store.mark_published(confirmed, "parse_packet") is True
    assert store.publishable() == []
    assert store.publishable(include_published=True)
    assert store.adopt_annotation("0x405000", name="meaningful_symbol")
    assert store.adopt_annotation("0x405001", name="sub_405001", comment="") is None
    assert store.adopt_annotation("0x405002", comment="our [mcp:1234]") is None

    unresolved = store.targets("unresolved", limit=5)
    assert unresolved["targets"][0]["address"] == "0x402000"
    assert "dependency 0x403000 is resolved" in unresolved["targets"][0]["reason"]
    assert store.next_target(limit=5, query="parser")
    assert store.next_target(limit=2, strategy="frontier", rpc_fn=lambda *_args: {}) == []

    now = time.time()
    store._conn().execute("UPDATE findings SET updated_at=?, decayed_at=0 WHERE id=?", (now - 3 * 86400, open_id))
    monkeypatch.setattr(store_module.time, "time", lambda: now)
    assert store.decay_stale_confidence(half_life_days=1, min_confidence=0.1) >= 1

    duplicate_a = store.write("Duplicate title", addr="0x406000", category="analysis", confidence=0.2)
    duplicate_b = store.write("Duplicate title", addr="0x406000", category="analysis", confidence=0.3)
    assert duplicate_a != duplicate_b
    assert store.exists_similar("0x406000", "analysis", "Duplicate title") is True
    assert store.auto_merge(addr="0x406000", category="analysis")["merged"] == 1
    assert store.delete("missing") is False
    assert store.delete(duplicate_a) is True
    assert store.clear("does-not-exist") == 0


def test_target_inventory_and_semantic_fallback_shapes(tmp_path, monkeypatch):
    store = BlackboardStore(str(tmp_path / "workspace.db"))
    store.upsert_finding("Known", addr="0x401000", status="confirmed")

    inventory = {
        "functions": [
            {"start_ea": 0x402000, "name": "sub_402000", "xref_count": 8},
            {"addr": "0x403000", "name": "named_handler", "callers_count": 3},
            {"name": "missing_address"},
            "bad",
        ]
    }
    coverage = store.targets("coverage", limit=4, rpc_fn=lambda *_args: inventory)
    assert coverage["targets"][0]["address"] == "0x402000"
    assert "callers" in coverage["targets"][0]["reason"]
    assert store.last_coverage_note == ""
    no_live = store.targets("coverage", rpc_fn=None)
    assert no_live["targets"] == [] and "No live IDA" in no_live["note"]

    text_inventory = {"functions": "0x404000  xrefs=4  type  named"}
    assert store._function_inventory(lambda *_args: text_inventory)[0]["xref_count"] == 4
    assert store._function_inventory(lambda *_args: {"functions": 7}) == []
    assert store._neighbours(lambda *_args: {"callees": [{"ea": 0x405000}, "0x406000"]}, "0x401000", "callees") == ["4214784", "0x406000"]
    assert store._neighbours(lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")), "0x401000", "callees") == []

    class NoEmbedder:
        def embed_query_vector(self, _query):
            return None

    def get_no_embedder():
        return NoEmbedder()

    monkeypatch.setattr(store, "_get_embedder", get_no_embedder)
    store.write("Lexical packet note", "packet checksum", addr="0x407000")
    fallback = store.semantic_search("packet checksum", top_k=2)
    assert fallback and fallback[0]["match"] == "lexical"
