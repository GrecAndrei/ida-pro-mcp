"""Composed offline coverage for semantic backend resolution and search modes."""

import sys

from tests.ida_mcp.test_swarm_q04_search import _semantic


class _Index:
    _embedder = type("Embedder", (), {"backend": "fake"})()

    def __init__(self, rows, *, size=3, changed=False):
        self.rows = rows
        self.size = size
        self.changed = changed
        self.refreshed = 0
        self.calls = []

    def db_changed_since_load(self):
        return self.changed

    def refresh_from_disk(self):
        self.refreshed += 1
        self.changed = False

    def search(self, query, top_k, threshold, address_ranges=None):
        self.calls.append((query, top_k, threshold, address_ranges))
        return list(self.rows)[:top_k]


def test_get_backend_reports_empty_idb_and_empty_index(monkeypatch):
    import ida_pro_mcp.services as services

    sem = _semantic()
    monkeypatch.setattr(sem.idc, "get_idb_path", lambda: "", raising=False)
    assert sem.get_backend()["code"] == "NOT_FOUND"

    class Assembler:
        def _get_index(self, _path):
            return _Index([], size=0)

    monkeypatch.setattr(sem.idc, "get_idb_path", lambda: "/tmp/sample.idb", raising=False)

    def make_assembler():
        return Assembler()

    monkeypatch.setattr(services, "get_assembler", make_assembler)
    result = sem.get_backend()
    assert result["code"] == "NOT_FOUND"
    assert "No embeddings indexed yet" in result["message"]


def test_get_backend_refreshes_stale_index_and_exposes_degraded_or_ready_modes(monkeypatch):
    import ida_pro_mcp.services as services

    sem = _semantic()
    monkeypatch.setattr(sem.idc, "get_idb_path", lambda: "/tmp/sample.idb", raising=False)
    index = _Index([], size=2, changed=True)

    class Assembler:
        def _get_index(self, _path):
            return index

        def ensure_embedding_server(self):
            return False

        def _behavior_classifier(self):
            return "classifier"

    assembler = Assembler()

    def make_assembler():
        return assembler

    monkeypatch.setattr(services, "get_assembler", make_assembler)
    degraded = sem.get_backend()
    assert degraded[0] is index
    assert degraded[1] is None
    assert degraded[2:] == (
        "/tmp/sample.idb",
        "degraded — embedding backend unavailable; results ranked by lexical overlap only. Configure an embedding model and llama-server, then retry.",
    )
    assert index.refreshed == 1

    assembler.ensure_embedding_server = lambda: True
    ready = sem.get_backend()
    assert ready == (index, "classifier", "/tmp/sample.idb", "")


def test_search_nl_rejects_invalid_scopes_and_applies_radius_intersection(monkeypatch):
    sem = _semantic()
    index = _Index([
        {"ea": "not-an-ea", "name": "bad", "similarity": 1.0},
        {"ea": "0x800", "name": "outside", "similarity": 0.99},
        {"ea": "0x1000", "name": "inside", "similarity": 0.8},
        {"ea": "0x1100", "name": "boundary", "similarity": 0.7},
    ])
    monkeypatch.setattr(sem, "get_backend", lambda: (index, None, "/tmp/sample.idb", ""))

    assert sem.search_nl(" ")["code"] == "INVALID_ARGS"
    assert sem.search_nl("query", center_ea=0x1000, radius=0)["code"] == "INVALID_ARGS"
    assert sem.search_nl("query", center_ea=0x1000, radius="bad")["code"] == "INVALID_ARGS"
    assert sem.search_nl("query", range_start=0x2000, range_end=0x1000)["code"] == "INVALID_ARGS"

    response = sem.search_nl(
        "query",
        mode="quick",
        rerank=False,
        center_ea=0x1000,
        radius=0x100,
        range_start=0xF80,
        range_end=0x1080,
        include_items=True,
    )
    assert response["ok"] is True
    assert response["scope"] == {
        "start": "0xf80",
        "end": "0x1080",
        "center": "0x1000",
        "radius": 256,
    }
    assert [item["name"] for item in response["items"]] == ["inside"]
    assert index.calls[0][3] == [(0xF80, 0x1080)]


def test_search_nl_score_gates_explicit_min_score_and_preserves_degraded_note(monkeypatch):
    sem = _semantic()
    rows = [
        {"ea": "0x1000", "name": "high", "similarity": 0.9, "score": 0.9},
        {"ea": "0x2000", "name": "low", "similarity": 0.4, "score": 0.4},
    ]
    index = _Index(rows)
    monkeypatch.setattr(
        sem,
        "get_backend",
        lambda: (index, None, "/tmp/sample.idb", "degraded — lexical fallback"),
    )
    response = sem.search_nl("query", mode="quick", rerank=False, min_score=0.8)
    assert response["ok"] is True
    assert response["count"] == 1
    assert response["degraded"] == "degraded — lexical fallback"
    assert response["rerank"]["reason"] == "rerank disabled by caller"


def test_search_behavior_combines_insight_index_and_classifier(monkeypatch):
    sem = _semantic()
    package = sys.modules["ida_pro_mcp.ida_mcp.tools.search"]
    package._query_insight_by_tags = lambda _tags, mode="or": ["0x1000"]
    sem.idc.get_func_name = lambda ea: {0x1000: "indexed_fn", 0x2000: "sub_2000", 0x3000: "named_fn"}[ea]
    sem.idautils.Functions = lambda: [0x2000, 0x3000]
    sem.ida_hexrays.decompile = lambda ea: "pseudo for " + hex(ea)

    class Classifier:
        _anchor_embs = {"crypto_symmetric": [1.0]}

        def classify(self, pseudo, threshold, top_k, block):
            assert pseudo.startswith("pseudo")
            return [{"behavior": "crypto_symmetric", "confidence": 0.9}]

    index = _Index([], size=3)
    monkeypatch.setattr(sem, "get_backend", lambda: (index, Classifier(), "/tmp/sample.idb", ""))

    response = sem.search_behavior(" Crypto Symmetric ", limit=4)

    assert response["ok"] is True
    assert response["behavior"] == "crypto_symmetric"
    assert response["count"] == 2
    assert [item["source"] for item in response["items"]] == ["insight_index", "classifier"]
    assert response["items"][1]["confidence"] == 0.9
    assert "conf=0.90" in response["results"]


def test_search_nl_expands_scoped_candidates_and_handles_classifier_failures(monkeypatch):
    sem = _semantic()
    rows = [
        {"ea": "0x1000", "name": "parser", "similarity": 0.55},
        {"ea": "0x2000", "name": "crypto", "similarity": 0.45},
    ]
    index = _Index(rows, size=9001)

    class Classifier:
        def classify(self, *_args, **_kwargs):
            return [
                {"behavior": "network_http", "confidence": 0.95},
                {"behavior": "file_io", "confidence": 0.1},
            ]

    monkeypatch.setattr(sem, "get_backend", lambda: (index, Classifier(), "/tmp/sample.idb", ""))
    expanded = sem.search_nl("find the parser", mode="expand", rerank=False, limit=2)
    assert expanded["ok"] is True
    assert expanded["expansion_queries"] == ["network http"]
    assert any(call[0] == "network http" for call in index.calls)

    class BrokenClassifier:
        def classify(self, *_args, **_kwargs):
            raise RuntimeError("classifier unavailable")

    index.calls.clear()
    monkeypatch.setattr(sem, "get_backend", lambda: (index, BrokenClassifier(), "/tmp/sample.idb", ""))
    fallback = sem.search_nl("find the parser", mode="expand", rerank=False, limit=2)
    assert fallback["ok"] is True
    assert "expansion_queries" not in fallback


def test_search_nl_rerank_reorders_documents_and_preserves_recall_on_bad_scores(monkeypatch):
    sem = _semantic()
    import ida_hexrays

    import ida_pro_mcp.host.intelligence.rerank as rerank_module

    rows = [
        {"ea": "0x1000", "name": "first", "similarity": 0.9, "signature": "first signature"},
        {"ea": "0x2000", "name": "second", "similarity": 0.8},
    ]
    index = _Index(rows, size=2)
    index._row_docs_for_eas = lambda eas: {eas[0]: "stored first document"}
    monkeypatch.setattr(ida_hexrays, "decompile", lambda ea: f"decompiled {ea:x}", raising=False)

    class Reranker:
        _use_llama = True

        def rerank(self, _query, docs, *, deadline):
            assert docs == ["stored first document", "decompiled 2000"]
            assert deadline > 0
            return [{"index": 0, "score": 0.1}, {"index": 1, "score": 0.9}]

        def status(self):
            return {"profile_name": "fake-cross-encoder"}

    monkeypatch.setattr(rerank_module, "Reranker", Reranker)
    monkeypatch.setattr(sem, "get_backend", lambda: (index, None, "/tmp/sample.idb", ""))
    reranked = sem.search_nl("query", mode="quick", rerank=True, limit=2, include_items=True)
    assert reranked["rerank"]["applied"] is True
    assert reranked["rerank"]["profile"] == "fake-cross-encoder"
    assert reranked["items"][0]["addr"] == "0x2000"
    assert reranked["items"][0]["rerank_score"] == 0.9

    class IndiscriminatingReranker(Reranker):
        def rerank(self, _query, docs, *, deadline):
            return [{"index": i, "score": 0.5} for i, _ in enumerate(docs)]

    monkeypatch.setattr(rerank_module, "Reranker", IndiscriminatingReranker)
    index = _Index([
        {"ea": "0x1000", "name": "first", "similarity": 0.9},
        {"ea": "0x2000", "name": "second", "similarity": 0.8},
    ], size=2)
    monkeypatch.setattr(sem, "get_backend", lambda: (index, None, "/tmp/sample.idb", ""))
    preserved = sem.search_nl("query", mode="quick", rerank=True, limit=2)
    assert preserved["rerank"]["applied"] is False
    assert preserved["items"][0]["addr"] == "0x1000"


def test_search_behavior_reports_cold_classifier_and_invalid_l1_rows(monkeypatch):
    sem = _semantic()
    package = sys.modules["ida_pro_mcp.ida_mcp.tools.search"]
    package._query_insight_by_tags = lambda _tags, mode="or": ["not-an-address", "0x1000"]
    sem.idc.get_func_name = lambda _ea: "indexed_fn"

    class ColdClassifier:
        _anchor_embs = {}

    monkeypatch.setattr(sem, "get_backend", lambda: ("index", ColdClassifier(), "/tmp/sample.idb", ""))
    response = sem.search_behavior("Network HTTP", limit=4)
    assert response["ok"] is True
    assert response["behavior"] == "network_http"
    assert response["classifier_cold"] is True
    assert response["timed_out"] is True
    assert response["count"] == 1
