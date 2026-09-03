"""Boundary coverage for semantic search orchestration.

The index, classifier, and reranker are scripted at their process/module
boundaries.  This keeps the tests deterministic while exercising the actual
response and degradation contracts of the search tool.
"""

from __future__ import annotations

import builtins
import sys
import types

from tests.ida_mcp.test_search_semantic_mode_matrix import _Index, _semantic


def test_get_backend_handles_context_import_and_refresh_failures(monkeypatch):
    sem = _semantic()
    import ida_pro_mcp.services as services

    real_import = builtins.__import__

    def blocked_import(name, *args, **kwargs):
        if name in {"ida_pro_mcp.services", "host.intelligence.context"}:
            raise ImportError("context unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    assert sem.get_backend()["code"] == "NOT_FOUND"
    monkeypatch.setattr(builtins, "__import__", real_import)

    class Assembler:
        def _get_index(self, _path):
            return _Index([], size=0, changed=True)

        def ensure_embedding_server(self):
            raise AssertionError("empty index must return before backend startup")

    index = Assembler()._get_index("")
    index.refresh_from_disk = lambda: (_ for _ in ()).throw(RuntimeError("stale"))
    monkeypatch.setattr(services, "get_assembler", Assembler)
    monkeypatch.setattr(sem.idc, "get_idb_path", lambda: "/tmp/a.idb", raising=False)
    monkeypatch.setattr(Assembler, "_get_index", lambda _self, _path: index)
    result = sem.get_backend()
    assert result["code"] == "NOT_FOUND"
    assert "No embeddings indexed yet" in result["message"]


def test_call_rerank_supports_scripted_rerankers_without_deadline():
    sem = _semantic()

    class SimpleReranker:
        def rerank(self, query, docs):
            return [(query, docs)]

    assert sem._call_rerank(SimpleReranker(), "q", ["d"], 4.0) == [("q", ["d"])]


def test_search_nl_accepts_legacy_backend_tuple_and_radius_errors(monkeypatch):
    sem = _semantic()
    index = _Index([{"ea": "0x1000", "name": "f", "similarity": 0.5}])
    monkeypatch.setattr(sem, "get_backend", lambda: (index, None, "/tmp/a.idb"))
    assert sem.search_nl("q", mode="quick", rerank=False, limit=1)["count"] == 1

    import ida_pro_mcp.host.intelligence.scope_window as scope_window

    monkeypatch.setattr(
        scope_window,
        "radius_address_range",
        lambda *_args: (_ for _ in ()).throw(ValueError("address overflow")),
    )
    error = sem.search_nl("q", center_ea=0x1000, radius=4)
    assert error["code"] == "INVALID_ARGS"
    assert "address overflow" in error["message"]

    monkeypatch.setattr(sem, "get_backend", lambda: {"code": "NOT_FOUND"})
    assert sem.search_nl("q")["code"] == "NOT_FOUND"


def test_search_nl_expansion_merges_duplicates_and_survives_extra_failures(monkeypatch):
    sem = _semantic()

    class Index(_Index):
        size = 2

        def search(self, query, top_k, threshold, address_ranges=None):
            self.calls.append((query, top_k, threshold, address_ranges))
            if query == "q":
                return [
                    {"ea": "0x1000", "name": "base", "similarity": 0.2},
                    {"ea": "0x2000", "name": "other", "similarity": 0.3},
                ]
            if query == "network http":
                return [
                    {"ea": "0x1000", "name": "base", "similarity": 0.9},
                    {"ea": "", "name": "malformed", "similarity": 1.0},
                ]
            if query == "file io":
                raise RuntimeError("secondary index failure")
            return []

    class Classifier:
        def classify(self, *_args, **_kwargs):
            return [
                {"behavior": "network_http", "confidence": 0.9},
                {"behavior": "file_io", "confidence": 0.9},
            ]

    index = Index([], size=2)
    monkeypatch.setattr(
        sem,
        "get_backend",
        lambda: (index, Classifier(), "/tmp/a.idb", ""),
    )
    response = sem.search_nl("q", mode="expand", rerank=False, limit=2)
    assert response["ok"] is True
    assert response["items"][0]["addr"] == "0x1000"
    assert response["items"][0]["similarity"] == 0.864
    assert [call[0] for call in index.calls] == ["q", "network http", "file io"]


def test_search_nl_stops_expansion_at_deadline_and_handles_rerank_unavailable(
    monkeypatch,
):
    sem = _semantic()
    index = _Index([{"ea": "0x1000", "name": "f", "similarity": 0.7}], size=1)

    class Classifier:
        def classify(self, *_args, **_kwargs):
            return [{"behavior": "network_http", "confidence": 0.95}]

    monkeypatch.setattr(
        sem,
        "get_backend",
        lambda: (index, Classifier(), "/tmp/a.idb", ""),
    )
    clock = iter([0.0, 20.0])
    monkeypatch.setattr(sem._time, "time", lambda: next(clock))
    response = sem.search_nl("q", mode="expand", rerank=False, timeout_ms=1)
    assert response["ok"] is True
    assert [call[0] for call in index.calls] == ["q"]

    import ida_pro_mcp.host.intelligence.rerank as rerank_module

    class NoModel:
        _use_llama = False

    monkeypatch.setattr(rerank_module, "Reranker", NoModel)
    monkeypatch.setattr(sem._time, "time", lambda: 0.0)
    no_model = sem.search_nl("q", mode="quick", rerank=True)
    assert no_model["rerank"]["applied"] is False


def test_search_nl_rerank_handles_constructor_timeout_and_invalid_scores(monkeypatch):
    sem = _semantic()
    import ida_pro_mcp.host.intelligence.rerank as rerank_module

    index = _Index([
        {"ea": "0x1000", "name": "f", "similarity": 0.7},
    ], size=1)
    monkeypatch.setattr(sem, "get_backend", lambda: (index, None, "/tmp/a.idb", ""))

    class Broken:
        def __init__(self):
            raise RuntimeError("model unavailable")

    monkeypatch.setattr(rerank_module, "Reranker", Broken)
    response = sem.search_nl("q", mode="quick", rerank=True)
    assert response["ok"] is True
    assert response["rerank"]["applied"] is False

    class TimeoutReranker:
        _use_llama = True

        def rerank(self, *_args, **_kwargs):
            raise AssertionError("expired deadline must skip reranking")

    monkeypatch.setattr(rerank_module, "Reranker", TimeoutReranker)
    monkeypatch.setattr(sem._time, "time", iter([0.0, 2.0]).__next__)
    monkeypatch.setattr(sem._time, "monotonic", lambda: 5.0)
    timeout = sem.search_nl("q", mode="quick", rerank=True, timeout_ms=1)
    assert timeout["rerank"]["reason"] == "timeout"

    class InvalidScores:
        _use_llama = True

        def rerank(self, *_args, **_kwargs):
            return [{"index": 99, "score": 0.4}]

        def status(self):
            return {"profile_name": "invalid"}

    monkeypatch.setattr(rerank_module, "Reranker", InvalidScores)
    monkeypatch.setattr(sem._time, "time", lambda: 0.0)
    invalid = sem.search_nl("q", mode="quick", rerank=True)
    assert invalid["rerank"]["applied"] is False


def test_search_nl_rerank_falls_back_from_missing_docs_and_empty_results(monkeypatch):
    sem = _semantic()
    import ida_hexrays

    import ida_pro_mcp.host.intelligence.rerank as rerank_module

    index = _Index([{"ea": "0x1000", "name": "f", "similarity": 0.7}], size=1)
    monkeypatch.setattr(sem, "get_backend", lambda: (index, None, "/tmp/a.idb", ""))

    class Reranker:
        _use_llama = True

        def rerank(self, _query, docs, **_kwargs):
            assert docs == ["f"]
            return []

        def status(self):
            return {"profile_name": "empty"}

    monkeypatch.setattr(rerank_module, "Reranker", Reranker)
    monkeypatch.setattr(ida_hexrays, "decompile", lambda _ea: None, raising=False)
    response = sem.search_nl("q", mode="quick", rerank=True)
    assert response["ok"] is True
    assert response["rerank"]["pool"] == 1

    empty = _Index([], size=1)
    monkeypatch.setattr(sem, "get_backend", lambda: (empty, None, "/tmp/a.idb", ""))
    assert sem.search_nl("q", mode="quick", rerank=False)["count"] == 0


def test_search_behavior_handles_timeouts_backend_errors_and_classifier_edges(monkeypatch):
    sem = _semantic()
    package = sys.modules["ida_pro_mcp.ida_mcp.tools.search"]
    package._query_insight_by_tags = lambda _tags, mode="or": ["0x1000"]
    sem.idc.get_func_name = lambda _ea: "sub_1000"
    sem.idautils.Functions = lambda: [0x1000, 0x2000]
    sem.ida_hexrays.decompile = lambda ea: None if ea == 0x1000 else "pseudo"

    class Classifier:
        _anchor_embs = {"network_http": [1.0]}

        def classify(self, pseudo, **_kwargs):
            if pseudo == "pseudo":
                return [{"behavior": "network_http", "score": 0.7}]
            return []

    monkeypatch.setattr(
        sem,
        "get_backend",
        lambda: ("index", Classifier(), "/tmp/a.idb"),
    )
    response = sem.search_behavior("network http", limit=4)
    assert response["count"] == 2
    assert response["items"][1]["confidence"] == 0.7

    class Timer:
        def __init__(self, _timeout):
            self.calls = 0

        def check(self):
            self.calls += 1
            if self.calls > 1:
                raise TimeoutError

    monkeypatch.setattr(sem, "SearchTimeout", Timer)
    timeout = sem.search_behavior("network_http", limit=4)
    assert timeout["ok"] is True

    monkeypatch.setattr(sem, "get_backend", lambda: {"code": "NOT_FOUND"})
    package._query_insight_by_tags = lambda _tags, mode="or": []
    result = sem.search_behavior("network_http", limit=4)
    assert result["ok"] is True


def test_search_behavior_swallows_l1_and_backend_failures(monkeypatch):
    sem = _semantic()
    package = sys.modules["ida_pro_mcp.ida_mcp.tools.search"]
    package._query_insight_by_tags = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("insight unavailable")
    )
    monkeypatch.setattr(sem, "get_backend", lambda: (_ for _ in ()).throw(RuntimeError("backend")))
    response = sem.search_behavior("file_io", limit=4)
    assert response["ok"] is True
    assert response["count"] == 0


def test_search_behavior_rejects_blank_tags_and_zero_limit():
    sem = _semantic()
    assert sem.search_behavior(" ")["code"] == "INVALID_ARGS"
    response = sem.search_behavior("network_http", limit=0)
    assert response["ok"] is True
    assert response["count"] == 0
