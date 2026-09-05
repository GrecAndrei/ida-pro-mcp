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


def test_env_int_fallback_on_invalid_string(monkeypatch):
    sem = _semantic()
    monkeypatch.setenv("IDA_MCP_TEST_BAD_INT", "not-an-int")
    assert sem._env_int("IDA_MCP_TEST_BAD_INT", 42) == 42


def test_get_backend_fallback_to_context_assembler(monkeypatch):
    sem = _semantic()
    import builtins
    real_import = builtins.__import__

    def import_with_context_fallback(name, *args, **kwargs):
        if name == "ida_pro_mcp.services":
            raise ImportError("no services")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_with_context_fallback)

    class FakeAssembler:
        def _get_index(self, _path):
            return _Index([], size=0)

    context = types.ModuleType("host.intelligence.context")
    context.get_assembler = FakeAssembler
    monkeypatch.setitem(sys.modules, "host.intelligence.context", context)
    monkeypatch.setattr(sem.idc, "get_idb_path", lambda: "/tmp/sample.idb", raising=False)
    res = sem.get_backend()
    assert res["code"] == "NOT_FOUND"


def test_call_rerank_when_signature_raises(monkeypatch):
    sem = _semantic()

    class WeirdReranker:
        def rerank(self, query, docs):
            return [(query, docs)]

    import inspect
    monkeypatch.setattr(inspect, "signature", lambda _fn: (_ for _ in ()).throw(ValueError("bad signature")))
    assert sem._call_rerank(WeirdReranker(), "q", ["d"], 4.0) == [("q", ["d"])]


def test_search_nl_fallback_imports(monkeypatch):
    sem = _semantic()
    import builtins
    real_import = builtins.__import__

    def import_fallback_router(name, *args, **kwargs):
        if name in {
            "ida_pro_mcp.host.intelligence.scope_window",
            "ida_pro_mcp.host.intelligence.rerank",
        }:
            raise ImportError("fallback required")
        return real_import(name, *args, **kwargs)

    monkeypatch.delitem(sys.modules, "ida_pro_mcp.host.intelligence.scope_window", raising=False)
    monkeypatch.delitem(sys.modules, "ida_pro_mcp.host.intelligence.rerank", raising=False)
    monkeypatch.setattr(builtins, "__import__", import_fallback_router)

    scope = types.ModuleType("host.intelligence.scope_window")
    scope.radius_address_range = lambda center, radius: (center - radius, center + radius)
    monkeypatch.setitem(sys.modules, "host.intelligence.scope_window", scope)

    index = _Index([{"ea": "0x1000", "name": "f1", "similarity": 0.6}])
    monkeypatch.setattr(sem, "get_backend", lambda: (index, None, "/tmp/a.idb", ""))

    res = sem.search_nl("q", mode="quick", rerank=False, center_ea=0x1000, radius=0x100)
    assert res["ok"] is True


def test_search_nl_expansion_boundaries_and_rerank_docs_error(monkeypatch):
    sem = _semantic()

    class FlakyIndex:
        _embedder = type("Embedder", (), {"backend": "fake"})()

        def __init__(self, rows):
            self.rows = rows

        @property
        def size(self):
            raise RuntimeError("size error")

        def db_changed_since_load(self):
            return False

        def refresh_from_disk(self):
            pass

        def _row_docs_for_eas(self, _eas):
            raise RuntimeError("side table error")

    class ExpandingClassifier:
        _anchor_embs = {"anchor": [0.1]}

        def classify(self, *args, **kwargs):
            return [{"behavior": "crypto_aes", "confidence": 0.8}]

    index = FlakyIndex([
        {"ea": "invalid-ea", "name": "bad", "similarity": 0.5},
        {"ea": "0x1000", "name": "f1", "similarity": 0.6},
    ])

    def extra_search(q, **kwargs):
        if q == "original":
            return list(index.rows)
        return [{"ea": "0x2000", "name": "expanded_func", "similarity": 0.9}]

    index.search = extra_search

    rerank_module = types.ModuleType("ida_pro_mcp.host.intelligence.rerank")

    class CustomReranker:
        _use_llama = True

        def rerank(self, query, docs, deadline=None):
            return [{"index": 0, "score": 0.99}]

        def status(self):
            return {"profile_name": "custom"}

    rerank_module.Reranker = CustomReranker
    rerank_module.RERANK_MAX_CANDIDATES = 64
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.host.intelligence.rerank", rerank_module)

    monkeypatch.setattr(sem, "get_backend", lambda: (index, ExpandingClassifier(), "/tmp/a.idb", ""))

    res = sem.search_nl("original", mode="expand", rerank=True, center_ea=0x1000, radius=0x2000)
    assert res["ok"] is True

    index.rows = [{"ea": "invalid-only", "name": "named_func"}]
    res2 = sem.search_nl("original", mode="expand", rerank=False, range_start=0x1000, range_end=0x2000)
    assert res2["ok"] is True

    res_quick = sem.search_nl("original", mode="quick", rerank=None)
    assert "quick mode keeps latency bounded" in res_quick.get("rerank", {}).get("reason", "")


def test_search_nl_reranker_import_failure(monkeypatch):
    sem = _semantic()
    import builtins
    real_import = builtins.__import__

    def import_without_reranker(name, *args, **kwargs):
        if name == "ida_pro_mcp.host.intelligence.rerank":
            raise ImportError("reranker package unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.delitem(sys.modules, "ida_pro_mcp.host.intelligence.rerank", raising=False)
    monkeypatch.setattr(builtins, "__import__", import_without_reranker)

    index = _Index([{"ea": "0x1000", "name": "f1", "similarity": 0.8}])
    monkeypatch.setattr(sem, "get_backend", lambda: (index, None, "/tmp/a.idb", ""))
    res = sem.search_nl("query", mode="expand", rerank=True)
    assert res["ok"] is True


def test_search_behavior_timeout_and_limit_breaks(monkeypatch):
    sem = _semantic()
    package = sys.modules["ida_pro_mcp.ida_mcp.tools.search"]

    package._query_insight_by_tags = lambda _tags, mode="or": ["0x1000", "0x2000"]

    class L1Timer:
        def __init__(self, _t):
            self.count = 0

        def check(self):
            self.count += 1
            if self.count >= 2:
                raise TimeoutError

    monkeypatch.setattr(sem, "SearchTimeout", L1Timer)
    res_l1_timeout = sem.search_behavior("crypto_symmetric", limit=10)
    assert res_l1_timeout["ok"] is True

    package._query_insight_by_tags = lambda _tags, mode="or": []

    class MockClassifier:
        _anchor_embs = {"crypto_symmetric": [0.1]}

        def classify(self, pseudo, **kwargs):
            return [{"behavior": "crypto_symmetric", "confidence": 0.9}]

    sem.idautils.Functions = lambda: [0x1000, 0x1010, 0x1020, 0x1030, 0x1040]
    sem.idc.get_func_name = lambda ea: f"sub_{ea:x}"

    calls = [0]

    def decompile_with_err(ea):
        calls[0] += 1
        if calls[0] == 1:
            raise RuntimeError("decomp error")
        return "pseudocode"

    sem.ida_hexrays.decompile = decompile_with_err
    monkeypatch.setattr(sem, "get_backend", lambda: ("index", MockClassifier(), "/tmp/a.idb", ""))

    class NoOpTimer:
        def __init__(self, _t):
            pass

        def check(self):
            pass

    monkeypatch.setattr(sem, "SearchTimeout", NoOpTimer)
    res_limit = sem.search_behavior("crypto_symmetric", limit=3)
    assert res_limit["ok"] is True
    assert res_limit["count"] == 3
