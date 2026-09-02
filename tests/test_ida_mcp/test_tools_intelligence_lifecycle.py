"""Offline lifecycle tests for the intelligence tool's public dispatcher."""

from __future__ import annotations

import importlib
import sys
import types
from types import SimpleNamespace

import pytest

intelligence_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.intelligence")
services_mod = importlib.import_module("ida_pro_mcp.services")


class FakeEmbedder:
    backend = "fake-embedder"
    decomp_document_chars = 256

    def __init__(self):
        self.ready_calls = 0

    def ensure_ready(self):
        self.ready_calls += 1
        return True

    def status(self, **kwargs):
        return {"backend": self.backend, "ready": True, "probe": kwargs.get("probe", False)}


class FakeClassifier:
    ANCHORS = {"network": "socket", "crypto": "cipher"}
    _anchor_embs = {"network": [1.0]}
    last = None

    def __init__(self, embedder):
        self.embedder = embedder
        self.refreshed = []
        FakeClassifier.last = self

    @classmethod
    def instance(cls, embedder):
        return cls(embedder)

    def refresh_anchors(self, behaviors=None):
        self.refreshed.append(behaviors)

    def classify(self, text, **kwargs):
        return [{"behavior": "network", "score": 0.91, "text": text, "top_k": kwargs["top_k"]}]


class FakeIndex:
    created = []

    def __init__(self, db_path, embedder):
        self.db_path = db_path
        self._db = db_path
        self.embedder = embedder
        self.size = 2
        self.indexed = []
        FakeIndex.created.append(self)

    def index(self, ea, name, document, metadata):
        self.indexed.append((ea, name, document, metadata))
        return True

    def index_many(self, rows):
        self.indexed.extend(rows)
        return {"indexed": len(rows), "failed": 0}

    def index_async(self, *row):
        self.indexed.append(row)

    def quality_counts(self):
        return {"full": 1, "fast": 1}

    def metadata(self):
        return {"count": self.size, "path": self.db_path}

    def search(self, query, **kwargs):
        return [{"ea": "0x140001100", "name": "peer", "score": 0.88, "query": query}]

    def similar(self, document, **kwargs):
        return [{"ea": "0x140001100", "score": 0.9, "document": document}]


@pytest.fixture
def intelligence_env(monkeypatch):
    FakeIndex.created.clear()
    monkeypatch.setattr(intelligence_mod.idaapi, "FUNC_THUNK", 0x80, raising=False)
    monkeypatch.setattr(services_mod, "BgeCodeEmbedder", FakeEmbedder)
    monkeypatch.setattr(services_mod, "BehaviorClassifier", FakeClassifier)
    monkeypatch.setattr(services_mod, "FunctionEmbeddingIndex", FakeIndex)
    monkeypatch.setattr(intelligence_mod.idaapi, "PATH_TYPE_IDB", 1, raising=False)
    monkeypatch.setattr(
        intelligence_mod.idaapi,
        "get_path",
        lambda _path_type: "/tmp/lifecycle.idb",
        raising=False,
    )
    func = SimpleNamespace(start_ea=0x140001000, end_ea=0x140001020, flags=0)
    monkeypatch.setattr(intelligence_mod._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(intelligence_mod._compat, "get_flow_chart", lambda _ea: [])
    monkeypatch.setattr(intelligence_mod._compat, "get_segment_name", lambda _ea: ".text")
    monkeypatch.setattr(intelligence_mod._compat, "get_func_flags", lambda _ea: 0)
    monkeypatch.setattr(intelligence_mod.ida_funcs, "get_func_name", lambda _ea: "handler", raising=False)
    monkeypatch.setattr(intelligence_mod.idautils, "Functions", lambda: [0x140001000, 0x140001020], raising=False)
    monkeypatch.setattr(intelligence_mod.idautils, "Heads", lambda _start, _end: [0x140001000], raising=False)
    monkeypatch.setattr(intelligence_mod.idautils, "CodeRefsFrom", lambda *_args: [], raising=False)
    monkeypatch.setattr(intelligence_mod.idautils, "DataRefsFrom", lambda *_args: [], raising=False)
    monkeypatch.setattr(intelligence_mod, "_safe_decompile", lambda _ea: "int handler(void) { return 1; }")
    return func


def test_intelligence_status_anchors_and_classification(intelligence_env):
    status = intelligence_mod.intelligence(action="intelligence_status")
    assert status["ok"] is True
    assert status["embedder"]["backend"] == "fake-embedder"
    assert status["anchors"] == {
        "count": 2,
        "loaded": 1,
        "anchor_set_hash": status["anchors"]["anchor_set_hash"],
    }
    assert status["indexes"]["functions_indexed"] == 2

    embedder = intelligence_mod.intelligence(action="embedder_status", probe=True)
    assert embedder["ok"] is True and embedder["embedder"]["probe"] is True
    reranker = intelligence_mod.intelligence(action="reranker_status")
    assert reranker["ok"] is True and "reranker" in reranker

    anchors = intelligence_mod.intelligence(action="anchor_status")
    assert anchors["count"] == 2 and anchors["loaded"] == 1
    refreshed = intelligence_mod.intelligence(action="refresh_anchors", query="network,crypto")
    assert refreshed["ok"] is True
    assert refreshed["refreshed"] == ["network", "crypto"]
    assert FakeClassifier.last.refreshed == [["network", "crypto"]]

    classified = intelligence_mod.intelligence(
        action="classify_text", query="socket parser", top_k=2, threshold=0.8, block=True
    )
    assert classified["ok"] is True
    assert classified["backend"] == "fake-embedder"
    assert classified["behaviors"][0]["top_k"] == 2
    assert intelligence_mod.intelligence(action="classify_text")["error"] is True

    function = intelligence_mod.intelligence(action="classify_function", address="0x140001000")
    assert function["ok"] is True
    assert function["addr"] == "0x140001000"
    assert function["name"] == "handler"
    assert intelligence_mod.intelligence(action="classify_function")["error"] is True


def test_intelligence_indexing_retrieval_and_export(intelligence_env, monkeypatch):
    indexed = intelligence_mod.intelligence(action="index_function", addr="0x140001000")
    assert indexed["ok"] is True
    assert indexed["index"]["size"] == 2
    assert FakeIndex.created[-1].indexed[0][0] == "0x140001000"

    fast = intelligence_mod.intelligence(
        action="index_fast",
        start="0x140001000",
        end="0x140001030",
        index_limit=1,
        mode="fast",
    )
    assert fast["ok"] is True
    assert fast["mode"] == "fast"
    assert fast["quality"] == "fast"
    assert fast["indexed"] == 1
    assert fast["complete"] is False
    assert fast["remaining"] == 1
    assert fast["next_cursor"] == "0x140001000"

    paged = intelligence_mod.intelligence(
        action="index_range",
        ranges=[{"start": "0x140001000", "end": "0x140001030"}],
        index_limit=1,
        cursor="0x140000000",
        mode="fast",
    )
    assert paged["ok"] is True
    assert paged["ranges_specified"] == 1
    assert paged["index"]["quality_counts"] == {"full": 1, "fast": 1}
    assert intelligence_mod.intelligence(action="index_fast", cursor="not-an-address")["error"] is True

    similar = intelligence_mod.intelligence(
        action="similar_functions", addr="0x140001000", top_k=3, threshold=0.7
    )
    assert similar["ok"] is True
    assert similar["similar"][0]["ea"] == "0x140001100"

    semantic = intelligence_mod.intelligence(action="semantic_search", query="packet parser", top_k=4)
    assert semantic["ok"] is True
    assert semantic["matches"][0]["query"] == "packet parser"
    assert intelligence_mod.intelligence(action="semantic_search")["error"] is True

    summary = intelligence_mod.intelligence(action="export_index_summary")
    assert summary["ok"] is True
    assert summary["index"]["metadata"]["count"] == 2

    blackboard_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.blackboard")
    monkeypatch.setattr(
        blackboard_mod,
        "blackboard",
        lambda **kwargs: {"ok": True, "behavior": kwargs["query"], "results": [], "count": 0},
    )
    board = intelligence_mod.intelligence(action="blackboard_search", query="socket recv")
    assert board["ok"] is True and board["blackboard"]["count"] == 0
    assert intelligence_mod.intelligence(action="blackboard_search")["error"] is True


def test_intelligence_missing_idb_and_unready_backend(monkeypatch):
    monkeypatch.setattr(services_mod, "BgeCodeEmbedder", FakeEmbedder)
    monkeypatch.setattr(services_mod, "BehaviorClassifier", FakeClassifier)
    monkeypatch.setattr(services_mod, "FunctionEmbeddingIndex", FakeIndex)
    monkeypatch.setattr(intelligence_mod.idaapi, "PATH_TYPE_IDB", 1, raising=False)
    monkeypatch.setattr(intelligence_mod.idaapi, "get_path", lambda _path_type: "", raising=False)
    missing_idb = intelligence_mod.intelligence(action="export_index_summary")
    assert missing_idb.get("error")

    class Unready(FakeEmbedder):
        def ensure_ready(self):
            return False

    monkeypatch.setattr(services_mod, "BgeCodeEmbedder", Unready)
    unready = intelligence_mod.intelligence(action="semantic_search", query="anything")
    assert unready.get("error") is True


def test_intelligence_signature_document_and_metadata_modes(monkeypatch, intelligence_env):
    func = SimpleNamespace(start_ea=0x140001000, end_ea=0x140001030, flags=0)
    monkeypatch.setattr(intelligence_mod.ida_funcs, "get_func_name", lambda _ea: "sub_140001000")
    monkeypatch.setattr(intelligence_mod.idautils, "Heads", lambda *_args: [0x140001000, 0x140001004])
    monkeypatch.setattr(intelligence_mod.idautils, "CodeRefsFrom", lambda *_args: [0x140002000])
    monkeypatch.setattr(intelligence_mod.idautils, "DataRefsFrom", lambda *_args: [0x140003000])
    monkeypatch.setattr(intelligence_mod.idc, "get_name", lambda _ea: "recv")
    monkeypatch.setattr(
        intelligence_mod.idc,
        "get_strlit_contents",
        lambda *_args: b"packet marker\x00",
    )
    monkeypatch.setattr(intelligence_mod.idc, "generate_disasm_line", lambda ea, _flags: f"mov r{ea & 3}, r0")
    monkeypatch.setattr(intelligence_mod.idc, "print_insn_mnem", lambda ea: "mov" if ea == 0x140001000 else "ret")
    monkeypatch.setattr(
        intelligence_mod,
        "_build_function_structure_summary",
        lambda *_args, **_kwargs: {"evidence": "cfg: blocks=2 edges=1"},
    )
    signature = intelligence_mod._build_fast_signature(0x140001000, func)
    assert "apis:recv" in signature
    assert "strings:packet marker" in signature
    assert "opcodes:" in signature and "insns:" in signature
    assert "cfg: blocks=2" in signature
    monkeypatch.setattr(intelligence_mod, "_build_fast_signature", lambda *_args: signature)

    monkeypatch.setattr(
        intelligence_mod,
        "_build_decomp_document",
        lambda *_args, **_kwargs: "x" * 240,
    )
    document = intelligence_mod._build_full_index_document(
        0x140001000,
        "sub_140001000",
        "pseudocode " * 300,
        func,
        FakeEmbedder(),
    )
    assert len(document) <= 256
    assert "ida_refs:" in document

    class Block:
        start_ea = 0x140001000

        def succs(self):
            return [SimpleNamespace(start_ea=0x140000ff0)]

    monkeypatch.setattr(intelligence_mod._compat, "get_flow_chart", lambda _ea: [Block()])
    monkeypatch.setattr(intelligence_mod.idc, "get_name", lambda _ea: "recv")
    metadata = intelligence_mod._function_index_metadata(func)
    assert metadata["api_count"] == 2
    assert metadata["string_count"] == 2
    assert metadata["has_loops"] == 1
    assert metadata["cyclomatic"] == 2


def test_intelligence_batch_fallback_retry_and_filters(monkeypatch, intelligence_env):
    # index_batch falls back to a fast document when Hex-Rays cannot produce
    # pseudocode, while range/name/size filters still determine eligibility.
    monkeypatch.setattr(intelligence_mod, "_safe_decompile", lambda _ea: None)
    monkeypatch.setattr(intelligence_mod, "_build_fast_signature", lambda *_args: "fallback signature")
    result = intelligence_mod.intelligence(
        action="index_batch",
        ranges=[{"start": "0x140001000", "end": "0x140001030"}],
        query="handler",
        min_size=16,
        max_size=64,
        limit=2,
    )
    assert result["ok"] is True
    assert result["decompile_failed"] == 2
    assert result["quality"] == "full"
    assert result["index"]["quality_counts"] == {"full": 1, "fast": 1}

    class RetryIndex(FakeIndex):
        def index_many(self, rows):
            self.indexed.extend(rows[:1])
            return {"indexed": 0, "failed": 1, "resume_after_ea": rows[0][0]}

    monkeypatch.setattr(services_mod, "FunctionEmbeddingIndex", RetryIndex)
    retry = intelligence_mod.intelligence(action="index_fast", limit=1)
    assert retry["ok"] is True
    assert retry["retry_required"] is True
    assert retry["next_cursor"] == "0x140001000"


def test_intelligence_empty_index_and_family_scope_modes(monkeypatch, intelligence_env):
    class EmptyIndex(FakeIndex):
        def __init__(self, db_path, embedder):
            super().__init__(db_path, embedder)
            self.size = 0

    monkeypatch.setattr(services_mod, "FunctionEmbeddingIndex", EmptyIndex)
    assert intelligence_mod.intelligence(action="similar_functions", address="0x140001000")["error"] is True
    assert intelligence_mod.intelligence(action="semantic_search", query="x")["error"] is True
    assert intelligence_mod.intelligence(action="function_families")["error"] is True

    class FamilyIndex(FakeIndex):
        pass

    monkeypatch.setattr(services_mod, "FunctionEmbeddingIndex", FamilyIndex)
    families_mod = importlib.import_module("ida_pro_mcp.host.intelligence.families")
    monkeypatch.setattr(
        families_mod,
        "compute_function_families",
        lambda *args, **kwargs: {"families": [], "examined": kwargs.get("name_filter")},
    )
    scoped = intelligence_mod.intelligence(
        action="function_families",
        start="0x140001000",
        end="0x140002000",
        name_filter="handler",
        min_size=4,
        min_similarity=0.9,
        limit=3,
    )
    assert scoped["ok"] is True
    assert scoped["examined"] == "handler"

    radius = intelligence_mod.intelligence(
        action="function_families",
        address="0x140001000",
        radius=0x200,
    )
    assert radius["ok"] is True


def test_intelligence_index_and_classification_failure_modes(monkeypatch, intelligence_env):
    monkeypatch.setattr(intelligence_mod, "_safe_decompile", lambda _ea: None)
    assert intelligence_mod.intelligence(action="classify_function", address="0x140001000")["error"] is True
    assert intelligence_mod.intelligence(action="index_function", address="0x140001000")["error"] is True
    assert intelligence_mod.intelligence(action="similar_functions", address="0x140001000")["error"] is True

    monkeypatch.setattr(intelligence_mod, "_safe_decompile", lambda _ea: "int handler(void) { return 1; }")

    class RejectIndex(FakeIndex):
        def index(self, *_args, **_kwargs):
            return False

    monkeypatch.setattr(services_mod, "FunctionEmbeddingIndex", RejectIndex)
    rejected = intelligence_mod.intelligence(action="index_function", address="0x140001000")
    assert rejected["error"] is True
    assert "not indexed" in rejected["message"]

    monkeypatch.setattr(intelligence_mod, "_build_fast_signature", lambda *_args: "")
    empty_batch = intelligence_mod.intelligence(action="index_fast", limit=1)
    assert empty_batch["error"] is True
    assert empty_batch["details"]["failed"] >= 1


def test_intelligence_range_filters_cpu_fallback_and_retry_cursor(monkeypatch, intelligence_env):
    import os

    monkeypatch.setattr(os, "sched_getaffinity", lambda _pid: (_ for _ in ()).throw(OSError("no affinity")))
    monkeypatch.setattr(os, "cpu_count", lambda: 2)
    monkeypatch.setenv("IDA_MCP_FULL_INDEX_PASS_SIZE", "not-an-int")
    monkeypatch.setenv("IDA_MCP_INDEX_COMMIT_BATCH", "not-an-int")
    full = intelligence_mod.intelligence(action="index_range", mode="full")
    assert full["ok"] is True
    assert full["mode"] == "decompile"
    assert full["pass_limit"] == 8

    # Invalid range entries are ignored, while invalid numeric filters fall
    # back to no filter and still use the same range/index pipeline.
    filtered = intelligence_mod.intelligence(
        action="index_fast",
        ranges=[{"start": "bad", "end": "0x2"}, None, {"start": "0x140001000", "end": "0x140001001"}],
        min_size="bad",
        max_size="bad",
        limit=1,
        mode="fast",
    )
    assert filtered["ok"] is True
    assert filtered["ranges_specified"] == 1

    class NoCursorRetry(FakeIndex):
        def index_many(self, rows):
            self.indexed.extend(rows)
            return {"indexed": 0, "failed": 1}

    monkeypatch.setattr(services_mod, "FunctionEmbeddingIndex", NoCursorRetry)
    retry = intelligence_mod.intelligence(action="index_fast", limit=1, start_after="0x140000000")
    assert retry["ok"] is True
    assert retry["retry_required"] is True
    assert retry["next_cursor"] == "0x140000000"


def test_intelligence_search_and_family_exception_shapes(monkeypatch, intelligence_env):
    import importlib

    monkeypatch.setattr(intelligence_mod, "_safe_decompile", lambda _ea: "int handler(void) { return 1; }")

    class MetadataFailure(FakeIndex):
        def metadata(self):
            raise RuntimeError("metadata unavailable")

    monkeypatch.setattr(services_mod, "FunctionEmbeddingIndex", MetadataFailure)
    summary = intelligence_mod.intelligence(action="export_index_summary")
    assert summary["ok"] is True
    assert summary["index"]["metadata"] == {}

    blackboard_mod = importlib.import_module("ida_pro_mcp.ida_mcp.tools.blackboard")
    monkeypatch.setattr(blackboard_mod, "blackboard", lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("db down")))
    board = intelligence_mod.intelligence(action="blackboard_search", query="socket")
    assert board["error"] is True
    assert "db down" in board["message"]

    # Avoid importing numpy a second time in the per-test isolated-module
    # harness; intelligence only needs the family callable for this branch.
    families_mod = types.ModuleType("ida_pro_mcp.host.intelligence.families")
    families_mod.compute_function_families = lambda **_kwargs: {"families": []}
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.host.intelligence.families", families_mod)
    invalid_scope = intelligence_mod.intelligence(
        action="function_families",
        start="bad",
        end="0x140001000",
    )
    assert invalid_scope["error"] is True
