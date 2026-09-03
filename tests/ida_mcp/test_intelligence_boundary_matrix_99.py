"""Cross-mode coverage for the intelligence tool lifecycle."""

from __future__ import annotations

import builtins
import sys
import types

import pytest

from tests._isolated_repo_loader import install_common_stub, load_tool_module

install_common_stub()
_INTELLIGENCE = load_tool_module("intelligence")
_ORIGINAL_FAST_SIGNATURE = _INTELLIGENCE._build_fast_signature
_ORIGINAL_FULL_DOCUMENT = _INTELLIGENCE._build_full_index_document
_ORIGINAL_SAFE_DECOMPILE = _INTELLIGENCE._safe_decompile
_ORIGINAL_FAST_SIGNATURE = _INTELLIGENCE._build_fast_signature
_ORIGINAL_SAFE_DECOMPILE = _INTELLIGENCE._safe_decompile


class _Func:
    def __init__(self, start, end, flags=0):
        self.start_ea = start
        self.end_ea = end
        self.flags = flags


class _Embedder:
    backend = "fake-embedder"

    def __init__(self, ready=True):
        self.ready = ready
        self.decomp_document_chars = 100

    def ensure_ready(self):
        return self.ready

    def status(self, **kwargs):
        return {"backend": self.backend, "ready": self.ready, **kwargs}


class _Classifier:
    ANCHORS = {"network_http": "socket(); send();"}
    _anchor_embs = {"network_http": [1.0]}
    last = None

    @classmethod
    def instance(cls, _embedder):
        cls.last = cls()
        return cls.last

    def classify(self, text, **kwargs):
        if not text:
            return []
        return [{"behavior": "network_http", "confidence": 0.9, "text": text, **kwargs}]

    def refresh_anchors(self, behaviors):
        self.refreshed = behaviors


class _Index:
    def __init__(self, path, _embedder, *, size=1):
        self.path = path
        self.size = size
        self.indexed = []
        self.async_indexed = []
        self.search_calls = []
        self.batch_result = {"indexed": 1, "failed": 0}

    def index(self, *args):
        self.indexed.append(args)
        return True

    def index_async(self, *args):
        self.async_indexed.append(args)

    def index_many(self, pending):
        self.indexed.extend(pending)
        self.size += int(self.batch_result.get("indexed", 0))
        return self.batch_result

    def quality_counts(self):
        return {"full": self.size, "fast": 0, "fast_fallback": 0}

    def similar(self, *args, **kwargs):
        return [{"ea": "0x2000", "score": 0.8}]

    def search(self, query, **kwargs):
        self.search_calls.append((query, kwargs))
        return [{"ea": "0x2000", "score": 0.8}]

    def metadata(self):
        return {"path": self.path, "size": self.size}


class _Reranker:
    def status(self, **kwargs):
        return {"backend": "fake", "ready": True, **kwargs}


@pytest.fixture
def intel_env(monkeypatch):
    import ida_pro_mcp.host.intelligence.rerank as rerank
    import ida_pro_mcp.services as services

    common = install_common_stub()
    common.validate_range = lambda *_args, **_kwargs: (0x1000, 0x2000, None)
    mod = _INTELLIGENCE
    monkeypatch.setattr(services, "BgeCodeEmbedder", _Embedder)
    monkeypatch.setattr(services, "BehaviorClassifier", _Classifier)
    indexes = []

    def make_index(path, embedder):
        idx = _Index(path, embedder)
        indexes.append(idx)
        return idx

    monkeypatch.setattr(services, "FunctionEmbeddingIndex", make_index)
    monkeypatch.setattr(rerank, "Reranker", _Reranker)
    monkeypatch.setattr(mod.idaapi, "PATH_TYPE_IDB", 1, raising=False)
    monkeypatch.setattr(mod.idaapi, "get_path", lambda _kind: "/tmp/fake.idb", raising=False)
    monkeypatch.setattr(mod.ida_funcs, "get_func_name", lambda ea: f"sub_{ea:x}", raising=False)
    monkeypatch.setattr(
        mod,
        "_compat",
        types.SimpleNamespace(
            get_func_info=lambda ea: _Func(ea, ea + 0x20),
            get_func_flags=lambda _ea: 0,
            get_segment_name=lambda _ea: ".text",
            get_flow_chart=lambda _ea: [],
        ),
    )
    monkeypatch.setattr(mod, "_function_index_metadata", lambda _func: {"func_size": 32})
    monkeypatch.setattr(
        mod,
        "_build_full_index_document",
        lambda ea, name, pseudo, *_args: f"full:{ea:x}:{name}:{pseudo}",
    )
    monkeypatch.setattr(mod, "_build_fast_signature", lambda ea, _func=None: f"fast:{ea:x}")
    monkeypatch.setattr(mod, "_invalidate_tool_cache", lambda: None)
    monkeypatch.setattr(mod, "_safe_decompile", lambda _ea: "pseudo code")
    monkeypatch.setattr(
        mod.idautils,
        "Functions",
        lambda: [0x1000, 0x2000, 0x3000],
        raising=False,
    )
    return mod, indexes, services


def test_intelligence_status_anchor_and_refresh_actions(intel_env):
    mod, _indexes, _services = intel_env
    status = mod.intelligence(action="intelligence_status", probe=True, deep_hash=True)
    assert status["ok"] is True
    assert status["anchors"]["count"] == 1
    assert status["indexes"]["functions_indexed"] == 1
    assert mod.intelligence(action="embedder_status")["ok"] is True
    assert mod.intelligence(action="reranker_status")["reranker"]["ready"] is True

    anchor = mod.intelligence(action="anchor_status")
    assert anchor["count"] == 1
    refreshed = mod.intelligence(action="refresh_anchors", query="network_http, file_io")
    assert refreshed["refreshed"] == ["network_http", "file_io"]


def test_intelligence_classification_actions_cover_validation_and_decompile_modes(
    intel_env,
    monkeypatch,
):
    mod, _indexes, _services = intel_env
    assert mod.intelligence(action="classify_text")["code"] == "INVALID_ARGS"
    text = mod.intelligence(
        action="classify_text",
        query="send bytes",
        threshold=0.4,
        top_k=2,
        block=True,
    )
    assert text["behaviors"][0]["behavior"] == "network_http"

    assert mod.intelligence(action="classify_function")["code"] == "INVALID_ARGS"
    monkeypatch.setattr(mod, "validate_addr", lambda *_args, **_kwargs: (None, {"code": "bad"}))
    assert mod.intelligence(action="classify_function", addr="bad")["code"] == "bad"
    monkeypatch.setattr(mod, "validate_addr", lambda *_args, **_kwargs: (0x1000, None))
    monkeypatch.setattr(mod, "_safe_decompile", lambda _ea: None)
    assert mod.intelligence(action="classify_function", addr="0x1000")["code"] == "IDA_ERROR"
    monkeypatch.setattr(mod, "_safe_decompile", lambda _ea: "pseudo")
    result = mod.intelligence(action="classify_function", address="0x1000")
    assert result["addr"] == "0x1000"


def test_intelligence_index_function_handles_backend_failures_and_success(
    intel_env,
    monkeypatch,
):
    mod, indexes, _services = intel_env
    assert mod.intelligence(action="index_function")["code"] == "INVALID_ARGS"
    monkeypatch.setattr(mod, "validate_addr", lambda *_args, **_kwargs: (0x1000, None))
    monkeypatch.setattr(mod, "_safe_decompile", lambda _ea: None)
    assert mod.intelligence(action="index_function", addr="0x1000")["code"] == "IDA_ERROR"

    monkeypatch.setattr(mod, "_safe_decompile", lambda _ea: "pseudo")
    indexes.clear()
    response = mod.intelligence(action="index_function", addr="0x1000")
    assert response["ok"] is True
    assert indexes[-1].indexed

    failed_index = indexes[-1]
    failed_index.index = lambda *_args: False
    monkeypatch.setattr(_services, "FunctionEmbeddingIndex", lambda *_args: failed_index)
    failed = mod.intelligence(action="index_function", addr="0x1000")
    assert failed["code"] == "IDA_ERROR", failed


def test_intelligence_index_ranges_filters_and_cursor_errors(intel_env, monkeypatch):
    mod, indexes, _services = intel_env
    monkeypatch.setattr(
        mod,
        "_compat",
        types.SimpleNamespace(get_func_info=lambda ea: _Func(ea, ea + 0x20)),
    )
    monkeypatch.setattr(mod, "_function_index_metadata", lambda _func: {})
    monkeypatch.setattr(mod, "_build_fast_signature", lambda ea, _func=None: f"fast:{ea:x}")

    bad_cursor = mod.intelligence(action="index_fast", cursor="not-an-ea")
    assert bad_cursor["code"] == "INVALID_ARGS"
    response = mod.intelligence(
        action="index_range",
        start="0x1000",
        end="0x3000",
        min_size=32,
        max_size=32,
        index_limit=1,
    )
    assert response["ok"] is True, response
    assert response["mode"] == "fast"
    assert response["pass_limit"] == 1
    assert response["ranges_specified"] == 1
    assert response["remaining"] >= 0
    assert indexes


def test_intelligence_full_index_uses_decompile_fallback_and_retry_cursor(
    intel_env,
    monkeypatch,
):
    mod, indexes, _services = intel_env
    monkeypatch.setattr(
        mod,
        "_compat",
        types.SimpleNamespace(get_func_info=lambda ea: _Func(ea, ea + 0x20)),
    )
    monkeypatch.setattr(mod, "_function_index_metadata", lambda _func: {})
    monkeypatch.setattr(mod, "_build_fast_signature", lambda ea, _func=None: f"fast:{ea:x}")
    sequence = iter(["pseudo", None, "pseudo"])
    monkeypatch.setattr(mod, "_safe_decompile", lambda _ea: next(sequence))
    response = mod.intelligence(action="index_batch", mode="full", limit=2)
    assert response["ok"] is True, response
    assert response["decompile_failed"] == 1
    assert response["quality"] == "full"

    failed_index = indexes[-1]
    failed_index.batch_result = {"indexed": 0, "failed": 1, "resume_after_ea": "0x1000"}
    monkeypatch.setattr(_services, "FunctionEmbeddingIndex", lambda *_args: failed_index)
    retry = mod.intelligence(action="index_fast", index_limit=1)
    assert retry["ok"] is True, retry
    assert retry["retry_required"] is True
    assert retry["next_cursor"] == "0x1000"


def test_intelligence_embedding_unavailable_and_unknown_action(intel_env, monkeypatch):
    mod, _indexes, services = intel_env
    monkeypatch.setattr(services, "BgeCodeEmbedder", lambda: _Embedder(ready=False))
    unavailable = mod.intelligence(action="semantic_search", query="network")
    assert unavailable["code"] == "IDA_ERROR"
    unknown = mod.intelligence(action="not_real")
    assert unknown["code"] == "INVALID_ARGS"


def test_intelligence_similarity_semantic_blackboard_and_export_modes(intel_env):
    mod, indexes, _services = intel_env
    assert mod.intelligence(action="similar_functions")["code"] == "INVALID_ARGS"
    similar = mod.intelligence(action="similar_functions", addr="0x1000")
    assert similar["ok"] is True
    assert similar["similar"]

    semantic = mod.intelligence(action="semantic_search", query="network", top_k=2)
    assert semantic["matches"]
    assert indexes[-1].search_calls
    assert mod.intelligence(action="semantic_search")["code"] == "INVALID_ARGS"

    export = mod.intelligence(action="export_index_summary")
    assert export["index"]["metadata"]["size"] >= 1

    blackboard = types.ModuleType("ida_pro_mcp.ida_mcp.tools.blackboard")
    blackboard.blackboard = lambda **_kwargs: {"ok": True, "items": []}
    sys.modules[blackboard.__name__] = blackboard
    bb = mod.intelligence(action="blackboard_search", query="network")
    assert bb["ok"] is True
    assert mod.intelligence(action="blackboard_search")["code"] == "INVALID_ARGS"


def test_intelligence_function_families_ranges_and_mark_errors(intel_env, monkeypatch):
    mod, _indexes, _services = intel_env
    families = types.ModuleType("ida_pro_mcp.host.intelligence.families")
    families.compute_function_families = lambda *_args, **kwargs: {
        "families": [{"summary": "group", "members": [{"ea": 0x1000, "name": "f"}]}],
        "ranges": kwargs.get("address_ranges"),
    }
    sys.modules[families.__name__] = families
    result = mod.intelligence(
        action="function_families",
        start="0x1000",
        end="0x2000",
    )
    assert result["ok"] is True, result
    assert result["ranges"] == [(0x1000, 0x2000)]

    class BrokenStore:
        def __init__(self):
            raise RuntimeError("store unavailable")

    blackboard = types.ModuleType("ida_pro_mcp.ida_mcp.tools.blackboard")
    blackboard.BlackboardStore = BrokenStore
    sys.modules[blackboard.__name__] = blackboard
    broken = mod.intelligence(action="function_families", mark_examined=True)
    assert "mark_examined_error" in broken


def test_intelligence_helper_signatures_and_tinfo_guards(intel_env, monkeypatch):
    mod, _indexes, _services = intel_env
    monkeypatch.setattr(mod, "_build_fast_signature", _ORIGINAL_FAST_SIGNATURE)
    monkeypatch.setattr(mod, "_build_full_index_document", _ORIGINAL_FULL_DOCUMENT)
    monkeypatch.setattr(mod, "_safe_decompile", _ORIGINAL_SAFE_DECOMPILE)
    func = _Func(0x1000, 0x1100)
    mod.idautils.Heads = lambda *_args: [0x1000]
    mod.idautils.CodeRefsFrom = lambda *_args: [0x2000]
    mod.idautils.DataRefsFrom = lambda *_args: [0x3000]
    mod.idc.get_name = lambda _ea: "api"
    mod.idc.get_strlit_contents = lambda *_args: b"text"
    mod.idc.generate_disasm_line = lambda *_args: "mov eax, ebx"
    mod.idc.print_insn_mnem = lambda _ea: "mov"
    assert "apis:api" in mod._build_fast_signature(0x1000, func)
    assert "strings:text" in mod._build_fast_signature(0x1000, func)

    monkeypatch.setattr(mod, "_compat", types.SimpleNamespace(get_func_info=lambda _ea: None))
    assert mod._build_fast_signature(0x1000) == "sub_1000"
    monkeypatch.setattr(mod.ida_hexrays, "init_hexrays_plugin", lambda: False, raising=False)
    with pytest.raises(RuntimeError):
        mod._safe_decompile(0x1000)


def test_intelligence_helpers_build_fast_and_full_documents_across_sparse_shapes(
    intel_env,
    monkeypatch,
):
    mod, _indexes, _services = intel_env
    monkeypatch.setattr(mod, "_build_fast_signature", _ORIGINAL_FAST_SIGNATURE)
    monkeypatch.setattr(mod, "_build_full_index_document", _ORIGINAL_FULL_DOCUMENT)
    func = _Func(0x1000, 0x2000)
    mod.idautils.Heads = lambda *_args: list(range(0x1000, 0x1020, 4))
    mod.idautils.CodeRefsFrom = lambda ea, _flow: [ea, ea + 1] if ea == 0x1000 else []
    mod.idautils.DataRefsFrom = lambda ea: [ea + 0x100] if ea == 0x1000 else []
    mod.idc.get_name = lambda ea: "" if ea == 0x1000 else f"api_{ea:x}"
    mod.idc.get_strlit_contents = lambda ea, *_args: b"" if ea != 0x1100 else b"banner"
    mod.idc.generate_disasm_line = lambda ea, _flags: "" if ea == 0x1004 else "<mov eax, ebx>"
    mod.idc.print_insn_mnem = lambda ea: "" if ea == 0x1004 else "mov"
    signature = mod._build_fast_signature(0x1000, func)
    assert signature.startswith("sub_1000")
    assert "apis:api_1001" in signature
    assert "strings:banner" in signature
    assert "opcodes:movx" in signature
    assert "insns:" in signature

    structure = {"evidence": "cfg evidence"}
    monkeypatch.setattr(mod, "_build_function_structure_summary", lambda *_args, **_kwargs: structure)
    monkeypatch.setattr(mod, "_build_decomp_document", lambda *_args, **_kwargs: "document")
    embedder = _Embedder()
    embedder.decomp_document_chars = 32
    assert "ida_structure: cfg evidence" in mod._build_full_index_document(
        0x1000, "f", "short", func, embedder
    )

    monkeypatch.setattr(
        mod,
        "_build_function_structure_summary",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("cfg")),
    )
    assert mod._build_full_index_document(0x1000, "f", "short", func, embedder) == "document"
    monkeypatch.setattr(
        mod,
        "_build_fast_signature",
        lambda *_args, **_kwargs: "f | apis:NovelApi | strings:NovelString",
    )
    embedder.decomp_document_chars = 100
    long_doc = mod._build_full_index_document(0x1000, "f", "x" * 200, func, embedder)
    assert "ida_refs:" in long_doc


def test_intelligence_metadata_and_cache_helpers_cover_missing_refs(monkeypatch):
    mod = _INTELLIGENCE
    func = _Func(0x1000, 0x1100)
    mod.idautils.Heads = lambda *_args: [0x1000]
    mod.idautils.CodeRefsFrom = lambda *_args: []
    mod.idautils.DataRefsFrom = lambda *_args: []
    mod.idc.get_name = lambda _ea: ""
    mod.idc.get_strlit_contents = lambda *_args: None
    monkeypatch.setattr(mod.idaapi, "FUNC_THUNK", 0, raising=False)
    monkeypatch.setattr(
        mod,
        "_compat",
        types.SimpleNamespace(
            get_flow_chart=lambda _ea: [],
            get_segment_name=lambda _ea: None,
            get_func_flags=lambda _ea: 0,
        ),
    )
    assert mod._function_index_metadata(func)["cyclomatic"] == 0

    monkeypatch.setattr(mod.ida_hexrays, "init_hexrays_plugin", lambda: True, raising=False)
    monkeypatch.setattr(
        mod.ida_hexrays,
        "decompile",
        lambda ea, **_kwargs: f"cfunc-{ea:x}",
        raising=False,
    )
    assert mod._safe_decompile(0x1000) == "cfunc-1000"
    monkeypatch.setattr(mod, "_invalidate_tool_cache", lambda: None)
    mod._invalidate_tool_cache()


def test_intelligence_index_filters_malformed_ranges_and_names(intel_env, monkeypatch):
    mod, indexes, _services = intel_env
    common = sys.modules["ida_pro_mcp.ida_mcp.tools._common"]
    common.validate_range = lambda *_args, **_kwargs: (0x1000, 0x3000, None)
    monkeypatch.setattr(
        mod,
        "_compat",
        types.SimpleNamespace(
            get_func_info=lambda ea: None if ea == 0x3000 else _Func(ea, ea + 0x20)
        ),
    )
    monkeypatch.setattr(
        mod.ida_funcs,
        "get_func_name",
        lambda ea: "wanted" if ea == 0x1000 else "other",
    )
    monkeypatch.setattr(mod, "_function_index_metadata", lambda _func: {})
    monkeypatch.setattr(mod, "_build_fast_signature", lambda ea, _func=None: f"fast:{ea:x}")
    response = mod.intelligence(
        action="index_fast",
        ranges=[
            {"start": "0x1000", "end": "0x2000"},
            {"start": "bad", "end": "0x10"},
            "not-a-range",
        ],
        query="wanted",
        min_size="bad",
        max_size="bad",
        limit="bad",
    )
    assert response["ok"] is True, response
    assert response["failed"] >= 1
    assert response["skipped"] >= 1
    assert response["eligible"] == 1
    assert indexes


def test_intelligence_index_empty_pending_and_batch_retry_without_resume(intel_env, monkeypatch):
    mod, indexes, services = intel_env
    monkeypatch.setattr(
        mod,
        "_compat",
        types.SimpleNamespace(get_func_info=lambda _ea: None),
    )
    no_pending = mod.intelligence(action="index_fast")
    assert no_pending["code"] == "IDA_ERROR"

    monkeypatch.setattr(
        mod,
        "_compat",
        types.SimpleNamespace(get_func_info=lambda ea: _Func(ea, ea + 0x20)),
    )
    monkeypatch.setattr(mod, "_function_index_metadata", lambda _func: {})
    monkeypatch.setattr(mod, "_build_fast_signature", lambda ea, _func=None: f"fast:{ea:x}")
    failed_index = _Index("/tmp/fake", _Embedder())
    failed_index.batch_result = {"indexed": 0, "failed": 1}
    monkeypatch.setattr(services, "FunctionEmbeddingIndex", lambda *_args: failed_index)
    retry = mod.intelligence(action="index_fast", index_limit=1)
    assert retry["ok"] is True
    assert retry["retry_required"] is True
    assert retry["next_cursor"] is None
    assert indexes


def test_intelligence_optional_imports_and_family_scope_fallbacks(intel_env, monkeypatch):
    mod, _indexes, services = intel_env
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "ida_pro_mcp.services":
            raise ImportError("service package unavailable")
        if name == "host.intelligence.core":
            raise ImportError("legacy service package unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked)
    unavailable = mod.intelligence(action="anchor_status")
    assert unavailable["code"] == "IDA_ERROR"
    monkeypatch.setattr(builtins, "__import__", real_import)

    monkeypatch.setattr(
        services,
        "FunctionEmbeddingIndex",
        lambda *_args: _Index("/tmp/fake", _Embedder()),
    )
    families = types.ModuleType("ida_pro_mcp.host.intelligence.families")
    families.compute_function_families = lambda *_args, **_kwargs: {"families": []}
    sys.modules[families.__name__] = families
    monkeypatch.setattr(mod, "validate_addr", lambda *_args, **_kwargs: (None, {"code": "bad"}))
    result = mod.intelligence(
        action="function_families",
        addr="0x1000",
        radius="bad",
        start="bad",
        end="bad",
    )
    assert result["ok"] is True
