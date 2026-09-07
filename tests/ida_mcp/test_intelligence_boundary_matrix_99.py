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
_ORIGINAL_FUNCTION_INDEX_METADATA = _INTELLIGENCE._function_index_metadata
_ORIGINAL_INVALIDATE_TOOL_CACHE = _INTELLIGENCE._invalidate_tool_cache


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


def test_intelligence_safe_decompile(monkeypatch):
    import ida_hexrays

    monkeypatch.setattr(ida_hexrays, "init_hexrays_plugin", lambda: False, raising=False)
    with pytest.raises(RuntimeError, match="hexrays decompiler is not available"):
        _ORIGINAL_SAFE_DECOMPILE(0x1000)

    monkeypatch.setattr(ida_hexrays, "init_hexrays_plugin", lambda: True, raising=False)
    monkeypatch.setattr(ida_hexrays, "decompile", lambda ea: "decompiled", raising=False)
    assert _ORIGINAL_SAFE_DECOMPILE(0x1000) == "decompiled"


def test_intelligence_build_signature_and_document_branches(intel_env, monkeypatch):
    mod, _indexes, _services = intel_env

    # 1. Test _build_fast_signature with > 12 APIs, decode error, > 4 string refs, > 12 insns, _pn is None, structure exception
    func = _Func(0x1000, 0x1200)
    heads = [0x1000 + i * 4 for i in range(25)]
    monkeypatch.setattr(mod.idautils, "Heads", lambda _s, _e: heads, raising=False)
    # 15 APIs to trigger len(apis) > 12: break (line 85)
    monkeypatch.setattr(
        mod.idautils,
        "CodeRefsFrom",
        lambda ea, _fl: [0x5000 + (ea - 0x1000)],
        raising=False,
    )
    monkeypatch.setattr(
        mod.idc,
        "get_name",
        lambda ref: f"api_{ref:x}",
        raising=False,
    )

    # String refs: mock with decode exception (lines 97-98) and > 4 string refs (line 100)
    class BadDecodeBytes:
        def decode(self, *args, **kwargs):
            raise RuntimeError("corrupted string literal")

    str_objs = [BadDecodeBytes(), b"hello_1", b"hello_2", b"hello_3", b"hello_4", b"hello_5", b"hello_6"]
    str_idx = {"i": 0}

    def get_str(ref, *_args):
        idx = str_idx["i"]
        str_idx["i"] += 1
        return str_objs[idx % len(str_objs)]

    monkeypatch.setattr(mod.idautils, "DataRefsFrom", lambda ea: [0x6000 + (ea - 0x1000)], raising=False)
    monkeypatch.setattr(mod.idc, "get_strlit_contents", get_str, raising=False)
    monkeypatch.setattr(mod.idc, "generate_disasm_line", lambda _ea, _fl: "mov eax, 1", raising=False)
    monkeypatch.setattr(mod.idc, "tag_remove", lambda s: s, raising=False)
    # _pn is None branch (lines 128-129)
    monkeypatch.setattr(mod.idc, "print_insn_mnem", None, raising=False)
    # Structure summary exception (lines 149-150)
    monkeypatch.setattr(
        mod,
        "_build_function_structure_summary",
        lambda _func, **_kw: (_ for _ in ()).throw(RuntimeError("structure summary fail")),
    )

    sig = _ORIGINAL_FAST_SIGNATURE(0x1000, func)
    assert "apis:" in sig
    assert "strings:" in sig
    assert "code:" in sig
    assert "opcodes:" in sig

    # Also test non-auto-named func without func passed in
    monkeypatch.setattr(mod.ida_funcs, "get_func_name", lambda _ea: "my_named_func", raising=False)
    sig2 = _ORIGINAL_FAST_SIGNATURE(0x1000)
    assert "my_named_func" in sig2

    # 2. Test _build_full_index_document branches:
    # line 186: low in document_lower continue
    # line 194: if not appendages: return document
    # line 197: if len(suffix) >= max_chars: return suffix[-max_chars:]
    embedder = _Embedder()
    embedder.decomp_document_chars = 40

    monkeypatch.setattr(mod, "_build_function_structure_summary", lambda *a, **k: {})

    # Fast signature that yields novel values already present in document
    monkeypatch.setattr(
        mod,
        "_build_fast_signature",
        lambda _ea, _func=None: "my_func | apis:already_present | strings:known_str",
    )
    long_pseudo = "int my_func() {\n" + "    already_present();\n" * 5 + "    return known_str;\n}"
    doc_no_appendages = _ORIGINAL_FULL_DOCUMENT(0x1000, "my_func", long_pseudo, func, embedder)
    assert doc_no_appendages == mod._build_decomp_document("my_func", long_pseudo, max_chars=40)

    # Suffix exceeds max_chars (line 197)
    embedder_tiny = _Embedder()
    embedder_tiny.decomp_document_chars = 15
    monkeypatch.setattr(
        mod,
        "_build_fast_signature",
        lambda _ea, _func=None: "my_func | apis:super_long_novel_api_name_that_exceeds_budget",
    )
    doc_truncated = _ORIGINAL_FULL_DOCUMENT(0x1000, "my_func", "int f() {\n" + "    return 1;\n" * 5 + "}", func, embedder_tiny)
    assert len(doc_truncated) == 15


def test_intelligence_action_edge_branches(intel_env, monkeypatch):
    mod, _indexes, services = intel_env

    # Quality to mode mapping (line 322)
    res_qual = mod.intelligence(action="intelligence_status", quality="fast")
    assert res_qual["ok"] is True

    # intelligence_status Reranker exception (lines 397-398) & IDB path exception (lines 409-410)
    import ida_pro_mcp.host.intelligence.rerank as rerank

    class BrokenReranker:
        def status(self, **_kwargs):
            raise RuntimeError("reranker broken")

    monkeypatch.setattr(rerank, "Reranker", BrokenReranker)
    monkeypatch.setattr(mod.idaapi, "get_path", lambda _kind: "", raising=False)
    status_broken = mod.intelligence(action="intelligence_status")
    assert status_broken["ok"] is True
    assert status_broken["reranker"]["ready"] is False
    assert status_broken["indexes"]["functions_indexed"] == 0

    # classify_function decompile exception (lines 476-477)
    monkeypatch.setattr(mod, "_safe_decompile", lambda _ea: (_ for _ in ()).throw(RuntimeError("decompile fail")))
    err_cf = mod.intelligence(action="classify_function", addr="0x1000")
    assert err_cf["code"] == "IDA_ERROR"

    # index_function validate_addr error (line 497) & decompile error (lines 501-502)
    monkeypatch.setattr(mod, "validate_addr", lambda _a, **_k: (None, {"code": "INVALID_ADDR", "message": "bad"}))
    err_if1 = mod.intelligence(action="index_function", addr="invalid")
    assert err_if1["code"] == "INVALID_ADDR"

    monkeypatch.setattr(mod, "validate_addr", lambda _a, **_k: (0x1000, None))
    err_if2 = mod.intelligence(action="index_function", addr="0x1000")
    assert err_if2["code"] == "IDA_ERROR"

    # index_fast / index_range size and candidate filtering branches
    monkeypatch.setattr(mod.idaapi, "get_path", lambda _kind: "/tmp/fake.idb", raising=False)
    idx = _Index("/tmp/fake", _Embedder())
    monkeypatch.setattr(services, "FunctionEmbeddingIndex", lambda *_args: idx)

    # 1. invalid raw_start/raw_end (lines 576-577)
    r1 = mod.intelligence(action="index_range", start="bad_start", end="bad_end")
    assert r1["ok"] is True

    # 2. raw_start & invalid raw_radius (lines 591-592)
    r2 = mod.intelligence(action="index_range", start="0x1000", radius="invalid_radius")
    assert r2["ok"] is True

    # 3. raw_start & valid raw_radius (lines 579-590)
    r3 = mod.intelligence(action="index_range", start="0x1000", radius="0x100")
    assert r3["ok"] is True

    # 4. min_size and max_size filtering (lines 660-664)
    r_min = mod.intelligence(action="index_fast", min_size=100)
    assert r_min["code"] == "IDA_ERROR"
    assert r_min["details"]["skipped"] > 0

    r_max = mod.intelligence(action="index_fast", max_size=10)
    assert r_max["code"] == "IDA_ERROR"
    assert r_max["details"]["skipped"] > 0

    # 5. name_matcher skips (lines 668-669)
    r_name = mod.intelligence(action="index_fast", query="non_existent_*")
    assert r_name["code"] == "IDA_ERROR"
    assert r_name["details"]["skipped"] > 0

    # 6. candidate loop exception (lines 671-672)
    calls = {"cnt": 0}

    def flaky_name(ea):
        calls["cnt"] += 1
        if calls["cnt"] == 1:
            raise RuntimeError("flaky name fail")
        return f"sub_{ea:x}"

    monkeypatch.setattr(mod.ida_funcs, "get_func_name", flaky_name, raising=False)
    r_flaky = mod.intelligence(action="index_fast")
    assert r_flaky["ok"] is True
    assert r_flaky["failed"] >= 1

    # 7. use_decompile=True with _safe_decompile exception -> fast_fallback (lines 707-708)
    monkeypatch.setattr(mod.ida_funcs, "get_func_name", lambda ea: f"sub_{ea:x}", raising=False)
    monkeypatch.setattr(mod, "_safe_decompile", lambda _ea: (_ for _ in ()).throw(RuntimeError("hexrays fail")))
    r_decompile_fail = mod.intelligence(action="index_batch")
    assert r_decompile_fail["ok"] is True
    assert r_decompile_fail["indexed"] > 0

    # 8. batch document construction exception (lines 734-735)
    monkeypatch.setattr(
        mod,
        "_build_fast_signature",
        lambda _ea, _f=None: (_ for _ in ()).throw(RuntimeError("doc fail")),
    )
    r_doc_fail = mod.intelligence(action="index_fast")
    assert r_doc_fail["code"] == "IDA_ERROR"
    assert r_doc_fail["details"]["failed"] >= 1

    # 9. empty text from signature (lines 727-728) & empty pending (line 737)
    monkeypatch.setattr(mod, "_build_fast_signature", lambda _ea, _f=None: "")
    r_empty_text = mod.intelligence(action="index_fast")
    assert r_empty_text["code"] == "IDA_ERROR"
    assert r_empty_text["details"]["failed"] >= 1

    # 10. env commit batch conversion failure (lines 685-686) & CPU-detected pass size (lines 627-635)
    monkeypatch.setenv("IDA_MCP_INDEX_COMMIT_BATCH", "not_an_int")
    monkeypatch.setenv("IDA_MCP_FULL_INDEX_PASS_SIZE", "not_an_int")
    monkeypatch.setattr(mod, "_build_fast_signature", lambda _ea, _f=None: f"fast:{_ea:x}")
    r_full_pass = mod.intelligence(action="index_fast", mode="full")
    assert r_full_pass["ok"] is True

    # similar_functions validate_addr error (line 838), decompile error (lines 844-845),
    # empty pseudo (line 847), and empty index (line 850)
    monkeypatch.setattr(mod, "validate_addr", lambda _a, **_k: (None, {"code": "INVALID_ADDR", "message": "bad"}))
    err_sim1 = mod.intelligence(action="similar_functions", addr="invalid")
    assert err_sim1["code"] == "INVALID_ADDR"

    monkeypatch.setattr(mod, "validate_addr", lambda _a, **_k: (0x1000, None))
    monkeypatch.setattr(mod, "_safe_decompile", lambda _ea: (_ for _ in ()).throw(RuntimeError("sim decompile fail")))
    err_sim2 = mod.intelligence(action="similar_functions", addr="0x1000")
    assert err_sim2["code"] == "IDA_ERROR"

    monkeypatch.setattr(mod, "_safe_decompile", lambda _ea: "")
    err_sim3 = mod.intelligence(action="similar_functions", addr="0x1000")
    assert err_sim3["code"] == "IDA_ERROR"

    monkeypatch.setattr(mod, "_safe_decompile", lambda _ea: "int f() {}")
    idx_empty = _Index("/tmp/fake", _Embedder(), size=0)
    monkeypatch.setattr(services, "FunctionEmbeddingIndex", lambda *_args: idx_empty)
    err_sim4 = mod.intelligence(action="similar_functions", addr="0x1000")
    assert err_sim4["code"] == "NO_RESULTS"

    # semantic_search empty index (line 878)
    err_sem_empty = mod.intelligence(action="semantic_search", query="test query")
    assert err_sem_empty["code"] == "NO_RESULTS"

    # restore non-empty index for subsequent tests
    monkeypatch.setattr(services, "FunctionEmbeddingIndex", lambda *_args: idx)

    # blackboard_search import error (lines 898-899) and tool failure (lines 910-911)
    real_import = builtins.__import__

    def no_bb(name, *args, **kwargs):
        if "blackboard" in name:
            raise ImportError("blackboard missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_bb)
    err_bb = mod.intelligence(action="blackboard_search", query="search terms")
    assert err_bb["code"] == "IDA_ERROR"
    monkeypatch.setattr(builtins, "__import__", real_import)

    bb_broken = types.ModuleType("ida_pro_mcp.ida_mcp.tools.blackboard")
    bb_broken.blackboard = lambda **_kw: (_ for _ in ()).throw(RuntimeError("blackboard query error"))
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.tools.blackboard", bb_broken)
    err_bb_fail = mod.intelligence(action="blackboard_search", query="search terms")
    assert err_bb_fail["code"] == "IDA_ERROR"

    # export_index_summary metadata exception (lines 924-925)
    idx_broken_meta = _Index("/tmp/fake", _Embedder(), size=2)
    idx_broken_meta.metadata = lambda: (_ for _ in ()).throw(RuntimeError("meta broken"))
    monkeypatch.setattr(services, "FunctionEmbeddingIndex", lambda *_args: idx_broken_meta)
    res_meta_broken = mod.intelligence(action="export_index_summary")
    assert res_meta_broken["ok"] is True
    assert res_meta_broken["index"]["metadata"] == {}

    # function_families import error (lines 938-939) and empty index (line 942)
    def no_fam(name, *args, **kwargs):
        if "families" in name:
            raise ImportError("families missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_fam)
    err_fam = mod.intelligence(action="function_families")
    assert err_fam["code"] == "IDA_ERROR"
    monkeypatch.setattr(builtins, "__import__", real_import)

    monkeypatch.setattr(services, "FunctionEmbeddingIndex", lambda *_args: idx_empty)
    err_fam_empty = mod.intelligence(action="function_families")
    assert err_fam_empty["code"] == "NO_RESULTS"

    monkeypatch.setattr(services, "FunctionEmbeddingIndex", lambda *_args: idx)

    # function_families range error (line 955) and range/radius exceptions (lines 957-958, 968-969)
    # and mark_examined with BlackboardStore (lines 989-1006)
    families_mod = types.ModuleType("ida_pro_mcp.host.intelligence.families")
    families_mod.compute_function_families = lambda *_a, **_k: {
        "families": [
            {
                "family_id": 1,
                "summary": "family 1 summary",
                "members": [{"ea": "0x1000", "name": "sub_1000"}],
            }
        ]
    }
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.host.intelligence.families", families_mod)

    import ida_pro_mcp.ida_mcp.tools._common as common_mod

    # 1. validate_range returns error (line 955)
    monkeypatch.setattr(
        common_mod,
        "validate_range",
        lambda *_a, **_k: (None, None, {"code": "INVALID_RANGE", "message": "bad range"}),
    )
    err_fam_range = mod.intelligence(action="function_families", start="0x1000", end="0x2000")
    assert err_fam_range["code"] == "INVALID_RANGE"

    # 2. validate_range throws exception (lines 957-958)
    monkeypatch.setattr(
        common_mod,
        "validate_range",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("range fail")),
    )
    import ida_pro_mcp.host.intelligence.scope_window as scope_mod

    # 3. radius calculation success path (lines 960-967)
    monkeypatch.setattr(
        scope_mod,
        "radius_address_range",
        lambda c, r: (c - r, c + r),
    )
    res_fam_radius = mod.intelligence(action="function_families", addr="0x1000", radius=0x100)
    assert res_fam_radius["ok"] is True

    # 4. radius_address_range throws exception (lines 968-969)
    monkeypatch.setattr(
        scope_mod,
        "radius_address_range",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("radius fail")),
    )

    class MockBlackboardStore:
        records = []

        def record_examination(self, **kwargs):
            self.records.append(kwargs)

    bb_store_mod = types.ModuleType("ida_pro_mcp.ida_mcp.tools.blackboard")
    bb_store_mod.BlackboardStore = MockBlackboardStore
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.tools.blackboard", bb_store_mod)

    res_fam = mod.intelligence(
        action="function_families",
        start="0x1000",
        end="0x2000",
        addr="0x1000",
        radius="0x100",
        mark_examined=True,
        verdict="reviewed",
    )
    assert res_fam["ok"] is True
    assert res_fam["marked_examined"] == 1
    assert len(MockBlackboardStore.records) == 1

    # mark_examined with exception in record_examination (line 1006)
    class BrokenBlackboardStore:
        def record_examination(self, **kwargs):
            raise RuntimeError("record fail")

    bb_store_mod.BlackboardStore = BrokenBlackboardStore
    res_fam_err = mod.intelligence(
        action="function_families",
        mark_examined=True,
    )
    assert res_fam_err["ok"] is True
    assert "mark_examined_error" in res_fam_err


def test_intelligence_function_metadata_and_cache(intel_env, monkeypatch):
    mod, _indexes, _services = intel_env

    # Test _function_index_metadata with CFG loops, APIs, strings, thunk flag
    func = _Func(0x1000, 0x1040, flags=8)
    monkeypatch.setattr(mod.idautils, "Heads", lambda _s, _e: [0x1000, 0x1004], raising=False)
    monkeypatch.setattr(mod.idautils, "CodeRefsFrom", lambda _ea, _fl: [0x5000], raising=False)
    monkeypatch.setattr(mod.idc, "get_name", lambda _ref: "printf", raising=False)
    monkeypatch.setattr(mod.idautils, "DataRefsFrom", lambda _ea: [0x6000], raising=False)
    monkeypatch.setattr(mod.idc, "get_strlit_contents", lambda _ref, *_args: b"format", raising=False)

    class FakeBlock:
        def __init__(self, start_ea):
            self.start_ea = start_ea

        def succs(self):
            # Back-edge loop: 0x1004 -> 0x1000
            return [types.SimpleNamespace(start_ea=0x1000)]

    b1 = FakeBlock(0x1004)
    monkeypatch.setattr(mod._compat, "get_flow_chart", lambda _ea: [b1])
    monkeypatch.setattr(mod.idaapi, "FUNC_THUNK", 8, raising=False)
    monkeypatch.setattr(mod._compat, "get_func_flags", lambda _ea: 8)
    monkeypatch.setattr(mod._compat, "get_segment_name", lambda _ea: ".text")

    meta = _ORIGINAL_FUNCTION_INDEX_METADATA(func)
    assert meta["api_count"] == 2
    assert meta["string_count"] == 2
    assert meta["has_loops"] == 1
    assert meta["is_thunk"] == 1
    assert meta["segment"] == ".text"

    # Test _invalidate_tool_cache directly
    _ORIGINAL_INVALIDATE_TOOL_CACHE()


def test_intelligence_remaining_fallbacks(intel_env, monkeypatch):
    mod, _indexes, services = intel_env

    # 1. Radius import fallback (lines 586-587)
    real_import = builtins.__import__

    def import_hook_scope(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "ida_pro_mcp.host.intelligence.scope_window" and fromlist and "radius_address_range" in fromlist:
            raise ImportError("scope_window missing")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_hook_scope)
    scope_fallback = types.ModuleType("host.intelligence.scope_window")
    scope_fallback.radius_address_range = lambda c, r: (c - r, c + r)
    monkeypatch.setitem(sys.modules, "host.intelligence.scope_window", scope_fallback)
    r_fallback_scope = mod.intelligence(action="index_range", start="0x1000", radius="0x100")
    assert r_fallback_scope["ok"] is True
    monkeypatch.setattr(builtins, "__import__", real_import)

    # 2. CPU count fallback when sched_getaffinity is absent (lines 629-630)
    import os

    monkeypatch.delattr(os, "sched_getaffinity", raising=False)
    monkeypatch.setattr(mod, "_build_fast_signature", lambda _ea, _f=None: f"fast:{_ea:x}")
    r_cpu = mod.intelligence(action="index_fast", mode="full")
    assert r_cpu["ok"] is True

    # 3. Relative blackboard import fallback in mark_examined (lines 989-990)
    def import_hook_bb(name, globals=None, locals=None, fromlist=(), level=0):
        if level > 0 and ("blackboard" in name or (fromlist and "BlackboardStore" in fromlist)):
            raise ImportError("relative blackboard missing")
        return real_import(name, globals, locals, fromlist, level)

    class FallbackBlackboardStore:
        def record_examination(self, **kwargs):
            pass

    fallback_bb_mod = types.ModuleType("blackboard")
    fallback_bb_mod.BlackboardStore = FallbackBlackboardStore
    monkeypatch.setitem(sys.modules, "blackboard", fallback_bb_mod)
    monkeypatch.setattr(builtins, "__import__", import_hook_bb)

    families_mod = types.ModuleType("ida_pro_mcp.host.intelligence.families")
    families_mod.compute_function_families = lambda *_a, **_k: {
        "families": [
            {
                "family_id": 1,
                "summary": "family summary",
                "members": [{"ea": "0x1000", "name": "sub_1000"}],
            }
        ]
    }
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.host.intelligence.families", families_mod)

    r_bb_fallback = mod.intelligence(action="function_families", mark_examined=True)
    assert r_bb_fallback["ok"] is True
    monkeypatch.setattr(builtins, "__import__", real_import)

    # 4. Top-level exception handling -> handle_error (lines 1016-1017)
    monkeypatch.setattr(
        mod,
        "public_arg",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("fatal unexpected error")),
    )
    r_fatal = mod.intelligence(action="intelligence_status")
    assert r_fatal["ok"] is False
    assert "fatal unexpected error" in str(r_fatal.get("error") or r_fatal.get("message"))
