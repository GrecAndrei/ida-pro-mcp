"""Boundary coverage for small IDA-side support modules.

These tests keep the optional IDA and embedding integrations explicit: the
same helpers must remain total when the SDK, native embedder, cache resolver,
or SSE server is unavailable.
"""

from __future__ import annotations

import builtins
import importlib
import importlib.util
import sys
import types
from pathlib import Path

import pytest

from tests._isolated_repo_loader import install_common_stub, load_support_module

REPO = Path(__file__).resolve().parents[2]
IDA_MCP = REPO / "src" / "ida_pro_mcp" / "ida_mcp"


def _load(relpath: str, name: str):
    path = IDA_MCP / f"{relpath}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_events_without_ida(monkeypatch):
    real_import = builtins.__import__

    def no_ida_idp(name, *args, **kwargs):
        if name == "ida_idp":
            raise ImportError("IDA SDK unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_ida_idp)
    return _load("support/events", "remaining_events_no_ida")


def test_cache_canonicalization_and_address_extraction_boundaries():
    cache = _load("cache", "remaining_cache_canonicalization")

    assert cache._parse_addr(True) is None
    assert cache._parse_addr(3.5) is None
    assert cache._parse_addr("  ") is None
    assert cache._parse_addr("not-an-address") is None
    assert cache.canonicalize_value(" plain text ") == " plain text "
    assert cache.canonicalize_value(["0x20", 0x10]) == (16, 32)
    assert cache.canonicalize_value(["x", 1]) == ("x", 1)
    assert cache.canonicalize_value({2: ["0x30"], "a": "name"}) == (
        ("2", (48,)),
        ("a", "name"),
    )
    assert cache.canonicalize_kwargs({"limit": "10", "name": "x"}, {"limit": 10}) == {
        "name": "x"
    }

    assert cache.extract_addresses(None) == frozenset()
    assert cache.extract_addresses({"addr": True, "target": "symbol"}) == frozenset()
    assert cache.extract_addresses({"addrs": ["0x1000", "bad", 0x2000]}) == frozenset(
        {0x1000, 0x2000}
    )
    assert cache.extract_addresses({"addrs": "0x1000, 8192 bad"}) == frozenset(
        {0x1000, 0x2000}
    )


def test_cache_age_and_stale_generation_fail_closed(monkeypatch):
    cache_module = _load("cache", "remaining_cache_generation")
    now = [100.0]
    monkeypatch.setattr(cache_module.time, "time", lambda: now[0])
    cache = cache_module.ToolResultCache(ttl_seconds=5)

    cache.put("data", {"addr": 0x1000}, "value")
    now[0] = 106.0
    assert cache.get("data", {"addr": 0x1000}, with_age=True) == (None, 0.0)

    cache.put("data", {"addr": 0x1000}, "value")
    cache._write_generation += 1
    assert cache.get("data", {"addr": 0x1000}, with_age=True) == (None, 0.0)


def test_cache_narrow_invalidation_handles_mixed_address_forms():
    cache_module = _load("cache", "remaining_cache_invalidation")
    cache = cache_module.ToolResultCache(max_entries=8)
    cache.put("data", {"addrs": ["0x1000", "0x3000"]}, "multi")
    cache.put("data", {"addrs": "0x2000, 0x4000"}, "text")
    cache.put("data", {"address": "symbol"}, "symbol")

    cache.invalidate_for_write({"addrs": (0x3001,)})
    assert cache.get("data", {"addrs": [0x1000, 0x3000]}) is None
    assert cache.get("data", {"addrs": "0x2000, 0x4000"}) == "text"
    # An entry with an unparseable symbol key is conservatively treated as a
    # whole walk and is invalidated along with the written page.
    assert cache.get("data", {"address": "symbol"}) is None
    assert cache.stats()["entries"] == 1


def test_events_without_ida_and_defensive_internal_failures(monkeypatch):
    events = _load_events_without_ida(monkeypatch)
    events.EVENT_RING.clear()
    assert events._IDB_HOOKS_BASE is None
    assert events.install_hooks() is None
    assert events._fmt_addr(object()) == ""

    class BadResolver:
        def __call__(self):
            raise RuntimeError("cache unavailable")

    sync = types.ModuleType("ida_pro_mcp.ida_mcp.sync")
    sync._tool_cache = BadResolver()
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.sync", sync)
    events._invalidate_tool_cache()

    class BrokenServer:
        def broadcast_sse_event(self, *_args):
            raise RuntimeError("connection closed")

    rpc = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")
    rpc.MCP_SERVER = BrokenServer()
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.rpc", rpc)
    events._sse_emit({"type": "analysis"})
    events.record_event("analysis", "invalid", None)
    assert events.read_events(1)[0][0]["name"] == ""


def test_events_compatibility_broadcast_and_function_name_failures(monkeypatch):
    events = _load_events_without_ida(monkeypatch)
    events.EVENT_RING.clear()

    class Connection:
        def __init__(self, broken=False):
            self.broken = broken
            self.sent = []

        def send_event(self, kind, event):
            if self.broken:
                raise RuntimeError("dead socket")
            self.sent.append((kind, event))

    good = Connection()
    rpc = types.ModuleType("ida_pro_mcp.ida_mcp.rpc")
    rpc.MCP_SERVER = types.SimpleNamespace(
        _sse_connections={"good": good, "bad": Connection(broken=True)}
    )
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.rpc", rpc)
    events._sse_emit({"type": "analysis"})
    assert good.sent[0][0] == "analysis"

    idc = types.ModuleType("idc")
    idc.get_func_name = lambda _ea: (_ for _ in ()).throw(RuntimeError("idc"))
    idaapi = types.ModuleType("idaapi")
    idaapi.get_func_name = lambda _ea: (_ for _ in ()).throw(RuntimeError("idaapi"))
    monkeypatch.setitem(sys.modules, "idc", idc)
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    assert events._func_name(0x1000) == ""


def test_semantic_matching_optional_backend_and_remaining_branches(monkeypatch):
    sm = _load("support/semantic_matching", "remaining_semantic_matching")
    sm._EMBEDDER = None
    sm._EMB_CACHE.clear()

    # A one-character token takes the documented overlap fallback.
    assert sm.semantic_score_cheap("a", "b") == 0.0
    assert sm.semantic_score(" ", "x", return_detail=True) == {
        "score": 0.0,
        "method": "exact",
    }

    class Embedder:
        def embed_documents(self, texts):
            return [types.SimpleNamespace(ok=True, vector=[float(i + 1)]) for i, _ in enumerate(texts)]

        def cosine(self, _left, _right):
            return 0.25

    sm._EMBEDDER = Embedder()
    sm._EMB_CACHE_MAX = 1
    sm._EMB_CACHE["old"] = [1.0]
    assert sm._embed_batch(["new"])["new"] == [1.0]

    sm._EMB_CACHE.clear()
    assert sm._embed_batch(["one", "two"]) == {"one": [1.0], "two": [2.0]}
    assert sm._subword_tokens("uart0 uart00") == ["uart0", "uart", "uart00", "00"]

    monkeypatch.setattr(sm, "_embed_batch", lambda _texts: {"long query": [1.0]})
    assert sm.semantic_scores("long query", ["candidate"], force_embed=True) == [
        sm.semantic_score_cheap("long query", "candidate")
    ]
    monkeypatch.setattr(sm, "_embed_batch", lambda _texts: {"long query": [1.0], "candidate": [2.0]})
    monkeypatch.setattr(sm, "_get_embedder", lambda: None)
    assert sm._embedding_score("long query", "candidate") is None


def test_semantic_scores_skips_blank_top_candidates_and_missing_vectors(monkeypatch):
    sm = _load("support/semantic_matching", "remaining_semantic_batch")
    embedder = types.SimpleNamespace(cosine=lambda *_args: 0.5)
    sm._EMBEDDER = embedder
    monkeypatch.setattr(sm, "_winner_decisive", lambda _scores: False)
    monkeypatch.setattr(sm, "_embed_batch", lambda _texts: {"long query": [1.0]})
    assert sm.semantic_scores("long query", ["", ""]) == [0.0, 0.0]

    monkeypatch.setattr(
        sm,
        "_embed_batch",
        lambda _texts: {"long query": [1.0], "candidate": [2.0]},
    )
    assert sm.semantic_scores("long query", ["candidate"], force_embed=True) == [60.0]


def test_architecture_helpers_cover_degraded_sdk_and_segment_fallbacks(monkeypatch):
    install_common_stub()
    arch = load_support_module("arch_utils")
    ida_ida = importlib.import_module("ida_ida")
    idc = importlib.import_module("idc")
    monkeypatch.setattr(
        ida_ida,
        "inf_get_procname",
        lambda: (_ for _ in ()).throw(RuntimeError("old API")),
        raising=False,
    )
    monkeypatch.setattr(
        arch,
        "idaapi",
        types.SimpleNamespace(
            get_inf_structure=lambda: (_ for _ in ()).throw(RuntimeError("no info")),
            __EA64__=False,
        ),
    )
    monkeypatch.setattr(
        idc,
        "get_inf_attr",
        lambda _attr: (_ for _ in ()).throw(RuntimeError("no attr")),
        raising=False,
    )
    assert arch._proc_name_and_bitness() == ("", None)
    assert arch.get_arch() == "unknown"

    ida_segment = importlib.import_module("ida_segment")
    monkeypatch.setattr(arch, "is_riscv_family", lambda: True)
    monkeypatch.setattr(
        ida_ida,
        "inf_get_app_bitness",
        lambda: (_ for _ in ()).throw(RuntimeError("bitness unavailable")),
        raising=False,
    )
    monkeypatch.setattr(
        ida_segment,
        "get_first_segment_ea",
        lambda: (_ for _ in ()).throw(AttributeError("legacy IDA")),
        raising=False,
    )
    monkeypatch.setattr(idc, "get_first_seg", lambda: idc.BADADDR, raising=False)
    assert arch._riscv_gp_fix_refs(0x1000) == {"fixed": 0, "skipped": 0}


def test_riscv_gp_detection_ignores_malformed_candidates_and_bad_symbols(monkeypatch):
    install_common_stub()
    arch = load_support_module("arch_utils")
    idautils = importlib.import_module("idautils")
    idc = importlib.import_module("idc")
    monkeypatch.setattr(idautils, "Entries", lambda: iter([(), (1,)]), raising=False)
    monkeypatch.setattr(
        idc,
        "get_name_ea_simple",
        lambda _name: (_ for _ in ()).throw(RuntimeError("symbol table unavailable")),
        raising=False,
    )
    monkeypatch.setattr(idc, "get_inf_attr", lambda _attr: idc.BADADDR, raising=False)
    result = arch.detect_riscv_gp()
    assert result["found"] is False
    assert "GP not found" in result["note"]


@pytest.mark.parametrize("bad", [None, object()])
def test_events_function_name_is_total_for_bad_idc_modules(monkeypatch, bad):
    events = _load_events_without_ida(monkeypatch)
    monkeypatch.setitem(sys.modules, "idc", bad)
    monkeypatch.setitem(sys.modules, "idaapi", bad)
    assert events._func_name(0x1000) == ""
