"""Cover uncommon search-combinator parser, cache, and backend modes."""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

from tests._isolated_repo_loader import load_tool_submodule


def _module():
    return load_tool_submodule("search.combinators")


def test_bool_tokenizer_and_parser_cover_literals_and_expected_token_errors(monkeypatch):
    comb = _module()
    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000, 0x2000])
    monkeypatch.setattr(comb, "_func_name", lambda ea: {0x1000: "main", 0x2000: "worker"}[ea])

    assert comb._tokenize_bool(
        '(name:"main entry" && worker) || !leaf'
    ) == ["(", "name:main entry", "AND", "LITERAL:worker", ")", "OR", "NOT", "leaf:true"]
    assert comb._tokenize_bool('name:"escaped \\"quote\\""') == ['name:escaped "quote"']
    assert comb._tokenize_bool('"unterminated') == ["LITERAL:unterminated"]
    assert comb._tokenize_bool("name:main trailing")[-1] == "LITERAL:trailing"

    parser = comb._BoolParser(["name:main"])
    assert parser.peek() == "name:main"
    assert parser.parse_expr() == {0x1000}
    assert parser.peek() is None

    for tokens, expected in [
        (["name:main"], "Expected ')'"),
        (["name:main"], "Unexpected end"),
        (["LITERAL:main"], "literal"),
        (["bogus:value"], "Unknown primitive"),
        (["unexpected"], "Unexpected token"),
    ]:
        parser = comb._BoolParser(tokens)
        try:
            if expected == "Expected ')'":
                parser.consume(")")
            elif expected == "Unexpected end":
                parser.consume()
                parser.consume()
            else:
                parser.parse_expr()
        except ValueError as exc:
            assert expected.lower() in str(exc).lower()
        else:
            if expected == "literal":
                assert parser.pos == 1
            else:
                raise AssertionError(f"expected parser failure for {tokens}")

    assert comb.search_bool("name:main", False, 0, 1)["ok"] is True
    assert comb.search_bool("???", False, 0, 1)["error"] is True


def test_primitive_error_and_empty_result_modes_are_safe(monkeypatch):
    comb = _module()
    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000, 0x2000])
    monkeypatch.setattr(comb, "_func_name", lambda ea: f"fn_{ea:x}")

    monkeypatch.setattr(comb._compat, "get_func_info", lambda _ea: None)
    assert comb._prim_size("10") == set()
    assert comb._prim_funcs_by_mnem("ret") == set()

    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000])
    monkeypatch.setattr(comb, "_func_name", lambda _ea: (_ for _ in ()).throw(RuntimeError("name")))
    assert comb._set_to_items({0x1000}, 0, 1) == [{"addr": "0x1000", "ea": 0x1000, "name": "0x1000"}]

    monkeypatch.setattr(comb, "resolve_target", lambda _target: (comb.idaapi.BADADDR, "missing", {}))
    assert comb._prim_callers("missing") == set()
    assert comb._prim_callees("missing") == set()

    monkeypatch.setattr(comb, "resolve_target", lambda _target: (0x1000, None, {}))
    monkeypatch.setattr(comb._compat, "get_func_start", lambda _ea: None)
    assert comb._prim_callees("0x1000") == set()

    typeinf = types.ModuleType("ida_typeinf")
    typeinf.tinfo_t = lambda: SimpleNamespace(get_func_details=lambda _data: False)
    typeinf.func_type_data_t = lambda: SimpleNamespace(size=lambda: 0)
    monkeypatch.setitem(sys.modules, "ida_typeinf", typeinf)
    monkeypatch.setattr(comb.ida_nalt, "get_tinfo", lambda *_args: False, raising=False)
    assert comb._prim_args("2") == set()
    assert comb._prim_args("bad") == set()


def test_call_graph_cache_rebuild_and_fingerprint_modes(monkeypatch):
    comb = _module()
    comb._CALL_GRAPH_CACHE.clear()
    state = {"cheap": "cheap-1", "fp": "fp-1"}
    monkeypatch.setattr(comb, "_idb_cheap_key", lambda: state["cheap"])
    monkeypatch.setattr(comb, "_idb_fingerprint", lambda: state["fp"])
    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000, 0x2000])
    monkeypatch.setattr(comb, "_func_callees", lambda ea: {0x2000} if ea == 0x1000 else set())

    first = comb._get_call_graph()
    assert first == {"callers": {0x2000: {0x1000}}, "callees": {0x1000: {0x2000}}}
    assert comb._get_call_graph() is first

    state["cheap"] = "cheap-2"
    assert comb._get_call_graph() is first
    state["fp"] = "fp-2"
    rebuilt = comb._get_call_graph()
    assert rebuilt == first and rebuilt is not first

    broken = _module()
    monkeypatch.setattr(broken.idc, "get_idb_path", lambda: (_ for _ in ()).throw(RuntimeError("stat")), raising=False)
    assert broken._idb_cheap_key() == "unknown"
    monkeypatch.setattr(broken.idautils, "Functions", lambda: (_ for _ in ()).throw(RuntimeError("count")))
    assert broken._idb_fingerprint() == "unknown"


def test_index_backed_analysis_and_backend_failures(monkeypatch):
    comb = _module()
    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "/tmp/sample.i64", raising=False)
    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000])
    monkeypatch.setattr(comb, "_func_name", lambda _ea: "main")
    monkeypatch.setattr(comb._compat, "get_func_info", lambda _ea: SimpleNamespace(start_ea=0x1000, end_ea=0x1010))

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, _params=()):
            if query.startswith("SELECT COUNT"):
                return SimpleNamespace(fetchone=lambda: (2,))
            return SimpleNamespace(fetchall=lambda: [("0x1000", "main", 32), ("0x2000", "helper", 16)])

    index = SimpleNamespace(size=2, _conn=lambda: Conn())  # noqa: PLW0108
    services = types.ModuleType("ida_pro_mcp.services")
    services.get_assembler = lambda: SimpleNamespace(_get_index=lambda _path: index)
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)

    indexed = comb.search_analyze(scope="outlier", metric="size", offset=0, limit=1)
    assert indexed["ok"] is True and indexed["items"][0]["size"] == 32
    assert indexed["truncated"] is True

    class BrokenConn(Conn):
        def execute(self, *_args):
            raise RuntimeError("database")

    broken = SimpleNamespace(size=2, _conn=lambda: BrokenConn())  # noqa: PLW0108
    services.get_assembler = lambda: SimpleNamespace(_get_index=lambda _path: broken)
    fallback = comb.search_analyze(scope="outlier", metric="tiny", limit=5)
    assert fallback["ok"] is True and fallback["note"].endswith("direct IDA enumeration.")

    services.get_assembler = lambda: SimpleNamespace(_get_index=lambda _path: None)
    assert comb._get_index_metadata(0x1000) is None
    assert comb._get_embedding_similar(0x1000) == []


def test_semantic_and_vulnerable_index_candidates_are_filtered(monkeypatch):
    comb = _module()
    monkeypatch.setattr(comb.idc, "get_idb_path", lambda: "/tmp/sample.i64", raising=False)
    monkeypatch.setattr(comb, "_get_index_metadata", lambda _ea: {"func_size": 4, "bb_count": 1, "cyclomatic": 1})
    monkeypatch.setattr(comb._compat, "get_func_start", lambda ea: ea if ea in {0x1000, 0x2000} else None)
    monkeypatch.setattr(comb, "_func_name", lambda ea: {0x1000: "main", 0x2000: "worker"}.get(ea, hex(ea)))
    monkeypatch.setattr(comb.idautils, "Functions", lambda: [0x1000, 0x2000])
    monkeypatch.setattr(comb.idautils, "Names", lambda: [(0x1000, "read")])
    monkeypatch.setattr(comb.idc, "get_func_name", lambda ea: "read" if ea == 0x1000 else "worker")
    monkeypatch.setattr(comb, "_get_call_graph", lambda: {"callers": {0x1000: {0x2000}}, "callees": {0x2000: {0x1000}}})

    class Index:
        size = 2

        def hybrid_search(self, _query, **_kwargs):
            return [{"ea": "0x1000", "name": "main", "score": 0.8, "similarity": 0.7}]

        def search(self, _query, **_kwargs):
            return [{"addr": "0x2000", "similarity": 0.6}, {"addr": "bad", "similarity": 0.5}]

    index = Index()
    services = types.ModuleType("ida_pro_mcp.services")
    services.get_assembler = lambda: SimpleNamespace(
        _get_index=lambda _path: index,
        _behavior_classifier=lambda: object(),  # noqa: PLW0108
    )
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.services", services)

    semantic = comb.search_analyze(scope="semantic", pattern="crypto", limit=2)
    assert semantic["ok"] is True and semantic["items"][0]["size"] == 4
    vulnerable = comb.search_analyze(scope="vulnerable", depth=2, pattern="behavior_candidate")
    assert vulnerable["ok"] is True and vulnerable["count"] == 1
    assert vulnerable["items"][0]["vuln_type"] == "behavior_candidate"

    services.get_assembler = lambda: (_ for _ in ()).throw(RuntimeError("classifier"))
    assert comb.search_analyze(scope="vulnerable", depth=2)["ok"] is True
    assert comb.search_analyze(scope="semantic", pattern="crypto")["error"] is True
