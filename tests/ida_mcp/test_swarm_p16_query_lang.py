"""Regression tests for swarm/p16_query_lang findings.

WO-Q1 promotes the orphaned MATCH…WHERE DSL (paper sections 2.1 / 10.2
item 11 / inventory item 42) to the agent surface and fixes its silent
under-report:

1. ``run_query_lang`` accepted no ``limit``: the executor fetched candidates
   from the underlying tools with a hardcoded ``count=1000`` (functions,
   strings, imports) and, when the IDB held more candidates than that,
   silently reported a too-small ``total``.  The ``limit`` parameter (default
   1000) now sizes the candidate window, and a capped window is surfaced with
   ``truncated: True`` + ``total_matches`` — mirroring the search suite's
   timed_out/partial convention — instead of a silently-under-reported total.

2. The DSL op→backend translation smoke: MATCH function/string/import route to
   ``data(action=functions|strings|imports, count=limit)`` and MATCH call /
   MATCH instruction route to ``search(action=insns, pattern=…)`` with the
   arch-aware call-alias set (RISC-V raw blob → jal/jalr/c.jal/c.jalr).

3. WHERE/AND clauses and the contains/~ operators still parse.

Host-side tests: no live IDA session required — ``_call_tool`` and the tools
package are faked in-process.
"""

from __future__ import annotations

import sys
import types

from tests._isolated_repo_loader import load_support_module


def _plan(target, identifier, conditions=None):
    return {
        "target": target, "identifier": identifier,
        "conditions": conditions or [], "limit": 100,
        "sort_key": None, "sort_order": "ASC", "group_key": None,
    }


def _functions_backend(all_fns, count):
    """Fake ``data(action='functions')`` honoring ``count`` and reporting the
    full DB total next to the fetched page (mirrors the real data tool)."""
    page = all_fns[:count]
    return {
        "ok": True,
        "functions": page,
        "total": len(all_fns),
        "count": len(page),
        "offset": 0,
    }


_FNS = [
    {"addr": f"0x{0x1000 + i:x}", "name": f"f{i}", "size": 10 + i}
    for i in range(10)
]


# ---------------------------------------------------------------------------
# Parser: WHERE/AND clauses and operators still parse
# ---------------------------------------------------------------------------

def test_query_lang_parses_where_and_clauses():
    ql = load_support_module("query_lang")
    plan = ql.QueryParser().parse(
        'MATCH function * WHERE size > 100 AND name == "main" AND segment == ".text" LIMIT 10'
    )
    assert plan is not None
    assert plan["target"] == "function"
    assert plan["limit"] == 10
    conds = {c["key"]: (c["op"], c["value"]) for c in plan["conditions"]}
    assert conds == {
        "size": (">", 100),
        "name": ("==", "main"),
        "segment": ("==", ".text"),
    }


def test_query_lang_parses_contains_and_regex_conditions():
    ql = load_support_module("query_lang")
    plan = ql.QueryParser().parse('MATCH string * WHERE text contains "cmd.exe" AND value ~ "http"')
    assert plan is not None
    conds = {c["key"]: c["op"] for c in plan["conditions"]}
    assert conds == {"text": "contains", "value": "~"}


def test_query_lang_accepts_missing_where():
    # The parser is deliberately lenient: "MATCH function *" with no WHERE is a
    # valid wildcard function query, not a parse error.
    ql = load_support_module("query_lang")
    plan = ql.QueryParser().parse("MATCH function *")
    assert plan is not None
    assert plan["target"] == "function"
    assert plan["identifier"] == "*"
    assert plan["conditions"] == []


def test_query_lang_missing_where_executes_wildcard():
    ql = load_support_module("query_lang")
    ql._call_tool = lambda name, **kw: _functions_backend(_FNS, kw.get("count", 1000))
    resp = ql.run_query_lang("MATCH function *")
    assert resp["ok"] is True
    assert resp["total"] == 10


def test_query_lang_lenient_shapes():
    """A load of phrasings parse to the same plan — very hard to use wrong."""
    ql = load_support_module("query_lang")
    cases = {
        "function size > 100": ("function", "*", [("size", ">", 100)]),
        "functions with size > 100": ("function", "*", [("size", ">", 100)]),
        "find functions where size > 100": ("function", "*", [("size", ">", 100)]),
        "size > 100": ("function", "*", [("size", ">", 100)]),  # target defaulted
        "name = main": ("function", "*", [("name", "==", "main")]),  # '=' alias
        'strings containing "cmd.exe"': ("string", "*", [("text", "contains", "cmd.exe")]),
        'value matches "http"': ("function", "*", [("value", "~", "http")]),
        'text like "key" AND size < 20': ("function", "*", [("text", "contains", "key"), ("size", "<", 20)]),
        "MATCH function * WHERE size > 100 LIMIT 10": ("function", "*", [("size", ">", 100)]),
    }
    for q, (target, ident, conds) in cases.items():
        plan = ql.QueryParser().parse(q)
        assert plan is not None, q
        assert plan["target"] == target, q
        assert plan["identifier"] == ident, q
        got = [(c["key"], c["op"], c["value"]) for c in plan["conditions"]]
        assert got == conds, (q, got)


def test_query_lang_bare_identifier_becomes_filter():
    ql = load_support_module("query_lang")
    plan = ql.QueryParser().parse("function main")
    assert plan["target"] == "function"
    assert plan["identifier"] == "*"
    assert plan["conditions"] == [{"key": "name", "op": "contains", "value": "main"}]
    plan = ql.QueryParser().parse('calls to "malloc"')
    assert plan["target"] == "call"
    assert plan["identifier"] == "*"
    assert plan["conditions"] == [{"key": "text", "op": "contains", "value": "malloc"}]
    plan = ql.QueryParser().parse("imports from kernel32")
    assert plan["target"] == "import"
    assert plan["identifier"] == "*"
    assert plan["conditions"] == [{"key": "name", "op": "contains", "value": "kernel32"}]


def test_query_lang_free_text_falls_back_to_find():
    ql = load_support_module("query_lang")
    calls = []
    ql._call_tool = lambda name, **kw: calls.append((name, kw)) or {
        "ok": True, "results": "0x1000  main", "total": 1, "count": 1,
    }
    resp = ql.run_query_lang("what does main do")
    assert resp["ok"] is True
    assert calls, calls
    assert calls[0][0] == "search" and calls[0][1]["action"] == "find", calls


# ---------------------------------------------------------------------------
# Truncation: capped candidate window is reported, not silently under-counted
# ---------------------------------------------------------------------------

def test_query_lang_reports_truncated_when_window_capped():
    ql = load_support_module("query_lang")
    calls = []
    ql._call_tool = lambda name, **kw: calls.append((name, kw)) or _functions_backend(_FNS, kw.get("count", 1000))
    # 10 functions exist, but the window caps the fetch at 3.
    resp = ql.run_query_lang("MATCH function * WHERE size > 5", limit=3)
    assert resp["ok"] is True
    assert resp["truncated"] is True
    assert resp["total_matches"] == resp["total"] == 3  # matches seen before the cap
    assert resp["returned"] == 3
    # Op→backend translation: the fetch window became the data-tool count.
    assert calls[0] == ("data", {"action": "functions", "count": 3}), calls


def test_query_lang_no_truncation_when_all_candidates_seen():
    ql = load_support_module("query_lang")
    ql._call_tool = lambda name, **kw: _functions_backend(_FNS, kw.get("count", 1000))
    resp = ql.run_query_lang("MATCH function * WHERE size > 5")  # default limit 1000
    assert resp["ok"] is True
    assert resp["total"] == 10
    assert "truncated" not in resp
    assert "total_matches" not in resp


def test_query_lang_default_limit_stays_1000():
    ql = load_support_module("query_lang")
    calls = []
    ql._call_tool = lambda name, **kw: calls.append((name, kw)) or {"ok": True, "functions": [], "total": 0, "count": 0}
    ql.run_query_lang("MATCH function * WHERE size > 5")
    assert calls[0][1]["count"] == 1000, calls


def test_query_lang_clamps_limit_to_positive():
    ql = load_support_module("query_lang")
    calls = []
    ql._call_tool = lambda name, **kw: calls.append((name, kw)) or {"ok": True, "functions": [], "total": 0, "count": 0}
    ql.run_query_lang("MATCH function * WHERE size > 5", limit=0)
    assert calls[0][1]["count"] == 1, calls
    calls.clear()
    ql.run_query_lang("MATCH function * WHERE size > 5", limit=-5)
    assert calls[0][1]["count"] == 1, calls


def test_query_lang_strings_report_truncation_from_compact_backend():
    ql = load_support_module("query_lang")
    calls = []
    ql._call_tool = lambda name, **kw: calls.append((name, kw)) or {
        "ok": True,
        "strings": "0x1000  xrefs=1  cmd.exe\n0x2000  xrefs=0  powershell.exe",
        "total": 5,   # 3 more strings exist that were not fetched
        "count": 2,
        "offset": 0,
    }
    resp = ql.run_query_lang('MATCH string * WHERE text contains "cmd"')
    assert resp["ok"] is True
    assert resp["total"] == 1          # only the fetched window matched
    assert resp["returned"] == 1
    assert resp["truncated"] is True
    assert resp["total_matches"] == 1
    # Op→backend translation: strings fetch uses the candidate window.
    assert calls[0] == ("data", {"action": "strings", "count": 1000}), calls


def test_query_lang_imports_complete_window_not_truncated():
    ql = load_support_module("query_lang")
    ql._call_tool = lambda name, **kw: {
        "ok": True,
        "imports": "0x1000  kernel32  CreateFileA\n0x1004  kernel32  WriteFile",
        "total": 2,
        "count": 2,
        "offset": 0,
    }
    resp = ql.run_query_lang('MATCH import * WHERE name contains "Create"')
    assert resp["ok"] is True
    assert resp["returned"] == 1
    assert resp["total"] == 1
    assert "truncated" not in resp


def test_query_lang_call_propagates_backend_truncated_flag():
    ql = load_support_module("query_lang")
    ql._get_arch = lambda: "riscv"
    ql._call_tool = lambda name, **kw: {
        "ok": True,
        "truncated": True,  # search_insns hit its inner limit
        "results": "0x1000  [jal]\n0x1004  [jalr]",
    }
    resp = ql.QueryExecutor()._execute_call(_plan("call", "*"))
    assert resp["ok"] is True
    assert resp["truncated"] is True
    assert resp["total_matches"] == resp["total"] == 2


def test_query_lang_instruction_reports_truncated_when_backend_caps():
    ql = load_support_module("query_lang")
    ql._call_tool = lambda name, **kw: {
        "ok": True,
        "truncated": True,
        "results": "0x1000  [ecall]\n0x1004  [ecall]",
    }
    resp = ql.QueryExecutor()._execute_instruction(_plan("instruction", "ecall"))
    assert resp["ok"] is True
    assert resp["truncated"] is True
    assert resp["total_matches"] == 2


# ---------------------------------------------------------------------------
# Op→backend translation smoke (RISC-V raw-blob scenarios)
# ---------------------------------------------------------------------------

def test_query_lang_match_call_on_riscv_raw_blob_uses_link_aliases():
    """Opaque RISC-V raw blob: MATCH call must search jal/jalr/c.jal/c.jalr,
    not the x86-only 'call' mnemonic."""
    ql = load_support_module("query_lang")
    ql._get_arch = lambda: "riscv"
    calls = []
    ql._call_tool = lambda name, **kw: calls.append((name, kw)) or {
        "ok": True,
        "results": "0x1000  [jal]\n0x1004  [jalr]\n0x1008  [c.jal]",
    }
    resp = ql.run_query_lang("MATCH call * WHERE addr != ''")
    assert resp["ok"] is True
    assert resp["total"] == 3
    searched = {c[1]["pattern"] for c in calls}
    assert searched == {"jal", "jalr", "c.jal", "c.jalr"}, searched
    assert all(c[0] == "search" and c[1]["action"] == "insns" for c in calls), calls


def test_query_lang_match_instruction_on_riscv_blob_exact_mnemonic():
    ql = load_support_module("query_lang")
    calls = []
    ql._call_tool = lambda name, **kw: calls.append((name, kw)) or {
        "ok": True,
        "results": "0x1000  [ecall]",
    }
    resp = ql.run_query_lang("MATCH instruction ecall WHERE addr != ''")
    assert resp["ok"] is True
    assert resp["returned"] == 1
    assert calls[0] == ("search", {"action": "insns", "pattern": "ecall", "limit": 200}), calls


def test_query_lang_x86_call_alias_set_is_call_only():
    ql = load_support_module("query_lang")
    ql._get_arch = lambda: "x64"
    assert ql.QueryExecutor()._call_alias_set() == ["call"]


# ---------------------------------------------------------------------------
# Tool resolution from the tools package (real _get_tool path)
# ---------------------------------------------------------------------------

def test_query_lang_resolves_function_op_to_data_tool():
    ql = load_support_module("query_lang")
    fake = types.ModuleType("ida_pro_mcp.ida_mcp.tools.data")
    received = []

    def fake_data(action="functions", **kw):
        received.append((action, kw))
        return {"ok": True, "functions": [{"addr": "0x1000", "name": "f", "size": 100}], "total": 1, "count": 1, "offset": 0}

    fake.data = fake_data
    sys.modules["ida_pro_mcp.ida_mcp.tools.data"] = fake
    try:
        ql._TOOL_CACHE.clear()
        resp = ql.run_query_lang("MATCH function * WHERE size > 50 LIMIT 5")
        assert resp["ok"] is True
        assert resp["total"] == 1
        assert received == [("functions", {"count": 1000})], received
    finally:
        sys.modules.pop("ida_pro_mcp.ida_mcp.tools.data", None)
        ql._TOOL_CACHE.clear()


def test_query_lang_executor_composes_compact_and_structured_backend_shapes():
    ql = load_support_module("query_lang")
    ql._get_arch = lambda: "x64"

    def fake_call(tool_name, **kwargs):
        action = kwargs.get("action")
        if tool_name == "data" and action == "functions":
            return {"ok": True, "functions": "0x1000 20 xrefs=1 handler", "total": 1, "count": 1}
        if tool_name == "data" and action == "strings":
            return {"ok": True, "strings": "0x2000 xrefs=2 cmd.exe", "total": 1, "count": 1}
        if tool_name == "data" and action == "imports":
            return {"ok": True, "imports": "0x3000 kernel32 CreateFileA", "total": 1, "count": 1}
        if tool_name == "search" and action == "insns":
            return {"ok": True, "results": ["0x4000 [call]"]}
        if tool_name == "code" and action == "xrefs_to":
            return {"ok": True, "xrefs": [{"addr": "0x5000", "type": "call"}]}
        if tool_name == "idb" and action == "segments":
            return {"ok": True, "segments": [{"name": ".text", "start": "0x1000"}]}
        if tool_name == "code" and action == "blocks":
            return {"ok": True, "blocks": "0x6000 succs=[0x6010] preds=[]"}
        if tool_name == "search" and action == "find":
            return {"ok": True, "results": [{"addr": "0x7000", "text": "free text"}]}
        raise AssertionError((tool_name, kwargs))

    ql._call_tool = fake_call
    executor = ql.QueryExecutor(limit=2)
    assert executor.execute(_plan("function", "*", [{"key": "name", "op": "contains", "value": "handler"}]))["returned"] == 1
    assert executor.execute(_plan("string", "*", [{"key": "text", "op": "contains", "value": "cmd.exe"}]))["returned"] == 1
    assert executor.execute(_plan("import", "*", [{"key": "name", "op": "contains", "value": "Create"}]))["returned"] == 1
    assert executor.execute(_plan("call", "*"))["returned"] == 1
    assert executor.execute(_plan("instruction", "call"))["returned"] == 1
    assert executor.execute(_plan("xref", "0x401000"))["returned"] == 1
    assert executor.execute(_plan("segment", "*", [{"key": "name", "op": "==", "value": ".text"}]))["returned"] == 1
    assert executor.execute(_plan("block", "handler", [{"key": "succs", "op": "contains", "value": "0x6010"}]))["returned"] == 1
    assert executor.execute(_plan("find", "free text"))["results"]


def test_query_lang_executor_postprocesses_groups_and_propagates_backend_errors(monkeypatch):
    ql = load_support_module("query_lang")
    executor = ql.QueryExecutor()
    item = {"n": 5, "text": "alpha beta", "tags": ["alpha"]}
    assert executor._match_conditions(item, [
        {"key": "n", "op": "==", "value": 5},
        {"key": "n", "op": "!=", "value": 4},
        {"key": "n", "op": "<", "value": 6},
        {"key": "n", "op": ">", "value": 4},
        {"key": "n", "op": "<=", "value": 5},
        {"key": "n", "op": ">=", "value": 5},
        {"key": "text", "op": "contains", "value": "alpha"},
        {"key": "text", "op": "~", "value": "ALP"},
    ]) is True
    assert executor._match_conditions(item, [{"key": "text", "op": "~", "value": "["}]) is False
    grouped = executor._apply_postprocessing(
        [{"kind": "b", "score": 2}, {"kind": "a", "score": 1}],
        {"limit": 10, "sort_key": "score", "sort_order": "DESC", "group_key": "kind"},
    )
    assert list(grouped["grouped"]) == ["b", "a"]

    monkeypatch.setattr(ql, "_call_tool", lambda *_args, **_kwargs: {"error": True, "code": "IDA_ERROR"})
    assert executor._execute_instruction(_plan("instruction", "call"))["error"] is True
    assert executor._execute_block(_plan("block", "*"))["error"] is True
    assert executor.execute({"target": "unknown", "conditions": [], "limit": 1})["error"] is True
