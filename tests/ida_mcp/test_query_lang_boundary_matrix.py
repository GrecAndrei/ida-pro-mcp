"""Exercise parser and executor boundaries of the embedded query language."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from _isolated_repo_loader import load_support_module  # noqa: E402


def _module():
    return load_support_module("query_lang")


def test_parser_handles_empty_noise_aliases_and_tail_clauses():
    ql = _module()
    parser = ql.QueryParser()
    assert parser.parse("") is None
    assert parser.parse("   ") is None
    assert parser._pull_limit("function *") == ("function *", 100)
    assert parser._pull_limit("function * LIMIT 7") == ("function *", 7)
    assert parser._pull_sort("function *") == ("function *", None, "ASC")
    assert parser._pull_sort("function * SORT BY size DESC") == ("function *", "size", "DESC")
    assert parser._pull_sort("function * SORT BY name") == ("function *", "name", "ASC")
    assert parser._pull_group("function *") == ("function *", None)
    assert parser._pull_group("function * GROUP BY segment") == ("function *", "segment")

    assert parser.parse("please show every function *") == {
        "limit": 100,
        "sort_key": None,
        "sort_order": "ASC",
        "group_key": None,
        "target": "function",
        "identifier": "*",
        "conditions": [],
    }
    assert parser.parse("size >= 10") ["target"] == "function"
    assert parser.parse("punctuation !!!")["target"] == "find"


@pytest.mark.parametrize(
    "query,target,identifier",
    [
        ("functions named main", "function", "*"),
        ("strings literal password", "string", "*"),
        ("calls to malloc", "call", "*"),
        ("apis from kernel32", "import", "*"),
        ("crossrefs to 0x401000", "xref", "0x401000"),
        ("mnemonic mov", "instruction", "mov"),
        ("basic_blocks at main", "block", "main"),
        ("sections named .text", "segment", "*"),
    ],
)
def test_parser_accepts_target_aliases_and_connective_words(query, target, identifier):
    plan = _module().QueryParser().parse(query)
    assert plan["target"] == target
    assert plan["identifier"] == identifier


def test_parser_accepts_quoted_identifiers_and_identifier_coercion():
    parser = _module().QueryParser()
    assert parser._extract_identifier_and_conditions('"two words" WHERE name = "x"')[0] == "two words"
    assert parser._extract_identifier_and_conditions("with *")[0] == "*"
    assert parser._extract_identifier_and_conditions("size > 4")[0] == "*"

    for target, key in ql_target_keys():
        plan = {"target": target, "identifier": "needle", "conditions": []}
        parser._coerce_identifier(plan)
        assert plan["identifier"] == "*"
        assert plan["conditions"] == [{"key": key, "op": "contains", "value": "needle"}]
    untouched = {"target": "function", "identifier": "*", "conditions": []}
    parser._coerce_identifier(untouched)
    assert untouched["conditions"] == []
    existing = {"target": "function", "identifier": "name", "conditions": [{"key": "x"}]}
    parser._coerce_identifier(existing)
    assert existing["identifier"] == "name"


def ql_target_keys():
    return [
        ("function", "name"),
        ("string", "text"),
        ("import", "name"),
        ("segment", "name"),
        ("call", "text"),
    ]


@pytest.mark.parametrize(
    "condition,expected",
    [
        ('name contains "main"', {"key": "name", "op": "contains", "value": "main"}),
        ('name like "main"', {"key": "name", "op": "contains", "value": "main"}),
        ('text matches "cmd\\.exe"', {"key": "text", "op": "~", "value": r"cmd\.exe"}),
        ("size >= 10", {"key": "size", "op": ">=", "value": 10}),
        ("size < 2.5", {"key": "size", "op": "<", "value": 2.5}),
        ('name = "main"', {"key": "name", "op": "==", "value": "main"}),
        ("size neq 3", {"key": "size", "op": "!=", "value": 3}),
    ],
)
def test_parser_condition_operator_aliases(condition, expected):
    assert _module().QueryParser()._parse_single_condition(condition) == expected


def test_parser_splits_quoted_and_mixed_condition_separators():
    parser = _module().QueryParser()
    parts = parser._split_conditions('text contains "A AND B" AND size > 3 && name = x; tag = y')
    assert parts == ['text contains "A AND B"', "size > 3", "name = x", "tag = y"]
    assert parser._parse_conditions("bad syntax") == []
    assert parser._starts_condition("size > 3") is True
    assert parser._starts_condition("literal text") is False


def test_executor_condition_matching_and_postprocessing_edges():
    ql = _module()
    executor = ql.QueryExecutor(limit="bad")
    assert executor._fetch_limit == 1000
    item = {"name": "main", "size": 10, "tags": ["api", "safe"], "text": "cmd.exe"}
    assert executor._match_conditions(item, []) is True
    for op, expected in (("==", "main"), ("!=", "other"), ("<", 11), (">", 9), ("<=", 10), (">=", 10), ("contains", "ma"), ("~", "CMD")):
        assert executor._match_conditions(item, [{"key": "name" if op in ("==", "!=", "contains") else "size" if op not in ("~",) else "text", "op": op, "value": expected}]) is True
    assert executor._match_conditions(item, [{"key": "missing", "op": "==", "value": 1}]) is False
    assert executor._match_conditions(item, [{"key": "size", "op": ">", "value": "bad"}]) is False
    assert executor._match_conditions(item, [{"key": "tags", "op": "contains", "value": "api"}]) is True
    assert executor._match_conditions(item, [{"key": "size", "op": "contains", "value": 1}]) is False
    assert executor._match_conditions(item, [{"key": "text", "op": "~", "value": "["}]) is False
    assert executor._match_conditions(item, [{"key": "name", "op": "unknown", "value": "x"}]) is True

    plan = {"limit": 1, "sort_key": "size", "sort_order": "DESC", "group_key": "name"}
    response = executor._apply_postprocessing(
        [{"name": "a", "size": 1}, {"name": "b", "size": 2}], plan, capped=True
    )
    assert response["grouped"] == {"b": [{"name": "b", "size": 2}]}
    assert response["truncated"] is True and response["total_matches"] == 2
    assert executor._apply_postprocessing([{"x": object()}], {"limit": 2, "sort_key": "x"})["ok"] is True


def test_executor_window_folding_and_arch_aliases(monkeypatch):
    ql = _module()
    executor = ql.QueryExecutor(2)
    assert executor._window_capped([], 1) is False
    assert executor._window_capped({"total": 4, "count": 2}, 2) is True
    assert executor._window_capped({"truncated": True}, 1) is True
    assert executor._window_capped({}, 2, 2) is True
    assert executor._window_capped({}, 1, 2) is False
    assert executor._fold_insn_matches("0x1 [mov]\n0x2 [ret]") == [
        {"text": "0x1 [mov]", "addr": "0x1"},
        {"text": "0x2 [ret]", "addr": "0x2"},
    ]
    assert executor._fold_insn_matches(["0x1 [mov]"])[0]["addr"] == "0x1"
    assert executor._fold_insn_matches([]) == []
    for arch, expected in (("x64", ["call"]), ("arm64", ["bl", "blr", "call"]), ("unknown", sorted(ql._CALL_MNEMONICS))):
        monkeypatch.setattr(ql, "_get_arch", lambda arch=arch: arch)
        assert executor._call_alias_set() == expected


def test_executor_delegates_all_result_shapes_and_errors(monkeypatch):
    ql = _module()
    executor = ql.QueryExecutor(2)
    responses = {}

    def call(name, **kwargs):
        responses[(name, kwargs.get("action"))] = kwargs
        return {
            ("data", "functions"): {"functions": "0x1 10 xrefs=2 xrefs_from=3 main"},
            ("data", "strings"): {"strings": "0x2 xrefs=1 secret"},
            ("data", "imports"): {"imports": "0x3 kernel32 CreateFileA"},
            ("search", "insns"): {"results": "0x4 [call]"},
            ("code", "xrefs_to"): {"xrefs": [{"addr": "0x5"}]},
            ("idb", "segments"): {"segments": [{"name": ".text"}]},
            ("search", "find"): {"ok": True, "results": [{"text": "needle"}]},
            ("code", "blocks"): {"blocks": "0x6 succs=[0x7] preds=[]"},
        }.get((name, kwargs.get("action")))

    monkeypatch.setattr(ql, "_call_tool", call)
    base = {"limit": 10, "sort_key": None, "sort_order": "ASC", "group_key": None, "conditions": []}
    assert executor._execute_function({**base, "identifier": "*"})["returned"] == 1
    assert executor._execute_string({**base, "identifier": "*"})["returned"] == 1
    assert executor._execute_import({**base, "identifier": "*"})["returned"] == 1
    assert executor._execute_call({**base, "identifier": "*"})["returned"] == 1
    assert executor._execute_instruction({**base, "identifier": "call"})["returned"] == 1
    assert executor._execute_xref({**base, "identifier": "0x1"})["returned"] == 1
    assert executor._execute_segment({**base, "identifier": "*"})["returned"] == 1
    assert executor._execute_find({**base, "identifier": "needle"})["ok"] is True
    assert executor._execute_block({**base, "identifier": "main"})["returned"] == 1
    assert executor._execute_block({**base, "identifier": "*"})["error"] is True
    assert executor.execute({"target": "missing"})["error"] is True
    assert responses[("data", "functions")]["count"] == 2


@pytest.mark.parametrize(
    "target,plan",
    [
        ("function", {"functions": None}),
        ("string", {"strings": None}),
        ("import", {"imports": None}),
    ],
)
def test_executor_normalizes_non_list_backend_shapes(monkeypatch, target, plan):
    ql = _module()
    monkeypatch.setattr(ql, "_call_tool", lambda *_args, **_kwargs: plan)
    base = {"identifier": "*", "conditions": [], "limit": 10, "sort_key": None, "sort_order": "ASC", "group_key": None}
    result = ql.QueryExecutor().execute({"target": target, **base})
    assert result["ok"] is True and result["returned"] == 0


def test_executor_propagates_backend_errors_and_query_entrypoint(monkeypatch):
    ql = _module()
    assert ql.run_query_lang("")["error"] is True
    monkeypatch.setattr(ql, "_call_tool", lambda *_args, **_kwargs: {"error": True, "code": "BACKEND"})
    plan = {"target": "instruction", "identifier": "mov", "conditions": [], "limit": 10}
    assert ql.QueryExecutor().execute(plan)["code"] == "BACKEND"
    assert ql.run_query_lang("MATCH instruction mov", limit="bad")["code"] == "BACKEND"


def test_tool_loader_and_caller_fallbacks(monkeypatch):
    ql = _module()
    # Nonexistent tool resolution and error handling
    assert ql._get_tool("nonexistent_unknown_tool_xyz") is None
    res = ql._call_tool("nonexistent_unknown_tool_xyz")
    assert res.get("error") is True
    assert "not available" in res["message"]

    # Tool that raises exception
    monkeypatch.setitem(ql._TOOL_CACHE, "exploding_tool", lambda **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    err = ql._call_tool("exploding_tool")
    assert err.get("error") is True
    assert "boom" in err["message"]


def test_parser_empty_and_extraction_edges():
    ql = _module()
    parser = ql.QueryParser()
    assert parser._parse_head_and_conditions("") is None
    assert parser._extract_target("") == (None, "")
    assert parser._extract_identifier_and_conditions("") == ("*", [])


def test_condition_evaluator_all_comparison_operators():
    ql = _module()
    executor = ql.QueryExecutor()

    # != operator returning False
    assert executor._match_conditions({"name": "main"}, [{"key": "name", "op": "!=", "value": "main"}]) is False
    assert executor._match_conditions({"name": "other"}, [{"key": "name", "op": "!=", "value": "main"}]) is True

    # < operator returning False
    assert executor._match_conditions({"size": 20}, [{"key": "size", "op": "<", "value": 10}]) is False
    assert executor._match_conditions({"size": 5}, [{"key": "size", "op": "<", "value": 10}]) is True

    # > operator returning False
    assert executor._match_conditions({"size": 5}, [{"key": "size", "op": ">", "value": 10}]) is False
    assert executor._match_conditions({"size": 20}, [{"key": "size", "op": ">", "value": 10}]) is True

    # <= operator returning False
    assert executor._match_conditions({"size": 15}, [{"key": "size", "op": "<=", "value": 10}]) is False
    assert executor._match_conditions({"size": 10}, [{"key": "size", "op": "<=", "value": 10}]) is True

    # >= operator returning False
    assert executor._match_conditions({"size": 5}, [{"key": "size", "op": ">=", "value": 10}]) is False
    assert executor._match_conditions({"size": 10}, [{"key": "size", "op": ">=", "value": 10}]) is True

    # ~ regex operator returning False
    assert executor._match_conditions({"name": "sub_1000"}, [{"key": "name", "op": "~", "value": "^crypto_"}]) is False
    assert executor._match_conditions({"name": "crypto_aes"}, [{"key": "name", "op": "~", "value": "^crypto_"}]) is True


def test_executor_handles_non_dict_and_capped_backends(monkeypatch):
    ql = _module()
    executor = ql.QueryExecutor()
    base = {"identifier": "test", "conditions": [], "limit": 10}

    # All executors returning non-dict
    monkeypatch.setattr(ql, "_call_tool", lambda *_args, **_kwargs: None)
    assert executor._execute_function(base)["error"] is True
    assert executor._execute_call(base)["error"] is True
    assert executor._execute_string(base)["error"] is True
    assert executor._execute_import(base)["error"] is True
    assert executor._execute_instruction(base)["error"] is True
    assert executor._execute_xref(base)["error"] is True
    assert executor._execute_segment(base)["error"] is True
    assert executor._execute_find(base)["error"] is True
    assert executor._execute_find({**base, "limit": "bad"})["error"] is True
    assert executor._execute_block({**base, "identifier": "main"})["error"] is True

    # _execute_block with blocks not a string and not a list
    monkeypatch.setattr(ql, "_call_tool", lambda *_args, **_kwargs: {"blocks": 12345})
    res_block = executor._execute_block({**base, "identifier": "main"})
    assert res_block["ok"] is True
    assert res_block["returned"] == 0

    # _execute_call hitting the 200 call cap across patterns
    fake_calls = [{"addr": hex(0x401000 + i * 4), "text": f"call sub_{i}"} for i in range(210)]
    monkeypatch.setattr(ql, "_call_tool", lambda *_args, **_kwargs: {"ok": True, "results": fake_calls})
    call_res = executor._execute_call(base)
    assert call_res["ok"] is True
    assert call_res.get("truncated") is True


def test_run_query_lang_uninterpretable_query(monkeypatch):
    ql = _module()
    monkeypatch.setattr(ql.QueryParser, "parse", lambda self, q: None)
    res = ql.run_query_lang("some uninterpretable string")
    assert res.get("error") is True
    assert "query could not be interpreted" in res["message"]


def test_fallback_globals_stubs():
    ql = _module()
    # Exercise fallback stubs if defined
    tool_fn = ql.tool(lambda: 42)
    assert tool_fn() == 42
    idaread_fn = ql.idaread(lambda: 43)
    assert idaread_fn() == 43
    err = ql.make_error("TEST_CODE", "test message")
    assert err["code"] == "TEST_CODE"
    assert ql.MCPError.INVALID_ARGS == "INVALID_ARGS"
