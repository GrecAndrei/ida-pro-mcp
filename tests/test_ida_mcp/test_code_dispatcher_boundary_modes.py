"""Boundary and fallback coverage for the composed code dispatcher."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ida_pro_mcp.ida_mcp.tools.code import code

code_module = __import__("ida_pro_mcp.ida_mcp.tools.code", fromlist=["*"])


def _error(result):
    assert result.get("error") is True, result
    return result


def test_missing_function_modes_return_consistent_errors(fresh_fake_idb):
    """A data address must fail consistently across all function workflows."""
    for action in (
        "decompile",
        "decompile_chain",
        "blocks",
        "callgraph",
        "export",
        "strings_in_func",
        "semantic_decompile",
        "decomp_dataflow",
        "smart_decompile",
        "explain",
        "trace_argument_origin",
    ):
        result = code(action=action, address="0x140002000")
        assert result["error"] is True, (action, result)
        assert result.get("code")

    assert code(action="callees", address="0x140002000")["error"] is True
    assert code(action="diff_functions", addrs=["0x140001000"])["error"] is True
    assert code(action="xrefs_to_field", address="0x140001000")["error"] is True
    assert code(action="unknown", address="0x140001000")["error"] is True
    assert code(action="disasm")["error"] is True


def test_disassembly_range_validation_and_raw_modes(monkeypatch, fresh_fake_idb):
    """Raw, bounded, and malformed range requests stay distinct."""
    assert _error(code(action="disasm", address="0x140001000", end="bad"))
    assert _error(code(action="disasm", address="0x140001000", end="0x140001000"))
    assert _error(code(action="disasm", address="0x140001000", window="bad"))
    assert _error(code(action="disasm", address="0x140001000", window=1, structured=True))

    raw = code(
        action="disasm",
        address="0x140003000",
        end="0x140003020",
        style="annotated",
        include_bytes=True,
        include_comments=True,
        annotate_branches=True,
    )
    assert raw["ok"] is True
    assert raw["warning"].startswith("Address is not within")
    assert raw["range"] == "0x140003000-0x140003020"

    monkeypatch.setattr(code_module, "_disasm_window", lambda *_args, **_kwargs: [])
    empty = code(action="disasm", address="0x140001000", window=0)
    assert empty["ok"] is True
    assert empty["count"] == 0
    assert empty["range"] == "0x140001000-0x140001000"


def test_decompile_failures_are_preserved_across_composed_actions(monkeypatch, fresh_fake_idb):
    failure = {
        "error": True,
        "code": "DECOMPILER_FAILED",
        "category": "hexrays",
        "message": "Hex-Rays refused this function",
        "hint": "Open the function in IDA first",
        "details": {"reason": "test"},
    }
    monkeypatch.setattr(code_module, "_decompile_with_diagnostics", lambda _ea: (None, failure))

    for action in ("decompile", "decompile_chain", "semantic_decompile", "decomp_dataflow", "smart_decompile"):
        result = code(action=action, address="0x140001000")
        assert result["error"] is True, (action, result)
        assert result["category"] == "hexrays"
        assert result["details"] == {"reason": "test"}

    explained = code(action="explain", address="0x140001000")
    assert explained["error"] is True
    assert explained["message"].startswith("Decompilation failed")

    diff = code(action="diff_functions", addrs=["0x140001000", "0x140001050"])
    assert diff["error"] is True
    assert diff["code"] == "DECOMPILER_FAILED"

    def raises(_ea):
        raise RuntimeError("decompiler crashed")

    monkeypatch.setattr(code_module, "_decompile_with_diagnostics", raises)
    chain = code(action="decompile_chain", address="0x140001000")
    assert chain["error"] is True
    assert chain["details"]["exception_type"] == "RuntimeError"


def test_field_xrefs_and_path_modes_use_structured_operands(monkeypatch, fresh_fake_idb):
    import ida_ua
    import idautils
    import idc

    class Operand:
        type = ida_ua.o_displ

    class Instruction:
        def __init__(self):
            self.ops = []

    monkeypatch.setattr(ida_ua, "insn_t", Instruction, raising=False)

    def decode(insn, _ea):
        insn.ops = [Operand()]
        return 1

    monkeypatch.setattr(ida_ua, "decode_insn", decode, raising=False)
    monkeypatch.setattr(ida_ua, "get_operand_value", lambda *_args: 8, raising=False)
    monkeypatch.setattr(idc, "generate_disasm_line", lambda *_args: "mov rax, [rcx+8]", raising=False)
    monkeypatch.setattr(idautils, "Functions", lambda: iter([0x140001000]), raising=False)
    monkeypatch.setattr(idautils, "FuncItems", lambda _ea: iter([0x140001008]), raising=False)

    found = code(action="xrefs_to_field", address="0x140001000", field_name="target_struct.name_ptr")
    assert found["ok"] is True
    assert found["struct"] == "target_struct"
    assert found["offset"] == 8
    assert found["xrefs"][0]["ea"] == "0x140001008"

    missing_target = code(action="find_paths", address="0x140001000", target="0x140003000")
    assert missing_target["ok"] is True
    assert missing_target["paths"] == []

    monkeypatch.setattr(idautils, "XrefsFrom", lambda *_args: iter([SimpleNamespace(to=0x140001050, iscode=True)]), raising=False)
    reachable = code(action="find_paths", address="0x140001000", target="0x140001050", max_depth=3)
    assert reachable["ok"] is True
    assert reachable["paths"]


def test_decompile_all_empty_and_exception_modes(monkeypatch, fresh_fake_idb):
    import ida_funcs
    import idautils

    monkeypatch.setattr(idautils, "Functions", lambda: iter(()), raising=False)
    empty = code(action="decompile_all", query="does-not-exist", offset="bad", limit="bad")
    assert empty["ok"] is True
    assert empty["results"] == []
    assert empty["total_matched"] == 0

    monkeypatch.setattr(idautils, "Functions", lambda: iter([0x140001000, 0x140001050]), raising=False)
    monkeypatch.setattr(ida_funcs, "get_func_name", lambda ea: "main" if ea == 0x140001000 else "helper", raising=False)
    monkeypatch.setattr(code_module, "_decompile_with_diagnostics", lambda _ea: (_ for _ in ()).throw(RuntimeError("boom")))
    result = code(action="decompile_all", limit=2, mode="full")
    assert result["ok"] is True
    assert len(result["results"]) == 2
    assert all(item["error"] is True for item in result["results"])


@pytest.mark.parametrize(
    "action,kwargs",
    [
        ("find_paths", {}),
        ("diff_functions", {"addrs": ["0x140001000", "bad"]}),
        ("strings_in_func", {"address": "0x140003000"}),
        ("xrefs_to_field", {"address": "0x140001000", "field_name": "missing"}),
    ],
)
def test_composed_argument_failures_are_actionable(action, kwargs, fresh_fake_idb):
    result = code(action=action, **kwargs)
    assert result.get("error") is True or result.get("ok") is True or result.get("xrefs") == []
    if result.get("error") is True:
        assert result.get("message")
