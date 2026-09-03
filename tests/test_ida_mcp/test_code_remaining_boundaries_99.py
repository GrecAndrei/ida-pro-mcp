"""Boundary coverage for composed code-dispatcher modes."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

code_module = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code")


def _ok(result):
    assert result.get("ok") is True, result
    return result


def test_decompile_all_listing_and_non_dict_failure_entries(monkeypatch, fresh_fake_idb):
    import ida_funcs
    import idautils

    funcs = [0x140001000, 0x140001050, 0x140001080]
    monkeypatch.setattr(idautils, "Functions", lambda: iter(funcs), raising=False)
    monkeypatch.setattr(ida_funcs, "get_func_name", lambda ea: f"fn_{ea:x}", raising=False)
    monkeypatch.setattr(
        code_module._compat,
        "get_func_info",
        lambda ea: SimpleNamespace(start_ea=ea, end_ea=ea + 16),
    )
    monkeypatch.setattr(code_module._compat, "get_prototype_string", lambda _ea: "int fn(void)")
    listing = _ok(code_module.code(action="decompile_all", mode="listing", limit="bad", offset="bad"))
    assert listing["returned"] == 3
    assert listing["results"][0]["mode"] == "listing"

    outcomes = iter([(None, None), (None, {"message": "refused"}), (None, None)])
    monkeypatch.setattr(code_module, "_decompile_with_diagnostics", lambda _ea: next(outcomes))
    full = _ok(code_module.code(action="decompile_all", mode="full", limit=3))
    assert all(item["error"] is True for item in full["results"])
    assert full["results"][0]["code"]
    assert full["results"][1]["message"] == "refused"


def test_code_disasm_and_missing_function_paths_handle_bad_limits(monkeypatch, fresh_fake_idb):
    monkeypatch.setattr(code_module, "is_riscv_family", lambda: True)
    monkeypatch.setattr(code_module, "_detect_riscv_gp", lambda: (_ for _ in ()).throw(RuntimeError("gp")))
    monkeypatch.setattr(code_module, "_disasm_range", lambda *_args, **_kwargs: ["0x140003000: db 0"])
    raw = _ok(
        code_module.code(
            action="disasm",
            address="0x140003000",
            end="0x140003010",
            limit="not-an-int",
        )
    )
    assert raw["warning"].startswith("Address is not within")

    monkeypatch.setattr(code_module._compat, "get_func_info", lambda _ea: None)
    monkeypatch.setattr(code_module, "_get_prev_func", lambda _ea: 0x140001000)
    monkeypatch.setattr(code_module, "_get_next_func", lambda _ea: 0x140001100)
    previous = code_module.code(action="decompile", address="0x140001080")
    assert previous["error"] is True and "0x140001000" in previous["message"]
    monkeypatch.setattr(code_module, "_get_prev_func", lambda _ea: None)
    following = code_module.code(action="decompile_chain", address="0x140001080")
    assert following["error"] is True and "0x140001100" in following["message"]


def test_code_graph_xref_and_block_limits_are_bounded(monkeypatch, fresh_fake_idb):
    import idaapi
    import idautils

    xrefs = [SimpleNamespace(frm=0x140001050, to=0x140001000, iscode=True, type=idaapi.fl_CN)]
    monkeypatch.setattr(idautils, "XrefsTo", lambda *_args: iter(xrefs), raising=False)
    monkeypatch.setattr(idautils, "XrefsFrom", lambda *_args: iter(xrefs), raising=False)
    monkeypatch.setattr(idautils, "FuncItems", lambda _ea: iter([0x140001000, 0x140001004]), raising=False)
    monkeypatch.setattr(code_module._compat, "get_func_start", lambda ea: ea)
    assert _ok(code_module.code(action="xrefs_to", address="0x140001000", max_items=0))["count"] == 0
    assert _ok(code_module.code(action="xrefs_from", address="0x140001000", max_items=0))["count"] == 0

    block = SimpleNamespace(start_ea=0x140001000, end_ea=0x140001008, succs=lambda: iter(()), preds=lambda: iter(()))
    monkeypatch.setattr(code_module._compat, "get_flow_chart", lambda _ea: [block, block])
    assert _ok(code_module.code(action="blocks", address="0x140001000", max_items=1))["count"] == 1
    assert _ok(code_module.code(action="callgraph", address="0x140001000", max_depth=0))["edges"] == ""


def test_code_field_xrefs_fail_closed_without_instruction_decoder(monkeypatch, fresh_fake_idb):
    import idautils

    record = fresh_fake_idb.type_lib.get("target_struct")
    assert record is not None
    monkeypatch.setattr(code_module, "ida_ua", None)
    monkeypatch.setattr(idautils, "Functions", lambda: iter([0x140001000]), raising=False)
    monkeypatch.setattr(idautils, "FuncItems", lambda _ea: iter([0x140001004]), raising=False)
    result = _ok(
        code_module.code(
            action="xrefs_to_field",
            address="0x140001000",
            field_name="target_struct.name_ptr",
        )
    )
    assert result["xrefs"] == []
    assert result["offset"] == 8


def test_code_cache_invalidation_and_error_envelopes(monkeypatch):
    cache = SimpleNamespace(cleared=False, invalidate_all=lambda: setattr(cache, "cleared", True))
    sync = SimpleNamespace(_tool_cache=lambda: cache)
    monkeypatch.setitem(__import__("sys").modules, "ida_pro_mcp.ida_mcp.sync", sync)
    code_module._invalidate_tool_read_cache()
    assert cache.cleared is True
    assert code_module._decompile_error_entry("0x1", None)["error"] is True
    assert code_module._decompile_error_entry("0x1", {"message": "bad", "hint": "retry"})["hint"] == "retry"


def test_code_public_aliases_and_unexpected_dispatch_errors(monkeypatch, fresh_fake_idb):
    monkeypatch.setattr(code_module, "normalize_list_input", lambda _value: (_ for _ in ()).throw(RuntimeError("normalizer")))
    result = code_module.code(action="xrefs_to", address="0x140001000")
    assert result["error"] is True

    monkeypatch.setattr(code_module, "normalize_list_input", lambda value: [value] if not isinstance(value, list) else value)
    assert code_module.code(action="unknown", address="0x140001000")["error"] is True
