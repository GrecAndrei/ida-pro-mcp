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


def test_invalidate_tool_read_cache_fallbacks(monkeypatch):
    import sys

    # Fallback to ida_mcp.sync (lines 111-114)
    cleared = []
    fake_sync = SimpleNamespace(_tool_cache=lambda: SimpleNamespace(invalidate_all=lambda: cleared.append(True)))
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.sync", None)
    monkeypatch.setitem(sys.modules, "ida_mcp.sync", fake_sync)
    code_module._invalidate_tool_read_cache()
    assert cleared == [True]

    # Neither exists (lines 113-114)
    monkeypatch.setitem(sys.modules, "ida_mcp.sync", None)
    assert code_module._invalidate_tool_read_cache() is None

    # Cache invalidate exception (lines 119-120)
    err_sync = SimpleNamespace(_tool_cache=lambda: (_ for _ in ()).throw(RuntimeError("cache fail")))
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.sync", err_sync)
    assert code_module._invalidate_tool_read_cache() is None


def test_code_dispatch_aliases_and_disasm_limits(monkeypatch, fresh_fake_idb):
    # line 300: addr given and addrs is empty string
    res = code_module.code(action="disasm", addr="0x140001000", addrs="")
    assert res.get("ok") is True

    # lines 423-426: disasm with limit not int and max_items invalid
    res2 = code_module.code(action="disasm", address="0x140001000", limit=None, max_items="invalid_int")
    assert res2.get("ok") is True

    # line 716: radius/window when func is None
    monkeypatch.setattr(code_module._compat, "get_func_info", lambda _ea: None)
    res_rad = code_module.code(action="disasm", address="0x140001080", window=4)
    assert res_rad.get("ok") is True
    assert "warning" in res_rad

    # lines 777-779: gather_function_context returns ctx and raises Exception
    monkeypatch.setattr(code_module._compat, "get_func_info", lambda ea: SimpleNamespace(start_ea=ea, end_ea=ea + 16))
    monkeypatch.setattr(code_module, "gather_function_context", lambda _ea, **_k: {"callers": 2})
    res_ctx = code_module.code(action="disasm", address="0x140001090")
    assert res_ctx.get("context") == {"callers": 2}

    monkeypatch.setattr(code_module, "gather_function_context", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("ctx fail")))
    res_ctx_fail = code_module.code(action="disasm", address="0x1400010a0")
    assert res_ctx_fail.get("ok") is True


def test_decompile_and_chain_edge_cases(monkeypatch, fresh_fake_idb):
    import ida_funcs

    class FakeCfunc:
        def __str__(self):
            return "return 0;"

    # lines 457-458: action == "decompile", func is None, prev_ea is None, next_ea is 0x140001100
    monkeypatch.setattr(code_module._compat, "get_func_info", lambda _ea: None)
    monkeypatch.setattr(code_module, "_get_prev_func", lambda _ea: None)
    monkeypatch.setattr(code_module, "_get_next_func", lambda _ea: 0x140001100)
    res_dec = code_module.code(action="decompile", address="0x140001010")
    assert res_dec.get("error") is True
    assert "0x140001100" in res_dec.get("message", "")

    # lines 471-472: thunk with calc_thunk_target raising
    func = SimpleNamespace(start_ea=0x140001020, end_ea=0x140001030)
    monkeypatch.setattr(code_module._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(code_module._compat, "get_func_flags", lambda _ea: ida_funcs.FUNC_THUNK)
    monkeypatch.setattr(code_module._compat, "calc_thunk_target", lambda _ea: (_ for _ in ()).throw(RuntimeError("thunk fail")))
    monkeypatch.setattr(code_module, "_decompile_with_diagnostics", lambda _ea: (FakeCfunc(), None))
    res_thunk = code_module.code(action="decompile", address="0x140001020")
    assert res_thunk.get("ok") is True

    # lines 486-487: thunk with demangle_name raising
    monkeypatch.setattr(code_module._compat, "calc_thunk_target", lambda _ea: 0x140002000)
    import idc
    monkeypatch.setattr(idc, "get_name", lambda _ea: "sub_thunk_target")
    import sys
    monkeypatch.setitem(sys.modules, "ida_nalt", SimpleNamespace(
        demangle_name=lambda *_a: (_ for _ in ()).throw(RuntimeError("demangle fail")),
        get_short_name_synonym=lambda: 0,
    ))
    res_demangle = code_module.code(action="decompile", address="0x140001030")
    assert "// THUNK -> 0x140002000" in res_demangle.get("code", "")

    # lines 531-534: annotation failure and outer enrichment failure
    monkeypatch.setattr(code_module._compat, "get_func_flags", lambda _ea: 0)
    monkeypatch.setattr(code_module, "_build_decompile_enrichment", lambda *_a, **_k: {"blackboard_context": [1]})
    monkeypatch.setattr(code_module, "annotate_pseudocode", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("annot fail")))
    res_ann_err = code_module.code(action="decompile", address="0x140001040", details=True)
    assert res_ann_err.get("ok") is True

    monkeypatch.setattr(code_module, "_build_decompile_enrichment", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("enrich fail")))
    res_enr_err = code_module.code(action="decompile", address="0x140001050")
    assert res_enr_err.get("ok") is True

    # lines 541-542: _decompile_with_diagnostics raising Exception
    monkeypatch.setattr(code_module, "_decompile_with_diagnostics", lambda *_a: (_ for _ in ()).throw(RuntimeError("dec crash")))
    res_dec_crash = code_module.code(action="decompile", address="0x140001060")
    assert res_dec_crash.get("error") is True
    assert "dec crash" in res_dec_crash.get("message", "")

    # line 587: decompile_chain with multiple CodeRefsTo from same caller_fn
    import idautils
    monkeypatch.setattr(idautils, "CodeRefsTo", lambda *_a: iter([0x140002000, 0x140002004]))
    monkeypatch.setattr(code_module._compat, "get_func_start", lambda _xref: 0x140002000)
    monkeypatch.setattr(code_module, "_decompile_with_diagnostics", lambda _ea: (FakeCfunc(), None))
    res_chain = code_module.code(action="decompile_chain", address="0x140001070")
    assert res_chain.get("ok") is True
    assert res_chain.get("caller_count") == 1


def test_xrefs_to_field_deep_branches(monkeypatch, fresh_fake_idb):
    import ida_typeinf
    import ida_ua
    import idautils

    # lines 940-953: ordinal scan without struct_name, get_numbered_type returning False then True
    class MockTil:
        pass

    class MockMember:
        name = "data_val"
        offset = 64
        type = "int"

    class MockTinfo:
        def __init__(self, ordinal):
            self.ordinal = ordinal
        def get_numbered_type(self, _til, ord_val):
            return ord_val == 2
        def get_type_name(self):
            return "auto_struct_t"
        def is_struct(self):
            return True
        def is_union(self):
            return False
        def get_udt_details(self, udt):
            udt.members = [MockMember()]
            return True

    class MockUDT:
        def __init__(self):
            self.members = [MockMember()]
        def __iter__(self):
            return iter(self.members)

    monkeypatch.setattr(ida_typeinf, "get_idati", MockTil)
    monkeypatch.setattr(ida_typeinf, "get_ordinal_qty", lambda _til: 3)
    monkeypatch.setattr(ida_typeinf, "tinfo_t", lambda: MockTinfo(1))
    monkeypatch.setattr(ida_typeinf, "udt_type_data_t", MockUDT)

    def mock_decode(insn, ea):
        if ea == 0x10:
            return 0  # decode_insn <= 0 (line 968)
        if ea == 0x20:
            raise RuntimeError("decode fail")  # lines 976-978
        op = SimpleNamespace(type=getattr(ida_ua, "o_displ", 4))
        insn.ops = [op]
        return 1

    monkeypatch.setattr(ida_ua, "decode_insn", mock_decode)
    monkeypatch.setattr(ida_ua, "get_operand_value", lambda _insn, _idx: 8, raising=False)

    # Part 1: decode_insn <= 0 (line 968), decode_insn raises (lines 976-978),
    # match and max_items break (lines 1006, 1008)
    monkeypatch.setattr(idautils, "Functions", lambda: iter([0x140001000, 0x140002000]))
    monkeypatch.setattr(idautils, "FuncItems", lambda _ea: iter([0x10, 0x20, 0x30]))
    res_items = code_module.code(action="xrefs_to_field", address="0x140001080", field_name="data_val", max_items=1)
    assert res_items.get("count") == 1

    # Part 2: insns_scanned >= 200000 (lines 993-994, 1010)
    monkeypatch.setattr(ida_ua, "decode_insn", lambda _insn, _ea: 0)
    monkeypatch.setattr(idautils, "Functions", lambda: iter([0x140001000, 0x140002000]))
    monkeypatch.setattr(idautils, "FuncItems", lambda _ea: range(200001))
    res_insn_trunc = code_module.code(action="xrefs_to_field", address="0x140001090", field_name="data_val")
    assert res_insn_trunc.get("truncated") is True

    # Part 3: funcs_scanned >= 5000 (lines 986-987)
    monkeypatch.setattr(idautils, "Functions", lambda: range(5001))
    monkeypatch.setattr(idautils, "FuncItems", lambda _ea: iter(()))
    res_trunc = code_module.code(action="xrefs_to_field", address="0x1400010a0", field_name="data_val", max_items=1)
    assert res_trunc.get("truncated") is True

    # lines 1036-1037: Exception searching for field
    monkeypatch.setattr(idautils, "Functions", lambda: (_ for _ in ()).throw(RuntimeError("scan crash")))
    res_scan_err = code_module.code(action="xrefs_to_field", address="0x1400010b0", field_name="data_val")
    assert res_scan_err.get("error") is True


def test_find_paths_argument_and_depth_validation(fresh_fake_idb):
    # lines 1043-1044: target required
    res_no_tgt = code_module.code(action="find_paths", address="0x140001000")
    assert res_no_tgt.get("error") is True
    assert "target required" in res_no_tgt.get("message", "")

    # lines 1048-1049: invalid target address
    res_bad_tgt = code_module.code(action="find_paths", address="0x140001000", target="not_an_ea")
    assert res_bad_tgt.get("error") is True

    # line 1063: path depth >= max_depth
    res_depth = code_module.code(action="find_paths", address="0x140001000", target="0x140001050", max_depth=1)
    assert res_depth.get("ok") is True


def test_strings_in_func_riscv_gp_branches(monkeypatch, fresh_fake_idb):
    # lines 1111-1126: RISC-V GP branches in strings_in_func when no strings found
    monkeypatch.setattr(code_module, "is_riscv_family", lambda: True)
    monkeypatch.setattr(code_module._compat, "get_func_info", lambda ea: SimpleNamespace(start_ea=ea, end_ea=ea + 8))

    # Applied GP
    cleared = []
    monkeypatch.setattr(code_module, "_invalidate_tool_read_cache", lambda: cleared.append(True))
    monkeypatch.setattr(code_module, "_detect_riscv_gp", lambda: {"found": True, "applied": True})
    res_applied = code_module.code(action="strings_in_func", address="0x140001010")
    assert res_applied.get("riscv_gp", {}).get("applied") is True
    assert cleared == [True]

    # Unresolved GP
    monkeypatch.setattr(code_module, "_detect_riscv_gp", lambda: {"found": False})
    res_unresolved = code_module.code(action="strings_in_func", address="0x140001020")
    assert "unresolved" in res_unresolved.get("note", "")

    # Exception in detect
    monkeypatch.setattr(code_module, "_detect_riscv_gp", lambda: (_ for _ in ()).throw(RuntimeError("gp fail")))
    res_gp_err = code_module.code(action="strings_in_func", address="0x140001030")
    assert res_gp_err.get("ok") is True


def test_explain_suggested_actions_and_firmware_signals(monkeypatch, fresh_fake_idb):
    # lines 1282, 1295, 1298 in smart_decompile
    class FakeCfunc:
        def __str__(self):
            return "do_work();"

    func = SimpleNamespace(start_ea=0x140001000, end_ea=0x140001010)
    monkeypatch.setattr(code_module._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(code_module, "_decompile_with_diagnostics", lambda _ea: (FakeCfunc(), None))
    monkeypatch.setattr(code_module, "_build_decompile_enrichment", lambda *_a, **_k: {
        "api_calls": [],
        "crypto_hints": [],
        "dangerous_patterns": [{"name": "strcpy"}],
        "var_rename_hints": [],
        "blackboard_context": [],
        "complexity": {"blocks": 1, "lines": 1},
    })
    # 0 callers -> line 1295
    monkeypatch.setattr(code_module, "_collect_compact_callers", lambda _ea: [])
    monkeypatch.setattr(code_module, "_collect_compact_callees", lambda _ea: [])
    monkeypatch.setattr(code_module, "_collect_function_strings", lambda _ea: [])

    res_zero = code_module.code(action="smart_decompile", address="0x140001010")
    assert res_zero.get("ok") is True
    assert any("taint(trace)" in s.get("action", "") for s in res_zero.get("suggested_next_actions", []))
    assert any("dead_end" in s.get("action", "") for s in res_zero.get("suggested_next_actions", []))

    # >= 5 callers -> line 1298
    monkeypatch.setattr(code_module, "_collect_compact_callers", lambda _ea: ["c1", "c2", "c3", "c4", "c5"])
    res_many = code_module.code(action="smart_decompile", address="0x140001020")
    assert any("xrefs_to" in s.get("action", "") for s in res_many.get("suggested_next_actions", []))

    # lines 1407, 1445 in explain
    monkeypatch.setattr(code_module, "_detect_firmware_signals", lambda _ea, _code: ["mmio_store_0x4000"])
    monkeypatch.setattr(code_module, "_collect_compact_callers", lambda _ea: [])
    res_exp = code_module.code(action="explain", address="0x140001030")
    assert res_exp.get("ok") is True
    assert "firmware_signals" in res_exp


def test_code_import_fallbacks(monkeypatch):
    import importlib
    import sys

    # lines 32-33 and 40-41
    mod = sys.modules.get("ida_pro_mcp.ida_mcp.tools.code") or sys.modules.get("ida_mcp.tools.code")
    if mod is None:
        return
    monkeypatch.setitem(sys.modules, "ida_ua", None)
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.support.arch_utils", None)
    monkeypatch.setitem(sys.modules, "ida_mcp.support.arch_utils", None)
    try:
        importlib.reload(mod)
        assert mod.ida_ua is None
        assert mod._detect_riscv_gp is None
    finally:
        monkeypatch.delitem(sys.modules, "ida_ua", raising=False)
        monkeypatch.delitem(sys.modules, "ida_pro_mcp.ida_mcp.support.arch_utils", raising=False)
        monkeypatch.delitem(sys.modules, "ida_mcp.support.arch_utils", raising=False)
        importlib.reload(mod)
