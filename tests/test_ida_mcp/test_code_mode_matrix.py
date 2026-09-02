"""Cross-mode coverage for the high-level code dispatcher."""

from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest

from ida_pro_mcp.ida_mcp.tools.code import code

code_module = importlib.import_module("ida_pro_mcp.ida_mcp.tools.code")


class _Cfunc:
    def __str__(self):
        return "int main(int argc) { return argc + 1; }"


class _Block:
    def __init__(self, start, end, succs=(), preds=()):
        self.start_ea = start
        self.end_ea = end
        self._succs = list(succs)
        self._preds = list(preds)

    def succs(self):
        return iter(self._succs)

    def preds(self):
        return iter(self._preds)


def _assert_ok(result):
    assert result.get("ok") is True, result
    return result


def _assert_success(result):
    assert result.get("error") is not True, result
    return result


def _install_shared_code_fakes(monkeypatch):
    import idautils

    cfunc = _Cfunc()
    monkeypatch.setattr(code_module, "_decompile_with_diagnostics", lambda _ea: (cfunc, None))
    monkeypatch.setattr(code_module._compat, "get_prototype_string", lambda _ea: "int main(int argc)")
    monkeypatch.setattr(code_module, "_build_function_structure_summary", lambda *_args, **_kwargs: {"blocks": 1})
    monkeypatch.setattr(
        code_module,
        "_build_decompile_enrichment",
        lambda *_args, **_kwargs: {
            "api_calls": ["recv", "strcpy"],
            "dangerous_patterns": ["strcpy"],
            "crypto_hints": ["AES"],
            "var_rename_hints": [{"var": "v1", "suggested": "buf"}],
            "blackboard_context": [],
            "complexity": {"blocks": 1},
        },
    )
    monkeypatch.setattr(code_module, "annotate_pseudocode", lambda pseudo, *_args, **_kwargs: pseudo + "\n// annotated")
    monkeypatch.setattr(code_module, "_compute_cfg_semantics", lambda *_args: {"edges": 1})
    monkeypatch.setattr(code_module, "_build_decompiler_dataflow", lambda *_args, **_kwargs: {"edges": [{"from": "a", "to": "b", "kind": "data"}]})
    monkeypatch.setattr(code_module, "_semantic_pseudocode_summary", lambda _pseudo: "adds one")
    monkeypatch.setattr(code_module, "_collect_compact_callers", lambda _ea: [{"addr": "0x1", "name": "caller"}])
    monkeypatch.setattr(code_module, "_collect_compact_callees", lambda _ea: [{"addr": "0x2", "name": "callee"}])
    monkeypatch.setattr(code_module, "_collect_function_strings", lambda _ea: ["hello"])
    monkeypatch.setattr(code_module, "_collect_function_string_entries", lambda *_args, **_kwargs: [{"addr": "0x140002010", "value": "hello"}])
    monkeypatch.setattr(code_module, "_detect_firmware_signals", lambda *_args: [])
    monkeypatch.setattr(code_module, "_trace_argument_origin", lambda *_args: {"ok": True, "origin": "caller"})
    monkeypatch.setattr(code_module, "_disasm_window", lambda *_args, **_kwargs: ["0x140001000: push rbp"])
    monkeypatch.setattr(code_module, "_disasm_range", lambda *_args, **_kwargs: ["0x140001000: ret"])
    monkeypatch.setattr(code_module, "_disasm_range_structured", lambda *_args: [{"addr": "0x140001000", "mnemonic": "ret"}])
    monkeypatch.setattr(idautils, "CodeRefsTo", lambda *_args: iter([0x140001050]), raising=False)
    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda *_args: iter([SimpleNamespace(to=0x140001050, iscode=True, type=1)]), raising=False)
    monkeypatch.setattr(idautils, "FuncItems", lambda _ea: iter([0x140001000, 0x140001008]), raising=False)
    return cfunc


def test_decompile_chain_and_enriched_decompile_modes(monkeypatch, fresh_fake_idb):
    _install_shared_code_fakes(monkeypatch)
    # Keep the caller/callee collection on the scalar EA path.  This also
    # exercises the public code dispatcher without coupling the test to a
    # particular fake ``ida_funcs`` object shape.
    monkeypatch.setattr(code_module._compat, "get_func_start", int)
    import idautils
    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda *_args: iter([0x140001080]), raising=False)
    normal = _assert_ok(code(action="decompile", address="0x140001000", details=False))
    assert normal["code"]
    assert "var_rename_hints" not in normal
    detailed = _assert_ok(code(action="decompile", address="0x140001000", details=True))
    assert detailed["annotated_code"]
    chain = _assert_ok(code(action="decompile_chain", address="0x140001000", max_depth=20))
    assert chain["caller_count"] == 1
    assert chain["callee_count"] == 1
    missing = code(action="decompile", address="0x140002000")
    assert missing["error"] is True
    assert code(action="decompile", address="bad")["error"] is True


def test_disasm_xrefs_graph_export_paths_and_strings(monkeypatch):
    import idaapi
    import idautils

    _install_shared_code_fakes(monkeypatch)
    block_a = _Block(0x140001000, 0x140001010)
    block_b = _Block(0x140001010, 0x140001020, [block_a], [block_a])
    block_a._succs = [block_b]
    block_a._preds = [block_b]
    monkeypatch.setattr(code_module._compat, "get_flow_chart", lambda _ea: [block_a, block_b])
    monkeypatch.setattr(idautils, "XrefsTo", lambda *_args: iter([SimpleNamespace(frm=0x140001050, iscode=True)]), raising=False)
    monkeypatch.setattr(idautils, "XrefsFrom", lambda *_args: iter([SimpleNamespace(to=0x140001050, iscode=True, type=idaapi.fl_CN)]), raising=False)

    window = _assert_ok(code(action="disasm", address="0x140001000", window=2, style="classic"))
    assert window["window"] == 2
    assert code(action="disasm", address="0x140001000", window=2, structured=True)["error"] is True
    assert code(action="disasm", address="0x140001000", window=-1)["error"] is True
    structured = _assert_ok(code(action="disasm", address="0x140001000", structured=True))
    assert structured["instructions"]
    assert _assert_ok(code(action="disasm", address="0x140001000"))["disasm"]
    raw = _assert_ok(code(action="disasm", address="0x140002000", end="0x140002020", structured=True))
    assert raw["instructions"]

    for action in ("xrefs_to", "xrefs_from", "callees", "callers", "blocks", "callgraph"):
        result = _assert_ok(code(action=action, address="0x140001000"))
        assert result["addr"]
    for fmt, key in (("c_header", "header"), ("prototypes", "prototype"), ("json", "name")):
        result = _assert_success(code(action="export", address="0x140001000", format=fmt))
        assert key in result
    paths = _assert_ok(code(action="find_paths", address="0x140001000", target="0x140001050"))
    assert paths["paths"]
    strings = _assert_ok(code(action="strings_in_func", address="0x140001000"))
    assert strings["count"] == 1


def test_field_diff_semantic_smart_explain_trace_and_detect(monkeypatch, fresh_fake_idb):
    import idautils

    _install_shared_code_fakes(monkeypatch)
    diff = _assert_ok(code(action="diff_functions", addrs=["0x140001000", "0x140001050"]))
    assert "similarity" in diff
    assert code(action="diff_functions", addrs=["0x140001000"])["error"] is True
    semantic = _assert_ok(code(action="semantic_decompile", address="0x140001000"))
    assert semantic["semantic_summary"] == "adds one"
    flow = _assert_ok(code(action="decomp_dataflow", address="0x140001000"))
    assert flow["count"] == 1
    smart = _assert_ok(code(action="smart_decompile", address="0x140001000"))
    assert "dangerous" in smart["behavior_tags"]
    explain = _assert_ok(code(action="explain", address="0x140001000"))
    assert "Purpose:" in explain["summary"]
    traced = _assert_ok(code(action="trace_argument_origin", address="0x140001000", arg_index=1))
    assert traced["origin"] == "caller"

    monkeypatch.setattr(code_module, "_run_custom_detector", lambda *_args: {"ok": True, "matches": [{"addr": "0x140001000"}]})
    detected = _assert_ok(code(action="detect", rule_type="xor_threshold", threshold=2))
    assert detected["matches"]
    monkeypatch.setattr(idautils, "FuncItems", lambda _ea: iter([0x140001000]), raising=False)
    missing_field = _assert_success(code(action="xrefs_to_field", address="0x140001000", field_name="Missing.field"))
    assert missing_field["xrefs"] == []


def test_decompile_all_listing_full_and_public_argument_aliases(monkeypatch, fresh_fake_idb):
    _install_shared_code_fakes(monkeypatch)
    listing = _assert_ok(code(action="decompile_all", limit=1, mode="listing", query="main"))
    assert listing["mode"] == "listing"
    assert listing["returned"] == 1
    full = _assert_ok(code(action="decompile_all", limit=2, mode="full"))
    assert full["results"]
    assert full["total_matched"] >= 2
    assert code(action="decompile_all", offset="not-an-int")["ok"] is True
    assert code(action="unknown", address="0x140001000")["error"] is True


def test_decompile_all_pagination_and_failure_envelopes(monkeypatch, fresh_fake_idb):
    import ida_funcs
    import idautils

    names = {0x140001000: "alpha", 0x140001010: "beta", 0x140001020: "alpha_two"}
    monkeypatch.setattr(idautils, "Functions", lambda: iter(names), raising=False)
    monkeypatch.setattr(ida_funcs, "get_func_name", lambda ea: names[ea], raising=False)
    # Invalid max_items is normalized to the safe fallback budget, while an
    # offset beyond the match set returns honest empty-page metadata.
    empty = _assert_ok(code(action="decompile_all", max_items="not-an-int", offset=99))
    assert empty["returned"] == 0 and empty["total_matched"] == 3

    calls = iter([
        (None, {"code": "DECOMPILER_FAILED", "category": "runtime", "message": "too large"}),
        (None, None),
        (_Cfunc(), None),
    ])
    monkeypatch.setattr(code_module, "_decompile_with_diagnostics", lambda _ea: next(calls))
    result = _assert_ok(code(action="decompile_all", limit=3, mode="full"))
    assert result["count"] == 3
    assert result["results"][0]["error"] is True
    assert result["results"][1]["error"] is True
    assert result["results"][2]["code"]

def test_decompile_thunk_and_chain_skips_invalid_duplicate_context(monkeypatch, fresh_fake_idb):
    import ida_funcs
    import ida_nalt
    import idautils
    import idc

    fn = SimpleNamespace(start_ea=0x140001000, end_ea=0x140001020)
    monkeypatch.setattr(code_module._compat, "get_func_info", lambda _ea: fn)
    monkeypatch.setattr(code_module._compat, "get_func_flags", lambda _ea: ida_funcs.FUNC_THUNK)
    monkeypatch.setattr(code_module._compat, "calc_thunk_target", lambda _ea: 0x140002000)
    monkeypatch.setattr(code_module._compat, "get_prototype_string", lambda _ea: "int thunk(void)")
    monkeypatch.setattr(idc, "get_name", lambda _ea: "real_impl(int)" if _ea == 0x140002000 else "thunk")
    monkeypatch.setattr(ida_nalt, "demangle_name", lambda name, _style: name, raising=False)
    monkeypatch.setattr(ida_nalt, "get_short_name_synonym", lambda: 0, raising=False)
    monkeypatch.setattr(code_module, "_decompile_with_diagnostics", lambda _ea: (_Cfunc(), None))
    monkeypatch.setattr(code_module, "_build_function_structure_summary", lambda *_args, **_kwargs: {})
    thunk = _assert_ok(code(action="decompile", address="0x140001000"))
    assert "THUNK -> 0x140002000 (real_impl)" in thunk["code"]

    refs = [
        SimpleNamespace(frm=0x140003000),
        SimpleNamespace(frm=0x140003000),
        SimpleNamespace(frm=0x140004000),
        SimpleNamespace(frm=0x140005000),
    ]
    monkeypatch.setattr(idautils, "CodeRefsTo", lambda *_args: iter(refs), raising=False)
    monkeypatch.setattr(idautils, "FuncItems", lambda _ea: iter([0x140001000]), raising=False)
    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda *_args: iter([
        SimpleNamespace(to=0x140006000), SimpleNamespace(to=0x140006000),
        SimpleNamespace(to=0x140007000),
    ]), raising=False)
    def func_start(ea):
        ea = getattr(ea, "frm", getattr(ea, "to", ea))
        return None if ea in {0x140005000, 0x140007000} else ea

    monkeypatch.setattr(code_module._compat, "get_func_start", func_start)
    chain = _assert_ok(code(action="decompile_chain", address="0x140001000", max_depth=1))
    assert chain["caller_count"] == 2
    assert chain["callee_count"] == 1


def test_disasm_cross_mode_errors_raw_address_and_riscv_gp(monkeypatch, fresh_fake_idb):
    import idautils

    _install_shared_code_fakes(monkeypatch)
    monkeypatch.setattr(code_module, "is_riscv_family", lambda: True)
    monkeypatch.setattr(code_module, "_detect_riscv_gp", lambda: {"gp": "0x7000", "source": "test"})
    assert code(action="disasm", address="0x140001000", end="bad")["error"] is True
    assert code(action="disasm", address="0x140001000", end="0x140000000")["error"] is True
    assert code(action="disasm", address="0x140001000", window="bad")["error"] is True
    assert code(action="disasm", address="0x140001000", window=1, structured=True)["error"] is True
    assert code(action="disasm", address="0x140001000", window=1)["riscv_gp"]

    monkeypatch.setattr(code_module._compat, "get_func_info", lambda _ea: None)
    monkeypatch.setattr(code_module, "_disasm_range_structured", lambda *_args: [{"addr": "0x1"}])
    raw = _assert_ok(code(action="disasm", address="0x140003000", end="0x140003010", structured=True))
    assert raw["instructions"] == [{"addr": "0x1"}]
    monkeypatch.setattr(idautils, "XrefsTo", lambda *_args: iter(()), raising=False)


def test_explain_exercises_api_purpose_and_string_modes(monkeypatch, fresh_fake_idb):
    import idaapi
    import idautils
    import idc

    fn = SimpleNamespace(start_ea=0x140001000, end_ea=0x140001010)
    pseudo = (
        "recv socket connect bind listen accept fopen fread fwrite CreateFile open read "
        "malloc VirtualAlloc mmap system exec execve popen CreateProcess CryptEncrypt "
        "AES_encrypt SHA256_Update MD5_Update HMAC RegSetValue RegOpenKey memcpy memset "
        "strcpy strncpy sprintf snprintf gets scanf sscanf vsprintf"
    )
    monkeypatch.setattr(code_module._compat, "get_func_info", lambda _ea: fn)
    monkeypatch.setattr(code_module, "_decompile_with_diagnostics", lambda _ea: (pseudo, None))
    monkeypatch.setattr(code_module._compat, "get_prototype_string", lambda _ea: "void handler(void)")
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "handler", raising=False)
    monkeypatch.setattr(idautils, "XrefsTo", lambda *_args: iter([SimpleNamespace(iscode=True)]), raising=False)
    monkeypatch.setattr(idautils, "FuncItems", lambda _ea: iter([0x140001000]), raising=False)
    monkeypatch.setattr(idautils, "XrefsFrom", lambda *_args: iter([
        SimpleNamespace(type=idaapi.fl_CN, to=0x140002000),
        SimpleNamespace(type=idaapi.fl_CF, to=0x140002004),
    ]), raising=False)
    monkeypatch.setattr(idc, "get_name", lambda ea: f"callee_{ea:x}", raising=False)
    monkeypatch.setattr(idc, "get_strlit_contents", lambda _ea: b"important-string", raising=False)
    monkeypatch.setattr(code_module._compat, "get_flow_chart", lambda _ea: [object(), object()])
    monkeypatch.setattr(code_module, "_detect_firmware_signals", lambda *_args: [])
    result = _assert_ok(code(action="explain", address="0x140001000"))
    assert len(result["purpose"]) >= 8
    assert result["dangerous_calls"]
    assert "Key strings" in result["summary"]
