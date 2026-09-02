"""Search helpers exercised at the shared boundary used by every search mode."""

from __future__ import annotations

from inspect import unwrap
from types import SimpleNamespace

import pytest

from ida_pro_mcp.ida_mcp.tools.search import basic, code as search_code, core, search


def test_core_cache_timeout_pagination_and_response_shapes(monkeypatch):
    core._SEARCH_CACHE.clear()
    monkeypatch.setattr(core, "_MAX_CACHE_SIZE", 2)
    core._cache_set("a", 1)
    core._cache_set("b", 2)
    core._cache_set("c", 3)
    assert core._cache_get("a") is None
    assert core._cache_get("c") == 3
    assert core.clip_text("  one\n two  ", 20) == "one two"
    assert core.clip_text("x" * 10, 6) == "xxx..."
    page, total, truncated = core.paginate_records([{"v": 2}, {"v": 1}], 0, 1, lambda x: x["v"])
    assert page == [{"v": 2}] and total == 2 and truncated
    assert core._match_size_rule(15, ">", 10, None)
    assert core._match_size_rule(15, ">", 10, 20)
    assert core._match_size_rule(15, "<", 20, None)
    assert core._match_size_rule(15, "==", 10, 20)
    response = core.normalize_search_result({"matches": "0x1000  hit\nplain"}, action="bytes", query="90")
    assert response["results"] == response["matches"]
    assert response["items"][0]["addr"] == "0x1000"
    assert core.make_item(addr=0x1000, name="main", score="0.8", snippet="a\n b")["score"] == 0.8
    assert core._item_from_text_line("not an address")["line"] == "not an address"
    assert core.looks_like_identifier("main")
    assert not core.looks_like_identifier("48 89 e5")
    assert core.looks_like_identifier("ns::Thing")
    timeout = core.SearchTimeout(1)
    assert timeout.deadline is not None
    monkeypatch.setattr(core._time, "time", lambda: timeout.deadline + 1)
    assert timeout.is_expired()
    with pytest.raises(TimeoutError):
        timeout.check()


def test_core_resolution_demangle_riscv_and_safe_api_fallbacks(monkeypatch, fresh_fake_idb):
    exact = core.resolve_target("0x140001000", require_function=True)
    assert exact[0] == 0x140001000 and exact[2]["match"] == "address"
    named = core.resolve_target("main", require_function=True)
    assert named[0] == 0x140001000
    unique = core.resolve_target("helper", require_function=True)
    assert unique[0] == 0x140001050
    missing = core.resolve_target("does_not_exist")
    assert missing[0] == fresh_fake_idb.BADADDR if hasattr(fresh_fake_idb, "BADADDR") else missing[0] != 0x140001000

    class _Insn:
        def __init__(self, mnem, ops, ea=0x20):
            self._mnem = mnem
            self.ops = ops
            self.ea = ea

        def get_canon_mnem(self):
            return self._mnem

    import ida_ua
    reg = SimpleNamespace(type=ida_ua.o_reg, reg=5)
    imm = SimpleNamespace(type=ida_ua.o_imm, value=0x123)
    lui = _Insn("lui", [reg, imm])
    addi = _Insn("addi", [reg, reg, SimpleNamespace(type=ida_ua.o_imm, value=0xFFF)])
    assert core.riscv_lui_addi_pair(lui, addi) == (0x122FFF, 0x20)
    assert core.riscv_lui_addi_pair(_Insn("mov", [reg, imm]), addi) is None
    assert core._sign_extend_12(0x800) == -2048
    assert core.safe_generate_disasm_line(0x140001000)
    assert core.safe_generate_disasm_line(core.idaapi.BADADDR) is None
    assert core.safe_get_strlit_contents(0x140002010) == "sample_name"
    assert core.build_constant_db()


def test_search_byte_instruction_and_text_modes_on_c_and_raw_ranges(monkeypatch, fresh_fake_idb):
    fresh_fake_idb.patch_bytes(0x140001100, b"\x90\x90\xcc\x41\x42\x43")
    class _Pattern:
        pass

    monkeypatch.setattr(basic.ida_bytes, "compiled_binpat_vec_t", _Pattern, raising=False)
    monkeypatch.setattr(basic.ida_bytes, "BIN_SEARCH_FORWARD", 0, raising=False)
    monkeypatch.setattr(basic.ida_bytes, "parse_binpat_str", lambda *_args: 0, raising=False)
    monkeypatch.setattr(
        basic.ida_bytes,
        "bin_search",
        lambda start, *_args: (0x140001100, 0) if start <= 0x140001100 else (basic.idaapi.BADADDR, 0),
        raising=False,
    )
    bytes_result = basic.search_bytes("90 90", None, None, True, 0, 10)
    assert bytes_result["ok"] is True
    assert "0x140001100" in bytes_result["results"]
    assert basic.search_string("sample_name", False, True, 0, 10)["ok"] is True
    assert basic.search_immediate("0x20", None, None, True, 0, 10)["ok"] is True
    assert basic.search_name("main", False, 0, 10)["ok"] is True
    assert search_code.search_insns("push,mov", None, None, True, 0, 10)["ok"] is True
    assert search_code.search_text("call", False, None, None, True, 0, 10)["ok"] is True
    assert search_code.search_operand("rbp", False, None, None, True, 0, 10)["ok"] is True
    fresh_fake_idb.set_cmt(0x140001000, "interesting", 0)
    assert search_code.search_comment("interesting", False, None, None, 0, 10)["ok"] is True


def test_search_router_public_aliases_intents_and_error_modes(monkeypatch):
    # Replace the expensive backends only for this router test; the individual
    # implementation tests above still execute the real search loops.
    router_globals = unwrap(search).__globals__
    for name in (
        "search_bytes", "search_string", "search_immediate", "search_name", "search_insns",
        "search_text", "search_operand", "search_comment", "search_data_ref", "search_code_ref",
        "search_regex", "search_func_by_sig", "search_find", "search_callers", "search_callees",
        "search_api", "search_constants", "search_decompiled", "search_structured", "search_type",
        "search_export", "search_summary", "run_query_lang", "_search_behavior_impl", "search_bool",
        "search_analyze", "search_neighborhood", "search_outlier", "search_fingerprint", "search_path",
        "search_reach", "search_noreach", "search_symbol", "search_symbol_info", "search_demangle",
        "search_xrefs_to_string", "search_data_value",
    ):
        monkeypatch.setitem(router_globals, name, lambda *args, **kwargs: {"ok": True, "results": "0x1000 hit", "items": [{"address": 0x1000}]})
    for action, pattern in (("bytes", "90"), ("literal", "main"), ("callers", "main"), ("vulnerable", None), ("overview", None), ("boolean", "name:main"), ("pointer", "0x140001000"), ("path", "main")):
        kwargs = {"action": action, "pattern": pattern}
        if action == "path":
            kwargs["dst"] = "main"
        result = search(**kwargs)
        assert result.get("ok") is True, result
    assert search(action="bytes")["error"] is True
    assert search(action="path", pattern="main")["error"] is True
    assert search(action="structured", constraints="bad")["error"] is True
