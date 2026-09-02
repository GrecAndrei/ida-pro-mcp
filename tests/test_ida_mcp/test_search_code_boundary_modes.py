"""Exercise instruction/text/operand/comment searches through shared scans."""

from __future__ import annotations

from types import SimpleNamespace

from tests._isolated_repo_loader import load_tool_submodule


def _module():
    return load_tool_submodule("search.code")


def _scan(monkeypatch, code, *, note="", error=""):
    monkeypatch.setattr(code, "resolve_scan_segments", lambda *_a, **_k: ([(0x1000, 0x1004)], note, error))
    monkeypatch.setattr(code, "iter_code", lambda _start, _end, force=False: iter((0x1000, 0x1001, 0x1002)))
    monkeypatch.setattr(code, "iter_segments", lambda *_a, **_k: [(0x1000, 0x1003)])
    monkeypatch.setattr(code.idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)
    monkeypatch.setattr(code.ida_bytes, "get_flags", lambda _ea: 1, raising=False)
    monkeypatch.setattr(code.ida_bytes, "is_code", lambda _flags: True, raising=False)
    monkeypatch.setattr(code.idc, "next_head", lambda ea, _end: ea + 1 if ea < 0x1002 else code.idaapi.BADADDR, raising=False)


def test_instruction_sequences_support_wildcards_context_and_errors(monkeypatch):
    code = _module()
    _scan(monkeypatch, code, note="raw blob")
    monkeypatch.setattr(code.idc, "print_insn_mnem", lambda ea: {0x1000: "mov", 0x1001: "add", 0x1002: "ret"}.get(ea, ""), raising=False)
    monkeypatch.setattr(code.idc, "next_head", lambda ea, _end: ea + 1, raising=False)
    monkeypatch.setattr(code._compat, "get_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(code.ida_funcs, "get_func_name", lambda _ea: "main", raising=False)
    result = code.search_insns("mov,*,ret", None, None, True, 0, 3)
    assert result["ok"] is True and result["count"] == 1
    assert "[mov,add,ret]" in result["results"] and "in:main" in result["results"]
    assert result["note"] == "raw blob"
    assert code.search_insns("mov", None, None, False, 0, 1)["truncated"] is True

    failed = _module()
    _scan(monkeypatch, failed, error="no executable segments")
    assert failed.search_insns("mov", None, None, False, 0, 1)["error"] is True


def test_text_and_operand_search_cover_context_timeout_and_no_exec(monkeypatch):
    code = _module()
    _scan(monkeypatch, code, note="relaxed")
    monkeypatch.setattr(code, "safe_generate_disasm_line", lambda ea: f"\x01mov r{ea & 1}, r0")
    monkeypatch.setattr(code.ida_lines, "tag_remove", lambda text: text.replace("\x01", ""), raising=False)
    monkeypatch.setattr(code._compat, "get_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(code.ida_funcs, "get_func_name", lambda _ea: "worker", raising=False)
    text = code.search_text("mov", False, None, None, True, 0, 2)
    assert text["count"] == 2 and text["truncated"] is True and text["note"] == "relaxed"
    assert "in:worker" in text["results"]

    class Expired:
        def __init__(self, _timeout):
            pass

        def check(self):
            raise TimeoutError

    monkeypatch.setattr(code, "SearchTimeout", Expired)
    timed = code.search_text("mov", False, None, None, False, 0, 2, timeout_ms=1)
    assert timed["timed_out"] is True

    code = _module()
    _scan(monkeypatch, code, error="no executable segments")
    assert code.search_operand("r0", False, None, None, False, 0, 1)["error"] is True


def test_operand_and_comment_modes_format_regular_and_repeatable_hits(monkeypatch):
    code = _module()
    _scan(monkeypatch, code)
    void = getattr(code.idaapi, "o_void", 0)
    operands = {0x1000: ["r0", "#1"], 0x1001: ["r1"]}
    monkeypatch.setattr(code.idc, "get_operand_type", lambda ea, i: void if i >= len(operands.get(ea, [])) else 1, raising=False)
    monkeypatch.setattr(code.idc, "print_operand", lambda ea, i: operands[ea][i], raising=False)
    monkeypatch.setattr(code.idc, "print_insn_mnem", lambda _ea: "mov", raising=False)
    monkeypatch.setattr(code, "safe_generate_disasm_line", lambda _ea: "mov r0, #1")
    monkeypatch.setattr(code.ida_lines, "tag_remove", lambda text: text, raising=False)
    operand = code.search_operand("#1", False, None, None, True, 0, 5)
    assert operand["count"] == 1 and "mov  r0, #1" in operand["results"]

    comments = {0x1000: "regular note", 0x1001: None, 0x1002: "repeat note"}
    monkeypatch.setattr(code.idc, "get_cmt", lambda ea, repeat: comments[ea] if (repeat == 0 and ea != 0x1002) else (comments[ea] if repeat == 1 else None), raising=False)
    comment = code.search_comment("note", False, None, None, 0, 5)
    assert comment["count"] == 2
    assert "regular" in comment["results"] and "repeatable" in comment["results"]

    monkeypatch.setattr(code, "SearchTimeout", lambda _timeout: SimpleNamespace(check=lambda: (_ for _ in ()).throw(TimeoutError)))
    timed = code.search_comment("note", False, None, None, 0, 5, timeout_ms=1)
    assert timed["timed_out"] is True
