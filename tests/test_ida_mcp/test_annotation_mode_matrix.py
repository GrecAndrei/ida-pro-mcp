"""Cross-mode behavior coverage for annotation and comment management."""

from __future__ import annotations

import importlib
import json
import types
from pathlib import Path

from ida_pro_mcp.host.agent_operations import get_agent_operation
from ida_pro_mcp.ida_mcp.tools.annotation import (
    _auto_comment_one,
    _classify_crypto_function,
    _detect_crypto_algorithm,
    _get_func_callees_with_addr,
    _govern_comment,
    _governance_check_proposed_comment,
    _is_probable_mmio,
    _mmio_label,
    _strip_api_suffix,
    annotation,
)

annotation_module = importlib.import_module("ida_pro_mcp.ida_mcp.tools.annotation")


def _assert_ok(result):
    assert result.get("ok") is True, result
    return result


class _Block:
    def __init__(self, start_ea, end_ea, successors=()):
        self.start_ea = start_ea
        self.end_ea = end_ea
        self._successors = list(successors)

    def succs(self):
        return iter(self._successors)

    def nsucc(self):
        return len(self._successors)


def test_public_mark_dangerous_translation_and_legacy_backend():
    operation = get_agent_operation("ida_mark_dangerous")
    assert operation is not None
    backend, args = operation.to_backend_call(
        {"address": "0x140001000", "prefix": "[audit] ", "limit": 2, "risk_ack": True}
    )
    assert backend == "annotation"
    assert args == {
        "action": "mark_dangerous",
        "address": "0x140001000",
        "prefix": "[audit] ",
        "limit": 2,
        "_risk_ack": True,
    }
    assert annotation(action="mark_dangerous", address="0x140001000", dry_run=True)["ok"] is True


def test_annotation_helpers_cover_signal_and_governance_fallbacks(monkeypatch):
    assert _strip_api_suffix("strcpyA") == "strcpy"
    assert _strip_api_suffix("puts@PLT") == "puts"
    assert _strip_api_suffix("puts") == "puts"
    assert _is_probable_mmio(0x40000000)
    assert _is_probable_mmio(0xE0000010)
    assert _is_probable_mmio(0xF0000000)
    assert not _is_probable_mmio(0x30000000)
    assert _mmio_label(0x40000010) == "PERIPH+0x10"
    assert _mmio_label(0x50000010) == "PERIPH_HI+0x10"
    assert _mmio_label(0xE0000010) == "SYSCTRL+0x10"
    assert _mmio_label(0xF1000000) == "SYSCTRL+0x11000000"

    monkeypatch.setattr(annotation_module, "evaluate_operation", lambda **_kwargs: {"approved": False})
    assert _govern_comment("blocked") is None
    assert _governance_check_proposed_comment(0x140001000, "blocked", "comment")["approved"] is False
    monkeypatch.setattr(annotation_module, "evaluate_operation", lambda **_kwargs: {"approved": True, "redacted_content": "safe"})
    assert _govern_comment("original") == "safe"
    def fail(**_kwargs):
        raise RuntimeError("governance unavailable")
    monkeypatch.setattr(annotation_module, "evaluate_operation", fail)
    assert _govern_comment("fallback") == "fallback"


def test_auto_comment_covers_call_string_mmio_crypto_and_no_signal(monkeypatch, fresh_fake_idb):
    import idautils
    import idc

    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: "call", raising=False)
    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda _ea, _flow: iter([0x140001050]), raising=False)
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "callee", raising=False)
    monkeypatch.setattr(idc, "get_name", lambda _ea: "", raising=False)
    monkeypatch.setattr(idc, "get_type", lambda _ea: "int callee(char *, int)", raising=False)
    call = _auto_comment_one(0x140001008, "[M] ")
    assert call["reason"] == "call_site"
    assert "callee(char *, int) -> int" in call["comment"]

    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: "lea", raising=False)
    monkeypatch.setattr(idautils, "DataRefsFrom", lambda _ea: iter([0x140002010]), raising=False)
    monkeypatch.setattr(idc, "get_str_type", lambda _ea: 0, raising=False)
    monkeypatch.setattr(idc, "get_strlit_contents", lambda *_args: b"user-visible text", raising=False)
    string_ref = _auto_comment_one(0x14000100D, "[M] ", dry_run=True)
    assert string_ref["reason"] == "string_ref"
    assert string_ref["applied"] is True

    monkeypatch.setattr(idautils, "DataRefsFrom", lambda _ea: iter(()), raising=False)
    monkeypatch.setattr(idc, "get_operand_value", lambda _ea, index: 0x40000020 if index == 1 else 0, raising=False)
    mmio = _auto_comment_one(0x14000100D, "[M] ", dry_run=True)
    assert mmio["reason"] == "mmio"
    assert "PERIPH" in mmio["comment"]

    monkeypatch.setattr(idc, "get_operand_value", lambda *_args: 0, raising=False)
    monkeypatch.setattr(annotation_module._compat, "get_func_start", lambda _ea: 0x140001000)
    crypto = _auto_comment_one(
        0x14000100D,
        "[M] ",
        dry_run=True,
        crypto_map={0x140001000: "AES"},
    )
    assert crypto["reason"] == "crypto"
    monkeypatch.setattr(annotation_module._compat, "get_func_start", lambda _ea: None)
    assert _auto_comment_one(0x14000100D, "[M] ", dry_run=True)["applied"] is False

    monkeypatch.setattr(annotation_module._compat, "get_func_info", lambda _ea: None)
    assert _detect_crypto_algorithm(0x140001000) == "unknown"
    assert _classify_crypto_function(0x140001000) is None


def test_annotation_control_flow_actions_write_and_respect_duplicate_prefix(monkeypatch):
    import idc

    loop_head = _Block(0x140001000, 0x140001004)
    loop_body = _Block(0x140001004, 0x140001010, [loop_head])
    branch_true = _Block(0x140001020, 0x140001024)
    branch_false = _Block(0x140001030, 0x140001034)
    branch = _Block(0x140001010, 0x140001020, [branch_true, branch_false])
    monkeypatch.setattr(annotation_module._compat, "get_flow_chart", lambda _ea: [loop_head, loop_body, branch])
    monkeypatch.setattr(idc, "prev_head", lambda _end, _start: 0x14000101C, raising=False)
    monkeypatch.setattr(idc, "generate_disasm_line", lambda _ea, _flags: "jne 0x140001020", raising=False)
    loops = _assert_ok(annotation(action="label_loops", addr="0x140001000", dry_run=False, limit=4))
    assert loops["count"] == 1
    branches = _assert_ok(annotation(action="label_branches", addr="0x140001000", dry_run=True, limit=4))
    assert branches["count"] == 1
    assert "T:0x140001020" in branches["branches"]

    writes = []
    monkeypatch.setattr(idc, "get_cmt", lambda _ea, _repeatable: "[M] existing", raising=False)
    monkeypatch.setattr(idc, "set_cmt", lambda *args: writes.append(args), raising=False)
    duplicate = annotation(action="label_loops", addr="0x140001000", prefix="[M] ", dry_run=False)
    assert duplicate["count"] == 1
    assert writes == []


def test_annotation_api_constants_tags_args_and_error_paths(monkeypatch, fresh_fake_idb):
    import ida_typeinf
    import idautils
    import idc

    function_ea = 0x140001000
    call_ea = 0x140001008
    monkeypatch.setattr(idautils, "Heads", lambda *_args: iter([call_ea, 0x14000100D]), raising=False)
    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda _ea, _flow: iter([0x140001050]), raising=False)
    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: "call", raising=False)
    monkeypatch.setattr(idc, "get_func_name", lambda ea: "strcpyA" if ea == 0x140001050 else "main", raising=False)
    monkeypatch.setattr(idc, "get_func_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(idc, "get_cmt", lambda *_args: "", raising=False)
    writes = []
    monkeypatch.setattr(idc, "set_cmt", lambda *args: writes.append(args), raising=False)
    dangerous = _assert_ok(annotation(action="mark_dangerous", addr=hex(function_ea), limit=1, dry_run=False))
    assert dangerous["count"] == 1
    assert writes

    magic_value, meaning = next(iter(annotation_module._MAGIC_CONSTANTS.items()))
    monkeypatch.setattr(idc, "get_operand_value", lambda _ea, index: magic_value if index == 0 else 0, raising=False)
    constants = _assert_ok(annotation(action="annotate_constants", addr=hex(function_ea), dry_run=True))
    assert constants["count"] == 2
    assert meaning in constants["constants"]

    monkeypatch.setattr(annotation_module, "_API_TO_TAG", {"strcpy": ["string_ops"]})
    tags = _assert_ok(annotation(action="tag_functions", addr=hex(function_ea), dry_run=True))
    assert tags["count"] == 1
    assert "string_ops" in tags["tagged"]

    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda _ea, _flow: iter(()), raising=False)
    docs = _assert_ok(annotation(action="document_args", addr=hex(function_ea), dry_run=True))
    assert docs["params"][0]["note"] == "no type information"

    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda _ea, _flow: iter([0x140001050]), raising=False)
    monkeypatch.setattr(idc, "get_func_name", lambda ea: "malloc" if ea == 0x140001050 else "main", raising=False)
    monkeypatch.setattr(idc, "next_head", lambda ea, _end: ea + 4, raising=False)
    monkeypatch.setattr(idc, "print_insn_mnem", lambda ea: "call" if ea == call_ea else "jne", raising=False)
    monkeypatch.setattr(idc, "generate_disasm_line", lambda *_args: "jne error", raising=False)
    error_paths = _assert_ok(annotation(action="mark_error_paths", addr=hex(function_ea), dry_run=True))
    assert error_paths["count"] == 1

    monkeypatch.setattr(idc, "get_func_name", lambda ea: "main" if ea == function_ea else "sub_helper", raising=False)
    propagated = _assert_ok(annotation(action="propagate_names", addr=hex(function_ea), dry_run=True))
    assert propagated["count"] == 1
    assert "main_helper" in propagated["suggestions"]

    assert _get_func_callees_with_addr(function_ea)
    assert ida_typeinf.get_idati()


def test_annotation_cleanup_validation_and_comment_manager_modes(monkeypatch, tmp_path: Path, fresh_fake_idb):
    import idc

    db = fresh_fake_idb
    db.set_cmt(0x140001000, "[M] inline  keep", 0)
    db.set_cmt(0x140001000, "[M] repeat", 1)
    db.set_cmt(0x140001000, "[M] function", 0)
    cleaned = _assert_ok(annotation(action="cleanup", addr="0x140001000", prefix="[M]", dry_run=False))
    assert cleaned["count"] >= 2

    assert annotation(action="validate", addr="0x140001000").get("ok") is not True
    approved = _assert_ok(annotation(action="validate", addr="0x140001000", value="ordinary note"))
    assert approved["approved"] is True
    blocked = _assert_ok(annotation(action="validate", addr="0x140001000", value="contact x@example.com"))
    assert blocked["violations"]

    structured = _assert_ok(annotation(action="set_structured", addr="0x140001000", text="one\ntwo", fmt="structured"))
    assert structured["format"] == "structured"
    dry = _assert_ok(annotation(action="set_structured", addr="0x140001000", text="preview", dry_run=True))
    assert dry["dry_run"] is True

    bulk = _assert_ok(annotation(action="bulk_set", items=json.dumps([
        {"addr": "0x140001000", "text": "regular"},
        {"addr": "0x140001001", "comment": "repeat", "type": "repeatable"},
        {"addr": "0x140001002", "text": "function", "type": "func"},
        {"text": "missing address"},
        {"addr": "0x140001003"},
    ])))
    assert bulk["set_count"] == 3
    assert bulk["error_count"] == 2
    assert annotation(action="bulk_set", items="not json").get("ok") is not True
    assert annotation(action="bulk_set", items="{} ").get("ok") is not True

    context = _assert_ok(annotation(action="get_context", addr="0x140001000"))
    assert context["func_name"]
    out = tmp_path / "comments.md"
    exported = _assert_ok(annotation(action="export_md", path=str(out)))
    assert exported["exported"] is True
    out.write_text("# import\n- `0x140001000`: imported note\n- `bad`: bad\n", encoding="utf-8")
    imported = _assert_ok(annotation(action="import_md", path=str(out), dry_run=True))
    assert imported["count"] == 1
    assert imported["error_count"] == 0
    summary = _assert_ok(annotation(action="summary"))
    assert summary["total_functions"] >= 2
    assert annotation(action="get_context").get("ok") is not True


def test_annotation_action_errors_are_stable():
    for action in (
        "auto_comment", "auto_comment_function", "label_loops", "label_branches",
        "annotate_constants", "document_args", "mark_error_paths", "propagate_names",
    ):
        result = annotation(action=action)
        assert result.get("ok") is not True, action
    assert annotation(action="unknown").get("ok") is not True
    assert annotation(action="import_md", path="/does/not/exist").get("ok") is not True


def test_crypto_detection_covers_named_algorithms_and_sdk_failures(monkeypatch, fresh_fake_idb):
    import idautils
    import idc

    monkeypatch.setattr(idautils, "Heads", lambda *_args: iter([0x140001000]), raising=False)
    monkeypatch.setattr(idautils, "DataRefsFrom", lambda *_args: iter(()), raising=False)
    for token, expected in (
        ("aes_encrypt", "AES"),
        ("sha256_update", "SHA-256"),
        ("sha-1 transform", "SHA-1"),
        ("md5_init", "MD5"),
        ("des_setkey", "DES"),
        ("rc4_crypt", "RC4"),
        ("ordinary arithmetic", "unknown"),
    ):
        monkeypatch.setattr(idc, "generate_disasm_line", lambda *_args, text=token: text, raising=False)
        assert _detect_crypto_algorithm(0x140001000) == expected

    monkeypatch.setattr(idautils, "Heads", lambda *_args: (_ for _ in ()).throw(RuntimeError("bad listing")), raising=False)
    assert _detect_crypto_algorithm(0x140001000) == "unknown"
    monkeypatch.setattr(annotation_module._compat, "get_func_info", lambda _ea: None)
    assert _get_func_callees_with_addr(0x140001000) == []


def test_annotation_comment_manager_handles_blocked_and_non_function_modes(monkeypatch, tmp_path, fresh_fake_idb):
    import idautils
    import idc

    monkeypatch.setattr(annotation_module, "_govern_comment", lambda _text: None)
    blocked = annotation(action="set_structured", addr="0x140001000", text="blocked")
    assert blocked["error"] is True
    assert annotation(action="bulk_set", items=json.dumps([{"addr": "0x140001000", "text": "blocked"}]))["error_count"] == 1

    # A mapped data address has no function context, but get_context remains a
    # valid read and reports only its point comments.
    monkeypatch.setattr(annotation_module, "_govern_comment", lambda text: text)
    context = _assert_ok(annotation(action="get_context", addr="0x140003000"))
    assert "func_name" not in context
    assert context["nearby_comments"] == []

    bulk = _assert_ok(annotation(action="bulk_set", items=json.dumps([None, {"addr": "bad", "text": "x"}, {"addr": "0x140001000", "text": ""}])))
    assert bulk["error_count"] == 3

    db = fresh_fake_idb
    db.set_cmt(0x140001008, "persisted", 0)
    monkeypatch.setattr(idautils, "Segments", lambda: iter([0x140001000]), raising=False)
    monkeypatch.setattr(idautils, "Functions", lambda *_args: iter([0x140001000]), raising=False)
    exported_path = tmp_path / "export.md"
    exported = _assert_ok(annotation(action="export_md", path=str(exported_path)))
    assert exported["comment_count"] >= 1
    exported_path.write_text("# imported\n- `0x140001008`: imported\n", encoding="utf-8")
    imported = _assert_ok(annotation(action="import_md", path=str(exported_path), dry_run=False))
    assert imported["count"] == 1
    assert idc.get_cmt(0x140001008, 0) == "imported"


def test_annotation_signal_helpers_cover_fallback_names_and_typed_governance(monkeypatch, fresh_fake_idb):
    import ida_nalt
    import ida_typeinf
    import idaapi
    import idautils
    import idc

    fn = types.SimpleNamespace(start_ea=0x140001000, end_ea=0x140001010)
    monkeypatch.setattr(annotation_module._compat, "get_func_info", lambda _ea: fn)
    monkeypatch.setattr(idautils, "Heads", lambda *_args: iter([0x140001004]), raising=False)
    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: "call", raising=False)
    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda *_args: iter([0x140001050]), raising=False)
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "", raising=False)
    monkeypatch.setattr(idc, "get_name", lambda _ea: "fallback_target", raising=False)
    monkeypatch.setattr(idc, "get_type", lambda _ea: "void fallback_target", raising=False)

    callees = _get_func_callees_with_addr(0x140001000)
    assert callees == [(0x140001004, "fallback_target")]
    comment = _auto_comment_one(0x140001004, "[M] ", dry_run=True)
    assert comment["reason"] == "call_site"
    assert "fallback_target(?) -> void fallback_target" in comment["comment"]

    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda *_args: iter(()), raising=False)
    monkeypatch.setattr(idautils, "DataRefsFrom", lambda *_args: iter([0x140002000]), raising=False)
    monkeypatch.setattr(idc, "get_str_type", lambda _ea: None, raising=False)
    monkeypatch.setattr(idc, "get_operand_value", lambda *_args: 0, raising=False)
    monkeypatch.setattr(annotation_module._compat, "get_func_start", lambda _ea: None)
    assert _auto_comment_one(0x140001004, "[M] ", dry_run=True)["applied"] is False

    class _Tinfo:
        def get_func_details(self, details):
            details.value = 2
            return True

    class _FuncDetails:
        def size(self):
            return self.value

    monkeypatch.setattr(annotation_module._compat, "get_func_info", lambda _ea: fn)
    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda *_args: iter([0x140001050]), raising=False)
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "danger_api", raising=False)
    monkeypatch.setattr(ida_nalt, "get_tinfo", lambda *_args: True, raising=False)
    monkeypatch.setattr(ida_typeinf, "tinfo_t", _Tinfo, raising=False)
    monkeypatch.setattr(idaapi, "func_type_data_t", _FuncDetails, raising=False)
    monkeypatch.setattr(
        annotation_module,
        "evaluate_operation",
        lambda **_kwargs: {
            "approved": False,
            "violations": [{"rule": "PII", "description": "sensitive"}],
            "redacted_content": "redacted",
        },
    )
    governed = _governance_check_proposed_comment(0x140001000, "secret", "comment")
    assert governed == {"approved": False, "violations": ["[PII] sensitive"], "redacted_comment": "redacted"}


def test_annotation_dispatcher_covers_write_and_analysis_action_modes(monkeypatch, fresh_fake_idb):
    import ida_nalt
    import ida_typeinf
    import idautils
    import idc

    fn = types.SimpleNamespace(start_ea=0x140001000, end_ea=0x140001010)
    monkeypatch.setattr(annotation_module._compat, "get_func_info", lambda _ea: fn)
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "main_handler", raising=False)
    monkeypatch.setattr(idc, "get_func_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(idc, "get_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(idc, "set_cmt", lambda *_args: None, raising=False)
    monkeypatch.setattr(idc, "set_func_cmt", lambda *_args: None, raising=False)
    monkeypatch.setattr(annotation_module, "_govern_comment", lambda comment, **_kwargs: comment)
    monkeypatch.setattr(annotation_module, "_classify_crypto_function", lambda _ea: None)

    monkeypatch.setattr(
        annotation_module,
        "_auto_comment_one",
        lambda *_args, **_kwargs: {
            "ok": True,
            "addr": "0x140001004",
            "applied": True,
            "reason": "call_site",
            "comment": "call",
        },
    )
    monkeypatch.setattr(idautils, "Heads", lambda *_args: iter([0x140001004, 0x140001008]), raising=False)
    assert _assert_ok(annotation(action="auto_comment", addr="0x140001004", dry_run=True))["count"] == 1
    function_comments = _assert_ok(annotation(action="auto_comment_function", addr="0x140001000", limit=1, dry_run=True))
    assert function_comments["count"] == 1

    loop_head = _Block(0x140001000, 0x140001004)
    loop_body = _Block(0x140001004, 0x140001010, [loop_head])
    branch = _Block(0x140001008, 0x140001010, [loop_head, _Block(0x140001020, 0x140001024)])
    monkeypatch.setattr(annotation_module._compat, "get_flow_chart", lambda _ea: [loop_head, loop_body, branch])
    monkeypatch.setattr(idc, "prev_head", lambda *_args: annotation_module.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(idc, "generate_disasm_line", lambda *_args: "jz error", raising=False)
    assert _assert_ok(annotation(action="label_loops", addr="0x140001000", dry_run=False))["count"] == 2
    assert _assert_ok(annotation(action="label_branches", addr="0x140001000", dry_run=False))["count"] == 1

    monkeypatch.setattr(annotation_module, "_get_func_callees_with_addr", lambda _ea: [(0x140001004, "VirtualAllocA")])
    dangerous = _assert_ok(annotation(action="mark_dangerous", addr="0x140001000", dry_run=False, limit=1))
    assert dangerous["count"] == 1
    magic_value = next(iter(annotation_module._MAGIC_CONSTANTS))
    monkeypatch.setattr(idc, "get_operand_value", lambda _ea, index: magic_value if index == 0 else 0, raising=False)
    constants = _assert_ok(annotation(action="annotate_constants", addr="0x140001000", dry_run=False, limit=1))
    assert constants["count"] == 1

    monkeypatch.setattr(annotation_module, "_API_TO_TAG", {"virtualalloc": ["memory", "process"]})
    tagged = _assert_ok(annotation(action="tag_functions", addr="0x140001000", dry_run=False, limit=1))
    assert tagged["count"] == 1

    class _Param:
        name = "buffer"
        type = "char *"

    class _Details:
        def size(self):
            return 1

        def __getitem__(self, _index):
            return _Param()

    class _Tinfo:
        def get_func_details(self, details):
            return True

    monkeypatch.setattr(ida_typeinf, "tinfo_t", _Tinfo, raising=False)
    monkeypatch.setattr(ida_nalt, "get_tinfo", lambda *_args: True, raising=False)
    monkeypatch.setattr(annotation_module.idaapi, "func_type_data_t", _Details, raising=False)
    docs = _assert_ok(annotation(action="document_args", addr="0x140001000", dry_run=False))
    assert docs["params"][0]["name"] == "buffer"

    monkeypatch.setattr(annotation_module, "_get_func_callees_with_addr", lambda _ea: [(0x140001004, "malloc")])
    monkeypatch.setattr(idc, "next_head", lambda _ea, _end: 0x140001008, raising=False)
    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: "jz", raising=False)
    error_paths = _assert_ok(annotation(action="mark_error_paths", addr="0x140001000", dry_run=False))
    assert error_paths["count"] == 1

    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "main_handler", raising=False)
    monkeypatch.setattr(annotation_module, "_get_func_callees_with_addr", lambda _ea: [(0x140001004, "sub_helper")])
    monkeypatch.setattr(idc, "get_name_ea_simple", lambda _name: 0x140001020, raising=False)
    propagated = _assert_ok(annotation(action="propagate_names", addr="0x140001000", dry_run=False))
    assert propagated["count"] == 1
