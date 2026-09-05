"""Remaining annotation/comment-manager modes and write-boundary tests."""

from __future__ import annotations

import json
import types

import pytest

from ida_pro_mcp.host.errors import MCPError, make_error
from ida_pro_mcp.ida_mcp.tools.annotation import (
    _annotation_comment_mgr_action,
    _auto_comment_one,
    _classify_crypto_function,
    _detect_crypto_algorithm,
    _get_func_callees_with_addr,
    _mmio_label,
    _set_inline_comment,
    _write_comment,
    annotation,
)

from . import test_annotation_mode_matrix as matrix

annotation_module = matrix.annotation_module


def test_comment_writer_normalizes_none_truthy_false_and_exception():
    assert _write_comment(lambda *_args: None) is True
    assert _write_comment(lambda *_args: True) is True
    assert _write_comment(lambda *_args: False) is False

    def broken(*_args):
        raise OSError("read-only IDB")

    assert _write_comment(broken) is False


def test_crypto_detection_reads_string_data_references(monkeypatch, fresh_fake_idb):
    import idautils
    import idc

    fn = types.SimpleNamespace(start_ea=0x140001000, end_ea=0x140001004)
    monkeypatch.setattr(annotation_module._compat, "get_func_info", lambda _ea: fn)
    monkeypatch.setattr(idautils, "Heads", lambda *_args: iter([fn.start_ea]), raising=False)
    monkeypatch.setattr(idautils, "DataRefsFrom", lambda *_args: iter([0x140002000]), raising=False)
    monkeypatch.setattr(idc, "generate_disasm_line", lambda *_args: "mov eax, ebx", raising=False)
    monkeypatch.setattr(idc, "get_str_type", lambda _ea: 0, raising=False)
    monkeypatch.setattr(idc, "get_strlit_contents", lambda *_args: b"sha-256 context", raising=False)

    assert _detect_crypto_algorithm(fn.start_ea) == "SHA-256"


def test_crypto_classifier_uses_behavior_hit_and_handles_classifier_failure(monkeypatch):
    import idaapi

    import ida_pro_mcp.services as services

    class _Classifier:
        @classmethod
        def instance(cls, _embedder):
            return cls()

        def classify(self, _pseudo, **_kwargs):
            return [{"behavior": "cryptographic primitive"}]

    class _Embedder:
        pass

    monkeypatch.setattr(idaapi, "decompile", lambda _ea: "aes_round", raising=False)
    monkeypatch.setattr(services, "BehaviorClassifier", _Classifier)
    monkeypatch.setattr(services, "BgeCodeEmbedder", _Embedder)
    monkeypatch.setattr(annotation_module, "_detect_crypto_algorithm", lambda _ea: "AES")
    assert _classify_crypto_function(0x140001000) == "AES"

    monkeypatch.setattr(_Classifier, "instance", classmethod(lambda _cls, _embedder: (_ for _ in ()).throw(RuntimeError("model unavailable"))))
    assert _classify_crypto_function(0x140001000) is None


def test_auto_comment_reports_governance_and_write_failures(monkeypatch, fresh_fake_idb):
    import idautils
    import idc

    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: "call", raising=False)
    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda *_args: iter([0x140001050]), raising=False)
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "danger", raising=False)
    monkeypatch.setattr(idc, "get_name", lambda _ea: "", raising=False)
    monkeypatch.setattr(idc, "get_type", lambda _ea: "void danger(void)", raising=False)
    monkeypatch.setattr(idc, "get_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(idc, "set_cmt", lambda *_args: False, raising=False)
    failed = _auto_comment_one(0x140001000, "[M] ")
    assert failed["ok"] is False
    assert failed["reason"] == "comment_write_failed"

    monkeypatch.setattr(annotation_module, "_govern_comment", lambda _text: None)
    assert _set_inline_comment(0x140001000, "blocked", dry_run=False) is False


@pytest.mark.parametrize(
    "action",
    [
        "auto_comment",
        "auto_comment_function",
        "label_loops",
        "label_branches",
        "mark_dangerous",
        "annotate_constants",
        "tag_functions",
        "document_args",
        "mark_error_paths",
        "propagate_names",
        "cleanup",
        "validate",
    ],
)
def test_annotation_actions_return_address_validation_errors(monkeypatch, action):
    invalid = make_error(MCPError.INVALID_ARGS, "bad address")
    monkeypatch.setattr(annotation_module, "validate_addr", lambda *_args, **_kwargs: (None, invalid))
    result = annotation(action=action, addr="not-an-address", value="note")
    assert result is invalid


def test_annotation_action_catches_unexpected_boundary_errors(monkeypatch):
    monkeypatch.setattr(annotation_module, "public_arg", lambda *_args: (_ for _ in ()).throw(RuntimeError("bad request")))
    result = annotation(action="auto_comment", addr="0x140001000")
    assert result.get("ok") is not True
    assert "bad request" in str(result)


def test_annotation_write_paths_record_failures_and_limit_modes(monkeypatch, fresh_fake_idb):
    import idautils
    import idc

    fn = types.SimpleNamespace(start_ea=0x140001000, end_ea=0x140001010)
    monkeypatch.setattr(annotation_module._compat, "get_func_info", lambda _ea: fn)
    monkeypatch.setattr(annotation_module._compat, "get_flow_chart", lambda _ea: [])
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "named", raising=False)
    monkeypatch.setattr(idc, "get_func_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(idc, "get_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(idc, "set_cmt", lambda *_args: False, raising=False)
    monkeypatch.setattr(idc, "set_func_cmt", lambda *_args: False, raising=False)
    monkeypatch.setattr(annotation_module, "_govern_comment", lambda text: text)
    monkeypatch.setattr(idautils, "Heads", lambda *_args: iter([0x140001004]), raising=False)
    monkeypatch.setattr(idautils, "CodeRefsFrom", lambda *_args: iter([0x140001050]), raising=False)
    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: "call", raising=False)
    monkeypatch.setattr(idc, "get_operand_value", lambda _ea, index: 0xDEADBEEF if index == 0 else 0, raising=False)
    monkeypatch.setattr(idc, "next_head", lambda ea, _end: annotation_module.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(idc, "get_name_ea_simple", lambda _name: 0x140001050, raising=False)
    monkeypatch.setattr(annotation_module, "_get_func_callees_with_addr", lambda _ea: [(0x140001004, "malloc")],)

    assert annotation(action="label_loops", addr="0x140001000")["count"] == 0
    assert annotation(action="label_branches", addr="0x140001000")["count"] == 0
    assert annotation(action="mark_dangerous", addr="0x140001000")["count"] == 0
    tagged = annotation(action="tag_functions", addr="0x140001000")
    assert tagged["count"] == 1
    assert tagged["write_failures"] == ["0x140001000"]
    assert annotation(action="document_args", addr="0x140001000")["count"] == 1
    assert annotation(action="propagate_names", addr="0x140001000")["count"] == 0

    monkeypatch.setattr(idautils, "Heads", lambda *_args: iter([0x140001004]), raising=False)
    monkeypatch.setattr(annotation_module, "_MAGIC_CONSTANTS", {0xDEADBEEF: "magic"})
    constants = annotation(action="annotate_constants", addr="0x140001000")
    assert constants["count"] == 1
    assert constants["write_failures"] == ["0x140001004"]

    monkeypatch.setattr(idautils, "Functions", lambda *_args: iter([0x140001000]), raising=False)
    monkeypatch.setattr(annotation_module, "_get_func_callees_with_addr", lambda _ea: [(0x140001004, "VirtualAlloc")],)
    monkeypatch.setattr(annotation_module, "_DANGEROUS_APIS_LOW", {"virtualalloc": "allocation"})
    dangerous = annotation(action="mark_dangerous", limit=1)
    assert dangerous["count"] == 1
    assert dangerous["write_failures"] == ["0x140001004"]


def test_comment_manager_rejects_missing_and_unsafe_paths_and_import_modes(monkeypatch, tmp_path, fresh_fake_idb):
    import idc

    assert annotation(action="set_structured", addr="0x140001000").get("ok") is not True
    assert annotation(action="bulk_set").get("ok") is not True
    assert annotation(action="export_md").get("ok") is not True
    assert annotation(action="import_md").get("ok") is not True

    monkeypatch.setattr(annotation_module, "validate_path_safe", lambda _path: (None, make_error(MCPError.INVALID_ARGS, "unsafe path")))
    assert annotation(action="export_md", path=str(tmp_path / "out.md"))["code"] == MCPError.INVALID_ARGS
    assert annotation(action="import_md", path=str(tmp_path / "in.md"))["code"] == MCPError.INVALID_ARGS

    source = tmp_path / "in.md"
    source.write_text("- `0x140001000`: blocked\n- `0x140001001`: malformed\n", encoding="utf-8")
    monkeypatch.setattr(annotation_module, "validate_path_safe", lambda path: (path, None))
    monkeypatch.setattr(annotation_module, "_govern_comment", lambda _text: None)
    imported = annotation(action="import_md", path=str(source))
    assert imported["count"] == 0
    assert imported["error_count"] == 2

    monkeypatch.setattr(annotation_module, "_govern_comment", lambda text: text)
    monkeypatch.setattr(idc, "set_cmt", lambda *_args: False, raising=False)
    rejected = annotation(action="import_md", path=str(source))
    assert rejected["count"] == 0
    assert rejected["error_count"] == 2


def test_comment_manager_structured_and_bulk_write_variants(monkeypatch, fresh_fake_idb):
    import idc

    monkeypatch.setattr(annotation_module, "_govern_comment", lambda text: text)
    calls = []
    monkeypatch.setattr(idc, "set_cmt", lambda *args: calls.append(("cmt", args)) or None, raising=False)
    monkeypatch.setattr(idc, "set_func_cmt", lambda *args: calls.append(("func", args)) or None, raising=False)

    structured = annotation(action="set_structured", addr="0x140001000", text="line one\nline two", fmt="structured")
    assert structured["format"] == "structured"
    assert "/* Analysis:" in calls[0][1][1]

    bulk = annotation(action="bulk_set", items=json.dumps([
        {"addr": "0x140001000", "text": "repeat", "type": "repeatable"},
        {"addr": "0x140001001", "comment": "function", "type": "func"},
        {"addr": "0x140001002", "text": "regular", "type": "other"},
        {"addr": "0x140001003", "text": ""},
    ]))
    assert bulk["set_count"] == 3
    assert bulk["error_count"] == 1
    assert {kind for kind, _args in calls} == {"cmt", "func"}


def test_mmio_label_under_periph_base():
    assert _mmio_label(0x1000) == "MMIO+0x1000"


def test_auto_comment_one_classifier_crypto_branch(monkeypatch):
    import idaapi
    import idc

    import ida_pro_mcp.services as services

    class _Classifier:
        @classmethod
        def instance(cls, _embedder):
            return cls()

        def classify(self, _pseudo, **_kwargs):
            return [{"behavior": "crypto primitive"}]

    class _Embedder:
        pass

    monkeypatch.setattr(annotation_module._compat, "get_func_start", lambda _ea: 0x140001000)
    monkeypatch.setattr(idaapi, "decompile", lambda _ea: "crypto_func()", raising=False)
    monkeypatch.setattr(services, "BehaviorClassifier", _Classifier)
    monkeypatch.setattr(services, "BgeCodeEmbedder", _Embedder)
    monkeypatch.setattr(annotation_module, "_detect_crypto_algorithm", lambda _ea: "AES-128")
    monkeypatch.setattr(idc, "print_insn_mnem", lambda _ea: "nop", raising=False)
    monkeypatch.setattr(idc, "get_operand_value", lambda _ea, _idx: 0, raising=False)
    monkeypatch.setattr(annotation_module, "_set_inline_comment", lambda *args, **kwargs: True)

    res = _auto_comment_one(0x140001000, prefix="[A] ", dry_run=False, crypto_map=None)
    assert res["ok"] is True
    assert res["reason"] == "crypto"
    assert "AES-128" in res["comment"]

    # Cover lines 250-251: exception inside classifier block is safely handled
    monkeypatch.setattr(_Classifier, "instance", classmethod(lambda _cls, _emb: (_ for _ in ()).throw(RuntimeError("fail"))))
    res2 = _auto_comment_one(0x140001000, prefix="[A] ", dry_run=False, crypto_map=None)
    assert res2["applied"] is False


def test_auto_comment_function_write_failures_accumulate(monkeypatch, fresh_fake_idb):
    import idautils
    import idc

    fn = types.SimpleNamespace(start_ea=0x140003000, end_ea=0x140003010)
    monkeypatch.setattr(annotation_module._compat, "get_func_info", lambda _ea: fn)
    monkeypatch.setattr(annotation_module, "validate_addr", lambda _addr, **_kwargs: (0x140003000, None))
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "target_func", raising=False)
    monkeypatch.setattr(idautils, "Heads", lambda *_args: iter([0x140003000, 0x140003004]), raising=False)

    def fake_auto_one(head, **_kwargs):
        if head == 0x140003000:
            return {"ok": False, "applied": False, "addr": hex(head)}
        return {"ok": True, "applied": True, "addr": hex(head)}

    monkeypatch.setattr(annotation_module, "_auto_comment_one", fake_auto_one)

    res = annotation(action="auto_comment_function", addr="0x140003000")
    assert res["ok"] is True
    assert "0x140003000" in res["write_failures"]
    assert res["count"] == 1


def test_label_loops_limits_and_write_failures(monkeypatch, fresh_fake_idb):
    import idc

    class _Block:
        def __init__(self, start, end, succ_starts):
            self.start_ea = start
            self.end_ea = end
            self._succs = [types.SimpleNamespace(start_ea=s) for s in succ_starts]

        def succs(self):
            return self._succs

    fc = [
        _Block(0x140004010, 0x140004018, [0x140004000]),
        _Block(0x140004030, 0x140004038, [0x140004020]),
    ]

    monkeypatch.setattr(annotation_module, "validate_addr", lambda _addr, **_kwargs: (0x140004000, None))
    monkeypatch.setattr(annotation_module._compat, "get_flow_chart", lambda _ea: fc)
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "loop_fn", raising=False)
    monkeypatch.setattr(idc, "get_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(idc, "set_cmt", lambda *_args: False, raising=False)
    monkeypatch.setattr(annotation_module, "_govern_comment", lambda c: c)

    res = annotation(action="label_loops", addr="0x140004000", limit=1)
    assert res["ok"] is True
    assert res["count"] == 1

    res2 = annotation(action="label_loops", addr="0x140004001", limit=10)
    assert res2["ok"] is True
    assert len(res2["write_failures"]) == 2


def test_label_branches_limits_empty_succs_and_write_failures(monkeypatch, fresh_fake_idb):
    import idc

    class _BranchBlock:
        def __init__(self, start, end, succs):
            self.start_ea = start
            self.end_ea = end
            self._succs = succs

        def nsucc(self):
            return 2

        def succs(self):
            return self._succs

    b1 = _BranchBlock(0x140005000, 0x140005010, [types.SimpleNamespace(start_ea=0x140005020)])
    b2 = _BranchBlock(0x140005020, 0x140005030, [types.SimpleNamespace(start_ea=0x140005040), types.SimpleNamespace(start_ea=0x140005050)])
    b3 = _BranchBlock(0x140005050, 0x140005060, [types.SimpleNamespace(start_ea=0x140005070), types.SimpleNamespace(start_ea=0x140005080)])

    monkeypatch.setattr(annotation_module, "validate_addr", lambda _addr, **_kwargs: (0x140005000, None))
    monkeypatch.setattr(annotation_module._compat, "get_flow_chart", lambda _ea: [b1, b2, b3])
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "branch_fn", raising=False)
    monkeypatch.setattr(idc, "prev_head", lambda *_args: annotation_module.idaapi.BADADDR, raising=False)
    monkeypatch.setattr(idc, "generate_disasm_line", lambda *_args: "jz target", raising=False)
    monkeypatch.setattr(idc, "get_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(idc, "set_cmt", lambda *_args: False, raising=False)
    monkeypatch.setattr(annotation_module, "_govern_comment", lambda c: c)

    res = annotation(action="label_branches", addr="0x140005000", limit=1)
    assert res["ok"] is True
    assert res["count"] == 1
    assert len(res["write_failures"]) == 1


def test_mark_dangerous_unbounded_and_limits(monkeypatch, fresh_fake_idb):
    import idautils

    funcs = list(range(0x140000000, 0x140000000 + 5005))
    monkeypatch.setattr(idautils, "Functions", lambda *_args: iter(funcs), raising=False)
    monkeypatch.setattr(
        annotation_module,
        "_get_func_callees_with_addr",
        lambda ea: [(ea, "strcpy"), (ea + 4, "gets")],
    )
    monkeypatch.setattr(
        annotation_module,
        "_DANGEROUS_APIS_LOW",
        {"strcpy": "buffer overflow", "gets": "buffer overflow"},
    )
    monkeypatch.setattr(annotation_module, "_write_comment", lambda *args: True)

    res = annotation(action="mark_dangerous", limit=1)
    assert res["ok"] is True
    assert res["count"] == 1


def test_tag_functions_unbounded_and_limits(monkeypatch, fresh_fake_idb):
    import idautils
    import idc

    funcs = list(range(0x140000000, 0x140000000 + 5005))
    monkeypatch.setattr(idautils, "Functions", lambda *_args: iter(funcs), raising=False)
    monkeypatch.setattr(
        annotation_module,
        "_get_func_callees_with_addr",
        lambda ea: [(ea, "recv"), (ea + 4, "send")],
    )
    monkeypatch.setattr(idc, "get_func_name", lambda ea: f"net_fn_{ea:x}", raising=False)
    monkeypatch.setattr(idc, "get_func_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(annotation_module, "_write_comment", lambda *args: True)

    res = annotation(action="tag_functions", limit=1)
    assert res["ok"] is True
    assert res["count"] == 1


def test_mark_error_paths_branches_and_limits(monkeypatch, fresh_fake_idb):
    import idc

    fn = types.SimpleNamespace(start_ea=0x140006000, end_ea=0x140006100)
    monkeypatch.setattr(annotation_module._compat, "get_func_info", lambda _ea: fn)
    monkeypatch.setattr(annotation_module, "validate_addr", lambda _addr, **_kwargs: (0x140006000, None))
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "err_fn", raising=False)
    monkeypatch.setattr(
        annotation_module,
        "_get_func_callees_with_addr",
        lambda _ea: [
            (0x140006010, "CreateFileW"),
            (0x140006030, "other_api"),
            (0x140006050, "fopen"),
            (0x140006070, "malloc"),
            (0x140006090, "socket"),
        ],
    )

    def fake_next_head(ea, _end):
        if ea == 0x140006050:
            return annotation_module.idaapi.BADADDR
        if ea == 0x140006070:
            return 0x140006074
        if ea == 0x140006074:
            return 0x140006078
        if ea == 0x140006090:
            return 0x140006094
        if ea == 0x140006094:
            return annotation_module.idaapi.BADADDR
        if ea == 0x140006010:
            return 0x140006014
        return annotation_module.idaapi.BADADDR

    def fake_mnem(ea):
        if ea in (0x140006074, 0x140006094):
            return "test"
        if ea in (0x140006014, 0x140006078):
            return "jnz"
        return "nop"

    monkeypatch.setattr(idc, "next_head", fake_next_head, raising=False)
    monkeypatch.setattr(idc, "print_insn_mnem", fake_mnem, raising=False)
    monkeypatch.setattr(idc, "generate_disasm_line", lambda *_args: "jnz loc_err", raising=False)
    monkeypatch.setattr(idc, "get_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(idc, "set_cmt", lambda *_args: False, raising=False)
    monkeypatch.setattr(annotation_module, "_govern_comment", lambda c: c)

    res = annotation(action="mark_error_paths", addr="0x140006000", limit=1)
    assert res["ok"] is True
    assert res["count"] == 1
    assert len(res["write_failures"]) == 1

    res2 = annotation(action="mark_error_paths", addr="0x140006001", limit=10)
    assert res2["ok"] is True
    assert res2["count"] == 2


def test_propagate_names_sub_error_limit_and_write_failures(monkeypatch, fresh_fake_idb):
    import idc

    monkeypatch.setattr(annotation_module, "validate_addr", lambda _addr, **_kwargs: (0x140007000, None))
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "sub_140007000", raising=False)
    res_err = annotation(action="propagate_names", addr="0x140007000")
    assert res_err["code"] == MCPError.INVALID_ARGS

    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "Parser_ParsePacket", raising=False)
    monkeypatch.setattr(
        annotation_module,
        "_get_func_callees_with_addr",
        lambda _ea: [
            (0x140007010, "sub_140007100"),
            (0x140007020, "sub_140007200"),
        ],
    )
    monkeypatch.setattr(idc, "get_name_ea_simple", lambda _name: 0x140007100, raising=False)
    monkeypatch.setattr(annotation_module, "_govern_comment", lambda c: c)
    monkeypatch.setattr(idc, "get_func_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(idc, "set_func_cmt", lambda *_args: False, raising=False)

    res_limit = annotation(action="propagate_names", addr="0x140007001", limit=1)
    assert res_limit["ok"] is True
    assert res_limit["count"] == 1
    assert len(res_limit["write_failures"]) == 1


def test_cleanup_unbounded_limit_and_write_failures(monkeypatch, fresh_fake_idb):
    import idautils
    import idc

    funcs = list(range(0x140000000, 0x140000000 + 5005))
    monkeypatch.setattr(idautils, "Functions", lambda *_args: iter(funcs), raising=False)

    fn = types.SimpleNamespace(start_ea=0x140008000, end_ea=0x140008010)

    def fake_get_func_info(ea):
        if ea == 0x140000000:
            return None
        return fn

    monkeypatch.setattr(annotation_module._compat, "get_func_info", fake_get_func_info)
    monkeypatch.setattr(annotation_module, "validate_addr", lambda _addr, **_kwargs: (0x140008000, None))

    def fake_get_func_cmt(ea, rep):
        return "[AUTO] func comment"

    def fake_get_cmt(ea, rep):
        return "[AUTO] inline comment"

    def fake_next_head(ea, end):
        if ea == 0x140008000:
            return 0x140008004
        return annotation_module.idaapi.BADADDR

    monkeypatch.setattr(idc, "get_func_cmt", fake_get_func_cmt, raising=False)
    monkeypatch.setattr(idc, "get_cmt", fake_get_cmt, raising=False)
    monkeypatch.setattr(idc, "next_head", fake_next_head, raising=False)
    monkeypatch.setattr(idc, "set_func_cmt", lambda *_args: False, raising=False)
    monkeypatch.setattr(idc, "set_cmt", lambda *_args: False, raising=False)

    res_limit = annotation(action="cleanup", prefix="[AUTO]", limit=1, dry_run=True)
    assert res_limit["ok"] is True
    assert res_limit["count"] >= 1

    res_inline = annotation(action="cleanup", addr="0x140008000", prefix="[AUTO]", limit=1, dry_run=True)
    assert res_inline["ok"] is True
    assert res_inline["count"] >= 1

    res_fail = annotation(action="cleanup", addr="0x140008001", prefix="[AUTO]", limit=10, dry_run=False)
    assert res_fail["ok"] is True
    assert len(res_fail["write_failures"]) >= 1


def test_validate_action_requires_addr():
    res = annotation(action="validate")
    assert res["code"] == MCPError.INVALID_ARGS
    assert "addr required" in res["message"]


def test_get_context_and_set_structured_addr_errors_and_extra_cmts(monkeypatch, fresh_fake_idb):
    import idc

    res_err = annotation(action="get_context", addr="invalid_ea")
    assert res_err["code"] == MCPError.ADDRESS_INVALID

    res_err2 = annotation(action="set_structured", addr="invalid_ea", text="note")
    assert res_err2["code"] == MCPError.ADDRESS_INVALID

    fn = types.SimpleNamespace(start_ea=0x140009000, end_ea=0x140009010)
    monkeypatch.setattr(annotation_module._compat, "get_func_info", lambda _ea: fn)
    monkeypatch.setattr(annotation_module, "validate_addr", lambda _addr, **_kwargs: (0x140009000, None))
    monkeypatch.setattr(idc, "get_name", lambda _ea: "ctx_func", raising=False)
    monkeypatch.setattr(idc, "get_func_name", lambda _ea: "ctx_func", raising=False)
    monkeypatch.setattr(idc, "get_func_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(idc, "get_cmt", lambda *_args: "", raising=False)

    def fake_extra_cmt(ea, idx):
        if idx == idc.E_PREV:
            return "anterior line"
        if idx == idc.E_NEXT:
            return "posterior line"
        return ""

    monkeypatch.setattr(idc, "get_extra_cmt", fake_extra_cmt, raising=False)

    res = annotation(action="get_context", addr="0x140009000")
    assert res["ok"] is True
    assert res["anterior"] == ["anterior line"]
    assert res["posterior"] == ["posterior line"]


def test_export_md_func_limit_breaks(monkeypatch, tmp_path, fresh_fake_idb):
    import idautils
    import idc

    out_file = tmp_path / "export.md"
    monkeypatch.setattr(annotation_module, "validate_path_safe", lambda path: (path, None))
    monkeypatch.setattr(idautils, "Segments", lambda: [0x140000000, 0x140010000])
    monkeypatch.setattr(idc, "get_segm_end", lambda ea: ea + 0x1000, raising=False)
    # > 5000 functions to hit lines 1250 and 1252 limit breaks
    monkeypatch.setattr(idautils, "Functions", lambda s, e: list(range(s, s + 5005)), raising=False)
    fn = types.SimpleNamespace(start_ea=0x140000010, end_ea=0x140000020)
    monkeypatch.setattr(annotation_module._compat, "get_func_info", lambda ea: fn)
    monkeypatch.setattr(idc, "get_func_name", lambda ea: f"fn_{ea:x}", raising=False)
    monkeypatch.setattr(idc, "get_func_cmt", lambda *_args: "cmt", raising=False)
    monkeypatch.setattr(idc, "get_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(idc, "next_head", lambda *_args: annotation_module.idaapi.BADADDR, raising=False)

    res = annotation(action="export_md", path=str(out_file), limit=1)
    assert res["ok"] is True
    assert out_file.exists()


def test_import_md_parse_address_exception(monkeypatch, tmp_path, fresh_fake_idb):
    in_file = tmp_path / "in.md"
    in_file.write_text("- `0x14000A000`: some comment\n", encoding="utf-8")
    monkeypatch.setattr(annotation_module, "validate_path_safe", lambda path: (path, None))
    monkeypatch.setattr(annotation_module, "parse_address", lambda _s: (_ for _ in ()).throw(ValueError("parse error")))

    res = annotation(action="import_md", path=str(in_file))
    assert res["ok"] is True
    assert res["error_count"] == 1
    assert "parse error" in res["errors"][0]["error"]


def test_summary_action_func_limit_breaks(monkeypatch, fresh_fake_idb):
    import idautils
    import idc

    monkeypatch.setattr(idautils, "Segments", lambda: [0x140000000, 0x140010000])
    monkeypatch.setattr(idc, "get_segm_end", lambda ea: ea + 0x1000, raising=False)
    monkeypatch.setattr(idautils, "Functions", lambda s, e: list(range(s, s + 10005)), raising=False)
    monkeypatch.setattr(idc, "get_func_cmt", lambda *_args: "", raising=False)
    monkeypatch.setattr(annotation_module._compat, "get_func_info", lambda ea: None)

    res = annotation(action="summary")
    assert res["ok"] is True
    assert res["total_functions"] == 10000


def test_comment_mgr_action_unknown_action():
    res = _annotation_comment_mgr_action("nonexistent_subaction", None, None, None, None, None)
    assert res["code"] == MCPError.INVALID_ARGS
    assert "Unknown comment-mgr action" in res["message"]
