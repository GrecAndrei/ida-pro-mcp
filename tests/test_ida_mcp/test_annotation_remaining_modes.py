"""Remaining annotation/comment-manager modes and write-boundary tests."""

from __future__ import annotations

import json
import types

import pytest

from ida_pro_mcp.host.errors import MCPError, make_error
from ida_pro_mcp.ida_mcp.tools.annotation import (
    _auto_comment_one,
    _classify_crypto_function,
    _detect_crypto_algorithm,
    _get_func_callees_with_addr,
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
