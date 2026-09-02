"""Cross-mode coverage for reference and signature search surfaces."""

from __future__ import annotations

from types import SimpleNamespace

from tests._isolated_repo_loader import load_tool_submodule


def _module():
    return load_tool_submodule("search.refs")


def test_data_and_code_reference_modes_share_target_and_response_boundaries(monkeypatch):
    refs = _module()
    target = 0x401000
    monkeypatch.setattr(
        refs,
        "resolve_target",
        lambda *_args, **_kwargs: (target, None, {"match": "exact"}),
    )
    xrefs = [
        SimpleNamespace(frm=0x402000, to=target, iscode=False),
        SimpleNamespace(frm=0x403000, to=target, iscode=False),
        SimpleNamespace(frm=0x404000, to=target, iscode=True),
    ]
    monkeypatch.setattr(refs.idautils, "XrefsTo", lambda *_args: iter(xrefs))
    monkeypatch.setattr(refs.idc, "get_name", lambda ea: "global_ref" if ea == 0x402000 else "")
    data = refs.search_data_ref("target", True, 0, 1, 0.0, False)
    assert data["ok"] is True
    assert data["truncated"] is True
    assert "global_ref" in data["results"]
    assert data["target_addr"] == hex(target)

    monkeypatch.setattr(refs._compat, "get_func_start", lambda ea: 0x400000 if ea == 0x404000 else None)
    monkeypatch.setattr(refs.ida_funcs, "get_func_name", lambda _ea: "caller")
    monkeypatch.setattr(refs, "safe_generate_disasm_line", lambda _ea: "call target")
    code = refs.search_code_ref("target", True, 0, 10, 0.0, False)
    assert code["ok"] is True
    assert code["count"] == 1
    assert "caller" in code["results"] and "call target" in code["results"]

    monkeypatch.setattr(refs, "resolve_target", lambda *_args, **_kwargs: (target, "not found", {}))
    assert refs.search_data_ref("missing", False, 0, 10, 0.0, False)["error"] is True
    assert refs.search_code_ref("missing", False, 0, 10, 0.0, False)["error"] is True


def test_regex_search_covers_validation_raw_segments_context_and_timeout(monkeypatch):
    refs = _module()
    assert refs.search_regex("(" * 21, False, None, None, False, 0, 5)["error"] is True
    assert refs.search_regex("(a+)+", False, None, None, False, 0, 5)["error"] is True
    assert refs.search_regex("[", False, None, None, False, 0, 5)["error"] is True
    assert refs.search_regex("\\" * 51, False, None, None, False, 0, 5)["error"] is True

    monkeypatch.setattr(refs, "resolve_scan_segments", lambda *_args, **_kwargs: ([], "", "no exec"))
    missing = refs.search_regex("needle", False, None, None, False, 0, 5)
    assert missing["error"] is True

    monkeypatch.setattr(refs, "resolve_scan_segments", lambda *_args, **_kwargs: ([(0x1000, 0x1003)], "raw scan", ""))
    monkeypatch.setattr(refs, "iter_code", lambda *_args, **_kwargs: iter([0x1000, 0x1001, 0x1002]))
    monkeypatch.setattr(refs, "safe_generate_disasm_line", lambda ea: "needle " + ("x" * 600) if ea == 0x1000 else "other")
    monkeypatch.setattr(refs._compat, "get_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(refs.ida_funcs, "get_func_name", lambda _ea: "scan_func")
    monkeypatch.setattr(refs.ida_lines, "tag_remove", lambda text: text)
    found = refs.search_regex("needle", False, None, None, True, 0, 5)
    assert found["ok"] is True
    assert found["note"] == "raw scan"
    assert "in:scan_func" in found["results"]
    assert len(found["results"]) < 600

    class _Timeout:
        def __init__(self, _timeout_ms):
            pass

        def check(self):
            raise TimeoutError("budget")

    monkeypatch.setattr(refs, "SearchTimeout", _Timeout)
    timed = refs.search_regex("needle", False, None, None, False, 0, 5, timeout_ms=1)
    assert timed["timed_out"] is True
    assert timed["hint"]


def test_signature_filters_compose_size_calls_args_leaf_and_entry_modes(monkeypatch):
    refs = _module()
    funcs = {
        0x1000: SimpleNamespace(start_ea=0x1000, end_ea=0x1064),
        0x1100: SimpleNamespace(start_ea=0x1100, end_ea=0x1120),
        0x1200: SimpleNamespace(start_ea=0x1200, end_ea=0x1240),
        0x1300: SimpleNamespace(start_ea=0x1300, end_ea=0x1320),
    }
    names = {0x1000: "main", 0x1100: "leaf", 0x1200: "worker", 0x1300: "entry"}
    call_type = next(iter(refs.CALL_XREF_TYPES))
    outgoing = {
        0x1000: [SimpleNamespace(to=0x1200, type=call_type)],
        0x1100: [],
        0x1200: [SimpleNamespace(to=0x1100, type=call_type)],
        0x1300: [],
    }
    incoming = {
        0x1000: [],
        0x1100: [SimpleNamespace(iscode=True)],
        0x1200: [SimpleNamespace(iscode=True)],
        0x1300: [],
    }
    monkeypatch.setattr(refs.idautils, "Functions", lambda: iter(funcs))
    monkeypatch.setattr(refs._compat, "get_func_info", funcs.get)
    monkeypatch.setattr(refs.ida_funcs, "get_func_name", names.get)
    monkeypatch.setattr(refs.idautils, "XrefsFrom", lambda ea: iter(outgoing.get(ea, [])))
    monkeypatch.setattr(refs.idautils, "XrefsTo", lambda ea, *_args: iter(incoming.get(ea, [])))
    monkeypatch.setattr(refs.idc, "get_name", names.get)
    monkeypatch.setattr(refs, "compile_smart_pattern", lambda pattern, **_kwargs: lambda value: str(pattern).lower() in str(value).lower())

    plain = refs.search_func_by_sig("main", 0, 10)
    assert plain["ok"] is True and "main" in plain["results"]
    sized = refs.search_func_by_sig("size:>30 size:<100", 0, 10)
    assert sized["total"] == 3
    called = refs.search_func_by_sig("calls:worker", 0, 10)
    assert called["total"] == 1 and "main" in called["results"]
    leaf = refs.search_func_by_sig("leaf", 0, 10)
    assert leaf["total"] == 2
    entries = refs.search_func_by_sig("entry_point", 0, 10)
    assert entries["total"] == 2

    class _Tinfo:
        def get_func_details(self, data):
            data._count = 2
            return True

    class _FuncData:
        def size(self):
            return self._count

    monkeypatch.setattr(refs.ida_typeinf, "tinfo_t", _Tinfo)
    monkeypatch.setattr(refs.ida_typeinf, "func_type_data_t", _FuncData, raising=False)
    monkeypatch.setattr(refs.ida_nalt, "get_tinfo", lambda _tif, ea: ea in {0x1000, 0x1200})
    args = refs.search_func_by_sig("args:2+", 0, 10)
    assert args["total"] == 2
    exact = refs.search_func_by_sig("params:2", 0, 1)
    assert exact["truncated"] is True

    class _Timeout:
        def __init__(self, _timeout_ms):
            pass

        def check(self):
            raise TimeoutError("budget")

    monkeypatch.setattr(refs, "SearchTimeout", _Timeout)
    timed = refs.search_func_by_sig("main", 0, 10, timeout_ms=1)
    assert timed["timed_out"] is True
