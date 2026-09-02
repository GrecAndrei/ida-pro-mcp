"""Boundary coverage for code-helper scans and disassembly windows."""

from __future__ import annotations

import importlib
import types

from tests.fakes.ida_fake import BADADDR


def _helpers():
    return importlib.import_module("ida_pro_mcp.ida_mcp.tools.code_helpers")


def test_disasm_window_handles_sparse_heads_and_tight_budgets(monkeypatch):
    helpers = _helpers()

    monkeypatch.setattr(
        helpers,
        "_format_disasm_line",
        lambda ea, **_kwargs: f"line-{ea:x}",
    )
    monkeypatch.setattr(
        helpers.idc,
        "prev_head",
        lambda ea, _minimum: {0x1004: 0x1000}.get(ea, BADADDR),
    )

    def next_head(ea, _maximum):
        return {
            0x1004: BADADDR,
            0x1007: 0x1008,
            0x1008: BADADDR,
            0x100B: BADADDR,
        }.get(ea, BADADDR)

    monkeypatch.setattr(helpers.idc, "next_head", next_head)
    monkeypatch.setattr(helpers.idc, "get_item_size", lambda _ea: 4)

    sparse = helpers._disasm_window(
        0x1004,
        radius=3,
        max_items=7,
        style="classic",
        include_bytes=False,
    )
    assert sparse == ["line-1000", "line-1004", "line-1008"]

    tight = helpers._disasm_window(
        0x1004,
        radius=3,
        max_items=2,
        style="classic",
        include_bytes=False,
    )
    assert tight == ["line-1004", "line-1008"]


def test_disasm_window_ignores_nonforward_next_heads(monkeypatch):
    helpers = _helpers()
    monkeypatch.setattr(
        helpers,
        "_format_disasm_line",
        lambda ea, **_kwargs: f"line-{ea:x}",
    )
    monkeypatch.setattr(helpers.idc, "prev_head", lambda *_args: BADADDR)
    monkeypatch.setattr(
        helpers.idc,
        "next_head",
        lambda ea, _maximum: 0x1000 if ea == 0x1004 else BADADDR,
    )
    monkeypatch.setattr(helpers.idc, "get_item_size", lambda _ea: 4)

    assert helpers._disasm_window(
        0x1004,
        radius=2,
        max_items=5,
        style="csmini",
        include_bytes=False,
    ) == ["line-1004"]


def test_gather_function_context_advances_all_iterator_modes(monkeypatch):
    helpers = _helpers()
    func = types.SimpleNamespace(start_ea=0x1000, end_ea=0x1008)

    class Iterator:
        def __init__(self, _func):
            self.ea = 0x1000

        def current(self):
            return self.ea

        def next_code(self):
            if self.ea == 0x1000:
                self.ea = 0x1004
                return True
            self.ea = BADADDR
            return False

    monkeypatch.setattr(helpers._compat, "get_func_start", lambda ea: ea)
    monkeypatch.setattr(helpers._compat, "get_func_info", lambda _ea: func)
    monkeypatch.setattr(helpers.idaapi, "get_first_cref_to", lambda _ea: BADADDR, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_first_cref_from", lambda _ea: BADADDR, raising=False)
    monkeypatch.setattr(helpers.idaapi, "get_first_dref_from", lambda _ea: BADADDR, raising=False)
    monkeypatch.setattr(helpers.idaapi, "func_item_iterator_t", Iterator, raising=False)
    monkeypatch.setattr(helpers, "_compute_cfg_semantics", lambda _func: {"nodes": 2})

    context = helpers.gather_function_context(0x1000)
    assert context["complexity"] == {"nodes": 2}


def test_api_prefilter_keeps_conservative_results_on_scan_limits_and_failures(monkeypatch):
    helpers = _helpers()
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda _ea: 0x1000)

    monkeypatch.setattr(helpers.idautils, "FuncItems", lambda _func: iter(range(4002)))
    assert helpers._function_may_reference_apis(0x1000, {"recv"}, set()) is True

    monkeypatch.setattr(
        helpers.idautils,
        "FuncItems",
        lambda _func: iter([0x1000]),
    )
    monkeypatch.setattr(
        helpers.idautils,
        "CodeRefsFrom",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("xref unavailable")),
    )
    monkeypatch.setattr(helpers, "_is_flow_control_mnemonic", lambda _mnem: True)
    assert helpers._function_may_reference_apis(0x1000, {"recv"}, {0x2000}) is True

    monkeypatch.setattr(
        helpers.idautils,
        "FuncItems",
        lambda _func: (_ for _ in ()).throw(RuntimeError("items unavailable")),
    )
    assert helpers._function_may_reference_apis(0x1000, set(), set()) is True


def test_api_chain_scan_stops_at_result_and_candidate_safety_limits(monkeypatch):
    helpers = _helpers()
    monkeypatch.setattr(
        helpers.idc,
        "get_name_ea_simple",
        lambda _name: (_ for _ in ()).throw(RuntimeError("name lookup unavailable")),
    )
    assert helpers._detect_api_chains(["recv"], max_items=0) == []

    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter(range(5002)))
    monkeypatch.setattr(helpers, "_function_may_reference_apis", lambda *_args: False)
    assert helpers._detect_api_chains(["recv"], max_items=2) == []

    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000]))
    monkeypatch.setattr(
        helpers,
        "_function_may_reference_apis",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("prefilter failed")),
    )
    assert helpers._detect_api_chains(["recv"], max_items=2) == []


def test_string_reference_scan_handles_invalid_objects_zero_addresses_and_duplicates(monkeypatch):
    helpers = _helpers()

    class BrokenString:
        def __str__(self):
            raise RuntimeError("string conversion failed")

    class StringObject:
        def __init__(self, ea):
            self.ea = ea

        def __str__(self):
            return "secret"

    def as_bytes(obj):
        if isinstance(obj, BrokenString):
            raise RuntimeError("string conversion failed")
        return b"secret"

    monkeypatch.setattr(helpers, "str", as_bytes, raising=False)
    monkeypatch.setattr(
        helpers.idautils,
        "Strings",
        lambda: [StringObject(0), BrokenString(), StringObject(0x5000), StringObject(0x6000)],
        raising=False,
    )
    monkeypatch.setattr(
        helpers.idautils,
        "XrefsTo",
        lambda _ea: [types.SimpleNamespace(frm=0x1000)],
    )
    monkeypatch.setattr(helpers._compat, "get_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(helpers.ida_funcs, "get_func_name", lambda _ea: "worker")

    matches = helpers._detect_string_refs("secret", max_items=5)
    assert len(matches) == 1
    assert matches[0]["string"] == "secret"

    assert helpers._detect_string_refs("secret", max_items=0) == []


def test_type_and_xor_detectors_continue_after_sdk_failures(monkeypatch):
    helpers = _helpers()
    monkeypatch.setattr(helpers, "_iter_all_functions", lambda: iter([0x1000, 0x2000, 0x3000]))

    class Tinfo:
        def __init__(self, ea):
            self.ea = ea

        def get_func_details(self, _data):
            if self.ea == 0x2000:
                return False
            if self.ea == 0x3000:
                raise RuntimeError("type details unavailable")
            return True

    monkeypatch.setattr(helpers.ida_typeinf, "tinfo_t", lambda: Tinfo(current_ea[0]))
    current_ea = [0]

    def get_tinfo(tinfo, ea):
        current_ea[0] = ea
        tinfo.ea = ea
        return ea != 0x1000

    monkeypatch.setattr(helpers.ida_nalt, "get_tinfo", get_tinfo)
    assert helpers._detect_type_matches("char") == []

    monkeypatch.setattr(helpers._compat, "get_func_start", lambda _ea: 0x1000)
    monkeypatch.setattr(
        helpers.idautils,
        "FuncItems",
        lambda _func: (_ for _ in ()).throw(RuntimeError("instruction iteration failed")),
    )
    assert helpers._detect_xor_heavy(threshold=1) == []
