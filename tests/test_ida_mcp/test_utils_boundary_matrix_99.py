"""Boundary coverage for shared IDA-side utility helpers."""

from __future__ import annotations

import builtins
import sys
import types

import pytest

from tests.fakes.ida_fake import BADADDR, create_fake_idb

create_fake_idb()

import ida_nalt
import ida_typeinf
import idaapi
import idautils
import idc

from ida_pro_mcp.ida_mcp import utils


def test_utils_address_and_collection_fallback_modes(monkeypatch):
    monkeypatch.setattr(idc, "get_name_ea_simple", lambda _value: BADADDR)
    assert utils.parse_address("deadbeef") == int("deadbeef", 16)
    with pytest.raises(utils.IDAError):
        utils.parse_address("")
    assert utils.normalize_dict_list("123") == [{}]
    assert utils.normalize_dict_list("a,b") == [{}]

    monkeypatch.setattr(utils, "looks_like_address", lambda _value: True)
    monkeypatch.setattr(utils, "parse_address", lambda _value: (_ for _ in ()).throw(utils.IDAError("bad")))
    monkeypatch.setattr(idautils, "Names", lambda: iter(()))
    with pytest.raises(utils.IDAError, match="Not found"):
        utils.resolve_symbol("0x1000")


def test_is_64bit_falls_back_to_legacy_ida_info(monkeypatch):
    original_import = builtins.__import__

    def _without_common(name, *args, **kwargs):
        if name.endswith("ida_pro_mcp.ida_mcp.tools._common"):
            raise ImportError("common helper unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _without_common)
    monkeypatch.setattr(
        idaapi,
        "get_inf_structure",
        lambda: types.SimpleNamespace(is_64bit=lambda: True),
    )
    assert utils.is_64bit() is True


def test_named_type_and_prototype_fallback_branches(monkeypatch):
    constants = (
        "BTF_STRUCT",
        "BTF_TYPEDEF",
        "BTF_ENUM",
        "BTF_UNION",
    )

    class _Tinfo:
        target = None

        def __init__(self, *_args):
            return None

        def get_named_type(self, _til, _name, kind):
            return kind == self.target

    original_tinfo = ida_typeinf.tinfo_t
    monkeypatch.setattr(ida_typeinf, "tinfo_t", _Tinfo)
    for constant in constants:
        _Tinfo.target = getattr(ida_typeinf, constant)
        assert utils.get_type_by_name("named_alias") is not None
    monkeypatch.setattr(ida_typeinf, "tinfo_t", original_tinfo)

    class _FalseTinfo(_Tinfo):
        target = None

        def __bool__(self):
            return False

    monkeypatch.setattr(ida_typeinf, "tinfo_t", _FalseTinfo)
    with pytest.raises(utils.IDAError, match="Unable to retrieve"):
        utils.get_type_by_name("missing_alias")
    monkeypatch.setattr(ida_typeinf, "tinfo_t", original_tinfo)

    class _NoPrototype:
        start_ea = 0x1000

    monkeypatch.setattr(idc, "get_type", lambda _ea: (_ for _ in ()).throw(RuntimeError("no type")))
    monkeypatch.setattr(ida_nalt, "get_tinfo", lambda *_args: False)
    assert utils.get_prototype(_NoPrototype()) is None


def test_refresh_decompiler_ctext_handles_success_and_refusal(monkeypatch):
    from ida_pro_mcp.ida_mcp import compat

    refreshed = []

    class _Failure:
        pass

    class _Cfunc:
        def refresh_func_ctext(self):
            refreshed.append(True)

    monkeypatch.setattr(utils.ida_hexrays, "hexrays_failure_t", _Failure, raising=False)
    monkeypatch.setattr(utils.ida_hexrays, "DECOMP_WARNINGS", 0, raising=False)
    monkeypatch.setattr(compat.ida_hexrays, "decompile_func", lambda *_args: _Cfunc(), raising=False)
    utils.refresh_decompiler_ctext(0x1000)
    assert refreshed == [True]
    monkeypatch.setattr(compat.ida_hexrays, "decompile_func", lambda *_args: None, raising=False)
    utils.refresh_decompiler_ctext(0x1000)


def test_stack_frame_import_and_missing_function_errors(monkeypatch):
    original_import = builtins.__import__

    def _without_sync(name, *args, **kwargs):
        if name.endswith("ida_pro_mcp.ida_mcp.sync"):
            raise ImportError("sync unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _without_sync)
    with pytest.raises(utils.IDAError, match="No function found"):
        utils.get_stack_frame_variables_internal(0xDEADBEEF, True)
    assert utils.get_stack_frame_variables_internal(0xDEADBEEF, False) == []
