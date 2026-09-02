"""Exercise the shared IDA-info helpers across supported SDK shapes."""

from __future__ import annotations

import importlib
import types

import pytest

from tests.fakes.ida_fake import create_sample_c_binary_idb, install_fake_idb

common = importlib.import_module("ida_pro_mcp.ida_mcp.tools._common")


@pytest.fixture(autouse=True)
def sample_idb():
    db = create_sample_c_binary_idb()
    install_fake_idb(db)
    return db


def test_info_helpers_use_idaapi_info_object_when_new_api_is_missing(monkeypatch):
    """IDA 7.x exposes values on get_inf_structure rather than ida_ida."""
    import ida_ida
    import idaapi

    new_api_names = (
        "inf_is_64bit",
        "inf_is_be",
        "inf_get_min_ea",
        "inf_get_max_ea",
        "inf_get_start_ea",
        "inf_get_procname",
        "inf_get_filetype",
        "inf_is_16bit",
        "inf_is_32bit_exactly",
    )
    idaapi_original = {
        name: getattr(idaapi, name, None)
        for name in ("inf_is_64bit", "inf_is_be")
    }
    for name in new_api_names:
        monkeypatch.delattr(ida_ida, name, raising=False)
    for name in idaapi_original:
        monkeypatch.delattr(idaapi, name, raising=False)

    assert common._inf_is_64bit() is True
    assert common._inf_is_be() is False
    assert common._inf_min_ea() == 0x140001000
    assert common._inf_max_ea() == idaapi.get_inf_structure().max_ea
    assert common._inf_start_ea() == 0x140000000
    assert common._inf_ptr_size() == 8


def test_info_helpers_use_legacy_idc_and_inf_attributes(monkeypatch, sample_idb):
    """The remaining legacy paths still work when only IDC values exist."""
    import ida_ida
    import idaapi
    import idc

    monkeypatch.delattr(ida_ida, "inf_get_procname", raising=False)
    monkeypatch.delattr(ida_ida, "inf_get_filetype", raising=False)
    monkeypatch.delattr(ida_ida, "inf_is_16bit", raising=False)
    monkeypatch.delattr(ida_ida, "inf_is_32bit_exactly", raising=False)
    monkeypatch.setattr(idc, "INF_PROCNAME", 33, raising=False)
    monkeypatch.setattr(idc, "INF_FILETYPE", 34, raising=False)
    monkeypatch.setattr(
        idc,
        "get_inf_attr",
        lambda attr: sample_idb.processor if attr == 33 else sample_idb.filetype if attr == 34 else 0,
        raising=False,
    )
    assert common._inf_procname() == "metapc"
    assert common._inf_filetype_id() == sample_idb.filetype
    assert common._inf_bitness() == 64

    # If IDC cannot provide the values, the old inf object remains a valid fallback.
    monkeypatch.setattr(idc, "get_inf_attr", lambda _attr: (_ for _ in ()).throw(RuntimeError("no IDC")))
    assert common._inf_procname() == "metapc"
    assert common._inf_filetype_id() == sample_idb.filetype


def test_info_helpers_fail_soft_when_every_sdk_variant_raises(monkeypatch):
    import ida_ida
    import idaapi
    import idc

    def explode(*_args, **_kwargs):
        raise RuntimeError("unavailable")

    for module, name in (
        (ida_ida, "inf_is_64bit"),
        (ida_ida, "inf_is_be"),
        (ida_ida, "inf_get_min_ea"),
        (ida_ida, "inf_get_max_ea"),
        (ida_ida, "inf_get_start_ea"),
        (ida_ida, "inf_get_procname"),
        (ida_ida, "inf_get_filetype"),
        (idaapi, "inf_is_64bit"),
        (idaapi, "inf_is_be"),
    ):
        monkeypatch.setattr(module, name, explode, raising=False)
    monkeypatch.setattr(idaapi, "get_inf_structure", explode, raising=False)
    monkeypatch.setattr(idc, "get_inf_attr", explode, raising=False)
    monkeypatch.setattr(idaapi, "cvar", types.SimpleNamespace(inf=types.SimpleNamespace()), raising=False)

    assert common._inf_is_64bit() is False
    assert common._inf_is_be() is False
    assert common._inf_min_ea() == 0
    assert common._inf_max_ea() == common.idaapi.BADADDR
    assert common._inf_start_ea() == common.idaapi.BADADDR
    assert common._inf_procname() == ""
    assert common._inf_filetype_id() == 0
    assert common._inf_bitness() == 32


def test_filetype_and_public_dispatch_boundaries():
    assert common._filetype_name() == "type_11"
    assert common._filetype_name(None) == "type_11"
    assert common._filetype_name(8) == "pe"
    assert common.public_arg({"x": False}, "x", True) is False
    assert common.run_action("missing", {}, tool_name="compat")["error"] is True
