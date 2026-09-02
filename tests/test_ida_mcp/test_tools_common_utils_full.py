"""Comprehensive unit tests for _common.py, utils.py, and error_handling.py.

Tests execute authentic logic against in-memory IDBs using tests/fakes/ida_fake.py
with zero dummy assertions.
"""

from __future__ import annotations

import errno
import struct
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Install fake IDA SDK in sys.modules BEFORE importing any ida_mcp modules
from tests.fakes.ida_fake import (
    BADADDR,
    BT_INT32,
    BT_PTR,
    BT_STRUCT,
    BT_VOID,
    SEGPERM_EXEC,
    SEGPERM_READ,
    SEGPERM_WRITE,
    FakeDatabase,
    FakeTinfo,
    FakeTypeLib,
    create_fake_idb,
    f_BIN,
    f_ELF,
    f_MACHO,
    f_PE,
    func_t,
    install_fake_idb,
    lvar_t,
    o_imm,
    o_near,
    o_reg,
    op_t,
    udm_t,
)

# Initialize global fake SDK so imports succeed
create_fake_idb()

from ida_pro_mcp.ida_mcp.error_handling import (
    ERROR_HINTS,
    MCPError,
    _category_for_code,
    _classify_error_code,
    _is_timeout_exception,
    _sanitize_exception_message,
    _timeout_code_for_context,
    check_debugger,
    handle_error,
    make_error,
    parse_address_canonical,
    parse_address_safe,
    require_arg,
    require_one_of,
    validate_action,
    validate_addr,
    validate_count,
    validate_path_safe,
    validate_range,
)
from ida_pro_mcp.ida_mcp.tools._common import (
    _filetype_name,
    _inf_bitness,
    _inf_filetype_id,
    _inf_is_64bit,
    _inf_is_be,
    _inf_max_ea,
    _inf_min_ea,
    _inf_procname,
    _inf_ptr_size,
    _inf_start_ea,
    public_arg,
    run_action,
    shannon_entropy,
)
from ida_pro_mcp.ida_mcp.utils import (
    Function,
    IDAError,
    compile_smart_pattern,
    get_function,
    get_image_size,
    get_prototype,
    get_stack_frame_variables_internal,
    get_type_by_name,
    hex_ea,
    hex_size,
    is_64bit,
    looks_like_address,
    my_modifier_t,
    normalize_dict_list,
    normalize_list_input,
    parse_address,
    resolve_symbol,
    smart_match,
)


@pytest.fixture(autouse=True)
def init_sample_idb():
    """Fixture that installs a rich fake IDB for common utility testing."""
    db = FakeDatabase(processor="metapc", bitness=64, base=0x140000000, filetype=f_PE)
    db.add_segment(0x140001000, 0x1000, name=".text", sclass="CODE", perm=SEGPERM_READ | SEGPERM_EXEC)
    db.add_segment(0x140002000, 0x1000, name=".data", sclass="DATA", perm=SEGPERM_READ | SEGPERM_WRITE)

    db.add_func(0x140001000, 0x140001040, name="main")
    db.add_func(0x140001040, 0x140001080, name="calc_hash")

    db.add_insn(0x140001000, "push", [op_t(0, o_reg, reg=5, text="rbp")], size=1)
    db.add_insn(0x140001001, "mov", [op_t(0, o_reg, reg=5, text="rbp"), op_t(1, o_reg, reg=4, text="rsp")], size=3)
    db.add_insn(0x140001004, "call", [op_t(0, o_near, addr=0x140001040, text="calc_hash")], size=5)
    db.add_insn(0x140001009, "ret", size=1)

    db.entries.append((1, 0x140001000, "main", False))

    struct_tif = FakeTinfo(lib=db.type_lib, name="user_context_t", kind=BT_STRUCT)
    struct_tif.add_udm(udm_t("uid", FakeTinfo(kind=BT_INT32, size=4), offset=0, size=4))
    struct_tif.add_udm(udm_t("name_ptr", FakeTinfo(kind=BT_PTR, size=8), offset=8, size=8))
    db.type_lib.register(struct_tif)

    install_fake_idb(db)
    return db


# ============================================================================
# 1. Tests for _common.py
# ============================================================================

def test_inf_helpers_64bit_pe(init_sample_idb):
    assert _inf_is_64bit() is True
    assert _inf_is_be() is False
    assert _inf_ptr_size() == 8
    assert _inf_bitness() == 64
    assert _inf_procname() == "metapc"
    assert _inf_min_ea() == 0x140001000
    assert _inf_max_ea() == 0x140003000
    assert _inf_start_ea() == 0x140000000
    assert _inf_filetype_id() == f_PE
    assert _filetype_name(8) == "pe"


def test_inf_helpers_32bit_arm_be():
    db = FakeDatabase(processor="arm", bitness=32, base=0x80000000, endian="big", filetype=f_ELF)
    db.add_segment(0x80000000, 0x4000, name=".text", sclass="CODE", perm=SEGPERM_READ | SEGPERM_EXEC)
    install_fake_idb(db)

    assert _inf_is_64bit() is False
    assert _inf_is_be() is True
    assert _inf_ptr_size() == 4
    assert _inf_bitness() == 32
    assert _inf_procname() == "arm"
    assert _filetype_name(7) == "elf"
    assert _filetype_name(10) == "macho"
    assert _filetype_name(17) == "raw"
    assert _filetype_name(999) == "type_999"


def test_public_arg_precedence():
    kwargs = {"address": "0x140001000", "count": 10, "empty": None}
    assert public_arg(kwargs, "address", "0x1000") == "0x140001000"
    assert public_arg(kwargs, "count", 5) == 10
    assert public_arg(kwargs, "empty", "fallback") == "fallback"
    assert public_arg(kwargs, "missing", "default_val") == "default_val"


def test_run_action_dispatch_and_error():
    handlers = {
        "status": lambda: {"status": "ok", "ready": True},
        "compute": lambda: {"result": 42},
    }
    res = run_action("status", handlers, tool_name="test_tool")
    assert res == {"status": "ok", "ready": True}

    err = run_action("comput", handlers, tool_name="test_tool")
    assert err["error"] is True
    assert err["code"] == MCPError.ACTION_NOT_FOUND
    assert "compute" in err["hint"]
    assert "test_tool" in err["message"]


def test_shannon_entropy():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy([]) == 0.0
    assert shannon_entropy(b"\x00" * 100) == 0.0
    assert shannon_entropy(b"\x00\x01" * 50) == 1.0

    data = bytes(range(256))
    ent = shannon_entropy(data)
    assert 7.9 < ent <= 8.0


# ============================================================================
# 2. Tests for utils.py
# ============================================================================

def test_get_image_size_and_is_64bit(init_sample_idb):
    size = get_image_size()
    assert size > 0
    assert is_64bit() is True


def test_parse_address_formats(init_sample_idb):
    assert parse_address(0x140001000) == 0x140001000
    assert parse_address("0x140001000") == 0x140001000
    assert parse_address("0X140001040") == 0x140001040
    assert parse_address("main") == 0x140001000
    assert parse_address("calc_hash") == 0x140001040
    assert parse_address("140001000") == 140001000

    with pytest.raises(IDAError, match="Failed to resolve address or symbol"):
        parse_address("non_existent_symbol_xyz")


def test_normalize_list_input():
    assert normalize_list_input(["a", "b"]) == ["a", "b"]
    assert normalize_list_input("foo, bar, baz") == ["foo", "bar", "baz"]
    assert normalize_list_input("single") == ["single"]
    assert normalize_list_input(123) == [123]


def test_resolve_symbol_scenarios(init_sample_idb):
    res_addr = resolve_symbol("0x140001000")
    assert res_addr["addr"] == "0x140001000"
    assert res_addr["name"] == "main"
    assert res_addr["is_func"] is True

    res_name = resolve_symbol("calc_hash")
    assert res_name["addr"] == "0x140001040"
    assert res_name["name"] == "calc_hash"
    assert res_name["is_func"] is True

    with pytest.raises(IDAError, match="query required"):
        resolve_symbol(None)

    with pytest.raises(IDAError, match="Not found"):
        resolve_symbol("unknown_func_404")


def test_normalize_dict_list():
    assert normalize_dict_list({"a": 1}) == [{"a": 1}]
    assert normalize_dict_list([{"a": 1}, {"b": 2}]) == [{"a": 1}, {"b": 2}]
    assert normalize_dict_list([]) == [{}]

    def parser(s: str) -> dict:
        k, v = s.split(":")
        return {k: v}

    res = normalize_dict_list(["k1:v1", "k2:v2"], string_parser=parser)
    assert res == [{"k1": "v1"}, {"k2": "v2"}]
    assert normalize_dict_list(["k1:v1", "k2:v2"]) == [{}]
    assert normalize_dict_list('{"x": 10}') == [{"x": 10}]
    assert normalize_dict_list('[{"x": 10}, {"y": 20}]') == [{"x": 10}, {"y": 20}]
    assert normalize_dict_list("k1:v1, k2:v2", string_parser=parser) == [{"k1": "v1"}, {"k2": "v2"}]
    assert normalize_dict_list(12345) == [{}]


def test_looks_like_address():
    assert looks_like_address("0x401000") is True
    assert looks_like_address("0XDEADBEEF") is True
    assert looks_like_address("401000") is True
    assert looks_like_address("140001000") is True
    assert looks_like_address("12") is False
    assert looks_like_address("main_func") is False
    assert looks_like_address("hello") is False


def test_get_function(init_sample_idb):
    fn = get_function(0x140001000)
    assert fn["addr"] == "0x140001000"
    assert fn["name"] == "main"
    assert int(fn["size"], 16) == 0x40

    fn_none = get_function(0x140009999, raise_error=False)
    assert fn_none is None

    with pytest.raises(IDAError, match="No function found at address"):
        get_function(0x140009999, raise_error=True)


def test_get_prototype_and_type_by_name(init_sample_idb):
    fn = init_sample_idb.get_func(0x140001000)
    proto = get_prototype(fn)
    assert proto is None or isinstance(proto, str)

    t_i8 = get_type_by_name("int8_t")
    assert t_i8.get_size() == 1
    t_u16 = get_type_by_name("uint16_t")
    assert t_u16.get_size() == 2
    t_i32 = get_type_by_name("int32")
    assert t_i32.get_size() == 4
    t_u64 = get_type_by_name("uint64")
    assert t_u64.get_size() == 8
    t_float = get_type_by_name("float")
    assert t_float.get_size() == 4
    t_double = get_type_by_name("double")
    assert t_double.get_size() == 8
    t_bool = get_type_by_name("bool")
    assert t_bool.get_size() == 1
    t_void = get_type_by_name("void")
    assert t_void.is_void()

    t_struct = get_type_by_name("user_context_t")
    assert t_struct.is_struct()
    assert t_struct.get_size() == 16

    with pytest.raises(IDAError, match="Unable to retrieve"):
        get_type_by_name("completely_unknown_type_t")


def test_modifier_and_formatting():
    assert hex_ea(0x1000) == "0x1000"
    assert hex_size(64) == "0x40"

    mod = my_modifier_t("var_1", FakeTinfo(kind=BT_INT32, size=4))
    assert mod.var_name == "var_1"
    assert mod.new_type.get_size() == 4

    class FakeLvinf:
        def __init__(self):
            lv1 = lvar_t("var_1", FakeTinfo(kind=BT_VOID, size=1), 0, 1)
            lv2 = lvar_t("var_2", FakeTinfo(kind=BT_VOID, size=1), 1, 1)
            self.lvvec = [lv1, lv2]

    lvinf = FakeLvinf()
    assert mod.modify_lvars(lvinf) is True
    assert lvinf.lvvec[0].type.get_size() == 4

    mod_not_found = my_modifier_t("var_missing", FakeTinfo(kind=BT_INT32, size=4))
    assert mod_not_found.modify_lvars(lvinf) is False


def test_smart_pattern_matching():
    matcher = compile_smart_pattern("foo")
    assert matcher("FOOBAR") is True
    assert matcher("hello") is False

    assert smart_match("Foo", "FooBar", case_sensitive=True) is True
    assert smart_match("Foo", "foobar", case_sensitive=True) is False

    empty_m = compile_smart_pattern("")
    assert empty_m("anything") is True


# ============================================================================
# 3. Tests for error_handling.py
# ============================================================================

def test_make_error_and_category():
    err_user = make_error(MCPError.INVALID_ARGS, "Parameter x invalid")
    assert err_user["error"] is True
    assert err_user["code"] == MCPError.INVALID_ARGS
    assert err_user["category"] == "user"
    assert err_user["recoverable"] is False
    assert "hint" in err_user

    err_policy = make_error(MCPError.GOVERNANCE_BLOCKED, "Blocked by safety policy")
    assert err_policy["category"] == "policy"

    err_runtime = make_error(MCPError.IDA_ERROR, "IDA kernel crashed")
    assert err_runtime["category"] == "runtime"

    err_custom = make_error(
        MCPError.TIMEOUT,
        "Operation timed out",
        hint="Retry with smaller slice",
        details={"step": 5},
        recoverable=True,
    )
    assert err_custom["hint"] == "Retry with smaller slice"
    assert err_custom["details"] == {"step": 5}
    assert err_custom["recoverable"] is True


def test_sanitize_exception_message():
    assert "Type mismatch" in _sanitize_exception_message(TypeError("'>' not supported between instances of 'str' and 'int'"))
    assert "Missing required parameter" in _sanitize_exception_message(TypeError("missing 1 required positional argument: 'x'"))
    assert "IDA API not available" in _sanitize_exception_message(AttributeError("module 'ida_nalt' has no attribute 'xyz'"))
    assert "Key not found" in _sanitize_exception_message(KeyError("missing_key"))
    assert "Value out of range" in _sanitize_exception_message(OverflowError("out of range"))


def test_timeout_classification_and_handling():
    t_err = TimeoutError("decompile hung")
    assert _is_timeout_exception(t_err) is True
    assert _timeout_code_for_context("decompile_function", "decompile hung") == MCPError.DECOMPILER_TIMEOUT
    assert _timeout_code_for_context("emulate_step", "emulation timed out") == MCPError.EMULATION_TIMEOUT
    assert _timeout_code_for_context("search_bytes", "search timed out") == MCPError.SEARCH_TIMEOUT
    assert _timeout_code_for_context(None, "generic timeout") == MCPError.RPC_TIMEOUT

    err = handle_error(TimeoutError("Search took too long"), context="search_patterns")
    assert err["error"] is True
    assert err["code"] == MCPError.SEARCH_TIMEOUT
    assert err["recoverable"] is True
    assert "traceback" in err["details"]

    os_err = OSError()
    os_err.errno = getattr(errno, "ETIMEDOUT", 110)
    assert _is_timeout_exception(os_err) is True


def test_parse_address_canonical_comprehensive(init_sample_idb):
    ea, err = parse_address_canonical(None)
    assert ea is None and err["code"] == MCPError.MISSING_REQUIRED_ARG

    ea, err = parse_address_canonical(True)
    assert ea is None and err["code"] == MCPError.ADDRESS_INVALID

    ea, err = parse_address_canonical(-1)
    assert ea is None and err["code"] == MCPError.ADDRESS_INVALID

    ea, err = parse_address_canonical(123.45)
    assert ea is None and err["code"] == MCPError.ADDRESS_INVALID

    ea, err = parse_address_canonical("   ")
    assert ea is None and err["code"] == MCPError.MISSING_REQUIRED_ARG

    ea, err = parse_address_canonical("0x140001000")
    assert ea == 0x140001000 and err is None

    ea, err = parse_address_canonical("0xGGGG")
    assert ea is None and err["code"] == MCPError.ADDRESS_INVALID

    ea, err = parse_address_canonical("main")
    assert ea == 0x140001000 and err is None

    ea, err = parse_address_canonical("140001000")
    assert ea == 0x140001000 and err is None

    ea, err = parse_address_canonical("1000")
    assert ea is None and err["code"] == MCPError.ADDRESS_INVALID
    assert "Ambiguous address" in err["message"]

    ea, err = parse_address_canonical("!@#$%^")
    assert ea is None and err["code"] == MCPError.ADDRESS_INVALID


def test_validate_addr(init_sample_idb):
    ea, err = validate_addr("0x140001000", require_code=True, require_func=True)
    assert ea == 0x140001000 and err is None

    ea, err = validate_addr("0x999999000")
    assert ea is None and err["code"] == MCPError.ADDRESS_NOT_MAPPED

    ea, err = validate_addr("0x140002000", require_func=True)
    assert ea is None and err["code"] == MCPError.FUNCTION_NOT_FOUND


def test_validate_range():
    s, e, err = validate_range("0x140001000", "0x140002000")
    assert s == 0x140001000 and e == 0x140002000 and err is None

    s, e, err = validate_range("0x140002000", "0x140001000")
    assert s is None and err["code"] == MCPError.INVALID_ARG_VALUE

    s, e, err = validate_range("0x1000", "0x20000000")
    assert s is None and err["code"] == MCPError.SIZE_LIMIT_EXCEEDED


def test_validate_path_safe():
    p, err = validate_path_safe("")
    assert p is None and err["code"] == MCPError.MISSING_REQUIRED_ARG

    p, err = validate_path_safe("test\x00file.txt")
    assert p is None and err["code"] == MCPError.INVALID_ARG_VALUE

    p, err = validate_path_safe("../etc/passwd")
    assert p is None and err["code"] == MCPError.PATH_TRAVERSAL

    p, err = validate_path_safe("/usr/bin/local", allow_absolute=False)
    assert p is None and err["code"] == MCPError.PATH_TRAVERSAL

    p, err = validate_path_safe("exports/sub/findings.json")
    assert p is not None and err is None


def test_require_arg_and_require_one_of():
    assert require_arg("val", "name") is None
    err = require_arg("", "name")
    assert err["code"] == MCPError.MISSING_REQUIRED_ARG
    err_none = require_arg(None, "name")
    assert err_none["code"] == MCPError.MISSING_REQUIRED_ARG

    assert require_one_of(addr="0x1000", name=None) is None
    assert require_one_of(addr=None, name="main") is None
    err_all_none = require_one_of(addr=None, name="", expr=None)
    assert err_all_none["code"] == MCPError.MISSING_REQUIRED_ARG


def test_validate_action_and_count():
    valid = ["create", "delete", "list", "info"]
    assert validate_action("create", valid) is None

    err = validate_action("creat", valid)
    assert err["code"] == MCPError.ACTION_NOT_FOUND
    assert "create" in err["hint"]

    assert validate_count(10, max_count=100) is None
    err_neg = validate_count(-1)
    assert err_neg["code"] == MCPError.INVALID_ARG_VALUE
    err_max = validate_count(20000, max_count=10000)
    assert err_max["code"] == MCPError.SIZE_LIMIT_EXCEEDED


def test_utils_image_size_fallback_and_symbol_resolution_modes(monkeypatch, init_sample_idb):
    import ida_ida
    import ida_name
    import idaapi
    import idautils
    import idc

    header = bytearray(0x80)
    header[:4] = b"PE\0\0"
    struct.pack_into("<I", header, 0x50, 0x2A00)
    monkeypatch.setattr(idaapi, "get_inf_structure", lambda: (_ for _ in ()).throw(AttributeError("legacy")))
    monkeypatch.setattr(ida_ida, "inf_get_omin_ea", lambda: 0x140001000)
    monkeypatch.setattr(ida_ida, "inf_get_omax_ea", lambda: 0x140002000)
    class _PE:
        def header(self):
            return bytes(header)

    def _peutils():
        return _PE()

    monkeypatch.setattr(idautils, "peutils_t", _peutils)
    assert get_image_size() == 0x2A00

    monkeypatch.setattr(idc, "get_name_ea_simple", lambda _query: BADADDR)
    monkeypatch.setattr(ida_name, "MNG_LONG_FORM", 0, raising=False)
    monkeypatch.setattr(ida_name, "demangle_name", lambda name, _flags: "Demo::run" if name == "_ZN4Demo3runEv" else None)
    monkeypatch.setattr(idautils, "Names", lambda: iter([(0x140002050, "_ZN4Demo3runEv")]))
    demangled = resolve_symbol("Demo::run")
    assert demangled == {"addr": "0x140002050", "name": "_ZN4Demo3runEv", "is_func": False}

    monkeypatch.setattr(ida_name, "demangle_name", lambda *_args: None)
    monkeypatch.setattr(idautils, "Names", lambda: iter([(0x140002060, "renamed_symbol")]))
    scanned = resolve_symbol("renamed_symbol")
    assert scanned["addr"] == "0x140002060"


def test_utils_prototype_and_type_alias_fallbacks(monkeypatch, init_sample_idb):
    import ida_nalt
    import ida_typeinf
    import idc

    class _WithPrototype:
        def get_prototype(self):
            return FakeTinfo(kind=BT_INT32, size=4)

    class _WithNoPrototype:
        start_ea = 0x140001000

    assert get_prototype(_WithPrototype()) is not None
    assert get_prototype(type("NullPrototype", (), {"get_prototype": lambda self: None})()) is None
    monkeypatch.setattr(idc, "get_type", lambda _ea: "int func(void)")
    assert get_prototype(_WithNoPrototype()) == "int func(void)"
    monkeypatch.setattr(idc, "get_type", lambda _ea: (_ for _ in ()).throw(RuntimeError("no legacy type")))
    monkeypatch.setattr(ida_nalt, "get_tinfo", lambda tif, _ea: setattr(tif, "kind", BT_INT32) or True)
    assert get_prototype(_WithNoPrototype()) is not None
    assert get_prototype(type("BrokenPrototype", (), {"get_prototype": lambda self: (_ for _ in ()).throw(RuntimeError("broken"))})()) is None

    aliases = {
        "uint8": 1, "int16": 2, "uint32": 4, "int64": 8,
        # The fake SDK represents the otherwise unsupported 128-bit and long
        # double kinds with its ordinary scalar fallback sizes.
        "int128": 4, "uint128": 4, "ldouble": 8, "boolean": 1,
    }
    for alias, size in aliases.items():
        assert get_type_by_name(alias).get_size() == size

    with pytest.raises(IDAError, match="Unable to retrieve"):
        get_type_by_name("not_a_real_type")


def test_utils_normalization_and_stack_frame_modes(monkeypatch, init_sample_idb):
    import ida_typeinf
    import idc

    import ida_pro_mcp.ida_mcp.utils as utils_module
    from ida_pro_mcp.ida_mcp import sync

    assert normalize_dict_list("", string_parser=lambda value: {"value": value}) == [{}]
    assert normalize_dict_list("not-json", string_parser=lambda value: {"value": value}) == [{"value": "not-json"}]
    assert normalize_dict_list(["", "x"], string_parser=lambda value: {"value": value}) == [{"value": "x"}]
    assert normalize_dict_list([{"ok": 1}, "mixed", 4]) == [{"ok": 1}]
    assert looks_like_address("") is False
    assert looks_like_address("0x") is True

    monkeypatch.setattr(sync, "ida_major", 8, raising=False)
    assert get_stack_frame_variables_internal(0x140001000, False) == []
    monkeypatch.setattr(sync, "ida_major", 9, raising=False)

    class _FrameInfo:
        def get_type_by_tid(self, _tid):
            return True

        def is_udt(self):
            return True

        def get_udt_details(self, out):
            out.extend([
                type("Member", (), {"name": "saved", "offset": 0, "size": 32, "type": "int", "is_gap": lambda self: False})(),
                type("Gap", (), {"name": "", "offset": 32, "size": 32, "type": "gap", "is_gap": lambda self: True})(),
            ])
            return True

    monkeypatch.setattr(ida_typeinf, "tinfo_t", _FrameInfo)
    monkeypatch.setattr(ida_typeinf, "udt_type_data_t", list)
    monkeypatch.setattr(utils_module._compat, "get_frame_id", lambda _ea: 77)
    frame = get_stack_frame_variables_internal(0x140001000, True)
    assert frame == [{"name": "saved", "offset": "0x0", "size": "0x4", "type": "int"}]
