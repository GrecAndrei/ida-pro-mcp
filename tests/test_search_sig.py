import os
import sys
import types
import pytest

ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))

# Mock IDA modules in-place to avoid breaking other tests
for mod_name in ("idaapi", "idautils", "idc", "ida_bytes", "ida_nalt",
                  "ida_lines", "ida_xref", "ida_funcs", "ida_hexrays",
                  "ida_typeinf", "ida_search", "ida_gdl", "ida_segment", "ida_kernwin", "ida_netnode", "ida_name", "ida_frame"):
    if mod_name not in sys.modules:
        sys.modules[mod_name] = types.ModuleType(mod_name)

sys.modules["idaapi"].BADADDR = 0xFFFFFFFF
sys.modules["idaapi"].get_kernel_version = lambda: "9.2"
sys.modules["idaapi"].MFF_FAST = 1
sys.modules["idaapi"].MFF_WRITE = 2
sys.modules["idaapi"].MFF_READ = 4

sys.modules["ida_kernwin"].MFF_FAST = 1
sys.modules["ida_kernwin"].MFF_WRITE = 2
sys.modules["ida_kernwin"].MFF_READ = 4
sys.modules["ida_funcs"].func_t = type("func_t", (), {})
sys.modules["ida_typeinf"].tinfo_t = type("tinfo_t", (), {})
sys.modules["ida_hexrays"].user_lvar_modifier_t = type("user_lvar_modifier_t", (), {})
sys.modules["idc"].batch = lambda x: 0
sys.modules["ida_netnode"].netnode = type("netnode", (), {
    "__init__": lambda *a, **kw: None,
    "longval": lambda *a: 0,
    "altval": lambda *a: 0,
    "getblob": lambda *a, **kw: None,
    "setblob": lambda *a, **kw: None,
})

# Mock rpc and sync modules in-place
for mod_name in ("rpc", "sync"):
    if mod_name not in sys.modules:
        sys.modules[mod_name] = types.ModuleType(mod_name)

sys.modules["rpc"].tool = lambda f: f
sys.modules["rpc"].unsafe = lambda f: f
sys.modules["rpc"].prompt = lambda f: f

sys.modules["sync"].idaread = lambda f: f
sys.modules["sync"].idawrite = lambda f: f
if not hasattr(sys.modules["sync"], "IDAError"):
    sys.modules["sync"].IDAError = type("IDAError", (Exception,), {})

# Define mock function info classes
class MockFunc:
    def __init__(self, start, end):
        self.start_ea = start
        self.end_ea = end

# Set up mock IDA behaviors
MOCK_FUNCTIONS = [0x401000, 0x402000, 0x403000]
MOCK_FUNC_MAP = {
    0x401000: MockFunc(0x401000, 0x401200),  # size = 512
    0x402000: MockFunc(0x402000, 0x402030),  # size = 48
    0x403000: MockFunc(0x403000, 0x4030c0),  # size = 192
}

class MockXref:
    def __init__(self, frm, to, iscode=True, xtype=21):
        self.frm = frm
        self.to = to
        self.iscode = iscode
        self.type = xtype

# Xrefs outgoing
MOCK_XREFS_FROM = {
    0x401000: [MockXref(0x401000, 0x402000)], # Calls 0x402000 (not leaf)
    0x402000: [],  # leaf
    0x403000: [],  # leaf
}

# Xrefs incoming
MOCK_XREFS_TO = {
    0x401000: [],  # no callers
    0x402000: [MockXref(0x401000, 0x402000)],
    0x403000: [],  # no callers
}

def setup_mocks():
    sys.modules["idautils"].Functions = lambda: MOCK_FUNCTIONS
    sys.modules["idaapi"].get_func = lambda ea: MOCK_FUNC_MAP.get(ea)
    sys.modules["ida_funcs"].get_func_name = lambda ea: f"func_{hex(ea)}"
    sys.modules["idc"].get_func_name = lambda ea: f"func_{hex(ea)}"
    sys.modules["idc"].get_name = lambda ea, *a: f"func_{hex(ea)}"
    sys.modules["idautils"].XrefsFrom = lambda ea, *a: MOCK_XREFS_FROM.get(ea, [])
    sys.modules["idautils"].XrefsTo = lambda ea, *a: MOCK_XREFS_TO.get(ea, [])

# Imports list for caching stub
sys.modules["ida_nalt"].get_import_module_qty = lambda: 0

from ida_pro_mcp.ida_mcp.tools.search.refs import search_func_by_sig

def test_func_by_sig_and_logic():
    setup_mocks()
    # 1. Test size constraint alone
    res = search_func_by_sig("size:>100", offset=0, limit=10)
    matches = res.get("matches", "")
    lines = matches.split("\n") if matches else []
    addrs = [line.split()[0] for line in lines]
    assert "0x401000" in addrs
    assert "0x403000" in addrs
    assert "0x402000" not in addrs

    # 2. Test leaf constraint alone
    res = search_func_by_sig("leaf", offset=0, limit=10)
    matches = res.get("matches", "")
    lines = matches.split("\n") if matches else []
    addrs = [line.split()[0] for line in lines]
    assert "0x402000" in addrs
    assert "0x403000" in addrs
    assert "0x401000" not in addrs

    # 3. Test AND logic: size:>100 AND leaf
    res = search_func_by_sig("size:>100 leaf", offset=0, limit=10)
    matches = res.get("matches", "")
    lines = matches.split("\n") if matches else []
    addrs = [line.split()[0] for line in lines]
    assert "0x403000" in addrs
    # 0x401000 is >100 but not a leaf, so it must be filtered out!
    assert "0x401000" not in addrs
    # 0x402000 is a leaf but not >100, so it must be filtered out!
    assert "0x402000" not in addrs

    # 4. Test no matching constraint
    res = search_func_by_sig("size:>1000", offset=0, limit=10)
    assert not res.get("matches", "")

