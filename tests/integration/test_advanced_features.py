from __future__ import annotations

import contextlib
import os
import sqlite3
import sys
from unittest.mock import MagicMock, patch

import pytest

from tests._isolated_repo_loader import load_host_module, load_tool_module

# Add search paths for local imports
_tools_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "ida_pro_mcp", "ida_mcp", "tools")
if _tools_dir not in sys.path:
    sys.path.insert(0, _tools_dir)


@contextlib.contextmanager
def mock_ida_context():
    """Context manager to temporarily mock all IDA Pro modules during test execution
    and completely clean them up afterwards to prevent test-runner pollution.
    """
    original_modules = {}
    ida_modules = [
        "idaapi", "idc", "idautils", "ida_bytes", "ida_funcs", "ida_ua",
        "ida_segment", "ida_kernwin", "ida_diskio", "ida_loader",
        "ida_name", "ida_netnode", "ida_entry", "ida_hexrays", "ida_nalt",
        "ida_strlist", "ida_typeinf", "ida_struct", "ida_enum", "ida_gdl",
        "ida_frame", "ida_moves", "ida_xref", "ida_search", "ida_expr",
        "ida_offset", "ida_range", "ida_lines", "ida_problems", "ida_regfind",
        "ida_allins", "ida_dbg"
    ]

    for m in ida_modules:
        if m in sys.modules:
            original_modules[m] = sys.modules[m]
        mock_mod = MagicMock()
        if m == "idaapi":
            mock_mod.get_kernel_version.return_value = "9.3"
        elif m == "idc":
            mock_mod.get_idb_path.return_value = ""
        elif m == "ida_loader":
            mock_mod.get_path.return_value = ""
            mock_mod.PATH_TYPE_IDB = 0
        sys.modules[m] = mock_mod

    try:
        yield
    finally:
        for m in ida_modules:
            if m in original_modules:
                sys.modules[m] = original_modules[m]
            else:
                sys.modules.pop(m, None)


# Fixture-style equivalent of mock_ida_context() that uses pytest's
# monkeypatch fixture (audit §7.2) so teardown is handled by pytest rather
# than the user-managed try/finally in the context manager above.
# Only used by the two tests whose sys.modules mutations were called out
# in the audit; the rest of the file keeps using mock_ida_context().
@pytest.fixture
def mock_ida(monkeypatch):
    ida_modules = [
        "idaapi", "idc", "idautils", "ida_bytes", "ida_funcs", "ida_ua",
        "ida_segment", "ida_kernwin", "ida_diskio", "ida_loader",
        "ida_name", "ida_netnode", "ida_entry", "ida_hexrays", "ida_nalt",
        "ida_strlist", "ida_typeinf", "ida_struct", "ida_enum", "ida_gdl",
        "ida_frame", "ida_moves", "ida_xref", "ida_search", "ida_expr",
        "ida_offset", "ida_range", "ida_lines", "ida_problems", "ida_regfind",
        "ida_allins", "ida_dbg",
    ]
    mocks = {}
    for m in ida_modules:
        mock_mod = MagicMock()
        if m == "idaapi":
            mock_mod.get_kernel_version.return_value = "9.3"
        elif m == "idc":
            mock_mod.get_idb_path.return_value = ""
        elif m == "ida_loader":
            mock_mod.get_path.return_value = ""
            mock_mod.PATH_TYPE_IDB = 0
        monkeypatch.setitem(sys.modules, m, mock_mod)
        mocks[m] = mock_mod
    yield mocks


def test_parse_register_offset():
    with mock_ida_context():
        intelligence_mod = load_tool_module("intelligence")
        _parse_register_offset = intelligence_mod._parse_register_offset
        # Test offset parsing from typical memory operands
        assert _parse_register_offset("[rsi+10h]") == ("rsi", 16)
        assert _parse_register_offset("[rdi-8]") == ("rdi", -8)
        assert _parse_register_offset("[rax+rbx*4+0x20]") == ("rax", 32)
        assert _parse_register_offset("[rcx]") == ("rcx", 0)
        assert _parse_register_offset("[rsi + 0x18]") == ("rsi", 24)


def test_tiny_emulator_parsing():
    with mock_ida_context():
        trace_mod = load_tool_module("trace_analysis")
        TinyEmulator = trace_mod.TinyEmulator

        # Mock get_func to return None inside mock context
        sys.modules["ida_funcs"].get_func.return_value = None

        emu = TinyEmulator(0x140001000)
        emu.regs["rsi"] = 0x1000
        emu.regs["rax"] = 2

        # Check parse_address_expr
        assert emu.parse_address_expr("[rsi+10h]") == 0x1010
        assert emu.parse_address_expr("[rsi+rax*4-0x8]") == 0x1000 + 8 - 8


def test_tiny_emulator_advanced():
    with mock_ida_context():
        trace_mod = load_tool_module("trace_analysis")
        TinyEmulator = trace_mod.TinyEmulator

        sys.modules["ida_funcs"].get_func.return_value = None

        emu = TinyEmulator(0x140001000)

        # Test taint propagation
        emu.set_reg_taint("rax", True)
        assert emu.is_reg_tainted("rax")
        assert emu.is_reg_tainted("eax")  # normalizes sub-registers

        emu.set_reg_taint("rax", False)
        assert not emu.is_reg_tainted("rax")

        # Test stack writes and stack strings
        emu.write_mem(0x7ffffff0, ord('T'), 1)
        emu.write_mem(0x7ffffff1, ord('E'), 1)
        emu.write_mem(0x7ffffff2, ord('S'), 1)
        emu.write_mem(0x7ffffff3, ord('T'), 1)
        emu.write_mem(0x7ffffff4, 0, 1)  # Null terminator

        stack_strs = emu.get_stack_strings()
        assert "TEST" in stack_strs

        # Test push and pop taint/value propagation
        emu.set_reg("rax", 0x1122334455667788)
        emu.set_reg_taint("rax", True)
        # Verify read_mem/write_mem with taint
        emu.write_mem(0x7ffffff8, 0x1122334455667788, 8)
        emu.set_mem_taint(0x7ffffff8, 8, True)
        assert emu.is_mem_tainted(0x7ffffff8, 8)
        assert emu.read_mem(0x7ffffff8, 8) == 0x1122334455667788

        # Test dereferenced pointers tracking
        emu.read_mem(0x140003000, 8)
        assert any(ptr == 0x140003000 for _, ptr, _ in emu.dereferenced_pointers)


def test_prefetch_context():
    with mock_ida_context():
        import sys

        import ida_funcs
        import idautils

        # Configure the active mock inside sys.modules
        sys.modules["ida_funcs"].get_func.return_value.start_ea = 0x1000
        sys.modules["ida_funcs"].get_func.return_value.end_ea = 0x1020

        f1 = ida_funcs.get_func(0x1000)
        print("DEBUG_F1_START:", f1.start_ea)
        print("DEBUG_F1_END:", f1.end_ea)

        idautils.XrefsTo.return_value = []
        idautils.XrefsFrom.return_value = []
        sys.modules["idc"].next_head.return_value = 0xffffffff

        sys.modules["ida_ua"].decode_insn.return_value = 0

        trace_mod = load_tool_module("trace_analysis")
        _prefetch_function_context = trace_mod._prefetch_function_context
        res = _prefetch_function_context(0x1000)
        assert res["ok"] is True
        assert res["function_address"] == "0x1000"
        assert "struct_definitions" in res
        assert "small_callees" in res



def test_tiny_emulator_new_instructions():
    with mock_ida_context():
        import sys
        from unittest.mock import MagicMock
        trace_mod = load_tool_module("trace_analysis")
        TinyEmulator = trace_mod.TinyEmulator

        # Configure mocked ida modules and constants
        import ida_ua
        ida_ua.o_reg = 1
        ida_ua.o_mem = 2
        ida_ua.o_phrase = 3
        ida_ua.o_displ = 4
        ida_ua.o_imm = 5
        ida_ua.o_near = 7

        # Set up a dictionary to hold our mocked instruction sequence
        mock_instructions = {}

        def mock_decode_insn(insn, ip):
            if ip in mock_instructions:
                inst_info = mock_instructions[ip]
                insn.size = inst_info.get("size", 4)
                insn.ea = ip

                # Setup operands
                ops = []
                for op_data in inst_info.get("ops", []):
                    op = MagicMock()
                    op.type = op_data.get("type", 0)
                    op.dtype = op_data.get("dtype", 0)
                    op.value = op_data.get("value", 0)
                    op.addr = op_data.get("addr", 0)
                    ops.append(op)

                while len(ops) < 6:
                    ops.append(MagicMock(type=0, dtype=0, value=0, addr=0))
                insn.ops = ops
                return 1
            return 0

        sys.modules["ida_ua"].decode_insn.side_effect = mock_decode_insn

        def mock_print_insn_mnem(ip):
            if ip in mock_instructions:
                return mock_instructions[ip]["mnem"]
            return ""

        sys.modules["idc"].print_insn_mnem.side_effect = mock_print_insn_mnem

        def mock_print_operand(ip, op_idx):
            if ip in mock_instructions:
                op_strs = mock_instructions[ip].get("op_strs", [])
                if op_idx < len(op_strs):
                    return op_strs[op_idx]
            return ""

        sys.modules["idc"].print_operand.side_effect = mock_print_operand

        # Mock get_func
        sys.modules["ida_funcs"].get_func.return_value = None

        emu = TinyEmulator(0x1000)

        # Helper to run emulator on registered instructions
        def run_emu_at(ip, mnem, op_strs, ops_data):
            mock_instructions[ip] = {
                "mnem": mnem,
                "op_strs": op_strs,
                "ops": ops_data,
                "size": 4
            }
            emu.ip = ip
            emu.step()

        # --- 1. ROL / ROR tests ---
        # 64-bit ROL immediate
        emu.set_reg("rax", 1)
        emu.set_reg_taint("rax", False)
        run_emu_at(0x1000, "rol", ["rax", "5"], [
            {"type": 1, "dtype": 7},
            {"type": 5, "value": 5}
        ])
        assert emu.get_reg("rax") == 0x20
        assert not emu.is_reg_tainted("rax")

        # 64-bit ROL immediate taint
        emu.set_reg("rax", 1)
        emu.set_reg_taint("rax", True)
        run_emu_at(0x1004, "rol", ["rax", "5"], [
            {"type": 1, "dtype": 7},
            {"type": 5, "value": 5}
        ])
        assert emu.get_reg("rax") == 0x20
        assert emu.is_reg_tainted("rax")

        # 64-bit ROR immediate
        emu.set_reg("rax", 0x20)
        emu.set_reg_taint("rax", False)
        run_emu_at(0x1008, "ror", ["rax", "5"], [
            {"type": 1, "dtype": 7},
            {"type": 5, "value": 5}
        ])
        assert emu.get_reg("rax") == 1

        # 64-bit ROL register-based count
        emu.set_reg("rbx", 0x8000000000000000)
        emu.set_reg("rcx", 1)
        emu.set_reg_taint("rbx", False)
        emu.set_reg_taint("rcx", False)
        run_emu_at(0x100c, "rol", ["rbx", "cl"], [
            {"type": 1, "dtype": 7},
            {"type": 1, "dtype": 0}
        ])
        assert emu.get_reg("rbx") == 1
        assert not emu.is_reg_tainted("rbx")

        # 64-bit ROL register count taint
        emu.set_reg("rbx", 0x8000000000000000)
        emu.set_reg("rcx", 1)
        emu.set_reg_taint("rcx", True)
        run_emu_at(0x1010, "rol", ["rbx", "cl"], [
            {"type": 1, "dtype": 7},
            {"type": 1, "dtype": 0}
        ])
        assert emu.get_reg("rbx") == 1
        assert emu.is_reg_tainted("rbx")

        # 32-bit ROL immediate
        emu.set_reg("rax", 0xf0000000)
        emu.set_reg_taint("rax", False)
        run_emu_at(0x1014, "rol", ["eax", "4"], [
            {"type": 1, "dtype": 2},
            {"type": 5, "value": 4}
        ])
        assert emu.get_reg("rax") == 0xf

        # 32-bit ROR immediate
        emu.set_reg("rax", 0xf)
        run_emu_at(0x1018, "ror", ["eax", "4"], [
            {"type": 1, "dtype": 2},
            {"type": 5, "value": 4}
        ])
        assert emu.get_reg("rax") == 0xf0000000

        # --- 2. NOT / NEG tests ---
        # NOT 64-bit
        emu.set_reg("rax", 0)
        emu.set_reg_taint("rax", False)
        emu.regs["zf"] = 0
        emu.regs["sf"] = 0
        run_emu_at(0x1020, "not", ["rax"], [
            {"type": 1, "dtype": 7}
        ])
        assert emu.get_reg("rax") == 0xffffffffffffffff
        assert emu.regs["zf"] == 0
        assert emu.regs["sf"] == 0

        # NOT 32-bit with taint
        emu.set_reg("rax", 0)
        emu.set_reg_taint("rax", True)
        run_emu_at(0x1024, "not", ["eax"], [
            {"type": 1, "dtype": 2}
        ])
        assert emu.get_reg("rax") == 0xffffffff
        assert emu.is_reg_tainted("rax")

        # NEG 64-bit
        emu.set_reg("rax", 1)
        emu.set_reg_taint("rax", False)
        run_emu_at(0x1028, "neg", ["rax"], [
            {"type": 1, "dtype": 7}
        ])
        assert emu.get_reg("rax") == 0xffffffffffffffff
        assert emu.regs["zf"] == 0
        assert emu.regs["sf"] == 1
        assert not emu.is_reg_tainted("rax")

        # NEG 32-bit zero with taint
        emu.set_reg("rax", 0)
        emu.set_reg_taint("rax", True)
        run_emu_at(0x102c, "neg", ["eax"], [
            {"type": 1, "dtype": 2}
        ])
        assert emu.get_reg("rax") == 0
        assert emu.regs["zf"] == 1
        assert emu.regs["sf"] == 0
        assert emu.is_reg_tainted("rax")

        # --- 3. CMOV tests ---
        # CMOVZ condition met (ZF = 1)
        emu.set_reg("rax", 0x1111)
        emu.set_reg("rbx", 0x2222)
        emu.regs["zf"] = 1
        emu.set_reg_taint("rbx", True)
        emu.set_reg_taint("rax", False)
        run_emu_at(0x1030, "cmovz", ["rax", "rbx"], [
            {"type": 1, "dtype": 7},
            {"type": 1, "dtype": 7}
        ])
        assert emu.get_reg("rax") == 0x2222
        assert emu.is_reg_tainted("rax")

        # CMOVZ condition NOT met (ZF = 0)
        emu.set_reg("rax", 0x1111)
        emu.set_reg("rbx", 0x2222)
        emu.regs["zf"] = 0
        emu.set_reg_taint("rax", False)
        emu.set_reg_taint("rbx", True)
        run_emu_at(0x1034, "cmovz", ["rax", "rbx"], [
            {"type": 1, "dtype": 7},
            {"type": 1, "dtype": 7}
        ])
        assert emu.get_reg("rax") == 0x1111
        assert not emu.is_reg_tainted("rax")

        # CMOVNZ condition met (ZF = 0)
        emu.set_reg("rax", 0x1111)
        emu.set_reg("rbx", 0x2222)
        emu.regs["zf"] = 0
        emu.set_reg_taint("rax", False)
        emu.set_reg_taint("rbx", True)
        run_emu_at(0x1038, "cmovnz", ["rax", "rbx"], [
            {"type": 1, "dtype": 7},
            {"type": 1, "dtype": 7}
        ])
        assert emu.get_reg("rax") == 0x2222
        assert emu.is_reg_tainted("rax")

        # CMOVNZ condition NOT met (ZF = 1)
        emu.set_reg("rax", 0x1111)
        emu.set_reg("rbx", 0x2222)
        emu.regs["zf"] = 1
        emu.set_reg_taint("rax", False)
        emu.set_reg_taint("rbx", True)
        run_emu_at(0x103c, "cmovnz", ["rax", "rbx"], [
            {"type": 1, "dtype": 7},
            {"type": 1, "dtype": 7}
        ])
        assert emu.get_reg("rax") == 0x1111
        assert not emu.is_reg_tainted("rax")

        # --- 4. SETcc tests ---
        # SETZ on register, ZF = 1
        emu.set_reg("rax", 0xff)
        emu.regs["zf"] = 1
        emu.flags_tainted = False
        run_emu_at(0x1040, "setz", ["al"], [
            {"type": 1, "dtype": 0}
        ])
        assert emu.get_reg("al") == 1
        assert not emu.is_reg_tainted("al")

        # SETZ on register, ZF = 0, tainted flags
        emu.set_reg("rax", 0xff)
        emu.regs["zf"] = 0
        emu.flags_tainted = True
        run_emu_at(0x1044, "setz", ["al"], [
            {"type": 1, "dtype": 0}
        ])
        assert emu.get_reg("al") == 0
        assert emu.is_reg_tainted("al")

        # SETNZ on memory address, ZF = 0, untainted flags
        emu.set_reg("rsi", 0x1000)
        emu.regs["zf"] = 0
        emu.flags_tainted = False
        run_emu_at(0x1048, "setnz", ["[rsi]"], [
            {"type": 3, "dtype": 0}
        ])
        assert emu.read_mem(0x1000, 1) == 1
        assert not emu.is_mem_tainted(0x1000, 1)

        # SETNZ on memory address, ZF = 1, tainted flags
        emu.set_reg("rsi", 0x1000)
        emu.regs["zf"] = 1
        emu.flags_tainted = True
        run_emu_at(0x104c, "setnz", ["[rsi]"], [
            {"type": 3, "dtype": 0}
        ])
        assert emu.read_mem(0x1000, 1) == 0
        assert emu.is_mem_tainted(0x1000, 1)


def test_symbolic_expression_solving_and_formatting():
    trace_mod = load_tool_module("trace_analysis")
    format_sym_expr = trace_mod.format_sym_expr
    format_constraint = trace_mod.format_constraint
    solve_constraints = trace_mod.solve_constraints

    # Test expression formatting
    expr1 = ("add", ("reg", "rdi"), ("val", 0x10))
    assert format_sym_expr(expr1) == "(rdi + 0x10)"

    expr2 = ("mem", ("sub", ("reg", "rbp"), ("val", 8)), 8)
    assert format_sym_expr(expr2) == "[(rbp - 8)]"

    # Test constraint formatting
    const1 = ("eq", expr1, ("val", 0x1337))
    assert format_constraint(const1) == "(rdi + 0x10) == 0x1337"

    const2 = ("zero", ("xor", ("reg", "rax"), ("val", 0xff)))
    assert format_constraint(const2) == "(rax ^ 0xff) == 0"

    # Test solving constraints
    solutions = solve_constraints([const1, const2])
    assert solutions["rdi"] == 0x1337 - 0x10
    assert solutions["rax"] == 0xff


def test_tiny_emulator_symbolic_execution_branch_split(mock_ida):
    # Audit §7.2: converted from `with mock_ida_context():` to a pytest
    # fixture (`mock_ida`) that uses `monkeypatch.setitem` for sys.modules
    # mocking. Pytest handles teardown via monkeypatch.undo() automatically.
    trace_mod = load_tool_module("trace_analysis")
    _trace_analysis_merged_dispatch = trace_mod._trace_analysis_merged_dispatch

    import ida_ua
    ida_ua.o_reg = 1
    ida_ua.o_mem = 2
    ida_ua.o_phrase = 3
    ida_ua.o_displ = 4
    ida_ua.o_imm = 5
    ida_ua.o_near = 7

    # Set up a dictionary to hold our mocked instruction sequence
    mock_instructions = {}

    def mock_decode_insn(insn, ip):
        if ip in mock_instructions:
            inst_info = mock_instructions[ip]
            insn.size = inst_info.get("size", 4)
            insn.ea = ip
            ops = []
            for op_data in inst_info.get("ops", []):
                op = MagicMock()
                op.type = op_data.get("type", 0)
                op.dtype = op_data.get("dtype", 0)
                op.value = op_data.get("value", 0)
                op.addr = op_data.get("addr", 0)
                ops.append(op)
            while len(ops) < 6:
                ops.append(MagicMock(type=0, dtype=0, value=0, addr=0))
            insn.ops = ops
            return 1
        return 0

    mock_ida["ida_ua"].decode_insn.side_effect = mock_decode_insn

    def mock_print_insn_mnem(ip):
        if ip in mock_instructions:
            return mock_instructions[ip]["mnem"]
        return ""

    mock_ida["idc"].print_insn_mnem.side_effect = mock_print_insn_mnem

    def mock_print_operand(ip, op_idx):
        if ip in mock_instructions:
            op_strs = mock_instructions[ip].get("op_strs", [])
            if op_idx < len(op_strs):
                return op_strs[op_idx]
        return ""

    mock_ida["idc"].print_operand.side_effect = mock_print_operand
    mock_ida["ida_funcs"].get_func.return_value = None

    # Set up instructions:
    # 0x1000: add rdi, 0x10
    # 0x1004: cmp rdi, 0x1337
    # 0x1008: je 0x1020
    # 0x100c: ret
    # 0x1020: ret
    mock_instructions[0x1000] = {
        "mnem": "add",
        "op_strs": ["rdi", "0x10"],
        "ops": [{"type": 1, "dtype": 7}, {"type": 5, "value": 0x10}],
        "size": 4
    }
    mock_instructions[0x1004] = {
        "mnem": "cmp",
        "op_strs": ["rdi", "0x1337"],
        "ops": [{"type": 1, "dtype": 7}, {"type": 5, "value": 0x1337}],
        "size": 4
    }
    mock_instructions[0x1008] = {
        "mnem": "je",
        "op_strs": ["0x1020"],
        "ops": [{"type": 7, "addr": 0x1020}],
        "size": 4
    }
    mock_instructions[0x100c] = {
        "mnem": "ret",
        "op_strs": [],
        "ops": [],
        "size": 1
    }
    mock_instructions[0x1020] = {
        "mnem": "ret",
        "op_strs": [],
        "ops": [],
        "size": 1
    }

    # Run speculative emulation via merged dispatch dispatcher
    res = _trace_analysis_merged_dispatch(
        action="deobfuscate_emulate",
        kwargs={
            "addr": "0x1000",
            "taint_regs": ["rdi"],
            "speculative": True,
            "max_depth": 10
        }
    )

    assert res["ok"] is True
    assert "paths" in res
    paths = res["paths"]
    assert len(paths) == 2

    # Check path properties
    p0 = paths[0]
    assert p0["last_address"] == "0x1020"
    assert "(rdi + 0x10) == 0x1337" in p0["constraints"]
    assert p0["solved_inputs"]["rdi"] == hex(0x1337 - 0x10)

    p1 = paths[1]
    assert p1["last_address"] == "0x100c"
    assert "(rdi + 0x10) != 0x1337" in p1["constraints"]
