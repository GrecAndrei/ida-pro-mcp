from __future__ import annotations

import os
import sys
import sqlite3
import pytest
import contextlib
from unittest.mock import MagicMock, patch

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
        sys.modules[m] = mock_mod
        
    try:
        yield
    finally:
        for m in ida_modules:
            if m in original_modules:
                sys.modules[m] = original_modules[m]
            else:
                sys.modules.pop(m, None)


def test_parse_register_offset():
    with mock_ida_context():
        from src.ida_pro_mcp.ida_mcp.tools.intelligence import _parse_register_offset
        # Test offset parsing from typical memory operands
        assert _parse_register_offset("[rsi+10h]") == ("rsi", 16)
        assert _parse_register_offset("[rdi-8]") == ("rdi", -8)
        assert _parse_register_offset("[rax+rbx*4+0x20]") == ("rax", 32)
        assert _parse_register_offset("[rcx]") == ("rcx", 0)
        assert _parse_register_offset("[rsi + 0x18]") == ("rsi", 24)


def test_tiny_emulator_parsing():
    with mock_ida_context():
        from src.ida_pro_mcp.ida_mcp.tools.trace_analysis import TinyEmulator
        
        # Mock get_func to return None inside mock context
        sys.modules["ida_funcs"].get_func.return_value = None
        
        emu = TinyEmulator(0x140001000)
        emu.regs["rsi"] = 0x1000
        emu.regs["rax"] = 2
        
        # Check parse_address_expr
        assert emu.parse_address_expr("[rsi+10h]") == 0x1010
        assert emu.parse_address_expr("[rsi+rax*4-0x8]") == 0x1000 + 8 - 8


def test_federation_blackboards(tmp_path):
    local_db = str(tmp_path / "local.blackboard.db")
    remote_db = str(tmp_path / "remote.blackboard.db")
    
    # Initialize local Blackboard with one entry
    from src.ida_pro_mcp.host.blackboard_store import BlackboardStore
    local_store = BlackboardStore(local_db)
    
    # Populate local entry
    with sqlite3.connect(local_db) as conn:
        conn.execute(
            """
            INSERT INTO blackboard (id, category, title, content, confidence, created_at, updated_at, version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("node_1", "general", "Local Node", "Desc 1", 0.5, 100.0, 100.0, 1)
        )
        conn.commit()
        
    # Initialize remote Blackboard with two entries
    remote_store = BlackboardStore(remote_db)
    with sqlite3.connect(remote_db) as conn:
        conn.execute(
            """
            INSERT INTO blackboard (id, category, title, content, confidence, created_at, updated_at, version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("node_1", "general", "Updated Remote Node", "Desc 1 version 2", 0.8, 100.0, 200.0, 2)
        )
        conn.execute(
            """
            INSERT INTO blackboard (id, category, title, content, confidence, created_at, updated_at, version)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("node_2", "network", "Remote Node 2", "Desc 2", 0.9, 150.0, 150.0, 1)
        )
        conn.commit()
        
    # Import Host-side FederationBridge (no IDA modules imported here)
    from src.ida_pro_mcp.host.intelligence.federation import FederationBridge
    bridge = FederationBridge(local_db)
    stats = bridge.federate_blackboards([remote_db])
    
    assert stats["inserted"] == 1
    assert stats["updated"] == 1
    assert stats["skipped"] == 0
    
    # Verify local DB updated
    with sqlite3.connect(local_db) as conn:
        rows = conn.execute("SELECT id, title, version, confidence FROM blackboard ORDER BY id").fetchall()
        
    assert rows[0][0] == "node_1"
    assert rows[0][1] == "Updated Remote Node"
    assert rows[0][2] == 2
    assert rows[0][3] == 0.8
    
    assert rows[1][0] == "node_2"
    assert rows[1][1] == "Remote Node 2"


def test_tiny_emulator_advanced():
    with mock_ida_context():
        from src.ida_pro_mcp.ida_mcp.tools.trace_analysis import TinyEmulator
        
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
        import idautils
        import ida_funcs
        
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
        
        from src.ida_pro_mcp.ida_mcp.tools.trace_analysis import _prefetch_function_context
        res = _prefetch_function_context(0x1000)
        assert res["ok"] is True
        assert res["function_address"] == "0x1000"
        assert "struct_definitions" in res
        assert "small_callees" in res

