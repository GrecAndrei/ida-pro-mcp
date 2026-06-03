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
