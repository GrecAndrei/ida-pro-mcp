from __future__ import annotations

from pathlib import Path

import pytest

from ida_pro_mcp.host.stores.knowledge_graph import KnowledgeGraph


def test_knowledge_graph_systems(tmp_path: Path) -> None:
    db_file = tmp_path / "kg_test.db"
    kg = KnowledgeGraph(str(db_file))

    # Add system
    sys_id = kg.add_system(
        name="Network Stack",
        description="TCP/IP Packet processing engine",
        members=["0x401000", "0x401100"],
        entry_points=["0x401000"],
        exit_points=["0x401100"],
        tags=["networking", "lwip"],
        confidence=0.85,
    )
    assert isinstance(sys_id, str)
    assert len(sys_id) > 0

    # Get system
    sys_obj = kg.get_system(sys_id)
    assert sys_obj is not None
    assert sys_obj["name"] == "Network Stack"
    assert "0x401000" in sys_obj["members"]
    assert "networking" in sys_obj["tags"]

    # List systems
    systems = kg.list_systems()
    assert len(systems) == 1

    # Update system
    kg.update_system(sys_id, description="Updated Network Stack description", coverage_pct=75.0)
    sys_updated = kg.get_system(sys_id)
    assert sys_updated["description"] == "Updated Network Stack description"
    assert sys_updated["coverage_pct"] == 75.0


def test_knowledge_graph_structs_and_gaps(tmp_path: Path) -> None:
    db_file = tmp_path / "kg_test2.db"
    kg = KnowledgeGraph(str(db_file))

    # Add struct
    struct_id = kg.add_struct(
        name="eth_header_t",
        size_bytes=14,
        members=[
            {"offset": 0, "size": 6, "name": "dst_mac"},
            {"offset": 6, "size": 6, "name": "src_mac"},
            {"offset": 12, "size": 2, "name": "ethertype"},
        ],
        confidence=0.9,
    )
    assert isinstance(struct_id, str)

    struct_obj = kg.get_struct(struct_id)
    assert struct_obj is not None
    assert struct_obj["name"] == "eth_header_t"
    assert len(struct_obj["members"]) == 3

    # List structs
    all_structs = kg.list_structs()
    assert len(all_structs) == 1

    # Add gap
    gap_id = kg.add_gap(
        expected="Missing Cryptographic Handshake",
        why="Standard requires ECDH key exchange before transmitting payloads",
    )
    assert isinstance(gap_id, str)

    gaps = kg.list_gaps(resolved=False)
    assert len(gaps) == 1
    assert gaps[0]["expected"] == "Missing Cryptographic Handshake"

    # Fill gap
    kg.fill_gap(gap_id, filled_by="0x408000")
    unresolved_gaps = kg.list_gaps(resolved=False)
    assert len(unresolved_gaps) == 0
    resolved_gaps = kg.list_gaps(resolved=True)
    assert len(resolved_gaps) == 1


def test_knowledge_graph_state_machines_and_peripherals(tmp_path: Path) -> None:
    db_file = tmp_path / "kg_test3.db"
    kg = KnowledgeGraph(str(db_file))

    # Add state machine
    sm_id = kg.add_state_machine(
        name="BLE Connection State Machine",
        state_var="0x20001000",
        states=[
            {"value": 0, "name": "DISCONNECTED"},
            {"value": 1, "name": "ADVERTISING"},
            {"value": 2, "name": "CONNECTED"},
        ],
    )
    assert isinstance(sm_id, str)

    # Record transitions
    kg.add_transition(
        sm_id=sm_id,
        from_state="DISCONNECTED",
        to_state="ADVERTISING",
        trigger_addr="0x402000",
        condition="BLE_EVT_START_ADV",
    )
    kg.add_transition(
        sm_id=sm_id,
        from_state="ADVERTISING",
        to_state="CONNECTED",
        trigger_addr="0x402100",
        condition="BLE_EVT_CONNECTED",
    )

    sm = kg.get_state_machine(sm_id)
    assert sm is not None
    assert len(sm["transitions"]) == 2

    # Add attack surface
    as_id = kg.add_attack_surface(
        entry_point="0x403000",
        name="UART Command Parser",
        input_type="serial_rx",
        reachable_from="external",
    )
    assert isinstance(as_id, str)
    surfaces = kg.list_attack_surface()
    assert len(surfaces) == 1

    # Add peripheral
    p_id = kg.add_peripheral(
        name="USART1",
        base_addr="0x40013800",
        drivers=["0x401200"],
    )
    assert isinstance(p_id, str)
    periphs = kg.list_peripherals()
    assert len(periphs) == 1

    # Summary
    summary = kg.summary()
    assert summary["systems"] == 0
    assert summary["structs"] == 0
    assert summary["state_machines"] == 1
    assert summary["attack_surface_entries"] == 1
    assert summary["peripherals"] == 1
