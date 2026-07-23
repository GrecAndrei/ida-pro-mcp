from __future__ import annotations

from ida_pro_mcp.host.intelligence.scope_window import function_entry_in_ranges, radius_address_range


def test_index_and_search_agree_on_radius_boundary():
    """Functions at center+radius are excluded; one byte inside is included."""
    center = 0x401000
    radius = 0x1000
    start, end = radius_address_range(center, radius)
    ranges = [(start, end)]

    inside = center + radius - 1
    boundary = center + radius

    assert function_entry_in_ranges(inside, ranges)
    assert not function_entry_in_ranges(boundary, ranges)


def test_index_and_search_agree_on_multiple_ranges():
    ranges = [
        radius_address_range(0x1000, 0x10),
        radius_address_range(0x5000, 0x20),
    ]

    assert function_entry_in_ranges(0x1008, ranges)
    assert function_entry_in_ranges(0x5010, ranges)
    assert not function_entry_in_ranges(0x3000, ranges)
