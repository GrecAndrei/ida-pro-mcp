"""Semantic index/search radius windows stay half-open and aligned."""

from __future__ import annotations

import pytest

from ida_pro_mcp.host.intelligence.scope_window import radius_address_range


def test_radius_address_range_is_half_open():
    assert radius_address_range(0x401000, 0x1000) == (0x400000, 0x402000)
    # Entry exactly at center+radius is outside the window (end exclusive).
    start, end = radius_address_range(100, 10)
    assert start == 90
    assert end == 110
    assert start <= 109 < end
    assert not (start <= 110 < end)


def test_radius_address_range_rejects_non_positive():
    with pytest.raises(ValueError, match="radius must be greater than zero"):
        radius_address_range(0x1000, 0)
    with pytest.raises(ValueError, match="radius must be greater than zero"):
        radius_address_range(0x1000, -1)


def test_function_entry_in_ranges_uses_half_open_entry_semantics():
    from ida_pro_mcp.host.intelligence.scope_window import function_entry_in_ranges

    ranges = [radius_address_range(100, 10)]
    assert function_entry_in_ranges(90, ranges)
    assert function_entry_in_ranges(109, ranges)
    assert not function_entry_in_ranges(89, ranges)
    assert not function_entry_in_ranges(110, ranges)
