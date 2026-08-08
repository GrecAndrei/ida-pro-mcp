"""Shared address-window helpers used by the semantic index and search."""

from __future__ import annotations

import pytest

from ida_pro_mcp.host.intelligence.scope_window import (
    function_entry_in_ranges,
    radius_address_range,
)


def test_radius_range_half_open():
    assert radius_address_range(0x1000, 16) == (0xFF0, 0x1010)
    with pytest.raises(ValueError, match="radius must be greater than zero"):
        radius_address_range(0x1000, 0)


def test_radius_range_clamps_at_zero():
    assert radius_address_range(0x10, 32) == (0, 0x30)


def test_radius_range_requires_positive_radius():
    with pytest.raises(ValueError, match="radius must be greater than zero"):
        radius_address_range(0x1000, -4)


def test_function_entry_in_ranges():
    ranges = [(0x1000, 0x1100), (0x2000, 0x2100)]
    assert function_entry_in_ranges(0x1050, ranges) is True
    assert function_entry_in_ranges(0x1000, ranges) is True
    assert function_entry_in_ranges(0x1100, ranges) is False  # half-open
    assert function_entry_in_ranges(0x1FFF, ranges) is False
    assert function_entry_in_ranges(0x2050, ranges) is True
    assert function_entry_in_ranges(0x3050, []) is False
