"""Shared address-window helpers for semantic index and search."""

from __future__ import annotations


def radius_address_range(center_ea: int, radius: int) -> tuple[int, int]:
    """Return a half-open byte window ``[center-radius, center+radius)``.

    Index and search must use the same bounds so a function whose entry sits
    exactly at ``center + radius`` is excluded from both.
    """
    center = int(center_ea)
    rad = int(radius)
    if rad <= 0:
        raise ValueError("radius must be greater than zero")
    return (max(0, center - rad), center + rad)


def function_entry_in_ranges(entry_ea: int, ranges: list[tuple[int, int]]) -> bool:
    """True when a function entry EA lies inside any half-open ``[start, end)`` range."""
    fea = int(entry_ea)
    return any(start <= fea < end for start, end in ranges)
