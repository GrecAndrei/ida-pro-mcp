"""Funcs tool sync-mode routing."""
from __future__ import annotations

from tests._isolated_repo_loader import load_tool_module

_funcs = load_tool_module("funcs")


class TestFuncsSyncRouting:
    """Funcs dispatches actions directly via sync routing."""

    def test_funcs_has_tool_decorator(self) -> None:
        assert callable(getattr(_funcs, "funcs", None))

    def test_funcs_has_parse_address(self) -> None:
        assert hasattr(_funcs, "parse_address")

    def test_funcs_has_validate_addr(self) -> None:
        assert hasattr(_funcs, "validate_addr")

    def test_funcs_has_require_arg(self) -> None:
        assert hasattr(_funcs, "require_arg")

    def test_funcs_has_validate_count(self) -> None:
        assert hasattr(_funcs, "validate_count")

    def test_funcs_has_make_error(self) -> None:
        assert callable(getattr(_funcs, "make_error", None))
