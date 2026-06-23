"""Tests for MCP resources and host infrastructure."""
from __future__ import annotations

import pytest

from tests._isolated_repo_loader import load_host_module

_res = load_host_module("resources")
list_resources = _res.list_resources


class TestMCPResources:
    """MCP Resources protocol — resources/list."""

    def test_list_resources_returns_list(self) -> None:
        result = list_resources()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_list_resources_entries_have_uri_and_name(self) -> None:
        for entry in list_resources():
            assert "uri" in entry
            assert "name" in entry

    def test_list_resources_entries_have_mime_type(self) -> None:
        for entry in list_resources():
            assert "mimeType" in entry
