"""Test for ida_pro_mcp.__main__ entry point."""

from __future__ import annotations

import runpy
import sys
from unittest.mock import patch


def test_package_main_invokes_server_main():
    with patch("ida_pro_mcp.host.server.server.main") as mock_main:
        runpy.run_module("ida_pro_mcp", run_name="__main__")
        assert mock_main.called
        assert sys.argv[0] == "ida_pro_mcp"
