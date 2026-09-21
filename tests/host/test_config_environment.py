"""Behavior-focused tests for host environment configuration."""

from __future__ import annotations

import importlib


def test_heuristic_boolean_env_defaults_survive_malformed_values(monkeypatch):
    """A malformed optional heuristic flag keeps its safe default."""
    import ida_pro_mcp.host.config as config

    with monkeypatch.context() as env:
        env.setenv("IDA_MCP_ALLOW_HEURISTIC_FALLBACKS", "not-a-bool")
        importlib.reload(config)
        assert config.ALLOW_HEURISTIC_FALLBACKS is False

        env.setenv("IDA_MCP_ALLOW_HEURISTIC_FALLBACKS", "enabled")
        importlib.reload(config)
        assert config.ALLOW_HEURISTIC_FALLBACKS is True

    importlib.reload(config)
