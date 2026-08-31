"""Behavior-focused tests for host environment configuration."""

from __future__ import annotations

import importlib


def test_ranking_boolean_env_defaults_survive_malformed_values(monkeypatch):
    """A typo must not silently disable the default embedding-first ranking."""
    import ida_pro_mcp.host.config as config

    with monkeypatch.context() as env:
        env.setenv("IDA_MCP_EMBEDDING_FIRST_MODE", "not-a-bool")
        env.setenv("IDA_MCP_ALLOW_HEURISTIC_FALLBACKS", "not-a-bool")
        importlib.reload(config)
        assert config.EMBEDDING_FIRST_MODE is True
        assert config.ALLOW_HEURISTIC_FALLBACKS is False

        env.setenv("IDA_MCP_EMBEDDING_FIRST_MODE", "off")
        env.setenv("IDA_MCP_ALLOW_HEURISTIC_FALLBACKS", "enabled")
        importlib.reload(config)
        assert config.EMBEDDING_FIRST_MODE is False
        assert config.ALLOW_HEURISTIC_FALLBACKS is True

    importlib.reload(config)
