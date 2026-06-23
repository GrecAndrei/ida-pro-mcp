"""Integration tests for embed model discovery.

These verify that ``find_embed_model()`` works across the various
search paths it claims to support, without needing IDA Pro.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from ida_pro_mcp.installer.runtime import find_embed_model


@pytest.fixture
def sandbox(monkeypatch):
    """Set up a sandbox filesystem with isolated home + cwd.

    All ``find_embed_model()`` search paths point inside *tmpdir*.
    """
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        home = root / "home"
        home.mkdir()
        install = root / "install"
        install.mkdir()
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.delenv("IDA_MCP_EMBED_MODEL", raising=False)
        monkeypatch.setenv("IDA_PRO_MCP_HOME", str(install))
        # Chdir into the sandbox so Path.cwd() resolves inside it.
        old_cwd = Path.cwd()
        os.chdir(str(root))
        try:
            yield root, home, install
        finally:
            os.chdir(str(old_cwd))


def _put_model(parent: Path, name: str = "bge-code-v1-q8_0.gguf") -> Path:
    model = parent / name
    model.parent.mkdir(parents=True, exist_ok=True)
    model.write_text("x", encoding="utf-8")
    return model


class TestFindEmbedModel:
    def test_env_var_takes_precedence(self, sandbox):
        root, home, install = sandbox
        model = _put_model(root / "somewhere")
        os.environ["IDA_MCP_EMBED_MODEL"] = str(model)
        assert find_embed_model(install) == str(model)

    def test_install_root(self, sandbox):
        root, home, install = sandbox
        model = _put_model(install)
        assert find_embed_model(install) == str(model)

    def test_install_models_dir(self, sandbox):
        root, home, install = sandbox
        model = _put_model(install / "models")
        assert find_embed_model(install) == str(model)

    def test_home_downloads(self, sandbox):
        root, home, install = sandbox
        model = _put_model(home / "Downloads")
        assert find_embed_model(install) == str(model)

    def test_home_downloads_ida_pro_mcp(self, sandbox):
        root, home, install = sandbox
        model = _put_model(home / "Downloads" / "ida-pro-mcp")
        assert find_embed_model(install) == str(model)

    def test_home_documents(self, sandbox):
        root, home, install = sandbox
        model = _put_model(home / "Documents")
        assert find_embed_model(install) == str(model)

    def test_home_models(self, sandbox):
        root, home, install = sandbox
        model = _put_model(home / "models")
        assert find_embed_model(install) == str(model)

    def test_home_cache_ida_pro_mcp_models(self, sandbox):
        root, home, install = sandbox
        model = _put_model(home / ".cache" / "ida-pro-mcp" / "models")
        assert find_embed_model(install) == str(model)

    def test_cwd(self, sandbox):
        root, home, install = sandbox
        model = _put_model(install)
        # install *is* cwd (see sandbox fixture)
        assert find_embed_model(install) == str(model)

    def test_cwd_models(self, sandbox):
        root, home, install = sandbox
        model = _put_model(install / "models")
        assert find_embed_model(install) == str(model)

    def test_embed_search_paths_env(self, sandbox):
        root, home, install = sandbox
        extra = root / "my_models"
        model = _put_model(extra)
        os.environ["IDA_MCP_EMBED_SEARCH_PATHS"] = str(extra)
        assert find_embed_model(install) == str(model)

    def test_different_quantization_name(self, sandbox):
        root, home, install = sandbox
        model = _put_model(install, "bge-code-v1-q4_K_M.gguf")
        assert find_embed_model(install) == str(model)

    def test_prefers_install_root_over_fallback(self, sandbox):
        root, home, install = sandbox
        preferred = _put_model(install)
        # Place a decoy one level deeper to verify we pick the shallower match.
        _put_model(install / "sub" / "deeper")
        assert find_embed_model(install) == str(preferred)

    def test_returns_empty_when_nothing_found(self, sandbox):
        root, home, install = sandbox
        assert find_embed_model(install) == ""
