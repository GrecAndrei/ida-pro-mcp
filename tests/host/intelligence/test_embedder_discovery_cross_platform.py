"""Cross-platform tests for embedder (bge-code-v1 / llama-server) discovery.

Covers:
  * Windows `.exe` variants of the llama-server binary
  * The installer-managed install root as a discovery location
  * The manual `embedder.json` override (write + read)
  * Conventional per-platform search directories
  * Path-list env vars (`IDA_MCP_EMBED_*` with `;` / `:` separators)
  * The cross-platform `_is_executable` helper
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import textwrap
from pathlib import Path

import pytest

from ida_pro_mcp.host.intelligence.core import (
    EMBEDDER_STATE_FILE,
    _find_llama_server,
    _find_model,
    _is_executable,
    _llama_server_binary_names,
    _read_embedder_state,
    _select_state_path,
    _install_root,
    write_embedder_state,
)


IS_WINDOWS = sys.platform == "win32"
EXE_SUFFIX = ".exe" if IS_WINDOWS else ""


@pytest.fixture
def clean_state(monkeypatch):
    """Strip every override path from the environment and module state."""
    for var in (
        "IDA_MCP_EMBED_SERVER_BIN",
        "IDA_MCP_EMBED_MODEL",
        "IDA_PRO_MCP_HOME",
        "IDA_MCP_CACHE_DIR",
        "IDA_MCP_DATA_DIR",
        "LOCALAPPDATA",
        "APPDATA",
        "XDG_CONFIG_HOME",
        "HOME",
        "USERPROFILE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core._MODEL_PATH_CACHE", None
    )
    return monkeypatch


@pytest.fixture
def sandbox_home(monkeypatch, tmp_path: Path):
    """Redirect Path.home() to a temporary dir so home-relative discovery is
    hermetic.  Also seeds a few "real-looking" platform vars."""
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core.Path.home", classmethod(lambda cls: tmp_path))
    if IS_WINDOWS:
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))
        monkeypatch.setenv("APPDATA", str(tmp_path / "AppData" / "Roaming"))
        monkeypatch.setenv("ProgramFiles", str(tmp_path / "ProgramFiles"))
        monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path / "ProgramFiles (x86)"))
    else:
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    return tmp_path


# ─── _is_executable ─────────────────────────────────────────────────────────


def test_is_executable_rejects_missing_file(tmp_path: Path):
    assert _is_executable(str(tmp_path / "nope")) is False
    assert _is_executable("") is False


def test_is_executable_rejects_text_file(tmp_path: Path):
    text = tmp_path / "readme.txt"
    text.write_text("hi", encoding="utf-8")
    assert _is_executable(str(text)) is False


def test_is_executable_accepts_platform_binary(tmp_path: Path):
    if IS_WINDOWS:
        bin_path = tmp_path / "llama-server.exe"
    else:
        bin_path = tmp_path / "llama-server"
    bin_path.write_bytes(b"MZ" if IS_WINDOWS else b"\x7fELF")
    bin_path.chmod(0o755)
    assert _is_executable(str(bin_path)) is True


# ─── _llama_server_binary_names ─────────────────────────────────────────────


def test_llama_server_binary_names_includes_exe_on_windows():
    names = _llama_server_binary_names()
    if IS_WINDOWS:
        assert "llama-server.exe" in names
    else:
        # POSIX still tolerates the .exe variant in case a tool placed it.
        assert "llama-server.exe" in names
    assert "llama-server" in names


# ─── _install_root ──────────────────────────────────────────────────────────


def test_install_root_windows_uses_localappdata(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))
    monkeypatch.delenv("IDA_PRO_MCP_HOME", raising=False)
    root = _install_root()
    assert root.endswith("ida-pro-mcp")
    assert "ida-pro-mcp" in root


def test_install_root_honors_ida_pro_mcp_home(monkeypatch, tmp_path: Path):
    override = tmp_path / "my-custom-root"
    monkeypatch.setenv("IDA_PRO_MCP_HOME", str(override))
    assert _install_root().endswith("my-custom-root")


# ─── write_embedder_state + _read_embedder_state ────────────────────────────


def test_write_and_read_embedder_state_roundtrip(tmp_path: Path):
    model = tmp_path / "bge-code-v1-q8_0.gguf"
    model.write_bytes(b"fake-gguf")
    server = tmp_path / "bin" / f"llama-server{EXE_SUFFIX}"
    server.parent.mkdir(parents=True, exist_ok=True)
    server.write_bytes(b"fake-bin")
    server.chmod(0o755)

    state_path = write_embedder_state(
        tmp_path, model_path=str(model), server_bin=str(server)
    )
    assert Path(state_path).is_file()
    blob = json.loads(Path(state_path).read_text(encoding="utf-8"))
    assert blob["model_path"].endswith("bge-code-v1-q8_0.gguf")
    assert blob["server_bin"].endswith(f"llama-server{EXE_SUFFIX}")
    assert "updated_at" in blob


def test_write_embedder_state_omits_empty_fields(tmp_path: Path):
    state_path = write_embedder_state(tmp_path, model_path="/some/model.gguf")
    blob = json.loads(Path(state_path).read_text(encoding="utf-8"))
    assert "model_path" in blob
    assert "server_bin" not in blob
    assert "disabled" not in blob


def test_write_embedder_state_persists_disabled_flag(tmp_path: Path):
    state_path = write_embedder_state(tmp_path, disabled=True)
    blob = json.loads(Path(state_path).read_text(encoding="utf-8"))
    assert blob["disabled"] is True


def test_read_embedder_state_install_root_wins(clean_state, tmp_path: Path, monkeypatch):
    """When the state file exists at <install_root>/embedder.json, it wins."""
    monkeypatch.setenv("IDA_PRO_MCP_HOME", str(tmp_path))

    real = tmp_path / "bge-code-v1-q8_0.gguf"
    real.write_bytes(b"real")
    write_embedder_state(tmp_path, model_path=str(real))

    # Even if APPDATA points at a different (non-existent) dir, install root wins.
    other = tmp_path / "elsewhere"
    monkeypatch.setenv(
        "APPDATA" if IS_WINDOWS else "XDG_CONFIG_HOME", str(other)
    )
    state = _read_embedder_state()
    assert state.get("model_path", "").endswith("bge-code-v1-q8_0.gguf")
    assert state["_source"].endswith(EMBEDDER_STATE_FILE)


# ─── _select_state_path ─────────────────────────────────────────────────────


def test_select_state_path_string():
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("ida_pro_mcp.host.intelligence.core.os.path.isfile", lambda p: True)
        assert _select_state_path("~/foo") == os.path.abspath(os.path.expanduser("~/foo"))


def test_select_state_path_list_picks_existing():
    with pytest.MonkeyPatch.context() as mp:
        def fake_isfile(p):
            return p.endswith("good")
        mp.setattr("ida_pro_mcp.host.intelligence.core.os.path.isfile", fake_isfile)
        out = _select_state_path(["/bad/one", "/path/good", "/other"])
        assert out.endswith(os.path.join("path", "good"))


def test_select_state_path_none_and_false():
    assert _select_state_path(None) == ""
    assert _select_state_path(False) == ""


def test_select_state_path_no_existing_files(tmp_path: Path):
    assert _select_state_path(str(tmp_path / "missing")) == ""


# ─── _find_llama_server ─────────────────────────────────────────────────────


def test_find_llama_server_uses_env_var(clean_state, tmp_path: Path):
    server = tmp_path / f"llama-server{EXE_SUFFIX}"
    server.write_bytes(b"MZ" if IS_WINDOWS else b"\x7fELF")
    server.chmod(0o755)
    clean_state.setenv("IDA_MCP_EMBED_SERVER_BIN", str(server))
    assert _find_llama_server().endswith(f"llama-server{EXE_SUFFIX}")


def test_find_llama_server_env_list_separated(clean_state, tmp_path: Path):
    bad = tmp_path / "missing.exe"
    good = tmp_path / f"llama-server{EXE_SUFFIX}"
    good.write_bytes(b"MZ" if IS_WINDOWS else b"\x7fELF")
    good.chmod(0o755)
    sep = ";" if IS_WINDOWS else ":"
    clean_state.setenv(
        "IDA_MCP_EMBED_SERVER_BIN", f"{bad}{sep}{good}"
    )
    assert _find_llama_server().endswith(f"llama-server{EXE_SUFFIX}")


def test_find_llama_server_picks_install_root_bin(clean_state, tmp_path: Path):
    """The installer places llama-server in <install_root>/bin/."""
    clean_state.setenv("IDA_PRO_MCP_HOME", str(tmp_path))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    server = bin_dir / f"llama-server{EXE_SUFFIX}"
    server.write_bytes(b"MZ" if IS_WINDOWS else b"\x7fELF")
    server.chmod(0o755)
    assert _find_llama_server() == str(server.resolve())


def test_find_llama_server_picks_install_root_direct(clean_state, tmp_path: Path):
    clean_state.setenv("IDA_PRO_MCP_HOME", str(tmp_path))
    server = tmp_path / f"llama-server{EXE_SUFFIX}"
    server.write_bytes(b"MZ" if IS_WINDOWS else b"\x7fELF")
    server.chmod(0o755)
    assert _find_llama_server() == str(server.resolve())


def test_find_llama_server_honors_embedder_state(clean_state, tmp_path: Path):
    """`embedder.json` server_bin override takes precedence over auto-scan."""
    clean_state.setenv("IDA_PRO_MCP_HOME", str(tmp_path))
    state = tmp_path / EMBEDDER_STATE_FILE

    chosen = tmp_path / "manual" / f"llama-server{EXE_SUFFIX}"
    chosen.parent.mkdir(parents=True, exist_ok=True)
    chosen.write_bytes(b"MZ" if IS_WINDOWS else b"\x7fELF")
    chosen.chmod(0o755)

    decoy = tmp_path / "bin" / f"llama-server{EXE_SUFFIX}"
    decoy.parent.mkdir(parents=True, exist_ok=True)
    decoy.write_bytes(b"MZ" if IS_WINDOWS else b"\x7fELF")
    decoy.chmod(0o755)

    state.write_text(
        json.dumps({"server_bin": str(chosen)}), encoding="utf-8"
    )
    assert _find_llama_server() == str(chosen.resolve())


def test_find_llama_server_returns_empty_when_nothing_found(clean_state, sandbox_home, monkeypatch):
    clean_state.setenv("IDA_PRO_MCP_HOME", str(sandbox_home))
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core.shutil.which", lambda x: None)
    assert _find_llama_server() == ""


def test_find_llama_server_rejects_non_executable_override(clean_state, sandbox_home: Path, tmp_path: Path, monkeypatch):
    clean_state.setenv("IDA_PRO_MCP_HOME", str(sandbox_home))
    fake = tmp_path / "fake-llama"
    fake.write_text("not a real binary", encoding="utf-8")
    clean_state.setenv("IDA_MCP_EMBED_SERVER_BIN", str(fake))
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core.shutil.which", lambda x: None)
    if IS_WINDOWS:
        # .exe extension is required on Windows; a bare "fake-llama" is rejected.
        assert _find_llama_server() == ""
    else:
        # POSIX checks the x bit; a text file without +x is also rejected.
        assert _find_llama_server() == ""


# ─── _find_model ────────────────────────────────────────────────────────────


def test_find_model_uses_env_var(clean_state, tmp_path: Path):
    model = tmp_path / "bge-code-v1-q8_0.gguf"
    model.write_bytes(b"x")
    clean_state.setenv("IDA_MCP_EMBED_MODEL", str(model))
    assert _find_model() == str(model.resolve())


def test_find_model_env_list_separated(clean_state, tmp_path: Path):
    bad = tmp_path / "missing.gguf"
    good = tmp_path / "bge-code-v1-q8_0.gguf"
    good.write_bytes(b"x")
    sep = ";" if IS_WINDOWS else ":"
    clean_state.setenv("IDA_MCP_EMBED_MODEL", f"{bad}{sep}{good}")
    assert _find_model() == str(good.resolve())


def test_find_model_picks_install_root(clean_state, tmp_path: Path):
    clean_state.setenv("IDA_PRO_MCP_HOME", str(tmp_path))
    model = tmp_path / "bge-code-v1-q8_0.gguf"
    model.write_bytes(b"x")
    assert _find_model() == str(model.resolve())


def test_find_model_picks_install_root_models_subdir(clean_state, tmp_path: Path):
    clean_state.setenv("IDA_PRO_MCP_HOME", str(tmp_path))
    models = tmp_path / "models"
    models.mkdir(parents=True, exist_ok=True)
    model = models / "bge-code-v1.gguf"
    model.write_bytes(b"x")
    assert _find_model() == str(model.resolve())


def test_find_model_honors_embedder_state(clean_state, tmp_path: Path):
    clean_state.setenv("IDA_PRO_MCP_HOME", str(tmp_path))
    state = tmp_path / EMBEDDER_STATE_FILE
    chosen = tmp_path / "elsewhere" / "bge-code-v1-q8_0.gguf"
    chosen.parent.mkdir(parents=True, exist_ok=True)
    chosen.write_bytes(b"x")
    decoy = tmp_path / "bge-code-v1-q8_0.gguf"
    decoy.write_bytes(b"x")
    state.write_text(
        json.dumps({"model_path": str(chosen)}), encoding="utf-8"
    )
    assert _find_model() == str(chosen.resolve())


def test_find_model_prefers_q8_over_full(clean_state, tmp_path: Path):
    """Both filenames are valid; the q8_0 variant is preferred."""
    clean_state.setenv("IDA_PRO_MCP_HOME", str(tmp_path))
    full = tmp_path / "bge-code-v1.gguf"
    full.write_bytes(b"full")
    q8 = tmp_path / "bge-code-v1-q8_0.gguf"
    q8.write_bytes(b"q8")
    out = _find_model()
    assert out == str(q8.resolve())


def test_find_model_returns_empty_when_nothing_found(clean_state, sandbox_home):
    clean_state.setenv("IDA_PRO_MCP_HOME", str(sandbox_home))
    assert _find_model() == ""


# ─── Cross-platform path resolution ─────────────────────────────────────────


@pytest.mark.skipif(not IS_WINDOWS, reason="Windows-specific path behavior")
def test_windows_program_files_search(clean_state, tmp_path: Path, monkeypatch):
    """`%ProgramFiles%\\llama.cpp\\bin` is honored on Windows."""
    clean_state.setenv("IDA_PRO_MCP_HOME", str(tmp_path))
    pf = tmp_path / "ProgramFiles"
    pf.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("ProgramFiles", str(pf))
    monkeypatch.setenv("ProgramFiles(x86)", str(pf / "(x86)"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "lad"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roam"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))

    bin_dir = pf / "llama.cpp" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    server = bin_dir / "llama-server.exe"
    server.write_bytes(b"MZ")
    assert _find_llama_server() == str(server.resolve())


@pytest.mark.skipif(not IS_WINDOWS, reason="Windows-specific path behavior")
def test_windows_scoop_search(clean_state, tmp_path: Path, monkeypatch):
    """`%USERPROFILE%\\scoop\\apps\\llama.cpp\\current\\bin` is honored."""
    clean_state.setenv("IDA_PRO_MCP_HOME", str(tmp_path))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "pf"))
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path / "pf86"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "lad"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roam"))
    profile = tmp_path / "home"
    monkeypatch.setenv("USERPROFILE", str(profile))

    bin_dir = profile / "scoop" / "apps" / "llama.cpp" / "current" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    server = bin_dir / "llama-server.exe"
    server.write_bytes(b"MZ")
    assert _find_llama_server() == str(server.resolve())


@pytest.mark.skipif(IS_WINDOWS, reason="POSIX-specific path behavior")
def test_posix_search_usr_local_bin(clean_state, tmp_path: Path, monkeypatch):
    """/usr/local/bin/llama-server is honored on POSIX."""
    clean_state.setenv("IDA_PRO_MCP_HOME", str(tmp_path))
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core.shutil.which", lambda x: None)
    # Don't let /usr/local/bin or /usr/bin from the real filesystem interfere.
    fake_root = tmp_path / "fake-root"
    fake_root.mkdir(parents=True, exist_ok=True)
    local = fake_root / "usr" / "local" / "bin"
    local.mkdir(parents=True, exist_ok=True)
    server = local / "llama-server"
    server.write_bytes(b"\x7fELF")
    server.chmod(0o755)
    _real_isdir = os.path.isdir
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core.os.path.isdir",
        lambda p: (p == "/usr/local/bin" or p == "/usr/bin" or p == str(local)) or _real_isdir(p),
    )
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core._is_executable",
        lambda p: p in ("/usr/local/bin/llama-server", "/usr/bin/llama-server", str(server)),
    )
    assert _find_llama_server().endswith("llama-server")
