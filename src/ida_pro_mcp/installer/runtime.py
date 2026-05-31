from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .common import InstallReport


def get_install_root() -> Path:
    override = os.environ.get("IDA_PRO_MCP_HOME")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
        return base / "ida-pro-mcp"
    return Path.home() / ".local" / "share" / "ida-pro-mcp"


def _ida_binary_names() -> list[str]:
    if sys.platform == "win32":
        return ["idat64.exe", "idat.exe", "ida64.exe", "ida.exe"]
    return ["idat64", "idat", "ida64", "ida"]


def detect_ida_install_dir() -> Path | None:
    for env_name in ("IDADIR", "IDA_DIR", "IDA_MCP_IDAT"):
        value = os.environ.get(env_name)
        if not value:
            continue
        p = Path(value).expanduser().resolve()
        if p.is_dir():
            return p
        if p.is_file():
            return p.parent
    for name in _ida_binary_names():
        resolved = shutil.which(name)
        if resolved:
            return Path(resolved).resolve().parent
    return None


def get_ida_plugin_dir() -> Path:
    env_dir = os.environ.get("IDAUSR") or os.environ.get("IDA_USER_DIR")
    if env_dir:
        base = Path(env_dir).expanduser()
    elif sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))) / "Hex-Rays" / "IDA Pro"
    else:
        base = Path.home() / ".idapro"
    return base / "plugins"


def run_checked(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode == 0:
        return
    details = (result.stderr or result.stdout or "").strip()
    tail = " | ".join([ln for ln in details.splitlines() if ln.strip()][-8:])[:800]
    raise RuntimeError(f"{' '.join(cmd)} failed ({result.returncode}): {tail}")


def kill_ida_processes() -> None:
    if sys.platform == "win32":
        for name in ["idat.exe", "idat64.exe", "ida.exe", "ida64.exe"]:
            subprocess.run(["taskkill", "/F", "/IM", name], capture_output=True)
        return
    for name in ["idat", "idat64", "ida", "ida64"]:
        subprocess.run(["pkill", "-x", name], capture_output=True)


def ida_processes_running() -> bool:
    if sys.platform == "win32":
        result = subprocess.run(["tasklist"], capture_output=True, text=True)
        if result.returncode != 0:
            return False
        out = (result.stdout or "").lower()
        return any(name in out for name in ["idat.exe", "idat64.exe", "ida.exe", "ida64.exe"])
    for name in ["idat", "idat64", "ida", "ida64"]:
        check = subprocess.run(["pgrep", "-x", name], capture_output=True)
        if check.returncode == 0:
            return True
    return False


def choose_runtime_source(runtime_source: str, source_root: Path) -> str:
    if runtime_source in {"local", "pypi"}:
        return runtime_source
    if (source_root / "pyproject.toml").exists():
        return "local"
    return "pypi"


def find_embed_model(install_root: Path) -> str:
    env_val = os.environ.get("IDA_MCP_EMBED_MODEL", "").strip()
    if env_val and Path(env_val).is_file():
        return env_val

    candidates = [
        install_root / "bge-code-v1-q8_0.gguf",
        install_root / "bge-code-v1.gguf",
        install_root.parent / "bge-code-v1-q8_0.gguf",
        Path.home() / "models" / "bge-code-v1-q8_0.gguf",
        Path.home() / "Downloads" / "bge-code-v1-q8_0.gguf",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)

    hf_snapshots = Path.home() / ".cache" / "huggingface" / "hub" / "models--BAAI--bge-code-v1" / "snapshots"
    if hf_snapshots.is_dir():
        for snap in sorted(hf_snapshots.iterdir(), reverse=True):
            for f in snap.glob("*.gguf"):
                return str(f)

    for root in (Path.home() / ".cache", Path.home() / "models", Path.home() / "Downloads"):
        if not root.is_dir():
            continue
        for f in root.rglob("bge-code-v1*.gguf"):
            return str(f)

    return ""


def find_llama_server_bin(install_root: Path) -> str:
    env_val = os.environ.get("IDA_MCP_EMBED_SERVER_BIN", "").strip()
    if env_val and Path(env_val).is_file() and os.access(env_val, os.X_OK):
        return env_val

    candidates = [
        install_root / "llama-server",
        install_root.parent / "llama-server",
        Path("/usr/local/bin/llama-server"),
        Path("/usr/bin/llama-server"),
        Path.home() / ".local" / "bin" / "llama-server",
        Path.home() / "llama.cpp" / "build" / "bin" / "llama-server",
    ]
    for c in candidates:
        if c.is_file() and os.access(str(c), os.X_OK):
            return str(c)

    for name in ("llama-server", "llama-server.exe"):
        found = shutil.which(name)
        if found:
            return found

    return ""


def setup_runtime_environment(
    install_root: Path,
    source_root: Path,
    runtime_source: str,
    dry_run: bool,
    report: InstallReport,
) -> Path:
    venv_dir = install_root / ".venv"
    python_exe = venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    if dry_run:
        report.metadata["venv_python"] = str(python_exe)
        return python_exe

    install_root.mkdir(parents=True, exist_ok=True)
    run_checked([sys.executable, "-m", "venv", str(venv_dir)])
    run_checked([str(python_exe), "-m", "pip", "install", "--upgrade", "pip"])

    resolved_source = choose_runtime_source(runtime_source, source_root)
    if resolved_source == "local":
        package_spec = str(source_root)
    else:
        package_spec = "ida-pro-mcp"
    run_checked([str(python_exe), "-m", "pip", "install", package_spec])
    run_checked(
        [
            str(python_exe),
            "-c",
            "import ida_pro_mcp.server, ida_pro_mcp.cli, requests, numpy, tomli_w; print('ok')",
        ]
    )
    report.metadata["runtime_source"] = resolved_source
    report.metadata["runtime_package"] = package_spec
    report.metadata["venv_python"] = str(python_exe)
    return python_exe


def discover_installed_package_paths(python_exe: Path) -> tuple[Path, Path]:
    cmd = [
        str(python_exe),
        "-c",
        (
            "import json, pathlib, ida_pro_mcp; "
            "pkg=pathlib.Path(ida_pro_mcp.__file__).resolve().parent; "
            "print(json.dumps({'pkg': str(pkg), 'loader': str(pkg / 'ida_mcp.py'), 'plugin_pkg': str(pkg / 'ida_mcp')}))"
        ),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    payload = json.loads(result.stdout.strip())
    loader = Path(payload["loader"])
    plugin_pkg = Path(payload["plugin_pkg"])
    return loader, plugin_pkg


def build_stdio_config(
    python_exe: Path,
    install_root: Path,
    embed_model: str = "",
    embed_server_bin: str = "",
) -> dict:
    idadir = os.environ.get("IDADIR") or os.environ.get("IDA_DIR")
    if not idadir:
        detected = detect_ida_install_dir()
        if detected:
            idadir = str(detected)

    env: dict[str, str] = {
        "IDA_MCP_MONOLITHIC_TOOL_DESCRIPTIONS": "1",
        "IDA_MCP_RESPONSE_MODE": "compact",
        "IDA_MCP_QOL_MODE": "balanced",
        "IDA_MCP_TOOLS_LIST_MODE": "full",
        "IDA_MCP_BATCH_COMPACT": "1",
        "IDA_MCP_COMPACT_MAX_ITEMS": "48",
        "IDA_MCP_COMPACT_MAX_STRING": "1400",
        "IDA_MCP_COMPACT_CHAR_BUDGET": "30000",
        "IDA_MCP_TRUNCATE_TOKENS": "2000",
    }
    if idadir:
        env["IDADIR"] = idadir
    wiki_dir = install_root / "wiki"
    if wiki_dir.exists():
        env["IDA_MCP_WIKI_DIR"] = str(wiki_dir)
    if embed_model:
        env["IDA_MCP_EMBED_MODEL"] = embed_model
    if embed_server_bin:
        env["IDA_MCP_EMBED_SERVER_BIN"] = embed_server_bin

    return {
        "command": str(python_exe),
        "args": ["-u", "-m", "ida_pro_mcp.server"],
        "env": env,
    }
