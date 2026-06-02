from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
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

    # Keep discovery deterministic and workspace-scoped by default.
    candidates = [
        install_root / "bge-code-v1-q8_0.gguf",
        install_root / "bge-code-v1.gguf",
        install_root / "models" / "bge-code-v1-q8_0.gguf",
        install_root / "models" / "bge-code-v1.gguf",
        install_root.parent / "bge-code-v1-q8_0.gguf",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)

    for f in install_root.rglob("bge-code-v1*.gguf"):
        return str(f)

    return ""


def find_llama_server_bin(install_root: Path) -> str:
    env_val = os.environ.get("IDA_MCP_EMBED_SERVER_BIN", "").strip()
    if env_val and Path(env_val).is_file() and os.access(env_val, os.X_OK):
        return env_val

    binary_name = "llama-server.exe" if sys.platform == "win32" else "llama-server"
    candidates = [
        install_root / binary_name,
        install_root / "bin" / binary_name,
        install_root.parent / binary_name,
    ]
    for c in candidates:
        if c.is_file() and os.access(str(c), os.X_OK):
            return str(c)

    for name in ("llama-server", "llama-server.exe"):
        found = shutil.which(name)
        if found:
            return found

    return ""


def _platform_asset_hints() -> tuple[list[str], list[str]]:
    machine = (os.uname().machine if hasattr(os, "uname") else "").lower()
    if sys.platform == "win32":
        os_hints = ["win", "windows"]
        arch_hints = ["arm64"] if "arm" in machine else ["x64", "amd64", "x86_64"]
    elif sys.platform == "darwin":
        os_hints = ["macos", "darwin"]
        arch_hints = ["arm64", "aarch64"] if "arm" in machine else ["x64", "x86_64"]
    else:
        os_hints = ["ubuntu", "linux"]
        if "arm" in machine or "aarch64" in machine:
            arch_hints = ["arm64", "aarch64"]
        elif "s390x" in machine:
            arch_hints = ["s390x"]
        else:
            arch_hints = ["x64", "x86_64", "amd64"]
    return os_hints, arch_hints


def _score_release_asset(name: str, os_hints: list[str], arch_hints: list[str]) -> int:
    low = name.lower()
    score = 0
    if "llama" in low and "bin" in low:
        score += 3
    if low.endswith(".zip") or low.endswith(".tar.gz") or low.endswith(".tgz"):
        score += 2
    if any(h in low for h in os_hints):
        score += 4
    if any(h in low for h in arch_hints):
        score += 4
    if "cuda" in low or "hip" in low or "vulkan" in low or "openvino" in low or "sycl" in low:
        score -= 1
    if "cudart" in low:
        score -= 3
    return score


def _extract_archive(archive: Path, out_dir: Path) -> None:
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(out_dir)
        return
    if archive.name.endswith(".tar.gz") or archive.name.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(out_dir)
        return
    raise RuntimeError(f"Unsupported archive format: {archive.name}")


def download_and_install_llama_server(
    install_root: Path,
    *,
    dry_run: bool,
    report: InstallReport,
) -> str:
    """Download latest llama.cpp release archive and install llama-server locally."""
    binary_name = "llama-server.exe" if sys.platform == "win32" else "llama-server"
    target_dir = install_root / "bin"
    target_path = target_dir / binary_name
    if target_path.exists() and os.access(target_path, os.X_OK):
        return str(target_path)
    if dry_run:
        report.add_step("llama_server", "dry-run", f"would install to {target_path}")
        return str(target_path)

    api_url = "https://api.github.com/repos/ggml-org/llama.cpp/releases/latest"
    req = urllib.request.Request(
        api_url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "ida-pro-mcp-installer"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    assets = payload.get("assets") or []
    if not isinstance(assets, list) or not assets:
        raise RuntimeError("No release assets found for llama.cpp latest release")

    os_hints, arch_hints = _platform_asset_hints()
    best_asset = None
    best_score = -10_000
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = str(asset.get("name") or "")
        url = str(asset.get("browser_download_url") or "")
        if not name or not url:
            continue
        score = _score_release_asset(name, os_hints, arch_hints)
        if score > best_score:
            best_score = score
            best_asset = {"name": name, "url": url}
    if not best_asset or best_score < 4:
        raise RuntimeError(
            f"Unable to resolve a suitable llama-server release asset for platform={sys.platform}, arch hints={arch_hints}"
        )

    with tempfile.TemporaryDirectory(prefix="ida-pro-mcp-llama-") as td:
        archive_path = Path(td) / best_asset["name"]
        extract_dir = Path(td) / "extract"
        extract_dir.mkdir(parents=True, exist_ok=True)
        req_asset = urllib.request.Request(
            best_asset["url"],
            headers={"User-Agent": "ida-pro-mcp-installer"},
        )
        with urllib.request.urlopen(req_asset, timeout=120) as resp:
            archive_path.write_bytes(resp.read())
        _extract_archive(archive_path, extract_dir)
        found = list(extract_dir.rglob(binary_name))
        if not found:
            raise RuntimeError(f"Downloaded asset did not contain {binary_name}: {best_asset['name']}")
        src_bin = found[0]
        target_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_bin, target_path)
        if sys.platform != "win32":
            target_path.chmod(0o755)

    report.add_step("llama_server", "ok", f"installed {target_path.name} from {best_asset['name']}")
    report.metadata["llama_server_asset"] = best_asset["name"]
    report.metadata["llama_server_bin"] = str(target_path)
    return str(target_path)


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
            "import ida_pro_mcp.host.server, ida_pro_mcp.cli, requests, numpy, tomli_w; print('ok')",
        ]
    )
    report.metadata["runtime_source"] = resolved_source
    report.metadata["runtime_package"] = package_spec
    report.metadata["venv_python"] = str(python_exe)
    return python_exe
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
        "args": ["-u", "-m", "ida_pro_mcp.host.server"],
        "env": env,
    }
