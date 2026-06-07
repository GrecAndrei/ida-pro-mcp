from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
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
    """Return the IDA install dir from env vars or PATH.

    This is the legacy single-install detector used by the host MCP server
    and the installer's environment-reading code paths.  The multi-install
    discovery logic lives in `installer/discovery.py` and is invoked
    separately by the install wizard.

    Note: this function deliberately does NOT read the installer state
    file (install_root/ida-install.json) — the host server's detection
    must be deterministic and not depend on what the installer last
    decided.  The installer's `_resolve_ida_install()` writes IDADIR into
    the MCP server env at config-write time, which is the right way to
    hand off the selection to the host.
    """
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


def kill_ida_processes(binary_path: str | Path | None = None) -> None:
    """Terminate running ida/idat processes.

    If `binary_path` is provided, only kill processes whose executable path
    (the first token of the command line) matches the canonicalized form of
    that path.  Without a filter the installer would happily SIGKILL a
    user's unrelated long-running IDA on a different binary — see §6.2.

    On failure to enumerate processes (missing pgrep/tasklist, permission
    error) this function silently returns; the installer prints its own
    warning when ida_processes_running() still reports True afterwards.
    """
    target_resolved: str | None = None
    if binary_path:
        try:
            target_resolved = str(Path(binary_path).expanduser().resolve())
        except OSError:
            target_resolved = str(binary_path)

    if sys.platform == "win32":
        if target_resolved:
            # Use WMIC to enumerate processes with their ExecutablePath and
            # filter to the canonicalized target before taskkill.  Fall back
            # to the legacy unfiltered behavior only if WMIC is missing.
            try:
                result = subprocess.run(
                    ["wmic", "process", "get", "ProcessId,ExecutablePath", "/FORMAT:CSV"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            except (OSError, subprocess.TimeoutExpired):
                result = None
            pids: list[str] = []
            if result is not None and result.returncode == 0:
                wanted = target_resolved.lower()
                for line in (result.stdout or "").splitlines():
                    cols = line.strip().split(",")
                    if len(cols) < 3:
                        continue
                    exe = cols[1].strip()
                    pid = cols[2].strip()
                    if not exe or not pid.isdigit():
                        continue
                    try:
                        exe_resolved = str(Path(exe).resolve()).lower()
                    except OSError:
                        exe_resolved = exe.lower()
                    if exe_resolved == wanted:
                        pids.append(pid)
                for pid in pids:
                    subprocess.run(
                        ["taskkill", "/F", "/PID", pid], capture_output=True
                    )
                return
            # WMIC unavailable — fall through to unfiltered behavior with a
            # narrower image-name match (still scoped to ida*/idat* only).
        for name in ["idat.exe", "idat64.exe", "ida.exe", "ida64.exe"]:
            subprocess.run(["taskkill", "/F", "/IM", name], capture_output=True)
        return

    if target_resolved:
        # pgrep -af lists "<pid> <cmdline>"; we match on the first token
        # being our canonicalized target.  This avoids killing IDAs whose
        # binary path differs even though the basename matches.
        try:
            result = subprocess.run(
                ["pgrep", "-af", "(ida|idat)64?"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            result = None
        if result is not None and result.returncode in (0, 1):
            pids: list[str] = []
            for line in (result.stdout or "").splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) < 2 or not parts[0].isdigit():
                    continue
                cmd_tokens = parts[1].split()
                if not cmd_tokens:
                    continue
                exe = cmd_tokens[0]
                try:
                    exe_resolved = str(Path(exe).resolve())
                except OSError:
                    exe_resolved = exe
                if exe_resolved == target_resolved:
                    pids.append(parts[0])
            for pid in pids:
                subprocess.run(["kill", "-KILL", pid], capture_output=True)
            return
        # pgrep -af missing — fall through to image-name-only kill.

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

    # Manual override via embedder.json (mirrors host discovery).
    try:
        from ida_pro_mcp.host.intelligence_core import (
            _read_embedder_state,
            _select_state_path,
        )
        manual = _select_state_path(_read_embedder_state().get("model_path"))
        if manual:
            return manual
    except Exception:
        pass

    home = Path.home()
    model_filenames = ("bge-code-v1-q8_0.gguf", "bge-code-v1.gguf")
    # Keep discovery deterministic and workspace-scoped by default, but also
    # check common user-level locations so the install wizard can auto-detect
    # an existing bge-code-v1 on Windows / macOS / Linux.
    bases = [
        install_root,
        install_root / "models",
        install_root.parent,
        home / "models",
        home / "Downloads",
        home / "Documents",
    ]
    seen: set[Path] = set()
    for base in bases:
        if not base:
            continue
        for fn in model_filenames:
            c = base / fn
            try:
                rp = c.resolve()
            except OSError:
                continue
            if rp in seen:
                continue
            seen.add(rp)
            if c.is_file():
                return str(c)

    # Hugging Face cache snapshots.
    hf_root = home / ".cache" / "huggingface" / "hub"
    if hf_root.is_dir():
        for f in hf_root.glob("models--*/snapshots/*/bge-code-v1*.gguf"):
            if f.is_file():
                return str(f)

    # Last-ditch recursive scan under the install root.
    for f in install_root.rglob("bge-code-v1*.gguf"):
        if f.is_file():
            return str(f)

    return ""


def find_llama_server_bin(install_root: Path) -> str:
    env_val = os.environ.get("IDA_MCP_EMBED_SERVER_BIN", "").strip()
    if env_val and Path(env_val).is_file():
        return env_val

    # Manual override via embedder.json (mirrors host discovery).
    try:
        from ida_pro_mcp.host.intelligence_core import (
            _read_embedder_state,
            _select_state_path,
        )
        manual = _select_state_path(_read_embedder_state().get("server_bin"))
        if manual:
            return manual
    except Exception:
        pass

    def _is_executable(p: Path) -> bool:
        if not p.is_file():
            return False
        if sys.platform == "win32":
            low = str(p).lower()
            if not (low.endswith(".exe") or low.endswith(".bat") or low.endswith(".cmd")):
                return False
            return True
        return os.access(str(p), os.X_OK)

    binary_names = ("llama-server.exe", "llama-server") if sys.platform == "win32" else (
        "llama-server", "llama-server.exe",
    )
    home = Path.home()
    roots: list[Path] = [
        install_root,
        install_root / "bin",
        install_root.parent,
    ]
    if sys.platform == "win32":
        roots.extend([
            home / "scoop" / "apps" / "llama.cpp" / "current",
            home / "scoop" / "apps" / "llama.cpp" / "current" / "bin",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "llama.cpp" / "bin",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "llama.cpp" / "bin",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "llama.cpp" / "bin",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "llama.cpp",
        ])
    else:
        roots.extend([
            home / ".local" / "bin",
            Path("/usr/local/bin"),
            Path("/usr/bin"),
        ])
        if sys.platform == "darwin":
            roots.extend([Path("/opt/homebrew/bin"), Path("/opt/local/bin")])

    seen: set[str] = set()
    for root in roots:
        if not root or not root.is_dir():
            continue
        for n in binary_names:
            cand = root / n
            ap = str(cand.resolve())
            if ap in seen:
                continue
            seen.add(ap)
            if _is_executable(cand):
                return str(cand)

    for name in binary_names:
        found = shutil.which(name)
        if found and _is_executable(Path(found)):
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


def _venv_python_exe(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def _probe_venv(python_exe: Path) -> bool:
    """Return True if the venv's python can launch and reports its own path."""
    if not python_exe.is_file():
        return False
    try:
        result = subprocess.run(
            [str(python_exe), "-c", "import sys; print(sys.executable)"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    return result.stdout.strip().lower() == str(python_exe).lower()


def _wipe_venv(venv_dir: Path) -> None:
    """Best-effort removal of an existing venv directory.

    On Windows, .exe handles may briefly keep files locked even after the
    owning process exits, so we retry with backoff.  If the rmtree keeps
    failing, we rename the stale venv out of the way so the new venv can
    be created alongside it; the user can clean up later.
    """
    if not venv_dir.exists():
        return
    deadline = time.time() + 15.0
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            shutil.rmtree(venv_dir)
            return
        except OSError as exc:
            last_err = exc
            time.sleep(0.5)
    try:
        backup = venv_dir.with_name(f".venv.stale.{int(time.time())}")
        venv_dir.rename(backup)
    except OSError as exc:
        raise RuntimeError(
            f"Could not remove stale venv at {venv_dir} "
            f"(processes may still be using it). Close any running MCP server "
            f"and re-run the installer. Last error: {exc}"
        ) from exc


def setup_runtime_environment(
    install_root: Path,
    source_root: Path,
    runtime_source: str,
    dry_run: bool,
    report: InstallReport,
) -> Path:
    venv_dir = install_root / ".venv"
    python_exe = _venv_python_exe(venv_dir)
    if dry_run:
        report.metadata["venv_python"] = str(python_exe)
        return python_exe

    install_root.mkdir(parents=True, exist_ok=True)

    # If a previous venv exists and is healthy, reuse it.  This avoids the
    # Windows race where a long-lived venv's .exe handles keep `python -m venv`
    # from overwriting the existing directory.
    if venv_dir.exists():
        if _probe_venv(python_exe):
            report.add_step("venv", "reused", str(python_exe))
        else:
            report.add_step("venv", "recreating", f"stale venv at {venv_dir}")
            _wipe_venv(venv_dir)
            run_checked([sys.executable, "-m", "venv", str(venv_dir)])
    else:
        run_checked([sys.executable, "-m", "venv", str(venv_dir)])

    # Sanity: the venv's python must launch.  If it doesn't, wipe and retry.
    if not _probe_venv(python_exe):
        _wipe_venv(venv_dir)
        run_checked([sys.executable, "-m", "venv", str(venv_dir)])
        if not _probe_venv(python_exe):
            raise RuntimeError(
                f"venv python at {python_exe} is not functional after creation"
            )

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
    ida_install: object | None = None,
) -> dict:
    """Build the stdio MCP server config for a specific IDA install.

    Resolution order for IDADIR:
      1. `ida_install` (IdaInstall from installer/discovery.py)
      2. IDADIR / IDA_DIR env
      3. `detect_ida_install_dir()` (legacy single-install path)
    """
    idadir = ""
    if ida_install is not None:
        idadir = str(getattr(ida_install, "path"))
    if not idadir:
        idadir = os.environ.get("IDADIR") or os.environ.get("IDA_DIR") or ""
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
