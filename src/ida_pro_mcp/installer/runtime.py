from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import uuid
import zipfile
from pathlib import Path, PureWindowsPath
from urllib.parse import quote, urlsplit

from .common import InstallReport, SigsManifest, atomic_write_text, reject_symlink_path

_log = logging.getLogger(__name__)


# Hard cap on llama.cpp release asset size. Anything larger is refused
# before we exhaust memory or fill /tmp (audit §6.3). The largest
# llama.cpp release asset historically clocks in under 600 MB; 2 GiB
# leaves comfortable headroom while still bounding worst-case damage.
MAX_DOWNLOAD_SIZE = 2 * 1024 * 1024 * 1024  # 2 GiB
_DOWNLOAD_CHUNK_BYTES = 1 * 1024 * 1024  # 1 MiB
_MODEL_MAX_DOWNLOAD_SIZE = 8 * 1024**3
_MAX_EXTRACTED_ARCHIVE_SIZE = 8 * 1024**3
_TRUE_ENV = {"1", "true", "yes", "on"}


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_DOWNLOAD_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalise_sha256(value: object) -> str:
    """Return a validated SHA-256 hex digest, or an empty string."""
    text = str(value or "").strip().lower()
    if text.startswith("sha256:"):
        text = text[7:]
    return text if re.fullmatch(r"[0-9a-f]{64}", text) else ""


def _download_to_file(
    request: urllib.request.Request,
    destination: Path,
    *,
    timeout: float,
    max_bytes: int,
    label: str,
    expected_sha256: str = "",
    expected_size: int = 0,
) -> tuple[int, str]:
    """Stream a response to a same-directory temporary file and verify it."""
    reject_symlink_path(destination, f"{label} destination")
    destination.parent.mkdir(parents=True, exist_ok=True)
    raw_expected_sha256 = str(expected_sha256 or "").strip()
    expected_sha256 = _normalise_sha256(raw_expected_sha256)
    if raw_expected_sha256 and not expected_sha256:
        raise RuntimeError(f"{label} has an invalid expected SHA-256")
    temporary: Path | None = None
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            declared_raw = response.headers.get("Content-Length")
            declared = 0
            if declared_raw:
                try:
                    declared = int(declared_raw)
                except (TypeError, ValueError):
                    declared = 0
            declared = max(declared, 0)
            if declared > max_bytes:
                raise RuntimeError(
                    f"{label} download exceeds the 8 GiB safety limit"
                    if max_bytes == _MODEL_MAX_DOWNLOAD_SIZE
                    else f"Refusing download: Content-Length={declared} exceeds MAX_DOWNLOAD_SIZE={max_bytes} bytes"
                )
            if expected_size and declared and declared != expected_size:
                raise RuntimeError(
                    f"{label} size mismatch: server declared {declared} bytes, expected {expected_size}"
                )
            with tempfile.NamedTemporaryFile(
                delete=False, dir=str(destination.parent), prefix=f".{destination.name}.", suffix=".part"
            ) as output:
                temporary = Path(output.name)
                digest = hashlib.sha256()
                total = 0
                while True:
                    chunk = response.read(_DOWNLOAD_CHUNK_BYTES)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise RuntimeError(
                            f"{label} download exceeds the 8 GiB safety limit"
                            if max_bytes == _MODEL_MAX_DOWNLOAD_SIZE
                            else f"Refusing download: stream exceeded MAX_DOWNLOAD_SIZE={max_bytes} bytes"
                        )
                    digest.update(chunk)
                    output.write(chunk)
                if total <= 0:
                    raise RuntimeError(f"{label} download was empty")
                if expected_size and total != expected_size:
                    raise RuntimeError(
                        f"{label} size mismatch: received {total} bytes, expected {expected_size}"
                    )
                actual_sha256 = digest.hexdigest()
                if expected_sha256 and actual_sha256 != expected_sha256:
                    raise RuntimeError(
                        f"{label} SHA-256 mismatch: expected={expected_sha256} actual={actual_sha256}"
                    )
                output.flush()
                os.fsync(output.fileno())
        os.replace(temporary, destination)
        temporary = None
        return total, actual_sha256
    except Exception:
        if temporary is not None:
            with contextlib.suppress(OSError):
                temporary.unlink()
        raise


def _profile_download_url(profile: object) -> str:
    url = str(getattr(profile, "download_url", "") or "")
    revision = str(getattr(profile, "download_revision", "") or "").strip()
    if not revision or not re.fullmatch(r"[0-9a-f]{40}", revision):
        return ""
    if "/resolve/main/" not in url:
        return ""
    return url.replace("/resolve/main/", f"/resolve/{revision}/", 1)


def _validate_https_host(url: str, host: str, *, path_prefix: str = "") -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != host:
        raise RuntimeError(f"Refusing untrusted download URL: {url}")
    if path_prefix and not parsed.path.startswith(path_prefix):
        raise RuntimeError(f"Refusing untrusted download URL: {url}")


def _copy_file_atomically(
    source: Path, destination: Path, *, overwrite: bool = True
) -> None:
    """Copy a regular file without exposing a partial destination.

    With ``overwrite=False`` the final hard-link step is atomic and refuses an
    existing destination, which lets callers implement a real no-clobber
    policy even if another process creates the file after a preflight check.
    """
    reject_symlink_path(destination, "file copy destination")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            delete=False, dir=str(destination.parent), prefix=f".{destination.name}.", suffix=".part"
        ) as output:
            temporary = Path(output.name)
            with open(source, "rb") as input_file:
                shutil.copyfileobj(input_file, output, length=_DOWNLOAD_CHUNK_BYTES)
            output.flush()
            os.fsync(output.fileno())
        if overwrite:
            os.replace(temporary, destination)
            temporary = None
        else:
            os.link(temporary, destination, follow_symlinks=False)
            temporary.unlink()
            temporary = None
    finally:
        if temporary is not None:
            with contextlib.suppress(OSError):
                temporary.unlink()


def get_install_root() -> Path:
    override = os.environ.get("IDA_PRO_MCP_HOME", "").strip()
    if override:
        return Path(os.path.expandvars(os.path.expanduser(override)))
    if sys.platform == "win32":
        local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
        base = Path(local_appdata or str(Path.home() / "AppData" / "Local"))
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


def run_checked(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float | None = 300.0,
) -> subprocess.CompletedProcess:
    """Run `cmd` and raise RuntimeError on non-zero exit or hang.

    Returns the completed process so callers that need stdout (e.g. site-
    package discovery) can read it.

    `timeout` defaults to 300 s (5 minutes). Pass `None` to disable
    the timeout for legitimately long operations (the installer never
    does this today; the only call sites are pip install / venv
    creation / smoke import, all of which finish in well under 5
    minutes on a healthy machine).

    Audit §6.9: previously subprocess.run was called without a
    timeout, so a hung external command (pip stalled on a slow PyPI
    mirror, venv creation deadlocked by file lock) would hang the
    installer forever with no recovery.
    """
    try:
        result = subprocess.run(
            cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"{' '.join(cmd)} timed out after {timeout}s"
        ) from exc
    if result.returncode == 0:
        return result
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
    error) this function silently returns.
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
            # WMIC unavailable or denied: fail closed. An explicit binary
            # scope must never degrade into killing every IDA process.
            return
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
        # pgrep -af missing or denied: fail closed. An explicit binary scope
        # must never degrade into killing every IDA process.
        return

    for name in ["idat", "idat64", "ida", "ida64"]:
        subprocess.run(["pkill", "-x", name], capture_output=True)


def choose_runtime_source(runtime_source: str, source_root: Path) -> str:
    if runtime_source in {"local", "snapshot", "pypi"}:
        return runtime_source
    # Default to a frozen snapshot of the checkout, never the live tree:
    # a .pth pointer to the working source makes the deployed server change
    # behavior whenever the checkout changes (or breaks it mid-edit).
    if (source_root / "pyproject.toml").exists():
        return "snapshot"
    return "pypi"


def _read_installer_embedder_state(install_root: Path) -> dict:
    """Read embedder state from the install root being configured.

    The host-side state reader intentionally follows the process environment
    because it is used by a running server.  Installer discovery receives an
    explicit ``install_root`` instead, so consulting that process-global state
    would let a custom install inherit another install's model or server.
    Keep this read local to the target root and treat malformed state as absent
    so filesystem discovery can still proceed.
    """
    state_path = Path(install_root) / "embedder.json"
    try:
        reject_symlink_path(state_path, "installer embedder state path")
        if not state_path.is_file():
            return {}
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, RuntimeError, json.JSONDecodeError, TypeError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def _expand_configured_path(value: str) -> Path:
    """Expand shell-style user/environment references in configured paths."""
    return Path(os.path.expandvars(os.path.expanduser(str(value).strip())))


def find_embed_model(install_root: Path, profile: str = "") -> str:
    """Locate a supported GGUF embedding model on disk.

    Returns the first match found from this search order:

    1. ``IDA_MCP_EMBED_MODEL`` env var (direct file path).
    2. ``embedder.json`` config file (mirrors host discovery).
    3. Globbing for the selected profile across a prioritized list of
       base directories (install root, user home, cwd).
    4. HuggingFace hub cache (``~/.cache/huggingface/hub/``).
    5. Recursive scan under *install_root* only (broad last-ditch walk).
    """
    # 1. Explicit env override.
    env_val = os.environ.get("IDA_MCP_EMBED_MODEL", "").strip()
    env_path = _expand_configured_path(env_val) if env_val else None
    if env_path is not None and env_path.is_file():
        return str(env_path)

    # 2. embedder.json (persistent state from a previous install/doctor run).
    state = _read_installer_embedder_state(install_root)
    try:
        from ida_pro_mcp.host.intelligence.core import (
            _select_state_path,
        )
        manual = _select_state_path(state.get("model_path"))
        state_profile = str(state.get("profile") or "").strip().lower()
        requested_from_env = str(profile or os.environ.get("IDA_MCP_EMBED_PROFILE") or "").strip().lower()
        from ida_pro_mcp.host.intelligence.model_profiles import (
            get_model_profile,
            profile_from_model,
        )

        if requested_from_env:
            requested_from_env = (
                get_model_profile(requested_from_env) or get_model_profile("qwen3-embedding-0.6b")
            ).key
        if state_profile:
            state_profile = (get_model_profile(state_profile) or get_model_profile("qwen3-embedding-0.6b")).key

        if manual and (
            not requested_from_env
            or state_profile == requested_from_env
            or (not state_profile and profile_from_model(manual).key == requested_from_env)
        ):
            return manual
    except Exception:
        pass

    from ida_pro_mcp.host.intelligence.model_profiles import BGE_CODE_V1, get_model_profile

    requested = str(
        profile or os.environ.get("IDA_MCP_EMBED_PROFILE") or state.get("profile") or BGE_CODE_V1.key
    )
    selected_profile = get_model_profile(requested) or BGE_CODE_V1
    patterns = selected_profile.filename_patterns

    home = Path.home()
    cwd = Path.cwd()

    # ── 3. Glob-based search across sensible locations ─────────────────
    # Each base is checked via Path.glob("bge-code-v1*.gguf") so every
    # quantization variant (q8_0, f16, q4_K_M, etc.) is found without
    # hardcoding filenames.
    bases: list[Path] = [
        install_root,
        install_root / "models",
        install_root.parent,
        home / ".cache" / "ida-pro-mcp" / "models",
        home / "models",
        home / "Downloads",
        home / "Downloads" / "ida-pro-mcp",
        home / "Documents",
        home / "Documents" / "ida-pro-mcp",
        cwd,
        cwd / "models",
    ]
    extra = os.environ.get("IDA_MCP_EMBED_SEARCH_PATHS", "").strip()
    if extra:
        sep = ";" if sys.platform == "win32" else ":"
        for entry in extra.split(sep):
            entry = entry.strip()
            if entry:
                bases.append(_expand_configured_path(entry))

    searched: list[str] = []
    seen: set[Path] = set()
    for base in bases:
        if not base:
            continue
        try:
            base_resolved = base.resolve()
        except OSError:
            continue
        if base_resolved in seen:
            continue
        seen.add(base_resolved)
        if not base_resolved.is_dir():
            continue
        searched.append(str(base_resolved))
        for pattern in patterns:
            for f in sorted(base_resolved.glob(pattern)):
                if f.is_file():
                    return str(f)

    # 4. Hugging Face cache snapshots.
    hf_root = home / ".cache" / "huggingface" / "hub"
    if hf_root.is_dir():
        for pattern in patterns:
            for f in hf_root.glob(f"models--*/snapshots/*/{pattern}"):
                if f.is_file():
                    return str(f)

    # 5. Last-ditch recursive scan under the install root only.
    for pattern in patterns:
        for f in install_root.rglob(pattern):
            if f.is_file():
                return str(f)

    _log.debug(
        "%s model not found after searching %d directories: %s",
        selected_profile.key,
        len(searched),
        "; ".join(searched),
    )
    return ""


def download_embed_model(install_root: Path, profile: str) -> str:
    """Download a user-selected profile model into the install model directory."""
    from ida_pro_mcp.host.intelligence.model_profiles import get_model_profile

    selected = get_model_profile(profile)
    if selected is None:
        raise RuntimeError(f"Unknown embedding profile: {profile}")
    if not selected.download_url or not selected.download_filename:
        raise RuntimeError(
            f"Profile {selected.key} has no managed download; provide --embed-model"
        )
    url = _profile_download_url(selected)
    expected_sha256 = _normalise_sha256(selected.download_sha256)
    if not url or not expected_sha256 or not selected.download_size:
        raise RuntimeError(
            f"Profile {selected.key} is missing a pinned download digest; provide --embed-model"
        )
    _validate_https_host(url, "huggingface.co")
    model_dir = install_root / "models"
    reject_symlink_path(model_dir, "managed model path")
    model_dir.mkdir(parents=True, exist_ok=True)
    destination = model_dir / selected.download_filename
    if destination.is_symlink():
        raise RuntimeError(f"Refusing managed model path symlink: {destination}")
    if destination.is_file() and destination.stat().st_size > 0:
        if (
            destination.stat().st_size == selected.download_size
            and _sha256_file(str(destination)) == expected_sha256
        ):
            return str(destination)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ida-pro-mcp-installer"},
    )
    _download_to_file(
        request,
        destination,
        timeout=300,
        max_bytes=_MODEL_MAX_DOWNLOAD_SIZE,
        label="Embedding model",
        expected_sha256=expected_sha256,
        expected_size=selected.download_size,
    )
    return str(destination)


def download_rerank_model(install_root: Path, profile: str) -> str:
    """Download a user-selected reranker profile into the install model dir.

    Mirrors :func:`download_embed_model` — same streaming downloader, same
    install-root ``models/`` destination, same ``.part`` partial-file cleanup.
    The host's rerank discovery finds the file there on next start.
    """
    from ida_pro_mcp.host.intelligence.rerank_profiles import get_rerank_model_profile

    selected = get_rerank_model_profile(profile)
    if selected is None:
        raise RuntimeError(f"Unknown rerank profile: {profile}")
    if not selected.download_url or not selected.download_filename:
        raise RuntimeError(
            f"Profile {selected.key} has no managed download; provide --rerank-model"
        )
    url = _profile_download_url(selected)
    expected_sha256 = _normalise_sha256(selected.download_sha256)
    if not url or not expected_sha256 or not selected.download_size:
        raise RuntimeError(
            f"Profile {selected.key} is missing a pinned download digest; provide --rerank-model"
        )
    _validate_https_host(url, "huggingface.co")
    model_dir = install_root / "models"
    reject_symlink_path(model_dir, "managed model path")
    model_dir.mkdir(parents=True, exist_ok=True)
    destination = model_dir / selected.download_filename
    if destination.is_symlink():
        raise RuntimeError(f"Refusing managed model path symlink: {destination}")
    if destination.is_file() and destination.stat().st_size > 0:
        if (
            destination.stat().st_size == selected.download_size
            and _sha256_file(str(destination)) == expected_sha256
        ):
            return str(destination)
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ida-pro-mcp-installer"},
    )
    _download_to_file(
        request,
        destination,
        timeout=300,
        max_bytes=_MODEL_MAX_DOWNLOAD_SIZE,
        label="Rerank model",
        expected_sha256=expected_sha256,
        expected_size=selected.download_size,
    )
    return str(destination)


def find_llama_server_bin(install_root: Path) -> str:
    def _is_executable(p: Path) -> bool:
        if not p.is_file():
            return False
        if sys.platform == "win32":
            low = str(p).lower()
            return low.endswith((".exe", ".bat", ".cmd"))
        return os.access(str(p), os.X_OK)

    env_val = os.environ.get("IDA_MCP_EMBED_SERVER_BIN", "").strip()
    env_path = _expand_configured_path(env_val) if env_val else None
    if env_path is not None and _is_executable(env_path):
        return str(env_path)

    # Manual override via the target install's embedder.json.
    try:
        from ida_pro_mcp.host.intelligence.core import (
            _select_state_path,
        )
        manual = _select_state_path(
            _read_installer_embedder_state(install_root).get("server_bin")
        )
        if manual and _is_executable(Path(manual)):
            return manual
    except Exception:
        pass

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
        local_appdata = os.environ.get("LOCALAPPDATA", "").strip()
        program_files = os.environ.get("ProgramFiles", "").strip() or r"C:\Program Files"
        program_files_x86 = os.environ.get("ProgramFiles(x86)", "").strip() or r"C:\Program Files (x86)"
        roots.extend([
            home / "scoop" / "apps" / "llama.cpp" / "current",
            home / "scoop" / "apps" / "llama.cpp" / "current" / "bin",
            Path(program_files) / "llama.cpp" / "bin",
            Path(program_files_x86) / "llama.cpp" / "bin",
        ])
        if local_appdata:
            roots.extend([
                Path(local_appdata) / "Programs" / "llama.cpp" / "bin",
                Path(local_appdata) / "Programs" / "llama.cpp",
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


def find_rerank_model(install_root: Path, profile: str = "") -> str:
    """Locate an installed reranker matching the requested profile.

    The host intentionally falls back to another known reranker when the
    requested family is unavailable.  That is useful at runtime, but wrong
    for the installer wizard: a user selecting the 4B or BGE profile must not
    be told that a different model was found and then have that model pinned
    into client configuration.
    """
    env_val = os.environ.get("IDA_MCP_RERANK_MODEL", "").strip()
    env_path = _expand_configured_path(env_val) if env_val else None
    if env_path is not None and env_path.is_file():
        return str(env_path)

    from ida_pro_mcp.host.intelligence.rerank_profiles import (
        get_rerank_model_profile,
        profile_from_rerank_model,
    )

    state = _read_installer_embedder_state(install_root)
    try:
        from ida_pro_mcp.host.intelligence.rerank import (
            _select_state_path,
        )

        nested_state = state.get("rerank")
        state = nested_state if isinstance(nested_state, dict) else {}
        manual = _select_state_path(state.get("model_path"))
        requested_name = str(
            profile
            or os.environ.get("IDA_MCP_RERANK_PROFILE")
            or state.get("profile")
            or "qwen3-reranker-0.6b"
        ).strip()
        selected = get_rerank_model_profile(requested_name)
        if selected is None:
            selected = get_rerank_model_profile("qwen3-reranker-0.6b")
        if manual and selected is not None:
            state_profile = get_rerank_model_profile(state.get("profile"))
            if state_profile is not None and state_profile.key == selected.key:
                return manual
            if not state.get("profile") and profile_from_rerank_model(manual).key == selected.key:
                return manual
    except Exception:
        pass

    requested_name = str(
        profile
        or os.environ.get("IDA_MCP_RERANK_PROFILE")
        or state.get("profile")
        or "qwen3-reranker-0.6b"
    ).strip()
    selected = get_rerank_model_profile(requested_name)
    if selected is None:
        selected = get_rerank_model_profile("qwen3-reranker-0.6b")
    if selected is None or not selected.filename_patterns:
        return ""

    home = Path.home()
    cwd = Path.cwd()
    bases: list[Path] = [
        install_root,
        install_root / "models",
        install_root.parent,
        home / ".cache" / "ida-pro-mcp" / "models",
        home / "models",
        home / "Downloads",
        home / "Downloads" / "ida-pro-mcp",
        home / "Documents",
        home / "Documents" / "ida-pro-mcp",
        cwd,
        cwd / "models",
    ]
    extra = os.environ.get("IDA_MCP_RERANK_SEARCH_PATHS", "").strip()
    if extra:
        sep = ";" if sys.platform == "win32" else ":"
        bases.extend(
            _expand_configured_path(entry)
            for entry in extra.split(sep)
            if entry.strip()
        )

    seen: set[Path] = set()
    for base in bases:
        try:
            resolved_base = base.resolve()
        except OSError:
            continue
        if resolved_base in seen or not resolved_base.is_dir():
            continue
        seen.add(resolved_base)
        for pattern in selected.filename_patterns:
            for candidate in sorted(resolved_base.glob(pattern)):
                if candidate.is_file():
                    return str(candidate)

    hf_root = home / ".cache" / "huggingface" / "hub"
    if hf_root.is_dir():
        for pattern in selected.filename_patterns:
            for candidate in hf_root.glob(f"models--*/snapshots/*/{pattern}"):
                if candidate.is_file():
                    return str(candidate)

    for pattern in selected.filename_patterns:
        for candidate in install_root.rglob(pattern):
            if candidate.is_file():
                return str(candidate)
    return ""


def _r2_version(bin_path: str) -> str:
    """Probe an rz/r2 binary for its version string.

    ``rz --version`` (Rizin) and ``r2 -v`` (radare2) both print a one-line
    banner; try them in that order and return the first non-empty first line.
    Returns "" when the binary cannot be probed (missing, non-executable, or
    it hangs — a 10 s cap keeps a wedged engine from stalling the installer).
    """
    for flag in ("--version", "-v"):
        try:
            result = subprocess.run(
                [bin_path, flag], capture_output=True, text=True, timeout=10
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            first = (result.stdout or result.stderr or "").strip().splitlines()
            if first and first[0].strip():
                return first[0].strip()
    return ""


def resolve_r2_binary() -> tuple[str, str]:
    """Locate the rz (Rizin) or r2 (radare2) engine binary on PATH.

    Paper §8.2 item 11 / Architecture A Phase 1: the installer only *records*
    an engine the user already has.  Returns ``(bin_path, version)`` with
    version "" when the binary exists but cannot be probed, and ``("", "")``
    when neither rz nor r2 is on PATH — the caller then prints install
    instructions instead of downloading a pinned release (a documented
    follow-up that mirrors the llama.cpp pin discipline).
    """
    for name in ("rz", "r2"):
        found = shutil.which(name)
        if found:
            return found, _r2_version(found)
    return "", ""


def stage_sigs(
    source: Path,
    sig_dir: Path,
    dry_run: bool,
    report: InstallReport,
) -> SigsManifest:
    """Copy ``*.sig`` / ``*.sig.gz`` from ``source`` into IDA's signature dir.

    ``source`` may be a single ``.sig``/``.sig.gz`` file or a directory.
    Directory sources are walked recursively and their relative subpaths are
    preserved, so a multi-arch pack (e.g. a RISC-V sig pack with nested
    layout) cannot collide on basename.  An existing file in ``sig_dir`` is
    never overwritten — it is reported as skipped, so a pack can never clobber
    IDA's bundled signatures.  ``ida_list_sigs`` (the host MCP signature op)
    surfaces staged files by basename from ``<IDADIR>/sig``.

    On real runs the staged destinations are added to ``report.modified_files``;
    in dry-run the manifest records what *would* be written and nothing touches
    the filesystem.
    """
    source = source.expanduser().resolve()
    if not source.exists():
        raise RuntimeError(f"--sigs source not found: {source}")
    if source.is_file():
        if source.name.lower().endswith((".sig", ".sig.gz")):
            candidates = [source]
        else:
            candidates = []
    else:
        candidates = sorted(list(source.rglob("*.sig")) + list(source.rglob("*.sig.gz")))

    requested_sig_root = sig_dir.expanduser()
    reject_symlink_path(requested_sig_root, "IDA signature directory")
    sig_root = requested_sig_root.resolve()
    staged: list[str] = []
    skipped: list[str] = []
    for cand in candidates:
        if cand.is_symlink() or not cand.is_file():
            report.add_warning(f"Skipping non-regular signature file: {cand}")
            continue
        try:
            rel = cand.relative_to(source)
        except ValueError:
            # Single-file source: stage into the top of sig_dir by basename.
            rel = Path(cand.name)
        if not rel.parts:
            # cand == source (a bare .sig file): relative_to yields Path('.'),
            # which would copy the file onto sig_dir itself.
            rel = Path(cand.name)
        dest = sig_root / rel
        try:
            dest.resolve().relative_to(sig_root)
        except ValueError as exc:
            raise RuntimeError(f"signature destination escapes IDA sig directory: {dest}") from exc
        current = sig_root
        for part in dest.relative_to(sig_root).parts:
            current /= part
            if current.is_symlink():
                raise RuntimeError(f"Refusing symlinked signature destination: {current}")
        if dest.exists():
            skipped.append(str(dest))
            continue
        staged.append(str(dest))
        if not dry_run:
            try:
                _copy_file_atomically(cand, dest, overwrite=False)
            except FileExistsError:
                # A bundled signature (or another installer) appeared after
                # the preflight check. Preserve it and report the same result
                # as the non-racing path.
                staged.pop()
                skipped.append(str(dest))
                continue
            report.add_modified(dest)

    return SigsManifest(
        source=str(source),
        sig_dir=str(sig_dir),
        staged=staged,
        skipped=skipped,
        dry_run=dry_run,
    )


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
    if low.endswith((".zip", ".tar.gz", ".tgz")):
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
    """Extract `archive` into `out_dir` with a path-traversal guard.

    Refuses any member whose canonicalized destination is not contained
    inside `out_dir` (zip slip / tar slip — audit §6.3).  Also refuses
    members declared as absolute paths or containing '..' segments,
    catching attacks that exploit case-folding or symlinks created
    during extraction.
    """
    reject_symlink_path(archive, "archive path")
    reject_symlink_path(out_dir, "archive extraction path")
    out_dir.mkdir(parents=True, exist_ok=True)
    extract_root = out_dir.resolve()
    extracted_bytes = 0

    def _safe_target(member_name: str) -> Path:
        if not member_name:
            raise RuntimeError(f"refusing empty archive member name in {archive.name}")
        # Reject absolute paths and parent-dir traversal eagerly so the
        # error message is precise; the resolve() check below is the
        # final authority.
        normalized = member_name.replace("\\", "/")
        candidate = Path(normalized)
        windows_candidate = PureWindowsPath(normalized)
        if (
            candidate.is_absolute()
            or windows_candidate.is_absolute()
            or bool(windows_candidate.drive)
            or ".." in candidate.parts
        ):
            raise RuntimeError(
                f"refusing to extract {member_name!r} from {archive.name}: absolute or traversal path"
            )
        target = (out_dir / normalized).resolve()
        try:
            target.relative_to(extract_root)
        except ValueError as exc:
            raise RuntimeError(
                f"refusing to extract {member_name!r} from {archive.name}: outside extract root"
            ) from exc
        return target

    def _copy_member(source, target: Path, declared_size: int) -> None:
        nonlocal extracted_bytes
        if declared_size < 0 or extracted_bytes + declared_size > _MAX_EXTRACTED_ARCHIVE_SIZE:
            raise RuntimeError(
                f"refusing archive extraction over {_MAX_EXTRACTED_ARCHIVE_SIZE} bytes"
            )
        copied = 0
        with open(target, "wb") as destination:
            while True:
                chunk = source.read(_DOWNLOAD_CHUNK_BYTES)
                if not chunk:
                    break
                copied += len(chunk)
                if extracted_bytes + copied > _MAX_EXTRACTED_ARCHIVE_SIZE:
                    raise RuntimeError(
                        f"refusing archive extraction over {_MAX_EXTRACTED_ARCHIVE_SIZE} bytes"
                    )
                destination.write(chunk)
        extracted_bytes += copied

    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                target = _safe_target(info.filename)
                mode = (info.external_attr >> 16) & 0o170000
                if mode == stat.S_IFLNK:
                    raise RuntimeError(
                        f"refusing symlink member {info.filename!r} from {archive.name}"
                    )
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if mode not in (0, stat.S_IFREG):
                    raise RuntimeError(
                        f"refusing special archive member {info.filename!r} from {archive.name}"
                    )
                if target.is_symlink():
                    raise RuntimeError(
                        f"refusing to overwrite symlink {info.filename!r} in {archive.name}"
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                if info.file_size > _MAX_EXTRACTED_ARCHIVE_SIZE:
                    raise RuntimeError(
                        f"refusing archive extraction over {_MAX_EXTRACTED_ARCHIVE_SIZE} bytes"
                    )
                with zf.open(info) as source:
                    _copy_member(source, target, info.file_size)
        return
    if archive.name.endswith(".tar.gz") or archive.name.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                target = _safe_target(member.name)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                # Do not extract links or special files. Even a link whose
                # target is inside the root can change the meaning of a later
                # member and turn a safe archive into a write primitive.
                if not member.isfile():
                    raise RuntimeError(
                        f"refusing non-regular tar member {member.name!r} from {archive.name}"
                    )
                if target.is_symlink():
                    raise RuntimeError(
                        f"refusing to overwrite symlink {member.name!r} in {archive.name}"
                    )
                extracted = tf.extractfile(member)
                if extracted is None:
                    raise RuntimeError(f"could not read tar member {member.name!r}")
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    _copy_member(extracted, target, member.size)
                finally:
                    extracted.close()
        return
    raise RuntimeError(f"Unsupported archive format: {archive.name}")


def download_and_install_llama_server(
    install_root: Path,
    *,
    dry_run: bool,
    report: InstallReport,
    allow_unverified: bool | None = None,
) -> str:
    """Download a verified llama.cpp release archive and install llama-server."""
    binary_name = "llama-server.exe" if sys.platform == "win32" else "llama-server"
    target_dir = install_root / "bin"
    target_path = target_dir / binary_name
    reject_symlink_path(target_dir, "managed llama-server path")
    if target_path.is_symlink():
        raise RuntimeError(f"Refusing managed llama-server path symlink: {target_path}")
    if target_path.is_file() and os.access(target_path, os.X_OK):
        return str(target_path)
    if dry_run:
        report.add_step("llama_server", "dry-run", f"would install to {target_path}")
        return str(target_path)

    if allow_unverified is None:
        allow_unverified = os.environ.get("IDA_MCP_ALLOW_UNVERIFIED_DOWNLOADS", "").lower() in _TRUE_ENV
    release_tag = os.environ.get("IDA_MCP_LLAMA_RELEASE", "").strip()
    if release_tag:
        api_url = (
            "https://api.github.com/repos/ggml-org/llama.cpp/releases/tags/"
            f"{quote(release_tag, safe='')}"
        )
    else:
        # GitHub's /releases/latest can be a lightweight marker release with
        # no binaries. Scan the ordered release list instead and pick the
        # newest compatible asset.
        api_url = "https://api.github.com/repos/ggml-org/llama.cpp/releases?per_page=20"
    req = urllib.request.Request(
        api_url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "ida-pro-mcp-installer"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    releases = [payload] if isinstance(payload, dict) else payload
    if not isinstance(releases, list) or not releases:
        raise RuntimeError("No release metadata found for llama.cpp")

    os_hints, arch_hints = _platform_asset_hints()
    best_asset = None
    best_score = -10_000
    saw_unverified_match = False
    for release in releases:
        if not isinstance(release, dict) or release.get("draft"):
            continue
        assets = release.get("assets") or []
        if not isinstance(assets, list):
            continue
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            name = str(asset.get("name") or "")
            url = str(asset.get("browser_download_url") or "")
            if not name or not url:
                continue
            if (
                name in {".", ".."}
                or "/" in name
                or "\\" in name
                or Path(name).name != name
            ):
                raise RuntimeError(f"Refusing unsafe llama.cpp asset name: {name!r}")
            score = _score_release_asset(name, os_hints, arch_hints)
            if score < 4:
                continue
            _validate_https_host(
                url,
                "github.com",
                path_prefix="/ggml-org/llama.cpp/releases/download/",
            )
            digest = _normalise_sha256(asset.get("digest"))
            if not digest:
                saw_unverified_match = True
                if not allow_unverified:
                    continue
            if score > best_score:
                best_score = score
                best_asset = {
                    "name": name,
                    "url": url,
                    "sha256": digest,
                    "release": str(release.get("tag_name") or "unknown"),
                    "size": int(asset.get("size") or 0),
                }
    if not best_asset or best_score < 4:
        if saw_unverified_match and not allow_unverified:
            raise RuntimeError(
                "A compatible llama.cpp asset was found without a GitHub SHA-256 digest; "
                "refusing unverified installation. Set IDA_MCP_ALLOW_UNVERIFIED_DOWNLOADS=1 "
                "only if you accept that risk."
            )
        raise RuntimeError(
            f"Unable to resolve a suitable llama-server release asset for platform={sys.platform}, arch hints={arch_hints}"
        )

    with tempfile.TemporaryDirectory(prefix="ida-pro-mcp-llama-") as td:
        # Stage downloads inside the temp dir.  We use a NamedTemporaryFile
        # (delete=False) so a half-written archive cannot collide with a
        # concurrent installer run (audit §6.3 TOCTOU concern), then
        # os.replace into the canonical archive_path.
        canonical_archive = Path(td) / best_asset["name"]
        extract_dir = Path(td) / "extract"
        extract_dir.mkdir(parents=True, exist_ok=True)
        req_asset = urllib.request.Request(
            best_asset["url"],
            headers={"User-Agent": "ida-pro-mcp-installer"},
        )
        _download_to_file(
            req_asset,
            canonical_archive,
            timeout=120,
            max_bytes=MAX_DOWNLOAD_SIZE,
            label="llama-server archive",
            expected_sha256=best_asset["sha256"],
            expected_size=best_asset["size"],
        )
        archive_path = canonical_archive
        _extract_archive(archive_path, extract_dir)
        found = list(extract_dir.rglob(binary_name))
        found = [path for path in found if path.is_file() and not path.is_symlink()]
        if not found:
            raise RuntimeError(f"Downloaded asset did not contain {binary_name}: {best_asset['name']}")
        src_bin = found[0]
        target_dir.mkdir(parents=True, exist_ok=True)
        temporary_target: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                delete=False, dir=str(target_dir), prefix=f".{binary_name}.", suffix=".part"
            ) as output:
                temporary_target = Path(output.name)
                with open(src_bin, "rb") as source:
                    shutil.copyfileobj(source, output, length=_DOWNLOAD_CHUNK_BYTES)
                output.flush()
                os.fsync(output.fileno())
            if sys.platform != "win32":
                temporary_target.chmod(0o755)
            os.replace(temporary_target, target_path)
            temporary_target = None
        finally:
            if temporary_target is not None:
                with contextlib.suppress(OSError):
                    temporary_target.unlink()

    verification = "verified" if best_asset["sha256"] else "UNVERIFIED"
    report.add_step(
        "llama_server",
        "ok",
        f"installed {target_path.name} from {best_asset['name']} ({verification})",
    )
    report.metadata["llama_server_asset"] = best_asset["name"]
    report.metadata["llama_server_release"] = best_asset["release"]
    report.metadata["llama_server_sha256"] = best_asset["sha256"]
    report.metadata["llama_server_bin"] = str(target_path)
    return str(target_path)


def _venv_python_exe(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def python_environment_kind(python_exe: Path | None = None) -> str:
    """Classify the interpreter the runtime venv will be built from.

    IDA 9.4's IDAPython detects uv/anaconda/homebrew-managed Pythons and
    warns about libpython/venv mismatch, so the installer surfaces the same
    awareness instead of silently building a venv from such an interpreter.
    Returns one of: "uv", "conda", "homebrew", "pyenv", "asdf", "system".

    Detection is path/env based (no subprocesses): uv exports UV_* env vars
    and lives under ``~/.local/share/uv``; conda sets ``CONDA_PREFIX`` and
    lives under ``*/anaconda3|miniconda3|conda``; Homebrew python lives
    under ``/opt/homebrew`` (macOS ARM) or ``/usr/local/Cellar`` /
    ``/usr/local/opt``; pyenv shims under ``.pyenv/versions`` / ``pyenv``;
    asdf under ``.asdf/installs`` / ``asdf``. Anything else is "system".
    """
    exe = python_exe or Path(sys.executable)
    try:
        resolved = str(Path(exe).resolve())
    except OSError:
        resolved = str(exe)
    low = resolved.lower()
    path_parts = [p for p in low.replace("\\", "/").split("/") if p]

    if (
        os.environ.get("UV_ACTIVE")
        or os.environ.get("UV_CACHE_DIR")
        or "share/uv" in low
        or "uv/python" in low
        or "uv" in path_parts
    ):
        return "uv"
    if (
        os.environ.get("CONDA_PREFIX")
        or os.environ.get("CONDA_DEFAULT_ENV")
        or any(k in low for k in ("/anaconda3", "/miniconda3", "/conda/", "conda\\"))
        or "conda" in path_parts
    ):
        return "conda"
    if (
        low.startswith("/opt/homebrew")
        or "/homebrew/" in low
        or "/cellar/" in low
        or "/usr/local/opt/" in low
        or "homebrew" in path_parts
    ):
        return "homebrew"
    if "/.pyenv/versions" in low or "/pyenv/" in low or "pyenv" in path_parts:
        return "pyenv"
    if "/.asdf/installs" in low or "/asdf/" in low or "asdf" in path_parts:
        return "asdf"
    return "system"


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
    if not venv_dir.is_dir():
        try:
            venv_dir.unlink()
            return
        except OSError:
            pass
    deadline = time.time() + 15.0
    while time.time() < deadline:
        try:
            shutil.rmtree(venv_dir)
            return
        except OSError:
            time.sleep(0.5)
    try:
        backup = venv_dir.with_name(f".venv.stale.{int(time.time())}-{uuid.uuid4().hex}")
        venv_dir.rename(backup)
    except OSError as exc:
        raise RuntimeError(
            f"Could not remove stale venv at {venv_dir} "
            f"(processes may still be using it). Close any running MCP server "
            f"and re-run the installer. Last error: {exc}"
        ) from exc


def _snapshot_source(
    source_root: Path,
    install_root: Path,
    dry_run: bool,
    report: InstallReport,
) -> Path:
    """Copy the checkout into ``install_root/runtime-src-<stamp>`` and return
    the snapshot path.

    The deployed server is pip-installed from this frozen copy, so edits to
    the working checkout never leak into a running install. Older snapshots
    are pruned; only the newest is kept.
    """
    stamp = time.strftime("%Y%m%d-%H%M")
    target = install_root / f"runtime-src-{stamp}"
    reject_symlink_path(target, "runtime snapshot path")
    if dry_run:
        report.add_step("snapshot", "dry-run", f"would copy {source_root} -> {target}")
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(tempfile.mkdtemp(prefix=f".{target.name}.staging-", dir=str(target.parent)))
    staged = staging_root / target.name
    pattern_ignore = shutil.ignore_patterns(
        ".git", "__pycache__", "*.pyc", ".venv", "venv", "env", "dist", "build",
        "node_modules", "*.egg-info", ".pytest_cache", ".ruff_cache",
        ".mypy_cache", ".coverage", "htmlcov", ".tmp*", "*.sock", "ida_mcp_cache",
    )

    def ignore(folder: str, names: list[str]) -> set[str]:
        ignored = set(pattern_ignore(folder, names))
        for name in names:
            if name in ignored:
                continue
            path = os.path.join(folder, name)
            try:
                st = os.lstat(path)
                # Do not follow checkout symlinks into arbitrary directories
                # or copy linked secrets into the managed runtime snapshot.
                if stat.S_ISLNK(st.st_mode) or not (
                    stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)
                ):
                    ignored.add(name)
            except OSError:
                ignored.add(name)
        return ignored

    try:
        shutil.copytree(source_root, staged, ignore=ignore, ignore_dangling_symlinks=True)
        backup: Path | None = None
        if target.exists() or target.is_symlink():
            backup = target.parent / f".{target.name}.backup-{os.getpid()}-{uuid.uuid4().hex}"
            os.replace(target, backup)
        try:
            os.replace(staged, target)
        except BaseException:
            if backup is not None and not (target.exists() or target.is_symlink()):
                os.replace(backup, target)
            raise
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)
    report.add_modified(target)
    report.add_step("snapshot", "ok", str(target))
    siblings = sorted(
        (p for p in install_root.glob("runtime-src-*") if p != target),
        key=lambda p: p.name,
        reverse=True,
    )
    for old in siblings:
        shutil.rmtree(old, ignore_errors=True)
        report.add_step("snapshot", "pruned", str(old))
    return target


def _write_dev_pth(venv_dir: Path, source_root: Path, dry_run: bool, report: InstallReport) -> Path:
    """Write a ``.pth`` file in the venv site-packages so imports resolve from
    the working source tree instead of a copied package.

    Called when ``--runtime-source local`` is used explicitly.
    Also removes any previously pip-installed ``ida_pro_mcp`` package from
    site-packages so the ``.pth``-based source tree takes precedence.
    """
    python_exe = _venv_python_exe(venv_dir)
    result = run_checked(
        [str(python_exe), "-c", "import site; print(site.getsitepackages()[0])"],
        timeout=15,
    )
    raw_site_packages = result.stdout.strip()
    if not raw_site_packages or "\n" in raw_site_packages or "\r" in raw_site_packages:
        raise RuntimeError("venv did not report a usable site-packages directory")
    site_packages = Path(raw_site_packages).expanduser()
    if not site_packages.is_absolute():
        raise RuntimeError(f"venv reported a relative site-packages directory: {site_packages}")
    reject_symlink_path(site_packages, "venv site-packages path")
    if not site_packages.is_dir():
        raise RuntimeError(f"venv site-packages directory does not exist: {site_packages}")
    pth_path = site_packages / "ida_pro_mcp_dev.pth"
    reject_symlink_path(pth_path, "development source pointer")
    src_path = source_root / "src"
    if dry_run:
        report.add_step("dev_pth", "dry-run", f"would write {pth_path} -> {src_path}")
        return pth_path
    atomic_write_text(pth_path, f"{src_path}\n")
    report.add_modified(pth_path)
    report.add_step("dev_pth", "ok", f"{pth_path} -> {src_path}")

    # Remove any stale pip-installed copy so the .pth source takes precedence
    stale_pkg_dir = site_packages / "ida_pro_mcp"
    reject_symlink_path(stale_pkg_dir, "stale runtime package path")
    if stale_pkg_dir.is_dir():
        shutil.rmtree(stale_pkg_dir)
        report.add_step("dev_pth", "cleanup", f"removed stale {stale_pkg_dir}")
    for p in site_packages.glob("ida_pro_mcp-*.dist-info"):
        reject_symlink_path(p, "stale runtime metadata path")
        if p.is_dir():
            shutil.rmtree(p)
            report.add_step("dev_pth", "cleanup", f"removed stale {p}")

    return pth_path


def _remove_dev_pth(venv_dir: Path, report: InstallReport) -> None:
    """Remove an old live-source pointer before installing a frozen runtime.

    ``--runtime-source local`` is intentionally a development mode.  A later
    normal install must not inherit its ``.pth`` file, otherwise edits in a
    checkout can still override the package that pip just installed.
    """
    python_exe = _venv_python_exe(venv_dir)
    result = run_checked(
        [str(python_exe), "-c", "import site; print(site.getsitepackages()[0])"],
        timeout=15,
    )
    raw_site_packages = result.stdout.strip()
    if not raw_site_packages or "\n" in raw_site_packages or "\r" in raw_site_packages:
        raise RuntimeError("venv did not report a usable site-packages directory")
    site_packages = Path(raw_site_packages).expanduser()
    if not site_packages.is_absolute():
        raise RuntimeError(f"venv reported a relative site-packages directory: {site_packages}")
    reject_symlink_path(site_packages, "venv site-packages path")
    if not site_packages.is_dir():
        raise RuntimeError(f"venv site-packages directory does not exist: {site_packages}")
    pth_path = site_packages / "ida_pro_mcp_dev.pth"
    reject_symlink_path(pth_path, "development source pointer")
    if pth_path.is_file():
        pth_path.unlink()
        report.add_modified(pth_path)
        report.add_step("dev_pth", "removed", f"removed live source pointer {pth_path}")


def setup_runtime_environment(
    install_root: Path,
    source_root: Path,
    runtime_source: str,
    dry_run: bool,
    report: InstallReport,
) -> Path:
    venv_dir = install_root / ".venv"
    reject_symlink_path(venv_dir, "runtime environment path")
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
        _write_dev_pth(venv_dir, source_root, dry_run, report)
        report.metadata["runtime_source"] = "local-dev"
        report.metadata["runtime_package"] = f"pth:{source_root / 'src'}"
    else:
        _remove_dev_pth(venv_dir, report)
        if resolved_source == "snapshot":
            package_spec = str(_snapshot_source(source_root, install_root, dry_run, report))
            report.metadata["runtime_source"] = "snapshot"
        else:
            package_spec = str(source_root) if resolved_source == "local" else "ida-pro-mcp"
            report.metadata["runtime_source"] = resolved_source
        run_checked([str(python_exe), "-m", "pip", "install", package_spec])
        report.metadata["runtime_package"] = package_spec

    run_checked(
        [
            str(python_exe),
            "-c",
            "import ida_pro_mcp.host.server, ida_pro_mcp.cli, requests, numpy, tomli_w; print('ok')",
        ]
    )
    report.metadata["venv_python"] = str(python_exe)
    return python_exe
def find_idalib_python_dir(ida_dir: str) -> str:
    """Directory holding the ``idapro`` package for an install (IDA 9.3+).

    Returns ``<ida_dir>/idalib/python`` when it contains the ``idapro``
    package directory (the runtime the ``idalib`` MCP backend needs), else
    "".
    """
    if not ida_dir:
        return ""
    candidate = os.path.join(ida_dir, "idalib", "python")
    if os.path.isdir(os.path.join(candidate, "idapro")):
        return candidate
    return ""


def activate_idalib(ida_dir: str) -> tuple[bool, str]:
    """Point the idapro activation at *ida_dir*.

    Returns (ok, detail): True when ``py-activate-idalib.py -d <dir>``
    exists and exits 0.  Activation records the install idalib loads
    ``libidalib.so`` from; one install is active at a time.
    """
    py = os.path.join(find_idalib_python_dir(ida_dir), "py-activate-idalib.py")
    if not os.path.isfile(py):
        return False, f"no py-activate-idalib.py under {ida_dir}"
    try:
        result = subprocess.run(
            [sys.executable, py, "-d", ida_dir],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return False, "activation timed out"
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or f"exited {result.returncode}").strip()
    return True, "activated"


def build_stdio_config(
    python_exe: Path,
    install_root: Path,
    embed_model: str = "",
    embed_server_bin: str = "",
    embed_profile: str = "",
    embed_backend: str = "",
    rerank_model: str = "",
    rerank_profile: str = "",
    gemini_api_key: str = "",
    gemini_vertex_project: str = "",
    gemini_vertex_location: str = "",
    gemini_vertex: bool = False,
    ida_install: object | None = None,
    disable_policy: bool = False,
    rerank_disabled: bool = False,
    r2_bin: str = "",
    ida_runtime: str = "",
) -> dict:
    """Build the stdio MCP server config for a specific IDA install.

    Resolution order for IDADIR:
      1. `ida_install` (IdaInstall from installer/discovery.py)
      2. IDADIR / IDA_DIR env
      3. `detect_ida_install_dir()` (legacy single-install path)

    ``embed_backend == "gemini"`` selects the opt-in cloud embedder: the
    client env carries ``IDA_MCP_EMBED_BACKEND=gemini`` plus the chosen
    credential (AI Studio API key or Vertex project/location).  When
    ``gemini_vertex`` is true, the explicit Vertex choice is carried in the
    environment even if the project is incomplete, so an ambient AI Studio
    key cannot silently select the wrong route.  The API key is written into
    the generated client config only when the user provided it; the server
    also honours the process environment if it is unset here.
    """
    idadir = ""
    if ida_install is not None:
        idadir = str(ida_install.path)
    if not idadir:
        idadir = os.environ.get("IDADIR") or os.environ.get("IDA_DIR") or ""
    if not idadir:
        detected = detect_ida_install_dir()
        if detected:
            idadir = str(detected)

    env: dict[str, str] = {
        # Point the spawned server at the same install root the installer
        # wrote its state files (embedder.json, ida-install.json,
        # install-report.json) under.  Without this, a custom --install-root
        # is invisible to the host's get_install_root and installer-selected
        # values that only live in state (e.g. --gemini-model / rerank
        # profile) are silently dropped.
        "IDA_PRO_MCP_HOME": str(install_root),
        "IDA_MCP_RESPONSE_MODE": "compact",
        "IDA_MCP_QOL_MODE": "balanced",
        "IDA_MCP_TOOL_SURFACE": "agent",
        "IDA_MCP_BATCH_COMPACT": "1",
        "IDA_MCP_COMPACT_MAX_ITEMS": "48",
        "IDA_MCP_COMPACT_MAX_STRING": "1400",
        "IDA_MCP_COMPACT_CHAR_BUDGET": "30000",
        "IDA_MCP_TRUNCATE_TOKENS": "2000",
    }
    if disable_policy:
        env["IDA_MCP_POLICY_MODE"] = "off"
    if idadir:
        env["IDADIR"] = idadir
    wiki_dir = install_root / "wiki"
    if wiki_dir.exists():
        env["IDA_MCP_WIKI_DIR"] = str(wiki_dir)
    if embed_model:
        env["IDA_MCP_EMBED_MODEL"] = embed_model
    if embed_server_bin:
        env["IDA_MCP_EMBED_SERVER_BIN"] = embed_server_bin
    if embed_profile:
        env["IDA_MCP_EMBED_PROFILE"] = embed_profile
    if rerank_model:
        env["IDA_MCP_RERANK_MODEL"] = rerank_model
    if rerank_disabled:
        # User explicitly declined the reranker in the wizard; make the opt-out
        # effective at runtime instead of silently activating it whenever a
        # matching GGUF exists on disk.
        env["IDA_MCP_RERANK_DISABLED"] = "1"
    elif rerank_profile:
        env["IDA_MCP_RERANK_PROFILE"] = rerank_profile
    backend_key = str(embed_backend or "").strip().lower()
    if backend_key == "local":
        # Explicitly selecting local mode must override a stale
        # embedder.json that may still say backend=gemini.
        env["IDA_MCP_EMBED_BACKEND"] = "local"
    elif backend_key == "gemini":
        env["IDA_MCP_EMBED_BACKEND"] = "gemini"
        if gemini_vertex:
            env["IDA_MCP_GEMINI_VERTEX"] = "1"
        if gemini_api_key:
            env["GEMINI_API_KEY"] = gemini_api_key
        if gemini_vertex_project:
            env["GOOGLE_CLOUD_PROJECT"] = gemini_vertex_project
        if gemini_vertex_location:
            env["VERTEX_AI_LOCATION"] = gemini_vertex_location
    if r2_bin:
        # The host r2/Rizin engine (default-off) reads IDA_MCP_R2_BIN to
        # spawn rz/r2 as a subprocess.  --with-r2 records the resolved binary
        # here so the generated client config enables the engine.
        env["IDA_MCP_R2_BIN"] = r2_bin
    if ida_runtime and str(ida_runtime).strip().lower() == "idalib":
        # In-process idalib backend (experimental): the host spawns
        # `python -m ida_pro_mcp.idalib_worker` instead of idat per session.
        # Requires a 9.3+ install with the idapro whl + activation (the
        # wizard runs py-activate-idalib.py when this option is chosen).
        env["IDA_MCP_RUNTIME"] = "idalib"

    return {
        "command": str(python_exe),
        "args": ["-u", "-m", "ida_pro_mcp.host.server"],
        "env": env,
    }


def install_optional_packages(
    python_exe: Path | None,
    packages: list[str],
) -> bool:
    """Best-effort ``pip install`` of optional runtime packages (e.g. google-auth).

    Failures are non-fatal by design: the Gemini backend reports a clear
    error and the user can install the package later.  Returns True on
    success, False when the venv python is unknown or the install failed.
    """
    if not python_exe or not packages:
        return False
    cmd = [str(python_exe), "-m", "pip", "install", *packages]
    try:
        run_checked(cmd, timeout=300.0)
        return True
    except Exception:
        return False
