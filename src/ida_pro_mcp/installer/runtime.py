from __future__ import annotations

import contextlib
import json
import logging
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

_log = logging.getLogger(__name__)


# Hard cap on llama.cpp release asset size. Anything larger is refused
# before we exhaust memory or fill /tmp (audit §6.3). The largest
# llama.cpp release asset historically clocks in under 600 MB; 2 GiB
# leaves comfortable headroom while still bounding worst-case damage.
MAX_DOWNLOAD_SIZE = 2 * 1024 * 1024 * 1024  # 2 GiB
_DOWNLOAD_CHUNK_BYTES = 1 * 1024 * 1024  # 1 MiB


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
    if runtime_source in {"local", "snapshot", "pypi"}:
        return runtime_source
    # Default to a frozen snapshot of the checkout, never the live tree:
    # a .pth pointer to the working source makes the deployed server change
    # behavior whenever the checkout changes (or breaks it mid-edit).
    if (source_root / "pyproject.toml").exists():
        return "snapshot"
    return "pypi"


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
    if env_val and Path(env_val).is_file():
        return env_val

    # 2. embedder.json (persistent state from a previous install/doctor run).
    state: dict = {}
    try:
        from ida_pro_mcp.host.intelligence.core import (
            _read_embedder_state,
            _select_state_path,
        )
        state = _read_embedder_state()
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
                bases.append(Path(entry).expanduser())

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
    model_dir = install_root / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    destination = model_dir / selected.download_filename
    if destination.is_file() and destination.stat().st_size > 0:
        return str(destination)
    partial = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(
        selected.download_url,
        headers={"User-Agent": "ida-pro-mcp-installer"},
    )
    max_bytes = 8 * 1024**3
    written = 0
    try:
        with urllib.request.urlopen(request, timeout=300) as response, open(partial, "wb") as output:
            content_length = int(response.headers.get("Content-Length") or 0)
            if content_length > max_bytes:
                raise RuntimeError("Embedding model download exceeds the 8 GiB safety limit")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise RuntimeError("Embedding model download exceeds the 8 GiB safety limit")
                output.write(chunk)
        if written <= 0:
            raise RuntimeError("Embedding model download was empty")
        os.replace(partial, destination)
    except Exception:
        with contextlib.suppress(OSError):
            partial.unlink()
        raise
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
    model_dir = install_root / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    destination = model_dir / selected.download_filename
    if destination.is_file() and destination.stat().st_size > 0:
        return str(destination)
    partial = destination.with_suffix(destination.suffix + ".part")
    request = urllib.request.Request(
        selected.download_url,
        headers={"User-Agent": "ida-pro-mcp-installer"},
    )
    max_bytes = 8 * 1024**3
    written = 0
    try:
        with urllib.request.urlopen(request, timeout=300) as response, open(partial, "wb") as output:
            content_length = int(response.headers.get("Content-Length") or 0)
            if content_length > max_bytes:
                raise RuntimeError("Rerank model download exceeds the 8 GiB safety limit")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise RuntimeError("Rerank model download exceeds the 8 GiB safety limit")
                output.write(chunk)
        if written <= 0:
            raise RuntimeError("Rerank model download was empty")
        os.replace(partial, destination)
    except Exception:
        with contextlib.suppress(OSError):
            partial.unlink()
        raise
    return str(destination)


def find_llama_server_bin(install_root: Path) -> str:
    env_val = os.environ.get("IDA_MCP_EMBED_SERVER_BIN", "").strip()
    if env_val and Path(env_val).is_file():
        return env_val

    # Manual override via embedder.json (mirrors host discovery).
    try:
        from ida_pro_mcp.host.intelligence.core import (
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
            return low.endswith((".exe", ".bat", ".cmd"))
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


def find_rerank_model(install_root: Path, profile: str = "qwen3-reranker-0.6b") -> str:
    """Locate an already-installed rerank GGUF, mirroring the host's _find_rerank_model logic."""
    env_val = os.environ.get("IDA_MCP_RERANK_MODEL", "").strip()
    if env_val and Path(env_val).is_file():
        return env_val
    try:
        from ida_pro_mcp.host.intelligence.rerank import _find_rerank_model
        result = _find_rerank_model()
        if result:
            return result
    except Exception:
        pass
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
    extract_root = out_dir.resolve()

    def _safe_target(member_name: str) -> Path:
        if not member_name:
            raise RuntimeError(f"refusing empty archive member name in {archive.name}")
        # Reject absolute paths and parent-dir traversal eagerly so the
        # error message is precise; the resolve() check below is the
        # final authority.
        candidate = Path(member_name)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise RuntimeError(
                f"refusing to extract {member_name!r} from {archive.name}: absolute or traversal path"
            )
        target = (out_dir / member_name).resolve()
        try:
            target.relative_to(extract_root)
        except ValueError as exc:
            raise RuntimeError(
                f"refusing to extract {member_name!r} from {archive.name}: outside extract root"
            ) from exc
        return target

    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                _safe_target(info.filename)
            zf.extractall(out_dir)
        return
    if archive.name.endswith(".tar.gz") or archive.name.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as tf:
            for member in tf.getmembers():
                _safe_target(member.name)
                # Tar can also carry symlinks/hardlinks whose targets
                # escape the root even if `member.name` itself is safe.
                link = member.linkname or ""
                if link:
                    link_path = (out_dir / member.name).parent / link
                    try:
                        link_resolved = link_path.resolve()
                        link_resolved.relative_to(extract_root)
                    except (OSError, ValueError) as exc:
                        raise RuntimeError(
                            f"refusing tar member {member.name!r} with link target outside extract root"
                        ) from exc
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
        with urllib.request.urlopen(req_asset, timeout=120) as resp:
            # Honor Content-Length when present; reject before reading
            # the body if the server promises more than we'll accept.
            declared_len_raw = resp.headers.get("Content-Length")
            if declared_len_raw:
                try:
                    declared_len = int(declared_len_raw)
                except ValueError:
                    declared_len = -1
                if declared_len > MAX_DOWNLOAD_SIZE:
                    raise RuntimeError(
                        f"Refusing download: Content-Length={declared_len} exceeds "
                        f"MAX_DOWNLOAD_SIZE={MAX_DOWNLOAD_SIZE} bytes"
                    )
            tmp = tempfile.NamedTemporaryFile(
                delete=False, dir=str(td), prefix=".dl-", suffix=".part"
            )
            tmp_path = Path(tmp.name)
            total = 0
            try:
                while True:
                    chunk = resp.read(_DOWNLOAD_CHUNK_BYTES)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_SIZE:
                        raise RuntimeError(
                            f"Refusing download: stream exceeded MAX_DOWNLOAD_SIZE="
                            f"{MAX_DOWNLOAD_SIZE} bytes (read {total} so far)"
                        )
                    tmp.write(chunk)
                tmp.flush()
                os.fsync(tmp.fileno())
            finally:
                tmp.close()
            os.replace(tmp_path, canonical_archive)
        archive_path = canonical_archive
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
    while time.time() < deadline:
        try:
            shutil.rmtree(venv_dir)
            return
        except OSError:
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
    if dry_run:
        report.add_step("snapshot", "dry-run", f"would copy {source_root} -> {target}")
        return target
    if target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    ignore = shutil.ignore_patterns(
        ".git", "__pycache__", "*.pyc", ".venv", "venv", "dist", "build",
        "node_modules", "*.egg-info", ".pytest_cache", ".ruff_cache",
        ".mypy_cache", ".coverage", "htmlcov",
    )
    shutil.copytree(source_root, target, ignore=ignore)
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
    site_packages = Path(result.stdout.strip())
    pth_path = site_packages / "ida_pro_mcp_dev.pth"
    src_path = source_root / "src"
    if dry_run:
        report.add_step("dev_pth", "dry-run", f"would write {pth_path} -> {src_path}")
        return pth_path
    pth_path.parent.mkdir(parents=True, exist_ok=True)
    pth_path.write_text(f"{src_path}\n", encoding="utf-8")
    report.add_modified(pth_path)
    report.add_step("dev_pth", "ok", f"{pth_path} -> {src_path}")

    # Remove any stale pip-installed copy so the .pth source takes precedence
    stale_pkg_dir = site_packages / "ida_pro_mcp"
    if stale_pkg_dir.is_dir():
        shutil.rmtree(stale_pkg_dir)
        report.add_step("dev_pth", "cleanup", f"removed stale {stale_pkg_dir}")
    site_packages / "ida_pro_mcp-*.dist-info"
    for p in site_packages.glob("ida_pro_mcp-*.dist-info"):
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
    pth_path = Path(result.stdout.strip()) / "ida_pro_mcp_dev.pth"
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

    if runtime_source == "local":
        _write_dev_pth(venv_dir, source_root, dry_run, report)
        report.metadata["runtime_source"] = "local-dev"
        report.metadata["runtime_package"] = f"pth:{source_root / 'src'}"
    else:
        _remove_dev_pth(venv_dir, report)
        if runtime_source == "snapshot":
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
def build_stdio_config(
    python_exe: Path,
    install_root: Path,
    embed_model: str = "",
    embed_server_bin: str = "",
    embed_profile: str = "",
    embed_backend: str = "",
    gemini_api_key: str = "",
    gemini_vertex_project: str = "",
    gemini_vertex_location: str = "",
    ida_install: object | None = None,
    disable_policy: bool = False,
) -> dict:
    """Build the stdio MCP server config for a specific IDA install.

    Resolution order for IDADIR:
      1. `ida_install` (IdaInstall from installer/discovery.py)
      2. IDADIR / IDA_DIR env
      3. `detect_ida_install_dir()` (legacy single-install path)

    ``embed_backend == "gemini"`` selects the opt-in cloud embedder: the
    client env carries ``IDA_MCP_EMBED_BACKEND=gemini`` plus the chosen
    credential (AI Studio API key or Vertex project/location).  The API key
    is written into the generated client config only when the user provided
    it; the server also honours the process environment if it is unset here.
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
    if str(embed_backend or "").lower() == "gemini":
        env["IDA_MCP_EMBED_BACKEND"] = "gemini"
        if gemini_api_key:
            env["GEMINI_API_KEY"] = gemini_api_key
        if gemini_vertex_project:
            env["GOOGLE_CLOUD_PROJECT"] = gemini_vertex_project
        if gemini_vertex_location:
            env["VERTEX_AI_LOCATION"] = gemini_vertex_location

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
