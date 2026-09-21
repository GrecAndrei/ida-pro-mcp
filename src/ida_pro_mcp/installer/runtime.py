from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from .common import InstallReport, SigsManifest, atomic_write_text, reject_symlink_path

_log = logging.getLogger(__name__)


_DOWNLOAD_CHUNK_BYTES = 1 * 1024 * 1024  # 1 MiB


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(_DOWNLOAD_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalise_sha256(value: str | None) -> str:
    """Return a strict lowercase SHA-256 digest from common metadata forms."""
    text = str(value or "").strip().lower()
    if text.startswith("sha256:"):
        text = text[7:].strip()
    return text if len(text) == 64 and all(char in "0123456789abcdef" for char in text) else ""


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
    if not overwrite and destination.exists():
        raise FileExistsError(destination)
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


def kill_ida_processes(binary_path: str | Path | None = None) -> bool:
    """Terminate running ida/idat processes.

    If `binary_path` is provided, only kill processes whose executable path
    (the first token of the command line) matches the canonicalized form of
    that path.  Without a filter the installer would happily SIGKILL a
    user's unrelated long-running IDA on a different binary — see §6.2.

    Returns ``False`` when a scoped process listing cannot be obtained or a
    matching process cannot be terminated. Unscoped termination returns
    ``True`` after attempting each platform command; a non-zero exit code
    there simply means that no process with that name was running.
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
                    try:
                        killed = subprocess.run(
                            ["taskkill", "/F", "/PID", pid], capture_output=True
                        )
                    except (OSError, subprocess.TimeoutExpired):
                        return False
                    if killed.returncode != 0:
                        return False
                return True
            # WMIC unavailable or denied: fail closed. An explicit binary
            # scope must never degrade into killing every IDA process.
            return False
        for name in ["idat.exe", "idat64.exe", "ida.exe", "ida64.exe"]:
            try:
                subprocess.run(["taskkill", "/F", "/IM", name], capture_output=True)
            except (OSError, subprocess.TimeoutExpired):
                return False
        return True

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
                try:
                    killed = subprocess.run(["kill", "-KILL", pid], capture_output=True)
                except (OSError, subprocess.TimeoutExpired):
                    return False
                if killed.returncode != 0:
                    return False
            return True
        # pgrep -af missing or denied: fail closed. An explicit binary scope
        # must never degrade into killing every IDA process.
        return False

    for name in ["idat", "idat64", "ida", "ida64"]:
        try:
            subprocess.run(["pkill", "-x", name], capture_output=True)
        except (OSError, subprocess.TimeoutExpired):
            return False
    return True


def choose_runtime_source(runtime_source: str, source_root: Path) -> str:
    if runtime_source in {"local", "snapshot", "pypi"}:
        return runtime_source
    # Default to a frozen snapshot of the checkout, never the live tree:
    # a .pth pointer to the working source makes the deployed server change
    # behavior whenever the checkout changes (or breaks it mid-edit).
    if (source_root / "pyproject.toml").exists():
        return "snapshot"
    return "pypi"




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
    try:
        source_resolved = source_root.resolve()
        install_resolved = install_root.resolve()
        nested_install = install_resolved.relative_to(source_resolved)
    except ValueError:
        nested_install = None
    except OSError as exc:
        raise RuntimeError(f"Could not resolve snapshot paths: {exc}") from exc
    if nested_install is not None and not nested_install.parts:
        raise RuntimeError(
            "runtime snapshot requires --install-root to be outside the source checkout"
        )

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
        "node_modules", "*.egg-info", ".pytest_cache", ".pytest_tmp", ".ruff_cache",
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
                elif nested_install is not None:
                    candidate_relative = Path(path).resolve().relative_to(source_resolved)
                    if (
                        candidate_relative.parts
                        and nested_install.parts
                        and candidate_relative.parts[0] == nested_install.parts[0]
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
    from .clients import backup_file

    backup_file(pth_path, report, dry_run=False)
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
    if pth_path.exists() and not pth_path.is_file():
        raise RuntimeError(f"development source pointer is not a regular file: {pth_path}")
    if pth_path.is_file():
        from .clients import backup_file

        backup_file(pth_path, report, dry_run=False)
        pth_path.unlink()
        report.add_modified(pth_path)
        report.add_step("dev_pth", "removed", f"removed live source pointer {pth_path}")


def find_bundled_runtime(source_root: Path) -> Path | None:
    """Return path to bundled python executable if running inside a self-contained bundle."""
    candidates = [
        source_root / "runtime",
        source_root.parent / "runtime",
        source_root.parent.parent / "runtime",
    ]
    for c in candidates:
        if c.is_dir():
            py_candidates = [
                c / "bin" / "python3",
                c / "bin" / "python",
                c / "python.exe",
                c / "Scripts" / "python.exe",
            ]
            for py in py_candidates:
                if py.is_file() and (os.access(py, os.X_OK) or os.name == "nt"):
                    return py
    return None


def create_launcher_shims(install_root: Path, python_exe: Path) -> Path:
    """Create executable launcher shim in install_root / 'bin'."""
    bin_dir = install_root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        shim = bin_dir / "ida-pro-mcp.cmd"
        content = f'@echo off\r\n"{python_exe}" -m ida_pro_mcp.host.server %*\r\n'
        atomic_write_text(shim, content)
        return shim
    else:
        shim = bin_dir / "ida-pro-mcp"
        content = f'#!/bin/sh\nexec "{python_exe}" -m ida_pro_mcp.host.server "$@"\n'
        atomic_write_text(shim, content)
        shim.chmod(0o755)
        return shim


def setup_runtime_environment(
    install_root: Path,
    source_root: Path,
    runtime_source: str,
    dry_run: bool,
    report: InstallReport,
) -> Path:
    install_root.mkdir(parents=True, exist_ok=True)
    bundled_py = find_bundled_runtime(source_root)
    if bundled_py is not None:
        report.add_step("runtime", "bundled", str(bundled_py))
        report.metadata["runtime_source"] = "bundled"
        report.metadata["venv_python"] = str(bundled_py)
        if not dry_run:
            create_launcher_shims(install_root, bundled_py)
        return bundled_py

    venv_dir = install_root / ".venv"
    reject_symlink_path(venv_dir, "runtime environment path")
    python_exe = _venv_python_exe(venv_dir)
    if dry_run:
        report.metadata["venv_python"] = str(python_exe)
        return python_exe

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
    if not dry_run:
        create_launcher_shims(install_root, python_exe)
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
    candidate = Path(ida_dir) / "idalib" / "python"
    try:
        reject_symlink_path(candidate, "idalib Python path")
        idapro_path = candidate / "idapro"
        reject_symlink_path(idapro_path, "idalib package path")
    except RuntimeError:
        return ""
    if idapro_path.is_dir():
        return str(candidate)
    return ""


def activate_idalib(ida_dir: str) -> tuple[bool, str]:
    """Point the idapro activation at *ida_dir*.

    Returns (ok, detail): True when ``py-activate-idalib.py -d <dir>``
    exists and exits 0.  Activation records the install idalib loads
    ``libidalib.so`` from; one install is active at a time.
    """
    python_dir = find_idalib_python_dir(ida_dir)
    py_path = Path(python_dir) / "py-activate-idalib.py" if python_dir else Path()
    try:
        if python_dir:
            reject_symlink_path(py_path, "idalib activation script path")
    except RuntimeError as exc:
        return False, str(exc)
    if not py_path.is_file():
        return False, f"no py-activate-idalib.py under {ida_dir}"
    py = str(py_path)
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
    ida_install: object | None = None,
    disable_policy: bool = False,
    ida_runtime: str = "",
    intelligence_mode: str = "disabled",
    jev_model: str = "",
    custom_base_url: str = "",
    custom_allowed_origins: str = "",
    custom_model: str = "",
    custom_protocol: str = "",
    custom_api_key_env: str = "",
    custom_api_key_file: str = "",
    custom_local_http: bool = False,
) -> dict:
    """Build the stdio MCP server config for a specific IDA install.

    Resolution order for IDADIR:
      1. `ida_install` (IdaInstall from installer/discovery.py)
      2. IDADIR / IDA_DIR env
      3. `detect_ida_install_dir()` (legacy single-install path)

    Intelligence is configured explicitly as ``jev``, ``custom``, or
    ``disabled``. Credentials are deliberately never copied into generated
    client configuration; providers read credentials at request time.
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
        # wrote its state files (ida-install.json and install-report.json)
        # under. Without this, a custom --install-root is invisible to the
        # host's get_install_root.
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
    mode = str(intelligence_mode or "disabled").strip().lower()
    if mode not in {"jev", "custom", "disabled"}:
        raise ValueError("intelligence_mode must be jev, custom, or disabled")
    env["IDA_MCP_INTELLIGENCE_MODE"] = mode
    if mode == "jev" and jev_model:
        env["IDA_MCP_JEV_MODEL"] = str(jev_model).strip()
    if mode == "custom":
        if custom_base_url:
            env["IDA_MCP_CUSTOM_BASE_URL"] = str(custom_base_url).strip()
        if custom_allowed_origins:
            env["IDA_MCP_CUSTOM_ALLOWED_ORIGINS"] = str(custom_allowed_origins).strip()
        if custom_model:
            env["IDA_MCP_CUSTOM_MODEL"] = str(custom_model).strip()
        if custom_protocol:
            env["IDA_MCP_CUSTOM_PROTOCOL"] = str(custom_protocol).strip()
        if custom_api_key_env:
            env["IDA_MCP_CUSTOM_API_KEY_ENV"] = str(custom_api_key_env).strip()
        if custom_api_key_file:
            env["IDA_MCP_CUSTOM_API_KEY_FILE"] = str(custom_api_key_file).strip()
        if custom_local_http:
            env["IDA_MCP_CUSTOM_LOCAL_HTTP"] = "1"
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
    """Best-effort installation of explicitly requested optional packages.

    Provider credentials and provider SDKs are never installed implicitly;
    callers must supply the package list themselves. Returns True on success,
    False when the venv python is unknown or installation fails.
    """
    if not python_exe or not packages:
        return False
    cmd = [str(python_exe), "-m", "pip", "install", *packages]
    try:
        run_checked(cmd, timeout=300.0)
        return True
    except Exception:
        return False
