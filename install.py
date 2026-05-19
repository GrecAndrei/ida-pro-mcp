#!/usr/bin/env python3
"""
IDA Pro MCP - Installer v3.0
Unified installer for all MCP clients with uv support.
"""

import os
import sys
import json
import shutil
import argparse
import subprocess
import glob
import re
from pathlib import Path

# ============================================================================
# Windows ANSI Color Support
# ============================================================================


def enable_ansi():
    """Enable ANSI escape codes on Windows"""
    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            pass


enable_ansi()

# ============================================================================
# Colors
# ============================================================================


class C:
    if sys.stdout.isatty():
        RESET = "\033[0m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        RED = "\033[91m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        BLUE = "\033[94m"
        MAGENTA = "\033[95m"
        CYAN = "\033[96m"
        WHITE = "\033[97m"
    else:
        RESET = BOLD = DIM = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""


# ============================================================================
# Simple Text Logo
# ============================================================================

LOGO = f"""
{C.CYAN}================================================================================{C.RESET}

                         {C.MAGENTA}{C.BOLD}IDA Pro MCP{C.RESET}

              {C.WHITE}AI-Powered Reverse Engineering for IDA Pro{C.RESET}

{C.CYAN}================================================================================{C.RESET}
"""

# ============================================================================
# Helpers
# ============================================================================


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def step(num, total, msg):
    print(f"\n{C.CYAN}[{num}/{total}]{C.RESET} {msg}")


def success(msg):
    print(f"       {C.GREEN}OK{C.RESET} {msg}")


def warning(msg):
    print(f"       {C.YELLOW}!!{C.RESET} {msg}")


def error(msg):
    print(f"       {C.RED}ERR{C.RESET} {msg}")


def dim(msg):
    print(f"       {C.DIM}{msg}{C.RESET}")


def get_script_dir():
    return Path(__file__).parent.absolute()


def _ida_binary_names():
    if sys.platform == "win32":
        return ["idat64.exe", "idat.exe", "ida64.exe", "ida.exe"]
    return ["idat64", "idat", "ida64", "ida"]


def detect_ida_install_dir():
    """Best-effort auto-detection of IDA install directory."""
    for env_name in ("IDADIR", "IDA_DIR", "IDA_MCP_IDAT"):
        value = os.environ.get(env_name)
        if not value:
            continue
        p = Path(value).expanduser().resolve()
        if p.is_dir():
            return p
        if p.is_file():
            return p.parent

    cands = []
    if sys.platform == "win32":
        cands.extend(
            [
                Path(r"C:\Program Files\IDA Professional 9.2"),
                Path(r"C:\Program Files\IDA Pro 9.2"),
                Path(r"C:\Program Files\IDA Professional"),
                Path(r"C:\Program Files\IDA Pro"),
            ]
        )
    elif sys.platform == "linux":
        home = Path.home()
        patterns = [
            "/opt/ida*",
            "/opt/IDA*",
            "/opt/idapro*",
            "/opt/IDAPro*",
            "/usr/local/ida*",
            "/usr/local/IDA*",
            "/usr/local/idapro*",
            "/usr/local/IDAPro*",
            str(home / "ida*"),
            str(home / "IDA*"),
            str(home / "idapro*"),
            str(home / "IDAPro*"),
        ]
        for pattern in patterns:
            for p in glob.glob(os.path.expanduser(pattern)):
                cands.append(Path(p))
    else:
        cands.extend(
            [
                Path("/Applications/IDA Professional 9.2.app/Contents/MacOS"),
                Path("/Applications/IDA Pro 9.2.app/Contents/MacOS"),
                Path("/Applications/IDA Professional.app/Contents/MacOS"),
                Path("/Applications/IDA Pro.app/Contents/MacOS"),
            ]
        )

    bins = _ida_binary_names()
    for cand in cands:
        if not cand.exists() or not cand.is_dir():
            continue
        for name in bins:
            exe = cand / name
            if exe.exists() and (sys.platform == "win32" or os.access(exe, os.X_OK)):
                return cand

    for name in bins:
        resolved = shutil.which(name)
        if resolved:
            return Path(resolved).resolve().parent
    return None


def get_ida_user_dir():
    """Locate IDA user directory used for plugins/config."""
    env_dir = os.environ.get("IDAUSR") or os.environ.get("IDA_USER_DIR")
    if env_dir:
        return Path(env_dir).expanduser()
    return Path.home() / ".idapro"


def _ps_quote(s: str) -> str:
    return s.replace("'", "''")


def kill_processes_for_paths(paths, kill_ida=True):
    targets = [str(p) for p in paths if p]
    if sys.platform == "win32":
        for p in targets:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                f"$p='{_ps_quote(p)}'; Get-Process | Where-Object {{$_.Path -and ($_.Path -ieq $p)}} | Stop-Process -Force -ErrorAction SilentlyContinue",
            ]
            subprocess.run(cmd, capture_output=True)
        if kill_ida:
            for name in ["idat.exe", "idat64.exe", "ida.exe", "ida64.exe"]:
                subprocess.run(["taskkill", "/F", "/IM", name], capture_output=True)
    else:
        for p in targets:
            # Use an anchored regex so we only match commands that start with this
            # exact executable path, rather than broad substring matches.
            safe_pattern = rf"^{re.escape(p)}([[:space:]].*)?$"
            subprocess.run(["pkill", "-f", safe_pattern], capture_output=True)
        if kill_ida:
            # Never use broad `pkill -f ida` patterns: they can match unrelated
            # processes (e.g. paths containing "ida-pro-mcp") and kill terminals.
            for name in ["idat", "idat64", "ida", "ida64"]:
                subprocess.run(["pkill", "-x", name], capture_output=True)


def get_permanent_dir():
    """Get a professional permanent directory for the MCP server."""
    if sys.platform == "win32":
        return (
            Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
            / "ida-pro-mcp"
        )
    else:
        return Path.home() / ".local" / "share" / "ida-pro-mcp"


def get_ida_plugin_dir():
    """Find the IDA Pro plugins directory."""
    if sys.platform == "win32":
        ida_folder = Path(os.environ.get("APPDATA", "")) / "Hex-Rays" / "IDA Pro"
    else:
        ida_folder = get_ida_user_dir()
    return ida_folder / "plugins"


def get_codex_home_dir():
    """Get Codex home directory."""
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        return Path(codex_home).expanduser()
    return Path.home() / ".codex"


def _safe_remove_path(path: Path):
    """Remove existing file/dir/symlink safely."""
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _same_link_target(dst: Path, src: Path) -> bool:
    """Return True if dst is a symlink that resolves to src."""
    if not dst.is_symlink():
        return False
    try:
        return dst.resolve() == src.resolve()
    except Exception:
        return False


def _replace_with_symlink_or_copy(src: Path, dst: Path) -> str:
    """
    Ensure dst points to src.
    Returns one of: linked, copied, reused
    """
    if _same_link_target(dst, src):
        return "reused"

    if dst.exists() or dst.is_symlink():
        _safe_remove_path(dst)

    try:
        os.symlink(src, dst, target_is_directory=True)
        return "linked"
    except OSError:
        # Handle races / stale entries where dst appeared after removal.
        if dst.exists() or dst.is_symlink():
            _safe_remove_path(dst)
        shutil.copytree(src, dst)
        return "copied"


def _is_generated_skill_dir(path: Path) -> bool:
    """True if directory contains a generated SKILL.md from this repo's generator."""
    skill_file = path / "SKILL.md"
    if not skill_file.exists():
        return False
    try:
        text = skill_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    return "GENERATED: scripts/generate_tool_skills.py" in text


def _prune_generated_skills(codex_skills_dir: Path, keep_names: set[str]) -> int:
    """Remove generated ida-tool-* skills not in keep_names."""
    removed = 0
    if not codex_skills_dir.exists():
        return removed

    for child in codex_skills_dir.iterdir():
        if not child.name.startswith("ida-tool-"):
            continue
        if child.name in keep_names:
            continue
        if not child.is_dir():
            continue
        if not _is_generated_skill_dir(child):
            continue
        try:
            _safe_remove_path(child)
            removed += 1
        except Exception:
            continue
    return removed


def _ensure_generated_skills(install_path: Path):
    """
    Ensure `.agents/skills` exists.
    If missing but generator is available, run it once.
    """
    skills_root = install_path / ".agents" / "skills"
    if skills_root.exists():
        return skills_root

    generator = install_path / "scripts" / "generate_tool_skills.py"
    if generator.exists():
        try:
            _run_checked([sys.executable, str(generator)], cwd=install_path)
        except Exception:
            return None
    return skills_root if skills_root.exists() else None


def install_codex_skills(install_path: Path, skills_mode: str = "router"):
    """
    Install generated per-tool Codex skills into CODEX_HOME/skills.
    Returns dict: {ok, linked, copied, total, path, reason?}
    """
    try:
        skills_root = _ensure_generated_skills(install_path)
        if not skills_root or not skills_root.exists():
            return {"ok": False, "reason": "generated skills not found"}

        codex_skills_dir = get_codex_home_dir() / "skills"
        codex_skills_dir.mkdir(parents=True, exist_ok=True)

        source_skill_dirs = sorted(
            p for p in skills_root.iterdir() if p.is_dir() and (p / "SKILL.md").exists()
        )
        if not source_skill_dirs:
            return {"ok": False, "reason": "no skill directories with SKILL.md found"}

        if skills_mode == "router":
            source_skill_dirs = [
                p for p in source_skill_dirs if p.name == "ida-tool-router"
            ]
            if not source_skill_dirs:
                return {"ok": False, "reason": "router skill not found"}
        elif skills_mode == "full":
            pass
        elif skills_mode == "none":
            return {
                "ok": True,
                "linked": 0,
                "copied": 0,
                "reused": 0,
                "removed": 0,
                "total": 0,
                "path": str(codex_skills_dir),
                "mode": "none",
            }
        else:
            return {"ok": False, "reason": f"invalid skills mode: {skills_mode}"}

        keep_names = {p.name for p in source_skill_dirs}
        removed = _prune_generated_skills(codex_skills_dir, keep_names)

        linked = 0
        copied = 0
        reused = 0
        for src in source_skill_dirs:
            dst = codex_skills_dir / src.name
            try:
                result = _replace_with_symlink_or_copy(src, dst)
            except PermissionError:
                # If a correct symlink already exists but cannot be replaced
                # (e.g., restricted environment), treat it as reusable.
                if _same_link_target(dst, src):
                    result = "reused"
                else:
                    raise

            if result == "linked":
                linked += 1
            elif result == "copied":
                copied += 1
            elif result == "reused":
                reused += 1

        return {
            "ok": True,
            "linked": linked,
            "copied": copied,
            "reused": reused,
            "removed": removed,
            "total": len(source_skill_dirs),
            "path": str(codex_skills_dir),
            "mode": skills_mode,
        }
    except Exception as e:
        return {"ok": False, "reason": str(e)}


def relocate_self(dest_dir: Path):
    """Copy or upgrade the project in a permanent location."""
    src_dir = get_script_dir()
    if src_dir == dest_dir:
        return True

    is_upgrade = dest_dir.exists()
    action_str = "Upgrading" if is_upgrade else "Migrating"
    print(f"       {C.CYAN}>>{C.RESET} {action_str} to: {C.WHITE}{dest_dir}{C.RESET}")

    try:
        # Create destination if it doesn't exist
        dest_dir.mkdir(parents=True, exist_ok=True)

        # 1. CORE CODE (Always replace to ensure upgrade)
        core_items = [
            "src",
            "docs",
            ".agents",
            "scripts",
            "ida_mcp_stdio.py",
            "ida_mcp_http.py",
            "install.py",
            "client_configs.json",
            "pyproject.toml",
        ]
        for item in core_items:
            s = src_dir / item
            d = dest_dir / item
            if not s.exists():
                continue

            if s.is_dir():
                if d.exists():
                    shutil.rmtree(d)
                shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)

        # 2. DOCUMENTATION (Replace)
        for item in ["README.md", "LICENSE"]:
            if (src_dir / item).exists():
                shutil.copy2(src_dir / item, dest_dir / item)

        success(f"{action_str} successful")
        return True
    except Exception as e:
        error(f"{action_str} failed: {e}")
        return False


def check_uv_installed():
    """Check if uv is installed."""
    try:
        subprocess.run(["uv", "--version"], capture_output=True, check=True)
        return True
    except:
        return False


def _run_checked(cmd, *, cwd=None, env=None):
    """Run a subprocess and return concise diagnostics on failure."""
    result = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        detail = stderr or stdout
        if detail:
            lines = [line for line in detail.splitlines() if line.strip()]
            tail = " | ".join(lines[-6:])[:600]
            raise RuntimeError(
                f"{' '.join(cmd)} failed (exit {result.returncode}): {tail}"
            )
        raise RuntimeError(f"{' '.join(cmd)} failed (exit {result.returncode})")
    return result


def _pick_writable_uv_cache(install_path: Path) -> Path:
    """Return a writable cache dir for uv with safe fallbacks."""
    candidates = []
    env_cache = os.environ.get("UV_CACHE_DIR")
    if env_cache:
        candidates.append(Path(env_cache).expanduser())
    candidates.extend(
        [
            get_permanent_dir() / "cache" / "uv",
            install_path / ".uv-cache",
            Path("/tmp") / "ida-pro-mcp-uv-cache",
        ]
    )
    for cand in candidates:
        try:
            cand.mkdir(parents=True, exist_ok=True)
            probe = cand / ".write_probe"
            with open(probe, "w", encoding="utf-8") as f:
                f.write("ok")
            probe.unlink(missing_ok=True)
            return cand
        except Exception:
            continue
    raise RuntimeError("Unable to create a writable uv cache directory")


def _find_embed_model(install_path: Path) -> str:
    """
    Locate a bge-code-v1 GGUF embedding model.
    Search order:
      1. IDA_MCP_EMBED_MODEL env var
      2. Common GGUF filenames next to the install dir
      3. ~/.cache/huggingface and ~/models
      4. Interactive prompt (skipped in non-TTY environments)
    """
    env_val = os.environ.get("IDA_MCP_EMBED_MODEL", "")
    if env_val and os.path.isfile(env_val):
        return env_val

    # Common locations
    candidates = [
        install_path / "bge-code-v1-q8_0.gguf",
        install_path / "bge-code-v1.gguf",
        install_path.parent / "bge-code-v1-q8_0.gguf",
        Path.home() / ".cache" / "huggingface" / "hub" / "models--BAAI--bge-code-v1" / "snapshots",
        Path.home() / "models" / "bge-code-v1-q8_0.gguf",
        Path.home() / "Downloads" / "bge-code-v1-q8_0.gguf",
    ]
    for c in candidates:
        p = Path(c)
        if p.is_file():
            return str(p)
        # Handle HuggingFace snapshot dirs
        if p.is_dir():
            for snap in sorted(p.iterdir(), reverse=True):
                for f in snap.glob("*.gguf"):
                    return str(f)

    # Glob search in common dirs
    for search_root in (Path.home() / ".cache", Path.home() / "models", Path.home() / "Downloads"):
        if search_root.is_dir():
            for f in search_root.rglob("bge-code-v1*.gguf"):
                return str(f)

    # Interactive prompt (only when running in a real terminal)
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            ans = input(
                "\n  [embedding] Enter path to bge-code-v1 GGUF model (or press Enter to skip): "
            ).strip()
            if ans and os.path.isfile(ans):
                return ans
        except (EOFError, KeyboardInterrupt):
            pass

    return ""


def _find_llama_server_bin(install_path: Path) -> str:
    """
    Locate the llama-server binary.
    Search order:
      1. IDA_MCP_EMBED_SERVER_BIN env var
      2. Next to install dir
      3. PATH
      4. Common build locations
    """
    env_val = os.environ.get("IDA_MCP_EMBED_SERVER_BIN", "")
    if env_val and os.path.isfile(env_val) and os.access(env_val, os.X_OK):
        return env_val

    # Common locations
    names = ["llama-server", "llama-server.exe"]
    candidates = [
        install_path / "llama-server",
        install_path.parent / "llama-server",
        Path("/usr/local/bin/llama-server"),
        Path("/usr/bin/llama-server"),
        Path.home() / ".local" / "bin" / "llama-server",
        Path.home() / "llama.cpp" / "build" / "bin" / "llama-server",
    ]
    for c in candidates:
        if c.is_file() and os.access(str(c), os.X_OK):
            return str(c)

    # PATH lookup
    import shutil as _shutil
    for name in names:
        found = _shutil.which(name)
        if found:
            return found

    return ""


def get_mcp_server_config(
    install_path: Path, client_name: str = "", global_vertex_compat: bool = False
):
    """Get the MCP server configuration pointing to the permanent venv python."""
    if sys.platform == "win32":
        python_exe = install_path / ".venv" / "Scripts" / "python.exe"
    else:
        python_exe = install_path / ".venv" / "bin" / "python"

    server_script = install_path / "ida_mcp_stdio.py"

    detected_idadir = os.environ.get("IDADIR") or os.environ.get("IDA_DIR")
    if not detected_idadir:
        auto_ida = detect_ida_install_dir()
        if auto_ida:
            detected_idadir = str(auto_ida)

    env = {}
    if detected_idadir:
        env["IDADIR"] = detected_idadir
    wiki_dir = install_path / "docs" / "wiki"
    if wiki_dir.exists():
        env["IDA_MCP_WIKI_DIR"] = str(wiki_dir)
    # Provide full tool descriptions and schemas directly to the LLM at load time.
    env["IDA_MCP_MONOLITHIC_TOOL_DESCRIPTIONS"] = "1"
    # Aggressive context defaults for LLM clients (can be overridden per-call/env).
    env["IDA_MCP_RESPONSE_MODE"] = "compact"
    env["IDA_MCP_QOL_MODE"] = "balanced"
    env["IDA_MCP_TOOLS_LIST_MODE"] = "full"
    env["IDA_MCP_BATCH_COMPACT"] = "1"
    env["IDA_MCP_COMPACT_MAX_ITEMS"] = "48"
    env["IDA_MCP_COMPACT_MAX_STRING"] = "1400"
    env["IDA_MCP_COMPACT_CHAR_BUDGET"] = "30000"
    env["IDA_MCP_TRUNCATE_TOKENS"] = "2000"
    env["IDA_MCP_WIKI_DEFAULT_LIMIT"] = "140"

    if global_vertex_compat or client_name in (
        "Gemini CLI",
        "OpenCode",
        "opencode",
        "Antigravity",
        "Antigravity CLI",
        "Antigravity IDE",
    ):
        env["IDA_MCP_VERTEX_COMPAT"] = "1"

    # ── Embedding model detection ──────────────────────────────────────────
    # Detect bge-code-v1 GGUF and llama-server so the intelligence layer
    # can use real embeddings instead of TF-IDF fallback.
    _embed_model = _find_embed_model(install_path)
    _embed_server = _find_llama_server_bin(install_path)
    if _embed_model:
        env["IDA_MCP_EMBED_MODEL"] = _embed_model
        print(f"       {C.GREEN}>>{C.RESET} Embedding model: {_embed_model}")
    else:
        print(f"       {C.YELLOW}>>{C.RESET} No embedding model found. Set IDA_MCP_EMBED_MODEL to a bge-code-v1 GGUF path for semantic features.")
    if _embed_server:
        env["IDA_MCP_EMBED_SERVER_BIN"] = _embed_server
        print(f"       {C.GREEN}>>{C.RESET} llama-server: {_embed_server}")
    elif _embed_model:
        print(f"       {C.YELLOW}>>{C.RESET} llama-server not found. Set IDA_MCP_EMBED_SERVER_BIN for GPU-accelerated embeddings.")

    return {
        "command": str(python_exe),
        "args": ["-u", str(server_script)],
        "env": env,
    }


def setup_virtualenv(install_path: Path):
    """Create a high-performance virtual environment at the destination."""
    print(f"       {C.CYAN}>>{C.RESET} Setting up optimized environment...")
    venv_dir = install_path / ".venv"
    venv_python = venv_dir / (
        "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
    )
    try:
        # Force clean start to avoid interactive prompts
        if venv_dir.exists():
            try:
                shutil.rmtree(venv_dir)
            except Exception:
                kill_processes_for_paths([venv_python], kill_ida=False)
                shutil.rmtree(venv_dir)

        if check_uv_installed():
            uv_env = os.environ.copy()
            uv_cache = _pick_writable_uv_cache(install_path)
            uv_env["UV_CACHE_DIR"] = str(uv_cache)
            _run_checked(["uv", "venv", ".venv"], cwd=install_path, env=uv_env)
            # Install core dependencies into the permanent venv
            _run_checked(
                [
                    "uv",
                    "pip",
                    "install",
                    "idapro",
                    "yara-python",
                    "requests",
                    "tomli-w",
                    "-e",
                    ".",
                ],
                cwd=install_path,
                env=uv_env,
            )
        else:
            _run_checked([sys.executable, "-m", "venv", ".venv"], cwd=install_path)
            pip_exe = install_path / (
                ".venv/Scripts/pip.exe" if sys.platform == "win32" else ".venv/bin/pip"
            )
            _run_checked(
                [
                    str(pip_exe),
                    "install",
                    "idapro",
                    "yara-python",
                    "requests",
                    "tomli-w",
                    "-e",
                    ".",
                ],
                cwd=install_path,
            )
        success("Environment optimized")
        return True
    except Exception as e:
        error(f"Environment setup failed: {e}")
        return False


def verify_runtime_imports(install_path: Path) -> bool:
    """Verify core runtime imports inside the installed venv."""
    python_exe = install_path / (
        ".venv/Scripts/python.exe" if sys.platform == "win32" else ".venv/bin/python"
    )
    if not python_exe.exists():
        error(f"Venv python not found: {python_exe}")
        return False
    try:
        _run_checked(
            [
                str(python_exe),
                "-c",
                "import numpy, tomli_w, requests, ida_pro_mcp.host.server; print('ok')",
            ],
            cwd=install_path,
        )
        success("Runtime import check passed (numpy/tomli_w/requests/server)")
        return True
    except Exception as e:
        error(f"Runtime import check failed: {e}")
        return False


def _load_client_configs():
    """Load MCP client configuration paths from JSON data file."""
    script_dir = Path(__file__).parent.resolve()
    data_path = script_dir / "client_configs.json"
    if not data_path.exists():
        # Fallback: look next to the script
        data_path = Path(os.path.dirname(os.path.abspath(__file__))) / "client_configs.json"
    with open(data_path, "r", encoding="utf-8") as f:
        return json.load(f)["clients"]


def get_mcp_config_paths():
    """Get all known MCP client config file paths"""
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    xdg_config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
    is_windows = os.name == "nt"

    def pick_path(candidates):
        """Prefer an existing candidate, otherwise use the first as default."""
        for c in candidates:
            if c and c.exists():
                return c
        return candidates[0]

    def resolve(path_template: str):
        return Path(path_template.replace("{home}", str(home)).replace("{appdata}", str(appdata)).replace("{xdg_config}", str(xdg_config)))

    raw = _load_client_configs()
    configs = {}
    for name, meta in raw.items():
        paths = meta.get("paths", [])
        pick_existing = meta.get("pick_existing", False)
        env_override = meta.get("env_override")
        env_fallback = meta.get("env_fallback")

        if env_override:
            override = os.environ.get(env_override)
            if override:
                configs[name] = Path(override).expanduser()
                continue

        if isinstance(paths, dict):
            path_str = paths.get("windows", "") if is_windows else paths.get("unix", "")
            configs[name] = resolve(path_str)
        elif isinstance(paths, list):
            candidates = [resolve(p) for p in paths]
            if env_fallback:
                if env_fallback in os.environ:
                    # Use the XDG-style candidate (first one referencing xdg_config)
                    xdg_candidates = [c for c in candidates if str(xdg_config) in str(c)]
                    configs[name] = xdg_candidates[0] if xdg_candidates else candidates[0]
                else:
                    # Use the fallback candidate (non-xdg)
                    fallback = [c for c in candidates if str(xdg_config) not in str(c)]
                    configs[name] = fallback[0] if fallback else candidates[-1]
                continue
            configs[name] = pick_path(candidates) if pick_existing else candidates[0]
        else:
            configs[name] = resolve(paths)

    return configs


LEGACY_SERVER_NAMES = (
    "ida-pro-mcp",
    "github.com/mrexodia/ida-pro-mcp",
    "ida_mcp",
    "ida-pro-mcp-server",
)


def _looks_like_ida_mcp_entry(entry) -> bool:
    if not isinstance(entry, dict):
        return False
    tokens = []
    cmd = entry.get("command")
    args = entry.get("args")
    if isinstance(cmd, str):
        tokens.append(cmd)
    elif isinstance(cmd, list):
        tokens.extend(str(x) for x in cmd)
    if isinstance(args, str):
        tokens.append(args)
    elif isinstance(args, list):
        tokens.extend(str(x) for x in args)
    text = " ".join(tokens).lower()
    return ("ida_mcp_stdio.py" in text) or ("ida-pro-mcp" in text)


def _prune_legacy_entries(container: dict, server_name: str):
    if not isinstance(container, dict):
        return
    to_remove = []
    for key, value in container.items():
        if key == server_name:
            continue
        if key in LEGACY_SERVER_NAMES or _looks_like_ida_mcp_entry(value):
            to_remove.append(key)
    for key in to_remove:
        container.pop(key, None)


def _toml_key(key: str) -> str:
    if re.match(r"^[A-Za-z0-9_-]+$", key):
        return key
    escaped = key.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _toml_literal(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        escaped = (
            value.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        )
        return f'"{escaped}"'
    if isinstance(value, list):
        return "[" + ", ".join(_toml_literal(v) for v in value) + "]"
    raise TypeError(f"Unsupported TOML value type: {type(value)}")


def _toml_dump_simple(data: dict) -> str:
    lines = []

    def emit_table(table: dict, path: list[str]):
        scalar_items = []
        table_items = []
        for k, v in table.items():
            if isinstance(v, dict):
                table_items.append((k, v))
            else:
                scalar_items.append((k, v))
        if path:
            if lines:
                lines.append("")
            header = ".".join(_toml_key(p) for p in path)
            lines.append(f"[{header}]")
        for k, v in scalar_items:
            lines.append(f"{_toml_key(k)} = {_toml_literal(v)}")
        for k, sub in table_items:
            emit_table(sub, path + [k])

    emit_table(data, [])
    return "\n".join(lines) + "\n"


def update_json_config(
    config_path: Path,
    server_name: str = "ida-pro-mcp",
    client_name: str = "",
    install_path: Path = None,
    global_vertex_compat: bool = False,
) -> bool:
    """Add/Update server in a JSON config file."""
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)

        source_path = config_path
        if (
            client_name == "Copilot CLI"
            and not config_path.exists()
            and os.name != "nt"
        ):
            legacy = Path.home() / ".copilot" / "mcp-config.json"
            if legacy.exists() and legacy != config_path:
                source_path = legacy

        if source_path.exists():
            with open(source_path, "r", encoding="utf-8") as f:
                try:
                    config = json.load(f)
                except json.JSONDecodeError:
                    config = {}
        else:
            config = {}

        # Get server config
        server_config = get_mcp_server_config(
            install_path, client_name, global_vertex_compat
        )

        # GitHub Copilot CLI uses "mcpServers" with type: stdio
        if client_name == "Copilot CLI":
            # Remove stale "servers" entry if exists
            if "servers" in config and server_name in config["servers"]:
                del config["servers"][server_name]
            if "servers" in config and not config["servers"]:
                del config["servers"]

            if "mcpServers" not in config:
                config["mcpServers"] = {}
            # Copilot CLI format: type "local", tools required
            copilot_config = {
                "type": "local",
                "command": server_config["command"],
                "args": server_config["args"],
                "env": server_config["env"],
                "tools": ["*"],  # Required by Copilot CLI, "*" means all tools
            }
            _prune_legacy_entries(config["mcpServers"], server_name)
            config["mcpServers"][server_name] = copilot_config
        else:
            # Standard clients use "mcpServers" without type field
            if "mcpServers" not in config:
                config["mcpServers"] = {}
            _prune_legacy_entries(config["mcpServers"], server_name)
            config["mcpServers"][server_name] = server_config

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        return True
    except Exception as e:
        # dim(f"Failed to update {config_path}: {e}")
        return False


def update_toml_config(
    config_path: Path,
    server_name: str = "ida-pro-mcp",
    install_path: Path = None,
    client_name: str = "",
    global_vertex_compat: bool = False,
) -> bool:
    """Add/Update server in a TOML config file (for Codex)."""
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # Fallback for older python if installed
        try:
            import tomli_w
        except ImportError:
            tomli_w = None

        config_path.parent.mkdir(parents=True, exist_ok=True)

        config = {}
        if config_path.exists():
            with open(config_path, "rb") as f:
                try:
                    config = tomllib.load(f)
                except:
                    pass

        # Codex structure: [mcp_servers.ida-pro-mcp] ...
        if "mcp_servers" not in config:
            config["mcp_servers"] = {}

        _prune_legacy_entries(config["mcp_servers"], server_name)
        config["mcp_servers"][server_name] = get_mcp_server_config(
            install_path, client_name, global_vertex_compat
        )

        if tomli_w is not None:
            with open(config_path, "wb") as f:
                tomli_w.dump(config, f)
        else:
            # Fallback serializer so Codex repair still works without tomli-w.
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(_toml_dump_simple(config))

        return True
    except Exception as e:
        # dim(f"Failed to update {config_path}: {e}")
        return False


def update_opencode_config(
    config_path: Path,
    server_name: str = "ida-pro-mcp",
    install_path: Path = None,
    global_vertex_compat: bool = False,
) -> bool:
    """Add/Update server in OpenCode config file (uses MCP schema)."""
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)

        source_path = config_path
        if not config_path.exists():
            # Legacy paths from earlier installer versions.
            for legacy in (
                Path.home() / ".opencode" / "mcp_config.json",
                Path.home() / ".opencode" / "opencode.json",
            ):
                if legacy.exists():
                    source_path = legacy
                    break

        if source_path.exists():
            with open(source_path, "r", encoding="utf-8") as f:
                content = f.read()
                # Strip comments for parsing (JSONC support)
                import re

                # Remove single-line comments
                content = re.sub(r"//.*?$", "", content, flags=re.MULTILINE)
                # Remove multi-line comments
                content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
                try:
                    config = json.loads(content)
                except json.JSONDecodeError:
                    config = {}
        else:
            config = {}

        # OpenCode schema: "mcp": { "server-name": { "type": "local", "command": [...], "enabled": true } }
        if "$schema" not in config:
            config["$schema"] = "https://opencode.ai/config.json"
        if "mcp" not in config:
            config["mcp"] = {}
        _prune_legacy_entries(config["mcp"], server_name)

        server_config = get_mcp_server_config(
            install_path, "OpenCode", global_vertex_compat
        )

        # Transform to OpenCode's local MCP format
        opencode_config = {
            "type": "local",
            "command": [server_config["command"]] + server_config["args"],
            "enabled": True,
            "environment": server_config.get("env", {}),
        }

        config["mcp"][server_name] = opencode_config

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

        return True
    except Exception as e:
        # dim(f"Failed to update {config_path}: {e}")
        return False


def configure_client(client_name: str, config_path: Path) -> bool:
    """Configure a specific client."""
    if config_path.suffix == ".toml":
        return update_toml_config(config_path, client_name=client_name)
    else:
        return update_json_config(config_path, client_name=client_name)


# ============================================================================
# Install
# ============================================================================


def do_install(skills_mode: str = "router"):
    clear()
    print(LOGO)
    print(f"   {C.DIM}Version 3.1  |  Professional Migration Edition{C.RESET}\n")

    # Ask the user if they want to enable Vertex AI compatibility
    print(
        f"   {C.CYAN}?{C.RESET} Would you like to enable Vertex AI compatibility for all MCP clients?"
    )
    print(
        f"     {C.DIM}This optimizes the schema specifically for Google Gemini/Vertex API endpoints.{C.RESET}"
    )
    print(
        f"     {C.DIM}It is normally only enabled automatically for OpenCode, Gemini CLI, and Antigravity.{C.RESET}"
    )
    vertex_choice = input(f"   Enable globally? [y/N]: ").strip().lower()
    global_vertex_compat = vertex_choice in ("y", "yes")
    if global_vertex_compat:
        success("Vertex AI schema compatibility will be enabled globally.")

    total_steps = 7
    script_dir = get_script_dir()
    perm_dir = get_permanent_dir()

    # Step 1: Migration Check
    step(1, total_steps, "Analyzing location...")
    is_temp = any(
        x in str(script_dir).lower() for x in ["download", "temp", "tmp", "desktop"]
    )

    if is_temp:
        warning(f"Running from temporary location: {C.WHITE}{script_dir.name}{C.RESET}")
        if relocate_self(perm_dir):
            install_path = perm_dir
        else:
            warning("Staying in current location due to migration error.")
            install_path = script_dir
    else:
        success(f"Running from stable location: {C.WHITE}{script_dir}{C.RESET}")
        install_path = script_dir

    # Step 2: Check Python & UV
    step(2, total_steps, "Checking environment...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 11):
        error(f"Python 3.11+ required, found {version.major}.{version.minor}")
        return False
    success(f"Python {version.major}.{version.minor}.{version.micro}")

    if check_uv_installed():
        success("uv detected (will be used for execution)")
    else:
        warning("uv not found (falling back to python)")

    detected_ida = detect_ida_install_dir()
    if detected_ida:
        os.environ.setdefault("IDADIR", str(detected_ida))
        success(f"Detected IDA install: {detected_ida}")
    else:
        warning("IDA install path not auto-detected (set IDADIR if needed)")

    # Step 3: Install package & Venv
    step(3, total_steps, "Installing IDA Pro MCP environment...")
    dim("This may take a moment...")
    dim("Stopping running IDA/IDAT processes to prevent file locks...")
    kill_processes_for_paths([], kill_ida=True)
    if not setup_virtualenv(install_path):
        return False

    # Step 4: Configure MCP Clients
    step(4, total_steps, "Configuring MCP clients...")
    configs = get_mcp_config_paths()
    configured = []

    # Pass the install_path to get correct config
    def configure_with_path(client, path):
        if client == "OpenCode":
            return update_opencode_config(
                path,
                install_path=install_path,
                global_vertex_compat=global_vertex_compat,
            )
        elif path.suffix == ".toml":
            return update_toml_config(
                path,
                install_path=install_path,
                client_name=client,
                global_vertex_compat=global_vertex_compat,
            )
        else:
            return update_json_config(
                path,
                client_name=client,
                install_path=install_path,
                global_vertex_compat=global_vertex_compat,
            )

    priority_clients = [
        "Gemini CLI",
        "Antigravity",
        "Antigravity CLI",
        "Antigravity IDE",
        "Claude Code",
        "Codex",
        "Claude Desktop",
        "Copilot CLI",
        "OpenCode",
    ]

    for client, config_path in configs.items():
        if (
            config_path.exists()
            or config_path.parent.exists()
            or client in priority_clients
        ):
            if configure_with_path(client, config_path):
                configured.append(client)
                success(f"{client}")

    # Step 5: Install Codex Skills
    step(5, total_steps, "Installing Codex skills...")
    codex_skills_result = install_codex_skills(install_path, skills_mode=skills_mode)
    if codex_skills_result.get("ok"):
        success(
            f"Codex skills: {codex_skills_result.get('total', 0)} "
            f"(linked={codex_skills_result.get('linked', 0)}, copied={codex_skills_result.get('copied', 0)}, "
            f"reused={codex_skills_result.get('reused', 0)}, removed={codex_skills_result.get('removed', 0)})"
        )
        dim(f"Mode: {codex_skills_result.get('mode', skills_mode)}")
        dim(f"Installed to: {codex_skills_result.get('path')}")
    else:
        warning(
            f"Codex skills install skipped: {codex_skills_result.get('reason', 'unknown error')}"
        )

    # Step 6: Install IDA Plugin
    step(6, total_steps, "Installing IDA Pro plugin...")
    ida_plugin_dir = get_ida_plugin_dir()
    plugin_installed = False

    try:
        ida_plugin_dir.mkdir(parents=True, exist_ok=True)

        # Source files
        src_loader = install_path / "src" / "ida_pro_mcp" / "ida_mcp.py"
        src_pkg = install_path / "src" / "ida_pro_mcp" / "ida_mcp"

        # Destination
        dst_loader = ida_plugin_dir / "ida_mcp.py"
        dst_pkg = ida_plugin_dir / "ida_mcp"

        # Install loader
        if src_loader.exists():
            if dst_loader.exists() or dst_loader.is_symlink():
                dst_loader.unlink()
            try:
                os.symlink(src_loader, dst_loader)
            except OSError:
                shutil.copy2(src_loader, dst_loader)
            success(f"Plugin loader: {dst_loader}")

        # Install package
        if src_pkg.exists():
            if dst_pkg.exists():
                if dst_pkg.is_symlink():
                    dst_pkg.unlink()
                else:
                    shutil.rmtree(dst_pkg)
            try:
                os.symlink(src_pkg, dst_pkg, target_is_directory=True)
            except OSError:
                shutil.copytree(src_pkg, dst_pkg)
            success(f"Plugin package: {dst_pkg}")

        plugin_installed = True
    except Exception as e:
        warning(f"Plugin install failed: {e}")

    # Step 7: Verify
    step(7, total_steps, "Verifying installation...")
    server_script = install_path / "ida_mcp_stdio.py"
    if server_script.exists():
        success(f"Active server at: {server_script}")
    else:
        error(f"Server script not found!")

    if not verify_runtime_imports(install_path):
        warning("Runtime imports failed. Re-run installer after fixing environment.")
        return False

    # Summary
    print(f"""
{C.GREEN}================================================================================{C.RESET}

   {C.GREEN}Installation Complete!{C.RESET}

   {C.WHITE}Deployed Components:{C.RESET}
      - {C.CYAN}MCP Server{C.RESET} (headless host for IDEs)
      - {C.CYAN}IDA Plugin{C.RESET} {"(installed)" if plugin_installed else "(not installed - IDA not found)"}
      - {C.CYAN}Codex Skills{C.RESET} {"(installed)" if codex_skills_result.get("ok") else "(not installed)"} [{codex_skills_result.get("mode", skills_mode)}]

   {C.WHITE}Configured MCP Clients:{C.RESET}
""")
    if configured:
        for client in configured:
            print(f"      - {client}")
    else:
        print(f"      {C.DIM}(none configured){C.RESET}")

    print(f"""
   {C.WHITE}Next Steps:{C.RESET}
      1. Restart your IDE / MCP Client.
      2. In IDA Pro, enable the plugin via Edit -> Plugins -> MCP (Ctrl+Alt+M)

{C.GREEN}================================================================================{C.RESET}
""")
    return True


# ============================================================================
# Main
# ============================================================================


def main():
    parser = argparse.ArgumentParser(description="IDA Pro MCP Installer")
    parser.add_argument(
        "--uninstall", "-u", action="store_true", help="Uninstall IDA Pro MCP"
    )
    parser.add_argument(
        "--skills-mode",
        choices=["router", "full", "none"],
        default="router",
        help="Codex skill install mode (default: router). "
        '"router" installs only ida-tool-router to reduce context overhead; '
        '"full" installs every skill directory found under .agents/skills; '
        '"none" skips skill installation.',
    )
    args = parser.parse_args()

    try:
        if args.uninstall:
            print(
                "Uninstall not fully implemented in this version. Please verify config files manually."
            )
        else:
            do_install(skills_mode=args.skills_mode)
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(1)


if __name__ == "__main__":
    main()
