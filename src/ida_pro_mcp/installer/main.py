from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import os
import shlex
import shutil
import sys
import tempfile
import traceback
import uuid
from datetime import UTC, datetime
from pathlib import Path

from . import runtime as _runtime
from .clients import (
    backup_file,
    configure_clients,
    get_config_paths,
    rollback_from_backups,
)
from .common import (
    InstallerOptions,
    InstallReport,
    atomic_write_text,
    find_ida_sig_dir,
    installer_lock,
    reject_symlink_path,
)
from .discovery import (
    STATE_FILE,
    IdaInstall,
    detect_ida_installs,
    read_install_state,
    select_ida_install,
    write_install_state,
)
from .runtime import (
    activate_idalib,
    build_stdio_config,
    choose_runtime_source,
    download_and_install_llama_server,
    download_embed_model,
    download_rerank_model,
    find_embed_model,
    find_idalib_python_dir,
    find_llama_server_bin,
    find_rerank_model,
    get_install_root,
    install_optional_packages,
    kill_ida_processes,
    resolve_r2_binary,
    setup_runtime_environment,
    stage_sigs,
)

_sha256_file = _runtime._sha256_file


class UI:
    def __init__(self) -> None:
        self.use_color = sys.stdout.isatty()
        self.c_reset = "\033[0m" if self.use_color else ""
        self.c_info = "\033[96m" if self.use_color else ""
        self.c_ok = "\033[92m" if self.use_color else ""
        self.c_warn = "\033[93m" if self.use_color else ""
        self.c_err = "\033[91m" if self.use_color else ""

    def info(self, msg: str) -> None:
        print(f"{self.c_info}[info]{self.c_reset} {msg}")

    def ok(self, msg: str) -> None:
        print(f"{self.c_ok}[ok]{self.c_reset} {msg}")

    def warn(self, msg: str) -> None:
        print(f"{self.c_warn}[warn]{self.c_reset} {msg}")

    def err(self, msg: str) -> None:
        print(f"{self.c_err}[err]{self.c_reset} {msg}")


def _absolute_path(path: Path | str) -> Path:
    """Expand a user path without resolving symlinks or requiring existence."""
    return Path(os.path.abspath(os.path.expandvars(os.path.expanduser(os.fspath(path)))))


def _is_checkout_skill_link(path: Path) -> bool:
    """Return whether a link targets a complete skill inside a Git checkout."""
    try:
        target = path.resolve(strict=True)
        if (
            not target.is_dir()
            or target.name != "ida-pro-mcp"
            or target.parent.name != "skills"
            or target.parent.parent.name != ".agents"
            or not (target / "SKILL.md").is_file()
            or not (target / "references" / "operations.md").is_file()
        ):
            return False
        checkout_root = target.parent.parent.parent
        git_marker = checkout_root / ".git"
        return git_marker.is_dir() or git_marker.is_file()
    except OSError:
        return False


def run_embedder_doctor(opts: InstallerOptions, ui: UI) -> int:
    install_root = _absolute_path(opts.install_root or get_install_root())
    try:
        reject_symlink_path(install_root, "installer root")
    except RuntimeError as exc:
        ui.err(str(exc))
        return 1
    gemini_mode = opts.embed_backend == "gemini"
    profile = "" if gemini_mode else opts.embed_profile
    embed_model = "" if gemini_mode else (opts.embed_model_path or (
        find_embed_model(install_root, profile) if opts.embed_auto else ""
    ))
    embed_server = "" if gemini_mode else (opts.embed_server_bin or (find_llama_server_bin(install_root) if opts.embed_auto else ""))

    ui.info("Embedder doctor")
    ui.info("---------------")
    ui.info(f"install_root: {install_root}")
    if gemini_mode:
        ui.info("backend: gemini-embedding-2 (cloud — credentials come from the environment)")
        ui.info("llama-server: n/a (cloud backend)")
        ui.info("model: n/a (cloud backend)")
    else:
        ui.info(f"llama-server: {'found ' + embed_server if embed_server else 'not found'}")
        ui.info(f"model: {'found ' + embed_model if embed_model else 'not found'}")

    from ida_pro_mcp.host.intelligence import core as intel_core

    # Recreate singleton under doctor-selected env so status/probe reflect this setup.
    # Include the managed root and cloud settings: otherwise a custom
    # --install-root can report against the user's default state file and a
    # --gemini-api-key/--gemini-model override has no effect on the probe.
    doctor_env_names = (
        "IDA_PRO_MCP_HOME",
        "IDA_MCP_EMBED_BACKEND",
        "IDA_MCP_EMBED_SERVER_BIN",
        "IDA_MCP_EMBED_MODEL",
        "IDA_MCP_EMBED_PROFILE",
        "IDA_MCP_GEMINI_MODEL",
        "IDA_MCP_GEMINI_DIM",
        "IDA_MCP_GEMINI_VERTEX",
        "GEMINI_API_KEY",
        "GOOGLE_CLOUD_PROJECT",
        "VERTEX_AI_LOCATION",
    )
    previous_doctor_env = {name: os.environ.get(name) for name in doctor_env_names}
    prev_instance = intel_core.BgeCodeEmbedder._instance
    try:
        for name in doctor_env_names:
            os.environ.pop(name, None)
        os.environ["IDA_PRO_MCP_HOME"] = str(install_root)
        if gemini_mode:
            os.environ["IDA_MCP_EMBED_BACKEND"] = "gemini"
        else:
            # A previous Gemini install may have backend=gemini in the state
            # file. Explicitly force this doctor invocation to inspect the
            # requested local backend instead of inheriting that state.
            os.environ["IDA_MCP_EMBED_BACKEND"] = "local"
        if embed_server:
            os.environ["IDA_MCP_EMBED_SERVER_BIN"] = embed_server
        if embed_model:
            os.environ["IDA_MCP_EMBED_MODEL"] = embed_model
        if profile:
            os.environ["IDA_MCP_EMBED_PROFILE"] = profile
        if gemini_mode:
            os.environ["IDA_MCP_GEMINI_MODEL"] = opts.gemini_model
            os.environ["IDA_MCP_GEMINI_DIM"] = str(opts.gemini_dim)
            if opts.gemini_access == "vertex":
                os.environ["IDA_MCP_GEMINI_VERTEX"] = "1"
            if opts.gemini_api_key:
                os.environ["GEMINI_API_KEY"] = opts.gemini_api_key
            if opts.gemini_vertex_project:
                os.environ["GOOGLE_CLOUD_PROJECT"] = opts.gemini_vertex_project
            if opts.gemini_vertex_location:
                os.environ["VERTEX_AI_LOCATION"] = opts.gemini_vertex_location
        intel_core.BgeCodeEmbedder._instance = None
        emb = intel_core.BgeCodeEmbedder()
        status = emb.status(probe=True, deep_hash=False)
        status["model_fingerprint"] = intel_core.model_fingerprint(embed_model, deep_hash=False)
        status["server_fingerprint"] = intel_core.server_fingerprint(embed_server, deep_hash=False)
        status["embed_test_ok"] = False
        status["embed_test_dim"] = 0
        try:
            vec = emb.embed_vector("embedder doctor quick check")
            if vec is None:
                raise RuntimeError("embedding unavailable")
            status["embed_test_ok"] = bool(vec)
            status["embed_test_dim"] = len(vec or [])
        except Exception as exc:
            status["embed_test_error"] = str(exc)

        if status.get("ready"):
            ui.ok("embedder ready")
        else:
            ui.warn("embedder not ready")
        ui.info(f"backend: {status.get('backend')}")
        ui.info(f"embed test: {'ok' if status.get('embed_test_ok') else 'failed'}")
        if gemini_mode and status.get("error"):
            ui.warn(f"gemini: {status.get('error')}")
        ui.info("fallback: unavailable (semantic features fail explicitly)")
        print(json.dumps(status, indent=2))
        # A doctor command is commonly used as a readiness gate by scripts and
        # service managers.  Reporting a healthy-looking exit code when either
        # the backend probe or the quick embedding check failed makes those
        # callers proceed with a known-broken semantic setup.
        return 0 if status.get("ready") and status.get("embed_test_ok") else 1
    finally:
        intel_core.BgeCodeEmbedder._instance = prev_instance
        for name, value in previous_doctor_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _is_interactive_terminal() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _prompt_yes_no(question: str, default: bool) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        ans = input(f"{question} {suffix}: ").strip().lower()
        if not ans:
            return default
        if ans in {"y", "yes"}:
            return True
        if ans in {"n", "no"}:
            return False
        print("Please answer yes or no.")


def _prompt_choice(question: str, choices: list[str], default: str) -> str:
    indexed = {str(i + 1): value for i, value in enumerate(choices)}
    for i, value in enumerate(choices, start=1):
        marker = " (default)" if value == default else ""
        print(f"  {i}) {value}{marker}")
    while True:
        ans = input(f"{question} [1-{len(choices)}] (default: {default}): ").strip().lower()
        if not ans:
            return default
        if ans in indexed:
            return indexed[ans]
        if ans in choices:
            return ans
        print("Invalid choice.")


def _format_install_table(installs: list[IdaInstall]) -> str:
    """Format installs as a numbered table for the user prompt."""
    lines = []
    for i, inst in enumerate(installs, start=1):
        lines.append(f"  {i}) {inst.display}")
    return "\n".join(lines)


def _prompt_text(question: str, default: str = "") -> str:
    """Ask a free-form question with an optional default value."""
    suffix = f" (default: {default})" if default else ""
    ans = input(f"{question}{suffix}: ").strip().strip("\"'")
    return ans or default


def _prompt_secret(question: str) -> str:
    """Ask for a secret without echoing it into the terminal or command log."""
    return getpass.getpass(f"{question}: ").strip()


def _prompt_model_path(profile: str) -> str:
    """Ask the user to provide a model file path interactively."""
    print(f"Enter the full path to your {profile} GGUF model file, or leave empty to skip.")
    print("Example: /home/user/Downloads/model.gguf")
    while True:
        ans = input("Model path (or press Enter to skip): ").strip().strip("\"'")
        if not ans:
            return ""
        p = Path(os.path.expandvars(os.path.expanduser(ans)))
        if p.is_file():
            return str(p)
        print(f"File not found: {ans}. Check the path and try again.")


def _prompt_ida_install(installs: list[IdaInstall], default_index: int = 0) -> IdaInstall:
    print("Detected IDA Pro installs:")
    print(_format_install_table(installs))
    default_label = f"{default_index + 1}"
    while True:
        ans = input(
            f"Select IDA install [1-{len(installs)}] (default: {default_label}): "
        ).strip()
        if not ans:
            return installs[default_index]
        if ans.isdigit():
            n = int(ans)
            if 1 <= n <= len(installs):
                return installs[n - 1]
        # Allow selecting by version string
        for _i, inst in enumerate(installs):
            if ans in (inst.version_str, inst.full_version_str):
                return inst
        print("Invalid choice. Enter a number or version string (e.g. '9.3').")


def _resolve_ida_install(opts: InstallerOptions, ui: UI) -> IdaInstall:
    """Pick an IDA install: apply CLI overrides, prompt, or auto-pick.

    Always runs (even in --yes mode) so the rest of the install knows
    which IDA to wire into the launch config.
    """
    installs = detect_ida_installs()

    # Case 1: explicit override via CLI
    if opts.ida_dir or opts.ida_version:
        chosen = select_ida_install(
            installs,
            explicit_dir=_absolute_path(opts.ida_dir) if opts.ida_dir else None,
            explicit_version=opts.ida_version or None,
        )
        ui.ok(f"Selected IDA install (override): {chosen.display}")
        return chosen

    # Case 2: zero installs — fatal
    if not installs:
        ui.err(
            "No IDA Pro install detected. Pass --ida-dir <path>, set IDADIR, "
            "or install IDA Pro/IDA Home."
        )
        raise RuntimeError("no IDA Pro install found")

    # Case 3: one install — auto-pick (no need to prompt)
    if len(installs) == 1:
        ui.ok(f"Detected IDA install: {installs[0].display}")
        return installs[0]

    # Case 4: multiple installs — decide based on interactivity
    # Read last-saved state to default the prompt
    last = read_install_state(opts.install_root or get_install_root())
    default_index = 0
    if last is not None:
        for i, inst in enumerate(installs):
            if inst.path == last.path:
                default_index = i
                break

    if opts.yes or opts.interactive is False or opts.no_ida_prompt:
        chosen = installs[default_index]
        ui.ok(
            f"Auto-selected IDA install: {chosen.display} "
            f"(use --ida-dir to override; saved selection honored)"
        )
        return chosen

    # TTY prompt (only if we have one)
    if not _is_interactive_terminal():
        chosen = installs[default_index]
        ui.ok(
            f"Non-TTY: auto-selected {chosen.display} "
            f"(saved selection honored; use --ida-dir to override)"
        )
        return chosen

    chosen = _prompt_ida_install(installs, default_index=default_index)
    ui.ok(f"Selected IDA install: {chosen.display}")
    return chosen


def _run_interactive_wizard(opts: InstallerOptions, ui: UI) -> InstallerOptions:
    if opts.yes:
        return opts

    if opts.interactive is False:
        return opts

    if opts.interactive is None and not _is_interactive_terminal():
        return opts

    ui.info("Interactive install mode")
    ui.info("Press Enter to keep recommended defaults.")

    resolved_runtime = choose_runtime_source(opts.runtime_source, opts.source_root or Path.cwd())
    runtime_default = opts.runtime_source if opts.runtime_source != "auto" else resolved_runtime
    opts.runtime_source = _prompt_choice(
        "Runtime package source",
        ["snapshot", "pypi", "local"],
        runtime_default if runtime_default in {"snapshot", "pypi", "local"} else "snapshot",
    )

    if sys.platform != "win32":
        opts.install_cli_shim = _prompt_yes_no(
            "Install CLI shell shim into ~/.bashrc?",
            default=opts.install_cli_shim,
        )

    opts.skills_mode = _prompt_choice(
        "Codex skills mode",
        ["agent", "none"],
        opts.skills_mode,
    )

    opts.install_claude_skills = _prompt_yes_no(
        "Install auto-generated skills for Claude Code / OpenCode (~/.claude/skills, ~/.config/opencode/skills)?",
        default=opts.install_claude_skills,
    )

    # These choices select an embedding *model*.  The server backend that runs
    # the model is determined separately: either the native in-process library
    # (libmcp_llama.so, built from scripts/build_native_llama.sh — fastest,
    # lowest memory) or a llama-server subprocess (HTTP, works out of the box).
    # The installer sets up the subprocess path; the native library is auto-used
    # at runtime when present.
    _backend_choices = {
        "qwen3-embedding-0.6b (local GGUF, recommended)": "qwen3-embedding-0.6b",
        "bge-code-v1 (local GGUF)": "bge-code-v1",
        "zembed-1 (local GGUF, non-commercial)": "zembed-1",
        "gemini-embedding-2 (cloud, requires API key)": "gemini",
    }
    current_backend = opts.embed_backend if opts.embed_backend in _backend_choices.values() else "qwen3-embedding-0.6b"
    default_backend_label = next(k for k, v in _backend_choices.items() if v == current_backend)
    opts.embed_backend = _backend_choices[
        _prompt_choice(
            "Embedding backend",
            list(_backend_choices.keys()),
            default_backend_label,
        )
    ]
    if opts.embed_backend == "gemini":
        opts.embed_auto = False
        _access_choices = {
            "Google AI Studio (API key)": "aistudio",
            "Vertex AI (GCP)": "vertex",
        }
        current_access = opts.gemini_access if opts.gemini_access in _access_choices.values() else "aistudio"
        default_access_label = next(k for k, v in _access_choices.items() if v == current_access)
        opts.gemini_access = _access_choices[
            _prompt_choice(
                "Gemini access",
                list(_access_choices.keys()),
                default_access_label,
            )
        ]
        if opts.gemini_access == "aistudio":
            existing_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
            if existing_key:
                ui.ok("GEMINI_API_KEY detected in your environment; the server will use it.")
                opts.gemini_api_key = ""
            else:
                ui.info("Get a free key at https://aistudio.google.com/apikey")
                key = _prompt_secret(
                    "Gemini API key (or leave empty to rely on the GEMINI_API_KEY env var)"
                )
                opts.gemini_api_key = key.strip().strip("'\"")
                if opts.gemini_api_key:
                    ui.ok(
                        "Key recorded; it will be written into the MCP client config env block."
                    )
                else:
                    ui.warn(
                        "No key entered. Set GEMINI_API_KEY in your environment before "
                        "using semantic features."
                    )
        else:
            default_project = os.environ.get("GOOGLE_CLOUD_PROJECT") or ""
            opts.gemini_vertex_project = _prompt_text(
                "Google Cloud project ID (Vertex AI)", default=default_project
            ) or default_project
            opts.gemini_vertex_location = _prompt_text(
                "Vertex AI region (location)", default="us-central1"
            ) or "us-central1"
            opts.gemini_install_auth = _prompt_yes_no(
                "Install google-auth so Application Default Credentials "
                "(GOOGLE_APPLICATION_CREDENTIALS) work with Vertex AI?",
                default=True,
            )
            ui.info(
                "Vertex AI also needs the aiplatform.googleapis.com API enabled and "
                "the Vertex AI User role (roles/aiplatform.user)."
            )
    else:
        opts.embed_profile = opts.embed_backend
        if opts.embed_profile == "zembed-1":
            ui.info("Zembed 1 is opt-in and licensed CC-BY-NC-4.0 (non-commercial).")
    auto_embed_model = find_embed_model(opts.install_root or get_install_root(), opts.embed_profile)
    auto_embed_server = find_llama_server_bin(opts.install_root or get_install_root())
    # Check for the native in-process backend (libmcp_llama.so).
    # This is built separately from scripts/build_native_llama.sh and gives
    # ~10x faster cold-start and ~2x lower RAM vs the llama-server subprocess.
    # The installer doesn't build it, but we detect and report it here.
    _native_lib = ""
    if opts.embed_backend != "gemini":
        try:
            from ida_pro_mcp.host.intelligence.native import find_native_lib
            _native_lib = find_native_lib()
        except Exception:
            pass
        if _native_lib:
            ui.ok(f"Native embedding library found: {_native_lib}")
            ui.info("Native backend (in-process libmcp_llama.so) will be used automatically — "
                    "no llama-server subprocess needed.")
        else:
            ui.info("Native embedding library (libmcp_llama.so) not found.")
            ui.info("The server will use a llama-server subprocess (HTTP). "
                    "For faster startup and lower RAM, build the native library after install: "
                    "  bash scripts/build_native_llama.sh")
    selected_embed_model = opts.embed_model_path or auto_embed_model
    if opts.embed_backend != "gemini" and selected_embed_model:
        if not opts.embed_model_path:
            ui.ok(f"Detected embedding model: {auto_embed_model}")
        # Honor an explicit --no-embed-auto: the prompt default reflects the
        # current flag so a bare Enter cannot silently flip an opt-out back on.
        opts.embed_auto = _prompt_yes_no("Enable semantic embedding model for MCP clients?", default=opts.embed_auto)
        if opts.embed_auto:
            if not opts.embed_model_path:
                opts.embed_model_path = auto_embed_model
            if auto_embed_server and not opts.embed_server_bin:
                ui.ok(f"Detected llama-server: {auto_embed_server}")
                opts.embed_server_bin = auto_embed_server
            elif not auto_embed_server and not opts.embed_server_bin:
                ui.warn("llama-server not found.")
                opts.install_llama_server = _prompt_yes_no(
                    "Download and install llama-server automatically?",
                    default=True,
                )
    elif opts.embed_backend != "gemini":
        ui.warn(f"No {opts.embed_profile} model auto-detected.")
        if opts.interactive:
            if opts.embed_profile == "zembed-1" and _prompt_yes_no(
                "Download the managed Zembed 1 Q4_K_M model?", default=False
            ):
                if _prompt_yes_no("I accept the CC-BY-NC-4.0 model license", default=False):
                    opts.download_embed_model = True
                    opts.accept_model_license = True
                    opts.embed_auto = True
                    manual = ""
                else:
                    ui.warn("Zembed download skipped because its license was not accepted.")
                    manual = _prompt_model_path(opts.embed_profile)
            else:
                manual = _prompt_model_path(opts.embed_profile)
            if manual:
                ui.ok(f"Using model: {manual}")
                opts.embed_model_path = manual
                opts.embed_auto = True
            elif not opts.download_embed_model:
                opts.embed_auto = False
                ui.warn("Semantic embedding features stay disabled by default.")
        else:
            opts.embed_auto = False

    # --- Reranker model (second model required for semantic search quality) ---
    # Gemini supplies the embedding model remotely, but reranking is still a
    # separate local cross-encoder.  Keep this section independent of the
    # embedding backend so cloud users do not silently lose reranking.
    if opts.embed_backend == "gemini" or opts.embed_auto or opts.embed_model_path:
        ui.info(
            "Semantic search uses two models: an embedding model (already configured above) "
            "and a reranker (cross-encoder) that re-scores results for precision."
        )
        _rerank_choices = {
            "qwen3-reranker-0.6b (recommended, ~0.6B)": "qwen3-reranker-0.6b",
            "qwen3-reranker-4b (higher quality, larger)": "qwen3-reranker-4b",
            "bge-reranker-v2-gemma": "bge-reranker-v2-gemma",
            "bge-reranker-v2-m3": "bge-reranker-v2-m3",
        }
        current_rerank = opts.rerank_profile if opts.rerank_profile in _rerank_choices.values() else "qwen3-reranker-0.6b"
        default_rerank_label = next(k for k, v in _rerank_choices.items() if v == current_rerank)
        opts.rerank_profile = _rerank_choices[
            _prompt_choice(
                "Reranker model",
                list(_rerank_choices.keys()),
                default_rerank_label,
            )
        ]
        auto_rerank_model = find_rerank_model(opts.install_root or get_install_root(), opts.rerank_profile)
        selected_rerank_model = opts.rerank_model_path or auto_rerank_model
        if selected_rerank_model:
            if not opts.rerank_model_path:
                ui.ok(f"Detected reranker: {auto_rerank_model}")
            if _prompt_yes_no("Enable reranker for improved semantic search precision?", default=True):
                if not opts.rerank_model_path:
                    opts.rerank_model_path = auto_rerank_model
            else:
                # An explicit 'No' must stick: remember the opt-out and don't
                # let the default profile leak into state / client env.
                opts.rerank_disabled = True
                opts.rerank_model_path = ""
        else:
            ui.warn(f"No {opts.rerank_profile} reranker model found.")
            if _prompt_yes_no(
                f"Download managed {opts.rerank_profile} reranker model (~300 MB)?",
                default=True,
            ):
                from ida_pro_mcp.host.intelligence.rerank_profiles import get_rerank_model_profile

                selected_rerank = get_rerank_model_profile(opts.rerank_profile)
                if selected_rerank is not None and selected_rerank.opt_in:
                    if _prompt_yes_no(
                        f"I accept the {selected_rerank.license} license for {selected_rerank.display_name}",
                        default=False,
                    ):
                        opts.download_rerank_model = True
                        opts.accept_model_license = True
                    else:
                        ui.warn("Reranker download skipped because its license was not accepted.")
                        opts.rerank_disabled = True
                else:
                    opts.download_rerank_model = True
            else:
                opts.rerank_disabled = True
        ui.info(
            "Rerank tuning knobs (optional env vars): IDA_MCP_RERANK_POOL "
            "(recall pool, default 8), IDA_MCP_RERANK_DOC_BUDGET_CHARS "
            "(per-document budget, default 800), IDA_MCP_RERANK_CTX "
            "(per-pair context, default 1024)."
        )

    # Session runtime backend. idat is the default (crash-isolated
    # per-session idat processes); idalib runs the IDA kernel in-process
    # (python -m ida_pro_mcp.idalib_worker) — faster session start and undo
    # history, but one crash takes the session down and it needs the idapro
    # whl + activation on the chosen install.
    _runtime_choices = {
        "idat (per-session processes, recommended)": "idat",
        "idalib (in-process kernel, experimental)": "idalib",
    }
    current_runtime = opts.ida_runtime if opts.ida_runtime in _runtime_choices.values() else "idat"
    default_runtime_label = next(k for k, v in _runtime_choices.items() if v == current_runtime)
    opts.ida_runtime = _runtime_choices[
        _prompt_choice(
            "IDA session runtime backend",
            list(_runtime_choices.keys()),
            default_runtime_label,
        )
    ]
    if opts.ida_runtime == "idalib":
        chosen_install = getattr(opts, "_ida_install", None)
        ida_dir = str(chosen_install.path) if chosen_install is not None else ""
        idalib_py = find_idalib_python_dir(ida_dir)
        if not idalib_py:
            ui.warn(
                "idalib backend selected but no idapro package found under "
                f"{ida_dir or '<IDA install>'}/idalib/python. The runtime flag "
                "will be written anyway; sessions will fail until the whl is "
                "present and activated."
            )
        else:
            ui.ok(f"idapro package found: {idalib_py}")
            ui.info(
                "idalib activation will run after the installation phases complete, "
                "because it changes IDA's global active runtime."
            )

    opts.rollback_on_fail = _prompt_yes_no(
        "Rollback backed-up config files on failure?",
        default=opts.rollback_on_fail,
    )
    corpus_env_enabled = os.environ.get("IDA_MCP_BRON_CORPUS_VERIFY", "").lower() in {
        "1", "true", "yes", "on"
    }
    opts.with_bron_corpus = _prompt_yes_no(
        "Download the optional threat corpus and crypto signatures?",
        default=opts.with_bron_corpus or opts.verify_bron_corpus or corpus_env_enabled,
    )
    ui.info(
        "Policy gates are ON by default — they require evidence cards and "
        "acknowledgements for write-surface tools. Disable them only if you "
        "trust every MCP client and LLM with full edit access to your IDB."
    )
    opts.disable_policy = _prompt_yes_no(
        "Disable ALL policy gates (strict-blackboard, phase choreography, ack requirements)?",
        default=opts.disable_policy,
    )
    if opts.disable_policy:
        ui.warn("Policy gates DISABLED — all tools run without restrictions.")

    if not _prompt_yes_no("Proceed with installation now?", default=True):
        raise RuntimeError("Installation cancelled by user.")
    return opts


def _activate_idalib_after_install(
    opts: InstallerOptions,
    chosen_install: IdaInstall | None,
    report: InstallReport,
    ui: UI,
) -> None:
    """Activate idalib only after all selected install phases have succeeded."""
    if opts.ida_runtime != "idalib":
        return
    if opts.dry_run:
        report.add_step("idalib", "dry-run", "would activate after installation")
        return
    if chosen_install is None:
        raise RuntimeError("idalib selected but no IDA install was resolved")

    ida_dir = str(chosen_install.path)
    if not find_idalib_python_dir(ida_dir):
        raise RuntimeError(
            f"idalib selected but no idapro package was found under {ida_dir}/idalib/python"
        )

    ok, detail = activate_idalib(ida_dir)
    if ok:
        report.add_step("idalib", "ok", f"activated for {ida_dir}")
        ui.ok(
            f"idalib activated for {ida_dir} — "
            "IDA_MCP_RUNTIME=idalib is ready for MCP clients."
        )
    else:
        raise RuntimeError(f"idalib activation failed ({detail})")


def install_bashrc_cli(install_root: Path, dry_run: bool, report: InstallReport) -> bool:
    if sys.platform == "win32":
        report.add_warning("bashrc shim skipped on Windows")
        return False
    bashrc = Path.home() / ".bashrc"
    reject_symlink_path(bashrc, "bashrc path")
    block_start = "# >>> ida-pro-mcp >>>"
    block_end = "# <<< ida-pro-mcp <<<"
    venv_bin = install_root / ".venv" / "bin"
    block = "\n".join(
        [
            block_start,
            f"export IDA_PRO_MCP_HOME={shlex.quote(str(install_root))}",
            'case ":$PATH:" in',
            '  *":$IDA_PRO_MCP_HOME/.venv/bin:"*) ;;',
            '  *) export PATH="$IDA_PRO_MCP_HOME/.venv/bin:$PATH" ;;',
            'esac',
            f"export IDA_MCP_CLI={shlex.quote(str(venv_bin / 'ida-pro-mcp-cli'))}",
            block_end,
            "",
        ]
    )
    if bashrc.exists() and not bashrc.is_file():
        raise RuntimeError(f"Refusing non-regular bashrc path: {bashrc}")
    existing = bashrc.read_text(encoding="utf-8") if bashrc.exists() else ""
    start = existing.find(block_start)
    end_marker = existing.find(block_end, start + len(block_start)) if start >= 0 else -1
    if start >= 0 and end_marker >= 0:
        end = end_marker + len(block_end)
        newline = existing.find("\n", end)
        updated = existing[:start] + block + ("" if newline == -1 else existing[newline + 1 :])
    else:
        updated = existing.rstrip("\n") + ("\n" if existing.strip() else "") + block
    if not dry_run:
        bashrc.parent.mkdir(parents=True, exist_ok=True)
        backup_file(bashrc, report, dry_run=False)
        atomic_write_text(bashrc, updated)
        report.add_modified(bashrc)
    return True


def _replace_with_symlink_or_copy(src: Path, dst: Path) -> str:
    if not src.exists() and not src.is_symlink():
        raise FileNotFoundError(src)
    reject_symlink_path(dst, "skill destination")
    dst.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(tempfile.mkdtemp(prefix=f".{dst.name}.staging-", dir=str(dst.parent)))
    staged = staging_dir / dst.name
    try:
        try:
            os.rmdir(staging_dir)
            os.symlink(src, staged, target_is_directory=src.is_dir())
            mode = "linked"
        except OSError:
            # Recreate the staging directory if symlinks are unavailable
            # (notably Windows without developer mode).
            staging_dir.mkdir(parents=True, exist_ok=True)
            if src.is_dir():
                shutil.copytree(src, staged, ignore_dangling_symlinks=True)
            else:
                shutil.copy2(src, staged)
            mode = "copied"

        backup: Path | None = None
        if dst.exists() or dst.is_symlink():
            backup = dst.parent / f".{dst.name}.backup-{os.getpid()}-{uuid.uuid4().hex}"
            os.replace(dst, backup)
        try:
            os.replace(staged, dst)
        except BaseException:
            if backup is not None and not (dst.exists() or dst.is_symlink()):
                os.replace(backup, dst)
            raise
        if backup is not None:
            if backup.is_dir() and not backup.is_symlink():
                shutil.rmtree(backup)
            else:
                backup.unlink()
        return mode
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


def _install_claude_opencode_skills(report: InstallReport, dry_run: bool, ui: UI) -> bool:
    """Auto-generate and install skills for Claude Code and OpenCode."""
    try:
        from .skills import default_skill_dirs, install_skills
    except ImportError as exc:
        message = f"claude-skills import failed: {exc}"
        report.add_warning(message)
        report.add_step("claude-skills", "warn", message)
        ui.warn(message)
        return False
    try:
        target_dirs = default_skill_dirs()
        written = install_skills(target_dirs, dry_run=dry_run)
        count = sum(len(paths) for paths in written.values())
        if not dry_run:
            for paths in written.values():
                for p in paths:
                    report.add_modified(p)
        action = "would install" if dry_run else "installed"
        report.add_step(
            "claude-skills", "ok" if not dry_run else "dry-run",
            f"{action} {len(written)} skills ({count} files) to {len(target_dirs)} dirs",
        )
        ui.ok(f"Claude/OpenCode skills: {action} {len(written)} skills")
        return True
    except Exception as exc:
        message = f"claude-skills install failed: {exc}"
        report.add_warning(message)
        report.add_step("claude-skills", "warn", message)
        ui.warn(message)
        return False


def install_codex_skills(source_root: Path, mode: str, report: InstallReport, dry_run: bool) -> None:
    if mode == "none":
        report.add_step("skills", "skipped", "skills mode set to none")
        return
    source_root_skills = source_root / ".agents" / "skills"
    agent_skill = source_root_skills / "ida-pro-mcp"
    if not (agent_skill / "SKILL.md").exists():
        # PyPI wheels intentionally contain the runtime package, not the
        # repository's .agents tree.  Generate the same skill content from the
        # operation registry so a packaged install is still useful to Codex.
        from .skills import install_skills

        codex_home = os.environ.get("CODEX_HOME", "").strip() or str(Path.home() / ".codex")
        codex_skills = _absolute_path(codex_home) / "skills"
        written = install_skills([codex_skills], dry_run=dry_run)
        count = sum(len(paths) for paths in written.values())
        if not dry_run:
            for paths in written.values():
                for path in paths:
                    report.add_modified(path)
        action = "would generate" if dry_run else "generated"
        report.add_step(
            "skills",
            "dry-run" if dry_run else "ok",
            f"{action} {count} files to {codex_skills / 'ida-pro-mcp'}",
        )
        return
    selected = [agent_skill]
    codex_home = os.environ.get("CODEX_HOME", "").strip() or str(Path.home() / ".codex")
    codex_skills = _absolute_path(codex_home) / "skills"
    # A checkout-backed Codex skill is a supported development layout:
    # ~/.codex/skills/ida-pro-mcp -> <checkout>/.agents/skills/ida-pro-mcp.
    # It is safe to retain only when the link resolves to this exact source
    # skill.  Any other destination symlink remains rejected so an installer
    # run cannot write through a user-controlled redirect.
    reject_symlink_path(codex_skills, "skill installation root")
    destination = codex_skills / selected[0].name
    if destination.is_symlink():
        try:
            if (
                destination.resolve(strict=True) == agent_skill.resolve(strict=True)
                or _is_checkout_skill_link(destination)
            ):
                report.add_step(
                    "skills",
                    "dry-run" if dry_run else "ok",
                    f"using existing checkout-backed skill link at {destination}",
                )
                return
        except OSError:
            pass
        reject_symlink_path(destination / "SKILL.md", "skill installation path")
    else:
        reject_symlink_path(destination / "SKILL.md", "skill installation path")
    if dry_run:
        report.add_step("skills", "dry-run", f"would install {len(selected)} entries to {codex_skills}")
        return
    codex_skills.mkdir(parents=True, exist_ok=True)
    for src in selected:
        dst = codex_skills / src.name
        if dst.is_dir() and not dst.is_symlink():
            # Preserve user-added references/files in an existing skill
            # directory; only refresh the two files managed by this project.
            from .skills import install_skills

            written = install_skills([codex_skills], dry_run=False)
            for paths in written.values():
                for path in paths:
                    report.add_modified(path)
        else:
            _replace_with_symlink_or_copy(src, dst)
            report.add_modified(dst)
    report.add_step(
        "skills",
        "dry-run" if dry_run else "ok",
        f"would install {len(selected)} skills to {codex_skills}" if dry_run
        else f"installed {len(selected)} skills",
    )


def parse_args(argv: list[str] | None = None) -> InstallerOptions:
    parser = argparse.ArgumentParser(description="IDA Pro MCP installer")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print planned actions without changing managed files (writes an install report)",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--yes", "--auto", dest="yes", action="store_true", help="non-interactive mode (auto install)")
    mode_group.add_argument("--interactive", action="store_true", help="force interactive wizard mode")
    mode_group.add_argument("--no-interactive", action="store_true", help="disable interactive wizard mode")
    parser.add_argument("--uninstall", action="store_true", help="uninstall IDA Pro MCP plugins, client configurations, and shims")
    parser.add_argument("--kill-ida", action="store_true", help="terminate running ida/idat processes before install")
    parser.add_argument(
        "--ida-binary-path",
        default="",
        help="when used with --kill-ida, only terminate processes running this binary path "
        "(default: scope to the chosen IDA install's idat binary)",
    )
    parser.add_argument("--install-cli-shim", action="store_true", help="opt-in bashrc PATH shim installation")
    rollback_group = parser.add_mutually_exclusive_group()
    rollback_group.add_argument(
        "--rollback-on-fail",
        dest="rollback_on_fail",
        action="store_true",
        default=True,
        help="restore backed up config files if install fails (default)",
    )
    rollback_group.add_argument(
        "--no-rollback-on-fail",
        dest="rollback_on_fail",
        action="store_false",
        help="keep partial client changes when a later install phase fails",
    )
    parser.add_argument(
        "--runtime-source",
        choices=["auto", "local", "snapshot", "pypi"],
        default="auto",
        help="runtime package source: snapshot (default: frozen copy of the "
        "checkout), pypi, or local (dev mode: live source tree — not recommended)",
    )
    parser.add_argument("--embed-model", default="", help="explicit path to an embedding GGUF model")
    parser.add_argument(
        "--embed-profile", choices=["qwen3-embedding-0.6b", "bge-code-v1", "zembed-1"], default="qwen3-embedding-0.6b",
        help="embedding prompt/model profile (default: qwen3-embedding-0.6b)",
    )
    parser.add_argument(
        "--embed-backend", choices=["qwen3-embedding-0.6b", "bge-code-v1", "zembed-1", "gemini"], default="qwen3-embedding-0.6b",
        help="embedding backend: a local GGUF profile or the opt-in cloud gemini-embedding-2",
    )
    parser.add_argument(
        "--gemini-access", choices=["aistudio", "vertex"], default="aistudio",
        help="Gemini credential route: Google AI Studio API key or Vertex AI (GCP)",
    )
    parser.add_argument("--gemini-api-key", default="", help="Gemini API key (Google AI Studio)")
    parser.add_argument("--gemini-vertex-project", default="", help="Google Cloud project ID for Vertex AI")
    parser.add_argument("--gemini-vertex-location", default="us-central1", help="Vertex AI region/location")
    parser.add_argument("--gemini-model", default="gemini-embedding-2", help="Gemini embedding model name")
    parser.add_argument("--gemini-dim", type=int, default=768, help="Gemini embedding output dimensionality")
    parser.add_argument(
        "--gemini-install-auth", action="store_true",
        help="install google-auth into the runtime venv for Vertex AI ADC",
    )
    parser.add_argument(
        "--download-embed-model", action="store_true",
        help="download the selected managed embedding model",
    )
    parser.add_argument(
        "--rerank-model", default="", help="explicit path to a cross-encoder rerank GGUF model"
    )
    parser.add_argument(
        "--rerank-profile",
        choices=["qwen3-reranker-0.6b", "qwen3-reranker-4b", "bge-reranker-v2-gemma", "bge-reranker-v2-m3"],
        default="qwen3-reranker-0.6b",
        help="cross-encoder rerank profile (default: qwen3-reranker-0.6b)",
    )
    parser.add_argument(
        "--download-rerank-model", action="store_true",
        help="download the selected managed rerank model",
    )
    parser.add_argument(
        "--accept-model-license", action="store_true",
        help="confirm acceptance of the selected model's license when required",
    )
    parser.add_argument("--embed-server-bin", default="", help="explicit path to llama-server binary")
    parser.add_argument("--embedder-doctor", action="store_true", help="diagnose local embedder/model/server setup")
    parser.add_argument("--setup-embedder", action="store_true", help="convenience mode to configure embedder with client setup")
    parser.add_argument(
        "--install-llama-server",
        action="store_true",
        help="download and install llama-server automatically when embed model is enabled/found",
    )
    parser.add_argument(
        "--allow-unverified-downloads",
        action="store_true",
        help="allow llama-server downloads when GitHub omits its SHA-256 digest (unsafe; prefer verified assets)",
    )
    parser.add_argument(
        "--with-corpus",
        action="store_true",
        help="download and build the optional threat corpus and crypto signatures",
    )
    parser.add_argument(
        "--verify-corpus",
        action="store_true",
        help="require IDA_MCP_BRON_CORPUS_SHA256_* hashes for every threat-corpus source",
    )
    parser.add_argument("--no-embed-auto", action="store_true", help="disable automatic embedder/server discovery")
    parser.add_argument("--skills-mode", choices=["agent", "none"], default="agent", help="Codex skill installation mode")
    parser.add_argument("--install-skills", action="store_true", default=True, help="install auto-generated skills for Claude Code / OpenCode (default: on)")
    parser.add_argument("--no-install-skills", action="store_true", help="skip Claude Code / OpenCode skill installation")
    parser.add_argument(
        "--with-r2",
        action="store_true",
        help="locate rz (Rizin) / r2 (radare2) on PATH, record the resolved binary as "
        "IDA_MCP_R2_BIN in the generated MCP client config, and print its version. "
        "Does NOT download a pinned engine release in this phase.",
    )
    parser.add_argument(
        "--sigs",
        default="",
        metavar="DIR",
        help="stage a FLIRT signature pack (*.sig / *.sig.gz) into <IDADIR>/sig so "
        "ida_list_sigs can surface it (e.g. a RISC-V .sig pack). DIR may be a single "
        ".sig/.sig.gz file or a directory (walked recursively, subpaths preserved).",
    )

    parser.add_argument("--only", action="append", choices=["runtime", "clients", "skills", "shell", "r2", "sigs"], default=[], help="run only selected install phases")
    parser.add_argument("--install-root", default="", help="override install root directory")
    parser.add_argument(
        "--ida-runtime",
        choices=["idat", "idalib"],
        default=None,
        help="session runtime backend written to the client config env "
        "(default: idat). idalib runs the IDA kernel in-process; requires a "
        "9.3+ install with the idapro whl and activation.",
    )
    parser.add_argument(
        "--ida-dir",
        default="",
        help="explicit path to an IDA install directory (e.g. /opt/ida-pro-9.3)",
    )
    parser.add_argument(
        "--ida-version",
        default="",
        help="explicit IDA version constraint (e.g. '9.3', '9.2', '9.3.260421')",
    )
    parser.add_argument(
        "--no-ida-prompt",
        action="store_true",
        help="do not prompt for IDA install selection; pick highest-version automatically",
    )
    parser.add_argument(
        "--disable-policy",
        action="store_true",
        help="disable ALL policy gates (strict-blackboard, phase choreography, ack requirements); "
        "sets IDA_MCP_POLICY_MODE=off in the spawned server",
    )
    args = parser.parse_args(argv)
    opts = InstallerOptions(
        dry_run=args.dry_run,
        yes=args.yes,
        uninstall=args.uninstall,
        kill_ida=args.kill_ida,
        install_cli_shim=args.install_cli_shim,
        rollback_on_fail=args.rollback_on_fail,
        runtime_source=args.runtime_source,
        skills_mode=args.skills_mode,
        install_claude_skills=not args.no_install_skills,
        interactive=True if args.interactive else (False if args.no_interactive else None),
        embed_auto=not args.no_embed_auto,
        embed_profile=args.embed_profile,
        embed_backend=args.embed_backend,
        gemini_access=args.gemini_access,
        gemini_api_key=args.gemini_api_key,
        gemini_vertex_project=args.gemini_vertex_project,
        gemini_vertex_location=args.gemini_vertex_location,
        gemini_install_auth=args.gemini_install_auth,
        gemini_dim=args.gemini_dim,
        gemini_model=args.gemini_model,
        embed_model_path=args.embed_model,
        embed_server_bin=args.embed_server_bin,
        install_llama_server=args.install_llama_server,
        download_embed_model=args.download_embed_model,
        accept_model_license=args.accept_model_license,
        embedder_doctor=args.embedder_doctor,
        setup_embedder=args.setup_embedder,
        rerank_profile=args.rerank_profile,
        rerank_model_path=args.rerank_model,
        download_rerank_model=args.download_rerank_model,

        only=set(args.only),
        disable_policy=args.disable_policy,
        with_r2=args.with_r2,
        with_corpus=args.with_corpus,
        sigs_dir=args.sigs,
        ida_runtime=args.ida_runtime or "idat",
        ida_binary_path=args.ida_binary_path,
        allow_unverified_downloads=args.allow_unverified_downloads,
        with_bron_corpus=args.with_corpus or args.verify_corpus,
        verify_bron_corpus=args.verify_corpus,
    )
    if opts.setup_embedder:
        opts.embed_auto = True
        opts.install_llama_server = True
        if not opts.only:
            opts.only = {"clients"}
    opts.install_root = Path(args.install_root).expanduser() if args.install_root else get_install_root()
    # Prefer a checkout root that contains client_configs.json; otherwise use
    # the installed package directory so pip installs still find bundled assets.
    pkg_dir = Path(__file__).resolve().parents[1]
    repo_candidate = Path(__file__).resolve().parents[3]
    if (repo_candidate / "client_configs.json").exists():
        opts.source_root = repo_candidate
    elif (Path(__file__).resolve().parent / "client_configs.json").exists():
        opts.source_root = Path(__file__).resolve().parent
    else:
        opts.source_root = pkg_dir
    opts.ida_dir = args.ida_dir
    opts.ida_version = args.ida_version
    opts.no_ida_prompt = args.no_ida_prompt
    return opts


def _phase_enabled(opts: InstallerOptions, name: str) -> bool:
    return not opts.only or name in opts.only


def _report_client_configuration(
    source_root: Path,
    configured: list[str],
    report: InstallReport,
    ui: UI,
    *,
    dry_run: bool = False,
) -> None:
    """Report partial client setup instead of presenting it as success."""
    expected = len(get_config_paths(source_root))
    actual = len(configured)
    if actual == expected:
        action = "would configure" if dry_run else "configured"
        status = "dry-run" if dry_run else "ok"
        report.add_step("clients", status, f"{action} {actual} clients")
        if dry_run:
            ui.info(f"Would configure {actual} clients")
        else:
            ui.ok(f"Configured {actual} clients")
        return

    action = "would configure" if dry_run else "configured"
    detail = f"{action} {actual}/{expected} clients"
    report.add_warning(
        f"Client configuration was incomplete: {detail}. "
        "Review installer warnings and fix the affected client config files."
    )
    report.add_step("clients", "warn", detail)
    ui.warn(f"Client configuration incomplete: {detail}")
    client_failures = report.metadata.get("client_update_failures")
    if expected and not actual and client_failures:
        message = (
            "Client configuration failed: no supported client was configured. "
            "Review installer warnings and fix the affected client config files."
        )
        report.add_error(message)
        raise RuntimeError(message)


def _write_install_error_log(log_path: Path, traceback_text: str) -> None:
    """Append a traceback without opening an unexpected filesystem object."""
    reject_symlink_path(log_path, "installer error log path")
    if log_path.exists() and not log_path.is_file():
        raise RuntimeError(f"Refusing non-regular installer error log path: {log_path}")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).isoformat()
    with open(log_path, "a", encoding="utf-8") as logf:
        logf.write(f"\n=== {timestamp} run_install crashed ===\n{traceback_text}\n")


def _normalise_runtime_path(
    value: str,
    label: str,
    *,
    executable: bool = False,
    allow_missing: bool = False,
) -> str:
    """Return an absolute runtime path after checking its usable type.

    Client configuration is consumed later from a different working
    directory, so relative model and binary paths are not safe to persist.
    Explicit paths are always checked; dry-run-only paths returned by planned
    downloads may be absent until the real install runs.
    """
    candidate = Path(os.path.expandvars(os.path.expanduser(value)))
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as exc:
        raise RuntimeError(f"Could not resolve {label} path {value!r}: {exc}") from exc
    if allow_missing:
        return str(resolved)
    if not resolved.is_file():
        raise RuntimeError(f"{label} is not an existing regular file: {value}")
    if executable:
        if sys.platform == "win32":
            if resolved.suffix.lower() not in {".exe", ".bat", ".cmd"}:
                raise RuntimeError(f"{label} does not have an executable Windows suffix: {value}")
        elif not os.access(resolved, os.X_OK):
            raise RuntimeError(f"{label} is not executable: {value}")
    return str(resolved)


def _resolve_reranker_for_install(
    opts: InstallerOptions,
    install_root: Path,
    report: InstallReport,
    ui: UI,
    *,
    semantic_enabled: bool,
) -> str:
    """Resolve the selected local reranker and make absence explicit.

    Embedding and reranking are separate capabilities, including for Gemini's
    cloud embedding backend.  Non-interactive installs must perform the same
    profile-aware discovery as the wizard; otherwise the host can later find
    an arbitrary default model or silently run without precision reranking.
    """
    if opts.rerank_disabled:
        return ""
    if not semantic_enabled and not opts.rerank_model_path and not opts.download_rerank_model:
        return ""

    rerank_model = opts.rerank_model_path
    if not rerank_model:
        rerank_model = find_rerank_model(install_root, opts.rerank_profile)

    if opts.download_rerank_model and not rerank_model:
        from ida_pro_mcp.host.intelligence.rerank_profiles import get_rerank_model_profile

        selected_rerank = get_rerank_model_profile(opts.rerank_profile)
        if selected_rerank is None:
            raise RuntimeError(f"Unknown rerank profile: {opts.rerank_profile}")
        if selected_rerank.opt_in and not opts.accept_model_license:
            raise RuntimeError(
                f"{selected_rerank.display_name} is {selected_rerank.license}; "
                "rerun with --accept-model-license to download it"
            )
        if opts.dry_run:
            ui.info(f"Would download {selected_rerank.display_name} rerank model")
            report.add_step("rerank_model", "dry-run", selected_rerank.key)
        else:
            ui.info(f"Downloading {selected_rerank.display_name} rerank model")
            rerank_model = download_rerank_model(install_root, selected_rerank.key)

    if rerank_model:
        ui.ok("Rerank model configured for MCP clients")
        report.metadata["rerank_model"] = rerank_model
    elif not opts.rerank_disabled and not opts.dry_run:
        # Do not let host-side fallback discovery unexpectedly activate a
        # different model after this installer explicitly found none.
        opts.rerank_disabled = True
        ui.warn(
            f"No {opts.rerank_profile} reranker model found; reranking is disabled "
            "explicitly. Install the selected cross-encoder and rerun the installer "
            "to enable higher-precision semantic search."
        )
        report.add_step("rerank_model", "warn", "not found; explicitly disabled")
    return rerank_model


def _warn_ida_python_compat(chosen_install, report, ui) -> None:
    """Surface IDA 9.4's IDAPython uv/conda/homebrew interpreter warning.

    IDA 9.4's IDAPython detects uv/anaconda/homebrew-managed Pythons and
    warns about libpython/venv mismatch. The MCP server venv works fine
    regardless of the interpreter it is built from, but if IDAPython is
    pointed at the same interpreter (idapyswitch), IDA itself will warn.
    Mirror that awareness in the wizard instead of letting it surface as
    an unexplained IDA warning later. No-op on IDA < 9.4.
    """
    try:
        from .runtime import python_environment_kind
    except ImportError:
        return
    try:
        major = int(chosen_install.version[0])
        minor = int(chosen_install.version[1])
    except (TypeError, IndexError, ValueError):
        return
    if (major, minor) < (9, 4):
        return
    kind = python_environment_kind()
    if kind == "system":
        return
    report.metadata["python_kind"] = kind
    ui.warn(
        f"Running the installer on a {kind}-managed Python interpreter. "
        "IDA 9.4 warns when IDAPython uses such interpreters (libpython/"
        "venv mismatch). The MCP server runtime venv is unaffected, but if "
        "IDA's own Python check complains, point idapyswitch at a standard "
        "python.org or system Python."
    )


def run_install(opts: InstallerOptions, ui: UI) -> int:
    """Run one installer transaction under the per-root process lock."""
    install_root = opts.install_root or get_install_root()
    if opts.dry_run:
        # A dry run is a read-only plan except for the deliberate report file;
        # acquiring the normal lock would create .install.lock and the root
        # directory before any work has been performed.
        return _run_install_unlocked(opts, ui)
    try:
        with installer_lock(install_root):
            return _run_install_unlocked(opts, ui)
    except (OSError, RuntimeError) as exc:
        ui.err(f"Could not start installer: {exc}")
        return 1


def _run_uninstall(opts: InstallerOptions, ui: UI, report: InstallReport) -> int:
    source_root = opts.source_root or Path.cwd()
    install_root = opts.install_root or get_install_root()
    ui.info(f"Uninstalling IDA Pro MCP from {install_root}...")

    # 1. Prune from coding agent client configs
    from .clients import remove_server_entry_from_clients
    removed_clients = remove_server_entry_from_clients(source_root, report, opts.dry_run)
    if removed_clients:
        ui.ok(f"Removed server configuration from: {', '.join(removed_clients)}")
        report.add_step("clients", "uninstalled", f"removed from {len(removed_clients)} clients")

    # 2. Remove skills
    from .skills import SKILL_NAME, default_skill_dirs
    for sdir in default_skill_dirs():
        target_skill = sdir / SKILL_NAME
        if target_skill.exists():
            if not opts.dry_run:
                shutil.rmtree(target_skill, ignore_errors=True)
                report.add_modified(target_skill)
            ui.ok(f"Removed skill directory: {target_skill}")

    # 3. Remove IDA plugin if IDA installs found
    from .discovery import detect_ida_installs
    try:
        installs = detect_ida_installs()
        for inst in installs:
            plugin_dir = Path(inst.ida_dir) / "plugins"
            for plugin_file in [plugin_dir / "server_script.py", plugin_dir / "ida_pro_mcp_plugin.py"]:
                if plugin_file.is_file():
                    if not opts.dry_run:
                        plugin_file.unlink(missing_ok=True)
                        report.add_modified(plugin_file)
                    ui.ok(f"Removed IDA plugin: {plugin_file}")
    except Exception:
        pass

    # 4. Remove launcher shims
    bin_dir = install_root / "bin"
    if bin_dir.exists():
        if not opts.dry_run:
            shutil.rmtree(bin_dir, ignore_errors=True)
        ui.ok(f"Removed launcher shims in {bin_dir}")

    report.finalize(success=True)
    report_file = install_root / "uninstall-report.json"
    if not opts.dry_run:
        with contextlib.suppress(Exception):
            report.write(report_file)
    ui.ok("IDA Pro MCP successfully uninstalled.")
    return 0


def _run_install_unlocked(opts: InstallerOptions, ui: UI) -> int:
    report = InstallReport()
    install_root = _absolute_path(opts.install_root or get_install_root())
    source_root = _absolute_path(opts.source_root or Path.cwd())
    opts.install_root = install_root
    opts.source_root = source_root
    report.metadata.update({"install_root": str(install_root), "source_root": str(source_root)})

    if opts.uninstall:
        return _run_uninstall(opts, ui, report)

    try:
        reject_symlink_path(install_root, "installer root")
        # Resolve IDA only when a later phase actually needs it or the user
        # explicitly asked for an IDA override. Client configuration and
        # signature staging both need a concrete install, but runtime/skills/
        # shell-only installs should not fail just because IDA is absent on
        # this machine.
        chosen_install = None
        if (
            _phase_enabled(opts, "clients")
            or _phase_enabled(opts, "sigs")
            or opts.sigs_dir
            or opts.ida_dir
            or opts.ida_version
            or (opts.ida_runtime == "idalib" and not opts.dry_run)
        ):
            try:
                chosen_install = _resolve_ida_install(opts, ui)
            except RuntimeError as exc:
                if (
                    opts.ida_dir
                    or opts.ida_version
                    or opts.sigs_dir
                    or (opts.ida_runtime == "idalib" and not opts.dry_run)
                ):
                    raise
                msg = str(exc)
                if "no IDA Pro install found" not in msg and "No IDA Pro install detected" not in msg:
                    raise
                ui.warn("No IDA Pro install detected; continuing without IDADIR")
        if chosen_install is not None:
            opts._ida_install = chosen_install  # type: ignore[attr-defined]
            report.metadata["ida_install"] = chosen_install.to_dict()
            report.metadata["ida_version"] = chosen_install.full_version_str
            _warn_ida_python_compat(chosen_install, report, ui)

        opts = _run_interactive_wizard(opts, ui)
        if opts.ida_runtime == "idalib" and not _phase_enabled(opts, "clients"):
            raise RuntimeError(
                "--ida-runtime idalib requires the clients phase so its activation "
                "and runtime setting are applied"
            )
        if opts.with_r2 and not _phase_enabled(opts, "clients"):
            raise RuntimeError(
                "--with-r2 requires the clients phase so IDA_MCP_R2_BIN can be recorded"
            )
        # Validate user-supplied paths before any client config is touched.
        # The wizard already validates model paths, but CLI/API callers do not
        # go through those prompts.  A disabled reranker is intentionally not
        # resolved or validated because it must stay inert even if a stale
        # model path was supplied alongside the opt-out.
        if opts.embed_backend != "gemini" and opts.embed_model_path:
            opts.embed_model_path = _normalise_runtime_path(
                opts.embed_model_path, "Embedding model"
            )
        if opts.embed_server_bin:
            opts.embed_server_bin = _normalise_runtime_path(
                opts.embed_server_bin, "llama-server binary", executable=True
            )
        if opts.rerank_model_path and not opts.rerank_disabled:
            opts.rerank_model_path = _normalise_runtime_path(
                opts.rerank_model_path, "Reranker model"
            )
        if chosen_install is not None and not opts.dry_run:
            state_path = install_root / STATE_FILE
            backup_file(state_path, report, dry_run=False)
            try:
                write_install_state(install_root, chosen_install)
                report.add_modified(state_path)
            except OSError as exc:
                ui.warn(f"Could not write ida-install.json: {exc}")
        ui.info("Starting installer")
        ui.info(f"Install root: {install_root}")
        embed_model = ""
        embed_server = ""
        if opts.dry_run:
            ui.warn("Running in dry-run mode")

        if opts.kill_ida:
            # Prefer the explicit --ida-binary-path, fall back to the
            # selected install's idat binary, otherwise unscoped (legacy).
            kill_target: str | None = (
                getattr(opts, "ida_binary_path", "") or None
            )
            if not kill_target and chosen_install is not None and chosen_install.idat_binary:
                kill_target = str(chosen_install.idat_binary)
            if kill_target:
                ui.info(f"Stopping IDA processes for {kill_target} (--kill-ida enabled)")
            else:
                ui.warn(
                    "Stopping ALL IDA processes (--kill-ida without a binary "
                    "scope; pass --ida-binary-path or --ida-dir to narrow this)"
                )
            kill_succeeded = True
            if not opts.dry_run:
                kill_succeeded = kill_ida_processes(binary_path=kill_target)
                if not kill_succeeded:
                    message = (
                        "Could not enumerate or terminate the requested IDA "
                        "processes; continuing with installation."
                    )
                    report.add_warning(message)
                    ui.warn(message)
            report.add_step(
                "kill_ida",
                "dry-run" if opts.dry_run else ("ok" if kill_succeeded else "warn"),
                (
                    ("would stop " if opts.dry_run else "stopped ")
                    + (kill_target or "unscoped")
                    if kill_succeeded
                    else "process enumeration or termination failed"
                ),
            )
        else:
            report.add_step("kill_ida", "skipped", "not requested")

        python_exe = install_root / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        if _phase_enabled(opts, "runtime"):
            if opts.runtime_source == "local":
                ui.info("Setting up runtime environment (development mode)")
            else:
                ui.info("Setting up runtime environment")
            python_exe = setup_runtime_environment(
                install_root=install_root,
                source_root=source_root,
                runtime_source=opts.runtime_source,
                dry_run=opts.dry_run,
                report=report,
            )
            report.add_step(
                "runtime",
                "dry-run" if opts.dry_run else "ok",
                ("would prepare " if opts.dry_run else "ready: ") + str(python_exe),
            )
            if opts.dry_run:
                ui.info("Runtime environment would be prepared")
            elif opts.runtime_source == "local":
                ui.ok("Development mode: using source tree")
            else:
                ui.ok("Runtime environment ready")
        else:
            report.add_step("runtime", "skipped", "filtered by --only")

        corpus_env_enabled = os.environ.get("IDA_MCP_BRON_CORPUS_VERIFY", "").lower() in {
            "1", "true", "yes", "on"
        }
        corpus_requested = opts.with_bron_corpus or opts.verify_bron_corpus or corpus_env_enabled
        if (
            (opts.with_bron_corpus or opts.verify_bron_corpus)
            and not _phase_enabled(opts, "runtime")
        ):
            raise RuntimeError(
                "--with-corpus/--verify-corpus requires the runtime phase; "
                "remove --only clients (or include runtime)"
            )
        if _phase_enabled(opts, "runtime") and corpus_requested and not opts.dry_run:
            ui.info("Downloading threat corpus and crypto signatures")
            try:
                from .bron_corpus import download_bron_corpus
                strict_corpus = opts.verify_bron_corpus or os.environ.get(
                    "IDA_MCP_BRON_CORPUS_VERIFY", ""
                ).lower() in {"1", "true", "yes", "on"}
                if strict_corpus:
                    ui.info(
                        "Strict corpus verification enabled; every downloaded source "
                        "must have its IDA_MCP_BRON_CORPUS_SHA256_* hash configured."
                    )
                corpus_status = download_bron_corpus(
                    force=False, force_verify=strict_corpus
                )
                built = corpus_status.get("built", False)
                counts = corpus_status.get("counts", {})
                total = sum(counts.values()) if counts else 0
                sources_downloaded = len([
                    k for k, v in corpus_status.get("downloads", {}).items()
                    if "error" not in v
                ])
                if built:
                    ui.ok(f"Threat corpus ready ({total} entries from {sources_downloaded} sources)")
                else:
                    reason = corpus_status.get("reason", "unknown")
                    ui.warn(f"Corpus download incomplete: {reason}")
                report.add_step(
                    "corpus", "ok" if built else "warn",
                    f"{total} entries, {sources_downloaded} sources",
                )
                if not built:
                    raise RuntimeError(f"threat corpus was not built: {reason}")
            except Exception as exc:
                ui.warn(f"Corpus download failed: {exc}")
                report.add_step("corpus", "warn", str(exc))
                raise RuntimeError(f"threat corpus installation failed: {exc}") from exc
        elif _phase_enabled(opts, "runtime"):
            detail = (
                "dry-run"
                if opts.dry_run and corpus_requested
                else "optional; pass --with-corpus to enable"
            )
            report.add_step("corpus", "skipped", detail)

        # ── r2/Rizin engine (paper §8.2 item 11) ────────────────────────
        # Resolve an existing rz/r2 on PATH and record it as IDA_MCP_R2_BIN
        # in the generated client config so the default-off host engine can
        # find it.  Phase 1 never downloads a pinned engine release.
        r2_bin = ""
        r2_ver = ""
        if opts.with_r2:
            r2_bin, r2_ver = resolve_r2_binary()
            if r2_bin:
                if opts.dry_run:
                    ui.info(
                        f"Rizin/radare2 engine binary would be recorded: {r2_bin} "
                        f"({r2_ver or 'version unknown'})"
                    )
                else:
                    ui.ok(
                        f"Rizin/radare2 engine binary: {r2_bin} "
                        f"({r2_ver or 'version unknown'})"
                    )
                    ui.info(
                        "The resolved binary is recorded as IDA_MCP_R2_BIN in the "
                        "generated MCP client config."
                    )
            else:
                msg = (
                    "rz/r2 not found on PATH. Install Rizin (or radare2) to enable the r2 "
                    "engine: Debian/Ubuntu `sudo apt install rizin`, macOS `brew install "
                    "rizin`, or https://rizin.re. The engine stays disabled (default-off) "
                    "until a binary is available; Phase 1 does not download a pinned release."
                )
                ui.warn(msg)
                report.add_warning(msg)
            report.add_step(
                "r2",
                "dry-run" if opts.dry_run and r2_bin else ("ok" if r2_bin else "warn"),
                (
                    f"would record {r2_bin} {r2_ver or ''}".strip()
                    if opts.dry_run and r2_bin
                    else f"{r2_bin} {r2_ver or ''}".strip()
                    if r2_bin
                    else "rz/r2 not found on PATH"
                ),
            )
        elif _phase_enabled(opts, "r2"):
            report.add_step("r2", "skipped", "not requested (pass --with-r2)")

        # ── Signature-pack staging (paper §10.2 item 5e) ────────────────
        # Copy *.sig / *.sig.gz from --sigs <dir> into <IDADIR>/sig so
        # ida_list_sigs surfaces them — closes "nothing installs a RISC-V
        # .sig pack".  A staged RISC-V pack then shows up under ida_list_sigs
        # and can be applied per-IDB via ida_apply_sig.
        if opts.sigs_dir:
            sig_source = _absolute_path(opts.sigs_dir)
            if chosen_install is None:
                raise RuntimeError(
                    "--sigs requires an IDA install to derive <IDADIR>/sig from"
                )
            sig_dir = find_ida_sig_dir(chosen_install.path)
            manifest = stage_sigs(sig_source, sig_dir, opts.dry_run, report)
            report.metadata["sigs_manifest"] = manifest.to_dict()
            total = manifest.count + len(manifest.skipped)
            if not total:
                raise RuntimeError(f"No *.sig / *.sig.gz files found under {sig_source}")
            if manifest.count:
                action = "would stage" if opts.dry_run else "staged"
                ui.ok(f"{action} {manifest.count} signature file(s) into {sig_dir}")
                ui.info(
                    "ida_list_sigs (the host MCP signature op) surfaces them by basename "
                    "from <IDADIR>/sig; apply one per IDB with ida_apply_sig."
                )
            else:
                ui.info(
                    f"Preserved {total} existing signature file(s) in {sig_dir}; "
                    "nothing new was staged."
                )
            report.add_step(
                "sigs",
                "dry-run" if opts.dry_run else "ok",
                f"{manifest.count} staged, {len(manifest.skipped)} already present -> {sig_dir}",
            )
        elif _phase_enabled(opts, "sigs"):
            report.add_step("sigs", "skipped", "not requested (pass --sigs <dir>)")

        if _phase_enabled(opts, "clients"):
            ui.info("Configuring MCP clients")
            if opts.embed_backend == "gemini":
                rerank_model = _resolve_reranker_for_install(
                    opts,
                    install_root,
                    report,
                    ui,
                    semantic_enabled=True,
                )
                if rerank_model:
                    rerank_model = _normalise_runtime_path(
                        rerank_model, "Reranker model", allow_missing=opts.dry_run
                    )
                if not opts.dry_run:
                    try:
                        from ida_pro_mcp.host.intelligence.core import write_embedder_state
                        state_target = install_root / "embedder.json"
                        backup_file(state_target, report, dry_run=False)
                        state_path = write_embedder_state(
                            install_root,
                            backend="gemini",
                            gemini_model=opts.gemini_model,
                            gemini_dimension=opts.gemini_dim,
                            gemini_vertex_project=opts.gemini_vertex_project,
                            gemini_vertex_location=opts.gemini_vertex_location,
                            rerank=(
                                None
                                if opts.rerank_disabled
                                else {
                                    "profile": opts.rerank_profile,
                                    "model_path": rerank_model,
                                }
                            ),
                        )
                        report.metadata["embedder_state"] = str(state_path)
                        report.add_modified(Path(state_path))
                    except Exception as exc:
                        ui.warn(f"Could not persist embedder.json: {exc}")
                if opts.gemini_access == "vertex" and opts.gemini_install_auth and not opts.dry_run:
                    ui.info("Installing google-auth for Vertex AI Application Default Credentials")
                    if install_optional_packages(python_exe, ["google-auth"]):
                        ui.ok("google-auth installed for Vertex AI")
                        report.add_step("gemini-auth", "ok", "google-auth installed")
                    else:
                        ui.warn(
                            "google-auth install failed; the server will fall back to "
                            "VERTEX_AI_ACCESS_TOKEN"
                        )
                        report.add_step("gemini-auth", "warn", "google-auth install failed")
                ui.ok("Gemini embedding backend configured for MCP clients")
                if opts.gemini_access == "vertex":
                    ui.info(
                        f"Vertex AI: project={opts.gemini_vertex_project} "
                        f"location={opts.gemini_vertex_location}"
                    )
                server_cfg = build_stdio_config(
                    python_exe,
                    install_root,
                    embed_backend="gemini",
                    rerank_model=rerank_model,
                    rerank_profile=opts.rerank_profile,
                    gemini_api_key=opts.gemini_api_key,
                    gemini_vertex_project=opts.gemini_vertex_project,
                    gemini_vertex_location=opts.gemini_vertex_location,
                    gemini_vertex=opts.gemini_access == "vertex",
                    ida_install=getattr(opts, "_ida_install", None),
                    disable_policy=opts.disable_policy,
                    rerank_disabled=opts.rerank_disabled,
                    r2_bin=r2_bin,
                    ida_runtime=opts.ida_runtime,
                )
                configured = configure_clients(
                    source_root=source_root,
                    server_cfg=server_cfg,
                    report=report,
                    dry_run=opts.dry_run,
                )
                report.metadata["configured_clients"] = configured
                _report_client_configuration(
                    source_root, configured, report, ui, dry_run=opts.dry_run
                )
            else:
                embed_model = opts.embed_model_path
                embed_server = opts.embed_server_bin
                if opts.download_embed_model and not embed_model:
                    from ida_pro_mcp.host.intelligence.model_profiles import get_model_profile

                    selected_profile = get_model_profile(opts.embed_profile)
                    if selected_profile is None:
                        raise RuntimeError(f"Unknown embedding profile: {opts.embed_profile}")
                    if selected_profile.opt_in and not opts.accept_model_license:
                        raise RuntimeError(
                            f"{selected_profile.display_name} is {selected_profile.license}; "
                            "rerun with --accept-model-license to download it"
                        )
                    if opts.dry_run:
                        ui.info(f"Would download {selected_profile.display_name} embedding model")
                        report.add_step("embed_model", "dry-run", selected_profile.key)
                    else:
                        ui.info(f"Downloading {selected_profile.display_name} embedding model")
                        embed_model = download_embed_model(install_root, selected_profile.key)
                if opts.embed_auto and not embed_model:
                    embed_model = find_embed_model(install_root, opts.embed_profile)
                if opts.embed_auto and not embed_server:
                    embed_server = find_llama_server_bin(install_root)
                if (
                    opts.install_llama_server
                    and opts.embed_auto
                    and embed_model
                    and not embed_server
                ):
                    ui.info("Downloading and installing llama-server")
                    embed_server = download_and_install_llama_server(
                        install_root=install_root,
                        dry_run=opts.dry_run,
                        report=report,
                        allow_unverified=opts.allow_unverified_downloads or None,
                    )
                if embed_model:
                    embed_model = _normalise_runtime_path(
                        embed_model, "Embedding model", allow_missing=opts.dry_run
                    )
                if embed_server:
                    embed_server = _normalise_runtime_path(
                        embed_server,
                        "llama-server binary",
                        executable=True,
                        allow_missing=opts.dry_run,
                    )
                if embed_model:
                    ui.ok("Embedding model configured for MCP clients")
                    report.metadata["embed_model"] = embed_model
                elif opts.embed_auto:
                    ui.warn("No embedding model detected; semantic embedding features remain disabled")
                if embed_server:
                    report.metadata["embed_server_bin"] = embed_server
                rerank_model = _resolve_reranker_for_install(
                    opts,
                    install_root,
                    report,
                    ui,
                    semantic_enabled=bool(embed_model),
                )
                if rerank_model:
                    rerank_model = _normalise_runtime_path(
                        rerank_model, "Reranker model", allow_missing=opts.dry_run
                    )
                if (embed_model or embed_server or rerank_model) and not opts.dry_run:
                    try:
                        from ida_pro_mcp.host.intelligence.core import write_embedder_state
                        state_target = install_root / "embedder.json"
                        backup_file(state_target, report, dry_run=False)
                        # An explicit decline (opts.rerank_disabled) must not
                        # pin any rerank profile into state — that would make
                        # the host resolve the default profile and silently
                        # activate the reranker whenever a GGUF exists.
                        rerank_state = {"profile": opts.rerank_profile}
                        if rerank_model:
                            rerank_state["model_path"] = rerank_model
                        rerank_arg = None if opts.rerank_disabled else (rerank_state if (rerank_model or opts.rerank_profile) else None)
                        state_path = write_embedder_state(
                            install_root,
                            model_path=embed_model,
                            server_bin=embed_server,
                            profile=opts.embed_profile,
                            rerank=rerank_arg,
                        )
                        report.metadata["embedder_state"] = str(state_path)
                        report.add_modified(Path(state_path))
                    except Exception as exc:
                        ui.warn(f"Could not persist embedder.json: {exc}")
                server_cfg = build_stdio_config(
                    python_exe,
                    install_root,
                    embed_model=embed_model,
                    embed_server_bin=embed_server,
                    embed_profile=opts.embed_profile,
                    embed_backend="local",
                    rerank_model=rerank_model,
                    rerank_profile=opts.rerank_profile,
                    ida_install=getattr(opts, "_ida_install", None),
                    disable_policy=opts.disable_policy,
                    rerank_disabled=opts.rerank_disabled,
                    r2_bin=r2_bin,
                    ida_runtime=opts.ida_runtime,
                )
                configured = configure_clients(
                    source_root=source_root,
                    server_cfg=server_cfg,
                    report=report,
                    dry_run=opts.dry_run,
                )
                report.metadata["configured_clients"] = configured
                _report_client_configuration(
                    source_root, configured, report, ui, dry_run=opts.dry_run
                )
        else:
            report.add_step("clients", "skipped", "filtered by --only")

        if _phase_enabled(opts, "skills"):
            ui.info("Installing Codex skills")
            install_codex_skills(source_root, opts.skills_mode, report, opts.dry_run)
            ui.ok("Codex skills processed")

            if opts.install_claude_skills:
                ui.info("Installing Claude Code / OpenCode skills")
                _install_claude_opencode_skills(report, opts.dry_run, ui)
            else:
                report.add_step("claude-skills", "skipped", "disabled by user")
        else:
            report.add_step("skills", "skipped", "filtered by --only")

        if opts.install_cli_shim and _phase_enabled(opts, "shell"):
            ui.info("Installing shell CLI shim")
            shell_supported = install_bashrc_cli(install_root, opts.dry_run, report)
            if shell_supported:
                shell_status = "dry-run" if opts.dry_run else "ok"
                shell_detail = "would update bashrc" if opts.dry_run else "bashrc updated"
                report.add_step("shell", shell_status, shell_detail)
                if opts.dry_run:
                    ui.info("CLI shell shim would be installed")
                else:
                    ui.ok("CLI shell shim installed")
            else:
                report.add_step("shell", "skipped", "not supported on Windows")
                ui.info("CLI shell shim skipped on Windows")
        else:
            report.add_step("shell", "skipped", "not requested")

        if _phase_enabled(opts, "clients"):
            _activate_idalib_after_install(opts, chosen_install, report, ui)
        report.finalize(True)
        report_path = install_root / "install-report.json"
        reject_symlink_path(report_path, "installer report path")
        report.write(report_path)

    except Exception as exc:
        tb_text = traceback.format_exc()
        msg = f"Installation failed: {exc}"
        report.add_error(msg)
        # Keep a tail of the traceback in the report so post-mortem
        # tooling does not have to grep the log file separately.
        tb_tail = "\n".join(tb_text.splitlines()[-25:])
        report.add_error(f"traceback (tail):\n{tb_tail}")
        ui.err(msg)
        # Spill the full traceback to a logfile next to install-report.json
        # so a real crash is recoverable; a bare `return 1` would swallow it.
        log_root = opts.install_root or get_install_root()
        log_path = log_root / "install-error.log"
        try:
            _write_install_error_log(log_path, tb_text)
            ui.err(f"Full traceback: {log_path}")
        except (OSError, RuntimeError) as log_exc:
            ui.err(f"Could not write {log_path}: {log_exc}")
        if opts.rollback_on_fail:
            try:
                rollback_from_backups(report)
                report.add_step("rollback", "ok", "restored config backups")
                ui.warn("Rollback completed for backed-up config files")
            except Exception as rollback_exc:
                report.add_error(f"Rollback failed: {rollback_exc}")
                ui.err(f"Rollback failed: {rollback_exc}")
        report.finalize(False)
        report_path = (opts.install_root or get_install_root()) / "install-report.json"
        try:
            reject_symlink_path(report_path, "installer report path")
            report.write(report_path)
            ui.warn(f"Failure report written to {report_path}")
        except Exception:
            pass
        return 1

    return 0


def main(argv: list[str] | None = None) -> int:
    ui = UI()
    opts = parse_args(argv)
    if opts.embedder_doctor:
        return run_embedder_doctor(opts, ui)
    return run_install(opts, ui)


if __name__ == "__main__":
    raise SystemExit(main())
