from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import traceback
from datetime import UTC, datetime
from pathlib import Path

from .clients import configure_clients, rollback_from_backups
from .common import InstallerOptions, InstallReport
from .discovery import (
    IdaInstall,
    detect_ida_installs,
    read_install_state,
    select_ida_install,
    write_install_state,
)
from .runtime import (
    build_stdio_config,
    choose_runtime_source,
    download_and_install_llama_server,
    download_embed_model,
    find_embed_model,
    find_llama_server_bin,
    get_install_root,
    kill_ida_processes,
    setup_runtime_environment,
)


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


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def run_embedder_doctor(opts: InstallerOptions, ui: UI) -> int:
    install_root = opts.install_root or get_install_root()
    profile = opts.embed_profile
    embed_model = opts.embed_model_path or (
        find_embed_model(install_root, profile) if opts.embed_auto else ""
    )
    embed_server = opts.embed_server_bin or (find_llama_server_bin(install_root) if opts.embed_auto else "")

    ui.info("Embedder doctor")
    ui.info("---------------")
    ui.info(f"install_root: {install_root}")
    ui.info(f"llama-server: {'found ' + embed_server if embed_server else 'not found'}")
    ui.info(f"model: {'found ' + embed_model if embed_model else 'not found'}")

    from ida_pro_mcp.host.intelligence import core as intel_core

    # Recreate singleton under doctor-selected env so status/probe reflect this setup.
    prev_server = os.environ.get("IDA_MCP_EMBED_SERVER_BIN", "")
    prev_model = os.environ.get("IDA_MCP_EMBED_MODEL", "")
    prev_profile = os.environ.get("IDA_MCP_EMBED_PROFILE", "")
    prev_instance = intel_core.BgeCodeEmbedder._instance
    try:
        if embed_server:
            os.environ["IDA_MCP_EMBED_SERVER_BIN"] = embed_server
        if embed_model:
            os.environ["IDA_MCP_EMBED_MODEL"] = embed_model
        if profile:
            os.environ["IDA_MCP_EMBED_PROFILE"] = profile
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
            ui.ok("health endpoint: ok")
        else:
            ui.warn("health endpoint: not ready")
        ui.info(f"backend: {status.get('backend')}")
        ui.info(f"embed test: {'ok' if status.get('embed_test_ok') else 'failed'}")
        ui.info("fallback: unavailable (semantic features fail explicitly)")
        print(json.dumps(status, indent=2))
        return 0
    finally:
        intel_core.BgeCodeEmbedder._instance = prev_instance
        if prev_server:
            os.environ["IDA_MCP_EMBED_SERVER_BIN"] = prev_server
        elif "IDA_MCP_EMBED_SERVER_BIN" in os.environ:
            del os.environ["IDA_MCP_EMBED_SERVER_BIN"]
        if prev_model:
            os.environ["IDA_MCP_EMBED_MODEL"] = prev_model
        elif "IDA_MCP_EMBED_MODEL" in os.environ:
            del os.environ["IDA_MCP_EMBED_MODEL"]
        if prev_profile:
            os.environ["IDA_MCP_EMBED_PROFILE"] = prev_profile
        elif "IDA_MCP_EMBED_PROFILE" in os.environ:
            del os.environ["IDA_MCP_EMBED_PROFILE"]


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


def _prompt_model_path(profile: str) -> str:
    """Ask the user to provide a model file path interactively."""
    print(f"Enter the full path to your {profile} GGUF model file, or leave empty to skip.")
    print("Example: /home/user/Downloads/model.gguf")
    while True:
        ans = input("Model path (or press Enter to skip): ").strip().strip("\"'")
        if not ans:
            return ""
        p = Path(ans).expanduser()
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
            explicit_dir=Path(opts.ida_dir).expanduser() if opts.ida_dir else None,
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
        ["local", "pypi"],
        runtime_default if runtime_default in {"local", "pypi"} else "local",
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

    opts.embed_profile = _prompt_choice(
        "Embedding profile",
        ["bge-code-v1", "zembed-1"],
        opts.embed_profile,
    )
    if opts.embed_profile == "zembed-1":
        ui.info("Zembed 1 is opt-in and licensed CC-BY-NC-4.0 (non-commercial).")
    auto_embed_model = find_embed_model(opts.install_root or get_install_root(), opts.embed_profile)
    auto_embed_server = find_llama_server_bin(opts.install_root or get_install_root())
    if auto_embed_model:
        ui.ok(f"Detected embedding model: {auto_embed_model}")
        opts.embed_auto = _prompt_yes_no("Enable semantic embedding model for MCP clients?", default=True)
        if opts.embed_auto:
            opts.embed_model_path = auto_embed_model
            if auto_embed_server:
                ui.ok(f"Detected llama-server: {auto_embed_server}")
                opts.embed_server_bin = auto_embed_server
            else:
                ui.warn("llama-server not found.")
                opts.install_llama_server = _prompt_yes_no(
                    "Download and install llama-server automatically?",
                    default=True,
                )
    else:
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

    opts.rollback_on_fail = _prompt_yes_no(
        "Rollback backed-up config files on failure?",
        default=True if not opts.rollback_on_fail else opts.rollback_on_fail,
    )

    ui.info(
        "Policy gates are ON by default — they require evidence cards and "
        "acknowledgements for write-surface tools. Disable them only if you "
        "trust every MCP client and LLM with full edit access to your IDB."
    )
    opts.disable_policy = _prompt_yes_no(
        "Disable ALL policy gates (strict-blackboard, phase choreography, ack requirements)?",
        default=False,
    )
    if opts.disable_policy:
        ui.warn("Policy gates DISABLED — all tools run without restrictions.")

    if not _prompt_yes_no("Proceed with installation now?", default=True):
        raise RuntimeError("Installation cancelled by user.")
    return opts


def install_bashrc_cli(install_root: Path, dry_run: bool, report: InstallReport) -> None:
    if sys.platform == "win32":
        report.add_warning("bashrc shim skipped on Windows")
        return
    bashrc = Path.home() / ".bashrc"
    block_start = "# >>> ida-pro-mcp >>>"
    block_end = "# <<< ida-pro-mcp <<<"
    venv_bin = install_root / ".venv" / "bin"
    block = "\n".join(
        [
            block_start,
            f'export IDA_PRO_MCP_HOME="{install_root}"',
            'case ":$PATH:" in',
            '  *":$IDA_PRO_MCP_HOME/.venv/bin:"*) ;;',
            '  *) export PATH="$IDA_PRO_MCP_HOME/.venv/bin:$PATH" ;;',
            'esac',
            f'export IDA_PRO_MCP_CLI="{venv_bin / "ida-pro-mcp-cli"}"',
            block_end,
            "",
        ]
    )
    existing = bashrc.read_text(encoding="utf-8") if bashrc.exists() else ""
    if block_start in existing and block_end in existing:
        start = existing.index(block_start)
        end = existing.index(block_end) + len(block_end)
        newline = existing.find("\n", end)
        updated = existing[:start] + block + ("" if newline == -1 else existing[newline + 1 :])
    else:
        updated = existing.rstrip("\n") + ("\n" if existing.strip() else "") + block
    if not dry_run:
        bashrc.parent.mkdir(parents=True, exist_ok=True)
        bashrc.write_text(updated, encoding="utf-8")
    report.add_modified(bashrc)


def _replace_with_symlink_or_copy(src: Path, dst: Path) -> str:
    if dst.exists() or dst.is_symlink():
        if dst.is_dir() and not dst.is_symlink():
            shutil.rmtree(dst)
        else:
            dst.unlink()
    try:
        os.symlink(src, dst, target_is_directory=src.is_dir())
        return "linked"
    except OSError:
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
        return "copied"


def _install_claude_opencode_skills(report: InstallReport, dry_run: bool, ui: UI) -> None:
    """Auto-generate and install skills for Claude Code and OpenCode."""
    try:
        from .skills import default_skill_dirs, install_skills
    except ImportError as exc:
        report.add_warning(f"claude-skills: import error — {exc}")
        return
    try:
        target_dirs = default_skill_dirs()
        written = install_skills(target_dirs, dry_run=dry_run)
        count = sum(len(paths) for paths in written.values())
        for _skill_name, paths in written.items():
            for p in paths:
                report.add_modified(p)
        action = "would install" if dry_run else "installed"
        report.add_step(
            "claude-skills", "ok" if not dry_run else "dry-run",
            f"{action} {len(written)} skills ({count} files) to {len(target_dirs)} dirs",
        )
        ui.ok(f"Claude/OpenCode skills: {action} {len(written)} skills")
    except Exception as exc:
        report.add_warning(f"claude-skills install failed: {exc}")


def install_codex_skills(source_root: Path, mode: str, report: InstallReport, dry_run: bool) -> None:
    if mode == "none":
        report.add_step("skills", "skipped", "skills mode set to none")
        return
    source_root_skills = source_root / ".agents" / "skills"
    if not source_root_skills.exists():
        report.add_warning("skills source not found; skipping")
        return
    agent_skill = source_root_skills / "ida-pro-mcp"
    if not (agent_skill / "SKILL.md").exists():
        report.add_warning("agent skill source not found; regenerate skills before installing")
        return
    selected = [agent_skill]
    codex_skills = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))).expanduser() / "skills"
    if dry_run:
        report.add_step("skills", "dry-run", f"would install {len(selected)} entries to {codex_skills}")
        return
    codex_skills.mkdir(parents=True, exist_ok=True)
    for src in selected:
        dst = codex_skills / src.name
        _replace_with_symlink_or_copy(src, dst)
        report.add_modified(dst)
    report.add_step("skills", "ok", f"installed {len(selected)} skills")


def parse_args(argv: list[str] | None = None) -> InstallerOptions:
    parser = argparse.ArgumentParser(description="IDA Pro MCP installer")
    parser.add_argument("--dry-run", action="store_true", help="print planned actions without mutating files")
    parser.add_argument("--yes", action="store_true", help="non-interactive mode")
    parser.add_argument("--interactive", action="store_true", help="force interactive wizard mode")
    parser.add_argument("--no-interactive", action="store_true", help="disable interactive wizard mode")
    parser.add_argument("--kill-ida", action="store_true", help="terminate running ida/idat processes before install")
    parser.add_argument(
        "--ida-binary-path",
        default="",
        help="when used with --kill-ida, only terminate processes running this binary path "
        "(default: scope to the chosen IDA install's idat binary)",
    )
    parser.add_argument("--install-cli-shim", action="store_true", help="opt-in bashrc PATH shim installation")
    parser.add_argument("--rollback-on-fail", action="store_true", help="restore backed up config files if install fails")
    parser.add_argument("--runtime-source", choices=["auto", "local", "pypi"], default="auto", help="choose runtime package source")
    parser.add_argument("--embed-model", default="", help="explicit path to an embedding GGUF model")
    parser.add_argument(
        "--embed-profile", choices=["bge-code-v1", "zembed-1"], default="bge-code-v1",
        help="embedding prompt/model profile (default: bge-code-v1)",
    )
    parser.add_argument(
        "--download-embed-model", action="store_true",
        help="download the selected managed embedding model",
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
    parser.add_argument("--no-embed-auto", action="store_true", help="disable automatic embedder/server discovery")
    parser.add_argument("--skills-mode", choices=["agent", "none"], default="agent", help="Codex skill installation mode")
    parser.add_argument("--install-skills", action="store_true", default=True, help="install auto-generated skills for Claude Code / OpenCode (default: on)")
    parser.add_argument("--no-install-skills", action="store_true", help="skip Claude Code / OpenCode skill installation")

    parser.add_argument("--only", action="append", choices=["runtime", "clients", "skills", "shell"], default=[], help="run only selected install phases")
    parser.add_argument("--install-root", default="", help="override install root directory")
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
    args = parser.parse_args(argv)
    opts = InstallerOptions(
        dry_run=args.dry_run,
        yes=args.yes,
        kill_ida=args.kill_ida,
        install_cli_shim=args.install_cli_shim,
        rollback_on_fail=args.rollback_on_fail,
        runtime_source=args.runtime_source,
        skills_mode=args.skills_mode,
        install_claude_skills=not args.no_install_skills,
        interactive=True if args.interactive else (False if args.no_interactive else None),
        embed_auto=not args.no_embed_auto,
        embed_profile=args.embed_profile,
        embed_model_path=args.embed_model,
        embed_server_bin=args.embed_server_bin,
        install_llama_server=args.install_llama_server,
        download_embed_model=args.download_embed_model,
        accept_model_license=args.accept_model_license,
        embedder_doctor=args.embedder_doctor,
        setup_embedder=args.setup_embedder,

        only=set(args.only),
    )
    if opts.setup_embedder:
        opts.embed_auto = True
        opts.install_llama_server = True
        if not opts.only:
            opts.only = {"clients"}
    opts.install_root = Path(args.install_root).expanduser() if args.install_root else get_install_root()
    opts.source_root = Path(__file__).resolve().parents[3]
    opts.ida_dir = args.ida_dir
    opts.ida_version = args.ida_version
    opts.no_ida_prompt = args.no_ida_prompt
    # Dynamic attr (audit §6.2): scopes --kill-ida to a binary path so
    # we don't terminate a user's unrelated IDA on a different binary.
    opts.ida_binary_path = args.ida_binary_path  # type: ignore[attr-defined]
    return opts


def _phase_enabled(opts: InstallerOptions, name: str) -> bool:
    return not opts.only or name in opts.only


def run_install(opts: InstallerOptions, ui: UI) -> int:
    report = InstallReport()
    install_root = opts.install_root or get_install_root()
    source_root = opts.source_root or Path.cwd()
    report.metadata.update({"install_root": str(install_root), "source_root": str(source_root)})

    try:
        # Resolve IDA only when a later phase actually needs it or the user
        # explicitly asked for an IDA override. Client configuration benefits
        # from a concrete install, but runtime/skills/shell-only installs
        # should not fail just because IDA is absent on this machine.
        chosen_install = None
        if _phase_enabled(opts, "clients") or opts.ida_dir or opts.ida_version:
            try:
                chosen_install = _resolve_ida_install(opts, ui)
            except RuntimeError as exc:
                if opts.ida_dir or opts.ida_version:
                    raise
                msg = str(exc)
                if "no IDA Pro install found" not in msg and "No IDA Pro install detected" not in msg:
                    raise
                ui.warn("No IDA Pro install detected; continuing without IDADIR")
        if chosen_install is not None:
            opts._ida_install = chosen_install  # type: ignore[attr-defined]
            report.metadata["ida_install"] = chosen_install.to_dict()
            report.metadata["ida_version"] = chosen_install.full_version_str
            if not opts.dry_run:
                try:
                    write_install_state(install_root, chosen_install)
                except OSError as exc:
                    ui.warn(f"Could not write ida-install.json: {exc}")

        opts = _run_interactive_wizard(opts, ui)
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
            if not opts.dry_run:
                kill_ida_processes(binary_path=kill_target)
            report.add_step("kill_ida", "ok", kill_target or "unscoped")
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
            report.add_step("runtime", "ok", str(python_exe))
            if opts.runtime_source == "local":
                ui.ok("Development mode: using source tree")
            else:
                ui.ok("Runtime environment ready")
        else:
            report.add_step("runtime", "skipped", "filtered by --only")

        if _phase_enabled(opts, "runtime") and not opts.dry_run:
            ui.info("Downloading threat corpus and crypto signatures")
            try:
                from .bron_corpus import download_bron_corpus
                corpus_status = download_bron_corpus(force=False)
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
            except Exception as exc:
                ui.warn(f"Corpus download failed (non-fatal): {exc}")
                report.add_step("corpus", "warn", str(exc))
        elif _phase_enabled(opts, "runtime"):
            report.add_step("corpus", "skipped", "dry-run")

        if _phase_enabled(opts, "clients"):
            ui.info("Configuring MCP clients")
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
                )
            if embed_model:
                ui.ok("Embedding model configured for MCP clients")
                report.metadata["embed_model"] = embed_model
            elif opts.embed_auto:
                ui.warn("No embedding model detected; semantic embedding features remain disabled")
            if embed_server:
                report.metadata["embed_server_bin"] = embed_server
            if (embed_model or embed_server) and not opts.dry_run:
                try:
                    from ida_pro_mcp.host.intelligence.core import write_embedder_state
                    state_path = write_embedder_state(
                        install_root,
                        model_path=embed_model,
                        server_bin=embed_server,
                        profile=opts.embed_profile,
                    )
                    report.metadata["embedder_state"] = str(state_path)
                except Exception as exc:
                    ui.warn(f"Could not persist embedder.json: {exc}")
            server_cfg = build_stdio_config(
                python_exe,
                install_root,
                embed_model=embed_model,
                embed_server_bin=embed_server,
                embed_profile=opts.embed_profile,
                ida_install=getattr(opts, "_ida_install", None),
                disable_policy=opts.disable_policy,
            )
            configured = configure_clients(
                source_root=source_root,
                server_cfg=server_cfg,
                report=report,
                dry_run=opts.dry_run,
            )
            report.metadata["configured_clients"] = configured
            report.add_step("clients", "ok", f"configured {len(configured)} clients")
            ui.ok(f"Configured {len(configured)} clients")
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
            install_bashrc_cli(install_root, opts.dry_run, report)
            report.add_step("shell", "ok", "bashrc updated")
            ui.ok("CLI shell shim installed")
        else:
            report.add_step("shell", "skipped", "not requested")

        report.finalize(True)
        report_path = install_root / "install-report.json"
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
            log_root.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now(UTC).isoformat()
            with open(log_path, "a", encoding="utf-8") as logf:
                logf.write(
                    f"\n=== {timestamp} run_install crashed ===\n{tb_text}\n"
                )
            ui.err(f"Full traceback: {log_path}")
        except OSError as log_exc:
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
            report.write(report_path)
            ui.warn(f"Failure report written to {report_path}")
        except Exception:
            pass

def main(argv: list[str] | None = None) -> int:
    ui = UI()
    opts = parse_args(argv)
    if opts.embedder_doctor:
        return run_embedder_doctor(opts, ui)
    return run_install(opts, ui)


if __name__ == "__main__":
    raise SystemExit(main())
