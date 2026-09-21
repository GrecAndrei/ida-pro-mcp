from __future__ import annotations

import argparse
import contextlib
import os
import shlex
import shutil
import sys
import traceback
from datetime import UTC, datetime
from pathlib import Path

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
    find_idalib_python_dir,
    get_install_root,
    kill_ida_processes,
    setup_runtime_environment,
    stage_sigs,
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


def _absolute_path(path: Path | str) -> Path:
    """Expand a user path without resolving symlinks or requiring existence."""
    return Path(os.path.abspath(os.path.expandvars(os.path.expanduser(os.fspath(path)))))


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

    # Intelligence is configured as an explicit provider; no local model,
    # Gemini, native library, or secret-entry wizard is offered.
    mode_labels = {
        "Jev (TypeSafe hosted provider)": "jev",
        "Custom (operator HTTPS/loopback endpoint)": "custom",
        "Disabled (deterministic and lexical analysis only)": "disabled",
    }
    current_mode = opts.intelligence_mode if opts.intelligence_mode in mode_labels.values() else "disabled"
    default_mode_label = next(label for label, value in mode_labels.items() if value == current_mode)
    opts.intelligence_mode = mode_labels[
        _prompt_choice("Intelligence provider mode", list(mode_labels), default_mode_label)
    ]
    if opts.intelligence_mode == "jev":
        opts.jev_model = _prompt_text("Jev model", default=opts.jev_model or "jev-latest") or "jev-latest"
        ui.info("Provide TYPESAFE_API_KEY or TYPESAFE_API_KEY_FILE in the server environment; it is never stored by the installer.")
    elif opts.intelligence_mode == "custom":
        opts.custom_base_url = _prompt_text("Custom HTTPS origin", default=opts.custom_base_url)
        opts.custom_allowed_origins = _prompt_text(
            "Explicit allowed origins (comma-separated)", default=opts.custom_allowed_origins or opts.custom_base_url
        )
        opts.custom_model = _prompt_text("Custom model", default=opts.custom_model)
        opts.custom_api_key_env = _prompt_text(
            "Credential environment variable name", default=opts.custom_api_key_env or "CUSTOM_PROVIDER_API_KEY"
        )
        opts.custom_api_key_file = _prompt_text(
            "Credential file path (optional)", default=opts.custom_api_key_file
        )
        opts.custom_protocol = "typed_questions"
        ui.info("Credentials are read at request time and never copied into client configuration.")
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
    intelligence_group = parser.add_mutually_exclusive_group()
    intelligence_group.add_argument(
        "--intelligence-mode",
        choices=["jev", "custom", "disabled"],
        default="disabled",
        help="intelligence provider mode (default: disabled; no local/Gemini/native fallback)",
    )
    parser.add_argument("--jev-model", default="jev-latest", help="Jev model identifier")
    parser.add_argument("--custom-base-url", default="", help="custom provider HTTPS origin")
    parser.add_argument(
        "--custom-allowed-origin", action="append", default=[],
        help="explicit custom provider origin allowlist entry (repeatable)",
    )
    parser.add_argument("--custom-model", default="", help="custom typed-question model identifier")
    parser.add_argument(
        "--custom-api-key-env", default="CUSTOM_PROVIDER_API_KEY",
        help="environment variable name read for custom credentials",
    )
    parser.add_argument("--custom-api-key-file", default="", help="optional custom credential file path")
    parser.add_argument(
        "--custom-local-http", action="store_true",
        help="allow custom HTTP only for a loopback origin",
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
    parser.add_argument(
        "--sigs",
        default="",
        metavar="DIR",
        help="stage a FLIRT signature pack (*.sig / *.sig.gz) into <IDADIR>/sig so "
        "ida_list_sigs can surface it (e.g. a RISC-V .sig pack). DIR may be a single "
        ".sig/.sig.gz file or a directory (walked recursively, subpaths preserved).",
    )

    parser.add_argument("--only", action="append", choices=["runtime", "clients", "shell", "sigs"], default=[], help="run only selected install phases")
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
        interactive=True if args.interactive else (False if args.no_interactive else None),
        intelligence_mode=args.intelligence_mode,
        jev_model=args.jev_model,
        custom_base_url=args.custom_base_url,
        custom_allowed_origins=",".join(args.custom_allowed_origin),
        custom_model=args.custom_model,
        custom_api_key_env=args.custom_api_key_env,
        custom_api_key_file=args.custom_api_key_file,
        custom_local_http=args.custom_local_http,

        only=set(args.only),
        disable_policy=args.disable_policy,
        with_corpus=args.with_corpus,
        sigs_dir=args.sigs,
        ida_runtime=args.ida_runtime or "idat",
        ida_binary_path=args.ida_binary_path,
        with_bron_corpus=args.with_corpus or args.verify_corpus,
        verify_bron_corpus=args.verify_corpus,
    )
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
    directory, so relative runtime and binary paths are not safe to persist.
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

    # 2. Remove IDA plugin if IDA installs found
    from .discovery import detect_ida_installs
    try:
        installs = detect_ida_installs()
        for inst in installs:
            plugin_dir = Path(inst.path) / "plugins"
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
        # signature staging both need a concrete install, but runtime/
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
        # Validate the explicit provider configuration before any client
        # config is touched. Credentials are deliberately not read here.
        from ida_pro_mcp.host.intelligence.providers.config import resolve_provider_config

        provider_env = {
            "IDA_MCP_INTELLIGENCE_MODE": opts.intelligence_mode,
            # Defaults for an inactive provider are not configuration. Keep
            # them out of validation so a signatures-only or disabled install
            # does not manufacture a cross-mode conflict.
            "IDA_MCP_JEV_MODEL": opts.jev_model if opts.intelligence_mode == "jev" else "",
            "IDA_MCP_CUSTOM_BASE_URL": opts.custom_base_url if opts.intelligence_mode == "custom" else "",
            "IDA_MCP_CUSTOM_ALLOWED_ORIGINS": opts.custom_allowed_origins if opts.intelligence_mode == "custom" else "",
            "IDA_MCP_CUSTOM_MODEL": opts.custom_model if opts.intelligence_mode == "custom" else "",
            "IDA_MCP_CUSTOM_PROTOCOL": opts.custom_protocol if opts.intelligence_mode == "custom" else "",
            "IDA_MCP_CUSTOM_API_KEY_ENV": opts.custom_api_key_env if opts.intelligence_mode == "custom" else "",
            "IDA_MCP_CUSTOM_API_KEY_FILE": opts.custom_api_key_file if opts.intelligence_mode == "custom" else "",
            "IDA_MCP_CUSTOM_LOCAL_HTTP": "1" if opts.intelligence_mode == "custom" and opts.custom_local_http else "",
        }
        resolve_provider_config(env=provider_env, state={})
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

        # The intelligence provider is the only supported model-facing
        # configuration. Legacy local/Gemini/native model installer phases are
        # intentionally absent; client configuration only records the explicit
        # provider mode and safe non-secret settings.
        if _phase_enabled(opts, "clients"):
            ui.info("Configuring MCP clients")
            server_cfg = build_stdio_config(
                python_exe,
                install_root,
                intelligence_mode=opts.intelligence_mode,
                jev_model=opts.jev_model,
                custom_base_url=opts.custom_base_url,
                custom_allowed_origins=opts.custom_allowed_origins,
                custom_model=opts.custom_model,
                custom_protocol=opts.custom_protocol,
                custom_api_key_env=opts.custom_api_key_env,
                custom_api_key_file=opts.custom_api_key_file,
                custom_local_http=opts.custom_local_http,
                ida_install=getattr(opts, "_ida_install", None),
                disable_policy=opts.disable_policy,
                ida_runtime=opts.ida_runtime,
            )
            configured = configure_clients(
                source_root=source_root,
                server_cfg=server_cfg,
                report=report,
                dry_run=opts.dry_run,
            )
            report.metadata["configured_clients"] = configured
            report.metadata["intelligence_mode"] = opts.intelligence_mode
            _report_client_configuration(
                source_root, configured, report, ui, dry_run=opts.dry_run
            )
        else:
            report.add_step("clients", "skipped", "filtered by --only")

        # Agent skills are discovered live via tools/list + ida_help; no static
        # skill files are installed.

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
    return run_install(opts, ui)


if __name__ == "__main__":
    raise SystemExit(main())
