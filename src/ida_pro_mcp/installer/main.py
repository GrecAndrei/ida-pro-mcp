from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

from .clients import configure_clients, rollback_from_backups
from .common import InstallReport, InstallerOptions
from .runtime import (
    build_stdio_config,
    download_and_install_llama_server,
    find_embed_model,
    find_llama_server_bin,
    detect_ida_install_dir,
    discover_installed_package_paths,
    get_ida_plugin_dir,
    get_install_root,
    ida_processes_running,
    kill_ida_processes,
    choose_runtime_source,
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


def _build_embedder_capsule_state(embed_model: str, embed_server: str) -> dict:
    from ida_pro_mcp.host.intelligence_core import (
        EMBED_DIM,
        BehaviorClassifier,
    )

    anchor_blob = json.dumps(BehaviorClassifier.ANCHORS, sort_keys=True, separators=(",", ":")).encode("utf-8")
    anchor_hash = hashlib.sha256(anchor_blob).hexdigest()
    model_hash = ""
    if embed_model:
        try:
            model_hash = _sha256_file(embed_model)
        except OSError:
            model_hash = ""

    return {
        "backend": "bge-code-v1",
        "model_path": embed_model or "",
        "model_hash": model_hash,
        "embedding_dim": EMBED_DIM,
        "index_metadata": {
            "implementation": "FunctionEmbeddingIndex",
            "storage": "sqlite",
            "table": "func_embeddings",
            "db_path_pattern": "<idb_path>.embeddings.db",
            "pseudo_hash": "md5-16",
        },
        "anchor_metadata": {
            "anchor_count": len(BehaviorClassifier.ANCHORS),
            "anchor_hash_sha256": anchor_hash,
            "anchor_version": f"sha256:{anchor_hash[:16]}",
        },
        "last_indexed_functions": [],
        "thresholds": {
            "classification_default": 0.25,
            "coverage_default_min_similarity": 0.4,
            "anchor_min_confidence": dict(BehaviorClassifier.ANCHOR_MIN_CONFIDENCE),
        },
        "runtime": {
            "embed_server_bin": embed_server or "",
        },
    }


def run_embedder_doctor(opts: InstallerOptions, ui: UI) -> int:
    install_root = opts.install_root or get_install_root()
    embed_model = opts.embed_model_path or (find_embed_model(install_root) if opts.embed_auto else "")
    embed_server = opts.embed_server_bin or (find_llama_server_bin(install_root) if opts.embed_auto else "")

    ui.info("Embedder doctor")
    ui.info("---------------")
    ui.info(f"install_root: {install_root}")
    ui.info(f"llama-server: {'found ' + embed_server if embed_server else 'not found'}")
    ui.info(f"model: {'found ' + embed_model if embed_model else 'not found'}")

    from ida_pro_mcp.host import intelligence_core as intel_core

    # Recreate singleton under doctor-selected env so status/probe reflect this setup.
    prev_server = os.environ.get("IDA_MCP_EMBED_SERVER_BIN", "")
    prev_model = os.environ.get("IDA_MCP_EMBED_MODEL", "")
    prev_instance = intel_core.BgeCodeEmbedder._instance
    try:
        if embed_server:
            os.environ["IDA_MCP_EMBED_SERVER_BIN"] = embed_server
        if embed_model:
            os.environ["IDA_MCP_EMBED_MODEL"] = embed_model
        intel_core.BgeCodeEmbedder._instance = None
        emb = intel_core.BgeCodeEmbedder()
        status = emb.status(probe=True, deep_hash=False)
        status["model_fingerprint"] = intel_core.model_fingerprint(embed_model, deep_hash=False)
        status["server_fingerprint"] = intel_core.server_fingerprint(embed_server, deep_hash=False)
        status["embed_test_ok"] = False
        status["embed_test_dim"] = 0
        try:
            vec = emb.embed("embedder doctor quick check")
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
        ui.info(f"fallback available: {'yes' if status.get('backend') == 'tfidf-fallback' or not status.get('use_llama') else 'yes'}")
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


def _run_interactive_wizard(opts: InstallerOptions, ui: UI) -> InstallerOptions:
    if opts.yes:
        return opts

    if opts.interactive is False:
        return opts

    if opts.interactive is None and not _is_interactive_terminal():
        return opts

    ui.info("Interactive install mode")
    ui.info("Press Enter to keep recommended defaults.")

    detected_ida = detect_ida_install_dir()
    if detected_ida:
        ui.ok(f"Detected IDA install: {detected_ida}")
    else:
        ui.warn("No IDA install auto-detected (can still configure clients/runtime).")

    resolved_runtime = choose_runtime_source(opts.runtime_source, opts.source_root or Path.cwd())
    runtime_default = opts.runtime_source if opts.runtime_source != "auto" else resolved_runtime
    opts.runtime_source = _prompt_choice(
        "Runtime package source",
        ["local", "pypi"],
        runtime_default if runtime_default in {"local", "pypi"} else "local",
    )

    running = ida_processes_running()
    if running:
        ui.warn("IDA/IDAT processes appear to be running.")
    opts.kill_ida = _prompt_yes_no(
        "Stop running IDA/IDAT processes before install?",
        default=running,
    )

    if sys.platform != "win32":
        opts.install_cli_shim = _prompt_yes_no(
            "Install CLI shell shim into ~/.bashrc?",
            default=opts.install_cli_shim,
        )

    opts.skills_mode = _prompt_choice(
        "Codex skills mode",
        ["router", "full", "none"],
        opts.skills_mode,
    )

    auto_embed_model = find_embed_model(opts.install_root or get_install_root())
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
        ui.warn("No bge-code-v1 model auto-detected. Semantic embedding features stay disabled by default.")
        opts.embed_auto = False

    opts.rollback_on_fail = _prompt_yes_no(
        "Rollback backed-up config files on failure?",
        default=True if not opts.rollback_on_fail else opts.rollback_on_fail,
    )

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
            f'  *":$IDA_PRO_MCP_HOME/.venv/bin:"*) ;;',
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


def install_ida_plugin(
    python_exe: Path,
    report: InstallReport,
    dry_run: bool,
) -> None:
    plugin_dir = get_ida_plugin_dir()
    loader_src, pkg_src = discover_installed_package_paths(python_exe)
    loader_dst = plugin_dir / "ida_mcp.py"
    pkg_dst = plugin_dir / "ida_mcp"
    if dry_run:
        report.add_step("plugin", "dry-run", f"would install to {plugin_dir}")
        return
    plugin_dir.mkdir(parents=True, exist_ok=True)
    _replace_with_symlink_or_copy(loader_src, loader_dst)
    _replace_with_symlink_or_copy(pkg_src, pkg_dst)
    report.add_modified(loader_dst)
    report.add_modified(pkg_dst)
    report.add_step("plugin", "ok", str(plugin_dir))


def install_codex_skills(source_root: Path, mode: str, report: InstallReport, dry_run: bool) -> None:
    if mode == "none":
        report.add_step("skills", "skipped", "skills mode set to none")
        return
    source_root_skills = source_root / ".agents" / "skills"
    if not source_root_skills.exists():
        report.add_warning("skills source not found; skipping")
        return
    selected = [p for p in source_root_skills.iterdir() if p.is_dir() and (p / "SKILL.md").exists()]
    if mode == "router":
        selected = [p for p in selected if p.name == "ida-tool-router"]
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
    parser.add_argument("--install-cli-shim", action="store_true", help="opt-in bashrc PATH shim installation")
    parser.add_argument("--rollback-on-fail", action="store_true", help="restore backed up config files if install fails")
    parser.add_argument("--runtime-source", choices=["auto", "local", "pypi"], default="auto", help="choose runtime package source")
    parser.add_argument("--embed-model", default="", help="explicit path to bge-code-v1 GGUF model")
    parser.add_argument("--embed-server-bin", default="", help="explicit path to llama-server binary")
    parser.add_argument("--embedder-doctor", action="store_true", help="diagnose local embedder/model/server setup")
    parser.add_argument("--setup-embedder", action="store_true", help="convenience mode to configure embedder with client setup")
    parser.add_argument(
        "--install-llama-server",
        action="store_true",
        help="download and install llama-server automatically when embed model is enabled/found",
    )
    parser.add_argument("--no-embed-auto", action="store_true", help="disable automatic embedder/server discovery")
    parser.add_argument("--skills-mode", choices=["router", "full", "none"], default="router", help="Codex skill installation mode")
    parser.add_argument("--capsule", default="", help="optional path to write installer metadata capsule (.sideband)")
    parser.add_argument("--only", action="append", choices=["runtime", "clients", "plugin", "skills", "shell"], default=[], help="run only selected install phases")
    parser.add_argument("--install-root", default="", help="override install root directory")
    args = parser.parse_args(argv)
    opts = InstallerOptions(
        dry_run=args.dry_run,
        yes=args.yes,
        kill_ida=args.kill_ida,
        install_cli_shim=args.install_cli_shim,
        rollback_on_fail=args.rollback_on_fail,
        runtime_source=args.runtime_source,
        skills_mode=args.skills_mode,
        interactive=True if args.interactive else (False if args.no_interactive else None),
        embed_auto=not args.no_embed_auto,
        embed_model_path=args.embed_model,
        embed_server_bin=args.embed_server_bin,
        install_llama_server=args.install_llama_server,
        embedder_doctor=args.embedder_doctor,
        setup_embedder=args.setup_embedder,
        capsule_path=Path(args.capsule).expanduser() if args.capsule else None,
        only=set(args.only),
    )
    if opts.setup_embedder:
        opts.embed_auto = True
        opts.install_llama_server = True
        if not opts.only:
            opts.only = {"clients"}
    opts.install_root = Path(args.install_root).expanduser() if args.install_root else get_install_root()
    opts.source_root = Path(__file__).resolve().parents[3]
    return opts


def _phase_enabled(opts: InstallerOptions, name: str) -> bool:
    return not opts.only or name in opts.only


def run_install(opts: InstallerOptions, ui: UI) -> int:
    report = InstallReport()
    install_root = opts.install_root or get_install_root()
    source_root = opts.source_root or Path.cwd()
    report.metadata.update({"install_root": str(install_root), "source_root": str(source_root)})

    try:
        opts = _run_interactive_wizard(opts, ui)
        ui.info("Starting installer")
        ui.info(f"Install root: {install_root}")
        embed_model = ""
        embed_server = ""
        if opts.dry_run:
            ui.warn("Running in dry-run mode")

        if opts.kill_ida:
            ui.info("Stopping IDA processes (--kill-ida enabled)")
            if not opts.dry_run:
                kill_ida_processes()
            report.add_step("kill_ida", "ok", "requested")
        else:
            report.add_step("kill_ida", "skipped", "not requested")

        python_exe = install_root / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        if _phase_enabled(opts, "runtime"):
            ui.info("Setting up runtime environment")
            python_exe = setup_runtime_environment(
                install_root=install_root,
                source_root=source_root,
                runtime_source=opts.runtime_source,
                dry_run=opts.dry_run,
                report=report,
            )
            report.add_step("runtime", "ok", str(python_exe))
            ui.ok("Runtime environment ready")
        else:
            report.add_step("runtime", "skipped", "filtered by --only")

        if _phase_enabled(opts, "clients"):
            ui.info("Configuring MCP clients")
            embed_model = opts.embed_model_path
            embed_server = opts.embed_server_bin
            if opts.embed_auto and not embed_model:
                embed_model = find_embed_model(install_root)
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
            server_cfg = build_stdio_config(
                python_exe,
                install_root,
                embed_model=embed_model,
                embed_server_bin=embed_server,
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

        if _phase_enabled(opts, "plugin"):
            ui.info("Installing IDA plugin")
            install_ida_plugin(python_exe=python_exe, report=report, dry_run=opts.dry_run)
            ui.ok("IDA plugin install complete")
        else:
            report.add_step("plugin", "skipped", "filtered by --only")

        if _phase_enabled(opts, "skills"):
            ui.info("Installing Codex skills")
            install_codex_skills(source_root, opts.skills_mode, report, opts.dry_run)
            ui.ok("Codex skills processed")
        else:
            report.add_step("skills", "skipped", "filtered by --only")

        if opts.install_cli_shim and _phase_enabled(opts, "shell"):
            ui.info("Installing shell CLI shim")
            install_bashrc_cli(install_root, opts.dry_run, report)
            report.add_step("shell", "ok", "bashrc updated")
            ui.ok("CLI shell shim installed")
        else:
            report.add_step("shell", "skipped", "not requested")

        idadir = detect_ida_install_dir()
        if idadir:
            report.metadata["idadir"] = str(idadir)

        report.finalize(True)
        report_path = install_root / "install-report.json"
        report.write(report_path)

        if opts.capsule_path and not opts.dry_run:
            from ida_pro_mcp.capsule import CapsuleStore

            with CapsuleStore.open(opts.capsule_path) as capsule:
                if not capsule.is_initialized():
                    capsule.init(
                        project_name=install_root.name,
                        created_by="ida-pro-mcp-installer",
                    )
                capsule.add_install_report(
                    {
                        "status": report.status,
                        "started_at": report.started_at,
                        "finished_at": report.finished_at,
                        "metadata": report.metadata,
                        "steps": report.steps,
                        "warnings": report.warnings,
                    }
                )
                capsule.upsert_backend_profile(
                    name="ida-primary",
                    kind="ida",
                    config={
                        "idadir": str(detect_ida_install_dir() or ""),
                        "status": "primary",
                    },
                )
                for client in report.metadata.get("configured_clients", []):
                    capsule.upsert_client_profile(
                        name=str(client),
                        kind="mcp-client",
                        config={"configured": True, "server": "ida-pro-mcp"},
                    )
                if embed_model:
                    capsule.add_embedding_state(
                        _build_embedder_capsule_state(
                            embed_model=embed_model,
                            embed_server=embed_server,
                        )
                    )
                capsule.add_audit_event(
                    "installer_completed",
                    {
                        "install_root": str(install_root),
                        "report_path": str(report_path),
                        "status": report.status,
                    },
                )

        ui.ok(f"Install complete. Report: {report_path}")
        return 0
    except Exception as exc:
        msg = f"Installation failed: {exc}"
        report.add_error(msg)
        ui.err(msg)
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

        if opts.capsule_path and not opts.dry_run:
            try:
                from ida_pro_mcp.capsule import CapsuleStore

                with CapsuleStore.open(opts.capsule_path) as capsule:
                    if not capsule.is_initialized():
                        capsule.init(project_name=(opts.install_root or get_install_root()).name, created_by="ida-pro-mcp-installer")
                    capsule.add_audit_event(
                        "installer_failed",
                        {
                            "install_root": str(opts.install_root or get_install_root()),
                            "report_path": str(report_path),
                            "error": msg,
                        },
                    )
            except Exception as cap_exc:
                ui.warn(f"Failed to write capsule failure event: {cap_exc}")
        return 1


def main(argv: list[str] | None = None) -> int:
    ui = UI()
    opts = parse_args(argv)
    if opts.embedder_doctor:
        return run_embedder_doctor(opts, ui)
    return run_install(opts, ui)


if __name__ == "__main__":
    raise SystemExit(main())
