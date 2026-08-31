from __future__ import annotations

import contextlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _atomic_write(path: Path, payload: bytes) -> None:
    """Replace *path* atomically, keeping partial writes out of user files."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        mode = 0o600
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-", dir=str(path.parent)
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
        if os.name != "nt":
            with contextlib.suppress(OSError):
                directory_fd = os.open(path.parent, os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary_path.unlink()
        raise


def atomic_write_text(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Write text through a same-directory temporary file and rename."""
    _atomic_write(path, content.encode(encoding))


def atomic_write_bytes(path: Path, content: bytes) -> None:
    """Write bytes through a same-directory temporary file and rename."""
    _atomic_write(path, content)


@dataclass
class InstallerOptions:
    dry_run: bool = False
    yes: bool = False
    kill_ida: bool = False
    install_cli_shim: bool = False
    rollback_on_fail: bool = False
    runtime_source: str = "auto"
    skills_mode: str = "agent"
    install_claude_skills: bool = True  # install skills for Claude Code / OpenCode
    interactive: bool | None = None
    embed_auto: bool = True
    embed_profile: str = "qwen3-embedding-0.6b"
    embed_backend: str = "qwen3-embedding-0.6b"  # qwen3-embedding-0.6b | bge-code-v1 | zembed-1 | gemini
    gemini_access: str = "aistudio"  # aistudio | vertex
    gemini_api_key: str = ""
    gemini_vertex_project: str = ""
    gemini_vertex_location: str = "us-central1"
    gemini_install_auth: bool = False
    gemini_dim: int = 768
    gemini_model: str = "gemini-embedding-2"
    embed_model_path: str = ""
    embed_server_bin: str = ""
    install_llama_server: bool = False
    download_embed_model: bool = False
    accept_model_license: bool = False
    rerank_profile: str = "qwen3-reranker-0.6b"  # qwen3-reranker-0.6b | qwen3-reranker-4b | bge-reranker-v2-gemma | bge-reranker-v2-m3
    rerank_model_path: str = ""
    download_rerank_model: bool = False
    rerank_disabled: bool = False  # user explicitly declined the reranker; emit IDA_MCP_RERANK_DISABLED=1
    embedder_doctor: bool = False
    setup_embedder: bool = False
    only: set[str] = field(default_factory=set)
    install_root: Path | None = None
    source_root: Path | None = None
    # IDA install selection (9.2 ↔ 9.3 multi-install support)
    ida_dir: str = ""  # explicit path override
    ida_version: str = ""  # explicit version override (e.g. "9.3" or "9.3.260421")
    no_ida_prompt: bool = False  # don't prompt; pick highest-version automatically
    disable_policy: bool = False  # set IDA_MCP_POLICY_MODE=off in the spawned server
    # Session runtime backend: idat (default, crash-isolated per-session
    # processes) or idalib (experimental in-process kernel; needs the idapro
    # whl + activation on the chosen 9.3+ install). Written into the client
    # config env as IDA_MCP_RUNTIME.
    ida_runtime: str = "idat"  # idat | idalib
    # r2/Rizin engine (paper §8.2 item 11) — Phase 1 locates an existing
    # rz/r2 on PATH and records it as IDA_MCP_R2_BIN in the generated client
    # config; it does NOT download a pinned release (documented follow-up,
    # mirroring the llama.cpp pin discipline).
    with_r2: bool = False  # --with-r2: resolve + record rz/r2 into the client config
    # Signature-pack staging (paper §10.2 item 5e) — copies *.sig / *.sig.gz
    # from a source dir into <IDADIR>/sig, closing "nothing installs a RISC-V
    # .sig pack".
    sigs_dir: str = ""  # --sigs <dir>: stage a FLIRT sig pack into IDA's sig dir
    ida_binary_path: str = ""  # optional --kill-ida executable scope
    allow_unverified_downloads: bool = False  # explicit supply-chain escape hatch
    verify_bron_corpus: bool = False  # require per-source BRON SHA-256 env vars


@dataclass
class InstallReport:
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    finished_at: str | None = None
    status: str = "running"
    steps: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    backups: list[dict[str, str]] = field(default_factory=list)
    created_files: list[str] = field(default_factory=list)
    modified_files: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_step(self, name: str, status: str, detail: str = "") -> None:
        self.steps.append({"name": name, "status": status, "detail": detail})

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def add_error(self, message: str) -> None:
        self.errors.append(message)

    def add_backup(self, target: Path, backup: Path) -> None:
        self.backups.append({"target": str(target), "backup": str(backup)})

    def add_created(self, path: Path) -> None:
        """Record a file that did not exist before this install."""
        value = str(path)
        if value not in self.created_files:
            self.created_files.append(value)

    def add_modified(self, path: Path) -> None:
        self.modified_files.append(str(path))

    def finalize(self, success: bool) -> None:
        self.status = "ok" if success else "failed"
        self.finished_at = datetime.now(UTC).isoformat()

    def write(self, path: Path) -> None:
        payload = {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "steps": self.steps,
            "warnings": self.warnings,
            "errors": self.errors,
            "backups": self.backups,
            "created_files": self.created_files,
            "modified_files": self.modified_files,
            "metadata": self.metadata,
        }
        atomic_write_text(path, json.dumps(payload, indent=2))


def find_ida_sig_dir(ida_dir: Path) -> Path:
    """Return IDA's signature directory for an install.

    The host MCP ``ida_list_sigs`` op globs ``<IDADIR>/sig/**/*.sig``
    recursively (``ida_mcp/tools/misc.py``), so ``<ida_dir>/sig`` is the
    canonical staging target for a FLIRT sig pack.  The directory may not
    exist yet — staging creates it.
    """
    return Path(ida_dir) / "sig"


@dataclass
class SigsManifest:
    """Record of what the installer staged (or would stage) into IDA's sig dir.

    ``staged`` holds absolute destination paths of every signature file that
    was (dry_run) or would be (real) copied; ``skipped`` holds destinations
    that already existed and were deliberately not overwritten so a sig pack
    can never clobber IDA's bundled signatures.
    """

    source: str
    sig_dir: str
    staged: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    dry_run: bool = False

    @property
    def count(self) -> int:
        return len(self.staged)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "sig_dir": self.sig_dir,
            "staged": list(self.staged),
            "skipped": list(self.skipped),
            "dry_run": self.dry_run,
            "count": self.count,
        }
