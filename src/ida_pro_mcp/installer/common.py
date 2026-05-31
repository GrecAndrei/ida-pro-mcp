from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class InstallerOptions:
    dry_run: bool = False
    yes: bool = False
    kill_ida: bool = False
    install_cli_shim: bool = False
    rollback_on_fail: bool = False
    runtime_source: str = "auto"
    skills_mode: str = "router"
    interactive: bool | None = None
    embed_auto: bool = True
    embed_model_path: str = ""
    embed_server_bin: str = ""
    install_llama_server: bool = False
    embedder_doctor: bool = False
    setup_embedder: bool = False
    capsule_path: Path | None = None
    only: set[str] = field(default_factory=set)
    install_root: Path | None = None
    source_root: Path | None = None


@dataclass
class InstallReport:
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None
    status: str = "running"
    steps: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    backups: list[dict[str, str]] = field(default_factory=list)
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

    def add_modified(self, path: Path) -> None:
        self.modified_files.append(str(path))

    def finalize(self, success: bool) -> None:
        self.status = "ok" if success else "failed"
        self.finished_at = datetime.now(timezone.utc).isoformat()

    def write(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "steps": self.steps,
            "warnings": self.warnings,
            "errors": self.errors,
            "backups": self.backups,
            "modified_files": self.modified_files,
            "metadata": self.metadata,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
