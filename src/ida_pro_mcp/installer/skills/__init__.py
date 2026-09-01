"""Install the same action-specific IDA skill for Claude Code and OpenCode."""

from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from collections import defaultdict
from pathlib import Path

from ida_pro_mcp.host.agent_operations import (
    render_agent_operations_markdown,
    render_agent_skill_markdown,
)
from ida_pro_mcp.installer.common import atomic_write_text, reject_symlink_path

SKILL_NAME = "ida-pro-mcp"


def _publish_skill(skill_dir: Path, skill_text: str, reference_text: str) -> None:
    """Publish both generated skill files as one directory replacement.

    Existing user-created files under the skill directory are copied into the
    staging tree and retained.  Replacing the directory only after both
    generated files are ready prevents a failed refresh from leaving a
    playbook paired with a different operations reference.
    """
    reject_symlink_path(skill_dir, "skill installation path")
    if skill_dir.exists() and not skill_dir.is_dir():
        raise RuntimeError(f"Skill installation path is not a directory: {skill_dir}")
    parent = skill_dir.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(tempfile.mkdtemp(prefix=f".{skill_dir.name}.staging-", dir=str(parent)))
    staged = staging_root / skill_dir.name
    try:
        if skill_dir.exists():
            shutil.copytree(skill_dir, staged, symlinks=True)
        else:
            staged.mkdir()

        staged_skill = staged / "SKILL.md"
        staged_reference = staged / "references" / "operations.md"
        # A user-created link at either managed location must not turn the
        # staging write into a write through to an external target.
        for managed in (staged_skill, staged_reference, staged_reference.parent):
            if managed.is_symlink():
                managed.unlink()
        staged_reference.parent.mkdir(parents=True, exist_ok=True)
        reject_symlink_path(staged_skill, "staged skill installation path")
        reject_symlink_path(staged_reference, "staged skill reference path")
        atomic_write_text(staged_skill, skill_text)
        atomic_write_text(staged_reference, reference_text)

        backup: Path | None = None
        if skill_dir.exists():
            backup = parent / f".{skill_dir.name}.backup-{os.getpid()}-{uuid.uuid4().hex}"
            os.replace(skill_dir, backup)
        try:
            os.replace(staged, skill_dir)
        except BaseException:
            if backup is not None and not skill_dir.exists():
                os.replace(backup, skill_dir)
            raise
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)


def install_skills(
    target_dirs: list[Path],
    dry_run: bool = False,
    category_filter: list[str] | None = None,
) -> dict[str, list[Path]]:
    """Install the playbook and its reference together for each client.

    Publishing one target is atomic in ``_publish_skill``. The surrounding
    transaction also restores earlier targets if a later client directory
    cannot be published, so Claude/OpenCode setup cannot stop half-installed.
    """
    del category_filter
    written: dict[str, list[Path]] = defaultdict(list)
    targets: list[tuple[Path, Path, Path]] = []
    for target_dir in target_dirs:
        skill_dir = target_dir / SKILL_NAME
        skill_file = skill_dir / "SKILL.md"
        reference_file = skill_dir / "references" / "operations.md"
        reject_symlink_path(skill_file, "skill installation path")
        reject_symlink_path(reference_file, "skill reference installation path")
        targets.append((skill_dir, skill_file, reference_file))

    if not dry_run:
        skill_text = render_agent_skill_markdown()
        reference_text = render_agent_operations_markdown()
        backups: list[tuple[Path, Path | None]] = []
        published: list[Path] = []
        try:
            # Snapshot every existing destination before publishing any target.
            # Backups live beside their original directory so restoration stays
            # on the same filesystem and remains atomic.
            for skill_dir, _skill_file, _reference_file in targets:
                backup: Path | None = None
                if skill_dir.exists():
                    backup = skill_dir.parent / (
                        f".{skill_dir.name}.transaction-backup-"
                        f"{os.getpid()}-{uuid.uuid4().hex}"
                    )
                    shutil.copytree(skill_dir, backup, symlinks=True)
                backups.append((skill_dir, backup))

            for skill_dir, _skill_file, _reference_file in targets:
                _publish_skill(skill_dir, skill_text, reference_text)
                published.append(skill_dir)
        except BaseException:
            rollback_error: BaseException | None = None
            for skill_dir in reversed(published):
                backup = next(
                    (candidate for target, candidate in backups if target == skill_dir),
                    None,
                )
                try:
                    reject_symlink_path(skill_dir, "skill installation path")
                    if skill_dir.is_dir() and not skill_dir.is_symlink():
                        shutil.rmtree(skill_dir)
                    elif skill_dir.exists() or skill_dir.is_symlink():
                        skill_dir.unlink()
                    if backup is not None:
                        os.replace(backup, skill_dir)
                except BaseException as exc:
                    rollback_error = exc
                    break
            if rollback_error is not None:
                raise RuntimeError(
                    "skill installation failed and rollback was incomplete"
                ) from rollback_error
            raise
        finally:
            for _skill_dir, backup in backups:
                if backup is not None and (backup.exists() or backup.is_symlink()):
                    if backup.is_dir() and not backup.is_symlink():
                        shutil.rmtree(backup, ignore_errors=True)
                    else:
                        backup.unlink(missing_ok=True)

    for _skill_dir, skill_file, reference_file in targets:
        # Report both files so callers count (and back up / roll back) the
        # reference document too, not just SKILL.md.
        written[SKILL_NAME].append(skill_file)
        written[SKILL_NAME].append(reference_file)
    return written


def default_skill_dirs() -> list[Path]:
    """Standard skill directories for Claude Code and OpenCode."""
    import os

    home = Path.home()
    xdg = Path(
        os.path.expandvars(
            os.path.expanduser(
                os.environ.get("XDG_CONFIG_HOME", "").strip() or str(home / ".config")
            )
        )
    )
    return [
        home / ".claude" / "skills",
        xdg / "opencode" / "skills",
    ]
