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
    """Install the playbook and its reference together for each client."""
    del category_filter
    written: dict[str, list[Path]] = defaultdict(list)
    for target_dir in target_dirs:
        skill_dir = target_dir / SKILL_NAME
        skill_file = skill_dir / "SKILL.md"
        reference_file = skill_dir / "references" / "operations.md"
        reject_symlink_path(skill_file, "skill installation path")
        reject_symlink_path(reference_file, "skill reference installation path")
        if not dry_run:
            _publish_skill(
                skill_dir,
                render_agent_skill_markdown(),
                render_agent_operations_markdown(),
            )
        # Report both files so callers count (and back up / roll back) the
        # reference document too, not just SKILL.md.
        written[SKILL_NAME].append(skill_file)
        written[SKILL_NAME].append(reference_file)
    return written


def default_skill_dirs() -> list[Path]:
    """Standard skill directories for Claude Code and OpenCode."""
    import os

    home = Path.home()
    xdg = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))
    return [
        home / ".claude" / "skills",
        xdg / "opencode" / "skills",
    ]
