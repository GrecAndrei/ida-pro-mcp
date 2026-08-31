"""Install the same action-specific IDA skill for Claude Code and OpenCode."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from ida_pro_mcp.host.agent_operations import (
    render_agent_operations_markdown,
    render_agent_skill_markdown,
)
from ida_pro_mcp.installer.common import atomic_write_text, reject_symlink_path

SKILL_NAME = "ida-pro-mcp"


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
            reference_file.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(skill_file, render_agent_skill_markdown())
            atomic_write_text(reference_file, render_agent_operations_markdown())
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
