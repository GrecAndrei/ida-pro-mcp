"""Install the same action-specific IDA skill for Claude Code and OpenCode."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from ida_pro_mcp.host.agent_operations import (
    render_agent_operations_markdown,
    render_agent_skill_markdown,
)

SKILL_NAME = "ida-pro-mcp"


def generate_skills(category_filter: list[str] | None = None) -> dict[str, str]:
    """Return the one portable skill; category filtering is obsolete.

    The argument remains accepted so older installer callers do not fail, but
    the MCP operation registry—not a hand-curated category split—is the
    contract every agent receives.
    """
    del category_filter
    return {SKILL_NAME: render_agent_skill_markdown()}


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
        if not dry_run:
            reference_file.parent.mkdir(parents=True, exist_ok=True)
            skill_file.write_text(render_agent_skill_markdown(), encoding="utf-8")
            reference_file.write_text(render_agent_operations_markdown(), encoding="utf-8")
        written[SKILL_NAME].append(skill_file)
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
