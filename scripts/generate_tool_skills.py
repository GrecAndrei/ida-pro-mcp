#!/usr/bin/env python3
"""Generate the installable IDA MCP skill from the public operation contract.

The MCP schema is sufficient to call every advertised operation.  This skill
adds a compact workflow playbook and an optional reference file; it is not a
second, divergent tool registry.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from ida_pro_mcp.host.agent_operations import (  # noqa: E402
    list_agent_operations,
    render_agent_operations_markdown,
    render_agent_skill_markdown,
)

SKILLS_ROOT = REPO_ROOT / ".agents" / "skills"
SKILL_NAME = "ida-pro-mcp"
SKILL_ROOT = SKILLS_ROOT / SKILL_NAME
REFERENCE_PATH = SKILL_ROOT / "references" / "operations.md"
DOC_REFERENCE_PATH = REPO_ROOT / "docs" / "TOOLS_REFERENCE.md"
GEN_MARKER = "<!-- GENERATED: scripts/generate_tool_skills.py -->"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _skill_content() -> str:
    return render_agent_skill_markdown().replace(
        "# IDA Pro MCP\n", f"# IDA Pro MCP\n{GEN_MARKER}\n", 1
    )


def _reference_content() -> str:
    return render_agent_operations_markdown().replace(
        "# IDA MCP Agent Operations\n", f"# IDA MCP Agent Operations\n{GEN_MARKER}\n", 1
    )


def _readme_content() -> str:
    return f'''# IDA MCP Agent Skill
{GEN_MARKER}

`ida-pro-mcp` is the only generated Codex skill. Its `references/` directory
is installed with the skill, so its guidance remains available outside this
checkout.

The repository instructions live in `AGENTS.md`. This generated skill only
contains the agent-facing MCP workflow and operation reference.

Regenerate after changing `src/ida_pro_mcp/host/agent_operations.py`:

```text
python scripts/generate_tool_skills.py
```
'''


def _remove_obsolete_generated_layout() -> None:
    """Remove the router/docs split that could not survive installation."""
    old_router = SKILLS_ROOT / "ida-tool-router"
    old_docs = REPO_ROOT / ".agents" / "tool-docs"
    for path in (old_router, old_docs):
        if path.exists():
            shutil.rmtree(path)


def main() -> int:
    _remove_obsolete_generated_layout()
    _write(SKILL_ROOT / "SKILL.md", _skill_content())
    reference = _reference_content()
    _write(REFERENCE_PATH, reference)
    _write(DOC_REFERENCE_PATH, reference)
    _write(SKILLS_ROOT / "README.md", _readme_content())
    print(f"Generated {SKILL_ROOT.relative_to(REPO_ROOT)} from {len(list_agent_operations())} agent operations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
