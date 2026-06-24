"""Generate and install Claude Code / OpenCode skills from TOOL_DESCRIPTIONS."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# Category metadata — title, description, IDA analogy shown in the skill
# ---------------------------------------------------------------------------
_CATEGORY_META: Dict[str, Tuple[str, str]] = {
    "core": (
        "ida-core",
        "Core session and navigation tools — start here. Covers session lifecycle, "
        "bookmarks, batch calls, and response truncation.",
    ),
    "analysis": (
        "ida-analysis",
        "Primary analysis tools: decompile, disassemble, search, edit data, manage "
        "functions, types, segments, memory, and run calculations.",
    ),
    "security": (
        "ida-security",
        "Security-focused tools: classify functions, find gadgets, detect crypto, "
        "analyze ABI/stack, deobfuscate, and scan for vulnerabilities.",
    ),
    "advanced": (
        "ida-advanced",
        "Advanced IDA tools: ctree AST, microcode IR, CFG/call graphs, import "
        "analysis, export, history/undo, and data representation.",
    ),
    "debug": (
        "ida-debug",
        "Debugging and tracing tools: debugger control, coverage import, and "
        "execution trace analysis.",
    ),
    "other": (
        "ida-workflow",
        "Workflow and intelligence tools: blackboard knowledge base, firmware "
        "triage, intelligence/embeddings, governance, taint analysis, and "
        "multi-step workflows.",
    ),
    "project": (
        "ida-project",
        "Project management tools: save/load IDB, run scripts, and access recent files.",
    ),
}

_PREAMBLE = """\
---
name: {name}
description: "{description}"
---

# {title}

{body}
"""

_AUTOGEN_NOTE = "> Auto-generated from TOOL_DESCRIPTIONS. Re-run `ida-pro-mcp-install --install-skills` to refresh.\n\n"

_START_SKILL_NAME = "ida-start"
_START_SKILL_DESC = (
    "IDA Pro MCP orientation: first-turn playbook, tool map, and key shortcuts. "
    "Run this at the start of any RE session."
)
_START_SKILL_BODY = """\
## First turn
```
session(action='create', binary_path='path/to/binary')
llm_helpers(action='bootstrap')
```

## Key shortcuts mapped to tools
| IDA key | Tool + action |
|---------|--------------|
| P | `funcs(action='create', addr=..., _risk_ack=true)` |
| D | `data_ops(action='cycle_data', addr=..., _risk_ack=true)` |
| A | `data_ops(action='make_string', addr=..., _risk_ack=true)` |
| U | `data_ops(action='undefine', addr=..., size=N, _risk_ack=true)` |
| C | `data_ops(action='make_code', addr=..., _risk_ack=true)` |
| F5 | `code(action='decompile', addr=...)` |
| X | `code(action='xrefs_to', addr=...)` |
| N | `modify(action='rename', addr=..., name=..., _risk_ack=true)` |
| ; | `modify(action='comment', addr=..., comment=..., _risk_ack=true)` |
| G | `nav(action='goto', addr=...)` |

## Tool categories
- **ida-core** — session, batch, bookmarks, truncation
- **ida-analysis** — decompile, search, data, funcs, types, modify
- **ida-security** — classify, gadgets, crypto, ABI, deobfuscate
- **ida-advanced** — ctree, microcode, graph, imports, export, history
- **ida-debug** — debugger, coverage, traces
- **ida-workflow** — blackboard, firmware, intelligence, taint, governance

## Write operations
All write ops require `_risk_ack=true`. Pass it to skip the governance gate.

## Compact vs full mode
Default is compact (less tokens). Add `_response_mode='full'` for raw output.
"""


def _make_tool_entry(tool: str, description: str) -> str:
    return f"### `{tool}`\n{description}\n"


def generate_skills(
    category_filter: List[str] | None = None,
) -> Dict[str, str]:
    """
    Return {skill_name: skill_content} for all skills.
    category_filter limits to specific categories if given.
    """
    # Import here so this module is importable without the full host stack
    try:
        from ida_pro_mcp.host.schemas_data import TOOL_DESCRIPTIONS
        from ida_pro_mcp.host.schemas import classify_tool_category
    except ImportError:
        # Fall back to minimal stubs when running outside the package
        TOOL_DESCRIPTIONS = {}  # type: ignore[assignment]
        def classify_tool_category(t: str) -> str:  # type: ignore[misc]
            return "other"

    # Group tools by category
    by_cat: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    for tool, desc in sorted(TOOL_DESCRIPTIONS.items()):
        cat = classify_tool_category(tool)
        by_cat[cat].append((tool, desc))

    skills: Dict[str, str] = {}

    # One skill per category
    for cat, tools in by_cat.items():
        if category_filter and cat not in category_filter:
            continue
        meta = _CATEGORY_META.get(cat)
        if not meta:
            skill_name = f"ida-{cat}"
            skill_desc = f"IDA Pro MCP tools — {cat} category."
        else:
            skill_name, skill_desc = meta

        title = skill_desc.split(".")[0]
        body = _AUTOGEN_NOTE + "\n".join(_make_tool_entry(t, d) for t, d in tools)
        content = _PREAMBLE.format(
            name=skill_name,
            description=skill_desc.replace('"', '\\"'),
            title=title,
            body=body,
        )
        skills[skill_name] = content

    # Orientation skill — hand-written body, no autogen note
    skills[_START_SKILL_NAME] = _PREAMBLE.format(
        name=_START_SKILL_NAME,
        description=_START_SKILL_DESC.replace('"', '\\"'),
        title="IDA Pro MCP — Quick Start",
        body=_START_SKILL_BODY,
    )

    return skills


def install_skills(
    target_dirs: List[Path],
    dry_run: bool = False,
    category_filter: List[str] | None = None,
) -> Dict[str, List[Path]]:
    """
    Write skills to each target directory.
    Returns {skill_name: [paths_written]}.
    """
    skills = generate_skills(category_filter=category_filter)
    written: Dict[str, List[Path]] = defaultdict(list)

    for target_dir in target_dirs:
        for skill_name, content in skills.items():
            skill_dir = target_dir / skill_name
            skill_file = skill_dir / "SKILL.md"
            if not dry_run:
                skill_dir.mkdir(parents=True, exist_ok=True)
                skill_file.write_text(content, encoding="utf-8")
            written[skill_name].append(skill_file)

    return written


def default_skill_dirs() -> List[Path]:
    """Standard skill directories for Claude Code and OpenCode."""
    home = Path.home()
    import os
    xdg = Path(os.environ.get("XDG_CONFIG_HOME", str(home / ".config")))
    return [
        home / ".claude" / "skills",           # Claude Code (global)
        xdg / "opencode" / "skills",           # OpenCode (global)
    ]
