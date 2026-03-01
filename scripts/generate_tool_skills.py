#!/usr/bin/env python3
"""
Generate Codex skill files from ida_mcp_stdio.py tool metadata.

Output:
  .agents/skills/ida-tool-router/SKILL.md
  .agents/tool-docs/ida-tool-<tool>.md
  .agents/skills/README.md
  .agents/tool-docs/README.md
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILE = REPO_ROOT / "ida_mcp_stdio.py"
SKILLS_ROOT = REPO_ROOT / ".agents" / "skills"
TOOL_DOCS_ROOT = REPO_ROOT / ".agents" / "tool-docs"
GEN_MARKER = "<!-- GENERATED: scripts/generate_tool_skills.py -->"


def _extract_literal_assignment(module: ast.Module, name: str) -> Any:
    value_node = None
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    value_node = node.value
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == name:
                value_node = node.value
    if value_node is None:
        raise RuntimeError(f"Could not find assignment for {name} in {SOURCE_FILE}")
    return ast.literal_eval(value_node)


def _eval_node(node: ast.AST, env: dict[str, Any]) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.List):
        return [_eval_node(x, env) for x in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_eval_node(x, env) for x in node.elts)
    if isinstance(node, ast.Dict):
        return {_eval_node(k, env): _eval_node(v, env) for k, v in zip(node.keys, node.values)}
    if isinstance(node, ast.Name):
        if node.id in env:
            return env[node.id]
        raise KeyError(f"Unknown name in AST eval: {node.id}")
    if isinstance(node, ast.Subscript):
        base = _eval_node(node.value, env)
        key = _eval_node(node.slice, env)
        return base[key]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _eval_node(node.left, env) + _eval_node(node.right, env)
    raise ValueError(f"Unsupported AST node in evaluator: {ast.dump(node, include_attributes=False)}")


def _extract_assignment_eval(module: ast.Module, name: str, env: dict[str, Any]) -> Any:
    value_node = None
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    value_node = node.value
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == name:
                value_node = node.value
    if value_node is None:
        raise RuntimeError(f"Could not find assignment for {name} in {SOURCE_FILE}")
    return _eval_node(value_node, env)


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9_-]+", "-", name.lower())


def _schema_type(schema: dict[str, Any]) -> str:
    st = schema.get("type")
    if isinstance(st, list):
        return "|".join(str(x) for x in st)
    if isinstance(st, str):
        return st
    if "enum" in schema:
        return "enum"
    return "any"


def _render_param(name: str, schema: dict[str, Any]) -> str:
    t = _schema_type(schema)
    enum = schema.get("enum")
    desc = schema.get("description", "").strip()
    bits = [f"- `{name}`: `{t}`"]
    if enum:
        if len(enum) <= 12:
            bits.append(f"allowed: `{', '.join(str(x) for x in enum)}`")
        else:
            bits.append(f"allowed_count: `{len(enum)}`")
    if desc:
        bits.append(desc)
    return " - ".join(bits)


def _render_tool_doc(
    tool_name: str,
    description: str,
    actions: list[str],
    arg_schema: dict[str, dict[str, Any]],
) -> str:
    lines: list[str] = []
    lines.append(f"# IDA MCP Tool Doc: `{tool_name}`")
    lines.append(GEN_MARKER)
    lines.append("")
    lines.append("## Purpose")
    lines.append(f"- Reference contract for the `{tool_name}` MCP tool.")
    lines.append("- Load this doc on demand from the router skill to minimize startup context.")
    lines.append("")
    lines.append("## Description")
    lines.append(description.strip() if description else "No description available.")
    lines.append("")
    lines.append("## Actions")
    if actions:
        lines.extend([f"- `{a}`" for a in actions])
    else:
        lines.append("- (none documented)")
    lines.append("- `grep` (host wrapper): run another action, then grep its output lines.")
    lines.append("")
    lines.append("## Parameters")
    if arg_schema:
        for key in sorted(arg_schema.keys()):
            lines.append(_render_param(key, arg_schema[key]))
    else:
        lines.append("- (tool takes action-only or dynamic args)")
    lines.append("")
    lines.append("## Invocation Guidance")
    lines.append("- Prefer compact responses first, then zoom in with narrower arguments.")
    lines.append("- Use `offset`/`limit` style pagination where supported.")
    lines.append("- If action is unclear, start with read-only/discovery actions before write actions.")
    lines.append("")
    return "\n".join(lines).strip() + "\n"


def _render_router_skill(tools: list[str]) -> str:
    lines: list[str] = []
    lines.append("---")
    lines.append('name: "ida-tool-router"')
    lines.append('description: "Use to select the correct per-tool IDA MCP tool doc and avoid loading all tool docs at once."')
    lines.append("metadata:")
    lines.append('  short-description: "Route to one tool skill"')
    lines.append("---")
    lines.append("")
    lines.append("# IDA MCP Tool Router Skill")
    lines.append(GEN_MARKER)
    lines.append("")
    lines.append("## Purpose")
    lines.append("Load only one tool doc at a time to keep context small.")
    lines.append("")
    lines.append("## How To Use")
    lines.append("- Identify the intended tool name from the user request.")
    lines.append("- Open only `.agents/tool-docs/ida-tool-<tool>.md` for that tool.")
    lines.append("- Avoid opening unrelated tool docs to keep context small.")
    lines.append("")
    lines.append("## Resolution Rules")
    lines.append("- Default doc filename: `ida-tool-<tool>.md`")
    lines.append("- Example: tool `search` -> `.agents/tool-docs/ida-tool-search.md`")
    lines.append("- Alias: `xfer_analysis` -> `ida-tool-xfer_analysis.md`")
    lines.append("- If unsure, list docs under `.agents/tool-docs/` and pick exact match.")
    lines.append("")
    lines.append("## Available Tool Count")
    lines.append(f"- `{len(tools)}`")
    lines.append("")
    return "\n".join(lines).strip() + "\n"


def _write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _cleanup_old_generated(root: Path) -> None:
    if not root.exists():
        return
    for child in root.iterdir():
        if not child.is_dir():
            continue
        if child.name.startswith("ida-tool-"):
            skill_file = child / "SKILL.md"
            if skill_file.exists():
                text = skill_file.read_text(encoding="utf-8", errors="ignore")
                if GEN_MARKER in text:
                    for p in sorted(child.rglob("*"), reverse=True):
                        if p.is_file():
                            p.unlink()
                        elif p.is_dir():
                            try:
                                p.rmdir()
                            except OSError:
                                pass
                    try:
                        child.rmdir()
                    except OSError:
                        pass


def _cleanup_old_generated_docs(root: Path) -> None:
    if not root.exists():
        return
    for doc in root.glob("ida-tool-*.md"):
        try:
            text = doc.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if GEN_MARKER in text:
            try:
                doc.unlink()
            except OSError:
                pass


def main() -> None:
    source_text = SOURCE_FILE.read_text(encoding="utf-8")
    module = ast.parse(source_text, filename=str(SOURCE_FILE))

    tool_descriptions: dict[str, str] = _extract_literal_assignment(module, "TOOL_DESCRIPTIONS")
    tool_actions: dict[str, list[str]] = _extract_literal_assignment(module, "TOOL_ACTIONS")
    tool_arg_schemas: dict[str, dict[str, dict[str, Any]]] = _extract_assignment_eval(
        module, "TOOL_ARG_SCHEMAS", {"TOOL_ACTIONS": tool_actions}
    )
    tools: list[str] = _extract_literal_assignment(module, "TOOLS")

    # Preserve advertised order from TOOLS list, then append any extras from descriptions.
    ordered_tools = []
    seen = set()
    for t in tools:
        if t not in seen:
            ordered_tools.append(t)
            seen.add(t)
    for t in sorted(tool_descriptions.keys()):
        if t not in seen:
            ordered_tools.append(t)
            seen.add(t)

    _cleanup_old_generated(SKILLS_ROOT)
    _cleanup_old_generated_docs(TOOL_DOCS_ROOT)

    for tool in ordered_tools:
        doc_file = TOOL_DOCS_ROOT / f"ida-tool-{_slug(tool)}.md"
        content = _render_tool_doc(
            tool_name=tool,
            description=tool_descriptions.get(tool, ""),
            actions=tool_actions.get(tool, []),
            arg_schema=tool_arg_schemas.get(tool, {}),
        )
        _write_file(doc_file, content)

    router_dir = SKILLS_ROOT / "ida-tool-router"
    _write_file(
        router_dir / "SKILL.md",
        _render_router_skill(ordered_tools),
    )

    readme = [
        "# Generated IDA Tool Skills",
        GEN_MARKER,
        "",
        "- Source: `ida_mcp_stdio.py` (`TOOL_DESCRIPTIONS`, `TOOL_ACTIONS`, `TOOL_ARG_SCHEMAS`)",
        "- Generator: `scripts/generate_tool_skills.py`",
        "",
        "## Regenerate",
        "```bash",
        "python3 scripts/generate_tool_skills.py",
        "```",
        "",
        "## Generated Skill Count",
        "`1` router skill (`ida-tool-router`)",
        "",
        "## Generated Tool Doc Count",
        f"`{len(ordered_tools)}` per-tool docs",
        "",
        "## Notes",
        "- Keep only one skill loaded (`ida-tool-router`) to avoid startup skill-list bloat.",
        "- Per-tool docs are plain markdown in `.agents/tool-docs/` and loaded on demand.",
        "- Edit source metadata in `ida_mcp_stdio.py`, then regenerate.",
        "",
        "## Manifest",
        "```json",
        json.dumps(
            {
                "tool_count": len(ordered_tools),
                "skills_root": str(SKILLS_ROOT.relative_to(REPO_ROOT)),
                "router_skill": str((router_dir / "SKILL.md").relative_to(REPO_ROOT)),
                "tool_docs_root": str(TOOL_DOCS_ROOT.relative_to(REPO_ROOT)),
            },
            indent=2,
        ),
        "```",
        "",
    ]
    _write_file(SKILLS_ROOT / "README.md", "\n".join(readme))

    docs_readme = [
        "# Generated IDA Tool Docs",
        GEN_MARKER,
        "",
        "- Source: `ida_mcp_stdio.py` metadata",
        "- Generator: `scripts/generate_tool_skills.py`",
        "",
        "These are per-tool reference docs intentionally not exposed as skills.",
        "",
        "## Count",
        f"`{len(ordered_tools)}` docs",
        "",
    ]
    _write_file(TOOL_DOCS_ROOT / "README.md", "\n".join(docs_readme))
    print(
        f"Generated router skill under {SKILLS_ROOT} and "
        f"{len(ordered_tools)} tool docs under {TOOL_DOCS_ROOT}"
    )


if __name__ == "__main__":
    main()
