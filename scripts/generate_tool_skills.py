#!/usr/bin/env python3
"""
Generate Codex skill files from ida_mcp_stdio.py tool metadata.

Output:
  .agents/skills/ida-tool-<tool>/SKILL.md
  .agents/skills/ida-tool-router/SKILL.md
  .agents/skills/README.md
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


def _render_tool_skill(
    tool_name: str,
    description: str,
    actions: list[str],
    arg_schema: dict[str, dict[str, Any]],
) -> str:
    lines: list[str] = []
    lines.append("# IDA MCP Tool Skill")
    lines.append(GEN_MARKER)
    lines.append("")
    lines.append(f"## Tool")
    lines.append(f"`{tool_name}`")
    lines.append("")
    lines.append("## Use This Skill When")
    lines.append(f"- You need to call the `{tool_name}` tool.")
    lines.append("- You want exact action/parameter contract without scanning global tool metadata.")
    lines.append("")
    lines.append("## Description")
    lines.append(description.strip() if description else "No description available.")
    lines.append("")
    lines.append("## Actions")
    if actions:
        lines.extend([f"- `{a}`" for a in actions])
    else:
        lines.append("- (none documented)")
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


def _render_router_skill(
    tools: list[str],
    descriptions: dict[str, str],
    actions: dict[str, list[str]],
) -> str:
    lines: list[str] = []
    lines.append("# IDA MCP Tool Router Skill")
    lines.append(GEN_MARKER)
    lines.append("")
    lines.append("## Purpose")
    lines.append("Route to the specific per-tool skill instead of loading all tool docs.")
    lines.append("")
    lines.append("## How To Use")
    lines.append("- Identify the intended tool name from the user request.")
    lines.append("- Open only `.agents/skills/ida-tool-<tool>/SKILL.md` for that tool.")
    lines.append("- Avoid opening unrelated tool skills to keep context small.")
    lines.append("")
    lines.append("## Tool Index")
    for t in tools:
        d = descriptions.get(t, "").strip()
        d = re.sub(r"\s+", " ", d)
        if len(d) > 120:
            d = d[:117] + "..."
        act = actions.get(t, [])
        act_str = ", ".join(act[:8])
        if len(act) > 8:
            act_str += ", ..."
        lines.append(f"- `{t}`: {d} | actions: {act_str if act_str else 'n/a'}")
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

    for tool in ordered_tools:
        skill_dir = SKILLS_ROOT / f"ida-tool-{_slug(tool)}"
        content = _render_tool_skill(
            tool_name=tool,
            description=tool_descriptions.get(tool, ""),
            actions=tool_actions.get(tool, []),
            arg_schema=tool_arg_schemas.get(tool, {}),
        )
        _write_file(skill_dir / "SKILL.md", content)

    router_dir = SKILLS_ROOT / "ida-tool-router"
    _write_file(
        router_dir / "SKILL.md",
        _render_router_skill(ordered_tools, tool_descriptions, tool_actions),
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
        f"## Generated Skill Count",
        f"`{len(ordered_tools) + 1}` (`{len(ordered_tools)}` per-tool + router)",
        "",
        "## Notes",
        "- These skills are intended to reduce prompt/context churn by loading tool docs on demand.",
        "- Edit source metadata in `ida_mcp_stdio.py`, then regenerate.",
        "",
        "## Manifest",
        "```json",
        json.dumps(
            {
                "tool_count": len(ordered_tools),
                "skills_root": str(SKILLS_ROOT.relative_to(REPO_ROOT)),
                "router_skill": str((router_dir / "SKILL.md").relative_to(REPO_ROOT)),
            },
            indent=2,
        ),
        "```",
        "",
    ]
    _write_file(SKILLS_ROOT / "README.md", "\n".join(readme))
    print(f"Generated {len(ordered_tools)} tool skills + router under {SKILLS_ROOT}")


if __name__ == "__main__":
    main()
