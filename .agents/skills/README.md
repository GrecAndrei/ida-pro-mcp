# Generated IDA Tool Skills
<!-- GENERATED: scripts/generate_tool_skills.py -->

- Source: `ida_mcp_stdio.py` (`TOOL_DESCRIPTIONS`, `TOOL_ACTIONS`, `TOOL_ARG_SCHEMAS`)
- Generator: `scripts/generate_tool_skills.py`

## Regenerate
```bash
python3 scripts/generate_tool_skills.py
```

## Generated Skill Count
`67` (`66` per-tool + router)

## Notes
- These skills are intended to reduce prompt/context churn by loading tool docs on demand.
- Edit source metadata in `ida_mcp_stdio.py`, then regenerate.

## Manifest
```json
{
  "tool_count": 66,
  "skills_root": ".agents/skills",
  "router_skill": ".agents/skills/ida-tool-router/SKILL.md"
}
```
