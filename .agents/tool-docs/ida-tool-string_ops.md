# IDA MCP Tool Doc: `string_ops`
<!-- GENERATED: scripts/generate_tool_skills.py -->

## Purpose
- Reference contract for the `string_ops` MCP tool.
- Load this doc on demand from the router skill to minimize startup context.

## Description
Advanced string analysis and IOC extraction. score_c2/indicators: C2 risk report — BehaviorClassifier on strings + API triads + family guess. ioc_extract: extract all IOCs (URLs, IPs, registry keys, C2 endpoints). persistence/evasion: persistence mechanisms and evasion techniques. find_urls/find_ips/find_paths/find_registry/find_emails/find_commands: pattern extraction. find_c2/find_configs/find_api_keys/find_databases/find_crypto_addrs: semantic extraction. find_stack_strings/find_base64: obfuscated string recovery. entropy_rank: rank strings by Shannon entropy. suspicious/encoding_stats/multilingual/decode_all: analysis utilities.

## Actions
- `decode_all` (tool-specific)
- `find_urls` (tool-specific)
- `find_paths` (analysis)
- `find_registry` (tool-specific)
- `find_ips` (tool-specific)
- `find_emails` (tool-specific)
- `find_commands` (tool-specific)
- `encoding_stats` (tool-specific)
- `multilingual` (tool-specific)
- `suspicious` (tool-specific)
- `find_xrefs` (tool-specific)
- `find_stack_strings` (tool-specific)
- `find_base64` (tool-specific)
- `find_api_keys` (tool-specific)
- `find_configs` (tool-specific)
- `find_c2` (tool-specific)
- `find_databases` (tool-specific)
- `find_crypto_addrs` (tool-specific)
- `entropy_rank` (tool-specific)
- `score_c2` (tool-specific)
- `indicators` (tool-specific)
- `persistence` (tool-specific)
- `evasion` (tool-specific)
- `ioc_extract` (tool-specific)

### Host wrapper actions (accepted by host dispatcher)
- `grep`: run another action, then grep output lines.
- `head`: run another action, then keep first N items.
- `tail`: run another action, then keep last N items.
- `pick`: run another action, then project top-level fields.
- `next`: continue paginated output with next token/cursor.
- `stats`: run another action, then return payload statistics.

## LLM Fast Path
- Canonical wiki page: `wiki(action='read', topic='tools/string_ops')`.
- Start with read/discovery actions (`list`, `index`, `search`, `info`) before mutating actions.
- Keep calls narrow: include only the minimum fields needed for one action.

## Parameters
- (tool takes action-only or dynamic args)

## Minimal Call Shapes
```json
{
  "name": "string_ops",
  "arguments": {
    "action": "decode_all"
  }
}
```
```json
{
  "name": "string_ops",
  "arguments": {
    "action": "grep",
    "source_action": "decode_all",
    "pattern": "<needle>"
  }
}
```

## Invocation Guidance
- Prefer compact responses first, then zoom in with narrower arguments.
- Use `offset`/`limit` style pagination where supported.
- If action is unclear, start with read-only/discovery actions before write actions.
- Re-read the canonical wiki page for detailed examples and failure modes.
