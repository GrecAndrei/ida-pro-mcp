"""Agent-facing MCP operation contract.

The IDA runtime uses broad ``tool(action=...)`` APIs.  They are convenient for
humans and backwards compatibility, but they are a poor function-calling
surface: an agent must infer which arguments belong to each action.  This
module is the single source of truth for the small, action-specific interface
advertised to MCP clients.

Each :class:`AgentOperation` owns its public JSON schema, one useful example,
and the translation to the legacy dispatcher.  Documentation, the in-band
help tool, and the Codex skill references are generated from this data.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from .errors import MCPError, make_error


@dataclass(frozen=True)
class AgentOperation:
    """One narrowly-scoped, model-facing MCP operation."""

    name: str
    description: str
    category: str
    input_schema: dict[str, Any]
    example: dict[str, Any]
    backend_tool: str | None = None
    backend_action: str | None = None
    argument_map: Mapping[str, str] = field(default_factory=dict)
    help_only: bool = False

    def validate(self, arguments: Any) -> dict[str, Any] | None:
        """Return a structured error for an invalid public operation call."""
        if not isinstance(arguments, dict):
            return make_error(MCPError.INVALID_ARGS, "arguments must be an object")

        properties = self.input_schema.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}
        unknown = sorted(str(key) for key in arguments if key not in properties)
        if unknown:
            return make_error(
                MCPError.INVALID_ARGS,
                f"Unknown argument(s) for operation '{self.name}': {', '.join(unknown)}",
                hint=f"Use ida_help(topic='{self.name}') for the exact contract.",
                details={"operation": self.name, "unknown": unknown},
            )
        for key in self.input_schema.get("required", []):
            if key not in arguments or arguments[key] is None or arguments[key] == "":
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"'{key}' is required for operation '{self.name}'",
                    hint=f"Example: {self.name}({self._example_text()})",
                    details={"operation": self.name, "required": key},
                )
        for key, value in arguments.items():
            schema = properties.get(key)
            if isinstance(schema, dict) and not _matches_schema_type(value, schema):
                expected = schema.get("type", "valid value")
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"'{key}' must be {expected} for operation '{self.name}'",
                    details={"operation": self.name, "argument": key, "expected": expected},
                )
            if isinstance(schema, dict) and isinstance(schema.get("enum"), list):
                if value not in schema["enum"]:
                    choices = ", ".join(str(item) for item in schema["enum"])
                    return make_error(
                        MCPError.INVALID_ARGS,
                        f"'{key}' must be one of: {choices}",
                        details={"operation": self.name, "argument": key},
                    )
        return None

    def to_backend_call(self, arguments: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Translate a public operation call to the legacy dispatcher shape."""
        if not self.backend_tool or not self.backend_action:
            raise ValueError(f"Operation {self.name} does not dispatch to a backend tool")
        backend_args: dict[str, Any] = {"action": self.backend_action}
        for key, value in arguments.items():
            backend_args[self.argument_map.get(key, key)] = value
        return self.backend_tool, backend_args

    def _example_text(self) -> str:
        return ", ".join(f"{key}={value!r}" for key, value in self.example.items())


def _matches_schema_type(value: Any, schema: Mapping[str, Any]) -> bool:
    expected = schema.get("type")
    if expected is None:
        return True
    expected_types = expected if isinstance(expected, list) else [expected]
    for kind in expected_types:
        if kind == "string" and isinstance(value, str):
            return True
        if kind == "integer" and isinstance(value, int) and not isinstance(value, bool):
            return True
        if kind == "number" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if kind == "boolean" and isinstance(value, bool):
            return True
        if kind == "array" and isinstance(value, list):
            return True
        if kind == "object" and isinstance(value, dict):
            return True
    return False


def _schema(properties: dict[str, dict[str, Any]], required: list[str] | None = None) -> dict[str, Any]:
    """Build a strict MCP input schema with no implicit argument surface."""
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


ADDRESS = {
    "type": "string",
    "description": "Function name or hexadecimal address, for example 0x401000.",
}
IDB = {"type": "string", "description": "Optional session ID, IDB path, or binary path."}
LIMIT = {"type": "integer", "description": "Maximum result items to return."}
RISK_ACK = {
    "type": "boolean",
    "description": "Set true only after verifying this IDB mutation is intended.",
}
CODE_EXEC_ACK = {
    "type": "boolean",
    "description": "Set true only after verifying this code execution is authorized and intended.",
}


AGENT_OPERATIONS: tuple[AgentOperation, ...] = (
    AgentOperation(
        name="ida_open_binary",
        description="Open a binary in a new or existing IDA analysis session.",
        category="session",
        input_schema=_schema(
            {
                "binary_path": {"type": "string", "description": "Absolute path to the binary to analyze."},
                "force_new": {"type": "boolean", "description": "Create a new session even if the binary is already open."},
                "notes": {"type": "string", "description": "Optional session notes."},
            },
            ["binary_path"],
        ),
        example={"binary_path": "/samples/target.exe"},
        backend_tool="session",
        backend_action="create",
    ),
    AgentOperation(
        name="ida_session_state",
        description="Get the current binary, analysis progress, and next useful actions.",
        category="session",
        input_schema=_schema({}),
        example={},
        backend_tool="session",
        backend_action="state",
    ),
    AgentOperation(
        name="ida_session_status",
        description="Check whether IDA analysis is ready without starting more work.",
        category="session",
        input_schema=_schema({}),
        example={},
        backend_tool="session",
        backend_action="status",
    ),
    AgentOperation(
        name="ida_close_session",
        description="Close the active IDA analysis session and release its runtime.",
        category="session",
        input_schema=_schema({}),
        example={},
        backend_tool="session",
        backend_action="close",
    ),
    AgentOperation(
        name="ida_overview",
        description="Get binary metadata, architecture, entry points, and high-level analysis context.",
        category="discovery",
        input_schema=_schema({"idb": IDB}),
        example={},
        backend_tool="idb",
        backend_action="overview",
    ),
    AgentOperation(
        name="ida_find",
        description="Find names, strings, imports, comments, and references matching text.",
        category="discovery",
        input_schema=_schema(
            {"query": {"type": "string", "description": "Text, symbol, API, or IOC to find."}, "limit": LIMIT, "idb": IDB},
            ["query"],
        ),
        example={"query": "recv", "limit": 20},
        backend_tool="search",
        backend_action="find",
        argument_map={"query": "pattern"},
    ),
    AgentOperation(
        name="ida_semantic_search",
        description="Find functions by behavior or natural-language intent after indexing the binary.",
        category="discovery",
        input_schema=_schema(
            {
                "query": {"type": "string", "description": "Behavior to find, such as 'function that decrypts strings'."},
                "mode": {"type": "string", "enum": ["quick", "expand"], "description": "quick is faster; expand adds behavior-driven matches."},
                "limit": LIMIT,
                "idb": IDB,
            },
            ["query"],
        ),
        example={"query": "function that decrypts strings", "mode": "quick", "limit": 20},
        backend_tool="search",
        backend_action="nl",
    ),
    AgentOperation(
        name="ida_index_functions",
        description="Build the function index for semantic search, using fast metadata or full Hex-Rays decompilation.",
        category="discovery",
        input_schema=_schema(
            {
                "quality": {
                    "type": "string",
                    "enum": ["fast", "full"],
                    "description": "fast scans metadata and disassembly; full decompiles functions in resumable passes for best retrieval quality.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Optional functions to process in this pass; full mode otherwise chooses an adaptive pass size.",
                },
                "cursor": {
                    "type": "string",
                    "description": "Resume after the next_cursor returned by a limited indexing pass.",
                },
                "idb": IDB,
            }
        ),
        example={"quality": "full"},
        backend_tool="intelligence",
        backend_action="index_fast",
        argument_map={"quality": "mode", "limit": "index_limit", "cursor": "start_after"},
    ),
    AgentOperation(
        name="ida_list_functions",
        description="List functions, optionally filtering by name.",
        category="discovery",
        input_schema=_schema({"query": {"type": "string", "description": "Optional function-name filter."}, "limit": LIMIT, "idb": IDB}),
        example={"limit": 50},
        backend_tool="funcs",
        backend_action="list",
    ),
    AgentOperation(
        name="ida_list_strings",
        description="List strings in the current binary, optionally filtered by text.",
        category="discovery",
        input_schema=_schema({"query": {"type": "string", "description": "Optional string filter."}, "limit": LIMIT, "idb": IDB}),
        example={"query": "http", "limit": 50},
        backend_tool="data",
        backend_action="strings",
        argument_map={"limit": "count"},
    ),
    AgentOperation(
        name="ida_list_imports",
        description="List imported APIs in the current binary.",
        category="discovery",
        input_schema=_schema({"limit": LIMIT, "idb": IDB}),
        example={"limit": 100},
        backend_tool="data",
        backend_action="imports",
        argument_map={"limit": "count"},
    ),
    AgentOperation(
        name="ida_decompile",
        description="Decompile one function with bounded CFG and ctree-derived structural evidence.",
        category="code",
        input_schema=_schema({"address": ADDRESS, "idb": IDB}, ["address"]),
        example={"address": "0x401000"},
        backend_tool="code",
        backend_action="decompile",
        argument_map={"address": "addrs"},
    ),
    AgentOperation(
        name="ida_disassemble",
        description="Disassemble one function or address range with compact CFG and call-target evidence when available.",
        category="code",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "end": {"type": "string", "description": "Optional end address for a range."},
                "style": {"type": "string", "enum": ["csmini", "classic", "annotated"], "description": "Assembly output style."},
                "limit": LIMIT,
                "idb": IDB,
            },
            ["address"],
        ),
        example={"address": "0x401000", "limit": 80},
        backend_tool="code",
        backend_action="disasm",
        argument_map={"address": "addrs", "style": "disasm_style"},
    ),
    AgentOperation(
        name="ida_xrefs_to",
        description="List cross-references to a function, data item, or address.",
        category="code",
        input_schema=_schema({"address": ADDRESS, "idb": IDB}, ["address"]),
        example={"address": "0x401000"},
        backend_tool="code",
        backend_action="xrefs_to",
        argument_map={"address": "addrs"},
    ),
    AgentOperation(
        name="ida_callers",
        description="List functions that call a target function.",
        category="code",
        input_schema=_schema({"address": ADDRESS, "idb": IDB}, ["address"]),
        example={"address": "recv"},
        backend_tool="code",
        backend_action="callers",
        argument_map={"address": "addrs"},
    ),
    AgentOperation(
        name="ida_callees",
        description="List functions called by a target function.",
        category="code",
        input_schema=_schema({"address": ADDRESS, "idb": IDB}, ["address"]),
        example={"address": "0x401000"},
        backend_tool="code",
        backend_action="callees",
        argument_map={"address": "addrs"},
    ),
    AgentOperation(
        name="ida_rename",
        description="Rename a function or symbol in the IDB.",
        category="edit",
        input_schema=_schema(
            {"address": ADDRESS, "name": {"type": "string", "description": "New symbol name."}, "risk_ack": RISK_ACK, "idb": IDB},
            ["address", "name"],
        ),
        example={"address": "0x401000", "name": "handle_recv", "risk_ack": True},
        backend_tool="modify",
        backend_action="rename",
        argument_map={"address": "addr", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_comment",
        description="Add or replace a comment at an address in the IDB.",
        category="edit",
        input_schema=_schema(
            {"address": ADDRESS, "comment": {"type": "string", "description": "Comment text."}, "risk_ack": RISK_ACK, "idb": IDB},
            ["address", "comment"],
        ),
        example={"address": "0x401000", "comment": "handles inbound packets", "risk_ack": True},
        backend_tool="modify",
        backend_action="comment",
        argument_map={"address": "addr", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_write_finding",
        description="Save an analysis finding to the durable session notebook.",
        category="findings",
        input_schema=_schema(
            {
                "title": {"type": "string", "description": "Short finding title."},
                "content": {"type": "string", "description": "Evidence and reasoning."},
                "address": ADDRESS,
                "category": {"type": "string", "description": "Finding category."},
                "confidence": {"type": "number", "description": "Confidence from 0 to 1."},
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Optional tags."},
            },
            ["title"],
        ),
        example={"title": "recv handler", "content": "Receives and parses inbound packets.", "address": "0x401000", "confidence": 0.8},
        backend_tool="blackboard",
        backend_action="write",
        argument_map={"address": "addr"},
    ),
    AgentOperation(
        name="ida_list_findings",
        description="List durable findings from the current analysis session.",
        category="findings",
        input_schema=_schema({"limit": LIMIT}),
        example={"limit": 20},
        backend_tool="blackboard",
        backend_action="list",
    ),
    AgentOperation(
        name="ida_next_target",
        description="Get the highest-priority next analysis target from the notebook frontier.",
        category="findings",
        input_schema=_schema({"limit": LIMIT}),
        example={"limit": 10},
        backend_tool="blackboard",
        backend_action="next_target",
    ),
    AgentOperation(
        name="ida_python",
        description="Execute a Python expression or script in the active IDA process.",
        category="support",
        input_schema=_schema(
            {
                "code": {
                    "type": "string",
                    "description": "Python expression or script to execute in IDA context.",
                },
                "risk_ack": CODE_EXEC_ACK,
            },
            ["code"],
        ),
        example={"code": "print(idaapi.get_imagebase())", "risk_ack": True},
        backend_tool="misc",
        backend_action="python",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_continue",
        description=(
            "Continue a truncated result; pass field when the response lists "
            "more than one truncated field."
        ),
        category="support",
        input_schema=_schema(
            {
                "token": {
                    "type": "string",
                    "description": "Continuation token from the response's _continue.token field.",
                },
                "field": {
                    "type": "string",
                    "description": (
                        "Exact field name from _continue.fields, required when "
                        "more than one field is truncated (for example code or annotated_code)."
                    ),
                },
                "offset": {
                    "type": "integer",
                    "description": "Optional item/character offset within the selected field.",
                },
                "count": {
                    "type": "integer",
                    "description": "Optional number of items/characters to return.",
                },
            },
            ["token"],
        ),
        example={"token": "ABC123", "field": "code"},
        backend_tool="truncation",
        backend_action="continue",
    ),
    AgentOperation(
        name="ida_help",
        description="Get the exact contract and example for an IDA operation, or search the operation catalog.",
        category="support",
        input_schema=_schema(
            {
                "topic": {"type": "string", "description": "Exact operation name, such as ida_decompile."},
                "query": {"type": "string", "description": "Words to search across operation names and descriptions."},
            }
        ),
        example={"topic": "ida_decompile"},
        help_only=True,
    ),
)

_OPERATIONS_BY_NAME = {operation.name: operation for operation in AGENT_OPERATIONS}


def get_agent_operation(name: Any) -> AgentOperation | None:
    """Return an operation by its exact public MCP name."""
    return _OPERATIONS_BY_NAME.get(str(name or "").strip())


def list_agent_operations() -> tuple[AgentOperation, ...]:
    """Return the stable public operation order used in tools/list and docs."""
    return AGENT_OPERATIONS


def build_agent_help(arguments: dict[str, Any]) -> dict[str, Any]:
    """Serve operation help in-band, independent of workspace files or skills."""
    topic = str(arguments.get("topic") or "").strip()
    query = str(arguments.get("query") or "").strip().lower()
    if topic:
        operation = get_agent_operation(topic)
        if not operation:
            return make_error(
                MCPError.INVALID_ARGS,
                f"Unknown operation '{topic}'",
                hint="Call ida_help(query='search term') to discover operations.",
            )
        return {
            "ok": True,
            "operation": _operation_payload(operation),
        }
    if query:
        matches = [
            _operation_payload(operation, include_schema=False)
            for operation in AGENT_OPERATIONS
            if query in operation.name.lower() or query in operation.description.lower() or query in operation.category.lower()
        ]
        return {"ok": True, "query": query, "operations": matches, "count": len(matches)}
    return {
        "ok": True,
        "operations": [_operation_payload(operation, include_schema=False) for operation in AGENT_OPERATIONS],
        "count": len(AGENT_OPERATIONS),
        "hint": "Pass topic='ida_decompile' for an exact schema and example.",
    }


def _operation_payload(operation: AgentOperation, *, include_schema: bool = True) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": operation.name,
        "description": operation.description,
        "category": operation.category,
        "example": operation.example,
    }
    if include_schema:
        payload["inputSchema"] = operation.input_schema
    return payload


def render_agent_skill_markdown() -> str:
    """Render the portable skill playbook installed for coding agents."""
    return '''---
name: "ida-pro-mcp"
description: "Use IDA Pro through the action-specific ida_* MCP operations."
---

# IDA Pro MCP

Use the `ida_*` tools shown by MCP. Their JSON schemas are the complete call
contract; do not invent a `tool(action=...)` call when an `ida_*` operation is
available.

## First turn

1. `ida_open_binary(binary_path=...)` when no session is active.
2. `ida_session_state()` to see analysis progress and context.
3. `ida_overview()` for architecture and entry-point context.
4. Use `ida_find(query=...)`, then pass returned addresses verbatim to
   `ida_decompile`, `ida_disassemble`, `ida_xrefs_to`, `ida_callers`, or
   `ida_callees`.

## Working rules

- Build the semantic index with `ida_index_functions()` before
  `ida_semantic_search(...)`. Use `quality="full"` when retrieval quality
  matters; both index qualities include bounded CFG/call evidence, while full
  quality also includes ctree-derived control and local data-flow evidence.
  Full indexing uses bounded passes, so repeat with the returned `next_cursor`
  until `complete` is true.
- Treat the `structure` field returned by `ida_decompile` and
  `ida_disassemble` as evidence: it summarizes CFG shape and call targets;
  decompilation additionally supplies bounded ctree control points and local
  data-flow. Use `ida_help` or the dedicated graph/legacy tools only when the
  compact summary is insufficient.
- Use hex address strings exactly as returned by tools.
- `ida_rename` and `ida_comment` mutate the IDB. Set `risk_ack=true` only
  after verifying the target and intended change.
- Use `ida_python(code=..., risk_ack=true)` for narrowly scoped IDA-side
  scripting; it executes in the live IDA process and is policy-gated.
- Record confirmed work with `ida_write_finding`; use `ida_next_target` to
  choose the next investigation point.
- If a result is truncated, read `_continue.token` and `_continue.fields`.
  Call `ida_continue(token=...)` when one field is listed; when multiple
  fields are listed, pass the exact selected name as `field=...` (for example
  `ida_continue(token="ABC123", field="code")`).

## Help

Call `ida_help(topic="ida_decompile")` for an exact schema and example, or
`ida_help(query="strings")` to discover an operation. This works through MCP
and does not depend on local workspace files.

## Reference

Read `references/operations.md` only when the MCP schema or `ida_help` does
not answer a specific question.
'''


def render_agent_operations_markdown() -> str:
    """Render the portable, per-operation reference installed with the skill."""
    lines = ["# IDA MCP Agent Operations", ""]
    lines.append("Generated from `host.agent_operations.AGENT_OPERATIONS`.")
    lines.append("")
    for operation in AGENT_OPERATIONS:
        lines.extend(
            [
                f"## `{operation.name}`",
                "",
                operation.description,
                "",
                "Input schema:",
                "```json",
                json.dumps(operation.input_schema, indent=2, ensure_ascii=False),
                "```",
                "",
                "Example:",
                "```json",
                json.dumps({"name": operation.name, "arguments": operation.example}, indent=2, ensure_ascii=False),
                "```",
                "",
            ]
        )
    return "\n".join(lines)
