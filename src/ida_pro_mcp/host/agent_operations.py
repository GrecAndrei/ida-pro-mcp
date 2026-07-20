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
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from .errors import MCPError, is_error_result, make_error


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
CALC_VALUE = {
    # Use a string for numeric values as well as addresses and symbols.  Vertex
    # converts JSON Schema type unions into ``any_of``, which cannot be
    # combined with this field's description in a function declaration.
    "type": "string",
    "description": "Numeric value, hexadecimal address, or symbol accepted by the calculation backend.",
}
CALC_OFFSETS = {
    # A list is unambiguous for agents and avoids a Vertex-incompatible union
    # between an array and a comma-separated string.
    "type": "array",
    "items": {"type": "string"},
    "description": "Ordered pointer-chain offsets.",
}
PERSIST = {
    "type": "boolean",
    "description": "Save the calculation result to the analysis notebook.",
}
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
        name="ida_batch",
        description="Execute several deterministic analysis operations sequentially in one request.",
        category="workflow",
        input_schema=_schema(
            {
                "calls": {
                    "type": "array",
                    "description": "Public ida_* calls as {name, arguments} objects; omit arguments for a parameterless call.",
                    "items": {
                        # Vertex AI converts JSON Schema type unions to
                        # ``any_of``. Its function-declaration schema rejects
                        # sibling fields such as properties beside that union,
                        # so model the parameterless form as {name} instead of
                        # allowing a bare string here.
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "arguments": {"type": "object"},
                        },
                        "required": ["name"],
                        "additionalProperties": False,
                    },
                },
                "continue_on_error": {"type": "boolean", "description": "Continue later calls after an error."},
            },
            ["calls"],
        ),
        example={"calls": [{"name": "ida_overview", "arguments": {}}, {"name": "ida_list_functions", "arguments": {"limit": 20}}]},
        backend_tool="batch",
        # The legacy batch tool has no action argument; this registry marker
        # lets schema-integrity checks recognize the host-side dispatch.
        backend_action="(pass calls array)",
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
        argument_map={"limit": "count"},
    ),
    AgentOperation(
        name="ida_create_function",
        description="Define a function at an address, optionally naming it and setting an explicit end boundary.",
        category="edit",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "end": {"type": "string", "description": "Optional exclusive end address."},
                "name": {"type": "string", "description": "Optional function name."},
                "flags": {"type": "integer", "description": "Optional IDA function flags to add."},
                "force": {"type": "boolean", "description": "Delete overlapping definitions before creating the function."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["address"],
        ),
        example={"address": "0x401000", "risk_ack": True},
        backend_tool="funcs",
        backend_action="create",
        argument_map={"address": "addr", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_change_function",
        description="Change a function's end boundary, equivalent to IDA's Set function end command.",
        category="edit",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "end": {"type": "string", "description": "New exclusive function end address, like the GUI cursor position."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["address", "end"],
        ),
        example={"address": "0x401000", "end": "0x401080", "risk_ack": True},
        backend_tool="funcs",
        backend_action="change",
        argument_map={"address": "addr", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_calc_eval",
        description="Evaluate a safe arithmetic or bitwise expression involving addresses and symbols.",
        category="calculation",
        input_schema=_schema(
            {"expr": {"type": "string", "description": "Expression such as 0x401000 + 0x20."}, "query": {"type": "string"}, "intent": {"type": "string"}, "persist": PERSIST, "idb": IDB},
            ["expr"],
        ),
        example={"expr": "0x401000 + 0x20"},
        backend_tool="calc",
        backend_action="eval",
    ),
    AgentOperation(
        name="ida_calc_offset",
        description="Calculate the signed and absolute distance between two addresses or symbols.",
        category="calculation",
        input_schema=_schema({"address": ADDRESS, "target": CALC_VALUE, "intent": {"type": "string"}, "persist": PERSIST, "idb": IDB}, ["address", "target"]),
        example={"address": "0x401000", "target": "0x401050"},
        backend_tool="calc",
        backend_action="offset",
        argument_map={"address": "addr"},
    ),
    AgentOperation(
        name="ida_calc_convert",
        description="Convert an integer or address into hexadecimal, decimal, binary, octal, byte, and ASCII forms.",
        category="calculation",
        input_schema=_schema({"value": CALC_VALUE, "persist": PERSIST, "idb": IDB}, ["value"]),
        example={"value": "1234"},
        backend_tool="calc",
        backend_action="convert",
    ),
    AgentOperation(
        name="ida_calc_resolve",
        description="Translate an IDA virtual address or file offset using the binary's segment mapping.",
        category="calculation",
        input_schema=_schema(
            {"address": CALC_VALUE, "value": CALC_VALUE, "to_va": {"type": "boolean"}, "from_file": {"type": "boolean"}, "intent": {"type": "string"}, "persist": PERSIST, "idb": IDB},
        ),
        example={"address": "0x401000"},
        backend_tool="calc",
        backend_action="resolve",
        argument_map={"address": "addr"},
    ),
    AgentOperation(
        name="ida_calc_deref",
        description="Read a typed value or pointer from an address, optionally following multiple pointer hops.",
        category="calculation",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "type": {
                    "type": "string",
                    "enum": ["bytes", "u8", "u16", "u32", "u64", "s8", "s16", "s32", "s64", "f32", "f64", "ptr", "string"],
                },
                "size": {"type": "integer"},
                "deref_depth": {"type": "integer"},
                "intent": {"type": "string"},
                "persist": PERSIST,
                "idb": IDB,
            },
            ["address"],
        ),
        example={"address": "0x401000", "type": "u32"},
        backend_tool="calc",
        backend_action="deref",
        argument_map={"address": "addr"},
    ),
    AgentOperation(
        name="ida_calc_chain",
        description="Follow a pointer chain from an address using explicit offsets.",
        category="calculation",
        input_schema=_schema({"address": ADDRESS, "offsets": CALC_OFFSETS, "size": {"type": "integer"}, "intent": {"type": "string"}, "persist": PERSIST, "idb": IDB}, ["address", "offsets"]),
        example={"address": "0x601020", "offsets": ["0x10", "0x20"]},
        backend_tool="calc",
        backend_action="chain",
        argument_map={"address": "addr"},
    ),
    AgentOperation(
        name="ida_calc_align",
        description="Align a value or address down, up, and to the nearest requested boundary.",
        category="calculation",
        input_schema=_schema(
            {
                "value": CALC_VALUE,
                "address": CALC_VALUE,
                "expr": {"type": "string"},
                "size": {"type": "integer"},
                "intent": {"type": "string"},
                "persist": PERSIST,
                "idb": IDB,
            },
            ["size"],
        ),
        example={"value": "0x401003", "size": 16},
        backend_tool="calc",
        backend_action="align",
        argument_map={"address": "addr"},
    ),
    AgentOperation(
        name="ida_calc_bitops",
        description="Apply a bitwise and, or, xor, not, shift-left, or shift-right operation to integer values.",
        category="calculation",
        input_schema=_schema(
            {
                "value": CALC_VALUE,
                "target": CALC_VALUE,
                "bit_op": {"type": "string", "enum": ["and", "or", "xor", "not", "shl", "shr"]},
                "op": {"type": "string", "enum": ["and", "or", "xor", "not", "shl", "shr"]},
                "intent": {"type": "string"},
                "persist": PERSIST,
                "idb": IDB,
            },
            ["value"],
        ),
        example={"value": "0xff", "target": "0x0f", "bit_op": "xor"},
        backend_tool="calc",
        backend_action="bitops",
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
_OPERATIONS_BY_BACKEND = {
    (operation.backend_tool, operation.backend_action): operation
    for operation in AGENT_OPERATIONS
    if operation.backend_tool and operation.backend_action
}

# A few backend actions have a deliberately different public name or are
# aliases of an action-specific operation.  Keep these here so public errors
# can offer valid agentic recovery guidance without changing the legacy API.
_BACKEND_REFERENCE_ALIASES = {
    ("data", "functions"): "ida_list_functions",
    ("intelligence", "index_batch"): "ida_index_functions",
    ("session", "health"): "ida_session_status",
}
_LEGACY_ACTION_CALL = re.compile(
    r"\b([A-Za-z_]\w*)\(\s*action\s*=\s*(['\"])([^'\"]+)\2[^)]*\)"
)
_LEGACY_REFERENCE = re.compile(
    r"\b[A-Za-z_]\w*\(\s*action\s*=|\b(?:funcs|code|data|search|session|misc|"
    r"intelligence|truncation|analysis|calc)\.[A-Za-z_]\w*|\baction\s*=\s*"
)


def _public_operation_for_backend(tool: Any, action: Any) -> AgentOperation | None:
    """Resolve a legacy backend pair to its public agentic operation."""
    key = (str(tool or "").strip(), str(action or "").strip())
    operation_name = _BACKEND_REFERENCE_ALIASES.get(key)
    if operation_name:
        return _OPERATIONS_BY_NAME.get(operation_name)
    return _OPERATIONS_BY_BACKEND.get(key)


def _rewrite_public_text(text: Any, operation_name: str) -> str:
    """Remove legacy call syntax from text returned for a public operation."""
    value = str(text or "")

    def replace_call(match: re.Match[str]) -> str:
        operation = _public_operation_for_backend(match.group(1), match.group(3))
        return operation.name if operation else match.group(0)

    value = _LEGACY_ACTION_CALL.sub(replace_call, value)
    if "index_fast" in value:
        value = value.replace("index_fast", "ida_index_functions(quality='fast')")
    if "index_batch" in value:
        value = value.replace("index_batch", "ida_index_functions(quality='full')")
    if not _LEGACY_REFERENCE.search(value):
        return value
    return (
        f"Use ida_help(topic='{operation_name}') for the public agentic contract. "
        "The legacy backend recovery syntax is not exposed on this surface."
    )


def _public_recovery_item(item: Any) -> dict[str, Any] | None:
    """Translate one legacy recovery recipe when a public equivalent exists."""
    if not isinstance(item, dict):
        return None
    args = item.get("args")
    if not isinstance(args, dict):
        return None
    operation = _public_operation_for_backend(item.get("tool"), args.get("action"))
    if operation is None:
        return None

    public_args: dict[str, Any] = {}
    reverse_map = {backend: public for public, backend in operation.argument_map.items()}
    for key, value in args.items():
        if key == "action":
            continue
        public_args[reverse_map.get(key, key)] = value
    required = operation.input_schema.get("required", [])
    if any(key not in public_args for key in required):
        return None
    result: dict[str, Any] = {"tool": operation.name, "args": public_args}
    if item.get("note"):
        result["note"] = _rewrite_public_text(item["note"], operation.name)
    return result


def _adapt_one_agent_error(payload: dict[str, Any], public_name: str) -> dict[str, Any]:
    adapted = dict(payload)
    for key in ("message", "hint"):
        if key in adapted and isinstance(adapted[key], str):
            adapted[key] = _rewrite_public_text(adapted[key], public_name)

    recovery = adapted.get("recovery")
    if isinstance(recovery, list):
        public_recovery = [item for raw in recovery if (item := _public_recovery_item(raw))]
        if public_recovery:
            adapted["recovery"] = public_recovery
        else:
            adapted.pop("recovery", None)
    return adapted


def adapt_agent_error_payload(payload: Any, operation_name: Any) -> Any:
    """Adapt legacy hints/recovery recipes before returning a public result.

    IDA-side handlers still serve the compatibility dispatcher, so their
    errors may mention ``tool(action=...)``.  The same handler is reached by
    public ``ida_*`` operations, where those references are invalid guidance.
    Adapt both top-level errors and per-item errors inside aggregate results.
    Legacy calls made through the legacy surface are left untouched.
    """
    public_name = str(operation_name or "").strip()
    if not public_name.startswith("ida_"):
        return payload
    if isinstance(payload, list):
        return [adapt_agent_error_payload(item, public_name) for item in payload]
    if not isinstance(payload, dict):
        return payload
    if is_error_result(payload):
        return _adapt_one_agent_error(payload, public_name)
    return {
        key: adapt_agent_error_payload(value, public_name)
        for key, value in payload.items()
    }


def translate_public_batch_arguments(arguments: Any) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Translate nested public ``ida_*`` calls to the compatibility batch form."""
    if not isinstance(arguments, dict):
        return None, make_error(MCPError.INVALID_ARGS, "arguments must be an object")
    calls = arguments.get("calls")
    if not isinstance(calls, list) or not calls:
        return None, make_error(MCPError.BATCH_EMPTY, "No calls provided in batch")

    translated: list[Any] = []
    for index, raw_call in enumerate(calls):
        if isinstance(raw_call, str):
            name = raw_call.strip()
            nested_args: dict[str, Any] = {}
        elif isinstance(raw_call, dict):
            name = raw_call.get("name")
            nested_args = raw_call.get("arguments", {})
            if not isinstance(nested_args, dict):
                return None, make_error(
                    MCPError.INVALID_ARGS,
                    f"Batch call {index} arguments must be an object",
                )
        else:
            return None, make_error(
                MCPError.INVALID_ARGS,
                f"Batch call {index} must be an ida_* name or {{name, arguments}} object",
            )

        operation = get_agent_operation(name) if isinstance(name, str) else None
        if operation is None:
            # Preserve legacy entries for compatibility with callers migrating
            # to the public surface; the outer batch dispatcher validates them.
            translated.append(raw_call)
            continue
        if operation.name == "ida_batch":
            return None, make_error(MCPError.INVALID_ARGS, "Nested ida_batch calls are not allowed")
        validation_error = operation.validate(nested_args)
        if validation_error:
            validation_error = dict(validation_error)
            validation_error.setdefault("details", {})
            if isinstance(validation_error["details"], dict):
                validation_error["details"] = {"batch_index": index, **validation_error["details"]}
            return None, validation_error
        if operation.help_only:
            return None, make_error(MCPError.INVALID_ARGS, "ida_help cannot be used inside ida_batch")
        backend_tool, backend_args = operation.to_backend_call(nested_args)
        translated.append({"name": backend_tool, "arguments": backend_args})

    result = dict(arguments)
    result["calls"] = translated
    # ``ida_batch`` uses a synthetic backend action only to enter the host's
    # batch branch; the actual batch payload must not contain it.
    result.pop("action", None)
    return result, None


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
  data-flow. Use `ida_help` or dedicated graph/advanced operations only when
  the compact summary is insufficient.
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
