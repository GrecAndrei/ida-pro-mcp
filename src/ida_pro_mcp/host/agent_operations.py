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
    backend_defaults: Mapping[str, Any] = field(default_factory=dict)
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
        required = self.input_schema.get("required", [])
        for key in required:
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
        # Mutating ops advertise risk_ack as required; only an explicit true
        # counts as acknowledgement (false/0/"true" must not pass schema).
        if "risk_ack" in required and arguments.get("risk_ack") is not True:
            return make_error(
                MCPError.INVALID_ARGS,
                f"'risk_ack' must be true for operation '{self.name}'",
                hint=f"Example: {self.name}({self._example_text()})",
                details={"operation": self.name, "required": "risk_ack"},
            )
        return None

    def to_backend_call(self, arguments: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Translate a public operation call to the legacy dispatcher shape."""
        if not self.backend_tool or not self.backend_action:
            raise ValueError(f"Operation {self.name} does not dispatch to a backend tool")
        backend_args: dict[str, Any] = {
            "action": self.backend_action,
            **self.backend_defaults,
        }
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
IDB = {
    "type": "string",
    "description": "Optional session ID, IDB path, or binary path. Must refer to a session owned by this MCP client.",
}
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
                "architecture": {
                    "type": "object",
                    "description": (
                        "Architecture preload hints. Keys: processor (e.g. metapc, arm, mipsl), "
                        "bitness (32 or 64), endian (little or big), loader, flags, loader_options. "
                        "Aliases: arch/proc/architecture → processor, bits → bitness, endianness → endian."
                    ),
                    "additionalProperties": False,
                    "properties": {
                        "processor": {"type": "string", "description": "IDA processor name, e.g. metapc, arm, mipsl."},
                        "bitness": {"type": "integer", "description": "32 or 64."},
                        "endian": {"type": "string", "description": "little or big."},
                        "loader": {"type": "string", "description": "IDA loader name, e.g. elf, pe, bin."},
                        "flags": {"type": "integer", "description": "IDA loader flags."},
                        "loader_options": {"type": "string", "description": "Raw loader options string."},
                    },
                },
                "analysis_options": {
                    "type": "object",
                    "description": "Full analysis options object; merged with individual keys below.",
                },
                "processor": {"type": "string", "description": "IDA processor name (shorthand for architecture.processor)."},
                "bitness": {"type": "integer", "description": "32 or 64 (shorthand for architecture.bitness)."},
                "endian": {"type": "string", "description": "little or big (shorthand for architecture.endian)."},
                "loader": {"type": "string", "description": "IDA loader name (shorthand for architecture.loader)."},
                "flags": {"type": "integer", "description": "IDA loader flags (shorthand for architecture.flags)."},
                "loader_options": {"type": "string", "description": "Raw loader options (shorthand for architecture.loader_options)."},
                "baseaddr": {"type": "string", "description": "Load base address, e.g. 0x400000."},
                "start_ea": {"type": "string", "description": "Start EA for analysis range."},
                "min_ea": {"type": "string", "description": "Minimum EA for analysis range."},
                "max_ea": {"type": "string", "description": "Maximum EA for analysis range."},
                "reanalyze": {"type": "boolean", "description": "Force reanalysis even if IDB exists."},
                "ida_args": {
                    "type": "array",
                    "description": "Extra raw IDA CLI args (e.g. -A -Sscript -Llog).",
                    "items": {"type": "string"},
                },
                "input_format": {"type": "string", "description": "Force a specific file format parser, e.g. bin, elf, pe, macho, ihex, srec."},
                "processor_options": {"type": "string", "description": "Processor-specific options string, e.g. ARM CPU type or MIPS ISA variant."},
                "rebase_to": {"type": "string", "description": "Rebase the database to this address (hex or decimal), e.g. 0x400000."},
                "entry_point": {"type": "string", "description": "Override the entry point address (hex or decimal)."},
                "stack_size": {"type": "integer", "description": "Stack size in bytes for stack analysis."},
                "memory_model": {"type": "integer", "description": "Memory model: 0=flat, 1=16-bit segmented, 2=32-bit segmented."},
            },
            ["binary_path"],
        ),
        example={
            "binary_path": "/samples/target.exe",
            "architecture": {"processor": "metapc", "bitness": 64},
        },
        backend_tool="session",
        backend_action="create",
    ),
    AgentOperation(
        name="ida_open_background",
        description="Open a binary in a session without blocking on IDA analysis; poll ida_session_status for progress.",
        category="session",
        input_schema=_schema(
            {
                "binary_path": {"type": "string", "description": "Absolute path to the binary to analyze."},
                "force_new": {"type": "boolean", "description": "Create a new session even if the binary is already open."},
                "notes": {"type": "string", "description": "Optional session notes."},
                "architecture": {
                    "type": "object",
                    "description": (
                        "Architecture preload hints. Keys: processor (e.g. metapc, arm, mipsl), "
                        "bitness (32 or 64), endian (little or big), loader, flags, loader_options. "
                        "Aliases: arch/proc/architecture → processor, bits → bitness, endianness → endian."
                    ),
                    "additionalProperties": False,
                    "properties": {
                        "processor": {"type": "string", "description": "IDA processor name, e.g. metapc, arm, mipsl."},
                        "bitness": {"type": "integer", "description": "32 or 64."},
                        "endian": {"type": "string", "description": "little or big."},
                        "loader": {"type": "string", "description": "IDA loader name, e.g. elf, pe, bin."},
                        "flags": {"type": "integer", "description": "IDA loader flags."},
                        "loader_options": {"type": "string", "description": "Raw loader options string."},
                    },
                },
                "analysis_options": {
                    "type": "object",
                    "description": "Full analysis options object; merged with individual keys below.",
                },
                "processor": {"type": "string", "description": "IDA processor name (shorthand for architecture.processor)."},
                "bitness": {"type": "integer", "description": "32 or 64 (shorthand for architecture.bitness)."},
                "endian": {"type": "string", "description": "little or big (shorthand for architecture.endian)."},
                "loader": {"type": "string", "description": "IDA loader name (shorthand for architecture.loader)."},
                "flags": {"type": "integer", "description": "IDA loader flags (shorthand for architecture.flags)."},
                "loader_options": {"type": "string", "description": "Raw loader options (shorthand for architecture.loader_options)."},
                "ida_args": {
                    "type": "array",
                    "description": "Extra raw IDA CLI args (e.g. -A -Sscript -Llog).",
                    "items": {"type": "string"},
                },
            },
            ["binary_path"],
        ),
        example={"binary_path": "/samples/huge-firmware.bin"},
        backend_tool="session",
        backend_action="create_background",
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
        name="ida_session_health",
        description="Report MCP server, IDA runtime, cache, and session-process health diagnostics.",
        category="session",
        input_schema=_schema(
            {
                "verbose": {
                    "type": "boolean",
                    "description": "Include per-runtime process details and action counts.",
                },
            }
        ),
        example={},
        backend_tool="session",
        backend_action="health",
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
        name="ida_session_get",
        description="Get details for a specific session by ID.",
        category="session",
        input_schema=_schema(
            {
                "session_id": {
                    "type": "string",
                    "description": "Session identifier, e.g. SID_ABC123.",
                },
            },
            ["session_id"],
        ),
        example={"session_id": "SID_ABC123"},
        backend_tool="session",
        backend_action="get",
    ),
    AgentOperation(
        name="ida_session_list",
        description="List available analysis sessions, optionally filtered by query.",
        category="session",
        input_schema=_schema(
            {
                "query": {"type": "string", "description": "Optional filter string (matches id, path, notes, tags)."},
                "binary_name": {"type": "string", "description": "Optional filter by binary file name (substring of the analyzed file's name)."},
                "limit": LIMIT,
                "offset": {"type": "integer", "description": "Pagination offset."},
            }
        ),
        example={"limit": 20},
        backend_tool="session",
        backend_action="list",
    ),
    AgentOperation(
        name="ida_session_switch",
        description="Switch the active session to another session by ID or binary path.",
        category="session",
        input_schema=_schema(
            {
                "session_id": {"type": "string", "description": "Target session identifier."},
                "binary_path": {"type": "string", "description": "Switch to the session for this binary path."},
                "reopen": {"type": "boolean", "description": "Restart the IDA runtime if it is not alive."},
            }
        ),
        example={"session_id": "SID_ABC123", "reopen": True},
        backend_tool="session",
        backend_action="switch",
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
                "min_score": {"type": "number", "description": "Minimum semantic or hybrid rank score."},
                "start": {"type": "string", "description": "Inclusive start address for result filtering."},
                "end": {"type": "string", "description": "Exclusive end address for result filtering."},
                "address": {"type": "string", "description": "Center address or function for radius filtering."},
                "radius": {"type": "integer", "description": "Byte radius around address for result filtering."},
                "idb": IDB,
            },
            ["query"],
        ),
        example={"query": "function that decrypts strings", "mode": "quick", "limit": 20},
        backend_tool="search",
        backend_action="nl",
        argument_map={"min_score": "semantic_min_score", "address": "addr"},
    ),
    AgentOperation(
        name="ida_index_functions",
        description="Build a scoped semantic function index in responsive background slices.",
        category="discovery",
        input_schema=_schema(
            {
                "quality": {
                    "type": "string",
                    "enum": ["fast", "full"],
                    "description": "fast scans metadata and disassembly; full adds Hex-Rays decompilation for better retrieval quality.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum functions for the whole job; omit to index every matching function.",
                },
                "cursor": {
                    "type": "string",
                    "description": "Start after this hexadecimal function address.",
                },
                "start": {"type": "string", "description": "Inclusive start address for one index range."},
                "end": {"type": "string", "description": "Exclusive end address for one index range."},
                "address": {"type": "string", "description": "Center function or address for radius-based indexing."},
                "radius": {"type": "integer", "description": "Byte radius around address; indexes overlapping functions."},
                "ranges": {
                    "type": "array",
                    "description": "Multiple address ranges to index.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "start": {"type": "string"},
                            "end": {"type": "string"},
                        },
                        "required": ["start", "end"],
                        "additionalProperties": False,
                    },
                },
                "query": {"type": "string", "description": "Optional function-name filter; glob and regex forms are supported."},
                "min_size": {"type": "integer", "description": "Minimum function size in bytes."},
                "max_size": {"type": "integer", "description": "Maximum function size in bytes."},
                "slice_size": {
                    "type": "integer",
                    "description": "Functions processed per IDA RPC slice; smaller values improve interactive responsiveness.",
                },
                "background": {
                    "type": "boolean",
                    "description": "Run non-blocking and return a task ID; defaults to true.",
                },
                "idb": IDB,
            }
        ),
        example={"quality": "full"},
        backend_tool="intelligence",
        backend_action="index_fast",
        argument_map={
            "quality": "mode",
            "cursor": "start_after",
            "address": "addr",
            "background": "_background",
            "slice_size": "_index_slice_size",
        },
        backend_defaults={"_background": True},
    ),
    AgentOperation(
        name="ida_index_status",
        description="Check progress or retrieve the result of a background semantic-index job started by this client.",
        category="discovery",
        input_schema=_schema(
            {"task_id": {"type": "string", "description": "Task ID returned by ida_index_functions."}}
        ),
        example={},
        backend_tool="background",
        backend_action="status",
    ),
    AgentOperation(
        name="ida_cancel_index",
        description="Cancel a queued or running semantic-index job started by this client after its current slice.",
        category="discovery",
        input_schema=_schema(
            {"task_id": {"type": "string", "description": "Task ID returned by ida_index_functions."}},
            ["task_id"],
        ),
        example={"task_id": "abc123def456"},
        backend_tool="background",
        backend_action="cancel",
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
            ["address", "risk_ack"],
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
            ["address", "end", "risk_ack"],
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
            ["address", "name", "risk_ack"],
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
            ["address", "comment", "risk_ack"],
        ),
        example={"address": "0x401000", "comment": "handles inbound packets", "risk_ack": True},
        backend_tool="modify",
        backend_action="comment",
        argument_map={"address": "addr", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_write_finding",
        description="Record or merge a typed claim, question, task, or decision with its evidence.",
        category="findings",
        input_schema=_schema(
            {
                "title": {"type": "string", "description": "Short, stable statement of the insight."},
                "content": {"type": "string", "description": "Reasoning, implications, or next verification step."},
                "address": ADDRESS,
                "category": {"type": "string", "description": "Finding category."},
                "confidence": {"type": "number", "description": "Confidence from 0 to 1."},
                "priority": {"type": "number", "description": "Investigation priority from 0 to 1."},
                "kind": {
                    "type": "string",
                    "enum": ["finding", "hypothesis", "question", "task", "decision"],
                    "description": "Role this item plays in the investigation. To record that an address was read and found uninteresting, use ida_mark_examined instead.",
                },
                "status": {
                    "type": "string",
                    "enum": ["open", "confirmed", "resolved", "rejected"],
                    "description": "Current lifecycle state.",
                },
                "tags": {"type": "array", "items": {"type": "string"}, "description": "Optional tags."},
                "evidence": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": {"type": "string"},
                            "value": {"type": "string"},
                            "address": {"type": "string"},
                            "weight": {"type": "number"},
                        },
                        "required": ["type", "value"],
                        "additionalProperties": False,
                    },
                    "description": "Concrete observations supporting the item.",
                },
            },
            ["title"],
        ),
        example={
            "title": "recv handler parses framed input",
            "content": "Length is read before dispatch.",
            "address": "0x401000",
            "kind": "finding",
            "status": "confirmed",
            "confidence": 0.8,
            "priority": 0.7,
            "evidence": [{"type": "call", "value": "recv", "address": "0x401024"}],
        },
        backend_tool="blackboard",
        backend_action="write",
        argument_map={"address": "addr"},
    ),
    AgentOperation(
        name="ida_mark_examined",
        description="Record that an address was read and judged, including when there was nothing there.",
        category="findings",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "verdict": {
                    "type": "string",
                    "enum": ["boring", "interesting", "unclear"],
                    "description": "boring: understood, nothing worth returning to. interesting: warrants a finding. unclear: could not decide.",
                },
                "note": {"type": "string", "description": "One line on what it turned out to be."},
                "name": {"type": "string", "description": "Function name, if known."},
            },
            ["address", "verdict"],
        ),
        example={"address": "0x401a20", "verdict": "boring", "note": "CRT string helper, no input handling."},
        backend_tool="blackboard",
        backend_action="mark_examined",
        argument_map={"address": "addr"},
    ),
    AgentOperation(
        name="ida_list_findings",
        description="List investigation items with lifecycle and type filters.",
        category="findings",
        input_schema=_schema({
            "kind": {"type": "string", "enum": ["finding", "hypothesis", "question", "task", "decision", "examined"]},
            "status": {"type": "string", "enum": ["open", "confirmed", "resolved", "rejected"]},
            "category": {"type": "string"},
            "address": ADDRESS,
            "tag": {"type": "string"},
            "min_confidence": {"type": "number"},
            "include_resolved": {"type": "boolean"},
            "include_contradicted": {"type": "boolean"},
            "limit": LIMIT,
        }),
        example={"status": "open", "limit": 20},
        backend_tool="blackboard",
        backend_action="list",
        argument_map={"address": "addr"},
    ),
    AgentOperation(
        name="ida_search_findings",
        description="Search investigation memory by meaning or keywords.",
        category="findings",
        input_schema=_schema({
            "query": {"type": "string", "description": "Concept, behavior, or keyword to recall."},
            "category": {"type": "string"},
            "include_resolved": {"type": "boolean"},
            "include_contradicted": {"type": "boolean"},
            "threshold": {"type": "number"},
            "limit": LIMIT,
        }, ["query"]),
        example={"query": "unchecked packet length", "limit": 10},
        backend_tool="blackboard",
        backend_action="search",
    ),
    AgentOperation(
        name="ida_update_finding",
        description="Revise an investigation item or transition its lifecycle state.",
        category="findings",
        input_schema=_schema({
            "entry_id": {"type": "string", "description": "Finding identifier."},
            "status": {"type": "string", "enum": ["open", "confirmed", "resolved", "rejected"]},
            "reason": {"type": "string", "description": "Reason for the transition, especially rejection."},
            "content": {"type": "string"},
            "confidence": {"type": "number"},
            "priority": {"type": "number"},
            "tags": {"type": "array", "items": {"type": "string"}},
        }, ["entry_id"]),
        example={"entry_id": "a1b2c3d4", "status": "resolved", "reason": "Verified in callers."},
        backend_tool="blackboard",
        backend_action="update",
    ),
    AgentOperation(
        name="ida_publish_findings",
        description="Write confirmed findings into the IDB as repeatable comments and symbols.",
        category="findings",
        input_schema=_schema(
            {
                "rename": {
                    "type": "boolean",
                    "description": "Also rename functions that IDA still auto-named. Never overwrites an existing symbol. Default true.",
                },
                "republish": {
                    "type": "boolean",
                    "description": "Rewrite findings already published and unchanged since. Default false.",
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "Report what would be written without touching the IDB. Does not need risk_ack.",
                },
                "limit": LIMIT,
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
        ),
        example={"rename": True, "limit": 25, "risk_ack": True},
        backend_tool="blackboard",
        backend_action="publish_findings",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_import_annotations",
        description="Adopt names and comments already in the IDB as confirmed findings.",
        category="findings",
        input_schema=_schema({"limit": LIMIT, "offset": {"type": "integer"}, "idb": IDB}),
        example={"limit": 100},
        backend_tool="blackboard",
        backend_action="import_annotations",
    ),
    AgentOperation(
        name="ida_analysis_brief",
        description="Summarize confirmed knowledge, open questions, conflicts, stale claims, and coverage.",
        category="findings",
        input_schema=_schema({"limit": LIMIT}),
        example={"limit": 8},
        backend_tool="blackboard",
        backend_action="workspace_brief",
    ),
    AgentOperation(
        name="ida_next_target",
        description="Suggest what to analyze next using one named strategy, with the reason for each candidate.",
        category="findings",
        input_schema=_schema({
            "strategy": {
                "type": "string",
                "enum": ["unresolved", "stale", "conflict", "coverage", "frontier"],
                "description": (
                    "unresolved: open threads and unverified findings (default). "
                    "stale: claims whose code changed since they were written. "
                    "conflict: contradictions needing reconciliation. "
                    "coverage: frequently-called functions nobody has read. "
                    "frontier: unexamined neighbours of confirmed findings."
                ),
            },
            "query": {"type": "string", "description": "Optional theme; reorders candidates by keyword overlap, never drops them."},
            "limit": LIMIT,
        }),
        example={"strategy": "coverage", "limit": 10},
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
            ["code", "risk_ack"],
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
    """Translate one recovery recipe when a public equivalent exists.

    Accepts both legacy backend recipes (``{tool, action, ...}``) and
    already-public recipes (``{tool: ida_*, args: {...}}``).
    """
    if not isinstance(item, dict):
        return None
    args = item.get("args")
    if not isinstance(args, dict):
        return None
    tool_name = str(item.get("tool") or "")
    if tool_name.startswith("ida_"):
        operation = _OPERATIONS_BY_NAME.get(tool_name)
        if operation is None:
            return None
        required = operation.input_schema.get("required", [])
        if any(key not in args for key in required):
            return None
        result: dict[str, Any] = {"tool": operation.name, "args": dict(args)}
        if item.get("note"):
            result["note"] = _rewrite_public_text(item["note"], operation.name)
        return result
    operation = _public_operation_for_backend(tool_name, args.get("action"))
    if operation is None:
        return None

    public_args: dict[str, Any] = {}
    reverse_map = {backend: public for public, backend in operation.argument_map.items()}
    for key, value in args.items():
        if key == "action":
            continue
        public_args[str(reverse_map.get(key, key))] = value
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
  Indexing runs as a background job by default; poll `ida_index_status()` with
  the returned task ID. Use range, radius, size, or name filters for a scoped
  job. Exact matching binaries can reuse compatible indexes across sessions.
- Treat the `structure` field returned by `ida_decompile` and
  `ida_disassemble` as evidence: it summarizes CFG shape and call targets;
  decompilation additionally supplies bounded ctree control points and local
  data-flow. Use `ida_help` for exact schemas when the compact summary is
  insufficient.
- Use hex address strings exactly as returned by tools.
- `ida_rename` and `ida_comment` mutate the IDB. Set `risk_ack=true` only
  after verifying the target and intended change.
- Use `ida_python(code=..., risk_ack=true)` for narrowly scoped IDA-side
  scripting; it executes in the live IDA process and is policy-gated.
- Record confirmed work with `ida_write_finding`, and record dead ends with
  `ida_mark_examined(verdict="boring")`. A function you read and dismissed is
  worth one line: without it, the next session reads it again.
- Responses carry `_recall` (what is already known about this address) and
  `_already_examined` (returned addresses you previously dismissed). Read them
  before re-deriving anything. A `_stale` field means the code changed after a
  claim about it was recorded — re-check that claim rather than trusting it.
- `ida_next_target(strategy=...)` picks the next investigation point:
  `unresolved` for open threads, `coverage` for functions nobody has read,
  `frontier` to expand from confirmed findings, `stale` and `conflict` for
  claims that need repair. Every candidate states why it was chosen.
- If `ida_write_finding` returns a `conflict`, two claims about the same thing
  disagree. Resolve it with `ida_update_finding` before building on either.
- `ida_import_annotations` early in a session adopts names and comments the
  last analyst left in the IDB, so you inherit their work instead of redoing
  it. `ida_publish_findings(risk_ack=true)` writes confirmed findings back as
  comments and symbols; use `dry_run=true` first to see what it would change.
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
