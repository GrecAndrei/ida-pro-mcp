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
from dataclasses import dataclass, field, replace
from typing import Any, Mapping

from .errors import MCPError, is_error_result, make_error
from .policy import RiskTier, classify_legacy_pair


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
    risk_tier: RiskTier | None = None

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
            if key not in arguments or arguments[key] is None:
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"'{key}' is required for operation '{self.name}'",
                    hint=f"Example: {self.name}({self._example_text()})",
                    details={"operation": self.name, "required": key},
                )
            if arguments[key] == "":
                schema = properties.get(key) if isinstance(properties.get(key), dict) else {}
                # Required strings reject "" unless the schema opts into empty
                # (ida_comment uses minLength 0 so "" clears the comment).
                min_len = schema.get("minLength")
                if min_len is None or int(min_len) > 0:
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
            if isinstance(schema, dict):
                nested_error = _validate_schema_value(value, schema, key)
                if nested_error is not None:
                    message, details = nested_error
                    return make_error(
                        MCPError.INVALID_ARGS,
                        f"{message} for operation '{self.name}'",
                        hint=f"Use ida_help(topic='{self.name}') for the exact contract.",
                        details={"operation": self.name, **details},
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
        """Translate a public operation call to the backend dispatcher.

        Public argument names stay on the wire. Host-only keys (``risk_ack``
        and any ``argument_map`` target that starts with ``_``) stay on the
        host for policy / job control and are stripped before IDA RPC.
        """
        if not self.backend_tool or not self.backend_action:
            raise ValueError(f"Operation {self.name} does not dispatch to a backend tool")
        backend_args: dict[str, Any] = {
            "action": self.backend_action,
            **self.backend_defaults,
        }
        for key, value in arguments.items():
            dest = self.argument_map.get(key, key)
            if isinstance(dest, str) and dest.startswith("_"):
                backend_args[dest] = value
                continue
            backend_args[key] = value
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


def _validate_schema_value(
    value: Any, schema: Mapping[str, Any], path: str
) -> tuple[str, dict[str, Any]] | None:
    """Validate the nested JSON-Schema subset used by public operations.

    The MCP boundary cannot rely on a full JSON-Schema validator because the
    operation schemas are also consumed by clients with different validators.
    Keeping this small recursive check in sync with the schemas prevents
    malformed nested objects from reaching the legacy dispatcher.
    """
    if not _matches_schema_type(value, schema):
        expected = schema.get("type", "valid value")
        return (
            f"'{path}' must be {expected}",
            {"argument": path, "expected": expected},
        )

    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        choices = ", ".join(str(item) for item in enum)
        return (
            f"'{path}' must be one of: {choices}",
            {"argument": path},
        )

    if isinstance(value, str) and "minLength" in schema:
        try:
            min_length = int(schema["minLength"])
        except (TypeError, ValueError):
            min_length = 0
        if len(value) < min_length:
            return (
                f"'{path}' must contain at least {min_length} characters",
                {"argument": path, "minLength": min_length},
            )

    schema_type = schema.get("type")
    if schema_type == "object" and isinstance(value, dict):
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}
        if schema.get("additionalProperties") is False:
            unknown = sorted(str(key) for key in value if key not in properties)
            if unknown:
                names = ", ".join(f"'{path}.{key}'" for key in unknown)
                return (
                    f"Unknown argument(s): {names}",
                    {"argument": path, "unknown": unknown},
                )

        required = schema.get("required", [])
        if not isinstance(required, list):
            required = []
        for key in required:
            if key not in value or value[key] is None:
                child_path = f"{path}.{key}"
                return (
                    f"'{child_path}' is required",
                    {"argument": child_path, "required": key},
                )
            child_schema = properties.get(key)
            if value[key] == "" and isinstance(child_schema, dict):
                min_length = child_schema.get("minLength")
                try:
                    rejects_empty = min_length is None or int(min_length) > 0
                except (TypeError, ValueError):
                    rejects_empty = True
                if rejects_empty:
                    child_path = f"{path}.{key}"
                    return (
                        f"'{child_path}' is required",
                        {"argument": child_path, "required": key},
                    )

        for key, child_value in value.items():
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                nested_error = _validate_schema_value(
                    child_value, child_schema, f"{path}.{key}"
                )
                if nested_error is not None:
                    return nested_error

    if schema_type == "array" and isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                nested_error = _validate_schema_value(item, item_schema, f"{path}[{index}]")
                if nested_error is not None:
                    return nested_error

    return None


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
        description=(
            "Open a binary in a new or existing IDA analysis session. The "
            "open is blocking and waits until IDA auto-analysis completes, so "
            "the returned session is fully analyzed and safe_mode is off. "
            "Only when the experimental IDA_MCP_BACKGROUND_OPEN=1 flag is set "
            "may large binaries instead auto-open in the background "
            "(background and safe_mode in the response); poll "
            "ida_session_status until safe_mode clears."
        ),
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
                        "arch": {"type": "string", "description": "Alias for processor."},
                        "proc": {"type": "string", "description": "Alias for processor."},
                        "bits": {"type": "integer", "description": "Alias for bitness."},
                        "endianness": {"type": "string", "description": "Alias for endian."},
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
                "memory_model": {"type": "integer", "description": "Memory model: 0=flat, 1=16-bit segmented, 2=32-bit segmented (no-op on IDA 9.x, which removed the API)."},
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
        description=(
            "EXPERIMENTAL — DISABLED BY DEFAULT. Open a binary in a session "
            "without blocking on IDA analysis. Requires IDA_MCP_BACKGROUND_OPEN=1 "
            "in the host environment; otherwise this operation fails with "
            "FEATURE_DISABLED and opens are blocking. When enabled, the session "
            "starts in safe mode (safe_mode: true): full-binary analysis, "
            "indexing, and script execution are blocked until analysis completes "
            "— manual small-area operations stay available. Poll "
            "ida_session_status for progress and for safe_mode to clear."
        ),
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
                        "arch": {"type": "string", "description": "Alias for processor."},
                        "proc": {"type": "string", "description": "Alias for processor."},
                        "bits": {"type": "integer", "description": "Alias for bitness."},
                        "endianness": {"type": "string", "description": "Alias for endian."},
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
                "input_format": {"type": "string", "description": "Force a specific file format parser, e.g. bin, elf, pe, macho, ihex, srec."},
                "processor_options": {"type": "string", "description": "Processor-specific options string, e.g. ARM CPU type or MIPS ISA variant."},
                "rebase_to": {"type": "string", "description": "Rebase the database to this address (hex or decimal), e.g. 0x400000."},
                "entry_point": {"type": "string", "description": "Override the entry point address (hex or decimal)."},
                "stack_size": {"type": "integer", "description": "Stack size in bytes for stack analysis."},
                "memory_model": {"type": "integer", "description": "Memory model: 0=flat, 1=16-bit segmented, 2=32-bit segmented (no-op on IDA 9.x, which removed the API)."},
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
        description=(
            "Get the current binary, analysis progress, and next useful "
            "actions. When several agents share one MCP connection, pass "
            "idb=<session_id> to target a specific session instead of the "
            "shared active one."
        ),
        category="session",
        input_schema=_schema({"idb": IDB}),
        example={"idb": "SID_ABC123"},
        backend_tool="session",
        backend_action="state",
    ),
    AgentOperation(
        name="ida_session_status",
        description=(
            "Check whether IDA analysis is ready without starting more work. "
            "Reports safe_mode and analysis_complete; while safe_mode is "
            "true, full-binary analysis, indexing, and script execution are "
            "blocked. When analysis completes, the response carries a "
            "one-shot analysis_complete warning. When several agents share "
            "one MCP connection, pass idb=<session_id> to target a specific "
            "session instead of the shared active one."
        ),
        category="session",
        input_schema=_schema({"idb": IDB}),
        example={"idb": "SID_ABC123"},
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
        input_schema=_schema(
            {
                "risk_ack": {
                    "type": "boolean",
                    "description": "Set true only after verifying this session teardown is intended.",
                }
            },
            ["risk_ack"],
        ),
        example={"risk_ack": True},
        backend_tool="session",
        backend_action="close",
        argument_map={"risk_ack": "_risk_ack"},
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
        name="ida_sso_activate",
        description="Activate the one-shot agent SSO realm with an allowlist of agent names.",
        category="session",
        input_schema=_schema(
            {
                "agents": {
                    "type": "array",
                    "description": "Agent names that may log in on this server.",
                    "items": {"type": "string"},
                },
                "secret": {
                    "type": "string",
                    "description": "Optional HMAC secret; otherwise the configured environment secret or a generated secret is used.",
                },
            },
            ["agents"],
        ),
        example={"agents": ["rev_a", "audit_b"]},
        backend_tool="session",
        backend_action="sso_activate",
    ),
    AgentOperation(
        name="ida_agent_login",
        description="Log an agent into the active SSO realm with a signed ticket.",
        category="session",
        input_schema=_schema(
            {
                "name": {"type": "string", "description": "Allowlisted agent name."},
                "ticket": {"type": "string", "description": "Signed name.payload.signature ticket minted for this agent."},
            },
            ["name", "ticket"],
        ),
        example={"name": "rev_a", "ticket": "rev_a.<payload>.<signature>"},
        backend_tool="session",
        backend_action="agent_login",
    ),
    AgentOperation(
        name="ida_agent_logout",
        description="Log an agent out and release only that agent's sessions.",
        category="session",
        input_schema=_schema(
            {
                "name": {"type": "string", "description": "Agent name to log out; omit when the per-call agent tag identifies it."},
            }
        ),
        example={"name": "rev_a"},
        backend_tool="session",
        backend_action="agent_logout",
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
                "bindings": {
                    "type": "object",
                    "description": "Output→input bindings map: step{i}_{key} refs to later call arguments (e.g. {\"step1_addr\": {\"step\": 2, \"key\": \"addr\"}}).",
                },
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
        description=(
            "Find names, strings, imports, comments, and references matching text. "
            "Pass kind='strings' for a dedicated string-literal search, kind='names' for "
            "symbol-only, or kind='imports'|'comments'|'instructions'|'refs' to restrict "
            "to that one category."
        ),
        category="discovery",
        input_schema=_schema(
            {
                "query": {"type": "string", "description": "Text, symbol, API, or IOC to find."},
                "kind": {
                    "type": "string",
                    "enum": ["all", "names", "strings", "imports", "comments", "instructions", "refs"],
                    "description": "Restrict to one category; 'strings' = string search. Default 'all'.",
                },
                "limit": LIMIT,
                "idb": IDB,
            },
            ["query"],
        ),
        example={"query": "recv", "kind": "strings", "limit": 20},
        backend_tool="search",
        backend_action="find",
        argument_map={"query": "pattern"},
    ),
    AgentOperation(
        name="ida_semantic_search",
        description=(
            "Find functions by behavior or natural-language intent after indexing the binary. "
            "Results are recalled by the embedding index (Stage 1) and, when a reranker is "
            "installed, re-scored by the cross-encoder (Stage 2) so the top of the list is "
            "the genuinely most relevant functions. Stage 2 runs automatically in expand "
            "mode and whenever rerank=true is passed; quick mode skips it (bounded on CPU "
            "boxes) unless explicitly requested."
        ),
        category="discovery",
        input_schema=_schema(
            {
                "query": {"type": "string", "description": "Behavior to find, such as 'function that decrypts strings'."},
                "mode": {"type": "string", "enum": ["quick", "expand"], "description": "quick is faster; expand adds behavior-driven matches."},
                "limit": LIMIT,
                "min_score": {"type": "number", "description": "Minimum semantic or hybrid rank score."},
                "rerank": {
                    "type": "boolean",
                    "description": (
                        "Re-score recalled candidates with the cross-encoder reranker. "
                        "Omitted = auto (on in expand mode, off in quick mode); explicit "
                        "true forces it, false disables it. No-op when no rerank model "
                        "is installed."
                    ),
                },
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
        name="ida_reranker_status",
        description="Report the cross-encoder reranker backend: installed model, profile, and whether it is ready.",
        category="discovery",
        input_schema=_schema(
            {
                "probe": {"type": "boolean", "description": "Start or attach the rerank server so ready reflects reality."},
                "idb": IDB,
            }
        ),
        example={"probe": True},
        backend_tool="intelligence",
        backend_action="reranker_status",
    ),
    AgentOperation(
        name="ida_function_families",
        description=(
            "Cluster lookalike functions by embedding cosine similarity and return each family "
            "with a centroid summary, a representative member, and per-member deltas. "
            "Examine the representative and skip the rest."
        ),
        category="discovery",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "radius": {"type": "integer", "description": "Byte radius around address to scope the clustering."},
                "start": {"type": "string", "description": "Inclusive start address of a scope range."},
                "end": {"type": "string", "description": "Exclusive end address of a scope range."},
                "query": {"type": "string", "description": "Optional function-name filter (substring)."},
                "min_size": {"type": "integer", "description": "Minimum family size to report (default 2)."},
                "min_similarity": {"type": "number", "description": "Cosine threshold for 'lookalike' (default 0.85)."},
                "limit": LIMIT,
                "mark_examined": {
                    "type": "boolean",
                    "description": "Record every family member as examined in one call (default false).",
                },
                "verdict": {
                    "type": "string",
                    "enum": ["boring", "interesting", "unclear"],
                    "description": "Verdict used when mark_examined is true (default boring).",
                },
                "idb": IDB,
            }
        ),
        example={"min_size": 2, "limit": 10},
        backend_tool="intelligence",
        backend_action="function_families",
        argument_map={"address": "addr"},
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
            "limit": "_index_total_limit",
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
        example={"value": "0x1234"},
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
                "bit_op": {
                    "type": "string",
                    "enum": ["and", "or", "xor", "not", "shl", "shr"],
                    "description": "Bitwise operation to apply (and, or, xor, not, shl, shr).",
                },
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
        input_schema=_schema({
            "address": ADDRESS,
            "idb": IDB,
            "details": {"type": "boolean", "description": "Include verbose enrichment: var_rename_hints, annotated_code, complexity, dataflow top_hubs. Default false."},
        }, ["address"]),
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
        description="Add, replace, or clear a comment at an address in the IDB.",
        category="edit",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "comment": {
                    "type": "string",
                    "minLength": 0,
                    "description": "Comment text. An empty string clears the comment.",
                },
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
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
        name="ida_export_findings",
        description=(
            "Export the investigation workspace (findings, hypotheses, "
            "questions, tasks, decisions) as full-fidelity JSON or "
            "human-readable Markdown in the findings format, with evidence, "
            "kind, status, confidence, priority, and tags. Pass a path to "
            "write a file; otherwise the content is returned inline."
        ),
        category="findings",
        input_schema=_schema({
            "format": {
                "type": "string",
                "enum": ["json", "markdown"],
                "description": "json: full-fidelity machine-readable snapshot. markdown: grouped report. Default json.",
            },
            "path": {"type": "string", "description": "Absolute output file path; when given, the file is written and the response returns the path instead of inline content."},
            "kind": {"type": "string", "description": "Only export items of this kind."},
            "status": {"type": "string", "enum": ["open", "confirmed", "resolved", "rejected"]},
            "category": {"type": "string"},
            "address": ADDRESS,
            "tag": {"type": "string"},
            "min_confidence": {"type": "number", "description": "Only export items at or above this confidence."},
            "include_resolved": {"type": "boolean", "description": "Include resolved items. Default true."},
            "include_contradicted": {"type": "boolean", "description": "Include items that contradict another item. Default true."},
            "limit": {"type": "integer", "description": "Cap the number of exported items; omit for the full workspace."},
        }),
        example={"format": "markdown", "limit": 50},
        backend_tool="blackboard",
        backend_action="export",
        argument_map={"address": "addr"},
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
    # ------------------------------------------------------------------ #
    # Hex / bytes view                                                    #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_read_bytes",
        description="Read raw bytes at an address. Returns hex dump and ASCII preview.",
        category="code",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "size": {"type": "integer", "description": "Number of bytes to read (max 4096)."},
                "idb": IDB,
            },
            ["address", "size"],
        ),
        example={"address": "0x1000", "size": 64},
        backend_tool="data",
        backend_action="read_bytes",
        argument_map={"address": "addr"},
    ),
    # ------------------------------------------------------------------ #
    # Patch bytes / nop                                                   #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_patch_bytes",
        description=(
            "Patch raw bytes at an address in the IDB. "
            "Pass hex_bytes (e.g. '9090') to write arbitrary bytes, "
            "or nop=true to nop-out the instruction(s) at the address."
        ),
        category="edit",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "hex_bytes": {"type": "string", "description": "Hex string of bytes to write, e.g. '9090'."},
                "nop": {"type": "boolean", "description": "If true, overwrite instruction(s) at address with NOPs."},
                "count": {"type": "integer", "description": "Number of bytes to NOP (default: size of instruction at address)."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["address", "risk_ack"],
        ),
        example={"address": "0x1234", "hex_bytes": "9090", "risk_ack": True},
        backend_tool="modify",
        backend_action="patch_bytes",
        argument_map={"address": "addr", "risk_ack": "_risk_ack"},
    ),
    # ------------------------------------------------------------------ #
    # IDB management / on-the-fly analysis control                        #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_save_idb",
        description=(
            "Save the current IDB to disk. "
            "Use after making significant changes (renames, comments, type fixes, patches) "
            "to ensure work is not lost if IDA exits. "
            "Optionally pass path= to save to a different file."
        ),
        category="edit",
        input_schema=_schema({
            "path": {"type": "string", "description": "Save path (default: current IDB path, i.e. in-place save)."},
            "idb": IDB,
            "risk_ack": RISK_ACK,
        }, ["risk_ack"]),
        example={"risk_ack": True},
        backend_tool="analysis",
        backend_action="save_idb",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_make_code",
        description=(
            "Force bytes at an address to be disassembled as a CPU instruction. "
            "Use when IDA has marked the location as data (db/dw/dq) or undefined (unk_) "
            "but you know it is valid code — for example a missed entry point, a tail call "
            "target, or an obfuscated branch destination. "
            "Automatically requeues the containing function for reanalysis."
        ),
        category="edit",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "size": {"type": "integer", "description": "Number of bytes to clear before creating instruction (default: auto-detect from current item)."},
                "idb": IDB,
                "risk_ack": RISK_ACK,
            },
            ["address", "risk_ack"],
        ),
        example={"address": "0x401234", "risk_ack": True},
        backend_tool="analysis",
        backend_action="make_code",
        argument_map={"address": "addr", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_undefine",
        description=(
            "Undefine (turn to raw bytes) code or data at an address range. "
            "Removes all IDA annotations for the region so it can be reinterpreted. "
            "Follow with ida_make_code, a type declaration, or reanalysis."
        ),
        category="edit",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "size": {"type": "integer", "description": "Number of bytes to undefine (default: size of current item at address)."},
                "idb": IDB,
                "risk_ack": RISK_ACK,
            },
            ["address", "risk_ack"],
        ),
        example={"address": "0x401234", "size": 4, "risk_ack": True},
        backend_tool="analysis",
        backend_action="undefine",
        argument_map={"address": "addr", "risk_ack": "_risk_ack"},
    ),
    # ------------------------------------------------------------------ #
    # Local variable rename                                               #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_rename_local",
        description=(
            "Rename a local variable inside a decompiled function. "
            "address is the function address; var_name is the current name (e.g. v3); "
            "new_name is the desired name."
        ),
        category="edit",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "var_name": {"type": "string", "description": "Current local variable name as shown in decompiler (e.g. v3, a1)."},
                "new_name": {"type": "string", "description": "New name for the local variable."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["address", "var_name", "new_name", "risk_ack"],
        ),
        example={"address": "0x401000", "var_name": "v3", "new_name": "packet_len", "risk_ack": True},
        backend_tool="modify",
        backend_action="rename_local",
        argument_map={"address": "addr", "risk_ack": "_risk_ack"},
    ),
    # ------------------------------------------------------------------ #
    # Struct / type editor                                                #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_get_type",
        description="Get a struct, enum, or typedef from the type library. Shows members, offsets, and sizes.",
        category="code",
        input_schema=_schema(
            {"name": {"type": "string", "description": "Type name to look up."}, "idb": IDB},
            ["name"],
        ),
        example={"name": "SOME_STRUCT"},
        backend_tool="types",
        backend_action="get",
    ),
    AgentOperation(
        name="ida_declare_type",
        description=(
            "Define a new struct, enum, or typedef in the local type library from a C declaration. "
            "E.g. 'struct pkt_hdr { uint32_t magic; uint16_t len; uint16_t flags; };'"
        ),
        category="edit",
        input_schema=_schema(
            {
                "declaration": {"type": "string", "description": "C declaration string, e.g. 'struct foo { int x; int y; };'"},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["declaration", "risk_ack"],
        ),
        example={"declaration": "struct pkt_hdr { uint32_t magic; uint16_t len; };", "risk_ack": True},
        backend_tool="types",
        backend_action="declare",
        argument_map={"declaration": "decl", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_apply_type",
        description=(
            "Apply a type to an address. kind=function sets a function prototype; "
            "kind=global sets a data variable type; kind=local sets a local variable type "
            "inside a decompiled function (requires var_name)."
        ),
        category="edit",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "type_str": {"type": "string", "description": "C type declaration or prototype to apply."},
                "kind": {
                    "type": "string",
                    "enum": ["function", "global", "local"],
                    "description": "What to type: function prototype, global variable, or local variable.",
                },
                "var_name": {"type": "string", "description": "Local variable name (required when kind=local)."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["address", "type_str", "risk_ack"],
        ),
        example={"address": "0x401000", "type_str": "int __fastcall foo(int a, int b);", "kind": "function", "risk_ack": True},
        backend_tool="types",
        backend_action="apply",
        argument_map={"address": "addr", "type_str": "decl", "var_name": "name", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_list_types",
        description="List structs, enums, and typedefs in the type library, optionally filtered by name.",
        category="discovery",
        input_schema=_schema(
            {
                "query": {"type": "string", "description": "Optional name filter."},
                "kind": {
                    "type": "string",
                    "enum": ["struct", "enum", "typedef", "all"],
                    "description": "Filter by kind (default: all).",
                },
                "limit": LIMIT,
                "idb": IDB,
            },
        ),
        example={"kind": "struct", "limit": 20},
        backend_tool="types",
        backend_action="list",
        argument_map={"limit": "count"},
    ),
    # ------------------------------------------------------------------ #
    # Segment management                                                  #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_list_segments",
        description="List all segments in the binary with name, address range, permissions, and class.",
        category="discovery",
        input_schema=_schema({"idb": IDB}),
        example={},
        backend_tool="segments",
        backend_action="list",
    ),
    AgentOperation(
        name="ida_add_segment",
        description="Create a new segment in the IDB.",
        category="edit",
        input_schema=_schema(
            {
                "start": {"type": "string", "description": "Start address (hex)."},
                "end": {"type": "string", "description": "End address (hex, exclusive)."},
                "name": {"type": "string", "description": "Segment name, e.g. .mmio or ROM."},
                "sclass": {
                    "type": "string",
                    "description": "Segment class: CODE, DATA, BSS, CONST, STACK, XTRN, etc.",
                },
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["start", "end", "name", "risk_ack"],
        ),
        example={"start": "0x40000000", "end": "0x40001000", "name": ".mmio", "sclass": "DATA", "risk_ack": True},
        backend_tool="segments",
        backend_action="add",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_set_segment_attrs",
        description=(
            "Update one segment attribute: name, align, comb, perm, bitness, type, or color. "
            "Pass the segment's start address plus attr and value. "
            "For permissions use attr='perm' with value like 'rwx' or an integer bitmap."
        ),
        category="edit",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "attr": {
                    "type": "string",
                    "description": "Segment attribute to change: name, align, comb, perm, bitness, type, or color.",
                },
                "value": {
                    "type": "string",
                    "description": "New value for the attribute (e.g. 'rwx' or an integer bitmap such as '0x7' for perm).",
                },
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["address", "attr", "value", "risk_ack"],
        ),
        example={"address": "0x40000000", "attr": "perm", "value": "rwx", "risk_ack": True},
        backend_tool="segments",
        backend_action="set_attr",
        argument_map={"address": "start", "attr": "attr", "value": "value", "risk_ack": "_risk_ack"},
    ),
    # ------------------------------------------------------------------ #
    # Call graph export                                                   #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_callgraph",
        description=(
            "Export a call graph rooted at a function. "
            "direction=down follows callees, up follows callers, both follows both. "
            "format=mermaid is best for rendering; json for programmatic use."
        ),
        category="code",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "depth": {"type": "integer", "description": "Max traversal depth (default 5)."},
                "direction": {
                    "type": "string",
                    "enum": ["down", "up", "both"],
                    "description": "Traversal direction.",
                },
                "format": {
                    "type": "string",
                    "enum": ["json", "dot", "mermaid"],
                    "description": "Output format.",
                },
                "max_nodes": {"type": "integer", "description": "Max nodes to collect (default 500)."},
                "idb": IDB,
            },
            ["address"],
        ),
        example={"address": "0x401000", "depth": 3, "format": "mermaid"},
        backend_tool="graph",
        backend_action="callgraph",
        argument_map={"address": "addr", "max_nodes": "max_items"},
    ),
    # ------------------------------------------------------------------ #
    # FLIRT signature application                                         #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_apply_sig",
        description=(
            "Apply a FLIRT signature file to the current IDB to rename known library functions. "
            "Use ida_list_sigs to see available signature files."
        ),
        category="edit",
        input_schema=_schema(
            {
                "name": {"type": "string", "description": "Signature name (without .sig extension), e.g. 'android_arm', 'gnu'."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["name", "risk_ack"],
        ),
        example={"name": "android_arm", "risk_ack": True},
        backend_tool="misc",
        backend_action="load_sig",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_list_sigs",
        description="List available FLIRT signature files that can be applied with ida_apply_sig.",
        category="discovery",
        input_schema=_schema(
            {
                "query": {"type": "string", "description": "Optional name filter."},
                "idb": IDB,
            },
        ),
        example={"query": "arm"},
        backend_tool="misc",
        backend_action="list_sigs",
        argument_map={"query": "name"},
    ),
    AgentOperation(
        name="ida_python",
        description=(
            "Execute a Python expression or script in the active IDA process; "
            "idaapi, idc, and idautils are in scope. "
            "When several agents share one MCP connection, pass idb=<session_id> "
            "to target a specific session instead of the shared active one."
        ),
        category="support",
        input_schema=_schema(
            {
                "code": {
                    "type": "string",
                    "description": "Python expression or script to execute in IDA context.",
                },
                "risk_ack": CODE_EXEC_ACK,
                "idb": IDB,
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
    # ------------------------------------------------------------------ #
    # Segment registers (segmented-mode sreg mapping)                    #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_sreg_get",
        description="Read the current segment-register mapping for a code address (segmented mode).",
        category="discovery",
        input_schema=_schema(
            {
                "start": ADDRESS,
                "reg": {"type": "string", "description": "Segment register name (e.g. 'cs', 'ds', 'ss', 'es', 'fs', 'gs')."},
                "idb": IDB,
            },
            ["start", "reg"],
        ),
        example={"start": "0x401000", "reg": "cs"},
        backend_tool="segments",
        backend_action="sreg_get",
    ),
    AgentOperation(
        name="ida_sreg_set",
        description="Set the segment-register mapping for a code address (segmented mode).",
        category="edit",
        input_schema=_schema(
            {
                "start": ADDRESS,
                "reg": {"type": "string", "description": "Segment register name (e.g. 'cs', 'ds', 'ss', 'es', 'fs', 'gs')."},
                # String for numeric selectors too: Vertex converts JSON Schema
                # type unions into any_of, which cannot sit beside description.
                "value": {"type": "string", "description": "Segment selector or value to map the register to (e.g. '0x30')."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["start", "reg", "value", "risk_ack"],
        ),
        example={"start": "0x401000", "reg": "ds", "value": "0x30", "risk_ack": True},
        backend_tool="segments",
        backend_action="sreg_set",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_sreg_list",
        description="List the segment-register mappings in effect for a code address (segmented mode).",
        category="discovery",
        input_schema=_schema(
            {
                "start": ADDRESS,
                "idb": IDB,
            },
            ["start"],
        ),
        example={"start": "0x401000"},
        backend_tool="segments",
        backend_action="sreg_list",
    ),
    # ------------------------------------------------------------------ #
    # Raw-blob authoring / reversibility primitives (modify)             #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_create_data",
        description=(
            "Define a data item (or a run of them) at an address so raw blobs become analyzable "
            "without redeclaring types. type selects the item kind: byte|word|dword|qword|pointer|array."
        ),
        category="edit",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "type": {
                    "type": "string",
                    "enum": ["byte", "word", "dword", "qword", "pointer", "array"],
                    "description": "Data item kind to lay (default: byte). 'pointer' lays FF_DWORD items; 'array' lays count dword-sized elements.",
                },
                "count": {"type": "integer", "description": "Number of consecutive items to lay (default 1)."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["address", "risk_ack"],
        ),
        example={"address": "0x1234", "type": "dword", "count": 16, "risk_ack": True},
        backend_tool="modify",
        backend_action="create_data",
        argument_map={"address": "addr", "type": "item_type", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_create_strlit",
        description="Define a string literal covering [address, address+size). strtype is 'c' (C string), 'c16' (UTF-16), or 'c32' (UTF-32).",
        category="edit",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "size": {"type": "integer", "description": "Byte length of the string literal."},
                "strtype": {
                    "type": "string",
                    "enum": ["c", "c16", "c32"],
                    "description": "String encoding (default 'c').",
                },
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["address", "size", "risk_ack"],
        ),
        example={"address": "0x1234", "size": 16, "strtype": "c", "risk_ack": True},
        backend_tool="modify",
        backend_action="create_strlit",
        argument_map={"address": "addr", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_undo_begin",
        description="Open an undo transaction so a failing batch can be rolled back. Pair with ida_undo_end.",
        category="edit",
        input_schema=_schema({"idb": IDB, "risk_ack": RISK_ACK}, ["risk_ack"]),
        example={"risk_ack": True},
        backend_tool="modify",
        backend_action="undo_begin",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_undo_end",
        description="Commit the changes wrapped by an ida_undo_begin transaction.",
        category="edit",
        input_schema=_schema({"idb": IDB, "risk_ack": RISK_ACK}, ["risk_ack"]),
        example={"risk_ack": True},
        backend_tool="modify",
        backend_action="undo_end",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    # ------------------------------------------------------------------ #
    # Entry points / IDB snapshots / analysis wait                       #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_add_entry",
        description="Mark an address as an entry point in the IDB (reclassifies it as code and adds an entry-point flag).",
        category="edit",
        input_schema=_schema(
            {"address": ADDRESS, "risk_ack": RISK_ACK, "idb": IDB},
            ["address", "risk_ack"],
        ),
        example={"address": "0x401000", "risk_ack": True},
        backend_tool="analysis",
        backend_action="add_entry",
        argument_map={"address": "addr", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_idb_snapshot",
        description="Save a named snapshot of the current IDB state so experiments can be rolled back with ida_idb_restore_snapshot.",
        category="edit",
        input_schema=_schema(
            {
                "name": {"type": "string", "description": "Optional snapshot name/label."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["risk_ack"],
        ),
        example={"name": "before_cleanup", "risk_ack": True},
        backend_tool="analysis",
        backend_action="snapshot",
        argument_map={"name": "snapshot_name", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_idb_restore_snapshot",
        description="Restore the IDB to a previously saved snapshot (pass ordinal or snapshot_id from ida_idb_snapshot).",
        category="edit",
        input_schema=_schema(
            {
                "ordinal": {"type": "integer", "description": "Snapshot ordinal to restore (0 = most recent)."},
                "snapshot_id": {"type": "string", "description": "Snapshot id/name to restore."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["risk_ack"],
        ),
        example={"snapshot_id": "before_cleanup", "risk_ack": True},
        backend_tool="analysis",
        backend_action="restore_snapshot",
        argument_map={"snapshot_id": "snapshot_name", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_auto_wait",
        description="Block until IDA's automatic analysis queue is idle (waits for a quiet IDB before batch work).",
        category="discovery",
        input_schema=_schema(
            {
                "timeout_ms": {"type": "integer", "description": "Max wait in milliseconds (default bounded by the RPC timeout)."},
                "idb": IDB,
            }
        ),
        example={},
        backend_tool="analysis",
        backend_action="auto_wait",
    ),
    # ------------------------------------------------------------------ #
    # Struct / enum member editing + TIL carry                           #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_struct_member_add",
        description="Add a member to a struct type. offset is the byte offset (-1 appends at the end); provide type_str or size.",
        category="edit",
        input_schema=_schema(
            {
                "struct_name": {"type": "string", "description": "Struct type name."},
                "member_name": {"type": "string", "description": "New member name."},
                "offset": {"type": "integer", "description": "Member byte offset (-1 appends)."},
                "type_str": {"type": "string", "description": "C type string for the member."},
                "size": {"type": "integer", "description": "Member size in bytes when type_str is omitted."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["struct_name", "member_name", "risk_ack"],
        ),
        example={"struct_name": "pkt_hdr", "member_name": "crc", "type_str": "uint32_t", "offset": -1, "risk_ack": True},
        backend_tool="types",
        backend_action="struct_member_add",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_struct_member_del",
        description="Delete a member from a struct type by name.",
        category="edit",
        input_schema=_schema(
            {
                "struct_name": {"type": "string", "description": "Struct type name."},
                "member_name": {"type": "string", "description": "Member name to delete."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["struct_name", "member_name", "risk_ack"],
        ),
        example={"struct_name": "pkt_hdr", "member_name": "crc", "risk_ack": True},
        backend_tool="types",
        backend_action="struct_member_del",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_struct_member_rename",
        description="Rename a member of a struct type.",
        category="edit",
        input_schema=_schema(
            {
                "struct_name": {"type": "string", "description": "Struct type name."},
                "member_name": {"type": "string", "description": "Current member name."},
                "new_name": {"type": "string", "description": "Replacement member name."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["struct_name", "member_name", "new_name", "risk_ack"],
        ),
        example={"struct_name": "pkt_hdr", "member_name": "crc", "new_name": "checksum", "risk_ack": True},
        backend_tool="types",
        backend_action="struct_member_rename",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_struct_member_set_type",
        description="Retype a member of a struct type from a C type string.",
        category="edit",
        input_schema=_schema(
            {
                "struct_name": {"type": "string", "description": "Struct type name."},
                "member_name": {"type": "string", "description": "Member name to retype."},
                "type_str": {"type": "string", "description": "C type string for the member."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["struct_name", "member_name", "type_str", "risk_ack"],
        ),
        example={"struct_name": "pkt_hdr", "member_name": "crc", "type_str": "uint64_t", "risk_ack": True},
        backend_tool="types",
        backend_action="struct_member_set_type",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_enum_member_add",
        description="Add an enumerator to an enum type (enum_name + member_name + numeric value).",
        category="edit",
        input_schema=_schema(
            {
                "enum_name": {"type": "string", "description": "Enum type name."},
                "member_name": {"type": "string", "description": "New enumerator name."},
                "value": {"type": "integer", "description": "Numeric value of the enumerator."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["enum_name", "member_name", "value", "risk_ack"],
        ),
        example={"enum_name": "status_t", "member_name": "STATUS_BUSY", "value": 2, "risk_ack": True},
        backend_tool="types",
        backend_action="enum_member_add",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_enum_member_rename",
        description="Rename an enumerator in an enum type.",
        category="edit",
        input_schema=_schema(
            {
                "enum_name": {"type": "string", "description": "Enum type name."},
                "member_name": {"type": "string", "description": "Current enumerator name."},
                "new_name": {"type": "string", "description": "Replacement enumerator name."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["enum_name", "member_name", "new_name", "risk_ack"],
        ),
        example={"enum_name": "status_t", "member_name": "STATUS_BUSY", "new_name": "STATUS_WAIT", "risk_ack": True},
        backend_tool="types",
        backend_action="enum_member_rename",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_enum_member_revalue",
        description="Revalue an enumerator in an enum type (new numeric value).",
        category="edit",
        input_schema=_schema(
            {
                "enum_name": {"type": "string", "description": "Enum type name."},
                "member_name": {"type": "string", "description": "Enumerator name to revalue."},
                "value": {"type": "integer", "description": "New numeric value."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["enum_name", "member_name", "value", "risk_ack"],
        ),
        example={"enum_name": "status_t", "member_name": "STATUS_WAIT", "value": 5, "risk_ack": True},
        backend_tool="types",
        backend_action="enum_member_revalue",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_til_delete",
        description="Delete a named type from the local Type Library (TIL).",
        category="edit",
        input_schema=_schema(
            {"name": {"type": "string", "description": "Type name to delete."}, "risk_ack": RISK_ACK, "idb": IDB},
            ["name", "risk_ack"],
        ),
        example={"name": "OBSOLETE_STRUCT", "risk_ack": True},
        backend_tool="types",
        backend_action="til_delete",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_til_export",
        description="Export matching named types as a C header file (cross-session carry).",
        category="edit",
        input_schema=_schema(
            {
                "path": {"type": "string", "description": "Absolute output header path."},
                "name": {"type": "string", "description": "Type-name filter (default '*')."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["path", "risk_ack"],
        ),
        example={"path": "/tmp/session_types.h", "risk_ack": True},
        backend_tool="types",
        backend_action="til_export",
        argument_map={"name": "til_filter", "risk_ack": "_risk_ack"},
    ),
    AgentOperation(
        name="ida_til_import",
        description="Import a C header file into the local Type Library.",
        category="edit",
        input_schema=_schema(
            {"path": {"type": "string", "description": "Absolute header file path to import."}, "risk_ack": RISK_ACK, "idb": IDB},
            ["path", "risk_ack"],
        ),
        example={"path": "/tmp/session_types.h", "risk_ack": True},
        backend_tool="types",
        backend_action="til_import",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    # ------------------------------------------------------------------ #
    # IDB events / register state                                        #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_events",
        description="Stream recent analysis/audit events from the IDB (useful to see what IDA has been doing).",
        category="discovery",
        input_schema=_schema(
            {
                "limit": {"type": "integer", "description": "Max events to return."},
                "tail": {"type": "integer", "description": "Return only the N most recent events."},
                "idb": IDB,
            }
        ),
        example={"limit": 20},
        backend_tool="idb",
        backend_action="events",
    ),
    AgentOperation(
        name="ida_registers",
        description="Dump the register state captured at an address (debugger/emulator/analysis capture).",
        category="discovery",
        input_schema=_schema({"addr": ADDRESS, "idb": IDB}, ["addr"]),
        example={"addr": "0x401000"},
        backend_tool="idb",
        backend_action="registers",
    ),
    # ------------------------------------------------------------------ #
    # Raw-value / query-language search                                  #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_search_data_value",
        description="Locate raw byte/word values or ASCII strings in memory (e.g. '0xDEADBEEF' or a magic string).",
        category="discovery",
        input_schema=_schema(
            {
                "value": {"type": "string", "description": "Raw value to locate (hex string or ASCII text)."},
                "size": {"type": "integer", "description": "Byte width for the scan (1/2/4/8; default auto-detect)."},
                "endian": {"type": "string", "enum": ["little", "big"], "description": "Byte order (default: binary endianness)."},
                "start": {"type": "string", "description": "Inclusive start address of the scan window."},
                "end": {"type": "string", "description": "Exclusive end address of the scan window."},
                "limit": LIMIT,
                "idb": IDB,
            },
            ["value"],
        ),
        example={"value": "0xDEADBEEF", "limit": 10},
        backend_tool="search",
        backend_action="data_value",
    ),
    AgentOperation(
        name="ida_search_query_lang",
        description=(
            "Run a structured query-language search over names, strings, and imports. "
            "Lenient grammar: MATCH/WHERE are optional, aliases and operator synonyms are "
            "accepted, bare identifiers become name/text filters, and free text falls back "
            "to unified find. Examples: 'functions with size > 100', 'strings containing "
            "cmd.exe', 'calls to malloc', 'function main', 'size > 100'."
        ),
        category="discovery",
        input_schema=_schema(
            {
                "query": {"type": "string", "description": "Query-language expression (or free text)."},
                "limit": LIMIT,
                "idb": IDB,
            },
            ["query"],
        ),
        example={"query": "functions with size > 100 LIMIT 10"},
        backend_tool="search",
        backend_action="query_lang",
    ),
    # ------------------------------------------------------------------ #
    # Rizin/radare2 sidecar engine (default-off)                         #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_r2_status",
        description="Check availability of the r2 sidecar engine for a binary.",
        category="discovery",
        input_schema=_schema(
            {"binary_path": {"type": "string", "description": "Absolute path to the raw binary (default: current session binary)."}, "idb": IDB}
        ),
        example={},
        backend_tool="r2",
        backend_action="status",
    ),
    AgentOperation(
        name="ida_r2_bininfo",
        description="Get r2 file metadata (arch/bits/entry/imports) for a binary without an IDB.",
        category="discovery",
        input_schema=_schema(
            {
                "binary_path": {"type": "string", "description": "Absolute path to the raw binary (default: current session binary)."},
                "addr": {"type": "string", "description": "Optional address/offset to resolve into the binary."},
                "idb": IDB,
            }
        ),
        example={},
        backend_tool="r2",
        backend_action="bininfo",
    ),
    AgentOperation(
        name="ida_r2_load_hints",
        description="Get r2-suggested load addresses for a raw binary (base/entry hypotheses).",
        category="discovery",
        input_schema=_schema(
            {
                "binary_path": {"type": "string", "description": "Absolute path to the raw binary (default: current session binary)."},
                "addr": {"type": "string", "description": "Optional address/offset to frame the hints."},
                "idb": IDB,
            }
        ),
        example={},
        backend_tool="r2",
        backend_action="load_hints",
    ),
    AgentOperation(
        name="ida_r2_disassemble_hypothesis",
        description="Disassemble at an address/offset with r2, without an IDB — useful to test a load-base or instruction-boundary hypothesis.",
        category="discovery",
        input_schema=_schema(
            {
                "address": {"type": "string", "description": "Address or file offset to disassemble at."},
                "binary_path": {"type": "string", "description": "Absolute path to the raw binary (default: current session binary)."},
                "count": {"type": "integer", "description": "Max instructions to disassemble."},
                "idb": IDB,
            },
            ["address"],
        ),
        example={"address": "0x1000", "count": 16},
        backend_tool="r2",
        backend_action="disassemble_hypothesis",
        argument_map={"address": "addr"},
    ),
    AgentOperation(
        name="ida_r2_vxrefs",
        description="Find raw pointer-word references to a value with r2 (no IDB cross-references needed).",
        category="discovery",
        input_schema=_schema(
            {
                "value": {"type": "string", "description": "Target value to find pointer-word references to."},
                "binary_path": {"type": "string", "description": "Absolute path to the raw binary (default: current session binary)."},
                "limit": LIMIT,
                "idb": IDB,
            },
            ["value"],
        ),
        example={"value": "0x20000000", "limit": 20},
        backend_tool="r2",
        backend_action="vxrefs",
    ),
    # ------------------------------------------------------------------ #
    # Dangerous-API marking                                              #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_mark_dangerous",
        description="Mark dangerous API calls with warning comments (optionally scoped to one function).",
        category="edit",
        input_schema=_schema(
            {
                "address": ADDRESS,
                "prefix": {"type": "string", "description": "Prefix for generated comments (default '[MCP] ')."},
                "limit": {"type": "integer", "description": "Max warnings to add."},
                "dry_run": {"type": "boolean", "description": "Preview without writing."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["address", "risk_ack"],
        ),
        example={"address": "0x401000", "risk_ack": True},
        backend_tool="annotation",
        backend_action="mark_dangerous",
        argument_map={"address": "addr", "risk_ack": "_risk_ack"},
    ),
    # ------------------------------------------------------------------ #
    # Raw-binary firmware shaping (headerless blobs)                     #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_fw_detect_vector_table",
        description="Detect a Cortex-M reset/ISR vector table in a raw firmware blob (start/end bound the scan window).",
        category="discovery",
        input_schema=_schema(
            {
                "start": {"type": "string", "description": "Inclusive start address of the scan window."},
                "end": {"type": "string", "description": "Exclusive end address of the scan window."},
                "limit": LIMIT,
                "idb": IDB,
            }
        ),
        example={"start": "0x0", "end": "0x400"},
        backend_tool="firmware",
        backend_action="detect_vector_table",
    ),
    AgentOperation(
        name="ida_fw_detect_load_base",
        description="Infer the preferred load base for a raw firmware blob.",
        category="discovery",
        input_schema=_schema(
            {
                "start": {"type": "string", "description": "Inclusive start address of the candidate window."},
                "end": {"type": "string", "description": "Exclusive end address of the candidate window."},
                "idb": IDB,
            }
        ),
        example={},
        backend_tool="firmware",
        backend_action="detect_load_base",
    ),
    AgentOperation(
        name="ida_fw_detect_mmio",
        description="Locate memory-mapped peripheral regions in a raw firmware blob.",
        category="discovery",
        input_schema=_schema(
            {
                "start": {"type": "string", "description": "Inclusive start address of the scan window."},
                "end": {"type": "string", "description": "Exclusive end address of the scan window."},
                "limit": LIMIT,
                "idb": IDB,
            }
        ),
        example={},
        backend_tool="firmware",
        backend_action="detect_mmio",
    ),
    AgentOperation(
        name="ida_fw_rtos_scan",
        description="Heuristically detect an RTOS kernel inside a raw firmware blob.",
        category="discovery",
        input_schema=_schema(
            {
                "start": {"type": "string", "description": "Inclusive start address of the scan window."},
                "end": {"type": "string", "description": "Exclusive end address of the scan window."},
                "limit": LIMIT,
                "idb": IDB,
            }
        ),
        example={},
        backend_tool="firmware",
        backend_action="rtos_scan",
    ),
    AgentOperation(
        name="ida_fw_carve",
        description="Extract a code/data region of a raw firmware blob into a bounded range.",
        category="discovery",
        input_schema=_schema(
            {
                "start": {"type": "string", "description": "Inclusive start address of the region to carve."},
                "end": {"type": "string", "description": "Exclusive end address of the region to carve."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["start", "end", "risk_ack"],
        ),
        example={"start": "0x800", "end": "0x2000", "risk_ack": True},
        backend_tool="firmware",
        backend_action="carve",
        argument_map={"risk_ack": "_risk_ack"},
    ),
    # ------------------------------------------------------------------ #
    # Emulation / debugger (ida_dbg)                                     #
    # ------------------------------------------------------------------ #
    AgentOperation(
        name="ida_emulate",
        description=(
            "Drive IDA's built-in emulator/debugger (ida_dbg) end to end. Auto-selects "
            "a backend at runtime (built-in emulator candidates first, then the native "
            "backend) and reports the active backend in every response. Actions: info "
            "(overview: backend, why chosen, process state, registers), backend, start, "
            "state, step (mode into|over|ret, count), run_to, suspend, continue, stop, "
            "get_reg, set_reg, read_mem, set_mem. Mutating actions require risk_ack=true."
        ),
        category="code",
        input_schema=_schema(
            {
                "action": {
                    "type": "string",
                    "enum": [
                        "info", "backend", "start", "state", "step", "run_to",
                        "suspend", "continue", "stop", "get_reg", "set_reg",
                        "read_mem", "set_mem",
                    ],
                    "description": "Emulation action to run.",
                },
                "name": {"type": "string", "description": "Register name (get_reg/set_reg) or backend name (backend)."},
                "names": {"type": "array", "items": {"type": "string"}, "description": "Registers to read in one get_reg call."},
                # Use a string for numeric register values too (hex or decimal):
                # Vertex converts JSON Schema type unions into any_of, which
                # cannot be combined with this field's description in a function
                # declaration. The backend parses int(str(value), 0).
                "value": {"type": "string", "description": "Register value for set_reg (hex string like '0x10' or decimal string)."},
                "address": {"type": "string", "description": "Function name or hexadecimal address for run_to/read_mem/set_mem."},
                "size": {"type": "integer", "description": "Byte count for read_mem (default 16)."},
                "data": {"type": "string", "description": "Hex bytes to write for set_mem (e.g. '9090')."},
                "start_addr": {"type": "string", "description": "Optional start address for start."},
                "args": {"type": "string", "description": "Process argv string for start."},
                "input_file": {"type": "string", "description": "Input file path for start."},
                "dir": {"type": "string", "description": "Working directory for start."},
                "count": {"type": "integer", "description": "Step count (default 1)."},
                "mode": {"type": "string", "enum": ["into", "over", "ret"], "description": "Step mode (default 'into')."},
                "force": {"type": "boolean", "description": "Reload the backend even if one is loaded (backend action)."},
                "unload": {"type": "boolean", "description": "Unload the backend after stop."},
                "governed": {"type": "boolean", "description": "Run the governance pre-check on mutating actions (default true)."},
                "timeout_ms": {"type": "integer", "description": "Per-action timeout in milliseconds (default 30000)."},
                "risk_ack": RISK_ACK,
                "idb": IDB,
            },
            ["action"],
        ),
        example={"action": "info"},
        backend_tool="emulate",
        backend_action="info",
        argument_map={"risk_ack": "_risk_ack"},
    ),
)


def _stamp_risk_tiers(ops: tuple[AgentOperation, ...]) -> tuple[AgentOperation, ...]:
    """Fill ``risk_tier`` from the backend pair so policy has one record per op."""
    stamped: list[AgentOperation] = []
    for op in ops:
        if op.risk_tier is not None:
            stamped.append(op)
            continue
        if op.help_only or not op.backend_tool:
            stamped.append(replace(op, risk_tier=RiskTier.READ))
            continue
        stamped.append(
            replace(
                op,
                risk_tier=classify_legacy_pair(op.backend_tool, op.backend_action),
            )
        )
    return tuple(stamped)


AGENT_OPERATIONS = _stamp_risk_tiers(AGENT_OPERATIONS)

_OPERATIONS_BY_NAME = {operation.name: operation for operation in AGENT_OPERATIONS}
_OPERATIONS_BY_BACKEND = {
    (operation.backend_tool, operation.backend_action): operation
    for operation in AGENT_OPERATIONS
    if operation.backend_tool and operation.backend_action
}


def backend_risk_tier(tool: str, action: str) -> RiskTier | None:
    """Return the public operation's risk tier for this backend pair, if any."""
    op = _OPERATIONS_BY_BACKEND.get((str(tool or ""), str(action or "")))
    if op is None or op.risk_tier is None:
        return None
    return op.risk_tier

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
    r"intelligence|truncation|analysis|calc|r2|firmware)\.[A-Za-z_]\w*|\baction\s*=\s*"
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


def translate_public_batch_arguments(
    arguments: Any,
    *,
    agent_surface: bool = False,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Translate nested public ``ida_*`` calls to the compatibility batch form.

    When ``agent_surface`` is true (the default MCP surface), nested calls that
    are not public ``ida_*`` operations are rejected instead of being forwarded
    as legacy ``tool(action=...)`` entries.
    """
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
            if agent_surface:
                return None, make_error(
                    MCPError.TOOL_NOT_FOUND,
                    f"'{name}' is not a public operation.",
                    hint=(
                        "Use ida_help(query=...) to find the matching ida_* "
                        "operation, or set IDA_MCP_TOOL_SURFACE=legacy."
                    ),
                    details={"name": name, "batch_index": index},
                )
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
            # Keep later calls runnable when continue_on_error is set; the
            # batch executor records this as the step result and does not
            # send it to IDA.
            backend_args: dict[str, Any] = {}
            if operation.backend_action:
                backend_args["action"] = operation.backend_action
            translated.append({
                "name": operation.backend_tool or operation.name,
                "arguments": backend_args,
                "_precomputed_error": validation_error,
            })
            continue
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
- Responses carry an injected recall channel:
  - `_recall` — what is already known about this address (prior findings,
    verdicts, and their `[mcp:]`-anchored claims). Read it before re-deriving
    anything.
  - `_already_examined` — addresses in the response you previously dismissed;
    do not re-read them as if they were new.
  - `_stale` — a claim whose underlying code changed after it was recorded.
    Re-check that claim rather than trusting it; a stale verdict means the
    code moved, not that the analysis was wrong.
  - `_recall_error` — when recall itself could not be loaded (e.g. no
    workspace). Proceed, but note that prior-session memory is unavailable.
- `ida_next_target(strategy=...)` picks the next investigation point:
  `unresolved` for open threads, `coverage` for functions nobody has read,
  `frontier` to expand from confirmed findings, `stale` and `conflict` for
  claims that need repair. Every candidate states why it was chosen. On
  opaque/raw binaries with no function inventory, `coverage` returns an
  explicit note (`coverage_pct=0`) instead of silently reporting an empty
  coverage.
- If `ida_write_finding` returns a `conflict`, two claims about the same thing
  disagree. Resolve it with `ida_update_finding` before building on either.
- Accept or reject background proposals explicitly. The crawler and trace
  machinery create real `proposed` entries and notify with the real entry id;
  respond with `ida_update_finding(entry_id=..., status="confirmed")` (accept)
  or `status="rejected"` with a reason, rather than leaving them in limbo.
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
