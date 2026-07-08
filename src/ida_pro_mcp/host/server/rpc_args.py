"""Pure RPC argument admission for IDA-bound tool calls.

Unknown non-underscore kwargs are rejected (not stripped). Keeping this logic
in a pure module lets host tests pin the contract without spinning a server.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..errors import MCPError, make_error


def prepare_rpc_args(
    tool_name: str,
    kwargs: Mapping[str, Any],
    tool_arg_schemas: Mapping[str, Mapping[str, Any]] | None,
) -> dict[str, Any]:
    """Build the kwargs dict that will be sent over the IDA RPC bridge.

    - Drops host-only keys that start with ``_`` (policy/qol controls).
    - If the tool has a non-empty arg schema, any remaining key not in the
      schema raises via a structured error dict (``error: true``).
    - If the schema is missing or empty, all non-underscore keys pass through
      (tools without an explicit schema stay open until schemas catch up).

    Returns either a plain args dict ready for RPC, or an error envelope from
    :func:`make_error` (callers must check with ``is_error_result`` / ``.get("error")``).
    """
    rpc_args = {
        k: v
        for k, v in kwargs.items()
        if not (isinstance(k, str) and k.startswith("_"))
    }
    schemas = tool_arg_schemas or {}
    allowed_map = schemas.get(tool_name) or {}
    if not allowed_map:
        return rpc_args

    allowed = set(allowed_map.keys())
    unknown = sorted(k for k in rpc_args if k not in allowed)
    if not unknown:
        return rpc_args

    preview = ", ".join(sorted(allowed)[:24])
    suffix = "…" if len(allowed) > 24 else ""
    return make_error(
        MCPError.INVALID_ARGS,
        f"Unknown argument(s) for tool '{tool_name}': {', '.join(unknown)}",
        hint=(
            "Remove unknown keys, or add them to "
            f"TOOL_ARG_SCHEMAS['{tool_name}'] if they are valid. "
            f"Allowed keys include: {preview}{suffix}"
        ),
        details={"unknown": unknown, "tool": tool_name},
    )
