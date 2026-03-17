"""
Batch tool - Execute multiple tool calls in a single request.
Reduces round-trips for LLMs that need to perform several operations.
"""

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import importlib


@tool
@idaread
def batch(
    calls: Annotated[list[dict], "List of tool calls: [{tool: str, action: str, ...params}]"],
    stop_on_error: Annotated[bool, "Stop executing remaining calls if one fails"] = False,
    **kwargs
) -> dict:
    """
    Execute multiple tool calls in a single request.

    Each item in `calls` should be a dict with at least:
      - tool: The tool name (e.g. "code", "data", "search")
      - action: The action to perform
      - ...additional parameters for that tool

    Example:
        batch(calls=[
            {"tool": "code", "action": "decompile", "addr": "0x401000"},
            {"tool": "data", "action": "strings", "count": 10},
            {"tool": "search", "action": "find", "pattern": "malloc"}
        ])

    Returns a list of results, one per call, in the same order.
    """
    if not calls:
        return make_error(MCPError.INVALID_ARGS, "calls list is required and cannot be empty")

    if len(calls) > 20:
        return make_error(MCPError.INVALID_ARGS, "Maximum 20 calls per batch",
                         hint="Split into multiple batch calls")

    # Lazy-load the tool registry
    tools_registry = {}

    def get_tool(name):
        # Validate tool name to prevent arbitrary module loading
        if not isinstance(name, str) or not name.replace("_", "").isalnum():
            return None
        if name not in tools_registry:
            try:
                mod = importlib.import_module(f".{name}", package=__package__)
                tools_registry[name] = getattr(mod, name)
            except (ImportError, AttributeError):
                tools_registry[name] = None
        return tools_registry[name]

    results = []
    for i, call in enumerate(calls):
        if not isinstance(call, dict):
            results.append(make_error(MCPError.INVALID_ARGS, f"Call {i}: expected dict, got {type(call).__name__}"))
            if stop_on_error:
                break
            continue

        tool_name = call.get("tool")
        if not tool_name:
            results.append(make_error(MCPError.INVALID_ARGS, f"Call {i}: tool key is required"))
            if stop_on_error:
                break
            continue

        tool_func = get_tool(tool_name)
        if tool_func is None:
            results.append(make_error(MCPError.TOOL_NOT_FOUND, f"Call {i}: tool {tool_name} not found"))
            if stop_on_error:
                break
            continue

        # Build kwargs for the tool (exclude 'tool' key itself)
        tool_kwargs = {k: v for k, v in call.items() if k != "tool"}

        try:
            result = tool_func(**tool_kwargs)
            results.append(result)
            if stop_on_error and isinstance(result, dict) and result.get("error"):
                break
        except Exception as e:
            results.append(handle_error(e, context=f"batch call {i} ({tool_name})"))
            if stop_on_error:
                break

    succeeded = sum(1 for r in results if isinstance(r, dict) and not r.get("error"))
    failed = len(results) - succeeded

    return {
        "ok": True,
        "results": results,
        "total": len(calls),
        "executed": len(results),
        "succeeded": succeeded,
        "failed": failed,
    }
