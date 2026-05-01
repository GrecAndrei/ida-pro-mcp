"""
Batch tool - Execute multiple tool calls in a single request.
Reduces round-trips for LLMs that need to perform several operations.
Supports dependency resolution, result piping, conditional execution, templates, and dry-run.
"""

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import importlib


# Predefined batch templates for common RE workflows
_BATCH_TEMPLATES = {
    "analyze_function": [
        {"tool": "code", "action": "decompile", "addr": "$addr"},
        {"tool": "data", "action": "strings_in_func", "addr": "$addr"},
        {"tool": "code", "action": "xrefs_from", "addr": "$addr"},
    ],
    "find_vulns_quick": [
        {"tool": "vuln_scan", "action": "dangerous_apis", "limit": 20},
        {"tool": "vuln_scan", "action": "taint_lattice", "limit": 10},
        {"tool": "taint", "action": "find_sinks", "addr": "$addr", "depth": 3},
    ],
    "map_binary": [
        {"tool": "binary_info", "action": "headers"},
        {"tool": "segments", "action": "list"},
        {"tool": "data", "action": "imports", "count": 50},
        {"tool": "data", "action": "functions", "count": 50},
    ],
    "deep_function_audit": [
        {"tool": "code", "action": "decompile", "addr": "$addr"},
        {"tool": "code", "action": "disasm", "addr": "$addr"},
        {"tool": "string_ops", "action": "find_xrefs", "addr": "$addr"},
        {"tool": "taint", "action": "find_sinks", "addr": "$addr", "depth": 5},
        {"tool": "vuln_scan", "action": "dangerous_apis", "addr": "$addr"},
    ],
    "crypto_hunt": [
        {"tool": "crypto_id", "action": "scan", "limit": 20},
        {"tool": "entropy", "action": "crypto_detect", "limit": 10},
        {"tool": "string_ops", "action": "entropy_rank", "limit": 20},
    ],
    "c2_investigation": [
        {"tool": "string_ops", "action": "find_c2", "limit": 30},
        {"tool": "string_ops", "action": "find_urls", "limit": 20},
        {"tool": "c2_detect", "action": "behavior_summary", "limit": 20},
    ],
}


def _resolve_template(calls, template_vars):
    """Expand template variables ($key) in calls."""
    if not template_vars:
        return calls
    resolved = []
    for call in calls:
        new_call = {}
        for k, v in call.items():
            if isinstance(v, str) and v.startswith("$") and v[1:] in template_vars:
                new_call[k] = template_vars[v[1:]]
            else:
                new_call[k] = v
        resolved.append(new_call)
    return resolved


def _resolve_dependencies(calls):
    """Topological sort of calls based on depends_on field."""
    n = len(calls)
    graph = {i: set() for i in range(n)}
    dependents = {i: [] for i in range(n)}
    for i, call in enumerate(calls):
        deps = call.get("depends_on")
        if deps is None:
            continue
        if isinstance(deps, int):
            deps = [deps]
        for dep in deps:
            if not isinstance(dep, int) or dep < 0 or dep >= n:
                return None, f"Call {i}: invalid dependency index {dep}"
            if dep >= i:
                return None, f"Call {i}: dependency {dep} must refer to an earlier call"
            graph[i].add(dep)
            dependents[dep].append(i)
    # Detect cycles using DFS
    visited = [0] * n  # 0=unvisited, 1=visiting, 2=done
    order = []
    def dfs(u):
        visited[u] = 1
        for v in dependents.get(u, []):
            if visited[v] == 1:
                return False
            if visited[v] == 0 and not dfs(v):
                return False
        visited[u] = 2
        order.append(u)
        return True
    for i in range(n):
        if visited[i] == 0 and not dfs(i):
            return None, "Circular dependency detected in batch calls"
    # Build execution order: process nodes with no deps first
    in_degree = [len(graph[i]) for i in range(n)]
    queue = [i for i in range(n) if in_degree[i] == 0]
    exec_order = []
    while queue:
        u = queue.pop(0)
        exec_order.append(u)
        for v in dependents.get(u, []):
            in_degree[v] -= 1
            if in_degree[v] == 0:
                queue.append(v)
    if len(exec_order) != n:
        return None, "Circular dependency detected in batch calls"
    return exec_order, None


def _pipe_result(call, results):
    """Resolve pipe references in call parameters."""
    pipe_from = call.get("pipe_from")
    if pipe_from is None:
        return call
    if not isinstance(pipe_from, int) or pipe_from < 0 or pipe_from >= len(results):
        return call
    source_result = results[pipe_from]
    if not isinstance(source_result, dict):
        return call
    pipe_field = call.get("pipe_field", "")
    if pipe_field:
        value = source_result.get(pipe_field)
    else:
        # Auto-detect common output fields
        for field in ("results", "data", "functions", "strings", "urls", "paths", "value"):
            if field in source_result:
                value = source_result[field]
                break
        else:
            value = None
    new_call = dict(call)
    # Replace "$pipe" placeholder in any parameter
    for k, v in list(new_call.items()):
        if isinstance(v, str) and v == "$pipe":
            new_call[k] = value
    return new_call


def _check_condition(call, results):
    """Evaluate conditional execution based on previous results."""
    condition = call.get("if_result")
    if condition is None:
        return True, None
    if not isinstance(condition, dict):
        return True, None
    idx = condition.get("index")
    if idx is None or not isinstance(idx, int) or idx < 0 or idx >= len(results):
        return False, f"Invalid condition index {idx}"
    prev = results[idx]
    if not isinstance(prev, dict):
        return False, f"Condition refers to non-dict result at index {idx}"
    op = condition.get("op", "exists")
    field = condition.get("field", "ok")
    expected = condition.get("value", True)
    actual = prev.get(field)
    if op == "exists":
        ok = actual is not None
    elif op == "eq":
        ok = actual == expected
    elif op == "ne":
        ok = actual != expected
    elif op == "gt":
        try:
            ok = actual > expected
        except Exception:
            ok = False
    elif op == "lt":
        try:
            ok = actual < expected
        except Exception:
            ok = False
    elif op == "contains":
        try:
            ok = expected in actual
        except Exception:
            ok = False
    else:
        ok = False
    if not ok:
        return False, f"Condition not met: result[{idx}].{field} {op} {expected} (actual: {actual})"
    return True, None


@tool
@idaread
def batch(
    calls: Annotated[list[dict], "List of tool calls: [{tool: str, action: str, ...params}]"],
    stop_on_error: Annotated[bool, "Stop executing remaining calls if one fails"] = False,
    dry_run: Annotated[bool, "Validate all calls without executing"] = False,
    template: Annotated[Optional[str], "Use a predefined template (analyze_function, find_vulns_quick, map_binary, deep_function_audit, crypto_hunt, c2_investigation)"] = None,
    template_vars: Annotated[Optional[dict], "Variables for template expansion (e.g., {addr: '0x401000'})"] = None,
    **kwargs
) -> dict:
    """
    Execute multiple tool calls in a single request.

    Supports dependency resolution, result piping, conditional execution,
    predefined templates, and dry-run validation.

    Each item in `calls` should be a dict with at least:
      - tool: The tool name (e.g. "code", "data", "search")
      - action: The action to perform
      - ...additional parameters for that tool

    Advanced features:
      - depends_on: [int] or int — indices of calls that must complete first.
      - pipe_from: int — index of call whose output feeds into this call.
      - pipe_field: str — field name to extract from piped result (default: auto-detect).
      - if_result: {"index": int, "field": str, "op": "eq|ne|gt|lt|contains|exists", "value": any}
        — conditionally execute based on a previous result.

    Templates:
      - analyze_function: decompile + strings + xrefs for a function
      - find_vulns_quick: dangerous APIs + taint + sinks
      - map_binary: headers + segments + imports + functions
      - deep_function_audit: comprehensive single-function analysis
      - crypto_hunt: crypto constants + entropy + high-entropy strings
      - c2_investigation: C2 strings + URLs + behavior summary

    Example:
        batch(calls=[
            {"tool": "code", "action": "decompile", "addr": "0x401000"},
            {"tool": "data", "action": "strings", "count": 10},
        ])

        batch(template="analyze_function", template_vars={"addr": "0x401000"})

        batch(calls=[
            {"tool": "search", "action": "find", "pattern": "malloc"},
            {"tool": "code", "action": "decompile", "pipe_from": 0, "addr": "$pipe"},
        ])

    Returns a list of results, one per call, in the execution order.
    """
    if not calls and not template:
        return make_error(MCPError.INVALID_ARGS, "calls list or template is required")

    if template:
        tmpl = _BATCH_TEMPLATES.get(template)
        if not tmpl:
            return make_error(MCPError.INVALID_ARGS, f"Unknown template: {template}", hint=f"Available: {', '.join(_BATCH_TEMPLATES.keys())}")
        calls = _resolve_template(tmpl, template_vars or {})

    if not calls:
        return make_error(MCPError.INVALID_ARGS, "calls list is required and cannot be empty")

    if len(calls) > 20:
        return make_error(MCPError.INVALID_ARGS, "Maximum 20 calls per batch",
                         hint="Split into multiple batch calls")

    # Resolve dependencies to get execution order
    exec_order, dep_err = _resolve_dependencies(calls)
    if dep_err:
        return make_error(MCPError.INVALID_ARGS, dep_err)

    # Lazy-load the tool registry
    tools_registry = {}

    def get_tool(name):
        if not isinstance(name, str) or not name.replace("_", "").isalnum():
            return None
        if name not in tools_registry:
            try:
                mod = importlib.import_module(f".{name}", package=__package__)
                tools_registry[name] = getattr(mod, name)
            except (ImportError, AttributeError):
                tools_registry[name] = None
        return tools_registry[name]

    # Dry-run: validate all calls without executing
    if dry_run:
        validation_errors = []
        validated = 0
        for idx in exec_order:
            call = calls[idx]
            tool_name = call.get("tool")
            if not tool_name:
                validation_errors.append(f"Call {idx}: missing 'tool' key")
                continue
            tool_func = get_tool(tool_name)
            if tool_func is None:
                validation_errors.append(f"Call {idx}: tool '{tool_name}' not found")
                continue
            validated += 1
        return {
            "ok": True,
            "dry_run": True,
            "total": len(calls),
            "validated": validated,
            "errors": validation_errors,
            "execution_order": exec_order,
        }

    results = [None] * len(calls)
    executed = 0
    skipped = 0

    for idx in exec_order:
        call = calls[idx]
        if not isinstance(call, dict):
            results[idx] = make_error(MCPError.INVALID_ARGS, f"Call {idx}: expected dict, got {type(call).__name__}")
            if stop_on_error:
                break
            continue

        # Conditional execution
        should_run, cond_err = _check_condition(call, results)
        if not should_run:
            results[idx] = {"ok": True, "skipped": True, "reason": cond_err}
            skipped += 1
            continue

        # Resolve piping
        call = _pipe_result(call, results)

        tool_name = call.get("tool")
        if not tool_name:
            results[idx] = make_error(MCPError.INVALID_ARGS, f"Call {idx}: tool key is required")
            if stop_on_error:
                break
            continue

        tool_func = get_tool(tool_name)
        if tool_func is None:
            results[idx] = make_error(MCPError.TOOL_NOT_FOUND, f"Call {idx}: tool {tool_name} not found")
            if stop_on_error:
                break
            continue

        # Build kwargs for the tool (exclude meta keys)
        meta_keys = {"tool", "depends_on", "pipe_from", "pipe_field", "if_result"}
        tool_kwargs = {k: v for k, v in call.items() if k not in meta_keys}

        try:
            result = tool_func(**tool_kwargs)
            results[idx] = result
            executed += 1
            if stop_on_error and isinstance(result, dict) and result.get("error"):
                break
        except Exception as e:
            results[idx] = handle_error(e, context=f"batch call {idx} ({tool_name})")
            if stop_on_error:
                break

    succeeded = sum(1 for r in results if isinstance(r, dict) and not r.get("error") and not r.get("skipped"))
    failed = sum(1 for r in results if isinstance(r, dict) and r.get("error"))

    return {
        "ok": True,
        "results": results,
        "total": len(calls),
        "executed": executed,
        "skipped": skipped,
        "succeeded": succeeded,
        "failed": failed,
        "execution_order": exec_order,
    }
