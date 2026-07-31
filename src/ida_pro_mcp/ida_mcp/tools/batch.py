"""
Batch tool - Execute multiple tool calls in a single request.
Reduces round-trips for LLMs that need to perform several operations.
Supports dependency resolution, result piping, conditional execution, templates, dry-run, and macro DSL.
"""

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]

import contextlib
import importlib
import json
import re
from typing import Any, Dict, List

# =============================================================================
# Macro DSL Interpreter (embedded into batch to avoid standalone duplication)
# =============================================================================

def _macro_get_path(data: Any, path: str) -> Any:
    if not path or path == ".":
        return data
    current = data
    for part in path.split("."):
        part = part.strip()
        if not part:
            continue
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            idx = int(part)
            current = current[idx] if 0 <= idx < len(current) else None
        else:
            return None
        if current is None:
            return None
    return current


def _macro_eval_cond(item: Any, expr: str) -> bool:
    expr = expr.strip()
    m = re.match(r"(.+?)\s*(==|!=|<=|>=|<|>)\s*(.+)", expr)
    if not m:
        val = _macro_get_path(item, expr)
        return bool(val) if val is not None else False
    left_path, op, right_raw = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
    left_val = _macro_get_path(item, left_path)
    right_raw = right_raw.strip('"\'')
    try:
        right_val = int(right_raw)
    except ValueError:
        try:
            right_val = float(right_raw)
        except ValueError:
            right_val = right_raw
    if left_val is None:
        return False
    try:
        if op == "==":
            return str(left_val) == str(right_val)
        elif op == "!=":
            return str(left_val) != str(right_val)
        elif op == "<":
            return float(left_val) < float(right_val)
        elif op == ">":
            return float(left_val) > float(right_val)
        elif op == "<=":
            return float(left_val) <= float(right_val)
        elif op == ">=":
            return float(left_val) >= float(right_val)
    except (ValueError, TypeError):
        return False
    return False


def _macro_apply_pipe_op(data: Any, op: str) -> Any:
    op = op.strip()
    if op == "count":
        return len(data) if isinstance(data, (list, dict, str)) else 0
    elif op.startswith("first(") and op.endswith(")"):
        n = int(op[6:-1])
        if isinstance(data, list):
            return data[:n]
        return data
    elif op.startswith("sort(") and op.endswith(")"):
        key = op[5:-1]
        desc = key.startswith("-")
        if desc:
            key = key[1:]
        if isinstance(data, list):
            try:
                return sorted(data, key=lambda x: (_macro_get_path(x, key) or 0), reverse=desc)
            except Exception:
                return data
        return data
    elif op == "unique":
        if isinstance(data, list):
            seen = []
            uniq = []
            for x in data:
                k = json.dumps(x, sort_keys=True, separators=(",", ":"))
                if k not in seen:
                    seen.append(k)
                    uniq.append(x)
            return uniq
        return data
    elif op.startswith("pluck(") and op.endswith(")"):
        key = op[6:-1]
        if isinstance(data, list):
            return [_macro_get_path(x, key) for x in data]
        return _macro_get_path(data, key)
    elif op == "reverse":
        if isinstance(data, list):
            return list(reversed(data))
        return data
    elif op.startswith("filter(") and op.endswith(")"):
        cond = op[7:-1]
        if isinstance(data, list):
            return [x for x in data if _macro_eval_cond(x, cond)]
        return data
    elif op.startswith("group_by(") and op.endswith(")"):
        key = op[9:-1]
        if isinstance(data, list):
            groups: Dict[str, List] = {}
            for x in data:
                k = str(_macro_get_path(x, key) or "null")
                groups.setdefault(k, []).append(x)
            return groups
        return data
    return data


class MacroDSLInterpreter:
    """Simple deterministic interpreter for the macro DSL."""

    def __init__(self):
        self.vars: Dict[str, Any] = {"_": None}
        self.results: List[Dict] = []
        self.tools_registry: Dict[str, Any] = {}

    def _get_tool(self, name: str):
        if not isinstance(name, str) or not name.replace("_", "").isalnum():
            return None
        if name not in self.tools_registry:
            try:
                mod = importlib.import_module(f".{name}", package=__package__)
                self.tools_registry[name] = getattr(mod, name)
            except (ImportError, AttributeError):
                self.tools_registry[name] = None
        return self.tools_registry[name]

    def run(self, script: str) -> Dict:
        lines = [l.strip() for l in script.splitlines() if l.strip() and not l.strip().startswith("#")]
        for line in lines:
            self._execute_line(line)
        return {
            "ok": True,
            "results": self.results,
            "vars": {k: v for k, v in self.vars.items() if not k.startswith("_")},
        }

    def _execute_line(self, line: str):
        if line.startswith("return "):
            expr = line[7:].strip()
            self.vars["_"] = self._eval_expr(expr)
            return
        if line.startswith("set "):
            m = re.match(r"set\s+(\w+)\s*=\s+(.+)", line)
            if m:
                var_name, expr = m.group(1), m.group(2).strip()
                self.vars[var_name] = self._eval_expr(expr)
                return
        if line.startswith("filter "):
            m = re.match(r"filter\s+(\w+)\s+where\s+(.+)", line)
            if m:
                var_name, cond = m.group(1), m.group(2)
                data = self.vars.get(var_name, [])
                if isinstance(data, list):
                    self.vars[var_name] = [x for x in data if _macro_eval_cond(x, cond)]
                return
        if line.startswith("for "):
            m = re.match(r"for\s+(\w+)\s+in\s+(\w+):\s*(.+)", line)
            if m:
                item_var, list_var, stmt = m.group(1), m.group(2), m.group(3).strip()
                data = self.vars.get(list_var, [])
                out = []
                for item in data:
                    self.vars[item_var] = item
                    result = self._eval_expr(stmt)
                    out.append(result)
                self.vars["_"] = out
                return
        if line.startswith("if "):
            m = re.match(r"if\s+(.+):\s*(.+)", line)
            if m:
                cond, stmt = m.group(1), m.group(2).strip()
                if self._eval_cond(cond):
                    self._eval_expr(stmt)
                return
        self.vars["_"] = self._eval_expr(line)

    def _eval_expr(self, expr: str) -> Any:
        expr = expr.strip()
        if "|" in expr:
            parts = [p.strip() for p in expr.split("|")]
            current = self._eval_expr(parts[0])
            for op in parts[1:]:
                current = _macro_apply_pipe_op(current, op)
            return current
        tool_match = re.match(r"(\w+)\((.*)\)", expr)
        if tool_match:
            tool_name, args_str = tool_match.group(1), tool_match.group(2)
            args = self._parse_args(args_str)
            tool_func = self._get_tool(tool_name)
            if tool_func is None:
                result = make_error(MCPError.TOOL_NOT_FOUND, f"Tool '{tool_name}' not found")
            else:
                try:
                    result = tool_func(**args)
                except Exception as e:
                    result = make_error("TOOL_ERROR", f"{tool_name} failed: {e}")
            self.results.append({"tool": tool_name, "args": args, "result": result})
            return result
        if expr in self.vars:
            return self.vars[expr]
        try:
            return json.loads(expr)
        except json.JSONDecodeError:
            pass
        if (expr.startswith('"') and expr.endswith('"')) or (expr.startswith("'") and expr.endswith("'")):
            return expr[1:-1]
        return expr

    def _parse_args(self, args_str: str) -> Dict[str, Any]:
        args = {}
        if not args_str.strip():
            return args
        tokens = []
        current = ""
        in_quote = False
        quote_char = None
        for c in args_str:
            if c in ('"', "'") and not in_quote:
                in_quote = True
                quote_char = c
                current += c
            elif c == quote_char and in_quote:
                in_quote = False
                quote_char = None
                current += c
            elif c == "," and not in_quote:
                tokens.append(current.strip())
                current = ""
            else:
                current += c
        if current.strip():
            tokens.append(current.strip())
        for token in tokens:
            if "=" not in token:
                continue
            k, v = token.split("=", 1)
            k = k.strip()
            v = v.strip()
            with contextlib.suppress(json.JSONDecodeError):
                v = json.loads(v)
            args[k] = v
        return args

    def _eval_cond(self, cond: str) -> bool:
        cond = cond.strip()
        m = re.match(r"(.+?)\s*(==|!=|<=|>=|<|>)\s*(.+)", cond)
        if not m:
            val = self.vars.get(cond)
            return bool(val) if val is not None else False
        left, op, right_raw = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
        left_val = self.vars.get(left)
        if left_val is None:
            return False
        right_raw = right_raw.strip('"\'')
        try:
            right_val = int(right_raw)
        except ValueError:
            try:
                right_val = float(right_raw)
            except ValueError:
                right_val = right_raw
        try:
            if op == "==":
                return str(left_val) == str(right_val)
            elif op == "!=":
                return str(left_val) != str(right_val)
            elif op == "<":
                return float(left_val) < float(right_val)
            elif op == ">":
                return float(left_val) > float(right_val)
            elif op == "<=":
                return float(left_val) <= float(right_val)
            elif op == ">=":
                return float(left_val) >= float(right_val)
        except (ValueError, TypeError):
            return False
        return False


# Predefined batch templates for common RE workflows
_BATCH_TEMPLATES = {
    "analyze_function": [
        {"tool": "code", "action": "decompile", "addr": "$addr"},
        {"tool": "data", "action": "strings_in_func", "addr": "$addr"},
        {"tool": "code", "action": "xrefs_from", "addr": "$addr"},
    ],
    "map_binary": [
        {"tool": "idb", "action": "summary"},
        {"tool": "segments", "action": "list"},
        {"tool": "data", "action": "imports", "count": 50},
        {"tool": "data", "action": "functions", "count": 50},
    ],
    "deep_function_audit": [
        {"tool": "code", "action": "decompile", "addr": "$addr"},
        {"tool": "code", "action": "disasm", "addr": "$addr"},
        {"tool": "code", "action": "callers", "addr": "$addr"},
        {"tool": "code", "action": "callees", "addr": "$addr"},
    ],
    "crypto_hunt": [
        {"tool": "search", "action": "find", "query": "aes rc4 blowfish base64", "limit": 20},
        {"tool": "data", "action": "strings", "count": 20},
    ],
    "network_protocol_hunt": [
        {"tool": "search", "action": "find", "query": "recv send connect socket", "limit": 20},
        {"tool": "search", "action": "find", "query": "http:// https:// url ip", "limit": 20},
        {"tool": "data", "action": "strings", "count": 30},
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
    calls: Annotated[list[dict], "List of tool calls: [{tool: str, action: str, ...params}]"] = None,
    stop_on_error: Annotated[bool, "Stop executing remaining calls if one fails"] = False,
    dry_run: Annotated[bool, "Validate all calls without executing"] = False,
    template: Annotated[Optional[str], "Use a predefined template (analyze_function, find_vulns_quick, map_binary, deep_function_audit, crypto_hunt, c2_investigation)"] = None,
    template_vars: Annotated[Optional[dict], "Variables for template expansion (e.g., {addr: '0x401000'})"] = None,
    script: Annotated[Optional[str], "Macro DSL script for complex multi-step workflows. Alternative to 'calls'."] = None,
    **kwargs
) -> dict:
    """
    Execute multiple tool calls in a single request.

    Supports dependency resolution, result piping, conditional execution,
    predefined templates, dry-run validation, and macro DSL scripting.

    JSON Mode (calls):
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

    DSL Mode (script):
      Provide a macro script instead of calls for complex workflows with
      variables, loops, conditionals, and pipes.

      set targets = search(action="bytes", pattern="48 89 5C 24")
      filter targets where size > 100
      for t in targets: code(action="decompile", addr=t.addr)
      return _

    Templates:
      - analyze_function: decompile + strings + xrefs for a function
      - map_binary: headers + segments + imports + functions
      - deep_function_audit: decompile + disasm + string xrefs + call chain
      - crypto_hunt: crypto constants + entropy + high-entropy strings
      - network_protocol_hunt: protocol detection + URLs + string search

    Example:
        batch(calls=[
            {"tool": "code", "action": "decompile", "addr": "0x401000"},
            {"tool": "data", "action": "strings", "count": 10},
        ])

        batch(template="analyze_function", template_vars={"addr": "0x401000"})

        batch(script='''
            set imports = data(action="imports")
            imports | pluck(name) | unique | count
            return _
        ''')

    Returns a list of results, one per call, in the execution order.
    """
    if script and script.strip():
        if dry_run:
            lines = [l.strip() for l in script.splitlines() if l.strip() and not l.strip().startswith("#")]
            detected = []
            for line in lines:
                m = re.search(r"(\w+)\(", line)
                if m:
                    detected.append(m.group(1))
            return {
                "ok": True,
                "dry_run": True,
                "mode": "script",
                "lines": len(lines),
                "tool_calls_detected": detected,
            }
        interpreter = MacroDSLInterpreter()
        result = interpreter.run(script)
        result["final"] = interpreter.vars.get("_")
        return result

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

    def _normalize_tool_name(name):
        if not isinstance(name, str):
            return name
        n = name.strip()
        if not n:
            return n
        if "." in n:
            n = n.split(".")[-1]
        if ":" in n:
            n = n.split(":")[-1]
        if "/" in n:
            n = n.split("/")[-1]
        if n.startswith("ida-pro-mcp_"):
            n = n[len("ida-pro-mcp_"):]
        return n

    def get_tool(name):
        name = _normalize_tool_name(name)
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
