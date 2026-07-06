"""
Filter: Context Guillotine — JQ-like filtering for tool outputs.

Never allow a tool to return an unbounded list.  Every tool that returns a list
MUST be post-processed through this filter before the data hits the JSON-RPC wire.

Implements a tiny deterministic query language:
  .              - identity (return as-is)
  .key           - extract field
  .key.subkey    - nested extraction
  []             - array identity
  [0:10]         - slice
  [?expr]        - filter where expression is true
  | count        - count elements
  | length       - string/array length
  | first(N)     - first N elements
  | sort(key)    - sort by key (desc with -key)
  | unique       - deduplicate
  | pluck(key)   - extract key from each object
  | reverse      - reverse array

Examples:
  filter(data=result, query=".functions[?size > 100] | first(10)")
  filter(data=result, query=".candidates | sort(-bridge_score) | first(5)")
  filter(data=result, query=".functions | pluck(name) | unique")
"""

from __future__ import annotations

import contextlib
import json
import re
from typing import Any, Dict, List

try:
    from ._common import *
except ImportError:
    try:
        from _common import *  # type: ignore[import-not-found]
    except ImportError:
        pass

if "tool" not in globals():
    def tool(f):
        return f  # type: ignore
if "idaread" not in globals():
    def idaread(f):
        return f  # type: ignore
if "IDAError" not in globals():
    IDAError = Exception  # type: ignore


def _get_path(data: Any, path: str) -> Any:
    """Navigate nested dicts/lists by dot-path."""
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


def _eval_simple_expr(item: Any, expr: str) -> bool:
    """Evaluate simple boolean expressions like 'size > 100', 'name == "main"'."""
    expr = expr.strip()
    # Handle numeric comparisons
    m = re.match(r"(.+?)\s*(==|!=|<=|>=|<|>)\s*(.+)", expr)
    if not m:
        # Treat as truthiness check
        val = _get_path(item, expr)
        return bool(val) if val is not None else False

    left_path, op, right_raw = m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
    left_val = _get_path(item, left_path)

    # Parse right side
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


def _apply_filter(data: Any, query: str) -> Any:
    """Apply a JQ-like filter string to data."""
    if not query or query == ".":
        return data

    query = query.strip()
    parts = [p.strip() for p in query.split("|")]

    # First part is always a path/selector
    current = data
    first = parts[0]

    # Handle path extraction + array filter + slice
    # Examples: .functions, .functions[0:10], .functions[?size > 100], .functions[]
    path_match = re.match(r"(\.[\w.]+)?(\[.*?\])?", first)
    if path_match:
        path = path_match.group(1) or "."
        bracket = path_match.group(2)

        if path != ".":
            current = _get_path(data, path.lstrip("."))

        if bracket:
            inner = bracket[1:-1]  # Remove [ ]
            if ":" in inner:
                # Slice [0:10]
                start, end = inner.split(":", 1)
                start = int(start.strip()) if start.strip() else 0
                end = int(end.strip()) if end.strip() else None
                if isinstance(current, list):
                    current = current[start:end]
            elif inner.startswith("?"):
                # Filter [?expr]
                expr = inner[1:].strip()
                if isinstance(current, list):
                    current = [x for x in current if _eval_simple_expr(x, expr)]
            elif inner == "":
                # Array identity []
                pass
            elif inner.isdigit():
                idx = int(inner)
                if isinstance(current, list) and 0 <= idx < len(current):
                    current = current[idx]

    # Apply pipeline operators
    for op in parts[1:]:
        op = op.strip()
        if not op:
            continue

        if op == "count":
            current = len(current) if isinstance(current, (list, dict, str)) else 0
        elif op == "length":
            current = len(current) if isinstance(current, (list, str)) else 0
        elif op.startswith("first(") and op.endswith(")"):
            n = int(op[6:-1])
            if isinstance(current, list):
                current = current[:n]
        elif op.startswith("sort(") and op.endswith(")"):
            key = op[5:-1]
            desc = key.startswith("-")
            if desc:
                key = key[1:]
            if isinstance(current, list):
                with contextlib.suppress(Exception):
                    current = sorted(
                        current,
                        key=lambda x: (_get_path(x, key) or 0),
                        reverse=desc,
                    )
        elif op == "unique":
            if isinstance(current, list):
                seen = []
                uniq = []
                for x in current:
                    # Use JSON serialization for dedup
                    k = json.dumps(x, sort_keys=True, separators=(",", ":"))
                    if k not in seen:
                        seen.append(k)
                        uniq.append(x)
                current = uniq
        elif op.startswith("pluck(") and op.endswith(")"):
            key = op[6:-1]
            if isinstance(current, list):
                current = [_get_path(x, key) for x in current]
        elif op == "reverse":
            if isinstance(current, list):
                current = list(reversed(current))
        elif op.startswith("group_by(") and op.endswith(")"):
            key = op[9:-1]
            if isinstance(current, list):
                groups: Dict[str, List] = {}
                for x in current:
                    k = str(_get_path(x, key) or "null")
                    groups.setdefault(k, []).append(x)
                current = groups

    return current


@tool
@idaread
def filter(
    data: dict = None,
    query: str = ".",
    **kwargs,
) -> dict:
    """
    Context Guillotine: JQ-like deterministic filtering for tool outputs.

    Every tool that returns a list SHOULD be post-processed through this filter
    to prevent context window overflow.  The filter runs entirely on the MCP
    server — the LLM never sees unbounded data.

    Query Syntax:
      .                  - identity (return as-is)
      .key               - extract field
      .key.subkey        - nested extraction
      []                 - array identity
      [0:10]             - slice first 10 elements
      [?expr]            - filter array where expression is true
      | count            - count elements
      | length           - string/array length
      | first(N)         - first N elements
      | sort(key)        - sort by key (prefix with - for descending)
      | unique           - deduplicate
      | pluck(key)       - extract key from each object
      | reverse          - reverse array
      | group_by(key)    - group objects by key

    Filter Expressions ([?expr]):
      Supports: ==, !=, <, >, <=, >=
      Examples: [?size > 100], [?name == "main"], [?entropy >= 5.5]

    Examples:
        # Get first 10 functions with size > 100, sorted by entropy desc
        filter(data=structured_result, query=".functions[?size > 100] | sort(-entropy) | first(10)")

        # Count candidates
        filter(data=structured_result, query=".candidates | count")

        # Get unique API names
        filter(data=structured_result, query=".functions | pluck(apis) | unique")

        # Group functions by segment
        filter(data=structured_result, query=".functions | group_by(segment)")
    """
    if data is None:
        return make_error(MCPError.INVALID_ARGS, "data required")
    try:
        result = _apply_filter(data, query)
        return {
            "ok": True,
            "filtered": result,
            "query": query,
            "original_type": type(data).__name__,
            "result_type": type(result).__name__,
        }
    except Exception as e:
        return make_error(MCPError.IDA_ERROR, f"Filter error: {e}")
