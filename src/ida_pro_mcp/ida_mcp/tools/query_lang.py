"""
Query Language: High-level pattern matching syntax for the IDB.

Instead of forcing the LLM to pass 15 JSON arguments to search tools,
expose a custom query language that the server translates into low-level
IDA API calls.

Syntax:
  MATCH <target> WHERE <conditions> [LIMIT N] [SORT BY key]

Targets:
  function <name|*>     - Match functions
  call <name|*>         - Match call instructions
  string <pattern|*>    - Match strings
  import <name|*>       - Match imports
  xref <addr>           - Match cross-references
  instruction <mnem|*>  - Match instructions
  block <*>             - Match basic blocks
  segment <name|*>      - Match segments

Conditions:
  name == "main"
  addr >= 0x401000
  size > 100
  segment == ".text"
  entropy >= 5.5
  apis contains "malloc"
  strings contains "cmd.exe"
  arg1 == "cmd.exe"        (for call instructions)
  complexity > 10

Operators:
  ==, !=, <, >, <=, >=
  contains                (substring match for strings/lists)
  ~                       (regex match)

Aggregates:
  LIMIT N
  SORT BY key (ASC|DESC)
  GROUP BY key

Examples:
  MATCH function * WHERE size > 100 AND segment == ".text" LIMIT 10
  MATCH call * WHERE arg1 == "cmd.exe" AND segment == ".text"
  MATCH string * WHERE value ~ "http[s]?://" LIMIT 20
  MATCH function * WHERE apis contains "VirtualAlloc" SORT BY size DESC
  MATCH instruction "mov" WHERE operand ~ "eax" LIMIT 50
"""

from __future__ import annotations

import importlib
import re
from typing import Any, Dict, List, Optional

try:
    from ._common import *
except ImportError:
    try:
        from _common import *  # type: ignore[import-not-found]
    except ImportError:
        pass

if "tool" not in globals():
    tool = lambda f: f  # type: ignore
if "idaread" not in globals():
    idaread = lambda f: f  # type: ignore
if "IDAError" not in globals():
    IDAError = Exception  # type: ignore
if "make_error" not in globals():
    def make_error(code, msg, **kw):
        return {"error": msg, **kw}  # type: ignore
if "MCPError" not in globals():
    class MCPError:
        INVALID_ARGS = "INVALID_ARGS"


_TOOL_CACHE: Dict[str, Any] = {}


def _get_tool(name: str):
    if name not in _TOOL_CACHE:
        try:
            mod = importlib.import_module(f".{name}", package=__package__)
            _TOOL_CACHE[name] = getattr(mod, name)
        except (ImportError, AttributeError):
            _TOOL_CACHE[name] = None
    return _TOOL_CACHE[name]


def _call_tool(name: str, **kwargs) -> Any:
    func = _get_tool(name)
    if func is None:
        return make_error(MCPError.INVALID_ARGS, f"Tool '{name}' not available")
    try:
        return func(**kwargs)
    except Exception as e:
        return make_error("TOOL_ERROR", f"{name} failed: {e}")


class QueryParser:
    """Parse high-level query strings into executable plans."""

    QUERY_RE = re.compile(
        r"MATCH\s+(\w+)\s+(\S+)\s+WHERE\s+(.+?)(?:\s+LIMIT\s+(\d+))?(?:\s+SORT\s+BY\s+(\w+)(?:\s+(ASC|DESC))?)?(?:\s+GROUP\s+BY\s+(\w+))?\s*$",
        re.IGNORECASE | re.DOTALL,
    )

    def parse(self, query: str) -> Optional[Dict]:
        m = self.QUERY_RE.match(query.strip())
        if not m:
            return None
        target, identifier, conditions, limit, sort_key, sort_order, group_key = m.groups()
        return {
            "target": target.lower(),
            "identifier": identifier,
            "conditions": self._parse_conditions(conditions),
            "limit": int(limit) if limit else 100,
            "sort_key": sort_key,
            "sort_order": (sort_order or "ASC").upper(),
            "group_key": group_key,
        }

    def _parse_conditions(self, conditions: str) -> List[Dict]:
        """Parse AND-separated conditions."""
        result = []
        # Split by AND but be careful with string literals
        tokens = []
        current = ""
        in_quote = False
        quote_char = None
        i = 0
        while i < len(conditions):
            c = conditions[i]
            if c in ('"', "'") and not in_quote:
                in_quote = True
                quote_char = c
                current += c
            elif c == quote_char and in_quote:
                in_quote = False
                quote_char = None
                current += c
            elif c.upper() == "A" and i + 3 < len(conditions) and conditions[i:i+4].upper() == " AND" and not in_quote:
                tokens.append(current.strip())
                current = ""
                i += 4
                continue
            else:
                current += c
            i += 1
        if current.strip():
            tokens.append(current.strip())

        for token in tokens:
            cond = self._parse_single_condition(token)
            if cond:
                result.append(cond)
        return result

    def _parse_single_condition(self, cond: str) -> Optional[Dict]:
        cond = cond.strip()
        # contains
        m = re.match(r"(\w+)\s+contains\s+(.+)", cond, re.IGNORECASE)
        if m:
            key, val = m.group(1), m.group(2).strip().strip('"\'')
            return {"key": key, "op": "contains", "value": val}
        # regex ~
        m = re.match(r"(\w+)\s*~\s*(.+)", cond)
        if m:
            key, val = m.group(1), m.group(2).strip().strip('"\'')
            return {"key": key, "op": "~", "value": val}
        # comparison operators
        m = re.match(r"(\w+)\s*(==|!=|<=|>=|<|>)\s*(.+)", cond)
        if m:
            key, op, val = m.group(1), m.group(2), m.group(3).strip().strip('"\'')
            # Try numeric
            try:
                val = int(val)
            except ValueError:
                try:
                    val = float(val)
                except ValueError:
                    pass
            return {"key": key, "op": op, "value": val}
        return None


class QueryExecutor:
    """Execute parsed query plans by delegating to existing tools."""

    def execute(self, plan: Dict) -> Dict:
        target = plan["target"]
        method = getattr(self, f"_execute_{target}", None)
        if not method:
            return make_error(MCPError.INVALID_ARGS, f"Unknown target: {target}")
        return method(plan)

    def _match_conditions(self, item: Dict, conditions: List[Dict]) -> bool:
        for cond in conditions:
            key = cond["key"]
            op = cond["op"]
            expected = cond["value"]
            actual = item.get(key)
            if actual is None:
                return False
            if op == "==":
                if str(actual) != str(expected):
                    return False
            elif op == "!=":
                if str(actual) == str(expected):
                    return False
            elif op in ("<", ">", "<=", ">="):
                try:
                    a = float(actual)
                    e = float(expected)
                    if op == "<" and not (a < e):
                        return False
                    if op == ">" and not (a > e):
                        return False
                    if op == "<=" and not (a <= e):
                        return False
                    if op == ">=" and not (a >= e):
                        return False
                except (ValueError, TypeError):
                    return False
            elif op == "contains":
                if isinstance(actual, list):
                    if expected not in actual:
                        return False
                elif isinstance(actual, str):
                    if expected not in actual:
                        return False
                else:
                    return False
            elif op == "~":
                try:
                    if not re.search(expected, str(actual), re.IGNORECASE):
                        return False
                except re.error:
                    return False
        return True

    def _apply_postprocessing(self, results: List[Dict], plan: Dict) -> Dict:
        limit = plan["limit"]
        sort_key = plan.get("sort_key")
        sort_order = plan.get("sort_order", "ASC")
        group_key = plan.get("group_key")

        if sort_key:
            try:
                results = sorted(
                    results,
                    key=lambda x: (x.get(sort_key) is None, x.get(sort_key) or 0),
                    reverse=(sort_order == "DESC"),
                )
            except Exception:
                pass

        total = len(results)
        results = results[:limit]

        if group_key:
            groups: Dict[str, List] = {}
            for r in results:
                k = str(r.get(group_key, "null"))
                groups.setdefault(k, []).append(r)
            return {
                "ok": True,
                "total": total,
                "returned": len(results),
                "grouped": groups,
                "plan": plan,
            }

        return {
            "ok": True,
            "total": total,
            "returned": len(results),
            "results": results,
            "plan": plan,
        }

    def _execute_function(self, plan: Dict) -> Dict:
        result = _call_tool("data", action="functions", count=1000)
        if not isinstance(result, dict) or "functions" not in result:
            return make_error("QUERY_ERROR", "Failed to fetch functions")
        funcs = result["functions"]
        matched = [f for f in funcs if self._match_conditions(f, plan["conditions"])]
        return self._apply_postprocessing(matched, plan)

    def _execute_call(self, plan: Dict) -> Dict:
        # Call instructions: search for calls then match conditions
        identifier = plan["identifier"]
        if identifier != "*":
            result = _call_tool("search", action="api", pattern=identifier, limit=200)
        else:
            result = _call_tool("search", action="instruction", pattern="call", limit=200)
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to search calls")
        calls = result.get("results", result.get("matches", []))
        matched = [c for c in calls if self._match_conditions(c, plan["conditions"])]
        return self._apply_postprocessing(matched, plan)

    def _execute_string(self, plan: Dict) -> Dict:
        result = _call_tool("data", action="strings", count=1000)
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to fetch strings")
        strings = result.get("strings", [])
        matched = [s for s in strings if self._match_conditions(s, plan["conditions"])]
        return self._apply_postprocessing(matched, plan)

    def _execute_import(self, plan: Dict) -> Dict:
        result = _call_tool("data", action="imports", count=1000)
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to fetch imports")
        imports = result.get("imports", [])
        matched = [i for i in imports if self._match_conditions(i, plan["conditions"])]
        return self._apply_postprocessing(matched, plan)

    def _execute_instruction(self, plan: Dict) -> Dict:
        identifier = plan["identifier"]
        if identifier != "*":
            result = _call_tool("search", action="mnemonic", pattern=identifier, limit=200)
        else:
            result = _call_tool("search", action="instruction", pattern=".*", limit=200)
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to search instructions")
        insns = result.get("results", result.get("matches", []))
        matched = [i for i in insns if self._match_conditions(i, plan["conditions"])]
        return self._apply_postprocessing(matched, plan)

    def _execute_xref(self, plan: Dict) -> Dict:
        addr = plan["identifier"]
        result = _call_tool("code", action="xrefs_to", addr=addr)
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to fetch xrefs")
        xrefs = result.get("xrefs", result.get("results", []))
        matched = [x for x in xrefs if self._match_conditions(x, plan["conditions"])]
        return self._apply_postprocessing(matched, plan)

    def _execute_segment(self, plan: Dict) -> Dict:
        result = _call_tool("idb", action="segments")
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to fetch segments")
        segments = result.get("segments", [])
        matched = [s for s in segments if self._match_conditions(s, plan["conditions"])]
        return self._apply_postprocessing(matched, plan)

    def _execute_block(self, plan: Dict) -> Dict:
        # Basic blocks: via code blocks action
        result = _call_tool("code", action="blocks", addr="0x0", limit=200)
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to fetch blocks")
        blocks = result.get("blocks", result.get("results", []))
        matched = [b for b in blocks if self._match_conditions(b, plan["conditions"])]
        return self._apply_postprocessing(matched, plan)


def run_query_lang(query: str) -> dict:
    """
    Execute a high-level query language string.

    Syntax:
      MATCH <target> <identifier> WHERE <conditions>
        [LIMIT N] [SORT BY key (ASC|DESC)] [GROUP BY key]

    Returns:
        {ok: True, total, returned, results, plan} or error dict.
    """
    if not query or not query.strip():
        return make_error(MCPError.INVALID_ARGS, "query is required")

    parser = QueryParser()
    plan = parser.parse(query)
    if not plan:
        return make_error(
            MCPError.INVALID_ARGS,
            "Failed to parse query",
            hint="Expected: MATCH <target> <id> WHERE <conditions> [LIMIT N] [SORT BY key]",
            example="MATCH function * WHERE size > 100 LIMIT 10",
        )

    executor = QueryExecutor()
    return executor.execute(plan)
