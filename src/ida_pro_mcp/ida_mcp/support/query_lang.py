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

import contextlib
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

# The support package has no _common.py, so the star-import above normally
# falls back to stubs.  Pull in the real error envelope from error_handling
# (pure stdlib, no IDA SDK dependency) so every error response honors the
# {error: True, code, message, hint} contract instead of a bare dict.  The
# relative import resolves against whatever parent package hosts this module
# (ida_pro_mcp.ida_mcp in the venv, ida_mcp in standalone IDA mode).
try:
    from ..error_handling import ERROR_HINTS, MCPError, make_error  # noqa: F401
except (ImportError, ValueError):
    pass

# Arch-aware call alias set for MATCH call: exact-mnemonic search over the
# real cross-arch CALL_MNEMONICS (call/jal/jalr/c.jal/c.jalr + link branches).
try:
    from ida_pro_mcp.ida_mcp.support.arch_utils import CALL_MNEMONICS as _CALL_MNEMONICS
    from ida_pro_mcp.ida_mcp.support.arch_utils import get_arch as _get_arch
except ImportError:
    try:
        from arch_utils import CALL_MNEMONICS as _CALL_MNEMONICS  # type: ignore[import-not-found]
        from arch_utils import get_arch as _get_arch  # type: ignore[import-not-found]
    except ImportError:
        _CALL_MNEMONICS = frozenset({
            "call", "jal", "jalr", "c.jal", "c.jalr",
            "bl", "blx", "blr", "bla", "bsr", "jsr",
            "call0", "call4", "call8", "call12",
            "callx0", "callx4", "callx8", "callx12",
            "calla", "calli", "rcall", "icall", "eicall",
        })

        def _get_arch() -> str:
            """Fallback arch probe when arch_utils is unavailable."""
            return "unknown"

# Per-arch subsets so MATCH call * on, say, x86 searches only "call" instead of
# re-scanning every exec segment for each of ~25 aliases.
_ARCH_CALL_ALIASES = {
    "x86": {"call"},
    "x64": {"call"},
    "arm": {"bl", "blx", "call"},
    "arm64": {"bl", "blr", "call"},
    "riscv": {"jal", "jalr", "c.jal", "c.jalr"},
    "riscv64": {"jal", "jalr", "c.jal", "c.jalr"},
    "mips": {"jal", "jalr", "call"},
    "mips64": {"jal", "jalr", "call"},
    "ppc": {"bl", "bla", "call"},
    "ppc64": {"bl", "bla", "call"},
}

if "tool" not in globals():
    def tool(f):
        return f  # type: ignore
if "idaread" not in globals():
    def idaread(f):
        return f  # type: ignore
if "IDAError" not in globals():
    IDAError = Exception  # type: ignore
if "make_error" not in globals():
    def make_error(code, msg, **kw):
        return {"error": True, "code": code, "message": msg, **kw}  # type: ignore
if "MCPError" not in globals():
    class MCPError:
        INVALID_ARGS = "INVALID_ARGS"


_TOOL_CACHE: Dict[str, Any] = {}


def _get_tool(name: str):
    if name not in _TOOL_CACHE:
        try:
            # Tool modules live in the sibling tools package, not support/.
            mod = importlib.import_module(f"..tools.{name}", package=__package__)
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
        """Parse AND-separated conditions, respecting quoted strings."""
        result = []
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
            elif not in_quote and conditions[i:i+5].upper() == " AND ":
                tokens.append(current.strip())
                current = ""
                i += 5
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
                with contextlib.suppress(ValueError):
                    val = float(val)
            return {"key": key, "op": op, "value": val}
        return None


class QueryExecutor:
    """Execute parsed query plans by delegating to existing tools."""

    def __init__(self, limit: int = 1000):
        # ``limit`` is the candidate-window cap: the maximum number of items
        # fetched from the underlying tools before WHERE filtering.  It is
        # distinct from the DSL ``LIMIT N`` clause (a post-filter result cap).
        try:
            self._fetch_limit = max(1, int(limit))
        except (TypeError, ValueError):
            self._fetch_limit = 1000

    def execute(self, plan: Dict) -> Dict:
        target = plan["target"]
        method = getattr(self, f"_execute_{target}", None)
        if not method:
            return make_error(MCPError.INVALID_ARGS, f"Unknown target: {target}")
        return method(plan)

    @staticmethod
    def _window_capped(response: Dict, fetched: int, window: Optional[int] = None) -> bool:
        """Whether the underlying tool's response reflects a capped window.

        The search/data tools report a full/DB-wide ``total`` next to the
        page ``count`` (``total > count`` means more candidates exist than
        were fetched) or an explicit ``truncated`` flag.  When neither is
        present and a ``window`` cap was actually applied, the fetch limit
        itself is the conservative signal.  This drives the ``truncated`` /
        ``total_matches`` response keys so ``total`` is never silently
        under-reported.
        """
        if not isinstance(response, dict):
            return False
        if isinstance(response.get("total"), int) and isinstance(response.get("count"), int):
            return response["total"] > response["count"]
        if response.get("truncated"):
            return True
        if window is not None:
            return fetched >= window
        return False

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
                if isinstance(actual, (list, str)):
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

    def _apply_postprocessing(self, results: List[Dict], plan: Dict, capped: bool = False) -> Dict:
        limit = plan["limit"]
        sort_key = plan.get("sort_key")
        sort_order = plan.get("sort_order", "ASC")
        group_key = plan.get("group_key")

        if sort_key:
            with contextlib.suppress(Exception):
                results = sorted(
                    results,
                    key=lambda x: (x.get(sort_key) is None, x.get(sort_key) or 0),
                    reverse=(sort_order == "DESC"),
                )

        total = len(results)
        results = results[:limit]

        if group_key:
            groups: Dict[str, List] = {}
            for r in results:
                k = str(r.get(group_key, "null"))
                groups.setdefault(k, []).append(r)
            response: Dict = {
                "ok": True,
                "total": total,
                "returned": len(results),
                "grouped": groups,
                "plan": plan,
            }
        else:
            response = {
                "ok": True,
                "total": total,
                "returned": len(results),
                "results": results,
                "plan": plan,
            }

        if capped:
            # The candidate window filled before the whole IDB was scanned, so
            # ``total`` is a lower bound on the true match count.  Mirror the
            # search suite's timed_out/truncated convention: surface it
            # explicitly instead of silently under-reporting.
            response["truncated"] = True
            response["total_matches"] = total
        return response

    def _execute_function(self, plan: Dict) -> Dict:
        result = _call_tool("data", action="functions", count=self._fetch_limit)
        if not isinstance(result, dict) or "functions" not in result:
            return make_error("QUERY_ERROR", "Failed to fetch functions")
        funcs = result["functions"]
        if isinstance(funcs, str):
            # The data tool returns one compact line per function; fold them
            # into dicts so conditions can match on addr/size/xrefs_to/name.
            items = []
            for line in funcs.splitlines():
                entry = {"text": line}
                parts = line.split()
                if parts:
                    entry["addr"] = parts[0]
                for part in parts[1:]:
                    if part.startswith("xrefs="):
                        entry["xrefs_to"] = part[len("xrefs="):]
                    elif part.startswith("xrefs_from="):
                        entry["xrefs_from"] = part[len("xrefs_from="):]
                if len(parts) > 1:
                    entry["size"] = parts[1]
                if len(parts) > 3:
                    entry["name"] = parts[3]
                items.append(entry)
            funcs = items
        elif not isinstance(funcs, list):
            funcs = []
        matched = [f for f in funcs if self._match_conditions(f, plan["conditions"])]
        capped = self._window_capped(result, len(funcs), self._fetch_limit)
        return self._apply_postprocessing(matched, plan, capped=capped)

    @staticmethod
    def _fold_insn_matches(matches) -> List[Dict]:
        """Fold search_insns text lines into per-instruction dicts.

        search_insns returns one compact line per match (``0x1000  [jalr]``);
        the block handler does the same folding so conditions can match on
        addr/text.  Dict items are passed through untouched.
        """
        if isinstance(matches, str):
            lines = matches.splitlines()
        elif isinstance(matches, list) and matches and isinstance(matches[0], str):
            lines = matches
        else:
            return matches
        items = []
        for line in lines:
            entry = {"text": line}
            parts = line.split()
            if parts:
                entry["addr"] = parts[0]
            items.append(entry)
        return items

    @staticmethod
    def _call_alias_set() -> List[str]:
        """Arch-aware mnemonics that encode calls (exact-mnemonic search)."""
        arch = _get_arch()
        subset = _ARCH_CALL_ALIASES.get(arch)
        if subset:
            return sorted(subset)
        return sorted(_CALL_MNEMONICS)

    def _execute_call(self, plan: Dict) -> Dict:
        # Call instructions: exact-mnemonic search over the arch-aware call
        # alias set, then match conditions.  The old path searched API imports
        # for a non-'*' identifier and used a *semantic* mnemonic search for
        # '*', neither of which finds RISC-V jal/jalr/c.jal/c.jalr reliably.
        identifier = (plan["identifier"] or "").strip().strip('"\'')
        aliases = self._call_alias_set()
        if identifier and identifier != "*" and identifier in aliases:
            patterns = [identifier]
        else:
            patterns = aliases
        calls = []
        seen = set()
        capped = False
        for pat in patterns:
            result = _call_tool("search", action="insns", pattern=pat, limit=200)
            if not isinstance(result, dict):
                return make_error("QUERY_ERROR", "Failed to search calls")
            if result.get("error"):
                # Propagate the tool's error instead of folding it into a
                # false {ok: True, total: 0} success.
                return result
            if result.get("truncated"):
                capped = True
            for m in self._fold_insn_matches(result.get("results", result.get("matches", []))):
                key = str(m.get("addr") or m.get("text") or m)
                if key in seen:
                    continue
                seen.add(key)
                calls.append(m)
            if len(calls) >= 200:
                # Aggregate cap across aliases: more call sites exist.
                capped = True
                break
        matched = [c for c in calls if self._match_conditions(c, plan["conditions"])]
        return self._apply_postprocessing(matched, plan, capped=capped)

    def _execute_string(self, plan: Dict) -> Dict:
        result = _call_tool("data", action="strings", count=self._fetch_limit)
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to fetch strings")
        strings = result.get("strings", [])
        if isinstance(strings, str):
            # One compact line per string (<addr>  xrefs=N  <content>); fold
            # into dicts so conditions can match on addr/xrefs_to/text.
            items = []
            for line in strings.splitlines():
                entry = {"text": line}
                parts = line.split()
                if parts:
                    entry["addr"] = parts[0]
                for part in parts[1:]:
                    if part.startswith("xrefs="):
                        entry["xrefs_to"] = part[len("xrefs="):]
                        break
                # The string content is everything after the xrefs= token.
                for idx, part in enumerate(parts[1:]):
                    if part.startswith("xrefs="):
                        entry["text"] = " ".join(parts[idx + 2:])
                        break
                items.append(entry)
            strings = items
        elif not isinstance(strings, list):
            strings = []
        matched = [s for s in strings if self._match_conditions(s, plan["conditions"])]
        capped = self._window_capped(result, len(strings), self._fetch_limit)
        return self._apply_postprocessing(matched, plan, capped=capped)

    def _execute_import(self, plan: Dict) -> Dict:
        result = _call_tool("data", action="imports", count=self._fetch_limit)
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to fetch imports")
        imports = result.get("imports", [])
        if isinstance(imports, str):
            # One compact line per import (<addr>  <module>  <name>); fold into
            # dicts so conditions can match on addr/module/name.
            items = []
            for line in imports.splitlines():
                entry = {"text": line}
                parts = line.split()
                if parts:
                    entry["addr"] = parts[0]
                if len(parts) > 1:
                    entry["module"] = parts[1]
                if len(parts) > 2:
                    entry["name"] = " ".join(parts[2:])
                items.append(entry)
            imports = items
        elif not isinstance(imports, list):
            imports = []
        matched = [i for i in imports if self._match_conditions(i, plan["conditions"])]
        capped = self._window_capped(result, len(imports), self._fetch_limit)
        return self._apply_postprocessing(matched, plan, capped=capped)

    def _execute_instruction(self, plan: Dict) -> Dict:
        # Exact-mnemonic search (search_insns), not the semantic
        # mnemonic/instruction search that matched loosely and returned noise.
        identifier = (plan["identifier"] or "").strip().strip('"\'')
        if identifier and identifier != "*":
            pattern = identifier
        else:
            pattern = "*"  # search_insns treats '*' as a wildcard mnemonic
        result = _call_tool("search", action="insns", pattern=pattern, limit=200)
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to search instructions")
        if result.get("error"):
            # Propagate the tool's error instead of a false {ok: True, total: 0}.
            return result
        insns = self._fold_insn_matches(result.get("results", result.get("matches", [])))
        capped = self._window_capped(result, len(insns), 200)
        matched = [i for i in insns if self._match_conditions(i, plan["conditions"])]
        return self._apply_postprocessing(matched, plan, capped=capped)

    def _execute_xref(self, plan: Dict) -> Dict:
        addr = plan["identifier"]
        result = _call_tool("code", action="xrefs_to", addr=addr)
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to fetch xrefs")
        xrefs = result.get("xrefs", result.get("results", []))
        matched = [x for x in xrefs if self._match_conditions(x, plan["conditions"])]
        # No fetch window was applied here; only explicit total/count/truncated
        # signals indicate a capped result.
        capped = self._window_capped(result, len(xrefs))
        return self._apply_postprocessing(matched, plan, capped=capped)

    def _execute_segment(self, plan: Dict) -> Dict:
        result = _call_tool("idb", action="segments")
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to fetch segments")
        segments = result.get("segments", [])
        matched = [s for s in segments if self._match_conditions(s, plan["conditions"])]
        capped = self._window_capped(result, len(segments))
        return self._apply_postprocessing(matched, plan, capped=capped)

    def _execute_block(self, plan: Dict) -> Dict:
        # Basic blocks: via the code blocks action. The identifier is the
        # function address/name whose CFG to inspect; the tool enumerates the
        # blocks of one function, not a program-wide scan.
        identifier = plan["identifier"]
        if identifier == "*":
            return make_error(
                MCPError.INVALID_ARGS,
                "block target requires a function address or name",
                hint="MATCH block <func_addr|name> WHERE ...",
            )
        result = _call_tool("code", action="blocks", addr=identifier, limit=200)
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to fetch blocks")
        if result.get("error"):
            return result
        blocks = result.get("blocks", result.get("results", []))
        if isinstance(blocks, str):
            # The code blocks action returns one compact line per block; fold
            # them into dicts so conditions can match on addr/text/succs/preds.
            block_items = []
            for line in blocks.splitlines():
                entry = {"text": line}
                parts = line.split()
                if parts:
                    entry["addr"] = parts[0]
                for part in parts[1:]:
                    if part.startswith("succs="):
                        entry["succs"] = part[len("succs="):].strip("[]")
                    elif part.startswith("preds="):
                        entry["preds"] = part[len("preds="):].strip("[]")
                block_items.append(entry)
            blocks = block_items
        elif not isinstance(blocks, list):
            blocks = []
        matched = [b for b in blocks if self._match_conditions(b, plan["conditions"])]
        capped = self._window_capped(result, len(blocks), 200)
        return self._apply_postprocessing(matched, plan, capped=capped)


def run_query_lang(query: str, limit: int = 1000) -> dict:
    """
    Execute a high-level query language string.

    Syntax:
      MATCH <target> <identifier> WHERE <conditions>
        [LIMIT N] [SORT BY key (ASC|DESC)] [GROUP BY key]

    Args:
        query:  The query-language expression.
        limit:  Candidate-window cap for the underlying tools (default 1000).
                When the window fills before the whole IDB is scanned, the
                response carries ``truncated: True`` plus ``total_matches``
                so ``total`` is never silently under-reported.  The DSL
                ``LIMIT N`` clause is a separate post-filter result cap.

    Returns:
        {ok: True, total, returned, results, plan} or error dict.
    """
    if not query or not query.strip():
        return make_error(MCPError.INVALID_ARGS, "query is required")

    try:
        fetch_limit = max(1, int(limit))
    except (TypeError, ValueError):
        fetch_limit = 1000

    parser = QueryParser()
    plan = parser.parse(query)
    if not plan:
        # NB: error_handling.make_error() has no ``example`` kwarg; fold the
        # example into the hint so a malformed query never crashes the RPC.
        return make_error(
            MCPError.INVALID_ARGS,
            "Failed to parse query",
            hint=(
                "Expected: MATCH <target> <id> WHERE <conditions> [LIMIT N] [SORT BY key] — "
                "e.g. MATCH function * WHERE size > 100 LIMIT 10"
            ),
        )

    executor = QueryExecutor(limit=fetch_limit)
    return executor.execute(plan)
