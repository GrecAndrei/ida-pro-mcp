"""
Query Language: High-level pattern matching syntax for the IDB.

Instead of forcing the LLM to pass 15 JSON arguments to search tools,
expose a custom query language that the server translates into low-level
IDA API calls.

The parser is deliberately lenient — "very hard to use wrong". Every
reasonable phrasing resolves to a plan; nothing errors out except an empty
query.  The canonical form is::

  MATCH <target> <id> WHERE <conditions> [LIMIT N] [SORT BY key (ASC|DESC)] [GROUP BY key]

but any of these are accepted interchangeably:

  function size > 100                (no MATCH / WHERE — conditions inline)
  functions with size > 100          (plural + "with")
  find functions where size > 100    ("find" prefix)
  MATCH function main                (identifier, no conditions)
  function main                      (identifier becomes name-contains condition)
  calls to "malloc"                  (identifier after a connective)
  strings containing "cmd.exe"       ("containing" as contains)
  name = main                        (single '=' alias for '==')
  value matches "http"               ("matches" alias for '~')
  size > 100                         (no target → defaults to functions)
  what does main do                  (free text → unified find fallback)

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

Operators (all aliased to a canonical op):
  ==  =   eq   equals
  !=  <>  ne   neq
  <  lt  >  gt  <=  le  >=  ge
  contains  containing  like  includes  has
  ~  matches  match  regex

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


# Lenient vocabulary — a single canonical op per alias group.
_OP_ALIASES = {
    "==": "==", "=": "==", "eq": "==", "equals": "==",
    "!=": "!=", "<>": "!=", "ne": "!=", "neq": "!=",
    "<": "<", "lt": "<", ">": ">", "gt": ">",
    "<=": "<=", "le": "<=", ">=": ">=", "ge": ">=",
    "contains": "contains", "containing": "contains", "like": "contains",
    "includes": "contains", "has": "contains",
    "~": "~", "matches": "~", "match": "~", "regex": "~",
}

_TARGET_ALIASES: Dict[str, tuple] = {
    "function": ("function", "functions", "func", "funcs", "fn", "fns"),
    "string": ("string", "strings", "str", "strs", "literal", "literals", "lit"),
    "call": ("call", "calls"),
    "import": ("import", "imports", "api", "apis"),
    "xref": ("xref", "xrefs", "crossref", "crossrefs", "cross_reference", "cross_references"),
    "instruction": ("instruction", "instructions", "insn", "insns", "mnemonic", "mnemonics", "opcode", "opcodes"),
    "block": ("block", "blocks", "basicblock", "basic_blocks", "bb", "bbs"),
    "segment": ("segment", "segments", "seg", "segs", "section", "sections"),
}

# Targets whose executor ignores the identifier — a bare non-'*' identifier is
# coerced into a name/text/substring condition so e.g. "function main" or
# "imports from kernel32" actually filters instead of returning everything.
_IDENTIFIER_COERCION = {
    "function": "name",
    "string": "text",
    "import": "name",
    "segment": "name",
    "call": "text",
}

_CONNECTIVE_WORDS = frozenset({
    "to", "from", "named", "called", "in", "into", "of", "with", "where",
    "whose", "that", "having", "containing", "for", "by", "on", "at",
})

_NOISE_WORDS = frozenset({
    "match", "find", "search", "list", "show", "get", "me", "all", "the",
    "every", "any", "some", "please", "give",
})

_WHERE_MARKER_RE = re.compile(r"^(?:where|with|such that|that|having|whose)\b\s*", re.IGNORECASE)

_CONTAINS_WORDS = ("contains", "containing", "like", "includes", "has")
_REGEX_WORDS = ("matches", "match", "regex")
_COMPARISON_RE = re.compile(
    r"(\w+)\s*(==|!=|<=|>=|<|>|=|eq|equals|ne|neq|lt|le|gt|ge)\s*(.+)",
    re.IGNORECASE,
)


class QueryParser:
    """Parse high-level query strings into executable plans (lenient).

    Accepts the canonical ``MATCH <target> <id> WHERE <conds> [LIMIT N]``
    form as well as relaxed/natural phrasing (no MATCH, no WHERE, plural
    aliases, single ``=``, connective words, free-text find fallback) so a
    caller is very hard to get wrong.
    """

    def parse(self, query: str) -> Optional[Dict]:
        if not query or not query.strip():
            return None
        q = query.strip()
        plan: Dict[str, Any] = {}
        q, plan["limit"] = self._pull_limit(q)
        q, plan["sort_key"], plan["sort_order"] = self._pull_sort(q)
        q, plan["group_key"] = self._pull_group(q)

        head = self._strip_noise(q)
        parsed = self._parse_head_and_conditions(head)
        if parsed:
            target, identifier, conditions = parsed
            plan.update({"target": target, "identifier": identifier, "conditions": conditions})
            self._coerce_identifier(plan)
            return plan

        # Free-text fallback → unified find.  Whatever the caller wrote, it
        # becomes a find pattern instead of a hard parse error.
        plan.update({"target": "find", "identifier": q.strip().strip('"\''), "conditions": []})
        return plan

    # -- tail clauses -------------------------------------------------------
    def _pull_limit(self, q: str):
        m = re.search(r"\blimit\s+(\d+)\b", q, re.IGNORECASE)
        if not m:
            return q, 100
        return (q[:m.start()] + " " + q[m.end():]).strip(), int(m.group(1))

    def _pull_sort(self, q: str):
        m = re.search(r"\bsort\s+by\s+(\w+)(?:\s+(asc|desc))?\b", q, re.IGNORECASE)
        if not m:
            return q, None, "ASC"
        rest = (q[:m.start()] + " " + q[m.end():]).strip()
        return rest, m.group(1).lower(), (m.group(2) or "ASC").upper()

    def _pull_group(self, q: str):
        m = re.search(r"\bgroup\s+by\s+(\w+)", q, re.IGNORECASE)
        if not m:
            return q, None
        return (q[:m.start()] + " " + q[m.end():]).strip(), m.group(1).lower()

    # -- head (target + identifier + conditions) ---------------------------
    def _strip_noise(self, q: str) -> str:
        words = q.split()
        i = 0
        while i < len(words) and words[i].lower().rstrip(",;") in _NOISE_WORDS:
            i += 1
        return " ".join(words[i:])

    def _parse_head_and_conditions(self, q: str) -> Optional[tuple]:
        if not q.strip():
            return None
        target, rest = self._extract_target(q)
        if target is None:
            # No target word → pure conditions default to functions.
            conditions = self._parse_conditions(q)
            if conditions:
                return ("function", "*", conditions)
            return None
        identifier, conditions = self._extract_identifier_and_conditions(rest)
        return (target, identifier, conditions)

    def _extract_target(self, q: str):
        words = q.split()
        if not words:
            return None, q
        first = words[0].strip(",;").lower()
        for canonical, aliases in _TARGET_ALIASES.items():
            if first in aliases:
                rest = q[len(words[0]):].strip().lstrip(",;").strip()
                return canonical, rest
        return None, q

    def _extract_identifier_and_conditions(self, rest: str):
        if not rest or not rest.strip():
            return "*", []
        rest = rest.strip()
        connective_alt = "|".join(sorted(_CONNECTIVE_WORDS, key=len, reverse=True))
        m = re.match(fr"^(?:{connective_alt})\b", rest, re.IGNORECASE)
        if m:
            rest = rest[m.end():].strip()
        m = re.match(r"""^(['"])(.*?)\1""", rest, re.DOTALL)
        if m:
            identifier = m.group(2)
            rest = rest[m.end():].strip()
        else:
            tokens = rest.split()
            if tokens and tokens[0] == "*":
                identifier = "*"
                rest = rest[len(tokens[0]):].strip()
            elif tokens and not self._starts_condition(rest):
                identifier = tokens[0]
                rest = rest[len(tokens[0]):].strip()
            else:
                identifier = "*"
        rest = _WHERE_MARKER_RE.sub("", rest).strip()
        conditions = self._parse_conditions(rest)
        return identifier, conditions

    @staticmethod
    def _starts_condition(s: str) -> bool:
        word_ops = "|".join(_CONTAINS_WORDS + _REGEX_WORDS)
        # Trailing whitespace-or-end instead of \b: after a symbol operator
        # ("size > 100") the next char is a space, and \b would fail on the
        # non-word→non-word transition.
        return bool(
            re.match(
                rf"\w+\s*(?:==|!=|<=|>=|<|>|=|eq|equals|ne|neq|lt|le|gt|ge|{word_ops})(?:\s|$)",
                s,
                re.IGNORECASE,
            )
        )

    def _coerce_identifier(self, plan: Dict) -> None:
        """Turn a bare identifier on an identifier-ignoring target into a filter."""
        identifier = plan.get("identifier") or "*"
        if identifier == "*" or plan.get("conditions"):
            return
        key = _IDENTIFIER_COERCION.get(plan.get("target"))
        if key:
            plan["conditions"] = [{"key": key, "op": "contains", "value": identifier}]
            # The identifier is now expressed as a condition; reset it so
            # downstream executors do not re-apply it (e.g. call-mnemonic set).
            plan["identifier"] = "*"

    # -- conditions ---------------------------------------------------------
    def _parse_conditions(self, conditions: str) -> List[Dict]:
        """Parse conditions separated by AND/comma/semicolon/&& (quote-aware)."""
        result = []
        for token in self._split_conditions(conditions or ""):
            cond = self._parse_single_condition(token)
            if cond:
                result.append(cond)
        return result

    @staticmethod
    def _split_conditions(s: str) -> List[str]:
        result = []
        current = ""
        in_quote = False
        quote_char = None
        i = 0
        n = len(s)
        while i < n:
            c = s[i]
            if c in ('"', "'") and not in_quote:
                in_quote = True
                quote_char = c
                current += c
                i += 1
                continue
            if in_quote:
                current += c
                if c == quote_char:
                    in_quote = False
                i += 1
                continue
            if s[i:i + 2] == "&&" or c in (",", ";"):
                if current.strip():
                    result.append(current.strip())
                current = ""
                i += 2 if s[i:i + 2] == "&&" else 1
                continue
            if (
                s[i:i + 3].upper() == "AND"
                and (i == 0 or s[i - 1].isspace())
                and (i + 3 >= n or s[i + 3].isspace())
            ):
                if current.strip():
                    result.append(current.strip())
                current = ""
                i += 3
                continue
            current += c
            i += 1
        if current.strip():
            result.append(current.strip())
        return result

    @staticmethod
    def _parse_single_condition(cond: str) -> Optional[Dict]:
        cond = cond.strip()
        contains_alt = "|".join(_CONTAINS_WORDS)
        regex_alt = "|".join(_REGEX_WORDS)
        m = re.match(rf"(\w+)\s+(?:{contains_alt})\s+(.+)", cond, re.IGNORECASE)
        if m:
            key, val = m.group(1), m.group(2).strip().strip('"\'')
            return {"key": key, "op": "contains", "value": val}
        m = re.match(rf"(\w+)\s*(?:~|{regex_alt})\s*(.+)", cond, re.IGNORECASE)
        if m:
            key, val = m.group(1), m.group(2).strip().strip('"\'')
            return {"key": key, "op": "~", "value": val}
        m = _COMPARISON_RE.match(cond)
        if m:
            key, raw_op, raw_val = m.group(1), m.group(2).lower(), m.group(3).strip().strip('"\'')
            op = _OP_ALIASES.get(raw_op, raw_op)
            # Keep the string value when it is not numeric (e.g. name == "main").
            val = raw_val
            try:
                val = int(raw_val)
            except ValueError:
                with contextlib.suppress(ValueError):
                    val = float(raw_val)
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

    def _execute_find(self, plan: Dict) -> Dict:
        """Free-text fallback: delegate unparseable input to unified find."""
        pattern = (plan.get("identifier") or "").strip()
        try:
            limit = max(1, int(plan.get("limit") or 100))
        except (TypeError, ValueError):
            limit = 100
        result = _call_tool("search", action="find", pattern=pattern, limit=limit)
        if not isinstance(result, dict):
            return make_error("QUERY_ERROR", "Failed to run unified find search")
        return result

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

    The parser is lenient — almost any phrasing resolves to a plan.  The
    canonical form is ``MATCH <target> <identifier> WHERE <conditions>
    [LIMIT N] [SORT BY key (ASC|DESC)] [GROUP BY key]``, but ``MATCH`` /
    ``WHERE`` are optional, target aliases and operator synonyms are accepted,
    bare identifiers become name/text filters, and free text falls back to the
    unified ``find`` search.

    Args:
        query:  The query-language expression (or free text).
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
        # Only reachable for input that stripped to nothing (whitespace-only
        # or pure punctuation); otherwise the parser degrades to a find plan.
        return make_error(
            MCPError.INVALID_ARGS,
            "query could not be interpreted",
            hint=(
                "Try: MATCH function * WHERE size > 100 LIMIT 10 — or just natural text "
                "like 'functions that parse config' (falls back to unified find)."
            ),
        )

    executor = QueryExecutor(limit=fetch_limit)
    return executor.execute(plan)
