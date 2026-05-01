#!/usr/bin/env python3
"""
Smart pattern matching: regex auto-detection, glob, semantic/fuzzy search.
No IDA dependencies — safe to import from both host and runtime.
"""
import os
import re
import fnmatch
import difflib
from functools import lru_cache
from typing import Any, Callable, Optional


_SEMANTIC_CANONICALS = {
    "find": "search",
    "lookup": "search",
    "locate": "search",
    "discover": "search",
    "query": "search",
    "match": "search",
    "decompiler": "decompile",
    "decompiled": "decompile",
    "pseudocode": "decompile",
    "pseudo": "decompile",
    "pcode": "decompile",
    "hexrays": "decompile",
    "ctree": "decompile",
    "routine": "function",
    "procedure": "function",
    "proc": "function",
    "method": "function",
    "subroutine": "function",
    "global": "data",
    "variable": "data",
    "memory": "data",
    "xref": "reference",
    "ref": "reference",
    "refs": "reference",
    "callsite": "reference",
    "caller": "reference",
    "callee": "reference",
    "literal": "string",
    "text": "string",
    "api": "import",
    "symbol": "import",
    "extern": "import",
}

_SEMANTIC_SINGLE_TOKEN_MIN_LEN = 5
_SEMANTIC_FUZZY_CUTOFF = 0.86
_SEMANTIC_CAMEL_BOUNDARY_1 = re.compile(r"([a-z])([A-Z])")
_SEMANTIC_CAMEL_BOUNDARY_2 = re.compile(r"([A-Z]+)([A-Z][a-z])")

_SMART_MATCH_MODE = (
    str(os.environ.get("IDA_MCP_SMART_MATCH_MODE", "balanced")).strip().lower()
)
if _SMART_MATCH_MODE not in {"off", "conservative", "balanced", "aggressive"}:
    _SMART_MATCH_MODE = "balanced"

_SMART_MATCH_MODE_DEFAULTS = {
    "off": {"semantic_enabled": False, "fuzzy_cutoff": 1.0},
    "conservative": {"semantic_enabled": True, "fuzzy_cutoff": 0.92},
    "balanced": {"semantic_enabled": True, "fuzzy_cutoff": _SEMANTIC_FUZZY_CUTOFF},
    "aggressive": {"semantic_enabled": True, "fuzzy_cutoff": 0.80},
}


def _resolve_optional_param(provided, default):
    return default if provided is None else provided


def _normalize_semantic_token(token: str) -> str:
    tok = token.lower().strip()
    if not tok:
        return tok
    for suffix in ("ing", "ers", "ies", "ied", "er", "ed", "es", "s"):
        if len(tok) > 4 and tok.endswith(suffix):
            if suffix in ("ies", "ied"):
                tok = tok[:-3] + "y"
            else:
                tok = tok[: -len(suffix)]
            break
    return _SEMANTIC_CANONICALS.get(tok, tok)


def _semantic_tokenize(text: str):
    if not text:
        return []
    tokens = []
    for raw in re.findall(r"[A-Za-z0-9_]+", text):
        expanded = _SEMANTIC_CAMEL_BOUNDARY_2.sub(r"\1 \2", raw)
        expanded = _SEMANTIC_CAMEL_BOUNDARY_1.sub(r"\1 \2", expanded)
        for part in expanded.replace("_", " ").split():
            tok = _normalize_semantic_token(part)
            if len(tok) >= 2:
                tokens.append(tok)
    return tokens


def _compile_semantic_matcher(pattern: str, *, fuzzy_cutoff: float = _SEMANTIC_FUZZY_CUTOFF):
    query_tokens = _semantic_tokenize(pattern)
    if not query_tokens:
        return None
    if (
        len(query_tokens) == 1
        and len(query_tokens[0]) < _SEMANTIC_SINGLE_TOKEN_MIN_LEN
        and " " not in pattern
    ):
        return None

    query_set = set(query_tokens)
    pathlike_query = len(query_set) == 2 and bool(re.search(r"[./\\:_-]", pattern))
    if pathlike_query:
        overlap_needed = 2
    else:
        overlap_needed = max(1, (len(query_set) + 1) // 2)
    fuzzy_tokens = [
        tok for tok in query_set if len(tok) >= _SEMANTIC_SINGLE_TOKEN_MIN_LEN
    ]

    def _semantic_matches(text: str) -> bool:
        text_tokens = set(_semantic_tokenize(text))
        if not text_tokens:
            return False
        overlap = len(query_set.intersection(text_tokens))
        if overlap >= overlap_needed:
            return True
        if not fuzzy_tokens:
            return False
        fuzzy_hits = 0
        for qtok in fuzzy_tokens:
            if difflib.get_close_matches(
                qtok, text_tokens, n=1, cutoff=fuzzy_cutoff
            ):
                fuzzy_hits += 1
                if overlap + fuzzy_hits >= overlap_needed:
                    return True
        return False

    return _semantic_matches


def _is_regex(pattern):
    if not pattern:
        return False
    if pattern.startswith("/") and pattern.count("/") >= 2:
        return True
    for ind in (r"\d", r"\w", r"\s", r"\b", r"\D", r"\W", r"\S", r"\B"):
        if ind in pattern:
            return True
    if re.search(r"\\[.^$*+?{}()|[\]\\]", pattern):
        return True
    if set("^$+{}()|").intersection(pattern):
        return True
    if re.search(r"\[.+\]", pattern):
        return True
    return False


@lru_cache(maxsize=1024)
def _compile_smart_pattern_cached(
    pattern, case_sensitive, semantic_enabled, fuzzy_cutoff
):
    return _compile_smart_pattern_uncached(
        pattern,
        case_sensitive=case_sensitive,
        semantic_enabled=semantic_enabled,
        fuzzy_cutoff=fuzzy_cutoff,
    )


def _compile_smart_pattern_uncached(
    pattern,
    *,
    case_sensitive=False,
    semantic_enabled=True,
    fuzzy_cutoff=_SEMANTIC_FUZZY_CUTOFF,
):
    if not pattern:
        return lambda _t: True
    regex = None
    if pattern.startswith("/") and pattern.count("/") >= 2:
        ls = pattern.rfind("/")
        body, fs = pattern[1:ls], pattern[ls + 1 :]
        flags = 0
        for c in fs:
            if c == "i":
                flags |= re.IGNORECASE
            elif c == "m":
                flags |= re.MULTILINE
            elif c == "s":
                flags |= re.DOTALL
        try:
            regex = re.compile(
                body, flags or (0 if case_sensitive else re.IGNORECASE)
            )
        except re.error:
            pass
    elif _is_regex(pattern):
        try:
            regex = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
        except re.error:
            pass
    if regex is not None:
        return lambda _t, _r=regex: bool(_r.search(_t))
    if "*" in pattern or "?" in pattern:
        pl = pattern.lower()
        return lambda _t, _p=pl: fnmatch.fnmatch(_t.lower(), _p)
    if case_sensitive:
        return lambda _t, _p=pattern: _p in _t
    pl = pattern.lower()
    if not semantic_enabled:
        return lambda _t, _p=pl: _p in _t.lower()
    semantic_match = _compile_semantic_matcher(pattern, fuzzy_cutoff=fuzzy_cutoff)
    if semantic_match is None:
        return lambda _t, _p=pl: _p in _t.lower()
    return lambda _t, _p=pl, _sem=semantic_match: (_p in _t.lower()) or _sem(_t)


def compile_smart_pattern(
    pattern,
    case_sensitive=False,
    *,
    semantic_enabled=None,
    fuzzy_cutoff=None,
):
    defaults = _SMART_MATCH_MODE_DEFAULTS[_SMART_MATCH_MODE]
    use_semantic = bool(
        _resolve_optional_param(semantic_enabled, defaults["semantic_enabled"])
    )
    use_cutoff = float(
        _resolve_optional_param(fuzzy_cutoff, defaults["fuzzy_cutoff"])
    )
    use_cutoff = max(0.0, min(1.0, use_cutoff))
    return _compile_smart_pattern_cached(
        pattern, case_sensitive, use_semantic, use_cutoff
    )


def smart_match(pattern, text, case_sensitive=False):
    return compile_smart_pattern(pattern, case_sensitive)(text)
