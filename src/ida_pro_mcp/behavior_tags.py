"""Single source of truth for canonical function behavior tags.

This vocabulary used to be duplicated verbatim in two places
(``host/stores/insight_index.py`` and ``ida_mcp/tools/search/core.py``), which
made it free for the two copies to drift apart and silently disagree about what
counts as a known behavior tag. Both now import from here.

Tags are coarse, deterministic, and intentionally provider-neutral: they
describe what a function *is*, never what an analyst should do about it.
"""

from __future__ import annotations

CANONICAL_TAGS: frozenset[str] = frozenset(
    {
        "crypto",
        "network",
        "file_io",
        "registry",
        "process",
        "string_decode",
        "allocator",
        "exception_handler",
        "obfuscation",
        "compression",
        "hashing",
        "encoding",
        "parser",
        "main",
        "init",
        "cleanup",
        "loop",
        "recursive",
        "thunk",
        "library",
        "data",
    }
)

__all__ = ["CANONICAL_TAGS"]
