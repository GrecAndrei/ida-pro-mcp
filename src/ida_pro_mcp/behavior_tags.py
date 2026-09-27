"""Single source of truth for function behavior vocabulary.

This module used to be two independent definitions living in different layers,
which is how they came to conflict: ``CANONICAL_TAGS`` was duplicated verbatim in
``host/stores/insight_index.py`` and ``ida_mcp/tools/search/core.py``, while the
finer ``BEHAVIOR_LABELS`` tuple was defined separately in
``host/intelligence/advisory.py`` with no stated relationship to the coarse set.
Two unrelated lists describing the same concept is a correctness problem, not a
style one: nothing stopped a label from being added to one and forgotten in the
other.

Both vocabularies are kept, because they do different jobs and both are
load-bearing:

- ``CANONICAL_TAGS`` is the coarse routing/indexing vocabulary. It backs the
  public ``ida_index_functions`` operation and the ``behavior_tags`` search
  filter constraints, so it is part of the public contract.
- ``BEHAVIOR_LABELS`` is the fine-grained answer vocabulary a typed-question
  provider may *select from*. It is advisory only; a provider may propose a
  label but never executes or authorizes anything.

``COARSE_TO_FINE`` is the declared relationship between them, and
``tests/host/test_behavior_vocabulary.py`` asserts the mapping is total and
consistent so the two can never silently drift apart again.
"""

from __future__ import annotations

# Coarse vocabulary: routing, indexing, and search filter constraints.
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

# Fine vocabulary: the answer choices a typed-question provider may select.
# Advisory only.
BEHAVIOR_LABELS: tuple[str, ...] = (
    "crypto_symmetric",
    "crypto_asymmetric",
    "crypto_hash",
    "network_http",
    "network_socket",
    "network_protocol",
    "file_io",
    "memory_allocation",
    "process_control",
    "authentication",
    "serialization",
    "logging",
    "parsing",
    "error_handling",
    "rop_chain",
    "write_what_where",
    "code_exec",
    "stack_pivot",
    "unknown",
)

# Every fine label resolves to exactly one coarse tag, except "unknown" which is
# the explicit no-evidence answer and therefore maps to no tag.
COARSE_TO_FINE: dict[str, str] = {
    "crypto_symmetric": "crypto",
    "crypto_asymmetric": "crypto",
    "crypto_hash": "hashing",
    "network_http": "network",
    "network_socket": "network",
    "network_protocol": "network",
    "file_io": "file_io",
    "memory_allocation": "allocator",
    "process_control": "process",
    "authentication": "process",
    "serialization": "encoding",
    "logging": "file_io",
    "parsing": "parser",
    "error_handling": "exception_handler",
    "rop_chain": "obfuscation",
    "write_what_where": "obfuscation",
    "code_exec": "process",
    "stack_pivot": "obfuscation",
}

UNRESOLVED_BEHAVIOR_LABEL = "unknown"

__all__ = [
    "BEHAVIOR_LABELS",
    "CANONICAL_TAGS",
    "COARSE_TO_FINE",
    "UNRESOLVED_BEHAVIOR_LABEL",
]
