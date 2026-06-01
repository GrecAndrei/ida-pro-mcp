"""Support libraries for ida_mcp tools.

Modules in this package are NOT tools (they do not have @tool decorators).
They are shared helpers used by tools in ida_mcp.tools.

Layout:
  - arch_utils:           Multi-architecture instruction helpers
  - firmware_heuristics:  Firmware entropy/fingerprint helpers
  - semantic_matching:    Token-level semantic helpers for search
  - hybrid_search:        SQL pre-filtering for structured search
  - query_lang:           Query-language parser/executor
  - _api_categories:      API category mappings
"""
