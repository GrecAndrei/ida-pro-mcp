# Agent Guidelines for IDA Pro MCP

## Recent Major Changes

### VOERA Architecture Integration (May 2026)
The following VOERA-inspired features have been integrated across the tool suite:

1. **Context Density Optimization** (`llm_helpers.py`)
   - New `compact` action: RE-specific content compaction (strips IDA tags, compresses hex dumps, truncates long xref lists)
   - Functions: `_clean_re_content()`, `_compress_xref_list()`, `_histogram_by_segment()`

2. **Neuro-Symbolic Governance** (`annotation.py`, `edit.py`)
   - `annotation(action="validate")`: Pre-flight validation for comments (detects contradictions, PII, misleading claims)
   - `edit(governed=True)`: Automatic governance checks before edits (prevents bad renames, dangerous patches, misleading comments)
   - Deterministic rule-based validation layer inspired by CyberCane

3. **Structured Semantic Retrieval** (`search.py`, `classify.py`)
   - `search(action="structured", constraints={...})`: Pre-filters functions by induced schema before semantic ranking
   - `classify(action="induce_schema")`: Induces structured attribute-value schema for any function
   - Attributes: behavior_tags, dangerous_apis, string_refs, vuln_class, structural_features

4. **Task Skill Crystallization** (`host/session.py`)
   - `SessionManager.crystallize_skill()`: Saves successful workflows as reusable L3 skills
   - `SessionManager.rate_skill()`: TD-style Q-value updates (MemRL-inspired)
   - `SessionManager.suggest_strategy()`: Ranks skills by Q-value + context matching
   - `SessionManager.log_activity()`: Episodic activity tracking

5. **Bridge-Conditioned Multi-Hop Search** (`agent.py`)
   - `agent(action="bridge_query")`: Chains through intermediate entities (bridge -> string refs -> candidates)
   - Automatically extracts bridge entities and expands via dual-entity search

6. **ReasoningBank Distillation** (`agent.py`)
   - `agent(action="reflect")`: Analyzes attempted strategies, extracts insights and guardrails
   - Distills successes/failures into reusable strategy objects

### Installer Refactoring
- Hardcoded MCP client config paths extracted from `install.py` into `client_configs.json`
- `install.py` now dynamically loads and resolves paths from JSON data
- Preserves all original logic: env overrides, XDG fallback, OS-specific paths

### Testing
- All 456 tests pass after changes
- Syntax-checked all modified files

## When Working on This Project

### Code Style
- Follow existing patterns: `@tool` + `@idaread`/`@idawrite` decorators
- Use `make_error(MCPError.*, ...)` for consistent error handling
- Keep docstrings comprehensive with LLM-friendly examples
- Prefer compact text output (one match per line) to minimize context usage

### Architecture
- `ida_mcp_stdio.py` is a thin shim (~78 lines) re-exporting `host/` package
- All server logic lives in `src/ida_pro_mcp/host/`
- Tool files live in `src/ida_pro_mcp/ida_mcp/tools/`
- `_real_stdout` must be injected before `IDAMCPServer` import

### Key Files
- `host/config.py` - Cross-cutting constants, limits, regexes
- `host/patterns.py` - Canonical smart pattern matching (zero IDA deps)
- `host/session.py` - Session management + VOERA skill crystallization
- `host/server.py` - JSON-RPC stdio server
- `host/schemas.py` - TOOL_ACTIONS, descriptions, schema builders
