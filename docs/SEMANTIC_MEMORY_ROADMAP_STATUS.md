# Sideband Semantic Memory Roadmap Status

This file tracks completion evidence for:
`docs/design/sideband_semantic_memory_codex_roadmap.md`

## Phase Status

- Phase 1 (Embedder hardening): complete
- Phase 2 (Intelligence actions): complete
- Phase 3 (Versioned embedding index): complete
- Phase 4 (Capsule semantic schema v2): complete
- Phase 5 (Capsule import/export): complete
- Phase 6 (Semantic object index): complete
- Phase 7 (Persistent blackboard semantic memory): complete
- Phase 8 (Evidence cards): complete
- Phase 9 (Embedder doctor/install integration): complete
- Phase 10 (Evaluation suite): complete
- Phase 11 (Capsule-backed session continuity): complete
- Phase 12 (Semantic rename propagation): complete
- Phase 13 (Analysis-only export): complete
- Phase 14 (Backend-neutral semantic records): complete
- Phase 15 (Sideband Memory UX): complete

## Evidence By Phase

1. Embedder hardening
- `src/ida_pro_mcp/host/intelligence_core.py`
- `tests/test_embedder_status.py`

2. Intelligence actions
- `src/ida_pro_mcp/ida_mcp/tools/agent.py`
- `src/ida_pro_mcp/host/schemas_data.py`
- `tests/test_agent_intelligence_static.py`

3. Versioned embedding index
- `src/ida_pro_mcp/host/intelligence_embeddings.py`
- `tests/test_intelligence_embeddings_metadata.py`

4. Capsule semantic schema v2
- `src/ida_pro_mcp/capsule/migrations.py`
- `src/ida_pro_mcp/capsule/store.py`
- `tests/test_capsule_store.py`

5. Capsule semantic import/export
- `src/ida_pro_mcp/capsule/cli.py`
- `src/ida_pro_mcp/capsule/store.py`
- `tests/test_capsule_cli.py`

6. Generic semantic object index
- `src/ida_pro_mcp/host/intelligence_embeddings.py`
- `tests/test_semantic_object_index.py`

7. Persistent blackboard semantics
- `src/ida_pro_mcp/ida_mcp/tools/blackboard.py`
- `tests/test_blackboard_semantic_persistence.py`

8. Evidence cards
- `src/ida_pro_mcp/ida_mcp/tools/agent.py`
- `src/ida_pro_mcp/capsule/store.py`
- `src/ida_pro_mcp/capsule/cli.py` (`list-evidence`)
- `tests/test_capsule_store.py`
- `tests/test_capsule_cli.py`

9. Embedder doctor / setup
- `src/ida_pro_mcp/installer/main.py`
- `tests/test_installer_llama_server.py`

10. Evaluation suite
- `tests/fixtures/semantic/*`
- `tests/test_semantic_fixtures.py`
- `tests/integration/test_semantic_real_embedder.py`
- `tests/benchmarks/benchmark_semantic_memory.py`

11. Capsule-backed sessions
- `src/ida_pro_mcp/host/server_session.py`
- `tests/test_session_capsule_continuity.py`

12. Rename propagation / suggestions
- `src/ida_pro_mcp/ida_mcp/tools/agent.py` (`rename_suggestions`)
- `docs/wiki/tools/agent.md`
- `tests/test_agent_rename_suggestions_static.py`

13. Analysis-only export
- `src/ida_pro_mcp/capsule/store.py` (`export_analysis_capsule`)
- `src/ida_pro_mcp/capsule/cli.py` (`export-analysis`)
- `tests/test_capsule_store.py`
- `tests/test_capsule_cli.py`

14. Backend-neutral records
- `src/ida_pro_mcp/capsule/store.py` (`_normalize_source_ref`)
- `src/ida_pro_mcp/ida_mcp/tools/agent.py` (`source_refs` shape)
- `src/ida_pro_mcp/ida_mcp/tools/blackboard.py` (`source_ref` metadata)
- `tests/test_capsule_store.py`

15. UX and docs
- `README.md` (Local Semantic Memory + demo workflow)
- `docs/design/CAPSULES.md`
- `docs/design/SEMANTIC_MEMORY.md`
- `docs/wiki/core/intelligence.md`
- `src/ida_pro_mcp/cli.py` (`intelligence` / `capsule` shortcut modes)
- `tests/test_cli.py`

## Overall Acceptance Criteria Mapping

1. Embedder doctor available
- `python install.py --embedder-doctor`
- `src/ida_pro_mcp/installer/main.py`

2. Function classification with behavior hints/evidence
- `agent(action="classify_function")`
- `agent(action="evidence_card")`

3. Similar function retrieval
- `agent(action="similar_functions")`

4. Persistence across sessions
- `IDA_MCP_CAPSULE` session sync in `server_session.py`

5. Capsule semantic metadata storage
- semantic tables in `capsule/migrations.py` and store APIs

6. Analysis-only capsule export
- `capsule cli export-analysis`

7. Explainability
- evidence cards with anchor + similarity evidence

8. Cautious claims
- evidence-card claim language uses "may implement"

9. Fallback utility without model
- TF-IDF fallback in `intelligence_core.py`

10. Unit tests model/IDA independent
- semantic/capsule/cli static + fake embedder tests

11. Optional integration tests
- `tests/integration/test_capsule_real_ida.py`
- `tests/integration/test_semantic_real_embedder.py`

12. Public docs clarity/safety
- README + docs/design/wiki updates above
