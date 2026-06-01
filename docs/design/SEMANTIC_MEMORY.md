# Semantic Memory (Sideband Direction)

This document describes the local semantic memory architecture in `ida-pro-mcp`.

## Scope

The repository and package remain `ida-pro-mcp`. "Sideband" is an architecture direction for capsule-native semantic memory, not a package rename.

## Local-First Model

Semantic memory is local-first by design:

- Primary backend: `bge-code-v1` via local `llama-server`
- Deterministic fallback: TF-IDF when model/server are unavailable
- No required remote embedding API

## Core Components

- `BgeCodeEmbedder` (`src/ida_pro_mcp/host/intelligence_core.py`)
- `FunctionEmbeddingIndex` and `SemanticObjectIndex` (`src/ida_pro_mcp/host/intelligence_embeddings.py`)
- `BehaviorClassifier` (`src/ida_pro_mcp/host/intelligence_core.py`)
- Capsule semantic store (`src/ida_pro_mcp/capsule/store.py`)

## Persistence Layers

1. Function embedding indexes (`<idb>.embeddings.db`)
2. Blackboard semantic records
3. Sideband capsule semantic tables:
   - `semantic_indexes`
   - `semantic_items`
   - `semantic_vectors` (optional)
   - `behavior_hits`
   - `evidence_cards`

## Capsule Continuity

When `IDA_MCP_CAPSULE` is set, runtime/session flows can persist:

- session state
- audit events
- embedder/index state snapshots
- blackboard semantic records
- evidence cards

## Evidence Discipline

Semantic classification is triage, not proof.

Outputs should be treated as:

- behavior hints
- evidence candidates
- confidence-scored follow-up targets

Not as definitive vulnerability/malware verdicts.

## Analysis-Only Export

Use capsule CLI for sharing analysis without raw blobs:

```bash
python -m ida_pro_mcp.capsule.cli export-analysis project.sideband --out analysis-only.sideband --metadata-only
```

Optional flags:

- `--include-vectors`
- `--include-notes`
- `--include-audit`

## Operator Commands

```bash
python install.py --embedder-doctor
ida-pro-mcp-cli intelligence status
ida-pro-mcp-cli intelligence doctor
ida-pro-mcp-cli capsule semantic-summary project.sideband --json
ida-pro-mcp-cli capsule list-evidence project.sideband --json
```

## Demo Workflow

1. `session(action="create", binary_path="...")`
2. `code(action="decompile", addr="0x401000")`
3. `agent(action="classify_function", addr="0x401000")`
4. `agent(action="similar_functions", addr="0x401000")`
5. `blackboard(action="write", title="finding", content="...")`
6. `agent(action="evidence_card", addr="0x401000")`
7. `ida-pro-mcp-cli capsule semantic-summary project.sideband --json`
