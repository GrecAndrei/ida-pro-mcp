# Roadmap: Future Features

This file tracks advanced features to be implemented after the core modular SDK has been fully audited and refined.

## ✅ Completed Features

### 1. YARA Integration (`yara_hunt` tool)
*   Surgical signature matching implemented using `yara-python`.
*   Supports scanning entire segments or specific ranges.

### 2. Token-Aware Truncation (LLM Optimization)
*   Middleware implemented in `truncation.py`.
*   Automatically prunes massive lists and strings while adding pagination notes.

### 3. Sparse Description Strategy
*   Tool descriptions in the MCP manifest stripped to single-line essentials.
*   Deep documentation moved to an on-demand `wiki` tool.

### 4. Multi-Session Parallelism
*   One headless IDA process per session for concurrent LLM workflows.

### 5. Batch + Context Tools
*   Host-side `batch` tool and `agent.context_pack` for fast per-function grounding.

### 6. Advanced Calc + Pagination
*   Pointer math (`deref`, `chain`, `align`) and offset/limit paging for search/results.

## 🎯 Next Steps

### 1. Deep BinDiff Support (`diff` enhancement)
*   **Goal**: Cross-binary structural analysis.
*   **Actions**:
    *   `parse_binexport`: Extract function matches and similarity from a `.BinExport` file.
    *   `apply_diff_names`: Automatically port names from a reference binary based on diff results.
*   **Benefit**: Essential for patch analysis and porting analysis between versions.

### 2. Graphviz Export (`graph` enhancement)
*   Generate high-quality `.svg` or `.png` graphs directly from the `graph` tool.

---
*Last Updated: 2026-01-05*
---
Doc status: Reviewed for multi-session parallel stdio, batch tool, analysis tool, context_pack, data.bulk_query, taint.slice, pagination.
Last reviewed: 2026-01-09
