# Navigation

Choose the page that matches the job.

| Task | Page |
| --- | --- |
| Install the runtime and open a binary | [Install and run your first session](getting-started) |
| Add the server to an MCP client (22+ clients) | [Configure an MCP client](client-configuration) |
| Move from discovery to a defensible conclusion | [A practical reverse-engineering workflow](reverse-engineering-workflow) |
| Preserve evidence, uncertainty, and disagreement | [Findings, evidence, and conflicts](findings-and-evidence) |
| Rename, annotate, patch, or reshape an IDB | [Safe IDB edits and rollback](safe-idb-edits) |
| Search by names, strings, or behavior | [Search, embeddings, and reranking](search-and-retrieval) |
| Diagnose sessions, ownership, timeouts, or safe mode | [Sessions and troubleshooting](sessions-troubleshooting) |
| Check behavior with a real IDA installation | [Live IDA validation](live-ida-validation) |
| Find terminology and configuration pointers | [Reference and FAQ](reference-faq) |

## Tool Reference Manuals

- [Discovery Operations (31 ops)](tools/discovery.md)
- [Code Operations (11 ops)](tools/code.md)
- [Edit Operations (33 ops)](tools/edit.md)
- [Types Operations](tools/types.md)
- [Segments Operations](tools/segments.md)
- [Findings Operations (10 ops)](tools/findings.md)
- [Session Operations (12 ops)](tools/session.md)
- [Calculation Operations (8 ops)](tools/calculation.md)
- [Signatures Operations](tools/signatures.md)
- [Support Operations (3 ops)](tools/support.md)
- [Workflow Operations (1 op)](tools/workflow.md)

## Repository references

- [GitHub Releases](https://github.com/GrecAndrei/ida-pro-mcp/releases)
- [README](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/README.md)
- [Safety model](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/guide/safety-model.md)
- [Live IDA testing](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/operations/live-ida-testing.md)

The older `tool(action=...)` interface is retained for compatibility. New
clients should use the exact-schema `ida_*` operations.
