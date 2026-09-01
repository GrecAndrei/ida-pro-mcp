# Navigation

Choose the page that matches the job.

| Task | Page |
| --- | --- |
| Install the runtime and open a binary | [Install and run your first session](getting-started) |
| Add the server to an MCP client | [Configure an MCP client](client-configuration) |
| Move from discovery to a defensible conclusion | [A practical reverse-engineering workflow](reverse-engineering-workflow) |
| Preserve evidence, uncertainty, and disagreement | [Findings, evidence, and conflicts](findings-and-evidence) |
| Rename, annotate, patch, or reshape an IDB | [Safe IDB edits and rollback](safe-idb-edits) |
| Search by names, strings, or behavior | [Search, embeddings, and reranking](search-and-retrieval) |
| Diagnose sessions, ownership, timeouts, or safe mode | [Sessions and troubleshooting](sessions-troubleshooting) |
| Check behavior with a real IDA installation | [Live IDA validation](live-ida-validation) |
| Find terminology and configuration pointers | [Reference and FAQ](reference-faq) |

## Repository references

- [Generated operation reference](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/TOOLS_REFERENCE.md)
- [README](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/README.md)
- [Safety model](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/guide/safety-model.md)
- [Live IDA testing](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/LIVE_IDA_TESTING.md)

The older `tool(action=...)` interface is retained for compatibility. New
clients should use the exact-schema `ida_*` operations.
