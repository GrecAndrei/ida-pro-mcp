# Search, embeddings, and reranking

Use lexical search for known names and indicators. Use semantic retrieval when
the question is behavioral and naming is incomplete.

## Start with deterministic discovery

`ida_find` is the normal first choice for a symbol, string, import, comment, or
reference. It does not require retrieval models.

For a broader inventory, use `ida_list_functions`, `ida_list_strings`, and
`ida_list_imports`. This keeps ordinary reconnaissance independent of optional
model setup.

## Build a semantic index

`ida_index_functions` creates a scoped index. Useful controls include:

- `query`, ranges, `start`/`end`, or an address plus radius;
- `min_size` and `max_size`;
- `quality="fast"` for metadata and disassembly;
- `quality="full"` when decompilation should improve retrieval;
- `background=true` and `ida_index_status` for long jobs;
- `ida_cancel_index` to stop a running job.

Indexing is gated while the session is in safe mode. It is interruptible and
resumable; a partial index is retained if a batch fails.

## Search and rerank

`ida_semantic_search` can search for intent such as “function that decrypts
strings.” `quick` keeps the operation bounded; `expand` adds behavior-driven
matches. Use range filters to keep the search focused.

Retrieval has two stages:

1. A bi-encoder embeds the query and indexed function documents for broad
   recall.
2. An optional cross-encoder reranks only the recalled pool.

The response reports whether reranking was applied. If no reranker is
available, or it produces non-discriminating scores, recall order is preserved
and the response says so. Do not interpret an unavailable result as a semantic
match.

The index stores model identity and dimension. It rebuilds when the model,
dimension, or prompt format changes; incompatible vector spaces are not
silently mixed.

## Local backends

Depending on the installation, local retrieval uses a GGUF model through
`llama-server`, or the optional in-process native backend when
`libmcp_llama.so` and a matching model are installed. The native backend can be selected explicitly with
`IDA_MCP_BACKEND=native`; `IDA_MCP_BACKEND=http` forces the subprocess path.

The native library is optional and must be built from a caller-supplied
llama.cpp checkout. See the [README](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/README.md)
and the repository's [technical intelligence guide](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/wiki/core/intelligence.md)
for model profiles and backend knobs.

To install the default local profile and the optional `llama-server` helper:

```bash
python install.py --embed-profile qwen3-embedding-0.6b \
  --download-embed-model --install-llama-server
python install.py --embedder-doctor
```

The first session does not need either component. Keep the model and server
configuration in the managed install root rather than in the repository.

## Gemini, explicitly opt in

The Gemini embedding backend is not selected automatically. Select it with
`IDA_MCP_EMBED_BACKEND=gemini` or installer configuration. It uploads the
compact behavioral signature of each function—not the full decompilation—to
Google. If no code may leave the machine, use a local backend.

For Google AI Studio, the installer form is:

```bash
python install.py --embed-backend gemini --gemini-access aistudio \
  --gemini-api-key "$GEMINI_API_KEY"
```

Credentials and model settings are environment/configuration concerns; consult
the [installer options](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/README.md)
rather than placing secrets in source control. The optional threat corpus is
also not downloaded by a normal install.

References: [generated intelligence operations](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/TOOLS_REFERENCE.md),
[intelligence implementation](https://github.com/GrecAndrei/ida-pro-mcp/tree/master/src/ida_pro_mcp/host/intelligence),
[installer options](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/install.py).
