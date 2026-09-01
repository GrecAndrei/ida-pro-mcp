# Install and run your first session

This page covers the smallest useful path from a checkout to a first recorded
finding.

## Requirements

- IDA Pro 9.2 or newer
- Python 3.11 or newer
- The runtime dependencies installed by the project installer

The server uses deterministic IDA SDK calls. Optional embedding and reranking
are separate retrieval helpers and are not required for ordinary analysis.

When an alpha release is published, the GitHub release also includes a source
bundle with the installer. Verify its `SHA256SUMS`, extract it, and run
`python install.py` from the extracted directory. The bundle is the easiest
way to install without cloning the repository.

## Install

From the repository root:

```bash
python install.py
```

The installer prepares the runtime, locates IDA, configures supported MCP
clients, and installs the portable skill for supported clients.

The default managed install root is `~/.local/share/ida-pro-mcp` on Unix-like
systems and `%LOCALAPPDATA%\ida-pro-mcp` on Windows. Set `IDA_PRO_MCP_HOME` or
pass `--install-root` when that location is not suitable. The installer writes
an install report there; a failed run attempts to roll back configuration
backups by default.

For an editable source setup:

```bash
pip install -e .
python -u -m ida_pro_mcp.host.server
```

Do not download retrieval models or the optional threat corpus unless you need
those features. They are opt-in.

## Open the first binary

Once the MCP server is available to your client, call:

```json
{"name": "ida_open_binary",
 "arguments": {"binary_path": "/path/to/sample"}}
```

Keep the returned `session_id`. Then orient:

```json
{"name": "ida_session_state", "arguments": {}}
{"name": "ida_session_status", "arguments": {}}
{"name": "ida_overview", "arguments": {}}
```

If the session reports `safe_mode: true`, IDA analysis is still pending. Poll
`ida_session_status` until the runtime reports that analysis is complete. Small,
single-function reads remain available during safe mode, but whole-binary work
such as indexing is gated.

## Make and record a first observation

For a known symbol or string:

```json
{"name": "ida_find",
 "arguments": {"query": "recv", "limit": 20}}
```

Read a candidate and its callers:

```json
{"name": "ida_decompile",
 "arguments": {"address": "0x401000"}}
{"name": "ida_xrefs_to",
 "arguments": {"address": "0x401000"}}
{"name": "ida_callers",
 "arguments": {"address": "0x401000"}}
```

Record a conclusion with the evidence that supports it:

```json
{"name": "ida_write_finding", "arguments": {
  "title": "packet receive handler",
  "content": "Parses inbound data before dispatching on the command byte.",
  "address": "0x401000",
  "confidence": 0.8
}}
```

If the function is a dead end, record that explicitly:

```json
{"name": "ida_mark_examined", "arguments": {
  "address": "0x401a20",
  "verdict": "boring",
  "note": "CRT string helper; no input handling."
}}
```

Continue with `ida_next_target` or summarize with
`ida_analysis_brief`. Export findings when handing work to another analyst.

References: [README.md](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/README.md),
[installer source](https://github.com/GrecAndrei/ida-pro-mcp/tree/master/src/ida_pro_mcp/installer),
[generated operation reference](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/TOOLS_REFERENCE.md).
