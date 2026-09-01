# Reference and FAQ

## Which interface should a new client use?

Use the exact-schema `ida_*` operations. The old broad
`tool(action=...)` interface remains for compatibility and is selected with
`IDA_MCP_TOOL_SURFACE=legacy`.

## Where do I get an operation's exact arguments?

Ask the server:

```text
ida_help(query="ida_decompile")
```

You can also consult the generated
[operation reference](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/TOOLS_REFERENCE.md). This wiki intentionally focuses
on workflows rather than repeating every schema.

## What does `risk_ack` mean?

It is an explicit acknowledgement required by IDB-writing operations and other
destructive session actions. It does not override operator policy. Set it only
after checking the target, intended change, and rollback plan.

## Does analysis data leave the machine?

The server itself has no LLM service behind it and uses deterministic local IDA
calls. Local embedding and reranking stay on the machine. The Gemini embedding
backend is opt-in and uploads compact behavioral signatures to Google, not full
decompilations.

## Are embeddings required?

No. `ida_find`, listings, code inspection, findings, and ordinary session
operations work without semantic models. Install models only when behavioral
search or reranking is useful.

## What is safe mode?

Safe mode protects whole-binary operations while IDA auto-analysis is pending.
Small-area manual reads and several annotation operations remain available.
Wait for `ida_session_status` to confirm analysis completion before indexing or
running other gated work.

## How do findings differ from IDB comments?

Findings live in the persistent investigation workspace and retain lifecycle,
confidence, evidence, conflicts, and stale state. Publishing copies reviewed
confirmed conclusions into the IDB. Importing annotations adopts existing names
and comments back into the workspace.

## How do I recover from a bad edit?

Use `ida_idb_snapshot` before experiments and
`ida_idb_restore_snapshot` to roll back. Undo transactions can bracket a batch.
Patches and undefines should be treated as destructive; verify bytes and
snapshots before using them.

## What does Alpha mean here?

The project is Alpha (1.0.0a1), so operation schemas and behavior may move.
Pin a commit when reproducibility matters.

## Is the optional threat corpus installed automatically?

No. It is opt-in with the installer. Normal installs do not download it.

## Where are policy settings documented?

The operator baseline uses `IDA_MCP_POLICY_MODE` or
`~/.config/ida-pro-mcp/policy.json`. See the
[safety model](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/guide/safety-model.md).

References: [README.md](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/README.md),
[generated operation reference](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/TOOLS_REFERENCE.md).
