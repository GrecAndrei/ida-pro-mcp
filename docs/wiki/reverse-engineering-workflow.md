# A practical reverse-engineering workflow

The most reliable workflow separates discovery, reading, recording, and
mutation. Let each step produce evidence for the next one.

## 1. Establish context

Open the binary, then check:

- `ida_session_state` for the active binary and useful next actions
- `ida_session_status` for `safe_mode` and analysis completion
- `ida_overview` for architecture, entry points, and analysis context
- `ida_list_imports` and `ida_list_strings` for an initial capability map

For a known API, string, or symbol, begin with `ida_find`. Use
`ida_list_functions` when you need an inventory rather than a match.

## 2. Read a candidate from several angles

For each promising function:

1. Call `ida_decompile` when pseudocode is useful.
2. Call `ida_disassemble` when instruction-level details matter.
3. Follow `ida_xrefs_to` and `ida_callers` to understand inputs and reachability.
4. Use `ida_callees` or `ida_callgraph` to understand what the function invokes.
5. Use `ida_read_bytes` to verify bytes when IDA's interpretation is uncertain.

Decompilation includes bounded structural evidence when available. Treat that
evidence as a guide to verify, not as a substitute for checking the relevant
instructions and references.

## 3. Turn observations into explicit workspace state

Write a finding when you have a claim worth carrying forward. Include:

- a precise title;
- what the code does and what it does not establish;
- an address when possible;
- confidence;
- evidence such as a call, string, constant, or related address.

Use `ida_mark_examined` for a reviewed but uninteresting or inconclusive
function. This prevents repeated dead ends from consuming later sessions.

## 4. Expand from confirmed facts

Use `ida_next_target` deliberately:

- `unresolved` for open questions and unverified findings;
- `stale` after relevant IDB changes;
- `conflict` when claims disagree;
- `coverage` for frequently called but unread functions;
- `frontier` for callers and callees around confirmed findings.

Each candidate includes a reason. Read the candidate, then record the outcome;
the workspace becomes more useful as the investigation becomes more explicit.

## 5. Publish only after review

Use `ida_publish_findings` with `dry_run: true` first. Confirm that the proposed
comments and names are appropriate, then repeat with the required
`risk_ack: true`. Publishing is an IDB mutation and should be treated as an
analyst review step, not automatic truth promotion.

References: [generated operation reference](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/docs/TOOLS_REFERENCE.md),
[investigation workspace implementation](https://github.com/GrecAndrei/ida-pro-mcp/blob/master/src/ida_pro_mcp/host/stores/blackboard_store.py).
