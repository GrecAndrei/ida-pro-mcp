# RISC-V raw-blob firmware recipe

Headerless RISC-V firmware is intentionally treated as an opaque raw image.
IDA's processor module, disassembly, decompilation, register/CSR metadata,
explicit architecture selection, and explicit GP configuration remain
authoritative.

## Safe workflow

1. Inspect the file with `ida_open_binary`, `ida_session_status`,
   `ida_overview`, and `ida_read_bytes`.
2. Supply known values explicitly with `ida_open_binary(..., processor="riscv",
   bitness=64, baseaddr="0x80000000")` or the legacy
   `analysis(action="set_architecture", ...)` action.
3. Use `ida_disassemble`/`ida_decompile` only after IDA analysis is ready.
4. If the analyst knows the GP value, use the explicit legacy
   `analysis(action="set_gp", gp=...)` action with the required policy
   acknowledgement. MCP inference never applies GP automatically.
5. Treat `ida_add_entry`, data creation, and segment-register changes as
   explicit policy-gated IDB mutations; snapshot before changing a raw image.

## Architecture advisory boundary

For an opaque raw file, the host may send a compact byte sample and bounded
candidate summaries to the configured Jev/custom provider as a typed advisory
question. The provider can return a hypothesis or `unknown`, but it cannot
select an IDA processor, rebase an IDB, seed functions, set GP, or authorize a
mutation. In `disabled` mode, or when the provider is unavailable or malformed,
the result fails closed and asks the analyst to provide explicit architecture
options. No RISC-V host-side opcode/bitness heuristic is treated as authority.

Provider transport never logs or persists raw decompilation, credentials,
prompt payloads, completions, or response bodies. Custom origins require an
explicit HTTPS allowlist; loopback HTTP requires an explicit opt-in. Use
`ida_intelligence_status` and `ida_usage_status` to inspect readiness and
budget state.

## What to record

Record the chosen base, processor, bitness, endian, and GP value in the
investigation workspace with evidence from bytes/disassembly. Keep the input
binary and IDB snapshot so the explicit choices can be reproduced. Do not
interpret an unavailable advisory as a negative architecture finding, and do
not let a Jev/custom answer satisfy `risk_ack`.
