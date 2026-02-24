# GADGETS Tool Manual

## What It Does
Finds exploit-relevant primitives: ROP/JOP/COP/syscall gadgets, write-what-where patterns, stack pivots, RWX regions, mitigation hints, SEH handler patterns, and pivot-chain building blocks.

## Actions
- `rop`: Gadgets ending in architecture-appropriate return instruction.
- `jop`: Gadgets ending in indirect jump-style dispatch.
- `cop`: Gadgets ending in indirect call-style dispatch.
- `syscall`: Gadgets ending in syscall-like instructions.
- `write_what_where`: Store-to-memory primitives that can chain to returns.
- `stack_pivot`: Stack pointer pivot candidates that chain to returns.
- `shellcode_space`: Writable+executable segment discovery.
- `mitigations`: Heuristic exploit-mitigation detection (format dependent).
- `seh_handlers`: Windows-style SEH setup pattern search.
- `pivot_chains`: Categorized gadget suggestions for chain construction.

## Key Parameters
- `action`: One of `rop|jop|cop|syscall|write_what_where|stack_pivot|shellcode_space|mitigations|seh_handlers|pivot_chains`.
- `addr`: Optional scope limiter to containing segment/address area.
- `limit`: Max results (default `50`).
- `max_insns`: Maximum instruction window per candidate gadget.
- `query`: Regex/substring filter applied to gadget text.

## Examples
```python
gadgets(action="rop", limit=100, max_insns=6)
gadgets(action="jop", addr="0x401000", query="mov|pop")
gadgets(action="syscall", limit=30)
gadgets(action="write_what_where", query="mov")
gadgets(action="stack_pivot", limit=40)
gadgets(action="shellcode_space")
gadgets(action="mitigations")
gadgets(action="seh_handlers", limit=20)
gadgets(action="pivot_chains", limit=60)
```

## Failure Modes
- Invalid scope address for `addr`.
- Sparse/optimized binaries may return zero gadgets.
- Architecture-specific pattern gaps can miss valid gadgets.
- Mitigation detection is heuristic and may report partial/unknown values.
- Large scans truncated by `limit` and reported as truncated where applicable.
