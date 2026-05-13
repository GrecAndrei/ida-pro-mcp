# gadgets

Finds ROP/JOP/COP gadgets, exploit primitives, and assesses exploit chain viability with ML scoring.

## Actions
- `rop` — find ROP gadgets; params: `max_length`, `filter`
- `jop` — find JOP gadgets
- `cop` — find COP (call-oriented) gadgets
- `syscall` — find syscall gadgets
- `write_what_where` — find write-what-where primitives
- `stack_pivot` — find stack pivot gadgets
- `shellcode_space` — find writable+executable regions suitable for shellcode
- `mitigations` — enumerate binary mitigations (NX, ASLR, CFI, etc.)
- `seh_handlers` — find SEH handler chains (Windows)
- `pivot_chains` — find multi-gadget pivot chains
- `classify_chain` — full exploit chain assessment using BehaviorClassifier with exploit anchors; returns `exploit_assessment`: HIGH/MEDIUM/LOW/MINIMAL

## Examples

```json
{"name": "gadgets", "arguments": {"action": "rop", "max_length": 5}}
```

```json
{"name": "gadgets", "arguments": {"action": "classify_chain"}}
```

## Notes
- All gadget actions now include `exploit_potential` scoring in their response, not just `classify_chain`.
- `classify_chain` uses BehaviorClassifier with exploit-specific anchors (rop_chain, write_what_where, code_exec, stack_pivot) for zero-shot assessment.
- Combine with `mitigations` to understand which gadget classes are actually exploitable given the binary's defenses.
