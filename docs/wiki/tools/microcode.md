# MICROCODE Tool Manual

## What It Does
Exposes Hex-Rays microcode (IR) summaries, block listings, and instruction listings for a function at requested maturity level.

## Actions
- `get`: Return microcode availability summary (`blocks_count`, maturity).
- `blocks`: List micro-block ranges/types.
- `instructions`: List micro-instructions (capped to 500 lines).

## Key Parameters
- `action`: One of `get|blocks|instructions`.
- `addr`: Required function address.
- `maturity`: Microcode optimization maturity level (`0-7`, default `3`).

## Examples
```python
microcode(action="get", addr="0x401000", maturity=3)
microcode(action="blocks", addr="0x401000", maturity=4)
microcode(action="instructions", addr="0x401000", maturity=5)
```

## Failure Modes
- `addr` not a valid function.
- Hex-Rays decompiler/microcode APIs unavailable.
- Microcode generation failure at selected maturity.
- Instruction output truncated at 500 items.
