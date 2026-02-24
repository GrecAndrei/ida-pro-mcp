# PATTERNS Tool Manual

## What It Does
Generates and matches FLIRT-like byte signatures, enumerates available `.sig` files, and reports likely signature-matched functions.

## Actions
- `generate`: Build a wildcarded pattern from a function.
- `match`: Match a hex pattern across functions.
- `list_sigs`: Enumerate available signature files.
- `apply_sig`: Queue a named signature for application.
- `create_sig`: Create compact signature metadata from a function.
- `matched`: List likely library/signature-identified functions.

## Key Parameters
- `action`: One of `generate|match|list_sigs|apply_sig|create_sig|matched`.
- `addr`: Required for `generate` and `create_sig`.
- `pattern`: Required for `match` (hex bytes with `??` wildcards).
- `name`: Signature name (required for `apply_sig`; optional for `create_sig`).
- `length`: Max bytes for generated pattern (default `32`).
- `offset`: Pagination offset for list-style actions.
- `count`: Max returned results (`0` means unbounded in supported actions).

## Examples
```python
patterns(action="generate", addr="0x401000", length=64)
patterns(action="match", pattern="55 8B EC ?? ??", count=25)
patterns(action="list_sigs", offset=0, count=50)
patterns(action="apply_sig", name="vc32rtf")
patterns(action="create_sig", addr="0x401000", name="parse_header_sig")
patterns(action="matched", offset=0, count=100)
```

## Failure Modes
- Missing required `addr`, `pattern`, or `name` per action.
- Invalid hex in `match` pattern.
- Address not inside a function for function-bound actions.
- Signature application only queued; final naming depends on auto-analysis.
