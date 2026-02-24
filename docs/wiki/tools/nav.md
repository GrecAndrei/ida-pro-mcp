# NAV Tool Manual

## What It Does
Provides lightweight navigation and triage helpers for address context, cursor state, and interesting instruction hotspots.

## Actions
- `goto`: Return context for a specific address.
- `cursor`: Return current screen cursor address (if available).
- `interesting`: Scan executable segments for predefined interesting mnemonics.

## Key Parameters
- `action`: One of `goto|cursor|interesting`.
- `addr`: Required by `goto`; ignored by other actions.

## Examples
```python
nav(action="goto", addr="0x401000")
nav(action="cursor")
nav(action="interesting")
```

## Failure Modes
- Missing `addr` for `goto`.
- Invalid `addr` for `goto`.
- `cursor` may return a warning with `addr=None` in headless mode.
