# HOOKS Tool Manual

## What It Does
Generates hook targets and templates (Frida, Detours), ranks likely instrumentation points, and suggests inline hook insertion candidates.

## Actions
- `suggest`: Category-based hook candidate discovery.
- `generate_frida`: Build Frida `Interceptor.attach` script for function.
- `generate_detours`: Build Microsoft Detours C++ template.
- `find_targets`: Rank named functions by category/importance heuristics.
- `inline_hooks`: Find candidate instruction sites with enough bytes for trampolines.

## Key Parameters
- `action`: One of `suggest|generate_frida|generate_detours|find_targets|inline_hooks`.
- `category`: For `suggest`; one of `network|file|crypto|registry|process`.
- `addr` or `func_name`: Required for script generation; `addr` required for `inline_hooks`.

## Examples
```python
hooks(action="suggest", category="network")
hooks(action="generate_frida", func_name="send")
hooks(action="generate_detours", addr="0x401000")
hooks(action="find_targets")
hooks(action="inline_hooks", addr="0x401000")
```

## Failure Modes
- Unknown category for `suggest`.
- Missing `addr`/`func_name` for generation actions.
- Function resolution failure (`FUNCTION_NOT_FOUND`).
- Generated template may need manual signature correction before compile/use.
