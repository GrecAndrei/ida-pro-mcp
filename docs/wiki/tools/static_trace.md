# static_trace

Static emulation/tracing of code paths, string decryption, and expression evaluation.

## Actions
- `static_trace` — trace execution statically from address; params: `address`, `steps` (optional)
- `decrypt_strings` — attempt static string decryption; params: `address`
- `eval_expr` — evaluate an expression in emulation context; params: `expression`, `address`

## Examples
```json
{"name": "static_trace", "arguments": {"action": "static_trace", "address": "0x401000", "steps": 100}}
```
```json
{"name": "static_trace", "arguments": {"action": "decrypt_strings", "address": "0x401200"}}
```

## Notes
- Alias: `emulate` resolves to this tool.
- Static tracing does not execute the binary; it symbolically follows code paths.
- `decrypt_strings` is effective against simple XOR/ADD string obfuscation.
