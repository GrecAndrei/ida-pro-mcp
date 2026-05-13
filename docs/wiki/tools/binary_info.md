# binary_info

Extracts binary-level metadata: headers, sections, compiler info, and more.

## Actions
- `headers` — parse file headers (PE/ELF/Mach-O)
- `sections` — list all sections/segments with attributes
- `relocations` — list relocation entries
- `resources` — enumerate embedded resources
- `debug_info` — report debug directory/info availability
- `compiler` — detect compiler and version
- `linker` — detect linker and version
- `timestamps` — extract compile/link timestamps
- `checksums` — report file checksums (header + computed)
- `overlay` — detect and describe overlay/appended data

## Examples
```json
{"name": "binary_info", "arguments": {"action": "headers"}}
```
```json
{"name": "binary_info", "arguments": {"action": "sections"}}
```

## Notes
- Works on the active session binary; no address param needed.
- `overlay` is useful for packed/self-extracting binaries.
