# TYPES Tool Manual

## What It Does
Manages IDA type information: listing/getting types, parsing declarations, declaring types, applying prototypes/types, inference, struct reads, and header import.

## Actions
- `list`: Enumerates TIL types with optional `query`, `offset`, `count`.
- `get`: Gets named type details (including struct/enum members when available).
- `set_prototype`: Parses and applies function prototype to `addr`.
- `parse_decl`: Validates one C declaration and returns parsed info.
- `declare`: Adds a parsed declaration to local type library (allocates ordinal).
- `apply`: Applies parsed type to function/global/local variable context.
- `search_structs`: Finds struct/union names or fields matching `query`.
- `infer`: Heuristic type inference at address.
- `read_struct`: Reads struct fields from memory at `addr`.
- `import_header`: Parses full header text into local types.

## Key Parameters
- `action`: `list|get|set_prototype|parse_decl|declare|apply|search_structs|infer|read_struct|import_header`.
- `name`: Type name; for `apply(kind="local")` this is local variable name; for `read_struct` this is struct name.
- `addr`: Required by `set_prototype`, `apply`, `infer`, `read_struct`.
- `decl`: Required for `set_prototype`, `parse_decl`, `declare`, `apply`, `import_header`.
- `kind`: For `apply`, practical values are `function`, `global`, `local`.
- `query`, `offset`, `count`: Filtering/pagination for list/search flows.

## Examples
```json
{"name":"types","arguments":{"action":"set_prototype","addr":"0x401000","decl":"int __fastcall sub_401000(char *buf, int len);"}}
```

```json
{"name":"types","arguments":{"action":"apply","addr":"0x401120","kind":"local","name":"v6","decl":"char *"}}
```

```json
{"name":"types","arguments":{"action":"import_header","decl":"typedef struct { int a; char b; } demo_t;"}}
```

## Failure Modes
- Missing required fields (`name`, `addr`, `decl`, or `query` depending on action).
- Parse/apply failures for invalid C declarations or incompatible targets.
- `get`/`read_struct` fail when named type does not exist.
- Local apply requires function context, decompilation success, and exact local variable name match.
- Error format is mixed in this tool (`make_error(...)` and plain `{"error": ...}`), so callers should handle both.
