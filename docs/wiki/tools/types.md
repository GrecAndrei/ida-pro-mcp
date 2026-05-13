# types

Manages type information: structs, enums, typedefs, prototypes, and type propagation.

## Actions
- `list` — list all local types. Optional `offset`, `count`, `filter`
- `get` — get type definition by `name` or `ordinal`
- `set_prototype` — set function prototype. Params: `address`, `prototype`
- `parse_decl` — parse a C declaration string. Params: `decl`
- `declare` — declare a new type. Params: `decl`
- `apply` — apply a type to an address. Params: `address`, `type_name`
- `search_structs` — search structs by field name/type. Params: `query`
- `infer` — infer type for an address. Params: `address`
- `read_struct` — read struct layout. Params: `name`
- `import_header` — import a C header file. Params: `path` or `content`
- `diff` — diff two types. Params: `type_a`, `type_b`
- `visualize` — text visualization of struct layout. Params: `name`
- `propagate` — propagate type info from address. Params: `address`
- `enum_values` — list enum members. Params: `name`
- `type_graph` — show type dependency graph. Params: `name`, optional `depth`

## Examples
```json
{"name": "types", "arguments": {"action": "set_prototype", "address": "0x401000", "prototype": "int __cdecl main(int argc, char **argv)"}}
```
```json
{"name": "types", "arguments": {"action": "read_struct", "name": "SOCKET_INFO"}}
```

## Notes
- `import_header` accepts either a file `path` or inline `content`.
- Use `propagate` after setting a type to push it through xrefs automatically.
