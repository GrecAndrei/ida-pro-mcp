# MCP Tools Reference

Auto-generated from the MCP stdio server registry. Lists every tool with actions and arguments.

## session

### Actions
- `discover`
- `create`
- `list`
- `switch`
- `close`
- `status`
- `rebuild`

### Args
- `action`: enum(discover, create, list, switch, close, status)
- `binary_path`: string
- `use_existing`: string
- `session_id`: string
- `processor`: string
- `flags`: integer
- `loader`: string
- `value`: ['string', 'object']
- `bitness`: integer
- `endian`: string
- `reanalyze`: boolean

## bookmarks

### Actions
- `add`
- `list`
- `delete`
- `update`
- `clear`
- `find`
- `export`

### Args
- `action`: enum(add, list, delete, update, clear, find, export)
- `addr`: string
- `id`: integer
- `name`: string
- `notes`: string
- `category`: string
- `priority`: integer
- `tags`: ['array', 'string']
- `query`: string

## analysis

### Actions
- `get_options`
- `set_options`
- `set_processor`
- `set_loader_options`
- `set_architecture`
- `reanalyze`

### Args
- `action`: enum(get_options, set_options, set_processor, set_loader_options, set_architecture, reanalyze)
- `options`: object
- `processor`: string
- `flags`: integer
- `loader`: string
- `value`: ['string', 'object']
- `bitness`: integer
- `endian`: string
- `start`: string
- `end`: string
- `idb`: string

## query

### Actions
- `data`
- `search`
- `strings_xref`
- `imports_deep`
- `symbols`
- `patterns`
- `idb`

### Args
- `action`: enum(data, search, strings_xref, imports_deep, symbols, patterns, idb)
- `subaction`: string
- `args`: object
- `idb`: string

## edit

### Actions
- `modify`
- `funcs`
- `segments`
- `data_ops`
- `fixups`
- `colorize`
- `comments_ai`
- `bulk`

### Args
- `action`: enum(modify, funcs, segments, data_ops, fixups, colorize, comments_ai, bulk)
- `subaction`: string
- `args`: object
- `idb`: string

## idb

### Actions
- `meta`
- `summary`
- `segments`
- `entrypoints`
- `bookmarks`

### Args
- `action`: enum (see Actions)
- `idb`: string

## code

### Actions
- `decompile`
- `disasm`
- `xrefs_to`
- `xrefs_from`
- `xrefs_to_field`
- `callees`
- `callers`
- `blocks`
- `analyze`
- `callgraph`
- `export`
- `find_paths`
- `strings_in_func`

### Args
- `action`: enum (see Actions)
- `idb`: string

## data

### Actions
- `functions`
- `globals`
- `strings`
- `imports`
- `exports`
- `lookup`
- `bulk_query`

### Args
- `action`: enum(functions, globals, strings, imports, exports, lookup, bulk_query)
- `query`: string
- `offset`: integer
- `count`: integer
- `items`: array
- `idb`: string

## search

### Actions
- `bytes`
- `string`
- `immediate`
- `name`
- `insns`
- `text`
- `operand`
- `comment`
- `data_ref`
- `code_ref`

### Args
- `action`: enum(bytes, string, immediate, name, insns, text, operand, comment, data_ref, code_ref)
- `pattern`: string
- `query`: string
- `limit`: integer
- `offset`: integer
- `start`: string
- `end`: string
- `idb`: string

## types

### Actions
- `list`
- `get`
- `set_prototype`
- `parse_decl`
- `declare`
- `apply`
- `search_structs`
- `infer`
- `read_struct`
- `import_header`

### Args
- `action`: enum (see Actions)
- `idb`: string

## memory

### Actions
- `read`
- `write`

### Args
- `action`: enum(read, write)
- `addr`: string
- `type`: enum(bytes, u8, u16, u32, u64, s8, s16, s32, s64, f32, f64, ptr, string)
- `size`: integer
- `data`: string
- `idb`: string

## modify

### Actions
- `rename`
- `comment`
- `set_type`
- `patch_asm`

### Args
- `action`: enum (see Actions)
- `idb`: string

## misc

### Actions
- `python`
- `idc`
- `load_sig`

### Args
- `action`: enum(python, idc, load_sig)
- `expr`: string
- `code`: string
- `name`: string
- `idb`: string

## debug

### Actions
- `start`
- `stop`
- `continue`
- `step_into`
- `step_over`
- `run_to`
- `run_until`
- `breakpoints`
- `add_bp`
- `del_bp`
- `enable_bp`
- `regs`
- `set_reg`
- `threads`
- `modules`
- `callstack`
- `read_mem`
- `write_mem`

### Args
- `action`: enum (see Actions)
- `idb`: string

## funcs

### Actions
- `create`
- `delete`
- `set_flags`
- `set_name`
- `add_comment`
- `list`
- `info`

### Args
- `action`: enum(create, delete, set_flags, set_name, add_comment, list, info)
- `addr`: string
- `end`: string
- `name`: string
- `flags`: integer
- `comment`: string
- `repeatable`: boolean
- `query`: string
- `offset`: integer
- `count`: integer
- `named_only`: boolean
- `include_prototype`: boolean
- `include_stack`: boolean
- `idb`: string

## segments

### Actions
- `list`
- `add`
- `delete`
- `set_attr`
- `set_perms`
- `move`

### Args
- `action`: enum(list, add, delete, set_attr, set_perms, move)
- `start`: string
- `end`: string
- `name`: string
- `sclass`: string
- `attr`: string
- `value`: ['string', 'integer']
- `offset`: integer
- `count`: integer
- `idb`: string

## project

### Actions
- `save`
- `close`
- `open`
- `load_binary`
- `list_recent`
- `get_cwd`
- `set_cwd`
- `list_dir`
- `exists`
- `read`
- `write`
- `sessions`
- `batch`

### Args
- `action`: enum (see Actions)
- `idb`: string

## plugins

### Actions
- `list`
- `run`

### Args
- `action`: enum (see Actions)
- `idb`: string

## trace

### Actions
- `get`
- `clear`
- `set_options`

### Args
- `action`: enum (see Actions)
- `idb`: string

## fixups

### Actions
- `list`
- `get`
- `add`
- `delete`

### Args
- `action`: enum (see Actions)
- `idb`: string

## data_ops

### Actions
- `make_data`
- `make_array`
- `make_string`
- `undefine`
- `make_code`

### Args
- `action`: enum (see Actions)
- `idb`: string

## agent

### Actions
- `analyze_function`
- `explore_address`
- `find_references`
- `search_all`
- `search_structs`
- `context_pack`

### Args
- `action`: enum(analyze_function, explore_address, find_references, search_all, search_structs, context_pack)
- `addr`: string
- `query`: string
- `depth`: integer
- `include_pseudocode`: boolean
- `max_items`: integer
- `use_cache`: boolean
- `idb`: string

## microcode

### Actions
- `get`
- `blocks`
- `instructions`

### Args
- `action`: enum (see Actions)
- `idb`: string

## graph

### Actions
- `callgraph`
- `cfg`
- `xref_graph`

### Args
- `action`: enum (see Actions)
- `idb`: string

## bulk

### Actions
- `rename`
- `comment`
- `apply_type`
- `rename_stack`
- `import_annotations`
- `export_annotations`

### Args
- `action`: enum (see Actions)
- `idb`: string

## ctree

### Actions
- `get`
- `traverse`
- `find_calls`
- `find_vars`
- `find_strings`
- `find_conditions`
- `get_logic_flow`

### Args
- `action`: enum(get, traverse, find_calls, find_vars, find_strings, find_conditions, get_logic_flow)
- `addr`: string
- `query`: string
- `depth`: integer
- `idb`: string

## diff

### Actions
- `functions`
- `bytes`
- `signatures`
- `summary`
- `export_binexport`

### Args
- `action`: enum (see Actions)
- `idb`: string

## lumina

### Actions
- `pull`
- `push`
- `status`
- `history`
- `search`

### Args
- `action`: enum (see Actions)
- `idb`: string

## symbols

### Actions
- `load_pdb`
- `load_dwarf`
- `status`
- `apply`
- `export`

### Args
- `action`: enum (see Actions)
- `idb`: string

## patterns

### Actions
- `generate`
- `match`
- `list_sigs`
- `apply_sig`
- `create_sig`

### Args
- `action`: enum (see Actions)
- `idb`: string

## structs

### Actions
- `recover`
- `analyze_usage`
- `list`
- `create`
- `add_member`
- `apply`
- `reconstruct_vtable`

### Args
- `action`: enum (see Actions)
- `idb`: string

## strings_xref

### Actions
- `analyze`
- `xref_chain`
- `detect_encoded`
- `find_format`
- `clusters`

### Args
- `action`: enum (see Actions)
- `idb`: string

## entropy

### Actions
- `section`
- `region`
- `packed_detect`
- `crypto_detect`
- `compare`
- `window`
- `summary`

### Args
- `action`: enum(section, region, packed_detect, crypto_detect, compare, window, summary)
- `addr`: string
- `size`: integer
- `threshold`: number
- `end_addr`: string
- `window`: integer
- `step`: integer
- `limit`: integer
- `idb`: string

## imports_deep

### Actions
- `thunks`
- `delay`
- `forwarded`
- `ordinal`
- `api_sets`
- `resolve`

### Args
- `action`: enum (see Actions)
- `idb`: string

## comments_ai

### Actions
- `get_context`
- `set_structured`
- `bulk_set`
- `export_md`
- `import_md`
- `summary`

### Args
- `action`: enum (see Actions)
- `idb`: string

## nav

### Actions
- `goto`
- `cursor`
- `interesting`

### Args
- `action`: enum (see Actions)
- `idb`: string

## colorize

### Actions
- `set_func`
- `set_range`
- `set_insn`
- `get`
- `clear`
- `palette`
- `highlight_pattern`

### Args
- `action`: enum (see Actions)
- `idb`: string

## emulate

### Actions
- `static_trace`
- `appcall`
- `decrypt_strings`
- `eval_expr`

### Args
- `action`: enum(static_trace, appcall, decrypt_strings, eval_expr)
- `addr`: string
- `func_name`: string
- `args`: array
- `max_steps`: integer
- `follow_calls`: boolean
- `max_depth`: integer
- `include_blocks`: boolean
- `expr`: string
- `idb`: string

## export

### Actions
- `listing`
- `html`
- `idc`
- `json`
- `binexport`
- `headers`

### Args
- `action`: enum (see Actions)
- `idb`: string

## history

### Actions
- `undo`
- `redo`
- `list`
- `snapshot`
- `restore`
- `diff`

### Args
- `action`: enum (see Actions)
- `idb`: string

## trace_analysis

### Actions
- `import_trace`
- `analyze_coverage`
- `find_loops`
- `extract_api_calls`
- `basic_blocks_hit`

### Args
- `action`: enum (see Actions)
- `idb`: string

## hooks

### Actions
- `suggest`
- `generate_frida`
- `generate_detours`
- `find_targets`
- `inline_hooks`

### Args
- `action`: enum (see Actions)
- `idb`: string

## taint

### Actions
- `find_arg_usage`
- `trace_return`
- `find_sinks`
- `data_flow`
- `backward_trace`
- `slice`

### Args
- `action`: enum(find_arg_usage, trace_return, find_sinks, data_flow, backward_trace, slice)
- `addr`: string
- `arg_num`: integer
- `depth`: integer
- `max_hits`: integer
- `idb`: string

## calc

### Actions
- `eval`
- `offset`
- `convert`
- `resolve`
- `deref`
- `chain`
- `align`

### Args
- `action`: enum(eval, offset, convert, resolve, deref, chain, align)
- `expr`: string
- `addr`: string
- `target`: string
- `value`: ['string', 'integer']
- `type`: string
- `size`: integer
- `offsets`: ['array', 'string']
- `idb`: string

## coverage

### Actions
- `import_drcov`
- `import_lighthouse`
- `highlight`
- `report`
- `uncovered`
- `filter`

### Args
- `action`: enum (see Actions)
- `idb`: string

## wiki

### Actions
- `list_topics`
- `read`
- `search`
- `sections`
- `index`

### Args
- `action`: enum(list_topics, read, search, sections, index)
- `topic`: string
- `query`: string
- `section`: string
- `offset`: integer
- `limit`: integer
- `include_snippets`: boolean
- `context_lines`: integer

## yara_hunt

### Actions
- `scan`
- `compile`
- `list_rules`

### Args
- `action`: enum (see Actions)
- `idb`: string

---
Doc status: Updated to match actual tool implementations.
Last reviewed: 2026-01-11
