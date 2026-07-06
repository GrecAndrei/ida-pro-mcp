# classify

Classifies functions and binaries by behavior using zero-shot ML (bge-code-v1) in embedding-first mode.

## Actions
- `function` — classify a single function's behavior; params: `address`. Returns `behavior_tags`.
- `binary` — classify the overall binary (malware family, packer, purpose)
- `all_functions` — batch-classify all functions; params: `offset`, `count`
- `library_code` — identify library/runtime functions
- `wrappers` — find thin wrapper functions
- `callbacks` — find callback-style functions
- `initializers` — find init/setup functions
- `error_handlers` — find error handling functions
- `hot_functions` — find high-complexity or high-call-count functions
- `orphans` — find unreferenced functions
- `induce_schema` — generate structured attribute-value schema for a function; params: `address`

## Examples

```json
{"name": "classify", "arguments": {"action": "function", "address": "0x401000"}}
```

```json
{"name": "classify", "arguments": {"action": "induce_schema", "address": "0x401000"}}
```

## Notes
- `function` uses BehaviorClassifier (bge-code-v1 zero-shot) as the primary ranking signal.
- `induce_schema` produces structured attribute-value schemas for function classification.
- Batch actions (`all_functions`, `library_code`, etc.) support `offset`/`count` pagination.
