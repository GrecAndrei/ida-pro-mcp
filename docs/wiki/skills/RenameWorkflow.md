# Skill: Rename Workflow

**Goal:** Rename all unnamed functions efficiently using embedding-based suggestions and propagation.

## Key Sequence

```
funcs(action="suggest_names")
  → review suggestions
  → funcs(action="set_name", address="0x...", name="new_name")
  → blackboard(action="list", category="rename_suggestion")
```

## When to Use

- After initial triage when many `sub_XXXX` functions remain
- After identifying key clusters to propagate meaningful names
- Iteratively as understanding deepens

## Smart Features Used

| Feature | Role |
|---------|------|
| FunctionEmbeddingIndex | Cosine similarity against known function patterns |
| Rename propagation | After a rename, automatically suggests names for callees |
| Blackboard | Stores propagated suggestions under `category=rename_suggestion` |

## How It Works

1. **suggest_names** uses bge-code-v1 embeddings to compare unnamed functions against a corpus of known patterns
2. Returns ranked suggestions with confidence scores
3. After you accept a rename via `set_name`, the system propagates context to callees
4. Propagated suggestions appear on the blackboard for batch review

## Example Flow

```json
{"name": "funcs", "arguments": {"action": "suggest_names", "count": 20}}
```

Review, then apply:

```json
{"name": "funcs", "arguments": {"action": "set_name", "address": "0x401230", "name": "decrypt_config"}}
```

Check propagated suggestions:

```json
{"name": "blackboard", "arguments": {"action": "list", "category": "rename_suggestion"}}
```

## Exit Criteria

- No remaining `sub_XXXX` functions in critical paths
- Propagated suggestions reviewed and applied/dismissed
- Blackboard rename_suggestion category cleared or confirmed
