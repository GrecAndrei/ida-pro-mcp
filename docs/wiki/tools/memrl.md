# memrl

Q-value reinforcement learning for ranking functions and entries by historical utility.

## Actions
- `record` — record a usage event; params: `key`, `context`
- `update` — update Q-value for a key; params: `key`, `reward`
- `rank` — rank entries by Q-value; params: `keys` (list), `context`
- `stats` — show RL statistics
- `top` — get top-K entries by Q-value; params: `limit`
- `get_q` — get Q-value for a key; params: `key`
- `suggest` — suggest next action based on Q-values; params: `context`
- `feedback` — provide explicit feedback; params: `key`, `positive` (bool)

## Examples
```json
{"name": "memrl", "arguments": {"action": "top", "limit": 10}}
```
```json
{"name": "memrl", "arguments": {"action": "feedback", "key": "sub_401000", "positive": true}}
```

## Notes
- Q-values are updated via TD-style learning from usage patterns.
- Used internally by Cartographer-mu for relevance-ranked context injection.
- `feedback` allows explicit human-in-the-loop reward signals.
