# filter (removed)

The standalone `filter` tool was removed in 0.9.x.

It duplicated host response controls that already exist on every tool:

- wrapper actions: `pick`, `grep`, `head`, `tail`, `stats`, `next`
- response compaction / truncation on the host

Do not call `filter`. Use those wrappers or request a smaller `limit` on the source tool.
