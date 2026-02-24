# IDB Tool Manual

## What It Does
Provides database-level metadata, summary statistics, segment details, entry points, bookmarks, and a combined overview payload.

## Actions
- `meta`: Binary and IDB metadata (paths, architecture, hashes, bounds).
- `summary`: Counts and coverage metrics (functions, imports, comments, code coverage).
- `overview`: Combined `meta + summary + top segments + entrypoints` snapshot.
- `segments`: Detailed segment records with pagination.
- `entrypoints`: Entry point/export listing with basic classification.
- `bookmarks`: IDA bookmark list.

## Key Parameters
- `action`: One of `meta|summary|segments|entrypoints|bookmarks|overview`.
- `offset`, `count`: Pagination controls for `segments` (`count=0` returns all from offset).

## Examples
```python
idb(action="meta")
idb(action="summary")
idb(action="overview")
idb(action="segments", offset=0, count=50)
idb(action="entrypoints")
idb(action="bookmarks")
```

## Failure Modes
- Unknown action.
- IDA version/API differences can alter available metadata fields.
- Very large databases can make summary calculations slower.
- Bookmark APIs may be absent and return empty list.
