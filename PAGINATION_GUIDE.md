# Pagination & Context Management Guide for LLMs

## Problem

Reverse engineering binaries often produces **massive amounts of data** that can overflow LLM context windows:
- Large binaries have 10,000+ functions
- String tables can have 50,000+ entries  
- Cross-reference queries can return thousands of results

## Solution: Smart Pagination

All data-heavy MCP tools support pagination to prevent context window exhaustion.

## Tools with Pagination Support

### 1. `data` tool

**All actions support pagination:**

```python
# Functions - typically 100s to 10,000s
data(action="functions", offset=0, count=50)
# Returns: {functions: [...], total: 5234, offset: 0, count: 50}

# Globals - typically 100s to 1,000s  
data(action="globals", offset=0, count=100)

# Strings - can be 10,000+
data(action="strings", offset=0, count=100)

# Imports - typically 50-500
data(action="imports", offset=0, count=100)

# Exports - typically 10-1,000
data(action="exports", offset=0, count=100)
```

**Filtering before pagination:**
```python
# Only named functions (reduces results dramatically)
data(action="functions", named_only=True, count=50)

# Functions above size threshold
data(action="functions", min_size=100, count=50)

# Search strings by content
data(action="strings", query="password", count=20)
```

### 2. `search` tool

**All search actions support `offset` and `limit`:**

```python
# Search with limit
search(action="name", pattern="*crypto*", limit=50, offset=0)

# Vulnerable patterns (can be 100s)
search(action="vulnerable", limit=50)

# Constants (can be 100s if binary uses crypto)
search(action="constants", limit=30)

# Pattern searches
search(action="bytes", pattern="55 8B EC", limit=100, offset=0)
search(action="string", pattern="error", limit=50, offset=0)
```

### 3. `idb` tool

**Segment and entrypoint listing:**

```python
# Segments (typically 10-50)
idb(action="segments", offset=0, count=100)

# Entrypoints (typically 1-20)
idb(action="entrypoints", offset=0, count=100)
```

### 4. `code` tool

**Cross-reference queries:**

```python
# Find all callers (can be 1,000+)
code(action="callers", addr="0x401000", limit=50)

# Find all xrefs to address
code(action="xrefs_to", addr="0x401000", limit=100)

# Find all xrefs from address  
code(action="xrefs_from", addr="0x401000", limit=100)
```

## Response Format

All paginated responses include:

```json
{
  "ok": true,
  "results": [...],           // The actual data
  "total": 5234,              // Total matches
  "offset": 0,                // Current offset
  "count": 50,                // Items returned
  "truncated": true           // More results available
}
```

## Best Practices for LLMs

### 1. Start Small

**Always start with small limits** to understand the data:

```python
# BAD: Request everything
data(action="functions", count=0)  # Returns ALL functions!

# GOOD: Start with sample
data(action="functions", count=10)  # See what you're dealing with
```

### 2. Progressive Loading

**Load more only when needed:**

```python
# 1. Get overview
result = data(action="functions", count=20, named_only=True)

# 2. If total is reasonable, get more
if result["total"] < 200:
    result = data(action="functions", count=result["total"], named_only=True)
```

### 3. Use Filters

**Reduce data before pagination:**

```python
# Instead of: Get all 5000 functions then filter
# BAD
all_funcs = data(action="functions", count=5000)
big_funcs = [f for f in all_funcs if f["size"] > 500]

# GOOD: Filter at source
big_funcs = data(action="functions", min_size=500, count=100)
```

### 4. Targeted Queries

**Use specific searches instead of listing everything:**

```python
# Instead of: List all functions, then search
# BAD
all_funcs = data(action="functions", count=1000)
crypto_funcs = [f for f in all_funcs if "crypto" in f["name"]]

# GOOD: Search directly
crypto_funcs = search(action="name", pattern="*crypto*", limit=50)
```

### 5. Iterative Refinement

**Query → Analyze → Refine:**

```python
# Step 1: Get summary
summary = idb(action="summary")
# Shows: 5234 functions, 1234 named

# Step 2: Focus on interesting functions
named = data(action="functions", named_only=True, count=50)

# Step 3: Deeper dive on specific function
details = agent(action="quick", addr=named["functions"][0]["addr"])
```

## Common Patterns

### Pattern 1: Survey Then Dive

```python
# 1. Survey: What's in this binary?
summary = idb(action="summary")

# 2. Sample: Look at a few functions
funcs = data(action="functions", count=10)

# 3. Dive: Deep analysis on specific target
details = agent(action="context_pack", addr=funcs["functions"][0]["addr"])
```

### Pattern 2: Search → Filter → Analyze

```python
# 1. Search: Find interesting targets
vulns = search(action="vulnerable", limit=50)

# 2. Filter: Group by type
format_string = [v for v in vulns["findings"] if v["vuln_type"] == "format_string"]

# 3. Analyze: Check top hits
for vuln in format_string[:5]:
    context = agent(action="quick", addr=vuln["addr"])
```

### Pattern 3: Progressive Exploration

```python
# Start small
batch1 = data(action="functions", offset=0, count=50, named_only=True)

# If interesting, get more
if interesting_patterns_found:
    batch2 = data(action="functions", offset=50, count=50, named_only=True)
```

## Anti-Patterns to Avoid

### ❌ Don't: Request Everything

```python
# This can return 50,000 strings!
data(action="strings", count=0)  # count=0 means "all"
```

### ❌ Don't: Iterate Without Limits

```python
# This will make 100 calls for 10,000 functions
for i in range(0, 10000, 100):
    data(action="functions", offset=i, count=100)
```

### ❌ Don't: Ignore Truncation Flags

```python
result = search(action="name", pattern="sub_*", limit=100)
# If result["truncated"] == true, you're only seeing partial results!
# Either refine query or acknowledge you're working with subset
```

### ✅ Do: Use Filters and Thresholds

```python
# Filter before paginating
data(action="functions", named_only=True, min_size=100, count=50)

# Use targeted searches
search(action="find", pattern="decrypt")  # Auto-searches names, strings, imports

# Get counts first
summary = idb(action="summary")
if summary["function_count"] < 500:
    # Small binary, safe to get more
    funcs = data(action="functions", count=500)
```

## Special Cases

### Large Binaries (10,000+ functions)

1. **Focus on named functions only**: `named_only=True` cuts results by 80-90%
2. **Use search**: `search(action="name", pattern="*interesting*")`
3. **Sample strategically**: Get first 100, analyze, decide if you need more

### Cross-Reference Explosions

Some functions are called 1000s of times (e.g., `malloc`, `memcpy`):

```python
# Check count first
xrefs = code(action="xrefs_to", addr="0x401000", limit=10)
if xrefs["total"] > 500:
    # Too many to analyze, focus on unique callers
    callers = search(action="callers", pattern="0x401000", limit=50)
```

### String Tables

String tables can be massive:

```python
# Don't: Get all strings
# Do: Search for specific patterns
search(action="string", pattern="password", limit=50)
search(action="string", pattern="http", limit=50)
```

## Summary

**Key Principles:**
1. **Start small** - Use low `count`/`limit` values initially
2. **Filter first** - Use `query`, `named_only`, `min_size` before pagination
3. **Check totals** - Look at `total` and `truncated` in responses
4. **Targeted searches** - Use `search` tool instead of listing everything
5. **Progressive loading** - Only get more data when analysis requires it

**Remember:** Your goal is analysis, not data collection. Get enough to answer the question, not everything available.
