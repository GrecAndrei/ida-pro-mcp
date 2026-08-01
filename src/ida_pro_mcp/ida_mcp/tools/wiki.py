import difflib
import re
from collections import OrderedDict

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


SEMANTIC_ALIASES = {
    "runtime": "execution",
    "flow": "trace",
    "path": "trace",
    "tracking": "trace",
    "lookup": "search",
    "find": "search",
    "locate": "search",
    "rewrite": "modify",
}

# Simple LRU cache for wiki page content
_WIKI_CACHE = OrderedDict()
_MAX_WIKI_CACHE = 16


def _get_wiki_root():
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(_script_dir))))
    return os.path.join(_repo_root, "docs", "wiki")


def _read_wiki_file(path):
    """Read a wiki file with caching."""
    real_path = os.path.realpath(path)
    if real_path in _WIKI_CACHE:
        _WIKI_CACHE.move_to_end(real_path)
        return _WIKI_CACHE[real_path]
    with open(path, encoding='utf-8') as f:
        content = f.read()
    _WIKI_CACHE[real_path] = content
    if len(_WIKI_CACHE) > _MAX_WIKI_CACHE:
        _WIKI_CACHE.popitem(last=False)
    return content


def _fuzzy_find_topic(query, topics_dict, cutoff=0.6):
    """Fuzzy find a topic name across all categories."""
    query_lower = query.lower().replace("_", " ")
    best_match = None
    best_score = 0.0
    for category, pages in topics_dict.items():
        for page in pages:
            # Check exact or substring
            full = f"{category}/{page}".lower()
            if query_lower in full or full in query_lower:
                return full, 1.0
            # Fuzzy match
            for candidate in (page.lower(), full, category.lower()):
                score = difflib.SequenceMatcher(None, query_lower, candidate).ratio()
                if score > best_score and score >= cutoff:
                    best_score = score
                    best_match = full
    return best_match, best_score


def protocol_resource() -> str:
    """The QuickStart page — operational guide for AI agents."""
    path = os.path.join(_get_wiki_root(), "QuickStart.md")
    try:
        return _read_wiki_file(path)
    except Exception:
        return "Use wiki(action='read', topic='QuickStart') for the quickstart guide."

@tool
def wiki(
    action: Annotated[Literal["list_topics", "read", "search", "semantic_search", "index", "sections", "suggest"],
                      "Action: list_topics|read|search|semantic_search|index|sections|suggest"],
    topic: Annotated[Optional[str], "Topic name (e.g. 'code', 'core/investigation')"] = None,
    query: Annotated[Optional[str], "Search query (alias for topic when action=search)"] = None,
    section: Annotated[Optional[str], "Specific section or subsection to read (header text)"] = None,
    offset: Annotated[int, "Start line offset for chunked reading"] = 0,
    limit: Annotated[int, "Maximum lines to return (0 for no limit)"] = 0,
    include_snippets: Annotated[bool, "Include match snippets in search results"] = False,
    context_lines: Annotated[int, "Snippet context lines before/after match"] = 2,
    **kwargs
) -> dict:
    """
    Access the specialized IDA MCP Wiki for tool documentation and workflows.
    Supports hierarchical section reading, line-based pagination, and fuzzy suggestion.

    Actions:
    - list_topics: List all available categories and pages.
    - read: Read a wiki page. Use 'section' for specific parts, and 'offset'/'limit' for chunks.
    - search: Search for keywords across the entire wiki.
    - semantic_search: Search with concept expansion (synonyms) plus typo-tolerant ranking.
    - index: Structured index with doc counts and metadata.
    - sections: List headers for a specific topic with line numbers.
    - suggest: Fuzzy-find the best-matching topic for a given query.
    """
    # Use script path to find docs, not os.getcwd() which may be wrong
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    # Go up from tools/ -> ida_mcp/ -> ida_pro_mcp/ -> src/ -> repo root
    _repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(_script_dir))))
    wiki_root = os.path.join(_repo_root, "docs", "wiki")
    wiki_root_real = os.path.realpath(wiki_root)

    try:
        def collect_topics():
            topics = {}
            for root, _dirs, files in os.walk(wiki_root):
                rel_path = os.path.relpath(root, wiki_root)
                category = "root" if rel_path == "." else rel_path.replace(os.sep, "/")
                pages = [f.replace(".md", "") for f in files if f.endswith(".md")]
                if pages:
                    topics[category] = sorted(pages)
            return topics

        def parse_headers(lines):
            headers = []
            for idx, line in enumerate(lines, 1):
                strip = line.strip()
                if strip.startswith("#"):
                    level = strip.count("#")
                    text = strip.lstrip("#").strip()
                    headers.append({"level": level, "text": text, "line": idx})
            return headers

        def _is_inside_wiki(candidate: str) -> bool:
            real_candidate = os.path.realpath(candidate)
            try:
                return os.path.commonpath([wiki_root_real, real_candidate]) == wiki_root_real
            except ValueError:
                return False

        def resolve_topic_path(topic_name: str):
            if not topic_name:
                return None, make_error(MCPError.INVALID_ARGS, "topic required")

            normalized = topic_name.strip().replace("\\", "/")
            if not normalized:
                return None, make_error(MCPError.INVALID_ARGS, "topic required")
            if os.path.isabs(normalized):
                return None, make_error(MCPError.PATH_TRAVERSAL, "Absolute topic paths are not allowed")
            if normalized.startswith("/"):
                normalized = normalized.lstrip("/")
            if normalized.endswith(".md"):
                normalized = normalized[:-3]

            parts = [p for p in normalized.split("/") if p]
            if not parts or any(p in (".", "..") for p in parts):
                return None, make_error(MCPError.PATH_TRAVERSAL, "Invalid wiki topic path")

            candidates = []
            if len(parts) > 1:
                candidates.append(os.path.join(wiki_root, *parts) + ".md")
            else:
                base = parts[0]
                for sub in ["tools", "core", ""]:
                    candidates.append(os.path.join(wiki_root, sub, base + ".md"))

            for cand in candidates:
                if not _is_inside_wiki(cand):
                    return None, make_error(MCPError.PATH_TRAVERSAL, "Topic path escapes wiki root")
                if os.path.exists(cand):
                    return cand, None

            return None, make_error(MCPError.FILE_NOT_FOUND, f"Wiki topic '{topic_name}' not found")

        if action == "list_topics":
            return {"ok": True, "categories": collect_topics()}

        elif action == "read":
            if not topic: return make_error(MCPError.INVALID_ARGS, "topic required")
            path, err = resolve_topic_path(topic)
            if err:
                # Try fuzzy suggestion and include it in the error
                topics = collect_topics()
                suggestion, score = _fuzzy_find_topic(topic, topics)
                if suggestion:
                    err["suggestion"] = suggestion
                    err["fuzzy_score"] = round(score, 3)
                return err

            lines = _read_wiki_file(path).splitlines(True)

            content_lines = lines
            target_section = None

            # Extract section if requested
            if section:
                section_lines = []
                found = False
                header_level = 0
                s_lower = section.lower().strip()

                for line in lines:
                    strip_line = line.strip()
                    if strip_line.startswith("#"):
                        # Check if this is our target header
                        # Support formats like "## 2.1 Symbolic Aggression" or "Symbolic Aggression"
                        h_text = strip_line.lstrip("#").strip().lower()
                        if s_lower in h_text:
                            found = True
                            header_level = strip_line.count("#")
                            section_lines.append(line)
                            continue

                        if found:
                            # If we hit another header of same or higher level, we are done
                            new_level = strip_line.count("#")
                            if new_level <= header_level:
                                break

                    if found:
                        section_lines.append(line)

                if found:
                    content_lines = section_lines
                    target_section = section
                else:
                    return make_error(MCPError.INVALID_ARGS, f"Section '{section}' not found in topic '{topic}'")

            # Detect all headers for "Table of Contents"
            toc = [h["text"] for h in parse_headers(lines)]

            # Apply line-based pagination
            total_lines = len(content_lines)
            start = max(0, offset)
            end = total_lines
            if limit > 0:
                end = min(total_lines, start + limit)

            paginated_lines = content_lines[start:end]

            # Determine breadcrumbs for the current chunk
            # We look back from the 'start' line in the original file to find active headers
            original_start_index = 0
            if target_section:
                # Find where this section started in the full file
                sec_text = target_section.lower().strip()
                for i, line in enumerate(lines):
                    if line.strip().startswith("#") and sec_text in line.lower():
                        original_start_index = i
                        break

            current_line_in_file = original_start_index + start
            breadcrumbs = []

            # Scan backwards from current line to find the header hierarchy
            for i in range(current_line_in_file, -1, -1):
                line = lines[i].strip()
                if line.startswith("#"):
                    level = line.count("#")
                    # Only add if it's a higher level than what we already found
                    if not breadcrumbs or level < breadcrumbs[0]["level"]:
                        breadcrumbs.insert(0, {"level": level, "text": line.lstrip("#").strip()})
                    if level == 1: # Reached the top
                        break

            result = {
                "ok": True,
                "topic": topic,
                "line_range": f"{current_line_in_file + 1}-{current_line_in_file + len(paginated_lines)}",
                "total_lines_in_topic": len(lines),
                "breadcrumbs": [b["text"] for b in breadcrumbs],
                "headers": toc[:50],
            }

            if target_section:
                result["section_filter"] = target_section

            result["content"] = "".join(paginated_lines)

            if limit > 0 and end < total_lines:
                result["_truncated"] = True
                result["next_offset"] = end
                result["lines_remaining"] = total_lines - end

            return result

        elif action in ("search", "semantic_search"):
            q = (query or topic or "").strip()
            if not q:
                return make_error(MCPError.INVALID_ARGS, "query required")
            q_lower = q.lower()
            query_tokens = re.findall(r"[a-z0-9_]+", q_lower)
            query_terms = {q_lower}.union(query_tokens)
            for token in query_tokens:
                if action == "semantic_search" and token in SEMANTIC_ALIASES:
                    query_terms.add(SEMANTIC_ALIASES[token])
            results = []

            for root, _, files in os.walk(wiki_root):
                for f in files:
                    if f.endswith(".md"):
                        p = os.path.join(root, f)
                        rel_name = os.path.relpath(p, wiki_root).replace(".md", "").replace(os.sep, "/")
                        content = _read_wiki_file(p)
                        content_lower = content.lower()
                        if any(t in content_lower or t in f.lower() for t in query_terms):
                                entry = {
                                    "topic": rel_name,
                                    "matched_on": ["semantic_overlap"] if action == "semantic_search" else ["content_contains"],
                                }
                                if action == "semantic_search":
                                    rel_tokens = set(re.findall(r"[a-z0-9_]+", rel_name.lower()))
                                    content_tokens = set(re.findall(r"[a-z0-9_]+", content_lower[:4000]))
                                    semantic_hits = sorted(
                                        t for t in query_terms if t in rel_tokens or t in content_tokens
                                    )
                                    if semantic_hits:
                                        entry["semantic_hits"] = semantic_hits[:10]
                                if include_snippets:
                                    lines = content.splitlines()
                                    matches = []
                                    for i, line in enumerate(lines):
                                        line_lower = line.lower()
                                        if any(t in line_lower for t in query_terms):
                                            start = max(0, i - context_lines)
                                            end = min(len(lines), i + context_lines + 1)
                                            snippet = "\n".join(lines[start:end])
                                            matches.append({"line": i + 1, "snippet": snippet})
                                            if len(matches) >= 5:
                                                break
                                    entry["matches"] = matches
                                results.append(entry)

            if action == "semantic_search":
                def semantic_sort_key(entry: dict) -> tuple[int, int, float, str]:
                    # Prioritize stronger semantic matches, then snippet density,
                    # then fuzzy topic similarity, and finally stable topic ordering.
                    sem_hits = len(entry.get("semantic_hits", []))
                    match_hits = len(entry.get("matches", []))
                    ratio = difflib.SequenceMatcher(None, q_lower, entry.get("topic", "").lower()).ratio()
                    return (-sem_hits, -match_hits, -ratio, entry.get("topic", ""))
                results.sort(key=semantic_sort_key)
            return {"ok": True, "action": action, "query": q, "matches": results, "count": len(results)}

        elif action == "sections":
            if not topic:
                return make_error(MCPError.INVALID_ARGS, "topic required")
            path, err = resolve_topic_path(topic)
            if err:
                topics = collect_topics()
                suggestion, score = _fuzzy_find_topic(topic, topics)
                if suggestion:
                    err["suggestion"] = suggestion
                    err["fuzzy_score"] = round(score, 3)
                return err
            lines = _read_wiki_file(path).splitlines(True)
            headers = parse_headers(lines)
            return {"ok": True, "topic": topic, "headers": headers}

        elif action == "suggest":
            q = (query or topic or "").strip()
            if not q:
                return make_error(MCPError.INVALID_ARGS, "query or topic required")
            topics = collect_topics()
            suggestion, score = _fuzzy_find_topic(q, topics)
            if suggestion:
                return {"ok": True, "query": q, "suggestion": suggestion, "score": round(score, 3)}
            return {"ok": True, "query": q, "suggestion": None, "score": 0.0}

        elif action == "index":
            topics = collect_topics()
            total_pages = sum(len(pages) for pages in topics.values())
            return {"ok": True, "categories": topics, "total_pages": total_pages}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")

    except Exception as e:
        return handle_error(e)
