import re

try:
    from ._common import *
except ImportError:
    from _common import *  # type: ignore[import-not-found]


def protocol_resource() -> str:
    """The Master Forensic RE Protocol - Rules of Engagement for AI Agents."""
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(_script_dir))))
    wiki_root = os.path.join(_repo_root, "docs", "wiki")
    path = os.path.join(wiki_root, "workflows", "ForensicProtocol.md")
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        return "CRITICAL: Name everything. Define structs. Debug is truth. Use wiki(topic='workflows/ForensicProtocol') for details."

@tool
def wiki(
    action: Annotated[Literal["list_topics", "read", "search", "semantic_search", "index", "sections"],
                      "Action: list_topics|read|search|semantic_search|index|sections"],
    topic: Annotated[Optional[str], "Topic name (e.g. 'debug', 'workflows/ForensicProtocol')"] = None,
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
    Supports hierarchical section reading and line-based pagination.
    
    Actions:
    - list_topics: List all available categories and pages.
    - read: Read a wiki page. Use 'section' for specific parts, and 'offset'/'limit' for chunks.
    - search: Search for keywords across the entire wiki.
    - semantic_search: Search with concept expansion (synonyms + fuzzy matching).
    - index: Structured index with doc counts and metadata.
    - sections: List headers for a specific topic with line numbers.
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
            for root, dirs, files in os.walk(wiki_root):
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
                for sub in ["tools", "workflows", "skills", "core", ""]:
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
                return err
            
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
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
            semantic_aliases = {
                "runtime": "execution",
                "flow": "trace",
                "path": "trace",
                "tracking": "trace",
                "lookup": "search",
                "find": "search",
                "locate": "search",
                "rewrite": "modify",
            }
            query_terms = {q_lower}
            for token in re.findall(r"[a-z0-9_]+", q_lower):
                query_terms.add(token)
                if action == "semantic_search" and token in semantic_aliases:
                    query_terms.add(semantic_aliases[token])
            results = []

            for root, _, files in os.walk(wiki_root):
                for f in files:
                    if f.endswith(".md"):
                        p = os.path.join(root, f)
                        rel_name = os.path.relpath(p, wiki_root).replace(".md", "").replace(os.sep, "/")
                        with open(p, 'r', encoding='utf-8') as file:
                            content = file.read()
                            content_lower = content.lower()
                            if any(t in content_lower or t in f.lower() for t in query_terms):
                                entry = {"topic": rel_name}
                                if include_snippets:
                                    lines = content.splitlines()
                                    matches = []
                                    for i, line in enumerate(lines):
                                        if q_lower in line.lower():
                                            start = max(0, i - context_lines)
                                            end = min(len(lines), i + context_lines + 1)
                                            snippet = "\n".join(lines[start:end])
                                            matches.append({"line": i + 1, "snippet": snippet})
                                            if len(matches) >= 5:
                                                break
                                    entry["matches"] = matches
                                results.append(entry)

            return {"ok": True, "query": q, "matches": results}

        elif action == "sections":
            if not topic:
                return make_error(MCPError.INVALID_ARGS, "topic required")
            path, err = resolve_topic_path(topic)
            if err:
                return err
            with open(path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            headers = parse_headers(lines)
            return {"ok": True, "topic": topic, "headers": headers}

        elif action == "index":
            topics = collect_topics()
            total_pages = sum(len(pages) for pages in topics.values())
            return {"ok": True, "categories": topics, "total_pages": total_pages}

        else:
            return make_error(MCPError.INVALID_ARGS, f"Unknown action: {action}")
            
    except Exception as e:
        return handle_error(e)
