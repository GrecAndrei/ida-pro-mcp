#!/usr/bin/env python3
"""Wiki/search helpers extracted from the main server implementation."""

import difflib
import json
import os
import re
import shlex
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import (
    EMBEDDING_FIRST_MODE,
    MAX_WIKI_RESULTS,
    WIKI_SEMANTIC_GROUPS,
    _bounded_int,
    _parse_line_range,
)
from .errors import MCPError, make_error
from .schemas import TOOL_ACTIONS, TOOL_ARG_SCHEMAS, TOOL_DESCRIPTIONS, TOOLS


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class ServerWikiMixin:
    def _resolve_wiki_root(self) -> str:
        env_path = os.environ.get("IDA_MCP_WIKI_DIR")
        candidates: List[str] = []
        if env_path:
            candidates.append(os.path.realpath(os.path.expanduser(env_path)))

        script_dir = os.path.realpath(SCRIPT_DIR)
        cwd = os.path.realpath(os.getcwd())
        home = os.path.realpath(str(Path.home()))

        candidates.extend(
            [
                os.path.join(script_dir, "docs", "wiki"),
                os.path.join(script_dir, "src", "ida_pro_mcp", "docs", "wiki"),
                os.path.join(os.path.dirname(script_dir), "docs", "wiki"),
                os.path.join(cwd, "docs", "wiki"),
                os.path.join(home, ".ida-pro-mcp", "wiki"),
                os.path.join(home, ".local", "share", "ida-pro-mcp", "wiki"),
            ]
        )

        seen = set()
        for cand in candidates:
            cand = os.path.realpath(cand)
            if cand in seen:
                continue
            seen.add(cand)
            if os.path.isdir(cand):
                return cand
        return ""

    def _wiki_parse_headers(self, lines: List[str]) -> List[dict]:
        headers = []
        for idx, line in enumerate(lines, 1):
            strip = line.strip()
            if strip.startswith("#"):
                level = strip.count("#")
                text = strip.lstrip("#").strip()
                headers.append({"level": level, "text": text, "line": idx})
        return headers

    def _wiki_tokenize(self, text: str) -> List[str]:
        if not text:
            return []
        return re.findall(r"[a-z0-9_]+", text.lower())

    def _wiki_stem_token(self, token: str) -> str:
        t = token.strip().lower()
        if len(t) <= 3:
            return t
        for suffix in ("ing", "ed", "es", "s"):
            if t.endswith(suffix) and len(t) - len(suffix) >= 3:
                stem = t[: -len(suffix)]
                if suffix == "ing" and stem.endswith("c"):
                    # tracing -> trace, mimicking simple English recovery.
                    stem += "e"
                return stem
        return t

    def _wiki_embed_text(self, text: str) -> Optional[List[float]]:
        txt = (text or "").strip()
        if not txt:
            return None
        key = txt[:2048].lower()
        cached = self._wiki_embed_cache.get(key)
        if cached is not None:
            return cached
        try:
            from .intelligence_core import BgeCodeEmbedder
            embedder = BgeCodeEmbedder()
            vec = embedder.embed(key)
        except Exception:
            return None
        if len(self._wiki_embed_cache) >= self._wiki_embed_cache_max:
            # simple FIFO-ish eviction
            try:
                self._wiki_embed_cache.pop(next(iter(self._wiki_embed_cache)))
            except Exception:
                self._wiki_embed_cache.clear()
        self._wiki_embed_cache[key] = vec
        return vec

    def _wiki_expand_semantic_terms(self, query_tokens: List[str]) -> set[str]:
        raw = {self._wiki_stem_token(t) for t in query_tokens if t}
        expanded = set(raw)
        for group in WIKI_SEMANTIC_GROUPS:
            stemmed_group = {self._wiki_stem_token(item) for item in group}
            if raw.intersection(stemmed_group):
                expanded.update(stemmed_group)
        return expanded

    def _wiki_semantic_search_pages(
        self,
        pages: List[dict],
        query: str,
        *,
        max_results: int,
        category_filter: Any = None,
        include_snippets: bool = False,
        context_lines: int = 2,
    ) -> List[dict]:
        query_lower = query.lower().strip()
        query_tokens = self._wiki_tokenize(query_lower)
        expanded_terms = self._wiki_expand_semantic_terms(query_tokens)
        scored: List[dict] = []
        for page in pages:
            if not self._wiki_match_category(page["topic"], category_filter):
                continue

            base_score, reasons = self._wiki_score_page(
                page, query_lower, query_tokens, fuzzy=True
            )
            page_tokens = page.get("stemmed_tokens")
            # Defensive fallback: keeps semantic search working if an older cache entry
            # (without stemmed_tokens) is present during rolling updates/tests.
            if not isinstance(page_tokens, set):
                page_tokens = {
                    self._wiki_stem_token(t) for t in page.get("tokens", set())
                }
            semantic_hits = sorted(expanded_terms.intersection(page_tokens))
            if semantic_hits:
                base_score += (len(semantic_hits) * 14) + 20
                reasons.append("semantic_overlap")

            if base_score <= 0:
                continue

            entry = {
                "topic": page["topic"],
                "title": page["title"],
                "category": page["category"],
                "score": base_score,
                "matched_on": reasons[:4],
            }
            if semantic_hits:
                entry["semantic_hits"] = semantic_hits[:10]
            if include_snippets:
                snippet_terms = (
                    " ".join(sorted(semantic_hits[:4])).strip() or query_lower
                )
                snippet_tokens = self._wiki_tokenize(snippet_terms)
                entry["matches"] = self._wiki_extract_snippets(
                    page["text"], snippet_terms, snippet_tokens, context_lines
                )
            scored.append(entry)
        scored.sort(key=lambda x: (-x["score"], x["topic"]))
        return scored[:max_results]

    def _wiki_get_index(self, wiki_root: str, force: bool = False) -> dict:
        now = time.time()
        cache = self._wiki_cache
        if (
            not force
            and cache.get("root") == wiki_root
            and now < float(cache.get("expires", 0.0))
        ):
            return cache

        topics: Dict[str, List[str]] = {}
        pages: List[dict] = []
        if wiki_root and os.path.isdir(wiki_root):
            for root, _, files in os.walk(wiki_root):
                rel_dir = os.path.relpath(root, wiki_root)
                category = "root" if rel_dir == "." else rel_dir.replace(os.sep, "/")
                for filename in sorted(files):
                    if not filename.endswith(".md"):
                        continue
                    full_path = os.path.join(root, filename)
                    try:
                        with open(
                            full_path, "r", encoding="utf-8", errors="ignore"
                        ) as f:
                            text = f.read()
                    except OSError:
                        continue
                    page_name = filename[:-3]
                    topic = (
                        page_name if category == "root" else f"{category}/{page_name}"
                    )
                    lines = text.splitlines()
                    headers = self._wiki_parse_headers([line + "\n" for line in lines])
                    title = headers[0]["text"] if headers else page_name
                    header_text = " ".join(h["text"] for h in headers).lower()
                    topics.setdefault(category, []).append(page_name)
                    text_to_tokenize = f"{topic} {title} {header_text} {text[:4000]}"
                    raw_tokens = self._wiki_tokenize(text_to_tokenize)
                    pages.append(
                        {
                            "topic": topic,
                            "topic_lower": topic.lower(),
                            "topic_basename": page_name.lower(),
                            "category": category,
                            "title": title,
                            "title_lower": title.lower(),
                            "headers": headers,
                            "header_text_lower": header_text,
                            "path": full_path,
                            "text": text,
                            "text_lower": text.lower(),
                            "line_count": len(lines),
                            "tokens": set(raw_tokens),
                            "stemmed_tokens": {
                                self._wiki_stem_token(t) for t in raw_tokens
                            },
                            "semantic_title_text": f"{topic} {title} {header_text}".strip(),
                            "semantic_body_text": text[:4000],
                        }
                    )

        for category in list(topics.keys()):
            topics[category] = sorted(set(topics[category]))
        pages.sort(key=lambda p: p["topic"])

        cache.update(
            {
                "root": wiki_root,
                "expires": now + self._wiki_cache_ttl,
                "topics": topics,
                "pages": pages,
            }
        )
        return cache

    def _wiki_normalize_topic(
        self, topic_name: Any
    ) -> tuple[Optional[str], Optional[dict]]:
        normalized = str(topic_name or "").strip().replace("\\", "/")
        if not normalized:
            return None, make_error(MCPError.INVALID_ARGS, "topic required")
        if os.path.isabs(normalized):
            return None, make_error(
                MCPError.INVALID_ARGS, "Absolute topic paths are not allowed"
            )
        if normalized.startswith("/"):
            normalized = normalized.lstrip("/")
        if normalized.endswith(".md"):
            normalized = normalized[:-3]
        parts = [p for p in normalized.split("/") if p]
        if not parts or any(p in (".", "..") for p in parts):
            return None, make_error(MCPError.INVALID_ARGS, "Invalid wiki topic path")
        return "/".join(parts), None

    def _normalize_wiki_args(self, args: dict) -> dict:
        """
        Accept tolerant wiki call shapes often produced by LLMs:
        - action: "read topic=tools/query"
        - action: "read QuickStart"
        - action: "{\"action\":\"read\",\"topic\":\"tools/query\"}"
        """
        out = dict(args or {})
        raw_action = out.get("action")
        if not isinstance(raw_action, str):
            return out
        action_text = raw_action.strip()
        if not action_text:
            return out

        # Handle JSON stuffed into action field.
        if action_text.startswith("{") and action_text.endswith("}"):
            try:
                payload = json.loads(action_text)
            except Exception:
                payload = None
            if isinstance(payload, dict):
                for k, v in payload.items():
                    out.setdefault(k, v)
                out["action"] = str(payload.get("action", "")).strip()
                return out

        parts = action_text.split(None, 1)
        base = parts[0].strip()
        if base not in TOOL_ACTIONS["wiki"]:
            return out

        out["action"] = base
        tail = parts[1].strip() if len(parts) > 1 else ""
        if tail:
            positional: List[str] = []
            for token in shlex.split(tail):
                if "=" in token:
                    k, v = token.split("=", 1)
                    key = k.strip()
                    val = v.strip()
                    if key and val and key not in out:
                        out[key] = val
                else:
                    rng_start, rng_end = _parse_line_range(token)
                    if (
                        base in ("read", "sections")
                        and (rng_start is not None or rng_end is not None)
                        and not out.get("lines")
                    ):
                        out["lines"] = token
                    else:
                        positional.append(token)

            if positional:
                joined = " ".join(positional).strip()
                if joined:
                    if base in ("read", "sections") and not out.get("topic"):
                        out["topic"] = joined
                    elif base == "search" and not out.get("query"):
                        out["query"] = joined

        # Tolerate callers that accidentally pass topic in `idb` for wiki actions.
        if base in ("read", "sections") and not out.get("topic"):
            maybe_topic = out.get("idb")
            if isinstance(maybe_topic, str):
                candidate = maybe_topic.strip()
                if (
                    candidate
                    and not os.path.isabs(candidate)
                    and not re.search(
                        r"\.(i64|idb|exe|dll|so|dylib|bin)$", candidate, re.IGNORECASE
                    )
                ):
                    out["topic"] = candidate
        return out

    def _wiki_generated_tool_doc(self, tool_name: str) -> Optional[str]:
        if not isinstance(tool_name, str):
            return None
        tool_name = tool_name.strip().lower()
        if tool_name.startswith("tools/"):
            tool_name = tool_name.split("/", 1)[1]
        if tool_name.endswith(".md"):
            tool_name = tool_name[:-3]
        if tool_name not in TOOLS:
            return None

        action_list = TOOL_ACTIONS.get(tool_name, [])
        schema = TOOL_ARG_SCHEMAS.get(tool_name, {})
        key_params = [p for p in schema.keys() if p not in ("action",)]
        key_params = key_params[:16]

        lines = [
            f"# {tool_name.upper()} Tool Manual",
            "",
            "## What It Does",
            TOOL_DESCRIPTIONS.get(tool_name, "No description available."),
            "",
            "## Actions",
        ]
        if action_list:
            for action in action_list:
                lines.append(f"- `{action}`")
        else:
            lines.append("- See tool source")

        lines.extend(["", "## Key Parameters"])
        if key_params:
            for param in key_params:
                lines.append(f"- `{param}`")
        else:
            lines.append("- None")

        sample_args = {"action": action_list[0] if action_list else "help"}
        for param in key_params[:3]:
            sample_args[param] = "<value>"

        lines.extend(
            [
                "",
                "## Examples",
                "```json",
                json.dumps(sample_args, indent=2),
                "```",
                "",
                "## Failure Modes",
                "- Invalid arguments or missing required fields.",
                "- Unsupported action name.",
                "- Runtime/tool-specific failures returned by server.",
            ]
        )
        return "\n".join(lines) + "\n"

    def _wiki_match_category(self, topic: str, category_filter: Any) -> bool:
        if not category_filter:
            return True
        if isinstance(category_filter, str):
            categories = [
                c.strip().strip("/").lower() for c in category_filter.split(",")
            ]
        elif isinstance(category_filter, list):
            categories = [str(c).strip().strip("/").lower() for c in category_filter]
        else:
            categories = [str(category_filter).strip().strip("/").lower()]
        categories = [c for c in categories if c]
        if not categories:
            return True

        topic_lower = topic.lower()
        for category in categories:
            if category == "root":
                if "/" not in topic_lower:
                    return True
                continue
            if topic_lower == category or topic_lower.startswith(f"{category}/"):
                return True
        return False

    def _wiki_extract_snippets(
        self,
        text: str,
        query_lower: str,
        query_tokens: List[str],
        context_lines: int,
        max_snippets: int = 5,
    ) -> List[dict]:
        lines = text.splitlines()
        snippets: List[dict] = []
        if not lines:
            return snippets
        terms = [query_lower] + [t for t in query_tokens if len(t) >= 3]
        terms = [t for t in terms if t]
        if not terms:
            return snippets
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if not any(term in line_lower for term in terms):
                continue
            start = max(0, i - context_lines)
            end = min(len(lines), i + context_lines + 1)
            snippets.append({"line": i + 1, "snippet": "\n".join(lines[start:end])})
            if len(snippets) >= max_snippets:
                break
        return snippets

    def _wiki_score_page(
        self,
        page: dict,
        query_lower: str,
        query_tokens: List[str],
        fuzzy: bool,
    ) -> tuple[int, List[str]]:
        reasons: List[str] = []
        qvec = self._wiki_embed_text(query_lower) if EMBEDDING_FIRST_MODE else None
        title_text = str(page.get("semantic_title_text") or "").strip()
        body_text = str(page.get("semantic_body_text") or "").strip()
        title_vec = self._wiki_embed_text(title_text) if qvec is not None else None
        body_vec = self._wiki_embed_text(body_text) if qvec is not None else None
        if qvec is not None and title_vec is not None:
            try:
                from .intelligence_core import BgeCodeEmbedder
                s_title = float(BgeCodeEmbedder.cosine(qvec, title_vec))
                s_body = float(BgeCodeEmbedder.cosine(qvec, body_vec)) if body_vec is not None else 0.0
                sim = (0.7 * s_title) + (0.3 * s_body)
                if fuzzy and len(query_lower) >= 3 and sim < 0.2:
                    topic_lower = str(page.get("topic_lower") or "")
                    title_lower = str(page.get("title_lower") or "")
                    base_lower = str(page.get("topic_basename") or "")
                    ratio = max(
                        difflib.SequenceMatcher(None, query_lower, topic_lower).ratio(),
                        difflib.SequenceMatcher(None, query_lower, title_lower).ratio(),
                        difflib.SequenceMatcher(None, query_lower, base_lower).ratio(),
                    )
                    if ratio >= 0.7:
                        sim = max(sim, ratio * 0.5)
                        reasons.append("lexical_similarity")
                if s_title > 0.25:
                    reasons.append("embedding_title")
                if s_body > 0.2:
                    reasons.append("embedding_body")
                return int(round(max(0.0, min(1.0, sim)) * 1000.0)), reasons
            except Exception:
                pass

        # Deterministic non-heuristic fallback: token Jaccard similarity.
        page_tokens = page.get("tokens", set())
        q_tokens = set(query_tokens)
        inter = len(page_tokens.intersection(q_tokens)) if isinstance(page_tokens, set) else 0
        union = len(page_tokens.union(q_tokens)) if isinstance(page_tokens, set) else len(q_tokens)
        sim = (float(inter) / float(max(1, union))) if union else 0.0
        if inter > 0:
            reasons.append("token_overlap")
        if sim <= 0.0 and fuzzy and len(query_lower) >= 3:
            topic_lower = str(page.get("topic_lower") or "")
            title_lower = str(page.get("title_lower") or "")
            base_lower = str(page.get("topic_basename") or "")
            ratio = max(
                difflib.SequenceMatcher(None, query_lower, topic_lower).ratio(),
                difflib.SequenceMatcher(None, query_lower, title_lower).ratio(),
                difflib.SequenceMatcher(None, query_lower, base_lower).ratio(),
            )
            if ratio >= 0.7:
                sim = ratio * 0.5
                reasons.append("lexical_similarity")
        return int(round(sim * 1000.0)), reasons

    def _wiki_search_pages(
        self,
        pages: List[dict],
        query: str,
        *,
        max_results: int,
        category_filter: Any = None,
        include_snippets: bool = False,
        context_lines: int = 2,
        fuzzy: bool = True,
    ) -> List[dict]:
        query_lower = query.lower().strip()
        query_tokens = self._wiki_tokenize(query_lower)
        scored: List[dict] = []
        for page in pages:
            if not self._wiki_match_category(page["topic"], category_filter):
                continue
            score, reasons = self._wiki_score_page(
                page, query_lower, query_tokens, fuzzy
            )
            if score <= 0:
                continue
            entry = {
                "topic": page["topic"],
                "title": page["title"],
                "category": page["category"],
                "score": score,
                "matched_on": reasons[:4],
            }
            if include_snippets:
                entry["matches"] = self._wiki_extract_snippets(
                    page["text"], query_lower, query_tokens, context_lines
                )
            scored.append(entry)
        scored.sort(key=lambda x: (-x["score"], x["topic"]))
        return scored[:max_results]

    def _wiki_related_topics(
        self, current_topic: str, pages: List[dict], max_items: int = 6
    ) -> List[str]:
        current = current_topic.lower()
        current_page = None
        for page in pages:
            if page["topic_lower"] == current:
                current_page = page
                break
        if not current_page:
            return []
        related = []
        for page in pages:
            if page["topic_lower"] == current:
                continue
            if page["category"] == current_page["category"]:
                related.append(page["topic"])
        return related[:max_items]

    def _wiki_resolve_topic(
        self, normalized_topic: str, pages: List[dict], strict: bool = False
    ) -> Optional[dict]:
        if not pages:
            return None
        wanted = normalized_topic.lower()
        by_topic = {p["topic_lower"]: p for p in pages}
        exact = by_topic.get(wanted)
        if exact:
            return exact
        if strict:
            return None

        if "/" not in wanted:
            if wanted in TOOLS:
                tool_topic = f"tools/{wanted}"
                if tool_topic in by_topic:
                    return by_topic[tool_topic]
            basename_matches = [p for p in pages if p["topic_basename"] == wanted]
            if len(basename_matches) == 1:
                return basename_matches[0]
            if len(basename_matches) > 1:
                for page in basename_matches:
                    if page["category"] == "tools":
                        return page
            slug = wanted.replace("-", "_").replace(" ", "_")
            if slug != wanted:
                slug_matches = [p for p in pages if p["topic_basename"] == slug]
                if slug_matches:
                    return slug_matches[0]
        return None

    def _handle_wiki(self, args: dict) -> dict:
        args = self._normalize_wiki_args(args)
        action = args.get("action")
        if action not in TOOL_ACTIONS["wiki"]:
            return make_error(
                MCPError.ACTION_NOT_FOUND,
                f"Unsupported wiki action: '{action}'",
                hint=(
                    f"Valid wiki actions: {', '.join(TOOL_ACTIONS['wiki'])}. "
                    "Examples: wiki(action='read', topic='tools/query'), "
                    "wiki(action='search', query='session'), "
                    "wiki(action='read', topic='tools/query', lines='20-60')."
                ),
            )

        wiki_root = self._resolve_wiki_root()
        wiki_index = self._wiki_get_index(wiki_root)
        topics: Dict[str, List[str]] = wiki_index.get("topics", {})
        pages: List[dict] = wiki_index.get("pages", [])

        verbose = bool(args.get("verbose", False))
        default_limit = (
            self.default_wiki_read_limit if action == "read" and not verbose else 0
        )
        q_limit = _bounded_int(
            args.get("limit", default_limit),
            default_limit,
            min_value=0,
            max_value=2000,
        )
        q_offset = _bounded_int(args.get("offset", 0), 0, min_value=0, max_value=200000)
        context_lines = _bounded_int(
            args.get("context_lines", 2), 2, min_value=0, max_value=10
        )
        include_snippets = bool(args.get("include_snippets", False))
        category_filter = args.get("category")
        max_results = _bounded_int(
            args.get("max_results", 20 if verbose else 8),
            20 if verbose else 8,
            min_value=1,
            max_value=MAX_WIKI_RESULTS,
        )
        fuzzy = bool(args.get("fuzzy", True))
        strict_topic = bool(args.get("strict_topic", False))
        include_related = bool(args.get("include_related", True if verbose else False))

        if action == "list_topics":
            if topics:
                counts = {category: len(items) for category, items in topics.items()}
                return {
                    "ok": True,
                    "categories": topics,
                    "counts": counts,
                    "total_pages": sum(counts.values()),
                }
            return {
                "ok": True,
                "categories": {"tools": sorted(TOOLS)},
                "total_pages": len(TOOLS),
                "note": "Wiki markdown files not found; serving generated tool docs.",
            }

        if action == "index":
            if topics:
                summary = {
                    "category_count": len(topics),
                    "total_pages": len(pages),
                    "wiki_root": wiki_root,
                }
                return {"ok": True, "categories": topics, "summary": summary}
            return {
                "ok": True,
                "categories": {"tools": sorted(TOOLS)},
                "summary": {
                    "category_count": 1,
                    "total_pages": len(TOOLS),
                    "wiki_root": None,
                },
            }

        if action in ("search", "semantic_search"):
            query = (args.get("query") or args.get("topic") or "").strip()
            if not query:
                return make_error(MCPError.INVALID_ARGS, "query required")
            if pages:
                if action == "semantic_search":
                    matches = self._wiki_semantic_search_pages(
                        pages,
                        query,
                        max_results=max_results,
                        category_filter=category_filter,
                        include_snippets=include_snippets,
                        context_lines=context_lines,
                    )
                else:
                    matches = self._wiki_search_pages(
                        pages,
                        query,
                        max_results=max_results,
                        category_filter=category_filter,
                        include_snippets=include_snippets,
                        context_lines=context_lines,
                        fuzzy=fuzzy,
                    )
            else:
                matches = []
                for tool_name in TOOLS:
                    text = self._wiki_generated_tool_doc(tool_name) or ""
                    q_lower = query.lower()
                    if q_lower in tool_name.lower() or q_lower in text.lower():
                        matches.append(
                            {
                                "topic": f"tools/{tool_name}",
                                "title": f"{tool_name.upper()} Tool Manual",
                                "category": "tools",
                                "score": 1,
                                "matched_on": ["fallback_tool_doc"],
                            }
                        )
                matches = matches[:max_results]
            response = {
                "ok": True,
                "action": action,
                "query": query,
                "matches": matches,
                "count": len(matches),
            }
            return response

        topic_name, topic_err = self._wiki_normalize_topic(args.get("topic"))
        if topic_err:
            return topic_err

        resolved_page = self._wiki_resolve_topic(
            topic_name or "", pages, strict=strict_topic
        )
        content: Optional[str] = None
        source = "generated"
        resolved_topic = topic_name
        title = None
        category = "tools"
        if resolved_page:
            content = resolved_page["text"]
            source = "markdown"
            resolved_topic = resolved_page["topic"]
            title = resolved_page["title"]
            category = resolved_page["category"]
        else:
            fallback = self._wiki_generated_tool_doc(topic_name or "")
            if fallback is not None:
                content = fallback
                source = "generated"
                normalized_tool = (topic_name or "").split("/")[-1].lower()
                resolved_topic = (
                    f"tools/{normalized_tool}" if normalized_tool else topic_name
                )
                title = (
                    f"{normalized_tool.upper()} Tool Manual"
                    if normalized_tool
                    else "Generated Tool Manual"
                )
                category = "tools"
            else:
                suggestions: List[str] = []
                if pages and topic_name:
                    suggestions = [
                        m["topic"]
                        for m in self._wiki_search_pages(
                            pages,
                            topic_name,
                            max_results=6,
                            category_filter=category_filter,
                            include_snippets=False,
                            fuzzy=True,
                        )
                    ]
                return make_error(
                    MCPError.FILE_NOT_FOUND,
                    f"Wiki topic '{topic_name}' not found",
                    details={
                        "wiki_root": wiki_root or None,
                        "suggestions": suggestions,
                    },
                    hint="Use wiki(action='search', query='...') or set IDA_MCP_WIKI_DIR.",
                )

        lines = content.splitlines(keepends=True)
        headers = self._wiki_parse_headers(lines)
        available_sections = [
            {
                "index": idx + 1,
                "title": h["text"],
                "level": h["level"],
                "line": h["line"],
            }
            for idx, h in enumerate(headers)
        ]

        if action == "sections":
            if not verbose:
                return {
                    "ok": True,
                    "topic": topic_name,
                    "resolved_topic": resolved_topic,
                    "source": source,
                    "title": title,
                    "sections": [h["title"] for h in available_sections],
                    "count": len(available_sections),
                }
            return {
                "ok": True,
                "topic": topic_name,
                "resolved_topic": resolved_topic,
                "source": source,
                "title": title,
                "headers": available_sections,
                "count": len(available_sections),
            }

        section = args.get("section")
        content_lines = lines
        section_filter = None
        section_start_line = 1
        if section:
            target_header = None
            if isinstance(section, int) or (
                isinstance(section, str) and str(section).strip().isdigit()
            ):
                section_idx = int(section) - 1
                if 0 <= section_idx < len(headers):
                    target_header = headers[section_idx]
            else:
                section_lower = str(section).strip().lower()
                for header in headers:
                    if section_lower == header["text"].strip().lower():
                        target_header = header
                        break
                if target_header is None:
                    for header in headers:
                        if section_lower in header["text"].strip().lower():
                            target_header = header
                            break
                if target_header is None and fuzzy and section_lower:
                    best_ratio = 0.0
                    best_header = None
                    for header in headers:
                        ratio = difflib.SequenceMatcher(
                            None, section_lower, header["text"].strip().lower()
                        ).ratio()
                        if ratio > best_ratio:
                            best_ratio = ratio
                            best_header = header
                    if best_ratio >= 0.74:
                        target_header = best_header

            if target_header is None:
                details_payload = (
                    {"available_sections": available_sections[:50]}
                    if verbose
                    else {
                        "available_sections": [
                            s["title"] for s in available_sections[:20]
                        ]
                    }
                )
                return make_error(
                    MCPError.INVALID_ARGS,
                    f"Section '{section}' not found",
                    details=details_payload,
                )

            section_filter = target_header["text"]
            section_start_line = int(target_header["line"])
            start_idx = section_start_line - 1
            end_idx = len(lines)
            for header in headers:
                if header["line"] <= section_start_line:
                    continue
                if header["level"] <= target_header["level"]:
                    end_idx = int(header["line"]) - 1
                    break
            content_lines = lines[start_idx:end_idx]

        line_sel_start, line_sel_end = _parse_line_range(args.get("lines"))
        if args.get("line_start") is not None:
            line_sel_start = _bounded_int(
                args.get("line_start"), 1, min_value=1, max_value=2_000_000
            )
        if args.get("line_end") is not None:
            line_sel_end = _bounded_int(
                args.get("line_end"), 1, min_value=1, max_value=2_000_000
            )
        has_line_window = (line_sel_start is not None) or (line_sel_end is not None)

        total_lines = len(content_lines)
        if has_line_window:
            section_abs_start = section_start_line
            section_abs_end = section_start_line + max(0, total_lines - 1)

            abs_start_req = (
                line_sel_start if line_sel_start is not None else section_abs_start
            )
            abs_end_req = line_sel_end if line_sel_end is not None else section_abs_end
            if abs_end_req < abs_start_req:
                abs_start_req, abs_end_req = abs_end_req, abs_start_req

            abs_start = max(section_abs_start, abs_start_req)
            abs_end = min(section_abs_end, abs_end_req)

            if total_lines <= 0 or abs_end < abs_start:
                slice_lines = []
                absolute_start = section_abs_start
                absolute_end = section_abs_start
            else:
                local_start = abs_start - section_abs_start
                local_end_exclusive = abs_end - section_abs_start + 1
                slice_lines = content_lines[local_start:local_end_exclusive]
                absolute_start = abs_start
                absolute_end = abs_end
        else:
            start = min(q_offset, total_lines)
            end = total_lines if q_limit <= 0 else min(total_lines, start + q_limit)
            slice_lines = content_lines[start:end]
            absolute_start = section_start_line + start
            absolute_end = (
                absolute_start + len(slice_lines) - 1 if slice_lines else absolute_start
            )
        result = {
            "ok": True,
            "topic": topic_name,
            "resolved_topic": resolved_topic,
            "title": title,
            "content": "".join(slice_lines),
            "line_range": f"{absolute_start}-{absolute_end}",
        }
        if verbose:
            result.update(
                {
                    "source": source,
                    "category": category,
                    "total_lines_in_topic": len(lines),
                    "headers": [h["text"] for h in headers[:100]],
                    "available_sections": available_sections[:100],
                }
            )
        if section_filter:
            result["section_filter"] = section_filter
        if include_related and pages and resolved_topic:
            result["related_topics"] = self._wiki_related_topics(resolved_topic, pages)
        if (not has_line_window) and q_limit > 0 and end < total_lines:
            result["_truncated"] = True
            result["next_offset"] = end
            result["lines_remaining"] = total_lines - end
            result["hint"] = (
                "Use wiki(action='read', topic='...', offset=next_offset, limit=...)"
            )
        return result
