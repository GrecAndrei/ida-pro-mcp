"""Semantic blackboard retrieval mixin for ContextAssembler."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Tuple

from .intelligence_core import BgeCodeEmbedder


class ContextAssemblerSemanticMixin:
    def _cached_bb_entry_vec(self, entry: Dict[str, Any]) -> Optional[List[float]]:
        """Get or compute cached embedding vector for a blackboard entry."""
        text = f"{entry.get('title', '')} {entry.get('content', '')}".strip()
        if not text:
            return None
        entry_id = str(entry.get("id") or "")
        updated = str(entry.get("updated_at") or "")
        cache_key = f"{entry_id}:{updated}:{hashlib.md5(text[:800].encode()).hexdigest()}"
        now = time.time()
        with self._bb_entry_vec_cache_lock:
            cached = self._bb_entry_vec_cache.get(cache_key)
            if cached is not None:
                vec, ts = cached
                if now - ts <= self._bb_entry_cache_ttl_sec:
                    with self._bb_cache_stats_lock:
                        self._bb_cache_hits += 1
                    return vec
                self._bb_entry_vec_cache.pop(cache_key, None)
        with self._bb_cache_stats_lock:
            self._bb_cache_misses += 1
        vec = self._embedder.embed(text[:400])
        with self._bb_entry_vec_cache_lock:
            if len(self._bb_entry_vec_cache) >= self._bb_entry_cache_max:
                stale_keys = [
                    k for k, (_, ts) in self._bb_entry_vec_cache.items()
                    if now - ts > self._bb_entry_cache_ttl_sec
                ]
                for k in stale_keys:
                    self._bb_entry_vec_cache.pop(k, None)
                if len(self._bb_entry_vec_cache) >= self._bb_entry_cache_max:
                    oldest = sorted(self._bb_entry_vec_cache.items(), key=lambda kv: kv[1][1])
                    drop_n = max(1, self._bb_entry_cache_max // 4)
                    for k, _ in oldest[:drop_n]:
                        self._bb_entry_vec_cache.pop(k, None)
            self._bb_entry_vec_cache[cache_key] = (vec, now)
        return vec

    def _cached_bb_entry_vecs(self, entries: List[Dict[str, Any]]) -> Dict[str, List[float]]:
        """Vectorize many blackboard entries with cache-first micro-batching."""
        out: Dict[str, List[float]] = {}
        misses: List[Tuple[str, str, str]] = []
        now = time.time()
        with self._bb_entry_vec_cache_lock:
            for entry in entries:
                text = f"{entry.get('title', '')} {entry.get('content', '')}".strip()
                if not text:
                    continue
                entry_id = str(entry.get("id") or "")
                updated = str(entry.get("updated_at") or "")
                cache_key = f"{entry_id}:{updated}:{hashlib.md5(text[:800].encode()).hexdigest()}"
                cached = self._bb_entry_vec_cache.get(cache_key)
                if cached is not None and (now - cached[1] <= self._bb_entry_cache_ttl_sec):
                    out[entry_id or cache_key] = cached[0]
                    with self._bb_cache_stats_lock:
                        self._bb_cache_hits += 1
                else:
                    misses.append((cache_key, text[:400], entry_id or cache_key))
                    with self._bb_cache_stats_lock:
                        self._bb_cache_misses += 1
        if misses:
            texts = [m[1] for m in misses]
            vecs = self._embedder.embed_batch(texts)
            with self._bb_entry_vec_cache_lock:
                for (cache_key, _text, entry_id), vec in zip(misses, vecs):
                    if len(self._bb_entry_vec_cache) >= self._bb_entry_cache_max:
                        oldest = sorted(self._bb_entry_vec_cache.items(), key=lambda kv: kv[1][1])
                        for k, _ in oldest[: max(1, self._bb_entry_cache_max // 5)]:
                            self._bb_entry_vec_cache.pop(k, None)
                    self._bb_entry_vec_cache[cache_key] = (vec, now)
                    out[entry_id] = vec
        return out

    def _semantic_candidates(
        self,
        all_entries: List[Dict[str, Any]],
        api_calls: Optional[List[str]],
        max_entries: int,
    ) -> List[Dict[str, Any]]:
        """Embedding-first candidate prefilter before semantic scoring."""
        if not all_entries:
            return []
        api_calls = api_calls or []
        q_text = " ".join(sorted(set(api_calls))).strip() or "binary reverse engineering related finding"
        query_vec: Optional[List[float]] = None
        try:
            query_vec = self._embedder.embed(q_text[:400])
        except Exception:
            query_vec = None

        scored: List[Tuple[float, Dict[str, Any]]] = []
        if query_vec is not None:
            texts: List[str] = []
            refs: List[Dict[str, Any]] = []
            for entry in all_entries:
                txt = f"{entry.get('title', '')} {entry.get('content', '')} {' '.join(entry.get('tags') or [])}".strip()
                if not txt:
                    continue
                texts.append(txt[:400])
                refs.append(entry)
            if texts:
                try:
                    vecs = self._embedder.embed_batch(texts)
                    for entry, emb_vec in zip(refs, vecs):
                        sim = BgeCodeEmbedder.cosine(query_vec, emb_vec)
                        scored.append((float(sim), entry))
                except Exception:
                    scored = []

        if not scored:
            out = [e for e in all_entries if (e.get("title") or e.get("content"))]
            out.sort(key=lambda e: float(e.get("updated_at") or 0.0), reverse=True)
            return out[:max_entries]

        embed_ranked = [e for _, e in sorted(scored, key=lambda x: x[0], reverse=True)]
        seen = {str(e.get("id") or id(e)) for e in embed_ranked}
        conf_fill = sorted(
            [e for e in all_entries if str(e.get("id") or id(e)) not in seen],
            key=lambda e: float(e.get("confidence") or 0.0),
            reverse=True,
        )
        head_take = max(1, max_entries - 1) if conf_fill else max_entries
        merged = embed_ranked[:head_take] + conf_fill + embed_ranked[head_take:]
        dedup: List[Dict[str, Any]] = []
        dedup_seen: set = set()
        for entry in merged:
            key = str(entry.get("id") or id(entry))
            if key in dedup_seen:
                continue
            dedup_seen.add(key)
            dedup.append(entry)
            if len(dedup) >= max_entries:
                break
        return dedup[:max_entries]

    def _get_bb_semantic_vec(
        self,
        query_vec: List[float],
        bb_store,
        top_k: int = 3,
        threshold: float = 0.5,
        max_entries: int = 20,
        api_calls: Optional[List[str]] = None,
        session_id: str = "",
    ) -> List[Dict[str, Any]]:
        """Semantic blackboard retrieval using a pre-computed query vector."""
        if bb_store is None:
            return []
        try:
            cache_key = ""
            if session_id:
                qh = hashlib.md5(json.dumps(query_vec[:32]).encode()).hexdigest()[:12]
                ah = hashlib.md5("|".join(sorted(api_calls or [])).encode()).hexdigest()[:8]
                cache_key = f"{session_id}:{qh}:{ah}:{threshold:.3f}:{max_entries}:{top_k}"
                with self._semantic_result_cache_lock:
                    cached = self._semantic_result_cache.get(cache_key)
                    if cached and (time.time() - cached[0] <= self._semantic_result_cache_ttl_sec):
                        return list(cached[1])

            all_entries = bb_store.list(limit=max(max_entries * 3, 30))
            if not all_entries:
                return []
            candidates = self._semantic_candidates(all_entries, api_calls, max_entries=max_entries)
            scored = []
            vecs = self._cached_bb_entry_vecs(candidates)
            for entry in candidates:
                entry_id = str(entry.get("id") or "")
                emb = vecs.get(entry_id)
                if emb is None:
                    continue
                sim = BgeCodeEmbedder.cosine(query_vec, emb)
                if sim >= threshold:
                    scored.append((sim, entry))
            scored.sort(reverse=True)
            out = [e for _, e in scored[:top_k]]
            if cache_key:
                with self._semantic_result_cache_lock:
                    if len(self._semantic_result_cache) > 300:
                        self._semantic_result_cache.clear()
                    self._semantic_result_cache[cache_key] = (time.time(), out)
            return out
        except Exception:
            return []

    def _get_bb_semantic(
        self,
        pseudocode: str,
        bb_store,
        top_k: int = 3,
        threshold: float = 0.5,
    ) -> List[Dict[str, Any]]:
        """Find semantically relevant blackboard entries using embedding similarity."""
        if bb_store is None or not pseudocode:
            return []
        try:
            all_entries = bb_store.list(limit=100)
            if not all_entries:
                return []
            query_vec = self._embedder.embed(pseudocode[:2000])
            scored = []
            for entry in all_entries:
                text = f"{entry.get('title', '')} {entry.get('content', '')}"
                if not text.strip():
                    continue
                emb = self._embedder.embed(text[:500])
                sim = BgeCodeEmbedder.cosine(query_vec, emb)
                if sim >= threshold:
                    scored.append((sim, entry))
            scored.sort(reverse=True)
            return [e for _, e in scored[:top_k]]
        except Exception:
            return []
