"""Provider-only intelligence compatibility facade.

The host no longer discovers, downloads, starts, or falls back to local,
Gemini, or native inference models.  Intelligence questions go through the
explicit provider registry; retrieval remains deterministic/lexical when a
provider is disabled or unavailable.

``BgeCodeEmbedder`` and ``BehaviorClassifier`` remain import-compatible names
for the indexing and session layers.  They deliberately never manufacture
vectors or select a legacy backend.
"""

from __future__ import annotations

import re
from typing import Any

from .embeddings import NOISE_WORDS, FunctionEmbeddingIndex  # noqa: F401
from .helpers import _EmbedResult, cosine_similarity
from .providers import provider_error_payload, provider_status, resolve_provider

# Kept as a runtime feature flag for callers that use the old symbol.  The
# provider architecture intentionally never enables embedding-first ranking.
INTEL_PROFILE = False

_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _identifier_terms(ident: str) -> list[str]:
    terms: list[str] = []
    for chunk in re.split(r"[_\W]+", str(ident or "")):
        if not chunk:
            continue
        terms.extend(part for part in _CAMEL_BOUNDARY_RE.split(chunk) if part)
    return terms or ([ident] if ident else [])


def _extract_signature(pseudocode: str, max_idents: int = 40) -> str:
    """Return a bounded identifier/API signature without retaining code text."""
    seen: set[str] = set()
    output: list[str] = []
    # Do not forward literal contents (which may contain credentials or
    # operator data); signatures use identifiers and API names only.
    text = re.sub(r"(?s)(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')", " ", str(pseudocode or ""))
    for ident in _IDENT_RE.findall(text):
        for term in _identifier_terms(ident):
            value = term.lower()
            if len(value) < 2 or value in NOISE_WORDS or value in seen:
                continue
            seen.add(value)
            output.append(term[:96])
            if len(output) >= max(1, int(max_idents)):
                return " ".join(output)
    return " ".join(output)


def _resolve_backend() -> str:
    """Compatibility helper returning the validated explicit mode."""
    try:
        from .providers.config import resolve_provider_config

        return resolve_provider_config().mode
    except Exception:
        return "invalid"


class BgeCodeEmbedder:
    """Compatibility facade with no local embedding implementation."""

    _instance: "BgeCodeEmbedder | None" = None
    _provider_only = True

    def __init__(self) -> None:
        self._provider = None
        self._config_error: dict[str, Any] | None = None
        try:
            self._provider = resolve_provider(with_ledger=True)
            config = self._provider.config
            self._mode = config.mode
            self.backend = config.provider_id if config.mode != "disabled" else "disabled"
            self._model = config.model
        except Exception as exc:
            self._mode = "invalid"
            self.backend = "invalid"
            self._model = None
            self._config_error = provider_error_payload(exc)
        self._dimension = 0
        self.dim = 0
        self._profile = None
        self.embedding_format = f"provider-only:{self.backend}:{self._model or ''}"

    @classmethod
    def reset(cls) -> "BgeCodeEmbedder":
        cls._instance = None
        return cls()

    @classmethod
    def instance(cls) -> "BgeCodeEmbedder":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def status(self, probe: bool = False, deep_hash: bool = False) -> dict[str, Any]:
        del probe, deep_hash
        if self._config_error:
            return {"backend": "invalid", "ready": False, **self._config_error}
        try:
            current = provider_status()
            if current.get("ok"):
                result = dict(current.get("provider") or {})
                result.setdefault("backend", self.backend)
                result["embedding_supported"] = False
                result["semantic_search"] = "lexical_fallback"
                return result
            return {"backend": self.backend, "ready": False, **current}
        except Exception:
            return {"backend": self.backend, "ready": False}

    def check_availability(self) -> bool:
        status = self.status()
        return bool(status.get("ready") and status.get("embedding_supported"))

    def embed(self, text: str, purpose: str = "document") -> _EmbedResult:
        del text, purpose
        return _EmbedResult(None, self.backend, False)

    def embed_vector(self, text: str, purpose: str = "document") -> None:
        del text, purpose

    def embed_query(self, text: str) -> _EmbedResult:
        return self.embed(text, purpose="query")

    def embed_query_vector(self, text: str) -> None:
        return self.embed_vector(text, purpose="query")

    def embed_documents(self, texts: list[str], purpose: str = "document") -> list[_EmbedResult]:
        del purpose
        # Preserve the old result shape for callers while making the absence of
        # vector capability explicit. Consumers can still persist/search the
        # bounded lexical signature path.
        return [_EmbedResult(None, self.backend, False) for _ in texts]

    def embed_batch(self, texts: list[str], purpose: str = "document") -> list[_EmbedResult]:
        return self.embed_documents(texts, purpose=purpose)

    def stop(self) -> None:
        """Compatibility no-op; no child process is owned by this facade."""

    @staticmethod
    def cosine(a: list[float], b: list[float]) -> float:
        return cosine_similarity(a, b)

    @staticmethod
    def _cosine(a: list[float], b: list[float]) -> float:
        return cosine_similarity(a, b)


class BehaviorClassifier:
    """Provider-backed advisory classifier; never performs local inference."""

    # Stable behavior labels are retained as application metadata for
    # compatibility and typed-question criteria. They are not local model
    # prompts or a fallback classifier; provider-backed decisions are made by
    # ``advisory.ask_behavior``.
    ANCHORS: dict[str, str] = {
        "crypto_symmetric": "state = input; round = key_schedule(key); state = cipher_rounds(state); output = state;",
        "crypto_hash": "ctx = hash_init(); compress(ctx, block); digest = finalize(ctx);",
        "network_http": "socket = connect(host, port); request = format_http(path); send(socket, request); response = recv(socket);",
        "network_raw": "socket = open(); connect(socket, peer); send(socket, buffer); receive(socket, buffer);",
        "process_injection": "process = open_process(pid); remote = allocate_remote(process); write_remote(process, remote, payload); create_remote_thread(process, remote);",
        "file_operations": "file = open(path); data = read(file); write(file, data); close(file);",
        "anti_debug": "debugger = detect_debugger(); ticks = read_timer(); if (debugger) return;",
        "anti_vm": "vendor = query_hypervisor(); if (vendor) virtual_machine = true;",
        "persistence": "key = open_startup_key(); set_value(key, path); start_service(service);",
        "evasion": "payload = decode(blob, key); sleep(delay); protect(code); execute(payload);",
        "string_decrypt": "plain = decrypt(ciphertext, key); if (printable(plain)) cache(plain);",
        "c2_communication": "beacon = build_message(host_id); send_http(endpoint, beacon); command = parse(response);",
        "privilege_escalation": "token = open_token(process); adjust_privileges(token); spawn_elevated(command);",
        "memory_manipulation": "memory = allocate(size); copy(memory, source); protect(memory, executable); call(memory);",
        "rop_gadget": "for (address = text_start; address < text_end; address++) collect_ret_gadget(address); chain = build_chain(gadgets);",
        "heap_spray": "for (index = 0; index < count; index++) heap[index] = allocate(chunk); trigger_corruption(heap);",
        "use_after_free": "object = allocate(size); free(object); dispatch(object);",
        "buffer_overflow": "buffer = local_array(); length = read(input); copy(buffer, input, length);",
        "format_string_vuln": "format = receive(user); printf(format);",
        "race_condition": "if (shared_flag) update(shared_state); worker_one(); worker_two();",
        "integer_overflow": "count = read_count(); size = count * element_size; buffer = allocate(size);",
        "path_traversal": "path = join(root, user_name); if (contains_parent(path)) reject(path);",
    }
    ANCHOR_MIN_CONFIDENCE: dict[str, float] = {}
    ANCHOR_CACHE_VERSION = 0
    _shared: "BehaviorClassifier | None" = None

    def __init__(self, embedder: BgeCodeEmbedder | None = None, provider=None) -> None:
        self._embedder = embedder or BgeCodeEmbedder()
        self._provider = provider
        self._provider_explicit = provider is not None
        self._anchor_embs: dict[str, list[float]] = {}

    @classmethod
    def instance(cls, embedder: BgeCodeEmbedder | None = None) -> "BehaviorClassifier":
        if cls._shared is None or (embedder is not None and cls._shared._embedder is not embedder):
            cls._shared = cls(embedder)
        return cls._shared

    def clear_cache(self) -> None:
        self._anchor_embs.clear()

    def refresh_anchors(self, behaviors: list[str] | None = None) -> None:
        del behaviors
        self._anchor_embs.clear()

    def classify_vec(self, query_vec: list[float], **kwargs: Any) -> list[dict[str, Any]]:
        # Typed-question providers do not expose vectors. Keep this explicit
        # empty result rather than inventing a local embedding fallback.
        del query_vec, kwargs
        return []

    @staticmethod
    def _anchor_explain(anchor_text: str, query_text: str) -> list[str]:
        phrases = [phrase.strip() for phrase in str(anchor_text or "").split(";") if phrase.strip()]
        query_tokens = set(re.findall(r"[A-Za-z0-9_]+", str(query_text or "").lower()))
        scored = []
        for phrase in phrases:
            phrase_tokens = set(re.findall(r"[A-Za-z0-9_]+", phrase.lower()))
            scored.append((len(query_tokens.intersection(phrase_tokens)), phrase))
        scored.sort(key=lambda item: item[0], reverse=True)
        return [phrase for overlap, phrase in scored if overlap > 0][:3]

    @staticmethod
    def _text_tokens(text: str) -> set[str]:
        out: set[str] = set()
        raw_text = str(text or "")
        for raw in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", raw_text):
            low = raw.lower()
            if low and low not in NOISE_WORDS:
                out.add(low)
        for raw in _IDENT_RE.findall(raw_text):
            for term in _identifier_terms(raw):
                low = term.lower()
                if low and low not in NOISE_WORDS:
                    out.add(low)
        out.update(item.lower() for item in re.findall(r"%[0-9.]*[a-zA-Z]|\.\.|0x[0-9a-fA-F]+", raw_text))
        return out

    def classify(
        self,
        text: str,
        threshold: float = 0.25,
        max_tokens: int = 3000,
        top_k: int = 4,
        block: bool = False,
        session_id: str = "",
    ) -> list[dict[str, Any]]:
        del block
        if not str(text or "").strip():
            return []
        try:
            from .advisory import ask_behavior

            result = ask_behavior(
                {"signature": _extract_signature(str(text)[:max_tokens])[:2048]},
                # Resolve the process's explicit provider at request time so
                # a long-lived compatibility facade cannot retain a disabled
                # or invalid mode after an operator rotates configuration.
                provider=self._provider if self._provider_explicit else None,
                session_id=session_id,
                operation="classify_text",
            )
            if not isinstance(result, list):
                return []
            return [
                row
                for row in result[: max(1, int(top_k))]
                if float(row.get("confidence", 0.0) or 0.0) >= float(threshold or 0.0)
            ]
        except Exception:
            return []


__all__ = [
    "BgeCodeEmbedder",
    "BehaviorClassifier",
    "FunctionEmbeddingIndex",
    "INTEL_PROFILE",
    "_extract_signature",
    "_resolve_backend",
]
