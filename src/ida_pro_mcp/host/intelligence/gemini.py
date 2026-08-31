"""Opt-in cloud embedding backend for Google Gemini embedding models.

Selected only when the user (or installer) explicitly requests it — via
``IDA_MCP_EMBED_BACKEND=gemini`` or ``embedder.json`` ``{"backend": "gemini"}``.
It is never chosen automatically, and it is network-facing: the *compact
behavioral signature* of a function is uploaded to Google, not the full
decompilation. Users who cannot send code to a third party should keep the
local llama-server backend (``intelligence/core.py``).

Auth sources (all environment variables; no secrets are written to disk by
the installer's ``embedder.json``):

  Google AI Studio (API key):
    GEMINI_API_KEY  /  GOOGLE_API_KEY

  Vertex AI — already-obtained access token:
    VERTEX_AI_ACCESS_TOKEN  /  GOOGLE_ACCESS_TOKEN

  Vertex AI — Application Default Credentials (service-account JSON):
    GOOGLE_APPLICATION_CREDENTIALS          (+ optional ``google-auth`` package)
    GOOGLE_CLOUD_PROJECT  /  VERTEX_AI_PROJECT
    VERTEX_AI_LOCATION   /  GOOGLE_CLOUD_REGION   (default ``us-central1``)

Request/response shapes follow the Gemini API (see
https://ai.google.dev/gemini-api/docs/embeddings):
  AI Studio single   :embedContent  ``{"model", "content", "embedContentConfig"}``
                       -> ``{"embedding": {"values": [...]}}``
  AI Studio batch    :batchEmbedContents ``{"requests": [...]}``
                       -> ``{"embeddings": [{"values": [...]}]}``
  Vertex predict     ``{"instances": [...], "parameters": {...}}``
                       -> ``{"predictions": [{"embeddings": {"values": [...]}}]}``
"""

from __future__ import annotations

import copy
import logging
import math
import os
import threading
import time
from typing import Any

import requests

from .helpers import _EmbedResult, cosine_similarity as _cosine, decomp_document_char_budget

logger = logging.getLogger(__name__)

GEMINI_DEFAULT_MODEL = "gemini-embedding-2"
GEMINI_MIN_DIM = 128
GEMINI_MAX_DIM = 3072
GEMINI_DEFAULT_DIM = 768
GEMINI_MAX_INPUT_TOKENS = 8192
GEMINI_BATCH_LIMIT = 100  # documented per-call cap for batchEmbedContents

_AI_STUDIO_EMBED = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:embedContent"
)
_AI_STUDIO_BATCH = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:batchEmbedContents"
)
_VERTEX_PREDICT = (
    "https://{location}-aiplatform.googleapis.com/v1/projects/{project}"
    "/locations/{location}/publishers/google/models/{model}:predict"
)
_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

_TASKS = {
    "retrieval_document": "RETRIEVAL_DOCUMENT",
    "retrieval_query": "RETRIEVAL_QUERY",
    "semantic_similarity": "SEMANTIC_SIMILARITY",
    "classification": "CLASSIFICATION",
    "clustering": "CLUSTERING",
    "question_answering": "QUESTION_ANSWERING",
    "fact_verification": "FACT_VERIFICATION",
    "code_retrieval_query": "CODE_RETRIEVAL_QUERY",
}
_TASK_BY_PURPOSE = {"query": "RETRIEVAL_QUERY", "document": "RETRIEVAL_DOCUMENT"}


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return int(default)


def _float_env(name: str, default: float) -> float:
    try:
        value = float(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return float(default)
    return value if math.isfinite(value) else float(default)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name, "").strip().lower()
    if not value:
        return bool(default)
    return value in ("1", "true", "yes", "on")


class _GeminiHTTPError(Exception):
    def __init__(self, status: int, body: str, retryable: bool = False):
        super().__init__(f"gemini HTTP {status}: {body[:400]}")
        self.status = status
        self.body = body
        self.retryable = retryable


class GeminiEmbedBackend:
    """Cloud embedding backend for ``gemini-embedding-2`` (or ``gemini-embedding-001``).

    Duck-type compatible with
    :class:`~ida_pro_mcp.host.intelligence.core.BgeCodeEmbedder` so the
    function index, context assembler, semantic server, and behavior
    classifier can use it unchanged.
    """

    def __init__(self, state: dict | None = None):
        state = dict(state or {})
        self._model = str(
            os.environ.get("IDA_MCP_GEMINI_MODEL")
            or state.get("gemini_model")
            or GEMINI_DEFAULT_MODEL
        )
        try:
            dim = int(
                os.environ.get("IDA_MCP_GEMINI_DIM")
                or state.get("gemini_dimension")
                or GEMINI_DEFAULT_DIM
            )
        except (TypeError, ValueError):
            dim = GEMINI_DEFAULT_DIM
        self._dim = max(GEMINI_MIN_DIM, min(GEMINI_MAX_DIM, dim))
        self._task_type_env = str(
            os.environ.get("IDA_MCP_GEMINI_TASK_TYPE")
            or state.get("gemini_task_type")
            or ""
        ).strip().lower()
        self._retries = max(0, _int_env("IDA_MCP_GEMINI_RETRIES", 2))
        self._timeout = max(1.0, _float_env("IDA_MCP_GEMINI_TIMEOUT", 30.0))
        self._batch_timeout = max(1.0, _float_env("IDA_MCP_GEMINI_BATCH_TIMEOUT", 120.0))
        self._max_batch_size = max(
            1, min(GEMINI_BATCH_LIMIT, _int_env("IDA_MCP_GEMINI_MAX_BATCH", GEMINI_BATCH_LIMIT))
        )
        self._batch_size = max(
            1, min(self._max_batch_size, _int_env("IDA_MCP_GEMINI_BATCH", 16))
        )
        self._batch_lock = threading.Lock()
        self._mode = "unset"
        self._api_key = ""
        self._env_token = ""
        # Vertex ADC token cache: the resolved token plus its expiry so
        # _auth_headers does not re-run google.auth.default + a network
        # refresh on every embedding request.
        self._adc_token_cache = ""
        self._adc_expiry = 0.0
        self._state_vertex_project = str(state.get("gemini_vertex_project") or "")
        self._state_vertex_location = str(state.get("gemini_vertex_location") or "")
        self._project = ""
        self._location = "us-central1"
        self._endpoint = ""
        self._ready = False
        self._error = ""
        self._configure()

    # ── configuration ─────────────────────────────────────────────────────

    def _configure(self) -> None:
        key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""
        access_token = (
            os.environ.get("VERTEX_AI_ACCESS_TOKEN")
            or os.environ.get("GOOGLE_ACCESS_TOKEN")
            or ""
        )
        # Vertex is chosen only when the user opts in explicitly: an
        # IDA_MCP_GEMINI_VERTEX flag, an access token, or the installer's
        # gemini_vertex_project.  A bare ambient GOOGLE_CLOUD_PROJECT in the
        # environment must NOT flip an AI-Studio key into Vertex mode.
        want_vertex = (
            _env_bool("IDA_MCP_GEMINI_VERTEX")
            or bool(access_token)
            or bool(self._state_vertex_project)
        )
        self._project = (
            os.environ.get("GOOGLE_CLOUD_PROJECT")
            or os.environ.get("GOOGLE_CLOUD_PROJECT_ID")
            or os.environ.get("VERTEX_AI_PROJECT")
            or self._state_vertex_project
            or ""
        )
        self._location = (
            os.environ.get("VERTEX_AI_LOCATION")
            or os.environ.get("GOOGLE_CLOUD_REGION")
            or self._state_vertex_location
            or "us-central1"
        )

        if want_vertex:
            self._mode = "vertex"
            self._api_key = ""
            self._endpoint = _VERTEX_PREDICT.format(
                location=self._location,
                project=self._project or "PROJECT",
                model=self._model,
            )
            if not self._project:
                self._ready = False
                self._error = (
                    "Vertex AI needs a project: set GOOGLE_CLOUD_PROJECT or VERTEX_AI_PROJECT"
                )
                return
            if access_token:
                self._env_token = access_token
                self._ready = True
                self._error = ""
                return
            self._env_token = ""
            token, err = self._adc_token()
            self._adc_token_cache = token
            if token:
                self._ready = True
                self._error = ""
            else:
                self._ready = False
                self._error = err
            return

        if key:
            self._mode = "aistudio"
            self._api_key = key
            self._env_token = ""
            self._endpoint = _AI_STUDIO_EMBED.format(model=self._model)
            self._ready = True
            self._error = ""
            return

        self._mode = "unset"
        self._api_key = ""
        self._env_token = ""
        self._endpoint = ""
        self._ready = False
        self._error = (
            "no Gemini credentials: set GEMINI_API_KEY (AI Studio) or "
            "VERTEX_AI_ACCESS_TOKEN / GOOGLE_APPLICATION_CREDENTIALS (Vertex)"
        )

    def _adc_token(self) -> tuple[str, str]:
        """Resolve a Vertex AI access token from Application Default Credentials."""
        try:
            import google.auth
            import google.auth.transport.requests
        except ImportError:
            return "", (
                "google-auth is not installed (needed for Vertex ADC); "
                "set VERTEX_AI_ACCESS_TOKEN or run 'pip install google-auth'"
            )
        try:
            creds, _proj = google.auth.default(scopes=[_CLOUD_PLATFORM_SCOPE])
        except Exception:
            try:
                creds, _proj = google.auth.default()
            except Exception as exc:  # noqa: BLE001 - report any ADC failure
                return "", f"ADC unavailable: {exc}"
        try:
            request = google.auth.transport.requests.Request()
            creds.refresh(request)
            # Some credential sources (e.g. some metadata flows) report no
            # expiry; fall back to a short default TTL so we still refresh
            # rather than pin a possibly-revoked token forever.
            self._adc_expiry = (
                creds.expiry.timestamp()
                if getattr(creds, "expiry", None) is not None
                else time.time() + 300.0
            )
            return creds.token, ""
        except Exception as exc:  # noqa: BLE001
            return "", f"ADC token refresh failed: {exc}"

    def _auth_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._mode == "aistudio":
            if self._api_key:
                headers["x-goog-api-key"] = self._api_key
        elif self._mode == "vertex":
            token = self._env_token or self._adc_token_cached()
            if token:
                headers["Authorization"] = f"Bearer {token}"
        return headers

    def _adc_token_cached(self) -> str:
        """Return a cached ADC token, refreshing only when it nears expiry.

        Resolving ADC runs ``google.auth.default`` plus a full network
        refresh; without caching, an embedding batch chunked at 16 would pay
        one refresh per request.
        """
        now = time.time()
        if self._adc_token_cache and self._adc_expiry > now + 60.0:
            return self._adc_token_cache
        token, err = self._adc_token()
        if token:
            self._adc_token_cache = token
            self._error = ""
        else:
            self._adc_token_cache = ""
            self._adc_expiry = 0.0
            self._error = err
        return self._adc_token_cache

    # ── HTTP ──────────────────────────────────────────────────────────────

    def _request(self, url: str, headers: dict, body: dict, timeout: float) -> dict:
        response = requests.post(url, headers=headers, json=body, timeout=timeout)
        if response.status_code >= 400:
            retryable = response.status_code == 429 or response.status_code >= 500
            raise _GeminiHTTPError(response.status_code, response.text, retryable=retryable)
        try:
            data = response.json()
        except ValueError as exc:
            raise _GeminiHTTPError(0, "non-JSON response from Gemini API") from exc
        if not isinstance(data, dict):
            raise _GeminiHTTPError(0, f"unexpected Gemini response type: {type(data).__name__}")
        return data

    def _post_retry(
        self,
        url: str,
        headers: dict,
        body: dict,
        timeout: float,
        *,
        task_in: str | None = None,
    ) -> dict:
        """POST with bounded retry and a one-shot task_type degradation.

        Some gemini-embedding-2 revisions reject ``taskType``. When the API
        answers 400 mentioning ``task_type``, rebuild the body without the
        task field and retry once (keeping ``outputDimensionality``).
        """
        attempts = max(1, self._retries + 1)
        for attempt in range(attempts):
            try:
                return self._request(url, headers, body, timeout)
            except _GeminiHTTPError as exc:
                task_present = self._task_present(body, task_in)
                if exc.status == 400 and task_present and "task_type" in (exc.body or "").lower():
                    body = self._drop_task(body, task_in)
                    continue
                if exc.retryable and attempt + 1 < attempts:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                raise
            except (requests.ConnectionError, requests.Timeout):
                if attempt + 1 < attempts:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                raise
        raise _GeminiHTTPError(0, "unreachable retry loop")  # pragma: no cover

    @staticmethod
    def _task_present(body: dict, task_in: str | None) -> bool:
        if task_in == "instances":
            return any("task_type" in inst for inst in body.get("instances", []))
        if task_in == "requests":
            # AI Studio batchEmbedContents nests taskType inside each
            # request's embedContentConfig.
            return any(
                isinstance(req, dict)
                and isinstance(req.get("embedContentConfig"), dict)
                and "taskType" in req["embedContentConfig"]
                for req in body.get("requests", [])
            )
        cfg = body.get("embedContentConfig")
        return isinstance(cfg, dict) and "taskType" in cfg

    @staticmethod
    def _drop_task(body: dict, task_in: str | None) -> dict:
        out = copy.deepcopy(body)
        if task_in == "instances":
            for inst in out.get("instances", []):
                inst.pop("task_type", None)
            return out
        if task_in == "requests":
            for req in out.get("requests", []):
                if isinstance(req, dict) and isinstance(req.get("embedContentConfig"), dict):
                    req["embedContentConfig"].pop("taskType", None)
            return out
        cfg = out.get("embedContentConfig")
        if isinstance(cfg, dict):
            cfg.pop("taskType", None)
            out["embedContentConfig"] = cfg
        return out

    # ── embedding ─────────────────────────────────────────────────────────

    def _task(self, purpose: str | None) -> str | None:
        mode = self._task_type_env
        if mode in ("none", "off", "0", "false", "no"):
            return None
        if mode:
            return _TASKS.get(mode, mode.upper())
        return _TASK_BY_PURPOSE.get(str(purpose or "document"))

    def _config_block(self, task: str | None) -> dict:
        cfg: dict[str, Any] = {"outputDimensionality": self._dim}
        if task:
            cfg["taskType"] = task
        return cfg

    def _embed_request(
        self, texts: list[str], purpose: str = "document"
    ) -> list[list[float]] | None:
        if not texts or not self._ready:
            return None
        headers = self._auth_headers()
        task = self._task(purpose)
        timeout = self._batch_timeout if len(texts) > 1 else self._timeout

        if self._mode == "aistudio":
            if len(texts) == 1:
                body: dict[str, Any] = {
                    "model": f"models/{self._model}",
                    "content": {"parts": [{"text": texts[0]}]},
                    "embedContentConfig": self._config_block(task),
                }
                data = self._post_retry(self._endpoint, headers, body, timeout)
                embedding = (data.get("embedding") or {})
                vec = self._normalize_vec(embedding.get("values"))
                return [vec] if vec is not None else None
            requests_payload: list[dict[str, Any]] = []
            for text in texts:
                requests_payload.append(
                    {
                        "model": f"models/{self._model}",
                        "content": {"parts": [{"text": text}]},
                        "embedContentConfig": self._config_block(task),
                    }
                )
            data = self._post_retry(
                _AI_STUDIO_BATCH.format(model=self._model),
                headers,
                {"requests": requests_payload},
                timeout,
                task_in="requests",
            )
            return self._extract_list(data.get("embeddings"), len(texts))

        # Vertex AI predict
        instances: list[dict[str, Any]] = []
        for text in texts:
            inst: dict[str, Any] = {"content": text}
            if task:
                inst["task_type"] = task
            instances.append(inst)
        body = {
            "instances": instances,
            "parameters": {"outputDimensionality": self._dim},
        }
        data = self._post_retry(
            self._endpoint, headers, body, timeout, task_in="instances"
        )
        return self._extract_list(data.get("predictions"), len(texts), vertex=True)

    def _normalize_vec(self, values: Any) -> list[float] | None:
        if not isinstance(values, list) or not values:
            return None
        try:
            vec = [float(x) for x in values]
        except (TypeError, ValueError):
            return None
        if self._dim and len(vec) != self._dim:
            return None
        vec = [x for x in vec if math.isfinite(x)]
        if self._dim and len(vec) != self._dim:
            return None
        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        return [x / norm for x in vec]

    def _extract_list(
        self, items: Any, expected: int, *, vertex: bool = False
    ) -> list[list[float]] | None:
        if not isinstance(items, list) or len(items) != expected:
            return None
        out: list[list[float]] = []
        for item in items:
            if vertex:
                if isinstance(item, dict):
                    embs = item.get("embeddings")
                    vec = self._normalize_vec(embs.get("values") if isinstance(embs, dict) else None)
                elif isinstance(item, list):
                    vec = self._normalize_vec(item)
                else:
                    vec = None
            else:
                vec = self._normalize_vec(item.get("values") if isinstance(item, dict) else None)
            if vec is None:
                return None
            out.append(vec)
        return out

    def embed(self, text: str, purpose: str = "document") -> _EmbedResult:
        try:
            vecs = self._embed_request([str(text or "")], purpose=purpose)
            if vecs:
                return _EmbedResult(vecs[0], self.backend, True)
            return _EmbedResult(None, "unavailable", False)
        except Exception as exc:  # noqa: BLE001 - never raise to callers
            logger.warning("gemini embed failed: %s", exc)
            return _EmbedResult(None, "unavailable", False)

    def embed_vector(self, text: str, purpose: str = "document") -> list[float] | None:
        result = self.embed(text, purpose=purpose)
        return result.vector if result.ok else None

    def embed_query(self, text: str) -> _EmbedResult:
        return self.embed(text, purpose="query")

    def embed_query_vector(self, text: str) -> list[float] | None:
        return self.embed_vector(text, purpose="query")

    def embed_document(self, text: str) -> _EmbedResult:
        return self.embed(text, purpose="document")

    def embed_documents(self, texts: list[str]) -> list[_EmbedResult]:
        return self.embed_batch(texts, purpose="document")

    def embed_batch(self, texts: list[str], purpose: str = "document") -> list[_EmbedResult]:
        if not texts:
            return []
        with self._batch_lock:
            batch_size = self._batch_size
        out: list[_EmbedResult] = []
        i = 0
        while i < len(texts):
            chunk = list(texts[i : i + batch_size])
            try:
                vecs = self._embed_request(chunk, purpose=purpose)
            except Exception as exc:  # noqa: BLE001
                logger.warning("gemini batch embed failed: %s", exc)
                vecs = None
            if vecs is None:
                out.extend(_EmbedResult(None, "unavailable", False) for _ in chunk)
            else:
                out.extend(_EmbedResult(v, self.backend, True) for v in vecs)
            i += len(chunk)
        return out

    # ── lifecycle ─────────────────────────────────────────────────────────

    def ensure_ready(self) -> bool:
        if not self._ready:
            self._configure()
        return bool(self._ready)

    def stop(self) -> None:
        """No subprocess to terminate — just disarm until re-armed."""
        self._ready = False

    def _probe(self) -> tuple[bool, str]:
        try:
            vecs = self._embed_request(["ping"], purpose="query")
            if vecs:
                return True, ""
            return False, self._error or "embedding probe returned no vector"
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    # ── introspection ─────────────────────────────────────────────────────

    def status(self, probe: bool = False, deep_hash: bool = False) -> dict:  # noqa: ARG002
        ready = bool(self._ready)
        probe_error = ""
        if probe and ready:
            ready, probe_error = self._probe()
        empty_fp = {
            "path": "", "exists": False, "size": 0, "mtime_ns": 0, "sha256_head_16mb": "",
        }
        return {
            "backend": self.backend,
            "use_llama": False,
            "disabled_by_env": bool(_env_bool("IDA_MCP_EMBED_DISABLED", False)),
            "server_bin": "",
            "server_bin_exists": False,
            "model_path": "",
            "model_exists": False,
            "ready": bool(ready),
            "port": None,
            "owns_process": False,
            "dim": self.dim,
            "profile": "gemini",
            "profile_name": self._model,
            "model_license": "google-cloud-tos",
            "query_document_prompts": bool(self._task_type_env != "none"),
            "batch_size": int(self._batch_size),
            "max_batch_size": int(self._max_batch_size),
            "max_input_chars": self.max_input_chars,
            "decomp_document_chars": self.decomp_document_chars,
            "consecutive_rpc_failures": 0,
            "last_recycle_reason": "",
            "fingerprints": {"model": dict(empty_fp), "server": dict(empty_fp)},
            "probe_error": probe_error,
            "error": self._error,
            "auth": self._mode,
            "model": self._model,
            "endpoint": self._endpoint,
            "project": self._project if self._mode == "vertex" else "",
            "location": self._location if self._mode == "vertex" else "",
        }

    @property
    def backend(self) -> str:
        return "gemini"

    @property
    def ready(self) -> bool:
        return bool(self._ready)

    @property
    def batch_size(self) -> int:
        return int(self._batch_size)

    @property
    def max_batch_size(self) -> int:
        return int(self._max_batch_size)

    @property
    def dim(self) -> int:
        return int(self._dim)

    @property
    def embedding_format(self) -> str:
        task = self._task_type_env or "auto"
        return f"gemini:v1:{self._model}:{self._dim}:{task}"

    @property
    def max_input_chars(self) -> int:
        from .core import EMBED_CHARS_PER_TOKEN  # runtime import avoids a cycle

        chars = int(GEMINI_MAX_INPUT_TOKENS * max(1.0, float(EMBED_CHARS_PER_TOKEN or 3.0)))
        return max(1024, min(32768, chars))

    @property
    def decomp_document_chars(self) -> int:
        from .core import DECOMP_DOCUMENT_CHARS, DECOMP_DOCUMENT_FRACTION  # runtime import

        return decomp_document_char_budget(
            self.max_input_chars,
            explicit_chars=DECOMP_DOCUMENT_CHARS,
            fraction=DECOMP_DOCUMENT_FRACTION,
        )

    @staticmethod
    def cosine(a: list[float], b: list[float]) -> float:
        return _cosine(a, b)
