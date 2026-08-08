"""Tests for the opt-in Gemini cloud embedding backend."""

from __future__ import annotations

import contextlib
import os
from unittest import mock

import pytest

from ida_pro_mcp.host.intelligence import gemini as gemini_mod
from ida_pro_mcp.host.intelligence.core import BgeCodeEmbedder, _resolve_backend, write_embedder_state
from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex
from ida_pro_mcp.host.intelligence.gemini import GeminiEmbedBackend


@pytest.fixture
def reset_singleton():
    old = BgeCodeEmbedder._instance
    BgeCodeEmbedder._instance = None
    yield
    inst = BgeCodeEmbedder._instance
    if inst is not None:
        with contextlib.suppress(Exception):
            inst.stop()
    BgeCodeEmbedder._instance = old


def _fake_response(payload, status=200, text="ok"):
    class _Resp:
        status_code = status

        def __init__(self):
            self.text = text

        def json(self):
            return payload

    return _Resp()


def _post_side_effect(dim=768, n=None):
    """Return a requests.post side_effect that answers single or batch calls."""

    def _post(url, headers, json, timeout):
        del headers, timeout
        values = [float(i + 1) * 0.1 for i in range(dim)]
        if url.endswith(":batchEmbedContents"):
            return _fake_response(
                {"embeddings": [{"values": list(values)} for _ in range(len(json["requests"]))]}
            )
        if url.endswith(":predict"):
            return _fake_response(
                {
                    "predictions": [
                        {"embeddings": {"values": list(values)}} for _ in range(len(json["instances"]))
                    ]
                }
            )
        return _fake_response({"embedding": {"values": list(values)}})

    return _post


# ── backend selection ──────────────────────────────────────────────────────


def test_resolve_backend_defaults_to_local(monkeypatch):
    monkeypatch.delenv("IDA_MCP_EMBED_BACKEND", raising=False)
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._read_embedder_state", dict)
    assert _resolve_backend() == "local"


def test_resolve_backend_gemini_via_env(monkeypatch):
    monkeypatch.setenv("IDA_MCP_EMBED_BACKEND", "gemini")
    assert _resolve_backend() == "gemini"


def test_resolve_backend_gemini_via_state(monkeypatch):
    monkeypatch.delenv("IDA_MCP_EMBED_BACKEND", raising=False)
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core._read_embedder_state", lambda: {"backend": "gemini"}
    )
    assert _resolve_backend() == "gemini"


def test_facade_routes_to_gemini_when_selected(monkeypatch, reset_singleton):
    monkeypatch.setenv("IDA_MCP_EMBED_BACKEND", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    emb = BgeCodeEmbedder()
    assert emb._gemini is not None
    assert emb.backend == "gemini"
    assert emb.dim == 768
    assert emb._ready is True


def test_facade_keeps_local_path_by_default(monkeypatch, reset_singleton):
    monkeypatch.delenv("IDA_MCP_EMBED_BACKEND", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core._read_embedder_state", dict)
    emb = BgeCodeEmbedder()
    assert emb._gemini is None


def test_ambient_gcp_project_does_not_force_vertex(monkeypatch, reset_singleton):
    """A stray GOOGLE_CLOUD_PROJECT in the env must not flip AI Studio into Vertex."""
    monkeypatch.setenv("IDA_MCP_EMBED_BACKEND", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "ambient-project")
    emb = BgeCodeEmbedder()
    assert emb._gemini._mode == "aistudio"
    assert emb._ready is True


def test_no_credentials_reports_unready(monkeypatch, reset_singleton):
    monkeypatch.setenv("IDA_MCP_EMBED_BACKEND", "gemini")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("VERTEX_AI_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("GOOGLE_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    emb = BgeCodeEmbedder()
    assert emb._ready is False
    res = emb.embed("anything")
    assert res.ok is False
    assert res.vector is None
    st = emb.status()
    assert st["ready"] is False
    assert "no Gemini credentials" in st["error"]


# ── AI Studio single/batch ─────────────────────────────────────────────────


def test_single_embed_aistudio_request_and_parse(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    captured = {}
    post = _post_side_effect(dim=768)

    def _capture(url, headers, json, timeout):
        captured.update(url=url, headers=dict(headers), body=json, timeout=timeout)
        return post(url, headers, json, timeout)

    with mock.patch("ida_pro_mcp.host.intelligence.gemini.requests.post", side_effect=_capture):
        res = GeminiEmbedBackend().embed("func abc calls memcpy")

    assert res.ok is True
    assert res.backend == "gemini"
    assert res.vector is not None and len(res.vector) == 768
    assert captured["url"].endswith(":embedContent")
    assert captured["headers"]["x-goog-api-key"] == "test-key"
    assert captured["body"]["model"] == "models/gemini-embedding-2"
    assert captured["body"]["content"]["parts"][0]["text"] == "func abc calls memcpy"
    assert captured["body"]["embedContentConfig"] == {
        "outputDimensionality": 768,
        "taskType": "RETRIEVAL_DOCUMENT",
    }


def test_embed_is_l2_normalized(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def _post(url, headers, json, timeout):
        del url, headers, json, timeout
        return _fake_response({"embedding": {"values": [3.0, 4.0] * 384}})

    with mock.patch("ida_pro_mcp.host.intelligence.gemini.requests.post", side_effect=_post):
        res = GeminiEmbedBackend().embed("x")
    assert res.ok is True
    norm = (sum(v * v for v in res.vector) ** 0.5)
    assert norm == pytest.approx(1.0, abs=1e-6)


def test_task_type_by_purpose(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    captured = {}

    def _capture(url, headers, json, timeout):
        captured["body"] = json
        return _post_side_effect(dim=768)(url, headers, json, timeout)

    g = GeminiEmbedBackend()
    with mock.patch("ida_pro_mcp.host.intelligence.gemini.requests.post", side_effect=_capture):
        g.embed("d", purpose="document")
        assert captured["body"]["embedContentConfig"]["taskType"] == "RETRIEVAL_DOCUMENT"
        g.embed("q", purpose="query")
        assert captured["body"]["embedContentConfig"]["taskType"] == "RETRIEVAL_QUERY"


def test_task_type_disabled_via_env(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("IDA_MCP_GEMINI_TASK_TYPE", "none")
    captured = {}

    def _capture(url, headers, json, timeout):
        captured["body"] = json
        return _post_side_effect(dim=768)(url, headers, json, timeout)

    g = GeminiEmbedBackend()
    with mock.patch("ida_pro_mcp.host.intelligence.gemini.requests.post", side_effect=_capture):
        g.embed("d", purpose="document")
    assert "taskType" not in captured["body"]["embedContentConfig"]


def test_task_type_400_degrades_once(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    calls = []

    def _flaky(url, headers, json, timeout):
        calls.append(json)
        if len(calls) == 1:
            return _fake_response({"error": {}}, status=400, text="task_type not supported")
        return _fake_response({"embedding": {"values": [0.1] * 768}})

    with mock.patch("ida_pro_mcp.host.intelligence.gemini.requests.post", side_effect=_flaky):
        res = GeminiEmbedBackend().embed("x")
    assert res.ok is True
    assert len(calls) == 2
    assert "taskType" not in calls[1]["embedContentConfig"]
    assert calls[1]["embedContentConfig"]["outputDimensionality"] == 768


def test_batch_aistudio(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    captured = {}

    def _capture(url, headers, json, timeout):
        captured.update(url=url, body=json)
        return _post_side_effect(dim=768)(url, headers, json, timeout)

    g = GeminiEmbedBackend()
    with mock.patch("ida_pro_mcp.host.intelligence.gemini.requests.post", side_effect=_capture):
        results = g.embed_batch(["a", "b", "c"])
    assert len(results) == 3
    assert all(r.ok for r in results)
    assert [r.vector[0] for r in results] == [r.vector[0] for r in results]
    assert captured["url"].endswith(":batchEmbedContents")
    assert len(captured["body"]["requests"]) == 3
    for item in captured["body"]["requests"]:
        assert item["model"] == "models/gemini-embedding-2"
        assert item["embedContentConfig"]["outputDimensionality"] == 768


# ── Vertex AI ──────────────────────────────────────────────────────────────


def test_vertex_access_token_path(monkeypatch):
    monkeypatch.setenv("VERTEX_AI_ACCESS_TOKEN", "tok")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "proj-1")
    monkeypatch.setenv("VERTEX_AI_LOCATION", "europe-west1")
    captured = {}

    def _capture(url, headers, json, timeout):
        captured.update(url=url, headers=dict(headers), body=json)
        return _post_side_effect(dim=768)(url, headers, json, timeout)

    g = GeminiEmbedBackend()
    assert g._mode == "vertex"
    with mock.patch("ida_pro_mcp.host.intelligence.gemini.requests.post", side_effect=_capture):
        res = g.embed("some pseudocode")
    assert res.ok is True and len(res.vector) == 768
    assert "europe-west1-aiplatform.googleapis.com" in captured["url"]
    assert "/projects/proj-1/" in captured["url"]
    assert captured["headers"]["Authorization"] == "Bearer tok"
    inst = captured["body"]["instances"][0]
    assert inst["content"] == "some pseudocode"
    assert inst["task_type"] == "RETRIEVAL_DOCUMENT"
    assert captured["body"]["parameters"] == {"outputDimensionality": 768}


def test_vertex_requested_without_credentials(monkeypatch):
    monkeypatch.setenv("IDA_MCP_GEMINI_VERTEX", "1")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "proj-1")
    monkeypatch.delenv("VERTEX_AI_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("GOOGLE_ACCESS_TOKEN", raising=False)
    monkeypatch.setattr(gemini_mod, "_CLOUD_PLATFORM_SCOPE", "unused")  # ensure no real auth
    with mock.patch.object(GeminiEmbedBackend, "_adc_token", return_value=("", "no creds available")):
        g = GeminiEmbedBackend()
    assert g._ready is False
    assert g.embed("x").ok is False


# ── errors ─────────────────────────────────────────────────────────────────


def test_dimension_mismatch_returns_unavailable(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def _short(url, headers, json, timeout):
        del url, headers, json, timeout
        return _fake_response({"embedding": {"values": [0.1, 0.2, 0.3, 0.4, 0.5]}})

    with mock.patch("ida_pro_mcp.host.intelligence.gemini.requests.post", side_effect=_short):
        res = GeminiEmbedBackend().embed("x")
    assert res.ok is False
    assert res.vector is None


def test_http_401_returns_unavailable(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    with mock.patch(
        "ida_pro_mcp.host.intelligence.gemini.requests.post",
        side_effect=lambda *a, **k: _fake_response({"error": "unauthorized"}, status=401),
    ):
        res = GeminiEmbedBackend().embed("x")
    assert res.ok is False
    assert res.vector is None


def test_retries_transient_errors(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("IDA_MCP_GEMINI_RETRIES", "2")
    calls = {"n": 0}

    def _flaky(url, headers, json, timeout):
        del url, headers, json, timeout
        calls["n"] += 1
        if calls["n"] < 3:
            return _fake_response({}, status=429)
        return _fake_response({"embedding": {"values": [0.1] * 768}})

    with mock.patch("ida_pro_mcp.host.intelligence.gemini.requests.post", side_effect=_flaky):
        res = GeminiEmbedBackend().embed("x")
    assert res.ok is True
    assert calls["n"] == 3


# ── index integration (whole embed layer) ──────────────────────────────────


def test_index_round_trip_with_gemini_backend(monkeypatch, tmp_path, reset_singleton):
    """FunctionEmbeddingIndex drives the real gemini backend (mocked HTTP)."""
    monkeypatch.setenv("IDA_MCP_EMBED_BACKEND", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(
        "ida_pro_mcp.host.intelligence.core._read_embedder_state", dict
    )
    db = str(tmp_path / "sample.embeddings.db")
    post = _post_side_effect(dim=768)
    with mock.patch("ida_pro_mcp.host.intelligence.gemini.requests.post", side_effect=post):
        idx = FunctionEmbeddingIndex(db, BgeCodeEmbedder())
        idx.index_many(
            [
                ("0x401000", "aes_encrypt", "state = load_block(input); sub_bytes(state);", None),
                ("0x402000", "tcp_send", "socket(AF_INET); connect(); send();", None),
            ]
        )
        assert idx.size == 2
        hits = idx.similar("sub_bytes state round_keys xor", top_k=2)
        assert len(hits) == 2
        # The stored format must be the gemini one so a restart does not rebuild.
        assert "gemini:v1:gemini-embedding-2:768" in str(idx.metadata().get("embedding_format"))


def test_embedding_format_stable_across_instances(monkeypatch):
    monkeypatch.setenv("IDA_MCP_EMBED_BACKEND", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    f1 = GeminiEmbedBackend().embedding_format
    f2 = GeminiEmbedBackend().embedding_format
    assert f1 == f2
    assert f1.startswith("gemini:v1:gemini-embedding-2:768")


def test_max_input_chars_uses_gemini_8192_token_window(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    g = GeminiEmbedBackend()
    # 8192 tokens * 3 chars ≈ 24576
    assert g.max_input_chars == 24576
    assert 1024 < g.decomp_document_chars < g.max_input_chars


# ── embedder.json persistence ──────────────────────────────────────────────


def test_write_embedder_state_gemini_never_stores_key(tmp_path):
    write_embedder_state(
        tmp_path,
        backend="gemini",
        gemini_model="gemini-embedding-2",
        gemini_dimension=768,
        gemini_vertex_project="proj-1",
        gemini_vertex_location="us-central1",
    )
    import json

    state = json.loads(tmp_path.joinpath("embedder.json").read_text())
    assert state["backend"] == "gemini"
    assert state["gemini_model"] == "gemini-embedding-2"
    assert state["gemini_dimension"] == 768
    assert state["gemini_vertex_project"] == "proj-1"
    assert "api_key" not in json.dumps(state).lower()


def test_write_embedder_state_rejects_unknown_backend(tmp_path):
    with pytest.raises(ValueError, match="unknown embedding backend"):
        write_embedder_state(tmp_path, backend="nonsense")
