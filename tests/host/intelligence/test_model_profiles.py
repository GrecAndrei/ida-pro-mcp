from __future__ import annotations

import json
import struct
import time

from ida_pro_mcp.host.intelligence import core
from ida_pro_mcp.host.intelligence.core import BgeCodeEmbedder
from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex
from ida_pro_mcp.host.intelligence.model_profiles import (
    BGE_CODE_V1,
    QWEN3_EMBEDDING_0_6B,
    ZEMBED_1,
    model_dimension,
    profile_from_model,
    read_gguf_metadata,
)


def _gguf_string(value: str) -> bytes:
    raw = value.encode()
    return struct.pack("<Q", len(raw)) + raw


def test_zembed_uses_its_asymmetric_query_and_document_prompts():
    assert ZEMBED_1.format_text("find string decryptors", "query") == (
        "<|im_start|>system\nquery<|im_end|>\n<|im_start|>user\n"
        "find string decryptors<|im_end|>\n"
    )
    assert ZEMBED_1.format_text("void decrypt(void)", "document") == (
        "<|im_start|>system\ndocument<|im_end|>\n<|im_start|>user\n"
        "void decrypt(void)<|im_end|>\n"
    )
    assert BGE_CODE_V1.format_text("plain code", "query") == "plain code"


def test_gguf_metadata_supplies_the_embedding_dimension(tmp_path):
    # A minimal GGUF v3 metadata section; tensor data is deliberately absent.
    metadata = [
        ("general.architecture", 8, _gguf_string("qwen3")),
        ("qwen3.embedding_length", 4, struct.pack("<I", 2560)),
    ]
    body = b"".join(
        _gguf_string(key) + struct.pack("<I", value_type) + value
        for key, value_type, value in metadata
    )
    path = tmp_path / "zembed-1-Q4_K_M.gguf"
    path.write_bytes(b"GGUF" + struct.pack("<IQQ", 3, 0, len(metadata)) + body)

    parsed = read_gguf_metadata(str(path))
    assert parsed["qwen3.embedding_length"] == 2560
    assert model_dimension(str(path), ZEMBED_1) == 2560


def test_profile_is_inferred_from_manual_model_name_without_a_configured_profile():
    assert profile_from_model("/models/zembed-1-Q4_K_M.gguf").key == "zembed-1"
    assert profile_from_model("/models/bge-code-v1-q8_0.gguf").key == "bge-code-v1"
    assert (
        profile_from_model("/models/Qwen3-Embedding-0.6B-Q8_0.gguf").key
        == "qwen3-embedding-0.6b"
    )


def test_qwen3_profile_uses_last_token_pooling_and_query_instruction():
    """The Qwen3 swap fixes two silent bugs: mean pooling on a decoder model
    and a missing query-side instruction prefix."""
    assert QWEN3_EMBEDDING_0_6B.pooling == "last"
    assert QWEN3_EMBEDDING_0_6B.dimension == 1024
    assert QWEN3_EMBEDDING_0_6B.format_text("find the decryptor", "query").startswith(
        "Instruct: Given a code analysis task"
    )
    assert QWEN3_EMBEDDING_0_6B.format_text("void decrypt(void)", "document") == (
        "void decrypt(void)"
    )
    assert QWEN3_EMBEDDING_0_6B.format_text("void decrypt(void)", "document").endswith(
        "void decrypt(void)"
    )


def test_selected_profile_does_not_reuse_an_incompatible_persisted_model(monkeypatch, tmp_path):
    bge_model = tmp_path / "bge-code-v1-q8_0.gguf"
    bge_model.write_bytes(b"not-a-real-gguf")
    monkeypatch.setattr(core, "_MODEL_PATH_CACHE", None)
    monkeypatch.setattr(
        core,
        "_read_embedder_state",
        lambda: {"model_path": str(bge_model), "profile": "bge-code-v1"},
    )
    monkeypatch.setattr(core.glob, "glob", lambda _pattern: [])
    monkeypatch.setenv("IDA_MCP_EMBED_PROFILE", "zembed-1")
    monkeypatch.delenv("IDA_MCP_EMBED_MODEL", raising=False)

    assert core._find_model() == ""


def test_model_discovery_cache_tracks_env_changes_and_new_files(monkeypatch, tmp_path):
    first = tmp_path / "first.gguf"
    second = tmp_path / "second.gguf"
    first.write_bytes(b"first")
    monkeypatch.setattr(core, "_MODEL_PATH_CACHE", None)
    monkeypatch.setattr(core, "_read_embedder_state", dict)
    monkeypatch.setattr(core.glob, "glob", lambda _pattern: [])

    monkeypatch.setenv("IDA_MCP_EMBED_MODEL", str(first))
    assert core._find_model() == str(first)

    # The explicit path is part of the cache identity, so a runtime model
    # switch cannot accidentally keep serving the first model.
    second.write_bytes(b"second")
    monkeypatch.setenv("IDA_MCP_EMBED_MODEL", str(second))
    assert core._find_model() == str(second)

    # A first probe before download must not permanently cache "not found".
    missing = tmp_path / "arrived-later.gguf"
    monkeypatch.setenv("IDA_MCP_EMBED_MODEL", str(missing))
    assert core._find_model() == ""
    missing.write_bytes(b"downloaded")
    assert core._find_model() == str(missing)


def test_zembed_sends_query_and_document_prompts_to_the_embedding_server(monkeypatch, tmp_path):
    embedder = object.__new__(BgeCodeEmbedder)
    embedder._port = 43123
    embedder._ready = True
    embedder._use_llama = True
    embedder._profile = ZEMBED_1
    embedder._dimension = 2
    embedder._consecutive_rpc_failures = 0
    embedder._max_rpc_failures = 2
    embedder._last_batch_timeout = False
    # Clearly outside the activation-grace window (0.0 would read as "inside
    # grace" on a fresh runner where monotonic() < 60s).
    embedder._server_started_at = time.monotonic() - 3600.0
    embedder._last_recycle_reason = ""
    embedder._model_path = ""
    embedder._server_bin = ""
    embedder._identity_cache = None
    monkeypatch.setattr(core, "_EMBED_LEASE_FILE", str(tmp_path / "lease.json"))
    requests: list[dict] = []

    class Response:
        def __init__(self, payload: bytes):
            self.payload = payload

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return self.payload

    def fake_urlopen(request, timeout):
        requests.append(json.loads(request.data))
        return Response(b'[{"index":0,"embedding":[3.0,4.0]}]')

    monkeypatch.setattr("ida_pro_mcp.host.intelligence.core.urllib.request.urlopen", fake_urlopen)

    assert embedder.embed_query_vector("find decryptors") == [0.6, 0.8]
    assert embedder.embed_document("void decrypt(void)").vector == [0.6, 0.8]
    assert requests[0]["input"] == ZEMBED_1.format_text("find decryptors", "query")
    assert requests[1]["input"] == ZEMBED_1.format_text("void decrypt(void)", "document")


class _FormatEmbedder:
    backend = "test"
    dim = 2

    def __init__(self, embedding_format: str):
        self.embedding_format = embedding_format

    def embed_documents(self, texts):
        return [[0.6, 0.8] for _ in texts]

    def embed_vector(self, _text):
        return [0.6, 0.8]


def test_index_rebuilds_when_embedding_prompt_format_changes(tmp_path):
    db_path = str(tmp_path / "sample.embeddings.db")
    first = FunctionEmbeddingIndex(db_path, _FormatEmbedder("profile-v1:a"))
    assert first.index("0x401000", "target", "void target(void)") is True
    assert first.size == 1

    changed = FunctionEmbeddingIndex(db_path, _FormatEmbedder("profile-v1:b"))
    assert changed.size == 0
    assert changed.metadata()["embedding_format"] == "profile-v1:b"
