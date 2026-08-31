"""Embedding-model profiles and lightweight GGUF metadata inspection."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EmbeddingModelProfile:
    key: str
    display_name: str
    filename_patterns: tuple[str, ...]
    dimension: int
    query_prefix: str = ""
    document_prefix: str = ""
    suffix: str = ""
    pooling: str = "mean"  # llama.cpp --pooling value; "last" for decoder models
    license: str = ""
    download_url: str = ""
    download_filename: str = ""
    # Managed downloads are pinned to an immutable Hub revision and checked
    # against the LFS SHA-256 before they become visible to the host.
    download_revision: str = ""
    download_sha256: str = ""
    download_size: int = 0
    opt_in: bool = False

    def format_text(self, text: str, purpose: str = "document") -> str:
        prefix = self.query_prefix if purpose == "query" else self.document_prefix
        return f"{prefix}{text}{self.suffix}"


BGE_CODE_V1 = EmbeddingModelProfile(
    key="bge-code-v1",
    display_name="BGE Code v1",
    filename_patterns=("bge-code-v1*.gguf",),
    dimension=1536,
    license="apache-2.0",
)

QWEN3_EMBEDDING_0_6B = EmbeddingModelProfile(
    key="qwen3-embedding-0.6b",
    display_name="Qwen3 Embedding 0.6B",
    filename_patterns=("Qwen3-Embedding-0.6B*.gguf", "qwen3-embedding-0.6b*.gguf"),
    dimension=1024,
    # Decoder model: last-token pooling, and query-side instruction prefix
    # ("Instruct: <task>\nQuery: <query>", documents get no prefix).  The
    # task line follows the model's training convention; retrieval docs
    # recommend tailoring it to the scenario.
    pooling="last",
    query_prefix=(
        "Instruct: Given a code analysis task, retrieve the relevant functions.\n"
        "Query: "
    ),
    license="apache-2.0",
    download_url=(
        "https://huggingface.co/Qwen/Qwen3-Embedding-0.6B-GGUF/resolve/main/"
        "Qwen3-Embedding-0.6B-Q8_0.gguf"
    ),
    download_filename="Qwen3-Embedding-0.6B-Q8_0.gguf",
    download_revision="370f27d7550e0def9b39c1f16d3fbaa13aa67728",
    download_sha256="06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439",
    download_size=639150592,
)

ZEMBED_1 = EmbeddingModelProfile(
    key="zembed-1",
    display_name="Zembed 1",
    filename_patterns=("zembed-1*.gguf",),
    dimension=2560,
    query_prefix="<|im_start|>system\nquery<|im_end|>\n<|im_start|>user\n",
    document_prefix="<|im_start|>system\ndocument<|im_end|>\n<|im_start|>user\n",
    suffix="<|im_end|>\n",
    license="cc-by-nc-4.0",
    download_url=(
        "https://huggingface.co/Abiray/zembed-1-Q4_K_M-GGUF/resolve/main/"
        "zembed-1-Q4_K_M.gguf"
    ),
    download_filename="zembed-1-Q4_K_M.gguf",
    download_revision="c1fed1b47f407fdf5ceb25d6919ac7e5237151c9",
    download_sha256="3098f7963ca0563e8b39a55ee09a53697e57e49be5b9082892739bf24e075836",
    download_size=2497280960,
    opt_in=True,
)

MODEL_PROFILES = {p.key: p for p in (BGE_CODE_V1, QWEN3_EMBEDDING_0_6B, ZEMBED_1)}
PROFILE_ALIASES = {
    "bge": "bge-code-v1",
    "bge-code": "bge-code-v1",
    "qwen3": "qwen3-embedding-0.6b",
    "qwen3-embedding": "qwen3-embedding-0.6b",
    "zembed": "zembed-1",
}


def get_model_profile(name: str | None) -> EmbeddingModelProfile | None:
    key = str(name or "").strip().lower()
    key = PROFILE_ALIASES.get(key, key)
    return MODEL_PROFILES.get(key)


def _read_gguf_value(handle, value_type: int) -> Any:
    scalar_formats = {
        0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i",
        6: "<f", 7: "<?", 10: "<Q", 11: "<q", 12: "<d",
    }
    if value_type in scalar_formats:
        fmt = scalar_formats[value_type]
        raw = handle.read(struct.calcsize(fmt))
        if len(raw) != struct.calcsize(fmt):
            raise ValueError("truncated GGUF scalar")
        return struct.unpack(fmt, raw)[0]
    if value_type == 8:
        size_raw = handle.read(8)
        if len(size_raw) != 8:
            raise ValueError("truncated GGUF string length")
        size = struct.unpack("<Q", size_raw)[0]
        if size > 16 * 1024 * 1024:
            raise ValueError("unreasonable GGUF string length")
        return handle.read(size).decode("utf-8", errors="replace")
    if value_type == 9:
        element_type_raw = handle.read(4)
        count_raw = handle.read(8)
        if len(element_type_raw) != 4 or len(count_raw) != 8:
            raise ValueError("truncated GGUF array")
        element_type = struct.unpack("<I", element_type_raw)[0]
        count = struct.unpack("<Q", count_raw)[0]
        if count > 10_000_000:
            raise ValueError("unreasonable GGUF array length")
        return [_read_gguf_value(handle, element_type) for _ in range(count)]
    raise ValueError(f"unsupported GGUF metadata type {value_type}")


def read_gguf_metadata(path: str) -> dict[str, Any]:
    """Read GGUF key/value metadata without loading tensor data."""
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "rb") as handle:
            if handle.read(4) != b"GGUF":
                return {}
            version_raw = handle.read(4)
            counts_raw = handle.read(16)
            if len(version_raw) != 4 or len(counts_raw) != 16:
                return {}
            version = struct.unpack("<I", version_raw)[0]
            _tensor_count, metadata_count = struct.unpack("<QQ", counts_raw)
            if version not in (2, 3) or metadata_count > 100_000:
                return {}
            metadata: dict[str, Any] = {"gguf.version": version}
            for _ in range(metadata_count):
                key = _read_gguf_value(handle, 8)
                value_type_raw = handle.read(4)
                if len(value_type_raw) != 4:
                    return {}
                metadata[str(key)] = _read_gguf_value(
                    handle, struct.unpack("<I", value_type_raw)[0]
                )
            return metadata
    except (OSError, ValueError, struct.error, RecursionError):
        return {}


def profile_from_model(path: str, requested: str | None = None) -> EmbeddingModelProfile:
    explicit = get_model_profile(requested)
    if explicit is not None:
        return explicit
    basename = os.path.basename(str(path or "")).lower()
    if "zembed-1" in basename or basename.startswith("zembed"):
        return ZEMBED_1
    if "bge-code-v1" in basename:
        return BGE_CODE_V1
    if "qwen3-embedding-0.6b" in basename:
        return QWEN3_EMBEDDING_0_6B
    metadata = read_gguf_metadata(path)
    name = str(metadata.get("general.name") or "").lower()
    if "zembed 1" in name or "zembed-1" in name:
        return ZEMBED_1
    if "bge code v1" in name or "bge-code-v1" in name:
        return BGE_CODE_V1
    if "qwen3 embedding 0.6b" in name or "qwen3-embedding" in name:
        return QWEN3_EMBEDDING_0_6B
    architecture = str(metadata.get("general.architecture") or "")
    dimension = int(metadata.get(f"{architecture}.embedding_length") or 0)
    return EmbeddingModelProfile(
        key="custom",
        display_name=str(metadata.get("general.name") or basename or "Custom GGUF embedder"),
        filename_patterns=(),
        dimension=dimension,
        license=str(metadata.get("general.license") or "unknown"),
        opt_in=True,
    )


def model_dimension(path: str, profile: EmbeddingModelProfile) -> int:
    metadata = read_gguf_metadata(path)
    architecture = str(metadata.get("general.architecture") or "")
    try:
        discovered = int(metadata.get(f"{architecture}.embedding_length") or 0)
    except (TypeError, ValueError):
        discovered = 0
    return discovered or profile.dimension
