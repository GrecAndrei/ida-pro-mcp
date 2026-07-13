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
    license: str = ""
    download_url: str = ""
    download_filename: str = ""
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
    opt_in=True,
)

MODEL_PROFILES = {p.key: p for p in (BGE_CODE_V1, ZEMBED_1)}
PROFILE_ALIASES = {
    "bge": "bge-code-v1",
    "bge-code": "bge-code-v1",
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
    except (OSError, ValueError, struct.error):
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
    metadata = read_gguf_metadata(path)
    name = str(metadata.get("general.name") or "").lower()
    if "zembed 1" in name or "zembed-1" in name:
        return ZEMBED_1
    if "bge code v1" in name or "bge-code-v1" in name:
        return BGE_CODE_V1
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
