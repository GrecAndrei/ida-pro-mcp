"""Cross-encoder reranker model profiles and lightweight GGUF discovery.

The two-stage retrieval pipeline pairs a fast bi-encoder (recall, the
embedding index) with a cross-encoder that re-scores only the recalled
candidates — full attention between the query and each document, so the
top of the list is correct instead of merely the neighborhood.

Profiles here cover the two reranker families that are first-class in
llama.cpp's ``--rerank`` mode:

  - Qwen3-Reranker (0.6B default, 4B precision opt-in) — May 2025, the
    current family.  The 0.6B is the speed tier for routine search; the 4B
    earns its latency on deep dives over stripped binaries.
  - BGE-Reranker-v2 (Gemma 2.6B middle tier, M3 compat) — the BGE family
    named in the two-stage retrieval literature.  Gemma is the correct
    middle capacity between the 0.6B and the 4B.

A reranker's output is a relevance score for one (query, document) pair, so
``document`` framing is fixed by the model at conversion time — unlike the
embedder there is no per-profile query prefix to inject.  The only
per-profile knobs are context length (llama.cpp truncates each pair to fit)
and the download source.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass

from .model_profiles import read_gguf_metadata


@dataclass(frozen=True)
class RerankModelProfile:
    key: str
    display_name: str
    family: str  # "qwen3" | "bge" | "custom"
    filename_patterns: tuple[str, ...]
    max_context: int = 8192  # --ctx-size we pass; llama.cpp truncates pairs to fit
    license: str = ""
    download_url: str = ""
    download_filename: str = ""
    # Managed downloads are pinned to an immutable Hub revision and checked
    # against the LFS SHA-256 before they become visible to the host.
    download_revision: str = ""
    download_sha256: str = ""
    download_size: int = 0
    opt_in: bool = False


QWEN3_RERANKER_0_6B = RerankModelProfile(
    key="qwen3-reranker-0.6b",
    display_name="Qwen3 Reranker 0.6B",
    family="qwen3",
    filename_patterns=("Qwen3-Reranker-0.6B*.gguf", "qwen3-reranker-0.6b*.gguf"),
    max_context=8192,
    license="apache-2.0",
    download_url=(
        "https://huggingface.co/ggml-org/Qwen3-Reranker-0.6B-Q8_0-GGUF/resolve/main/"
        "qwen3-reranker-0.6b-q8_0.gguf"
    ),
    download_filename="qwen3-reranker-0.6b-q8_0.gguf",
    download_revision="a02f48bb4f057028298c21fa033da2b30d7742d5",
    download_sha256="22c9979ce4fbcdc5acdc310c6641c32797eff1aa980b8f7a2db8a8ea23429a48",
    download_size=639153184,
)

BGE_RERANKER_V2_GEMMA = RerankModelProfile(
    key="bge-reranker-v2-gemma",
    display_name="BGE Reranker v2 Gemma",
    family="bge",
    filename_patterns=("bge-reranker-v2-gemma*.gguf", "bge-reranker-v2-gemma.*.gguf"),
    max_context=8192,
    license="apache-2.0",
    # WARNING (verified 2026-08-03): the RichardErkhov conversion that this
    # download points at is a HEADLESS base Gemma-2B — it ships no
    # sequence-classification head and no output.weight, so llama.cpp's
    # --rerank mode returns a constant score for every (query, doc) pair.
    # The profile stays for compatibility with a correct conversion; the
    # benchmark treats equal scores as a hard FAIL and the ggml-org Qwen3
    # conversions are the canonical working source.
    download_url=(
        "https://huggingface.co/RichardErkhov/BAAI_-_bge-reranker-v2-gemma-gguf/resolve/main/"
        "bge-reranker-v2-gemma.Q4_K_M.gguf"
    ),
    download_filename="bge-reranker-v2-gemma.Q4_K_M.gguf",
    download_revision="49b479f79e181f8ac1ddefddb3074ff3143b0570",
    download_sha256="ca597319b44ddcb1b063fe159fe472aaa431dc95ff97818ee5d63313cd5341d4",
    download_size=1630263040,
)

QWEN3_RERANKER_4B = RerankModelProfile(
    key="qwen3-reranker-4b",
    display_name="Qwen3 Reranker 4B",
    family="qwen3",
    filename_patterns=("Qwen3-Reranker-4B*.gguf", "qwen3-reranker-4b*.gguf"),
    max_context=8192,
    license="apache-2.0",
    download_url=(
        "https://huggingface.co/sinjab/Qwen3-Reranker-4B-Q4_K_M-GGUF/resolve/main/"
        "Qwen3-Reranker-4B-Q4_K_M.gguf"
    ),
    download_filename="Qwen3-Reranker-4B-Q4_K_M.gguf",
    download_revision="d73f4345c67a01c733567e53976d03d21586362d",
    download_sha256="70996092c3d39d4bd5cfbb9722f7ced33e5c8dffc403a1a77e10afafd4ead37c",
    download_size=2496717280,
)

BGE_RERANKER_V2_M3 = RerankModelProfile(
    key="bge-reranker-v2-m3",
    display_name="BGE Reranker v2 M3",
    family="bge",
    filename_patterns=("bge-reranker-v2-m3*.gguf",),
    max_context=8192,
    license="apache-2.0",
    download_url=(
        "https://huggingface.co/Felladrin/gguf-Q8_0-bge-reranker-v2-m3/resolve/main/"
        "bge-reranker-v2-m3-q8_0.gguf"
    ),
    download_filename="bge-reranker-v2-m3-q8_0.gguf",
    download_revision="fdac51aaf4d4cf7ec1415568a9044a1f8b139e26",
    download_sha256="a43c7c9b11a4c1517e5bf95151960e1621d1b72f7a493364b01e386cf1aaa1d3",
    download_size=635676416,
    opt_in=True,
)

RERANK_MODEL_PROFILES: dict[str, RerankModelProfile] = {
    p.key: p
    for p in (
        QWEN3_RERANKER_0_6B,
        BGE_RERANKER_V2_GEMMA,
        QWEN3_RERANKER_4B,
        BGE_RERANKER_V2_M3,
    )
}

RERANK_PROFILE_ALIASES = {
    "qwen3-reranker": "qwen3-reranker-0.6b",
    "qwen3": "qwen3-reranker-0.6b",
    "bge": "bge-reranker-v2-gemma",
    "bge-reranker-v2": "bge-reranker-v2-gemma",
    "bge-gemma": "bge-reranker-v2-gemma",
    "bge-m3": "bge-reranker-v2-m3",
}


def get_rerank_model_profile(name: str | None) -> RerankModelProfile | None:
    key = str(name or "").strip().lower()
    key = RERANK_PROFILE_ALIASES.get(key, key)
    return RERANK_MODEL_PROFILES.get(key)


def profile_from_rerank_model(
    path: str, requested: str | None = None
) -> RerankModelProfile:
    """Identify a rerank GGUF, honouring an explicit profile override first."""
    explicit = get_rerank_model_profile(requested)
    if explicit is not None:
        return explicit
    basename = os.path.basename(str(path or "")).lower()
    for profile in RERANK_MODEL_PROFILES.values():
        if any(fnmatch.fnmatch(basename, pat.lower()) for pat in profile.filename_patterns):
            return profile
    metadata = read_gguf_metadata(path)
    name = str(metadata.get("general.name") or "").lower()
    if "bge-reranker" in name:
        if "gemma" in name:
            return BGE_RERANKER_V2_GEMMA
        if "m3" in name:
            return BGE_RERANKER_V2_M3
        return BGE_RERANKER_V2_GEMMA
    if "qwen3-reranker" in name:
        if "4b" in name:
            return QWEN3_RERANKER_4B
        return QWEN3_RERANKER_0_6B
    return RerankModelProfile(
        key="custom-rerank",
        display_name=str(metadata.get("general.name") or basename or "Custom GGUF reranker"),
        family="custom",
        filename_patterns=(),
        max_context=8192,
        license=str(metadata.get("general.license") or "unknown"),
        opt_in=True,
    )
