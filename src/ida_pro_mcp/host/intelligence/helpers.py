from __future__ import annotations

import difflib
import math
import struct
from collections.abc import Sequence


def _q(vals: list[float], q: float, default: float = 0.0) -> float:
    if not vals:
        return float(default)
    s = sorted(float(v) for v in vals)
    if len(s) == 1:
        return s[0]
    i = int(round((len(s) - 1) * max(0.0, min(1.0, float(q)))))
    i = max(0, min(len(s) - 1, i))
    return float(s[i])


# Public alias for the quantile helper. ``_q`` is kept for back-compat with
# existing imports; new code should use ``quantile``.
quantile = _q


def dot_product(a: Sequence[float], b: Sequence[float]) -> float:
    """Sum of elementwise products. Equivalent to cosine similarity when
    both inputs are pre-normalized to unit length — the convention used by
    the BgeCodeEmbedder output vectors."""
    try:
        import numpy as np
        return float(np.dot(a, b))
    except (ImportError, ValueError):
        # ImportError: numpy unavailable.  ValueError: dimension mismatch —
        # match the historical per-row loop's truncated zip so a mismatched
        # (query, row) pair degrades gracefully instead of raising out of the
        # batch-cosine fallback.
        return sum(x * y for x, y in zip(a, b, strict=False))


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """True cosine similarity with safe zero-norm fallback."""
    dot = dot_product(a, b)
    na = math.sqrt(sum(float(x) * float(x) for x in a))
    nb = math.sqrt(sum(float(x) * float(x) for x in b))
    if na < 1e-9 or nb < 1e-9:
        return 0.0
    return dot / (na * nb)


class _EmbedResult:
    """Result of an embedding call.

    Production invariant: ``vector`` is *always* from the declared
    ``backend``.  When ``ok`` is False, ``vector`` is None and callers
    MUST surface the failure rather than proceed as if nothing happened.
    The old TF-IDF fallback violated this by returning garbage vectors
    whenever the model was unavailable.

    Shared by the local llama-server backend (``intelligence/core.py``) and
    the opt-in cloud Gemini backend (``intelligence/gemini.py``).
    """

    __slots__ = ("vector", "backend", "ok")

    def __init__(self, vector: list[float] | None, backend: str, ok: bool):
        self.vector = vector
        self.backend = backend
        self.ok = ok

    def __repr__(self) -> str:
        return f"_EmbedResult(backend={self.backend!r}, ok={self.ok})"


def pack_floats(vec: Sequence[float]) -> bytes:
    """Pack a list of floats into a raw little-endian float32 blob."""
    return struct.pack(f"{len(vec)}f", *vec)


def unpack_floats(blob: bytes) -> list[float]:
    """Inverse of :func:`pack_floats`.

    A float32 blob must be an exact multiple of four bytes.  Reject trailing
    bytes rather than silently dropping them, so callers can treat a corrupt
    persisted vector as unreadable instead of ranking with a truncated one.
    """
    if len(blob) % 4:
        raise ValueError("float32 blob size must be a multiple of 4 bytes")
    n = len(blob) // 4
    return list(struct.unpack(f"{n}f", blob))


def estimate_tokens(text) -> int:
    """Approximate token count for a string (~4 chars per token).

    Returns 0 for empty / falsy input. This is intentionally a rough
    heuristic — it matches the convention already used in
    ``llm_helpers._estimate_tokens`` and the inline ``len(text) // 4``
    expressions scattered through ``host/context_density.py``.
    """
    return len(text) // 4 if text else 0


def similarity_ratio(a: str, b: str) -> float:
    """Thin wrapper around :class:`difflib.SequenceMatcher` for two-string
    similarity. Returns a float in [0.0, 1.0]."""
    return difflib.SequenceMatcher(None, a, b).ratio()


def best_match(
    query: str,
    choices: list[str],
    *,
    n: int = 1,
    cutoff: float = 0.6,
) -> list[str]:
    """Wrap :func:`difflib.get_close_matches` so callers don't need to
    import difflib directly. Returns at most *n* matches above *cutoff*."""
    return difflib.get_close_matches(query or "", choices, n=n, cutoff=cutoff)


def coerce_int(value, default: int = 0) -> int:
    """Coerce a string / int to an int with a hex prefix fallback.

    Replaces the inline ``int(s, 16) if s.startswith("0x") else int(s)``
    pattern that recurs in ~10 places across the host package. Returns
    *default* if the value can't be parsed as an integer in any base.

    Note: this is intentionally narrower than
    :func:`ida_pro_mcp.ida_mcp.utils.parse_address` — it does not attempt
    symbol resolution. Use ``parse_address`` if you need symbol lookup.
    """
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return default
        try:
            if s.lower().startswith("0x"):
                return int(s, 16)
            return int(s)
        except ValueError:
            try:
                return int(s, 16)
            except ValueError:
                return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_str_list(value, sep: str = ",") -> list[str]:
    """Parse a CSV-style string into a list of trimmed non-empty items.

    If *value* is already a list/tuple, each element is trimmed and
    ``None`` entries are dropped. If *value* is empty / None, returns [].
    Otherwise splits on *sep* and trims.

    Replaces the inline ``[x.strip() for x in s.split(",") if x.strip()]``
    pattern that recurs in ~20 places across the host package.
    """
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if x is not None and str(x).strip()]
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return []
        return [p.strip() for p in s.split(sep) if p.strip()]
    s = str(value).strip()
    if not s:
        return []
    return [p.strip() for p in s.split(sep) if p.strip()]


def batch_cosine_similarity(
    query: Sequence[float],
    vectors: Sequence[Sequence[float]],
) -> list[float]:
    """Cosine similarity of *query* against every row in *vectors*.

    Prefers a vectorized NumPy path (one matrix multiply) when NumPy is
    importable, and falls back to a per-row pure-Python loop otherwise.
    Conventions match :func:`cosine_similarity`: a zero-norm query or row
    scores 0.0, so the two paths agree exactly on edge inputs.
    """
    if not vectors:
        return []
    try:
        import numpy as _np
    except ImportError:
        _np = None
    if _np is not None:
        try:
            return _batch_cosine_numpy(_np, query, vectors)
        except Exception:
            pass  # unexpected shapes/types fall back to the per-row loop
    return [cosine_similarity(query, v) for v in vectors]


def _batch_cosine_numpy(
    np, query: Sequence[float], vectors: Sequence[Sequence[float]]
) -> list[float]:
    """NumPy implementation of :func:`batch_cosine_similarity`."""
    q = np.asarray(list(query), dtype=np.float64)
    matrix = np.asarray([list(v) for v in vectors], dtype=np.float64)
    if q.ndim != 1 or matrix.ndim != 2 or matrix.shape[0] == 0:
        raise ValueError("unexpected array shape")
    if matrix.shape[1] != q.shape[0]:
        raise ValueError("dimension mismatch")
    q_norm = float(np.linalg.norm(q))
    if q_norm <= 1e-9:
        return [0.0] * matrix.shape[0]
    row_norms = np.linalg.norm(matrix, axis=1)
    tiny = row_norms <= 1e-9
    unit = matrix / np.where(tiny, 1.0, row_norms)[:, None]
    sims = unit @ (q / q_norm)
    sims = np.where(tiny, 0.0, sims)
    return [float(x) for x in sims]


def decomp_document_char_budget(
    max_input_chars: int,
    *,
    explicit_chars: int = 0,
    fraction: float = 0.20,
) -> int:
    """Full-decomp document budget shared by the local and cloud embedders.

    Both backends index long decompilations with the same cap: an explicit
    character override wins when set, otherwise a clamped fraction of the
    embedder's input window.  Kept here so the two backends cannot drift.
    """
    window = max(1024, int(max_input_chars) if max_input_chars else 1024)
    if explicit_chars and explicit_chars > 0:
        return max(1024, min(window, int(explicit_chars)))
    frac = max(0.1, min(1.0, float(fraction)))
    return max(1024, min(window, int(window * frac)))

