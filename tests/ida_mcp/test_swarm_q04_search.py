"""Regression tests for swarm/q04 — reliability/faster/more-useful search on
opaque device binaries (raw headerless .bin firmware, especially RISC-V).

Standalone tests: ida_* modules are stubbed via tests._isolated_repo_loader;
no live IDA session is required.

Pinned fixes (all implemented in the q04 wave):
- search_immediate / search_constants reconstruct 32-bit constants from an
  adjacent RISC-V lui+addi/addiw pair and match on the *resolved* value,
  reporting both instruction addresses.
- resolve_scan_segments: a raw blob with no EXEC segment falls back to
  scanning non-exec bytes with an explanatory note (never silent empty);
  a range that misses code on an otherwise-normal binary returns a crisp error.
- search router: timeout_ms=None (the default) resolves to a bounded
  whole-binary budget (DEFAULT_SEARCH_TIMEOUT_MS); 0 stays an explicit
  opt-out and an explicit value is forwarded untouched.
- resolve_target demangle memoization keyed on the DB fingerprint, plus a
  token pre-filter so unrelated mangled names never hit the demangle RPC.
- search_nl: embedding-backend failure degrades to lexical-only ranking with
  a note; classifier-cold search_behavior skips the up-to-200 decompile loop;
  "expand" mode runs extra queries only over the top recalled EAs (and gates
  expansion to a single extra query on very large binaries).
- _rescore_find_ranked: phrase-like queries get a wider embedding budget than
  identifier queries; rerank deadline is plumbed into the reranker when the
  backend accepts it.
- semantic_matching._subword_tokens splits RISC-V ABI digit suffixes
  (uart0 -> uart) while short register names (x5, a0) stay intact.
- FunctionEmbeddingIndex.search_text consumes persisted token columns (no
  per-row regex tokenization / per-query IDF on the hot path) with SQL
  address-range and token filters.
"""

from __future__ import annotations

import os
import sys
import time

from tests._isolated_repo_loader import load_support_module, load_tool_submodule


def _module(relpath: str):
    return load_tool_submodule(relpath, common_overrides={"os": os})


def _semantic():
    """Return search.semantic, loaded via the real search package __init__ so
    `from . import _query_insight_by_tags` resolves (a namespace-only parent
    would raise ImportError at call time)."""
    load_tool_submodule("search", common_overrides={"os": os})
    return sys.modules["ida_pro_mcp.ida_mcp.tools.search.semantic"]


# ---------------------------------------------------------------------------
# Fake IDA surface shared by the search-tool tests
# ---------------------------------------------------------------------------

class _Op:
    """ida_ua op_t stand-in: type/value/reg are the fields the pair detector reads."""

    def __init__(self, t: int, value: int = 0, reg: int = 0):
        self.type = t
        self.value = value
        self.reg = reg


class _Insn:
    """ida_ua.insn_t stand-in with get_canon_mnem()."""

    def __init__(self, mnem: str, ops, size: int = 4, ea: int = 0):
        self._mnem = mnem
        self.ops = ops
        self.size = size
        self.ea = ea

    def get_canon_mnem(self):
        return self._mnem


class _InsnT:
    """ida_ua.insn_t() holder populated by a decode table."""


class _DecodeTable:
    """Decode by EA: mutate the passed holder so the tool sees the entry."""

    def __init__(self, table):
        self._table = table

    def decode(self, insn, ea: int) -> int:
        entry = self._table.get(ea)
        if entry is None:
            return 0
        insn.ops = entry.ops
        insn.size = entry.size
        insn.ea = entry.ea
        insn.get_canon_mnem = entry.get_canon_mnem
        return 1


def _install_ida_constants():
    sys.modules["idaapi"].BADADDR = -1
    sys.modules["ida_ua"].o_reg = 1
    sys.modules["ida_ua"].o_imm = 5


def _install_insn_fakes(mod, table):
    _install_ida_constants()
    decode = _DecodeTable(table)
    mod.ida_ua.insn_t = _InsnT
    mod.ida_ua.decode_insn = decode.decode
    mod.idaapi.get_func = lambda ea: None
    mod.idc.next_head = lambda ea, end: -1


# A lui+addi pair that materializes 0xAAAA5555:
#   lui  t0, 0xAAAA5      # 20-bit high half
#   addi t0, t0, 0x555    # sign-extended low half
LUI_ADDI_TABLE = {
    0x1000: _Insn("lui", [_Op(1, 0, reg=5), _Op(5, 0xAAAA5)], size=4, ea=0x1000),
    0x1004: _Insn("addi", [_Op(1, 0, reg=5), _Op(1, 0, reg=5), _Op(5, 0x555)], size=4, ea=0x1004),
}


# ---------------------------------------------------------------------------
# RISC-V lui+addi constant reconstruction
# ---------------------------------------------------------------------------

def test_riscv_lui_addi_reconstructs_32bit_constant():
    core = _module("search.core")
    _install_ida_constants()
    pair = core.riscv_lui_addi_pair(LUI_ADDI_TABLE[0x1000], LUI_ADDI_TABLE[0x1004])
    assert pair == (0xAAAA5555, 0x1004), pair


def test_riscv_lui_addi_rejects_register_mismatch_and_non_lui():
    core = _module("search.core")
    _install_ida_constants()
    lui = LUI_ADDI_TABLE[0x1000]
    # addi rd != rs (t0 vs t1): not a valid li materialization.
    bad = _Insn("addi", [_Op(1, 0, reg=5), _Op(1, 0, reg=6), _Op(5, 0x555)], size=4, ea=0x1004)
    assert core.riscv_lui_addi_pair(lui, bad) is None
    # Non-lui first instruction (x86 mov): can never fire the pair detector.
    mov = _Insn("mov", [_Op(1, 0, reg=5), _Op(5, 0xAAAA5)], size=4, ea=0x1000)
    assert core.riscv_lui_addi_pair(mov, LUI_ADDI_TABLE[0x1004]) is None


def test_search_immediate_matches_resolved_lui_addi_on_raw_riscv_blob():
    """Opaque RISC-V raw blob: no EXEC segment, no known entry point. The
    constant is materialized as lui+addi; search_immediate must match the
    RESOLVED value and report the pair addresses plus the relax note."""
    basic = _module("search.basic")
    _install_insn_fakes(basic, LUI_ADDI_TABLE)
    basic.resolve_scan_segments = lambda *a, **k: (
        [(0x1000, 0x1010)],
        "Raw blob loaded without EXEC — scanning non-exec bytes as code. "
        "Check segment perms or pass start/end to narrow.",
        "",
    )
    basic.safe_generate_disasm_line = lambda ea: "lui t0, 0xAAAA5"
    basic.ida_lines.tag_remove = lambda s: s

    captured = {}
    def _build(results, offset, limit, matches_seen, truncated, **kw):
        captured.update(results=list(results), matches=matches_seen, truncated=truncated)
        return {"ok": True, "results": list(results)}

    basic.build_response = _build
    resp = basic.search_immediate("0xaaaa5555", None, None, False, 0, 10, timeout_ms=0)
    assert resp["ok"] is True
    assert captured["matches"] == 1, captured
    assert any("lui+addi@0x1004" in line and "0xaaaa5555" in line for line in captured["results"]), captured
    assert "Raw blob loaded without EXEC" in resp["note"], resp


def test_search_constants_matches_resolved_lui_addi_pattern():
    """The lui half (0xAAAA5) and addi half (0x555) are not known constants by
    themselves; only the resolved 0xAAAA5555 is pattern-magic and must surface
    a lui+addi@ annotated row."""
    adv = _module("search.advanced")
    _install_insn_fakes(adv, LUI_ADDI_TABLE)
    adv.resolve_scan_segments = lambda *a, **k: ([(0x1000, 0x1010)], "", "")
    adv.ida_funcs.get_func_name = lambda ea: "sub_1000"
    adv.safe_generate_disasm_line = lambda ea: "lui t0, 0xAAAA5"
    adv.ida_lines.tag_remove = lambda s: s
    adv.get_cached_constant_db = dict  # no known-constant DB entries
    adv.compile_smart_pattern = lambda p, case_sensitive=False: (
        lambda s: str(p).lower() in str(s).lower()
    )
    adv.paginate_records = lambda rows, off, lim, **k: (rows, len(rows), False)

    captured = {}
    def _build(results, offset, limit, total, truncated, **kw):
        captured.update(results=list(results), total=total, truncated=truncated)
        return {"ok": True, "results": list(results)}

    adv.build_response = _build
    resp = adv.search_constants("0xaaaa5555", None, None, False, 0, 10, False, 0)
    assert resp["ok"] is True
    assert captured["total"] == 1, captured
    line = captured["results"][0]
    assert "PATTERN_0xaaaa5555" in line, line
    assert "lui+addi@0x1004" in line, line


# ---------------------------------------------------------------------------
# resolve_scan_segments: raw-blob EXEC fallback vs crisp error
# ---------------------------------------------------------------------------

class _SegFake:
    """iter_segments stand-in: exec list for require_exec=True, all for False."""

    def __init__(self, segs_exec, segs_all):
        self.segs_exec = segs_exec
        self.segs_all = segs_all

    def __call__(self, range_start=None, range_end=None, *, require_exec=True):
        return list(self.segs_exec) if require_exec else list(self.segs_all)


def test_resolve_scan_segments_raw_blob_falls_back_to_nonexec_with_note():
    core = _module("search.core")
    # No EXEC segment anywhere in the whole DB: relax to non-exec bytes + note.
    core.iter_segments = _SegFake([], [(0x1000, 0x2000)])
    segs, note, err = core.resolve_scan_segments()
    assert segs == [(0x1000, 0x2000)]
    assert note and not err
    assert "Raw blob loaded without EXEC" in note


def test_resolve_scan_segments_normal_binary_no_note():
    core = _module("search.core")
    core.iter_segments = _SegFake([(0x1000, 0x2000)], [(0x1000, 0x2000)])
    segs, note, err = core.resolve_scan_segments()
    assert segs == [(0x1000, 0x2000)]
    assert not note and not err


def test_resolve_scan_segments_range_miss_on_normal_binary_is_crisp_error():
    core = _module("search.core")

    def iter_segments(range_start=None, range_end=None, *, require_exec=True):
        if range_start is None:
            return [(0x1000, 0x2000)]  # binary HAS an EXEC segment somewhere
        return [] if require_exec else [(0x9000, 0x9100)]

    core.iter_segments = iter_segments
    segs, note, err = core.resolve_scan_segments(0x9000, 0x9100)
    assert not segs and not note and err
    assert "No executable segment in range" in err


def test_resolve_scan_segments_empty_db_is_not_silent():
    core = _module("search.core")
    core.iter_segments = _SegFake([], [])
    segs, note, err = core.resolve_scan_segments()
    # No segments at all: the relax path still fires so callers get the note
    # instead of a silent empty result.
    assert not segs and note and not err


# ---------------------------------------------------------------------------
# Router default timeout budget
# ---------------------------------------------------------------------------

def test_router_resolves_default_timeout_budget():
    pkg = _module("search")
    seen = {}

    def _capture(pattern, r0, r1, ctx, off, lim, timeout_ms):
        seen["timeout_ms"] = timeout_ms
        return {"ok": True}

    pkg.search_bytes = _capture
    # None (the default) -> bounded whole-binary budget.
    pkg.search(action="bytes", pattern="AA")
    assert seen["timeout_ms"] == pkg.DEFAULT_SEARCH_TIMEOUT_MS == 8000
    # 0 stays an explicit no-limit opt-out.
    pkg.search(action="bytes", pattern="AA", timeout_ms=0)
    assert seen["timeout_ms"] == 0
    # Explicit values are forwarded untouched.
    pkg.search(action="bytes", pattern="AA", timeout_ms=1234)
    assert seen["timeout_ms"] == 1234


# ---------------------------------------------------------------------------
# resolve_target: demangle memoization + pre-filter
# ---------------------------------------------------------------------------

def test_demangle_cached_memoizes_per_db_fingerprint():
    core = _module("search.core")
    _install_ida_constants()
    core._get_db_fingerprint = lambda: "fp-1"
    calls = []

    def _demangle_safe(name):
        calls.append(name)
        return "foo()"

    core.demangle_safe = _demangle_safe
    core._DEMANGLE_CACHE.clear()
    core._DB_FINGERPRINT = None
    assert core.demangle_cached("_Z3foov") == "foo()"
    assert core.demangle_cached("_Z3foov") == "foo()"
    assert calls == ["_Z3foov"]  # second call is a cache hit
    # A different DB fingerprint invalidates the cache.
    core._get_db_fingerprint = lambda: "fp-2"
    assert core.demangle_cached("_Z3foov") == "foo()"
    assert calls == ["_Z3foov", "_Z3foov"]


def test_resolve_target_prefilters_names_before_demangle():
    """A plain-identifier target that shares no token with a mangled name must
    not pay the demangle RPC for it (directive: pre-filter before demangling
    every name)."""
    core = _module("search.core")
    _install_ida_constants()
    core.looks_like_address = lambda t: False
    core.idc.get_name_ea_simple = lambda t: -1
    core.idautils.Names = lambda: [(0x401000, "_Z3foov")]
    core.compile_smart_pattern = lambda p, case_sensitive=False: (
        lambda s: str(p).lower() in str(s).lower()
    )
    demangled = []
    core.demangle_safe = lambda name: demangled.append(name) or "foo()"
    core._DEMANGLE_CACHE.clear()
    core._DB_FINGERPRINT = None

    ea, err, meta = core.resolve_target("aardvark")
    assert ea == -1 and err
    assert demangled == []  # no demangle RPC for an unrelated mangled name


# ---------------------------------------------------------------------------
# search_nl / search_behavior semantic degradation + expansion scoping
# ---------------------------------------------------------------------------

class _FakeIndex:
    size = 4
    _embedder = type("_E", (), {"backend": "test"})()

    def __init__(self):
        self.calls = []

    def search(self, query, top_k, threshold, address_ranges=None):
        self.calls.append((query, top_k, address_ranges))
        return [
            {"ea": "0x401000", "name": "alpha_fn", "similarity": 0.9, "score": 0.9, "signature": "alpha"}
        ]

    def refresh_from_disk(self):
        pass

    def _row_docs_for_eas(self, eas):
        return {}


class _FakeClassifier:
    _anchor_embs = {"a": [1.0]}

    def __init__(self, hits):
        self.hits = hits

    def classify(self, text, threshold, top_k, block):
        return self.hits


def test_search_nl_degraded_falls_back_to_lexical_with_note():
    """Embedding backend cannot start but the index has rows: rank lexically
    and say so, instead of refusing the search."""
    sem = _semantic()
    idx = _FakeIndex()
    sem.get_backend = lambda: (
        idx,
        None,
        "test.idb",
        "degraded — embedding backend unavailable; results ranked by lexical overlap only.",
    )
    resp = sem.search_nl("alpha behavior", mode="quick", rerank=False)
    assert resp["ok"] is True
    assert resp["degraded"].startswith("degraded")
    assert "0x401000" in resp["results"]


def test_search_nl_tolerates_legacy_three_tuple_backend():
    sem = _semantic()
    sem.get_backend = lambda: (_FakeIndex(), None, "test.idb")
    resp = sem.search_nl("alpha behavior", mode="quick", rerank=False)
    assert resp["ok"] is True
    assert "degraded" not in resp


class _WideIndex(_FakeIndex):
    def __init__(self, count):
        super().__init__()
        self._count = count

    def search(self, query, top_k, threshold, address_ranges=None):
        self.calls.append((query, top_k, address_ranges))
        return [
            {
                "ea": f"0x{0x401000 + i:x}",
                "name": f"fn_{i}",
                "similarity": 0.9,
                "score": 0.9,
                "signature": f"fn_{i}",
            }
            for i in range(self._count)
        ][:top_k]


def test_search_nl_rerank_pool_sized_to_min_of_cap_and_recall():
    """The rerank pool must be min(RERANK_MAX_CANDIDATES, candidate_limit),
    and the deadline must be handed to a reranker that accepts it."""
    import ida_pro_mcp.host.intelligence.rerank as rerank_mod

    sem = _semantic()
    idx = _WideIndex(12)
    sem.get_backend = lambda: (idx, _FakeClassifier([]), "test.idb", "")

    class _ScriptedReranker:
        _use_llama = True
        _script = [{"index": i, "score": 0.1 * (i + 1)} for i in range(8)]
        last_deadline = None

        def __init__(self):
            pass

        def rerank(self, query, documents, deadline=0.0):
            _ScriptedReranker.last_deadline = deadline
            return list(self._script)

        def status(self):
            return {"profile_name": "Test"}

    _orig_reranker = rerank_mod.Reranker
    _orig_max = rerank_mod.RERANK_MAX_CANDIDATES
    rerank_mod.Reranker = _ScriptedReranker
    rerank_mod.RERANK_MAX_CANDIDATES = 8
    try:
        resp = sem.search_nl("find crypto", limit=3, mode="quick", rerank=True)
    finally:
        rerank_mod.Reranker = _orig_reranker
        rerank_mod.RERANK_MAX_CANDIDATES = _orig_max
    assert resp["ok"] is True
    assert resp["rerank"]["applied"] is True, resp["rerank"]
    assert resp["rerank"]["pool"] == 8, resp["rerank"]  # min(8, candidate_limit=12)
    # The deadline was plumbed through to the reranker.
    assert _ScriptedReranker.last_deadline is not None


def test_search_nl_expired_rerank_deadline_skips_and_explains():
    """When the caller's search deadline is already spent, skip the rerank
    phase and report reason='timeout' instead of silently burning the budget."""
    sem = _semantic()
    idx = _WideIndex(4)
    sem.get_backend = lambda: (idx, _FakeClassifier([]), "test.idb", "")

    class _LlamaReranker:
        _use_llama = True

        def __init__(self):
            pass

        def rerank(self, query, documents, deadline=0.0):
            raise AssertionError("rerank must not run after deadline expiry")

        def status(self):
            return {"profile_name": "Test"}

    import ida_pro_mcp.host.intelligence.rerank as rerank_mod
    _orig_reranker = rerank_mod.Reranker
    rerank_mod.Reranker = _LlamaReranker
    # Capture the REAL time functions BEFORE patching. ``sem._time`` is the
    # shared ``time`` module (semantic.py does ``import time as _time``), so
    # restoring with ``_real_time.time`` where ``_real_time`` IS ``sem._time``
    # is a self-referential no-op — the patch leaked globally and froze time
    # for every later test (it hung
    # test_pending_work_is_bounded_and_never_calls_auto_wait).
    _orig_time = time.time
    _orig_monotonic = time.monotonic
    try:
        # started_at uses the first time() sample; later phases see a much
        # larger clock, so the budget is already exhausted.
        samples = {"t": 0.0}
        def _fake_time():
            now = samples["t"]
            samples["t"] = 10.0
            return now
        sem._time.time = _fake_time
        sem._time.monotonic = lambda: 100.0
        resp = sem.search_nl("find crypto", limit=3, mode="quick", rerank=True, timeout_ms=1000)
    finally:
        rerank_mod.Reranker = _orig_reranker
        sem._time.time = _orig_time
        sem._time.monotonic = _orig_monotonic
    assert resp["ok"] is True
    assert resp["rerank"]["applied"] is False
    assert resp["rerank"]["reason"] == "timeout", resp["rerank"]


def test_search_nl_expansion_scoped_to_top_recalled_eas():
    """'expand' mode must run each extra query only over the top recalled EAs
    (one (ea, ea+1) range per function) instead of re-scanning the binary."""
    sem = _semantic()
    idx = _FakeIndex()
    hits = [
        {"behavior": "crypto_symmetric", "confidence": 0.9},
        {"behavior": "network_http", "confidence": 0.9},
    ]
    sem.get_backend = lambda: (idx, _FakeClassifier(hits), "test.idb", "")
    resp = sem.search_nl("find crypto", mode="expand", rerank=False)
    assert resp["ok"] is True
    extra = [c for c in idx.calls if c[0] in ("crypto symmetric", "network http")]
    assert len(extra) == 2, idx.calls
    for _q, _top_k, address_ranges in extra:
        assert address_ranges == [(0x401000, 0x401001)], address_ranges


def test_search_nl_large_binary_caps_expansion_queries():
    """Very large indexes gate expansion to a single extra query so a behavior
    explosion cannot push the search past its deadline."""
    sem = _semantic()
    idx = _FakeIndex()
    idx.size = 20000
    hits = [
        {"behavior": "crypto_symmetric", "confidence": 0.9},
        {"behavior": "network_http", "confidence": 0.9},
    ]
    sem.get_backend = lambda: (idx, _FakeClassifier(hits), "test.idb", "")
    resp = sem.search_nl("find crypto", mode="expand", rerank=False)
    assert resp["ok"] is True
    extra = [c for c in idx.calls if c[0] in ("crypto symmetric", "network http")]
    assert len(extra) == 1, idx.calls


def test_search_behavior_skips_cold_classifier():
    """A classifier whose anchor cache was never populated cannot label
    anything; skip the up-to-200 decompile loop and say so."""
    sem = _semantic()

    class _ColdClassifier:
        _anchor_embs = {}

        def classify(self, text, threshold, top_k, block):
            raise AssertionError("cold classifier must not run")

    sys.modules["ida_pro_mcp.ida_mcp.tools.search"]._query_insight_by_tags = lambda tags, mode="or": []
    import idautils
    idautils.Functions = lambda: (_ for _ in ()).throw(AssertionError("decompile loop ran"))
    sem.get_backend = lambda: (_FakeIndex(), _ColdClassifier(), "test.idb", "")

    resp = sem.search_behavior("crypto_symmetric")
    assert resp["ok"] is True
    assert resp.get("classifier_cold") is True, resp
    assert resp.get("timed_out") is True
    assert "Classifier cold" in resp["note"], resp["note"]


def test_call_rerank_passes_deadline_when_supported():
    sem = _semantic()

    class _WithDeadline:
        def rerank(self, query, docs, deadline=0.0):
            return ("deadline", deadline)

    class _WithoutDeadline:
        def rerank(self, query, docs):
            return ("plain", None)

    got = sem._call_rerank(_WithDeadline(), "q", ["d"], 123.0)
    assert got == ("deadline", 123.0)
    got = sem._call_rerank(_WithoutDeadline(), "q", ["d"], 123.0)
    assert got == ("plain", None)


# ---------------------------------------------------------------------------
# _rescore_find_ranked embedding budget
# ---------------------------------------------------------------------------

def test_rescore_find_ranked_phrase_widens_embedding_budget():
    unified = _module("search.unified")
    unified.DEFAULT_RESCORE_TOP_N = 64
    unified.SCORE_SUBSTRING = 60.0
    seen = {}

    def _semantic_scores(pattern, pool, top_n, substring_bonus):
        seen["top_n"] = top_n
        seen["pool_len"] = len(pool)
        return [60.0] * len(pool)

    unified.semantic_scores = _semantic_scores
    ranked = [{"_sem": f"line {i}", "line": f"line {i}"} for i in range(40)]
    unified._rescore_find_ranked(ranked, "function that handles AES key schedule")
    assert seen["top_n"] == 40, seen  # phrase: near DEFAULT_RESCORE_TOP_N

    seen.clear()
    ranked = [{"_sem": f"line {i}", "line": f"line {i}"} for i in range(40)]
    unified._rescore_find_ranked(ranked, "AESKeySchedule")
    assert seen["top_n"] == 24, seen  # identifier: tighter CPU budget


# ---------------------------------------------------------------------------
# RISC-V ABI subword tokenization (support/semantic_matching)
# ---------------------------------------------------------------------------

def test_subword_tokens_riscv_abi_names():
    sm = load_support_module("semantic_matching")
    # Peripheral instances generalize across numbered units.
    assert sm._subword_tokens("uart0_init") == ["uart0", "uart", "init"]
    assert sm._subword_tokens("gpio2_set_dir") == ["gpio2", "gpio", "set", "dir"]
    assert sm._subword_tokens("spi1_transfer") == ["spi1", "spi", "transfer"]
    # Short RISC-V ABI register names stay intact.
    assert sm._subword_tokens("x5") == ["x5"]
    assert sm._subword_tokens("a0") == ["a0"]
    assert sm._subword_tokens("t6") == ["t6"]
    # Hex addresses stay intact.
    assert sm._subword_tokens("0x401000") == ["0x401000"]
    # Existing camelCase / snake_case behavior is preserved.
    assert sm._subword_tokens("getProcAddress") == ["get", "proc", "address"]
    assert sm._subword_tokens("getenv_s") == ["getenv"]


# ---------------------------------------------------------------------------
# FunctionEmbeddingIndex.search_text persisted-token hot path (host-side)
# ---------------------------------------------------------------------------

def test_search_text_uses_persisted_tokens_on_raw_riscv_firmware(tmp_path):
    """Persisted search_tokens drive the hot path (no per-row regex / per-query
    IDF) and the address-range filter is pushed into SQL via ea_int."""
    from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex

    class _BatchResult:
        def __init__(self, vector):
            self.vector = vector

    class _BatchEmbedder:
        backend = "test"
        dim = 3

        def embed_batch(self, texts):
            return [_BatchResult([0.0, 0.6, 0.8]) for _ in texts]

    index = FunctionEmbeddingIndex(str(tmp_path / "blob.embeddings.db"), _BatchEmbedder())
    index.index_many(
        [
            ("0x3f00", "uart0_init", "int uart0_init(void) { return 0; }", None),
            ("0x4100", "gpio2_set_dir", "int gpio2_set_dir(int v) { return v; }", None),
            ("0x9000", "aes_crypto", "int aes_crypto(void) { return 1; }", None),
        ]
    )

    matches = index.search_text("uart init", top_k=3)
    assert matches and matches[0]["name"] == "uart0_init", matches
    assert matches[0]["matched_tokens"], matches[0]

    scoped = index.search_text("gpio", top_k=3, address_ranges=[(0x4000, 0x5000)])
    assert {m["ea"] for m in scoped} == {"0x4100"}, scoped
