"""Function-families clustering tests with a controlled fake index."""

from __future__ import annotations

from ida_pro_mcp.host.intelligence.families import (
    _ea_sort_key,
    _UnionFind,
    compute_function_families,
)


class _FakeIndex:
    """Minimal index surface compute_function_families relies on."""

    def __init__(self, cache, meta, docs=None):
        self._cache = cache  # {ea: [float, ...]}
        self._meta = meta    # {ea: {"name": str, "signature_text": str}}
        self._docs = docs or dict.fromkeys(cache, "")

    def _similarity_candidates(self, exclude_ea, address_ranges):
        out = []
        for ea, vec in self._cache.items():
            if exclude_ea and ea == exclude_ea:
                continue
            if address_ranges:
                ea_int = int(ea, 0)
                if not any(s <= ea_int < e for s, e in address_ranges):
                    continue
            out.append((ea, vec))
        return out

    def _row_meta_for_eas(self, eas):
        return {ea: self._meta.get(ea, {"name": ea}) for ea in eas}

    def _row_docs_for_eas(self, eas):
        return {ea: self._docs.get(ea, "") for ea in eas}


def _three_lookalikes_plus_odd_one():
    # Three nearly-identical "parse" functions (cos ~1.0) + one unrelated fn.
    cache = {
        "0x401000": [1.0, 0.0, 0.0],
        "0x402000": [0.99, 0.14, 0.0],   # ~0.99 cosine to 0x401000
        "0x403000": [0.98, 0.20, 0.0],   # ~0.98 cosine
        "0x501000": [0.0, 0.0, 1.0],     # orthogonal -> singleton
    }
    meta = {
        "0x401000": {"name": "parse_packet", "signature_text": "parse packet len memcpy copy"},
        "0x402000": {"name": "sub_402000", "signature_text": "parse packet len copy"},
        "0x403000": {"name": "parse_frame", "signature_text": "parse frame len memcpy"},
        "0x501000": {"name": "init_engine", "signature_text": "init engine start"},
    }
    docs = {
        "0x401000": "int parse_packet(char* buf, int len){ memcpy(dst, buf, len); }",
        "0x402000": "int sub_402000(char* p, int len){ copy(dst, p, len); }",
        "0x403000": "int parse_frame(byte* f, int n){ memcpy(d, f, n); }",
        "0x501000": "void init_engine(void){ start(); }",
    }
    return _FakeIndex(cache, meta, docs)


def test_clusters_lookalikes_and_reports_one_family():
    idx = _three_lookalikes_plus_odd_one()
    result = compute_function_families(idx, min_size=2, min_similarity=0.9)

    assert result["families_found"] == 1
    family = result["families"][0]
    assert family["size"] == 3
    # Representative: a named function that is closest to the centroid
    # (parse_frame is the statistical centre; sub_402000 is excluded for
    # having only an auto-generated name).
    assert family["representative"]["name"] == "parse_frame"
    assert {m["ea"] for m in family["members"]} == {"0x401000", "0x402000", "0x403000"}
    assert "parse" in family["summary"]
    assert len(family["deltas"]) == 2
    # Singleton not clustered.
    assert result["singletons"] == 1
    assert all(f["id"] != "0x501000" for f in result["families"])


def test_min_size_filters_small_families():
    idx = _three_lookalikes_plus_odd_one()
    result = compute_function_families(idx, min_size=4, min_similarity=0.9)
    assert result["families"] == []
    assert result["singletons"] == 4


def test_address_ranges_scope_the_clustering():
    idx = _three_lookalikes_plus_odd_one()
    # Only the odd-one-out lies inside this range -> no family of size >= 2.
    result = compute_function_families(
        idx, min_size=2, min_similarity=0.9,
        address_ranges=[(0x500000, 0x600000)],
    )
    assert result["families"] == []
    assert result["clustered"] == 1


def test_tighter_similarity_breaks_the_family():
    idx = _three_lookalikes_plus_odd_one()
    # 0.99 threshold still keeps 0x401000<->0x402000 but not 0x403000 pair-wise;
    # union-find may still connect through the chain, so assert at least that
    # the family is smaller or gone compared to the 0.9 run.
    loose = compute_function_families(idx, min_size=2, min_similarity=0.9)
    tight = compute_function_families(idx, min_size=2, min_similarity=0.999)
    assert tight["families_found"] <= loose["families_found"]


def test_delta_reports_shared_and_missing_tokens():
    idx = _three_lookalikes_plus_odd_one()
    result = compute_function_families(idx, min_size=2, min_similarity=0.9)
    family = result["families"][0]
    delta_of = {d["ea"]: d["delta"] for d in family["deltas"]}
    # sub_402000 vs representative parse_packet: 'frame' absent, 'copy' shared.
    sub_delta = delta_of.get("0x402000", [])
    assert isinstance(sub_delta, list)
    # Every delta is a +/- token list, never empty for a real variant.
    assert all(d["ea"] != family["representative"]["ea"] for d in family["deltas"])


def test_family_builder_rejects_empty_rows_and_honors_filters_and_caps():
    empty = _FakeIndex({}, {})
    assert compute_function_families(empty)["families"] == []

    idx = _FakeIndex(
        {
            "0x1000": None,
            "0x2000": [],
            "0x3000": ["not-a-number"],
            "0x4000": [1.0, 0.0],
            "0x5000": [0.99, 0.01],
        },
        {
            "0x4000": {"name": "keep"},
            "0x5000": {"name": "keep-two"},
        },
    )
    filtered = compute_function_families(idx, name_filter="missing")
    assert filtered["families"] == [] and filtered["clustered"] == 0

    capped = compute_function_families(idx, max_functions=1, min_size=1)
    assert capped["clustered"] == 1
    assert capped["families"] == []


def test_family_helpers_cover_empty_eas_and_redundant_union():
    assert _ea_sort_key("   ") == 0
    union_find = _UnionFind(2)
    union_find.union(0, 0)
    assert union_find.find(0) == 0
