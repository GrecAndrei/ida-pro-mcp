from __future__ import annotations

import pytest
from ida_pro_mcp.capsule import CapsuleStore
from ida_pro_mcp.host.intelligence.reasoner import VulnerabilityReasoner


def test_vulnerability_reasoner_noisy_or_math():
    reasoner = VulnerabilityReasoner()

    # Test single indicator: buffer_overflow (weight=0.85) with confidence 0.5.
    # P(V) = 1 - (1 - 0.05) * (1 - 0.85 * 0.5) = 1 - 0.95 * 0.575 = 0.45375 -> 0.4538
    hits = [{"behavior": "buffer_overflow", "confidence": 0.5, "id": "hit_1"}]
    res = reasoner.reason(hits)
    assert len(res) >= 1
    mem_corr = next((h for h in res if h["claim"] == "Memory Corruption"), None)
    assert mem_corr is not None
    assert mem_corr["confidence"] == pytest.approx(0.4538, abs=1e-4)

    # Test multiple indicators: buffer_overflow (0.5) and use_after_free (0.3)
    # P(V) = 1 - 0.95 * (1 - 0.85 * 0.5) * (1 - 0.80 * 0.3) = 1 - 0.95 * 0.575 * 0.76 = 1 - 0.41515 = 0.58485 -> 0.5849
    hits_multi = [
        {"behavior": "buffer_overflow", "confidence": 0.5, "id": "hit_1"},
        {"behavior": "use_after_free", "confidence": 0.3, "id": "hit_2"},
    ]
    res_multi = reasoner.reason(hits_multi)
    mem_corr_multi = next((h for h in res_multi if h["claim"] == "Memory Corruption"), None)
    assert mem_corr_multi is not None
    assert mem_corr_multi["confidence"] == pytest.approx(0.5849, abs=1e-4)


def test_reasoner_integration_on_capsule(tmp_path):
    capsule_path = tmp_path / "reasoner_test.sideband"
    with CapsuleStore.open(capsule_path) as c:
        c.init(project_name="reasoner_project")

        # Insert some low-level findings
        c.add_behavior_hit(
            item_id="item_1",
            behavior="format_string_vuln",
            confidence=0.8,
            hit_id="hit_fmt"
        )
        c.add_evidence_card(
            claim="integer_overflow",
            claim_type="integer_overflow",
            confidence=0.6,
            card_id="card_int"
        )

        # Run reasoning via CapsuleStore API
        hypotheses = c.run_vulnerability_reasoner()
        
        # Verify result contains the expected high-level profile
        vuln = next((h for h in hypotheses if h["claim"] == "Improper Input Validation"), None)
        assert vuln is not None
        
        # Check that it got persisted as a synthesized card in the database
        db_rows = c.conn.execute(
            "SELECT * FROM evidence_cards WHERE claim_type='synthesized_vulnerability'"
        ).fetchall()
        assert len(db_rows) >= 1
        assert db_rows[0]["claim"] == "Improper Input Validation"
        assert float(db_rows[0]["confidence"]) == vuln["confidence"]

        # Run reasoning a second time, verify clean replacement and no duplication
        hypotheses_2 = c.run_vulnerability_reasoner()
        db_rows_2 = c.conn.execute(
            "SELECT * FROM evidence_cards WHERE claim_type='synthesized_vulnerability'"
        ).fetchall()
        assert len(db_rows_2) == len(db_rows)


def test_vulnerability_reasoner_edge_cases():
    reasoner = VulnerabilityReasoner()

    # 1. Empty behavior hits and evidence cards -> empty output
    assert reasoner.reason([], []) == []

    # 2. Confidence extremes
    # Confidence = 0.0 should not trigger anything above background leak
    hits_zero = [{"behavior": "buffer_overflow", "confidence": 0.0}]
    assert reasoner.reason(hits_zero, []) == []

    # Confidence = 1.0 should trigger maximum value
    hits_max = [{"behavior": "buffer_overflow", "confidence": 1.0}]
    res = reasoner.reason(hits_max)
    mem_corr = next((h for h in res if h["claim"] == "Memory Corruption"), None)
    assert mem_corr is not None
    # P(V) = 1 - 0.95 * (1 - 0.85 * 1.0) = 1 - 0.95 * 0.15 = 1 - 0.1425 = 0.8575
    assert mem_corr["confidence"] == pytest.approx(0.8575, abs=1e-4)

    # 3. Invalid/negative confidence should be treated as 0 or handled gracefully
    hits_neg = [{"behavior": "buffer_overflow", "confidence": -0.5}]
    res_neg = reasoner.reason(hits_neg)
    # Since confidence is <= 0, it shouldn't produce high level claim
    assert not any(h["confidence"] > 0.1 for h in res_neg)

