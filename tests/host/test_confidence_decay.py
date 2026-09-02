"""Tests for blackboard confidence decay and store operations.

Covers host-side logic that doesn't require a live IDA session.
"""
import contextlib
import math
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore

_FAKE_NOW = 1_000_000_000.0


class TestConfidenceDecay(unittest.TestCase):
    """Confidence decay on stale blackboard entries."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_bb.db")
        self.store = BlackboardStore(db_path=self.db_path)

    def tearDown(self):
        with contextlib.suppress(Exception):
            self.store.close()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_decay_reduces_confidence(self):
        eid = self.store.write(title="test entry", content="test", confidence=0.9)
        # Set updated_at to 30 days ago
        import sqlite3
        from contextlib import closing
        with closing(self.store._conn()) as conn:
            conn.execute("UPDATE blackboard SET updated_at=? WHERE id=?",
                         (_FAKE_NOW - 30 * 86400, eid))
            conn.commit()
        # Decay with 14-day half-life
        with mock.patch(
            "ida_pro_mcp.host.stores.blackboard_store.time.time",
            return_value=_FAKE_NOW,
        ):
            updated = self.store.decay_stale_confidence(half_life_days=14.0)
        self.assertGreater(updated, 0)
        entry = self.store.read(eid)
        self.assertLess(entry["confidence"], 0.9)
        # After 30 days with 14-day half-life: 0.9 * exp(-30/14 * ln2) ≈ 0.9 * 0.23 ≈ 0.21
        self.assertLess(entry["confidence"], 0.5)

    def test_decay_preserves_recent_entries(self):
        eid = self.store.write(title="recent entry", content="test", confidence=0.9)
        # Don't modify updated_at — it's recent
        with mock.patch(
            "ida_pro_mcp.host.stores.blackboard_store.time.time",
            return_value=_FAKE_NOW,
        ):
            self.store.decay_stale_confidence(half_life_days=14.0)
        # Should not decay entries less than 1 day old
        entry = self.store.read(eid)
        self.assertAlmostEqual(entry["confidence"], 0.9, places=1)

    def test_decay_respects_min_confidence(self):
        eid = self.store.write(title="low conf", content="test", confidence=0.15)
        import sqlite3
        from contextlib import closing
        with closing(self.store._conn()) as conn:
            conn.execute("UPDATE blackboard SET updated_at=? WHERE id=?",
                         (_FAKE_NOW - 60 * 86400, eid))
            conn.commit()
        self.store.decay_stale_confidence(half_life_days=14.0, min_confidence=0.1)
        entry = self.store.read(eid)
        self.assertGreaterEqual(entry["confidence"], 0.1)

    def test_decay_slower_for_calibrated_entries(self):
        # Create two entries, one calibrated, one not
        eid_normal = self.store.write(title="normal", content="test", confidence=0.8)
        eid_calibrated = self.store.write(title="calibrated", content="test", confidence=0.8)
        # Mark one as calibrated
        self.store.update(eid_calibrated, calibrated=1)
        # Set both to 20 days ago
        import sqlite3
        from contextlib import closing
        with closing(self.store._conn()) as conn:
            old_time = _FAKE_NOW - 20 * 86400
            conn.execute("UPDATE blackboard SET updated_at=? WHERE id=?", (old_time, eid_normal))
            conn.execute("UPDATE blackboard SET updated_at=? WHERE id=?", (old_time, eid_calibrated))
            conn.commit()
        with mock.patch(
            "ida_pro_mcp.host.stores.blackboard_store.time.time",
            return_value=_FAKE_NOW,
        ):
            self.store.decay_stale_confidence(half_life_days=14.0)
        normal_entry = self.store.read(eid_normal)
        calibrated_entry = self.store.read(eid_calibrated)
        # Calibrated should have higher confidence (decays slower)
        self.assertGreater(calibrated_entry["confidence"], normal_entry["confidence"])


class TestBlackboardStoreBasics(unittest.TestCase):
    """Basic blackboard store operations."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_bb.db")
        self.store = BlackboardStore(db_path=self.db_path)

    def tearDown(self):
        with contextlib.suppress(Exception):
            self.store.close()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_write_and_read(self):
        eid = self.store.write(title="test", content="content", confidence=0.7)
        entry = self.store.read(eid)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["title"], "test")
        self.assertAlmostEqual(entry["confidence"], 0.7, places=2)

    def test_list_with_min_confidence(self):
        self.store.write(title="low", content="c", confidence=0.2)
        self.store.write(title="high", content="c", confidence=0.9)
        entries = self.store.list(min_confidence=0.5)
        self.assertTrue(all(e["confidence"] >= 0.5 for e in entries))

    def test_update_confidence(self):
        eid = self.store.write(title="test", content="c", confidence=0.5)
        self.store.update(eid, confidence=0.8)
        entry = self.store.read(eid)
        self.assertAlmostEqual(entry["confidence"], 0.8, places=2)

    def test_contradict(self):
        eid = self.store.write(title="test", content="c", confidence=0.8)
        ok = self.store.contradict(eid, reason="wrong")
        self.assertTrue(ok)
        entry = self.store.read(eid)
        self.assertTrue(entry.get("contradicted"))

    def test_mark_resolved(self):
        eid = self.store.write(title="test", content="c", confidence=0.8)
        ok = self.store.mark_resolved(eid)
        self.assertTrue(ok)
        entry = self.store.read(eid)
        self.assertTrue(entry.get("resolved"))

    def test_campaign_summary(self):
        self.store.write(title="a", content="c", confidence=0.8, category="vuln")
        self.store.write(title="b", content="c", confidence=0.5, category="crypto")
        summary = self.store.campaign_summary()
        self.assertIn("total_entries", summary)
        self.assertGreaterEqual(summary["total_entries"], 2)


if __name__ == "__main__":
    unittest.main()
