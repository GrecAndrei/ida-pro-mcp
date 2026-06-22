from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock

from ida_pro_mcp.host.intelligence.crystallizer import AgentMacroCrystallizer
from ida_pro_mcp.host.session import SessionManager
from ida_pro_mcp.host.server_session import ServerSessionMixin
from ida_pro_mcp.host.errors import MCPError


class TestAgentMacroCrystallizer(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_calculate_step_reward(self):
        # 1. Blackboard writes -> high reward
        r_bb = AgentMacroCrystallizer.calculate_step_reward({
            "tool": "blackboard",
            "action": "write",
            "result": "ok"
        })
        self.assertEqual(r_bb, 5.0)

        # 2. Hypothesis confirmation -> very high reward
        r_hyp = AgentMacroCrystallizer.calculate_step_reward({
            "tool": "session",
            "action": "confirm_hypothesis",
            "result": "success"
        })
        self.assertEqual(r_hyp, 10.0)

        # 3. Appending notes -> medium reward
        r_note = AgentMacroCrystallizer.calculate_step_reward({
            "tool": "session",
            "action": "add_note",
            "result": "note saved"
        })
        self.assertEqual(r_note, 3.0)

        # 4. Normal action with successful result -> 1.5
        r_success = AgentMacroCrystallizer.calculate_step_reward({
            "tool": "search",
            "action": "find",
            "result": '{"ok": true, "matches": [1, 2]}'
        })
        self.assertEqual(r_success, 1.5)

        # 5. Normal action with failure result -> 0.1
        r_fail = AgentMacroCrystallizer.calculate_step_reward({
            "tool": "search",
            "action": "find",
            "result": "error: timeout"
        })
        self.assertEqual(r_fail, 0.1)

    def test_mine_sequences_basic(self):
        # Repeating pattern: search.api -> code.xrefs_to (appears 3 times)
        # Other random actions in between
        activity_log = [
            {"tool": "search", "action": "api", "result": "ok"},
            {"tool": "code", "action": "xrefs_to", "result": "ok"},
            {"tool": "search", "action": "decompiled", "result": "ok"},
            {"tool": "search", "action": "api", "result": "ok"},
            {"tool": "code", "action": "xrefs_to", "result": "ok"},
            {"tool": "blackboard", "action": "write", "result": "ok"},  # High value step
            {"tool": "search", "action": "api", "result": "ok"},
            {"tool": "code", "action": "xrefs_to", "result": "ok"},
        ]

        ranked = AgentMacroCrystallizer.mine_sequences(activity_log, min_support=2)
        self.assertTrue(len(ranked) > 0)

        # The sequence ("search.api", "code.xrefs_to") should be identified with count=3
        top = ranked[0]
        self.assertEqual(top["sequence"], ["search.api", "code.xrefs_to"])
        self.assertEqual(top["count"], 3)
        self.assertTrue(top["score"] > 0)

    def test_synthesize_macro(self):
        seq = ["search.api", "code.xrefs_to", "blackboard.write"]
        macro = AgentMacroCrystallizer.synthesize_macro(seq)

        self.assertEqual(macro["name"], "Mined Macro: Search & Code & Blackboard")
        self.assertIn("search.api -> code.xrefs_to -> blackboard.write", macro["description"])
        self.assertEqual(macro["steps"], seq)
        self.assertIn("auto-crystallized", macro["tags"])

    def test_crystallize_from_log_integration(self):
        session_mgr = SessionManager(self.tmpdir)
        session = session_mgr.create_session(binary_path=os.path.join(self.tmpdir, "dummy.bin"))
        sid = session.session_id

        # Log some activities to build a repeating high-value sequence:
        # search.api -> code.xrefs_to -> blackboard.write (appears 2 times)
        for _ in range(2):
            session_mgr.log_activity(sid, "search", "api", "found function")
            session_mgr.log_activity(sid, "code", "xrefs_to", "referenced at 0x401000")
            session_mgr.log_activity(sid, "blackboard", "write", "registered finding")

        crystallizer = AgentMacroCrystallizer()
        res = crystallizer.crystallize_from_log(session_mgr, sid, min_support=2)

        self.assertTrue(res.get("ok"))
        self.assertEqual(res.get("frequency"), 2)
        self.assertIn("Search", res.get("skill", {}).get("name"))

        # Verify skill was saved to local metadata and is listable
        skills = session_mgr.list_skills(sid)
        self.assertTrue(skills.get("ok"))
        self.assertIn(res["skill_id"], skills.get("local_skills", {}))

    def test_crystallize_mined_macros_via_server(self):
        class DummyServer(ServerSessionMixin):
            def __init__(self, session_mgr):
                self.session_mgr = session_mgr
                self.current_session = None
                self.session_runtimes = {}
                self._session_capsules = {}
                self.call_tool = MagicMock()

        session_mgr = SessionManager(self.tmpdir)
        session = session_mgr.create_session(binary_path=os.path.join(self.tmpdir, "dummy.bin"))
        sid = session.session_id

        # Log some activities
        for _ in range(2):
            session_mgr.log_activity(sid, "search", "api", "ok")
            session_mgr.log_activity(sid, "code", "xrefs_to", "ok")

        srv = DummyServer(session_mgr)
        res = srv._handle_session({
            "action": "crystallize_mined_macros",
            "session_id": sid,
            "min_support": 2
        })

        self.assertTrue(res.get("ok"))
        self.assertEqual(res.get("frequency"), 2)
        self.assertEqual(res.get("sequence"), ["search.api", "code.xrefs_to"])


if __name__ == "__main__":
    unittest.main()
