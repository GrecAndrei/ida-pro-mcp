#!/usr/bin/env python3
import os
import sys
import tempfile
import shutil
import unittest

_project_root = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, _project_root)
sys.path.insert(0, os.path.join(_project_root, "src"))

from ida_mcp_stdio import SessionManager, IDAMCPServer


class TestEvidenceBootstrapManager(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mgr = SessionManager(self.tmpdir)
        self.binary = os.path.join(self.tmpdir, "sample.bin")
        with open(self.binary, "wb") as f:
            f.write(b"\x00" * 128)
        self.session = self.mgr.create_session(self.binary)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_bootstrap_init_and_status(self):
        init_res = self.mgr.bootstrap_init(self.session.session_id)
        self.assertTrue(init_res.get("ok"))
        self.assertTrue(init_res.get("initialized"))
        self.assertEqual(init_res.get("policies"), 12)

        status = self.mgr.bootstrap_status(self.session.session_id)
        self.assertTrue(status.get("ok"))
        self.assertTrue(status.get("initialized"))
        self.assertEqual(status.get("policy_count"), 12)

    def test_tournament_and_blend(self):
        self.mgr.bootstrap_init(self.session.session_id)
        run = self.mgr.bootstrap_run_tournament(self.session.session_id, rounds=250, seed=42)
        self.assertTrue(run.get("ok"))
        self.assertEqual(run.get("rounds"), 250)
        self.assertEqual(len(run.get("top_policies", [])), 5)

        blend = self.mgr.bootstrap_compute_blend(self.session.session_id, session_samples=50)
        self.assertTrue(blend.get("ok"))
        weights = blend.get("weights", {})
        self.assertAlmostEqual(weights.get("bootstrap", 0.0) + weights.get("session", 0.0), 1.0, places=5)

    def test_strategy_uses_bootstrap_blend(self):
        self.mgr.bootstrap_init(self.session.session_id, overwrite=True)
        self.mgr.bootstrap_run_tournament(self.session.session_id, rounds=300, seed=11)
        self.mgr.crystallize_skill(
            self.session.session_id,
            name="Decrypt strings",
            description="Analyze decoding and string reconstruction",
            steps=["find decode", "trace call graph"],
            tags=["crypto", "strings"],
        )
        self.mgr.rate_skill(self.session.session_id, "skill_decrypt_strings", reward=0.9)
        out = self.mgr.suggest_strategy(self.session.session_id, context="crypto string decoding")
        self.assertTrue(out.get("ok"))
        self.assertIn("bootstrap_prior", out)
        suggestions = out.get("suggestions", [])
        self.assertGreaterEqual(len(suggestions), 1)
        top = suggestions[0]
        self.assertIn("blended_score", top)
        self.assertIn("blend_weights", top)

        dash = self.mgr.dashboard(self.session.session_id)
        self.assertTrue(dash.get("ok"))
        self.assertTrue(dash.get("bootstrap", {}).get("initialized"))


class TestEvidenceBootstrapRouting(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.binary = os.path.join(self.tmpdir, "sample.bin")
        with open(self.binary, "wb") as f:
            f.write(b"\x90" * 256)
        self._orig_policy_mode = os.environ.get("IDA_MCP_POLICY_MODE")
        self._orig_rate_per_tool = os.environ.get("IDA_MCP_RATE_LIMIT_PER_TOOL")
        self._orig_rate_global = os.environ.get("IDA_MCP_RATE_LIMIT_GLOBAL")
        self._orig_rate_burst = os.environ.get("IDA_MCP_RATE_LIMIT_BURST")
        os.environ["IDA_MCP_POLICY_MODE"] = "permissive"
        os.environ["IDA_MCP_RATE_LIMIT_PER_TOOL"] = "10000"
        os.environ["IDA_MCP_RATE_LIMIT_GLOBAL"] = "10000"
        os.environ["IDA_MCP_RATE_LIMIT_BURST"] = "10000"
        self.server = IDAMCPServer()
        create = self.server._execute_tool("session", {"action": "create", "binary_path": self.binary})
        assert create.get("ok"), create
        self.sid = create["session"]["session_id"]

    def tearDown(self):
        for var, orig in [
            ("IDA_MCP_POLICY_MODE", self._orig_policy_mode),
            ("IDA_MCP_RATE_LIMIT_PER_TOOL", self._orig_rate_per_tool),
            ("IDA_MCP_RATE_LIMIT_GLOBAL", self._orig_rate_global),
            ("IDA_MCP_RATE_LIMIT_BURST", self._orig_rate_burst),
        ]:
            if orig is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = orig
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_route_bootstrap_actions(self):
        res1 = self.server._execute_tool("session", {"action": "bootstrap_init", "session_id": self.sid})
        self.assertTrue(res1.get("ok"))

        res2 = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_run_tournament",
                "session_id": self.sid,
                "rounds": 120,
                "seed": 7,
            },
        )
        self.assertTrue(res2.get("ok"))
        self.assertEqual(res2.get("rounds"), 120)

        res3 = self.server._execute_tool(
            "session",
            {"action": "bootstrap_compute_blend", "session_id": self.sid, "session_samples": 25},
        )
        self.assertTrue(res3.get("ok"))

        res4 = self.server._execute_tool("session", {"action": "bootstrap_status", "session_id": self.sid})
        self.assertTrue(res4.get("ok"))
        self.assertTrue(res4.get("initialized"))

        res5 = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_ingest_outcome",
                "session_id": self.sid,
                "predicted": 0.73,
                "observed": 1,
                "delay_seconds": 12,
            },
        )
        self.assertTrue(res5.get("ok"))
        self.assertIn("brier", res5)

    def test_predictor_contains_blended_confidence(self):
        self.server._execute_tool("session", {"action": "bootstrap_init", "session_id": self.sid})
        self.server._execute_tool(
            "session",
            {"action": "bootstrap_run_tournament", "session_id": self.sid, "rounds": 120, "seed": 17},
        )
        self.server._execute_tool(
            "session",
            {
                "action": "crystallize_skill",
                "session_id": self.sid,
                "name": "Beacon triage",
                "description": "Triage beacon and C2 behaviors",
                "steps": ["strings", "xrefs", "network"],
                "tags": ["network", "c2"],
            },
        )
        self.server._execute_tool(
            "session",
            {
                "action": "log_activity",
                "session_id": self.sid,
                "tool": "search",
                "activity_action": "find",
                "result": "beacon",
            },
        )
        out = self.server._execute_tool(
            "predictor",
            {
                "action": "suggest_next_tool",
                "session_id": self.sid,
                "context": "network beacon c2",
                "limit": 3,
            },
        )
        self.assertTrue(out.get("ok"))
        self.assertIn("bootstrap_prior", out)
        self.assertIn("strategy_confidence", out)
        if out.get("suggestions"):
            self.assertIn("blended_confidence", out["suggestions"][0])

    def test_predictor_recommend_bundle(self):
        self.server._execute_tool("session", {"action": "bootstrap_init", "session_id": self.sid})
        self.server._execute_tool(
            "session",
            {
                "action": "log_activity",
                "session_id": self.sid,
                "tool": "search",
                "activity_action": "find",
                "result": "http beacon",
            },
        )
        out = self.server._execute_tool(
            "predictor",
            {
                "action": "recommend_bundle",
                "session_id": self.sid,
                "context": "beacon triage",
                "limit": 3,
            },
        )
        self.assertTrue(out.get("ok"))
        self.assertEqual(out.get("action"), "recommend_bundle")
        bundle = out.get("bundle", {})
        self.assertIn("tool_suggestions", bundle)
        self.assertIn("focus_pivots", bundle)
        self.assertIn("address_suggestions", bundle)
        self.assertIn("stall_risk", bundle)

    def test_predictor_suggest_focus_exposes_embedding_focus_field(self):
        out = self.server._execute_tool(
            "predictor",
            {
                "action": "suggest_focus",
                "session_id": self.sid,
                "context": "auth parser crypto",
                "limit": 3,
            },
        )
        self.assertTrue(out.get("ok"))
        self.assertIn("embedding_focus", out)

    def test_dispute_lifecycle(self):
        self.server._execute_tool("session", {"action": "bootstrap_init", "session_id": self.sid})
        opened = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_open_dispute",
                "session_id": self.sid,
                "claim_id": "claim-42",
                "predicted": 0.81,
                "reason": "conflicting trace evidence",
            },
        )
        self.assertTrue(opened.get("ok"))
        did = opened["dispute"]["dispute_id"]

        listed = self.server._execute_tool(
            "session", {"action": "bootstrap_list_disputes", "session_id": self.sid, "status": "open"}
        )
        self.assertTrue(listed.get("ok"))
        self.assertGreaterEqual(listed.get("count", 0), 1)

        resolved = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_resolve_dispute",
                "session_id": self.sid,
                "dispute_id": did,
                "observed": 0,
                "delay_seconds": 60,
            },
        )
        self.assertTrue(resolved.get("ok"))
        self.assertEqual(resolved.get("dispute", {}).get("status"), "resolved")

        summary = self.server._execute_tool(
            "session",
            {"action": "bootstrap_summary", "session_id": self.sid},
        )
        self.assertTrue(summary.get("ok"))
        self.assertTrue(summary.get("initialized"))
        self.assertIn("calibration", summary)
        self.assertIn("disputes", summary)

    def test_snapshot_and_drift_workflow(self):
        self.server._execute_tool("session", {"action": "bootstrap_init", "session_id": self.sid, "overwrite": True})
        self.server._execute_tool(
            "session",
            {"action": "bootstrap_run_tournament", "session_id": self.sid, "rounds": 150, "seed": 44},
        )

        s1 = self.server._execute_tool(
            "session",
            {"action": "bootstrap_snapshot", "session_id": self.sid, "name": "before"},
        )
        self.assertTrue(s1.get("ok"))

        sim = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_simulate_batch",
                "session_id": self.sid,
                "n": 100,
                "seed": 9,
                "positive_rate": 0.62,
            },
        )
        self.assertTrue(sim.get("ok"))

        s2 = self.server._execute_tool(
            "session",
            {"action": "bootstrap_snapshot", "session_id": self.sid, "name": "after"},
        )
        self.assertTrue(s2.get("ok"))

        listed = self.server._execute_tool(
            "session",
            {"action": "bootstrap_list_snapshots", "session_id": self.sid, "limit": 10, "offset": 0},
        )
        self.assertTrue(listed.get("ok"))
        self.assertGreaterEqual(listed.get("count", 0), 2)

        drift = self.server._execute_tool(
            "session",
            {"action": "bootstrap_drift_report", "session_id": self.sid, "window": 2},
        )
        self.assertTrue(drift.get("ok"))
        self.assertTrue(drift.get("enough_data"))
        self.assertIn("drift", drift)

    def test_export_and_prune_metrics(self):
        self.server._execute_tool("session", {"action": "bootstrap_init", "session_id": self.sid, "overwrite": True})
        self.server._execute_tool(
            "session",
            {"action": "bootstrap_simulate_batch", "session_id": self.sid, "n": 120, "seed": 3, "positive_rate": 0.55},
        )
        for i in range(5):
            self.server._execute_tool(
                "session",
                {"action": "bootstrap_snapshot", "session_id": self.sid, "name": f"snap-{i}"},
            )

        exported = self.server._execute_tool(
            "session",
            {"action": "bootstrap_export_metrics", "session_id": self.sid},
        )
        self.assertTrue(exported.get("ok"))
        self.assertIn("series", exported)

        pruned = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_prune_data",
                "session_id": self.sid,
                "max_outcomes": 50,
                "max_disputes": 20,
                "max_snapshots": 3,
            },
        )
        self.assertTrue(pruned.get("ok"))
        self.assertLessEqual(pruned.get("after", {}).get("outcomes", 0), 50)
        self.assertLessEqual(pruned.get("after", {}).get("metric_snapshots", 0), 3)

        detailed = self.server._execute_tool(
            "session",
            {"action": "bootstrap_summary_detailed", "session_id": self.sid, "top_policies": 5},
        )
        self.assertTrue(detailed.get("ok"))
        self.assertIn("policy_diagnostics", detailed)

        calib = self.server._execute_tool(
            "session",
            {"action": "bootstrap_calibration_report", "session_id": self.sid, "min_bin_n": 1},
        )
        self.assertTrue(calib.get("ok"))
        self.assertIn("ece", calib)

        filt = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_export_metrics",
                "session_id": self.sid,
                "status": "resolved",
                "limit": 25,
            },
        )
        self.assertTrue(filt.get("ok"))
        self.assertIn("filters", filt)

    def test_baseline_and_alert_evaluation(self):
        self.server._execute_tool("session", {"action": "bootstrap_init", "session_id": self.sid, "overwrite": True})
        self.server._execute_tool(
            "session",
            {"action": "bootstrap_run_tournament", "session_id": self.sid, "rounds": 500, "seed": 1234},
        )
        for i in range(15):
            self.server._execute_tool(
                "session",
                {
                    "action": "bootstrap_simulate_batch",
                    "session_id": self.sid,
                    "n": 20,
                    "seed": i + 1,
                    "positive_rate": 0.5,
                },
            )
            self.server._execute_tool(
                "session",
                {"action": "bootstrap_snapshot", "session_id": self.sid, "name": f"b{i}"},
            )

        baseline = self.server._execute_tool(
            "session",
            {"action": "bootstrap_update_baseline", "session_id": self.sid, "window": 10, "percentile": 95.0},
        )
        self.assertTrue(baseline.get("ok"))
        self.assertTrue(baseline.get("enough_data"))

        alerts = self.server._execute_tool(
            "session",
            {"action": "bootstrap_evaluate_alerts", "session_id": self.sid, "window": 10},
        )
        self.assertTrue(alerts.get("ok"))
        self.assertIn("severity", alerts)
        self.assertIn("alerts", alerts)

        plan = self.server._execute_tool(
            "session",
            {"action": "bootstrap_mitigation_plan", "session_id": self.sid, "window": 10},
        )
        self.assertTrue(plan.get("ok"))
        self.assertIn("actions", plan)

        dry = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_apply_mitigation",
                "session_id": self.sid,
                "window": 10,
                "max_actions": 3,
                "dry_run": True,
            },
        )
        self.assertTrue(dry.get("ok"))
        self.assertTrue(dry.get("dry_run"))

        live = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_apply_mitigation",
                "session_id": self.sid,
                "window": 10,
                "max_actions": 2,
            },
        )
        self.assertTrue(live.get("ok"))
        self.assertIn("post_eval", live)

        hist = self.server._execute_tool(
            "session",
            {"action": "bootstrap_mitigation_history", "session_id": self.sid, "limit": 20, "offset": 0},
        )
        self.assertTrue(hist.get("ok"))
        self.assertGreaterEqual(hist.get("count", 0), 1)

        eff = self.server._execute_tool(
            "session",
            {"action": "bootstrap_mitigation_effectiveness", "session_id": self.sid, "window": 20},
        )
        self.assertTrue(eff.get("ok"))
        self.assertIn("effectiveness_score", eff)

        rw_dry = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_policy_reweight",
                "session_id": self.sid,
                "window": 20,
                "max_shift": 0.05,
                "dry_run": True,
            },
        )
        self.assertTrue(rw_dry.get("ok"))
        self.assertTrue(rw_dry.get("dry_run"))

        rw_live = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_policy_reweight",
                "session_id": self.sid,
                "window": 20,
                "max_shift": 0.05,
            },
        )
        self.assertTrue(rw_live.get("ok"))
        self.assertIn("updates", rw_live)

        rwh = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_policy_reweight_history",
                "session_id": self.sid,
                "limit": 10,
                "offset": 0,
            },
        )
        self.assertTrue(rwh.get("ok"))
        self.assertGreaterEqual(rwh.get("count", 0), 1)

        auto = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_autopilot",
                "session_id": self.sid,
                "window": 20,
                "dry_run": True,
            },
        )
        self.assertTrue(auto.get("ok"))
        self.assertTrue(auto.get("dry_run"))

        setp = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_set_autopilot_policy",
                "session_id": self.sid,
                "cooldown_seconds": 1,
                "daily_budget": 3,
                "max_live_actions": 2,
                "rollback_on_regression": True,
            },
        )
        self.assertTrue(setp.get("ok"))

        getp = self.server._execute_tool(
            "session",
            {"action": "bootstrap_get_autopilot_policy", "session_id": self.sid},
        )
        self.assertTrue(getp.get("ok"))
        self.assertEqual(getp.get("policy", {}).get("daily_budget"), 3)

        live1 = self.server._execute_tool(
            "session",
            {"action": "bootstrap_autopilot", "session_id": self.sid, "window": 20},
        )
        self.assertTrue(live1.get("ok"))
        live2 = self.server._execute_tool(
            "session",
            {"action": "bootstrap_autopilot", "session_id": self.sid, "window": 20},
        )
        self.assertTrue(live2.get("ok"))
        self.assertTrue(live2.get("blocked"))
        self.assertEqual(live2.get("reason"), "cooldown_active")

        rb = self.server._execute_tool(
            "session",
            {"action": "bootstrap_rollback_last_reweight", "session_id": self.sid},
        )
        self.assertTrue(rb.get("ok"))

        ps = self.server._execute_tool(
            "session",
            {"action": "bootstrap_plan_status", "session_id": self.sid},
        )
        self.assertTrue(ps.get("ok"))
        self.assertIn("overall", ps)
        self.assertIn("phases", ps)

        rg = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_readiness_gate",
                "session_id": self.sid,
                "min_tournament_rounds": 1,
                "min_snapshots": 1,
                "min_outcomes": 1,
                "max_ece": 1.0,
                "max_open_disputes": 1000,
            },
        )
        self.assertTrue(rg.get("ok"))
        self.assertIn("readiness", rg)
        self.assertIn("gates", rg)

        rr = self.server._execute_tool(
            "session",
            {"action": "bootstrap_record_readiness", "session_id": self.sid, "tag": "smoke"},
        )
        self.assertTrue(rr.get("ok"))

        rh = self.server._execute_tool(
            "session",
            {"action": "bootstrap_readiness_history", "session_id": self.sid, "limit": 20, "offset": 0},
        )
        self.assertTrue(rh.get("ok"))
        self.assertGreaterEqual(rh.get("count", 0), 1)

        rt = self.server._execute_tool(
            "session",
            {"action": "bootstrap_readiness_trend", "session_id": self.sid, "window": 2},
        )
        self.assertTrue(rt.get("ok"))
        self.assertIn("enough_data", rt)

        rgd = self.server._execute_tool(
            "session",
            {"action": "bootstrap_readiness_regression_guard", "session_id": self.sid, "window": 2, "auto_snapshot": False},
        )
        self.assertTrue(rgd.get("ok"))
        self.assertIn("triggered", rgd)

        fr = self.server._execute_tool(
            "session",
            {
                "action": "bootstrap_finalize_report",
                "session_id": self.sid,
                "trend_window": 2,
                "effectiveness_window": 10,
            },
        )
        self.assertTrue(fr.get("ok"))
        self.assertIn("stage", fr)
        self.assertIn("release_ready", fr)


if __name__ == "__main__":
    unittest.main()
