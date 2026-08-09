"""Regression tests for the p04 analysis primitives (WO-S3).

Covers the reversible-experiment + deterministic-analysis primitives added to
``analysis()`` (paper section 3.19 items 2-entry, 3, 10):

- ``add_entry``: promote a bootstrapped reset-vector / ISR candidate to a real
  entry point via ``ida_entry.add_entry(ordinal, ea, name, True)`` — the raw
  blob (RISC-V) bootstrap home.
- ``snapshot`` / ``restore_snapshot``: ``ida_loader`` DB snapshots for
  experiment rollback before ``publish_findings``.
- ``auto_wait``: bounded wait for auto-analysis to drain (50ms pump slices up
  to ``timeout_ms``). It must NEVER call the unbounded ``ida_auto.auto_wait()``
  (which drains the whole queue with no timeout and would blow the host RPC recv
  deadline — the same invariant pinned by test_swarm_t01_analysis.py), and it
  must never raise on timeout — it returns still-running with ``timed_out=true``.

All tests use _FakeIda-style fakes; no live IDA is required.
"""
import os
import sys
import time
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from tests._isolated_repo_loader import load_ida_module, load_tool_module

_EH_CACHE = {}


def _real_eh_overrides():
    """Use the REAL IDA-side error envelope (error/code/category/hint) rather
    than the isolated-loader stub so assertions match production make_error().

    Loaded lazily: load_ida_module() registers the ``ida_pro_mcp`` namespace
    package, which must not happen at module-import time.
    """
    eh = _EH_CACHE.get("eh")
    if eh is None:
        eh = load_ida_module("error_handling")
        _EH_CACHE["eh"] = eh
    return {
        "make_error": eh.make_error,
        "MCPError": eh.MCPError,
        "handle_error": eh.handle_error,
        "ERROR_HINTS": eh.ERROR_HINTS,
    }


def _blank_modules(names):
    for name in names:
        sys.modules.setdefault(name, types.ModuleType(name))


def _make_idaapi(**extra):
    mod = types.ModuleType("idaapi")
    mod.BADADDR = 0xFFFFFFFFFFFFFFFF
    mod.get_inf_structure = lambda: None
    mod.SETPROC_LOADER = 0
    mod.SETPROC_LOADER_NON_FATAL = 1
    for k, v in extra.items():
        setattr(mod, k, v)
    return mod


def _make_fake_ida_entry():
    """Fake ida_entry that records add_entry calls.

    Returns (module, calls). add_entry appends its positional args to calls and
    returns True by default; set module.result to False to force a refused add,
    or module.type_error_on_4arg to True to simulate an old 3-arg-only build.
    """
    mod = types.ModuleType("ida_entry")
    mod.calls = []
    mod.result = True
    mod.type_error_on_4arg = False

    def add_entry(*args):
        if mod.type_error_on_4arg and len(args) == 4:
            raise TypeError("add_entry() takes 3 positional arguments")
        mod.calls.append(args)
        return mod.result

    mod.add_entry = add_entry
    mod.get_entry_qty = lambda: len(mod.calls)
    return mod


def _make_fake_ida_loader():
    """Fake ida_loader for save_snapshot/restore_snapshot round-trips.

    save_snapshot records (name, flags) and stores the name; restore_snapshot
    records the name and succeeds only if the snapshot was previously saved.
    Set module.save_result = False to force a refused save.
    """
    mod = types.ModuleType("ida_loader")
    mod.saved = set()
    mod.save_calls = []
    mod.restore_calls = []
    mod.save_result = True
    mod.type_error_on_2arg = False

    def save_snapshot(*args):
        if mod.type_error_on_2arg and len(args) == 2:
            raise TypeError("save_snapshot() takes 1 positional argument")
        mod.save_calls.append(args)
        if mod.save_result:
            mod.saved.add(args[0])
        return mod.save_result

    def restore_snapshot(name):
        mod.restore_calls.append(name)
        return name in mod.saved

    mod.save_snapshot = save_snapshot
    mod.restore_snapshot = restore_snapshot
    return mod


def _make_fake_ida_auto():
    """Fake ida_auto with a deterministic drain counter.

    auto_is_ok() returns True once its call count exceeds flip_after (None =
    never drains). auto_make_step() records calls; auto_wait() records calls so
    tests can prove the unbounded API is never invoked.
    """
    mod = types.ModuleType("ida_auto")
    mod.flip_after = None
    mod.state = {"n": 0}
    mod.make_step_calls = 0
    mod.auto_wait_calls = 0

    def auto_is_ok():
        mod.state["n"] += 1
        if mod.flip_after is None:
            return False
        return mod.state["n"] > mod.flip_after

    def auto_make_step(*args, **kwargs):
        mod.make_step_calls += 1
        return True

    def auto_wait():
        mod.auto_wait_calls += 1
        return True

    mod.auto_is_ok = auto_is_ok
    mod.auto_make_step = auto_make_step
    mod.auto_wait = auto_wait
    return mod


class _AnalysisBase(unittest.TestCase):
    """Shared setup for the real analysis tool against fake ida_* modules.

    analysis.py binds ida_entry / ida_loader / ida_auto at import time, so all
    three fakes are installed in sys.modules BEFORE load_tool_module() runs.
    Subclasses customise behavior via the exposed self.ida_entry /
    self.ida_loader / self.ida_auto fakes after setUp.
    """

    def setUp(self):
        self.idaapi = _make_idaapi()
        sys.modules["idaapi"] = self.idaapi
        sys.modules["idc"] = types.ModuleType("idc")
        _blank_modules(
            ["ida_ida", "ida_segment", "ida_nalt", "ida_bytes", "ida_funcs",
             "ida_hexrays", "ida_lines", "idautils"]
        )
        self.ida_entry = _make_fake_ida_entry()
        sys.modules["ida_entry"] = self.ida_entry
        self.ida_loader = _make_fake_ida_loader()
        sys.modules["ida_loader"] = self.ida_loader
        self.ida_auto = _make_fake_ida_auto()
        sys.modules["ida_auto"] = self.ida_auto
        self._load_module()

    def _load_module(self):
        self.mod = load_tool_module("analysis", common_overrides=_real_eh_overrides())


class TestAddEntry(_AnalysisBase):
    """add_entry must register a real entry point via ida_entry.add_entry."""

    def test_registers_ordinal_with_name(self):
        res = self.mod.analysis(
            action="add_entry", ordinal=1, addr="0x1000", name="reset_vector"
        )
        self.assertEqual(res.get("ok"), True)
        self.assertEqual(res["ordinal"], 1)
        self.assertEqual(res["addr"], "0x1000")
        self.assertEqual(res["name"], "reset_vector")
        self.assertEqual(res["result"], True)
        # ida_entry.add_entry(ordinal, ea, name, is_manual=True)
        self.assertEqual(self.ida_entry.calls, [(1, 0x1000, "reset_vector", True)])

    def test_registers_ordinal_without_name(self):
        res = self.mod.analysis(action="add_entry", ordinal=2, addr="0x2000")
        self.assertEqual(res.get("ok"), True)
        self.assertEqual(res["name"], None)
        self.assertEqual(self.ida_entry.calls, [(2, 0x2000, "", True)])

    def test_missing_addr_errors(self):
        res = self.mod.analysis(action="add_entry", ordinal=1)
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "INVALID_ARGS")
        self.assertEqual(self.ida_entry.calls, [])

    def test_missing_ordinal_errors(self):
        res = self.mod.analysis(action="add_entry", addr="0x1000")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "INVALID_ARGS")
        self.assertEqual(self.ida_entry.calls, [])

    def test_invalid_ordinal_errors(self):
        res = self.mod.analysis(action="add_entry", ordinal="not-an-int", addr="0x1000")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "INVALID_ARGS")
        self.assertEqual(self.ida_entry.calls, [])

    def test_failed_add_entry_returns_ida_error(self):
        self.ida_entry.result = False
        res = self.mod.analysis(action="add_entry", ordinal=1, addr="0x1000")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "IDA_ERROR")
        self.assertEqual(self.ida_entry.calls, [(1, 0x1000, "", True)])

    def test_type_error_falls_back_to_3arg_form(self):
        self.ida_entry.type_error_on_4arg = True
        res = self.mod.analysis(action="add_entry", ordinal=1, addr="0x1000", name="x")
        self.assertEqual(res.get("ok"), True)
        # Old 3-arg-only build: (ordinal, ea, name).
        self.assertEqual(self.ida_entry.calls, [(1, 0x1000, "x")])


class TestAutoWait(_AnalysisBase):
    """auto_wait must drain deterministically and never call the unbounded
    ida_auto.auto_wait()."""

    def test_already_idle_returns_immediately(self):
        self.ida_auto.flip_after = 0  # first auto_is_ok() is True
        res = self.mod.analysis(action="auto_wait", timeout_ms=5000)
        self.assertEqual(res.get("ok"), True)
        self.assertIs(res["analysis_done"], True)
        self.assertEqual(res["queue_depth"], 0)
        self.assertIs(res["timed_out"], False)
        self.assertEqual(self.ida_auto.make_step_calls, 0)
        self.assertEqual(self.ida_auto.auto_wait_calls, 0)

    def test_drains_deterministically(self):
        self.ida_auto.flip_after = 2  # drains after two pump slices
        res = self.mod.analysis(action="auto_wait", timeout_ms=5000)
        self.assertEqual(res.get("ok"), True)
        self.assertIs(res["analysis_done"], True)
        self.assertEqual(res["queue_depth"], 0)
        self.assertIs(res["timed_out"], False)
        # Two queued units were drained; the unbounded API was not invoked.
        self.assertEqual(self.ida_auto.make_step_calls, 2)
        self.assertEqual(self.ida_auto.auto_wait_calls, 0)

    def test_timeout_zero_single_pump_still_running(self):
        # timeout_ms=0 performs one immediate pump and reports still-running
        # without sleeping — fully deterministic.
        started = time.time()
        res = self.mod.analysis(action="auto_wait", timeout_ms=0)
        elapsed = time.time() - started
        self.assertEqual(res.get("ok"), True)
        self.assertIs(res["analysis_done"], False)
        self.assertIs(res["timed_out"], True)
        self.assertEqual(res["queue_depth"], 1)
        self.assertEqual(self.ida_auto.make_step_calls, 1)
        self.assertEqual(self.ida_auto.auto_wait_calls, 0)
        self.assertLess(elapsed, 0.5)

    def test_timeout_bounded_and_never_calls_unbounded_auto_wait(self):
        # Analyzer never drains; the wait must return within ~timeout_ms, report
        # timed_out, and keep the unbounded ida_auto.auto_wait() untouched.
        self.ida_auto.flip_after = None
        started = time.time()
        res = self.mod.analysis(action="auto_wait", timeout_ms=150)
        elapsed = time.time() - started
        self.assertEqual(res.get("ok"), True)
        self.assertIs(res["analysis_done"], False)
        self.assertIs(res["timed_out"], True)
        self.assertGreaterEqual(res["queue_depth"], 1)
        self.assertGreaterEqual(self.ida_auto.make_step_calls, 1)
        self.assertEqual(self.ida_auto.auto_wait_calls, 0)
        # Bounded: returns well inside a second despite a never-draining queue.
        self.assertLess(elapsed, 1.0)

    def test_invalid_timeout_ms_errors(self):
        res = self.mod.analysis(action="auto_wait", timeout_ms="not-an-int")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "INVALID_ARGS")


class TestSnapshotRestore(_AnalysisBase):
    """snapshot/restore_snapshot must round-trip ida_loader DB snapshots."""

    def test_snapshot_saves_current_db(self):
        res = self.mod.analysis(action="snapshot", snapshot_name="pre_patch")
        self.assertEqual(res.get("ok"), True)
        self.assertEqual(res["snapshot_name"], "pre_patch")
        self.assertEqual(res["result"], True)
        # ida_loader.save_snapshot(name, dbflags) with DBFL_SNAPSHOT or 0.
        self.assertEqual(self.ida_loader.save_calls, [("pre_patch", 0)])

    def test_snapshot_missing_name_errors(self):
        res = self.mod.analysis(action="snapshot")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "INVALID_ARGS")

    def test_restore_snapshot_round_trip(self):
        self.mod.analysis(action="snapshot", snapshot_name="pre_patch")
        res = self.mod.analysis(action="restore_snapshot", snapshot_name="pre_patch")
        self.assertEqual(res.get("ok"), True)
        self.assertEqual(res["snapshot_name"], "pre_patch")
        self.assertEqual(self.ida_loader.restore_calls, ["pre_patch"])

    def test_restore_snapshot_missing_name_errors(self):
        res = self.mod.analysis(action="restore_snapshot")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "INVALID_ARGS")

    def test_save_failure_returns_ida_error(self):
        self.ida_loader.save_result = False
        res = self.mod.analysis(action="snapshot", snapshot_name="pre_patch")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "IDA_ERROR")

    def test_restore_unsaved_snapshot_errors(self):
        res = self.mod.analysis(action="restore_snapshot", snapshot_name="nope")
        self.assertTrue(res.get("error"))
        self.assertEqual(res.get("code"), "IDA_ERROR")

    def test_save_snapshot_type_error_falls_back_to_1arg(self):
        self.ida_loader.type_error_on_2arg = True
        res = self.mod.analysis(action="snapshot", snapshot_name="pre_patch")
        self.assertEqual(res.get("ok"), True)
        # 2-arg form raised TypeError -> fell back to save_snapshot(name).
        self.assertEqual(self.ida_loader.save_calls, [("pre_patch",)])


class TestRawBlobRiscvWorkflow(_AnalysisBase):
    """End-to-end primitives on an opaque raw RISC-V blob: bootstrap candidates
    are promoted via add_entry, and the experiment is wrapped in snapshot/restore
    so it can be rolled back before publish_findings."""

    def setUp(self):
        super().setUp()
        # Opaque raw blob: f_BIN filetype, RISC-V processor.
        self.idaapi.f_BIN = 17
        self.idaapi.f_BINARY = 17
        self.mod._inf_procname = lambda: "RISCV:RVA"
        self.mod._inf_filetype_id = lambda: 17
        self.mod._inf_bitness = lambda: 32
        self.mod._inf_is_be = lambda: False
        self.mod._inf_is_64bit = lambda: False
        self.mod._filetype_name = lambda ft: "raw" if ft == 17 else f"type_{ft}"

    def test_get_options_warns_raw_blob(self):
        res = self.mod.analysis(action="get_options")
        self.assertEqual(res.get("ok"), True)
        self.assertEqual(res["file_type_info"]["loader"], "raw")
        self.assertTrue(res.get("warnings"))
        self.assertIn("raw blob", res["warnings"][0])

    def test_reset_vector_promoted_and_rolled_back(self):
        # A bootstrapped reset-vector candidate at the raw blob head is promoted
        # to a real entry, then the experiment is wrapped for rollback.
        res_add = self.mod.analysis(
            action="add_entry", ordinal=1, addr="0x1000", name="reset_vector"
        )
        self.assertEqual(res_add.get("ok"), True)
        self.assertEqual(self.ida_entry.calls, [(1, 0x1000, "reset_vector", True)])

        # Snapshot the rollback point before the (hypothetical) experiment.
        res_snap = self.mod.analysis(action="snapshot", snapshot_name="pre_experiment")
        self.assertEqual(res_snap.get("ok"), True)
        self.assertIn("pre_experiment", self.ida_loader.saved)

        # Roll back the experiment.
        res_restore = self.mod.analysis(
            action="restore_snapshot", snapshot_name="pre_experiment"
        )
        self.assertEqual(res_restore.get("ok"), True)
        self.assertEqual(self.ida_loader.restore_calls, ["pre_experiment"])

    def test_auto_wait_after_bootstrapping(self):
        # Deterministic patch->verify loop on the raw blob: bounded wait drains,
        # then a fresh query is safe.
        self.ida_auto.flip_after = 0
        res = self.mod.analysis(action="auto_wait", timeout_ms=5000)
        self.assertEqual(res.get("ok"), True)
        self.assertIs(res["analysis_done"], True)
        self.assertEqual(self.ida_auto.auto_wait_calls, 0)


if __name__ == "__main__":
    unittest.main()
