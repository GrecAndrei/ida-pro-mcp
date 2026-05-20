"""
Integration test harness for running Python scripts inside real IDA Pro.

This module provides pytest fixtures and utilities that launch idat (IDA text mode)
with a target binary, run an IDAPython script, and capture the results via a JSON
file. All tests using these fixtures require a licensed IDA Pro installation.

Environment:
    IDA_DIR          - Path to IDA Pro installation (default: /home/REDACTED/ida-pro-9.2)
    TEST_BINARY      - Path to test binary (default: tests/data/test_binary.exe)
    SKIP_IDA_TESTS   - Set to "1" to skip all IDA integration tests
"""

import os
import sys
import json
import time
import tempfile
import subprocess
import pytest

IDA_DIR = os.environ.get("IDA_DIR", "/home/REDACTED/ida-pro-9.2")
IDAT = os.path.join(IDA_DIR, "idat")
TEST_BINARY = os.environ.get("TEST_BINARY", os.path.join(os.path.dirname(__file__), "..", "data", "test_binary.exe"))
SKIP_IDA_TESTS = os.environ.get("SKIP_IDA_TESTS", "0") == "1"


def _find_project_root() -> str:
    """Find the project root (where src/ lives)."""
    here = os.path.dirname(os.path.abspath(__file__))
    # Go up: tests/integration -> tests -> project_root
    return os.path.dirname(os.path.dirname(here))


PROJECT_ROOT = _find_project_root()
TOOLS_PATH = os.path.join(PROJECT_ROOT, "src")


def ida_is_available() -> bool:
    """Check if IDA text mode is installed and licensed."""
    if SKIP_IDA_TESTS:
        return False
    if not os.path.isfile(IDAT):
        return False
    if not os.path.isfile(TEST_BINARY):
        return False
    # Verify IDA can actually start by running a minimal script
    try:
        script = tempfile.mktemp(suffix=".py")
        result_file = tempfile.mktemp(suffix=".json")
        with open(script, "w") as f:
            f.write(f'''
import ida_auto, idc, json
ida_auto.auto_wait()
with open("{result_file}", "w") as f:
    json.dump({{"ok": True}}, f)
idc.qexit(0)
''')
        proc = subprocess.run(
            [IDAT, "-A", "-c", f"-S{script}", TEST_BINARY],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "TVHEADLESS": "1"},
        )
        available = os.path.exists(result_file)
        # Cleanup
        for f in (script, result_file):
            try:
                os.remove(f)
            except OSError:
                pass
        for ext in (".idb", ".i64", ".til", ".nam"):
            junk = os.path.splitext(TEST_BINARY)[0] + ext
            if os.path.exists(junk):
                try:
                    os.remove(junk)
                except OSError:
                    pass
        return available
    except Exception:
        return False


class IDARunner:
    """Launch idat with a binary, run an IDAPython script, return JSON result."""

    def __init__(self, ida_dir: str = IDA_DIR, binary: str = TEST_BINARY):
        self.idat = os.path.join(ida_dir, "idat")
        self.binary = binary
        self.project_root = PROJECT_ROOT

    def run_script(self, script_body: str, timeout: int = 120, processor: str = "") -> dict:
        """
        Write script_body to a temp file, launch idat -B -S<script>,
        and parse the JSON result written to a known temp file.

        The script_body should be valid IDAPython that calls auto_wait(),
        does work, writes a JSON file to the path stored in RESULT_PATH,
        and calls idc.qexit(0).
        """
        result_file = tempfile.mktemp(suffix=".json")
        script_file = tempfile.mktemp(suffix=".py")

        # Wrap the user's script with boilerplate
        # We avoid importing through ida_pro_mcp package (which pulls in zeromcp via rpc.py).
        # Instead we insert the tools directory directly and import the module by its file.
        wrapped = f'''
import sys
import os
# Avoid parent package imports that pull in zeromcp
sys.path.insert(0, {repr(self.project_root + "/src/ida_pro_mcp/ida_mcp/tools")})
sys.path.insert(0, {repr(self.project_root + "/src")})
RESULT_PATH = {repr(result_file)}

import ida_auto
import idc
import idautils
import json

ida_auto.auto_wait()

{script_body}

idc.qexit(0)
'''
        with open(script_file, "w") as f:
            f.write(wrapped)

        env = {**os.environ, "TVHEADLESS": "1", "IDA_NO_HISTORY": "1"}
        # -A: autonomous, -c: always create a new IDB (don't fail if no existing .i64)
        # -p<proc>: set processor type (e.g. -parm for ARM)
        cmd = [self.idat, "-A", "-c", f"-S{script_file}"]
        if processor:
            cmd.append(f"-p{processor}")
        cmd.append(self.binary)

        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"IDA timed out after {timeout}s") from e
        finally:
            elapsed = time.time() - start

        if not os.path.exists(result_file) or os.path.getsize(result_file) == 0:
            raise RuntimeError(
                f"IDA did not write result file (exit={proc.returncode}). stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
            )

        with open(result_file, "r") as f:
            result = json.load(f)

        result["_ida_elapsed"] = round(elapsed, 2)
        result["_ida_returncode"] = proc.returncode

        # Cleanup
        for f in (result_file, script_file):
            try:
                os.remove(f)
            except OSError:
                pass
        # Cleanup database files created by IDA
        for ext in (".idb", ".i64", ".til", ".nam", ".id0", ".id1", ".id2"):
            junk = os.path.splitext(self.binary)[0] + ext
            if os.path.exists(junk):
                try:
                    os.remove(junk)
                except OSError:
                    pass

        return result


@pytest.fixture(scope="session")
def ida_available() -> bool:
    return ida_is_available()


@pytest.fixture(scope="session")
def ida_runner() -> IDARunner:
    if not ida_is_available():
        pytest.skip("IDA Pro not available (set IDA_DIR or install IDA)")
    return IDARunner()
