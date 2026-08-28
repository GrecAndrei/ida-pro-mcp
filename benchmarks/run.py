#!/usr/bin/env python3
"""Portable benchmark runner for the IDA Pro MCP project.

The runner keeps benchmark *inputs* and *results* separate from source code.
It records reproducibility metadata at runtime and supports independent scopes:

  contract    schema/docs/lint checks
  host        non-live host and IDA-side fake test suites
  blackboard  deterministic workspace retrieval fixture
  retrieval   caller-supplied function corpus and gold queries
  ida         opt-in live-IDA surface suite

Examples:

  python benchmarks/run.py --scope contract host blackboard
  python benchmarks/run.py --scope retrieval --corpus /data/functions.json \
      --queries /data/queries.json --backend native
  python benchmarks/run.py --scope ida --ida-dir /opt/ida --binary /data/sample

Results are written as ``.json`` and ``.md`` beside ``--out``. No benchmark
result is checked in, and no default corpus, model path, CPU, or user path is
embedded in this repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


def _git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True,
            check=True, timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def metadata() -> dict[str, Any]:
    from ida_pro_mcp import __version__

    return {
        "package_version": __version__,
        "git_commit": _git("rev-parse", "HEAD"),
        "git_dirty": bool(_git("status", "--porcelain")),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _run(command: list[str], *, timeout: int = 900) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            command, cwd=REPO_ROOT, capture_output=True, text=True,
            timeout=timeout,
        )
        status = "passed" if proc.returncode == 0 else "failed"
        return {
            "status": status,
            "returncode": proc.returncode,
            "duration_seconds": round(time.perf_counter() - started, 3),
            "command": command,
            "stdout": proc.stdout[-12000:],
            "stderr": proc.stderr[-12000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "failed",
            "returncode": None,
            "duration_seconds": round(time.perf_counter() - started, 3),
            "command": command,
            "stdout": str(exc.stdout or "")[-12000:],
            "stderr": f"timed out after {timeout}s",
        }


def benchmark_contract() -> dict[str, Any]:
    checks = [
        _run([sys.executable, "scripts/check_schema_integrity.py"], timeout=120),
        _run(["ruff", "check", "."], timeout=120),
        _run([sys.executable, "-m", "pytest", "-q", "tests/test_docs_sync.py"], timeout=180),
    ]
    return {
        "status": "passed" if all(c["status"] == "passed" for c in checks) else "failed",
        "checks": checks,
    }


def benchmark_host() -> dict[str, Any]:
    result = _run(
        [sys.executable, "-m", "pytest", "-q", "tests/host", "tests/ida_mcp", "--durations=10"],
        timeout=1200,
    )
    match = re.search(r"(\d+) passed(?:, (\d+) skipped)?", result.get("stdout", ""))
    if match:
        result["tests_passed"] = int(match.group(1))
        result["tests_skipped"] = int(match.group(2) or 0)
    return result


class _FixtureEmbedder:
    """Stable local vectorizer used only to test blackboard ranking plumbing."""

    backend = "benchmark-fixture"
    dim = 96

    def embed_vector(self, text: str) -> list[float]:
        vector = [0.0] * self.dim
        for token in re.findall(r"[a-z0-9_]{2,}", str(text or "").lower()):
            slot = int(hashlib.sha256(token.encode()).hexdigest()[:8], 16) % self.dim
            vector[slot] += 1.0
        return vector

    def embed_query_vector(self, text: str) -> list[float]:
        return self.embed_vector(text)


def benchmark_blackboard() -> dict[str, Any]:
    from ida_pro_mcp.host.intelligence.helpers import pack_floats
    from ida_pro_mcp.host.stores.blackboard_store import BlackboardStore

    cases = [
        ("network packet receive handler", "network", "parses socket packets and validates framing"),
        ("cryptographic key schedule", "crypto", "derives AES round keys and initializes the cipher"),
        ("configuration file parser", "config", "opens a configuration file and parses key value pairs"),
        ("thread synchronization helper", "threads", "locks a mutex before updating shared state"),
        ("firmware interrupt dispatcher", "firmware", "routes interrupt vectors to device handlers"),
        ("archive decompression routine", "archive", "reads compressed bytes and expands an archive"),
    ]
    queries = [
        ("receive socket packets", "network"),
        ("AES encryption keys", "crypto"),
        ("parse settings file", "config"),
        ("mutex shared state", "threads"),
        ("interrupt vector device", "firmware"),
        ("expand compressed archive", "archive"),
    ]
    with tempfile.TemporaryDirectory(prefix="ida-mcp-benchmark-") as temp_dir:
        store = BlackboardStore(str(Path(temp_dir) / "blackboard.db"))
        embedder = _FixtureEmbedder()
        store._get_embedder = lambda: embedder
        for title, category, content in cases:
            entry_id = store.write(title=title, category=category, content=content, confidence=0.8)
            document = store._embedding_text(title, content, category)
            store._store_embedding(entry_id, pack_floats(embedder.embed_vector(document)), document)

        ranks: list[int | None] = []
        durations: list[float] = []
        for query, target in queries:
            started = time.perf_counter()
            hits = store.semantic_search(query, top_k=5, threshold=0.0)
            durations.append((time.perf_counter() - started) * 1000)
            rank = next((i + 1 for i, hit in enumerate(hits) if hit.get("category") == target), None)
            ranks.append(rank)

    return {
        "status": "passed",
        "backend": embedder.backend,
        "fixture_cases": len(queries),
        "recall_at_1": round(sum(rank == 1 for rank in ranks) / len(ranks), 4),
        "recall_at_5": round(sum(rank is not None for rank in ranks) / len(ranks), 4),
        "mrr": round(sum((1 / rank) if rank else 0 for rank in ranks) / len(ranks), 4),
        "median_query_ms": round(sorted(durations)[len(durations) // 2], 3),
        "ranks": ranks,
    }


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _query_rows(path: Path) -> list[tuple[str, list[str]]]:
    raw = _load_json(path)
    rows = raw.get("queries", raw) if isinstance(raw, dict) else raw
    out = []
    for row in rows:
        if not isinstance(row, dict) or not row.get("query"):
            continue
        target = row.get("targets", row.get("target", row.get("gold", row.get("name"))))
        if isinstance(target, str):
            target = [target]
        if isinstance(target, list) and target:
            out.append((str(row["query"]), [str(value) for value in target]))
    return out


def benchmark_retrieval(args: argparse.Namespace) -> dict[str, Any]:
    if not args.corpus or not args.queries:
        return {"status": "skipped", "reason": "--corpus and --queries are required"}
    corpus_path = Path(args.corpus).expanduser().resolve()
    queries_path = Path(args.queries).expanduser().resolve()
    if not corpus_path.is_file() or not queries_path.is_file():
        return {"status": "failed", "reason": "corpus or queries file does not exist"}

    if args.backend == "gemini":
        os.environ["IDA_MCP_EMBED_BACKEND"] = "gemini"
    else:
        os.environ["IDA_MCP_BACKEND"] = args.backend
    from ida_pro_mcp.host.intelligence.core import BgeCodeEmbedder
    from ida_pro_mcp.host.intelligence.embeddings import FunctionEmbeddingIndex

    corpus = _load_json(corpus_path)
    functions = [row for row in corpus.get("functions", []) if row.get("ea") and row.get("pseudocode")]
    queries = _query_rows(queries_path)[: args.query_limit or None]
    if not functions or not queries:
        return {"status": "failed", "reason": "corpus or queries contain no usable rows"}

    with tempfile.TemporaryDirectory(prefix="ida-mcp-retrieval-") as temp_dir:
        embedder = BgeCodeEmbedder()
        # The production indexing tool explicitly activates the HTTP server
        # before handing work to FunctionEmbeddingIndex. Do the same here so
        # a benchmark measures inference throughput instead of reporting an
        # instant all-failed run against a deliberately cold backend.
        if hasattr(embedder, "ensure_ready") and not embedder.ensure_ready():
            return {
                "status": "failed",
                "backend": args.backend,
                "reason": "embedding backend did not become ready",
            }
        index = FunctionEmbeddingIndex(str(Path(temp_dir) / "functions.db"), embedder)
        started = time.perf_counter()
        index_result = index.index_many([
            (str(row["ea"]), str(row.get("name") or row["ea"]), str(row["pseudocode"]), None)
            for row in functions
        ])
        index_seconds = time.perf_counter() - started
        ranks: list[int | None] = []
        for query, targets in queries:
            hits = index.search(query, top_k=max(5, args.top_k), threshold=0.0)
            rank = None
            for pos, hit in enumerate(hits, 1):
                haystack = {str(hit.get("ea") or "").lower(), str(hit.get("name") or "").lower()}
                if any(target.lower() in value for target in targets for value in haystack):
                    rank = pos
                    break
            ranks.append(rank)
        embedder.stop()

    return {
        "status": "passed" if not index_result.get("failed") else "failed",
        "backend": args.backend,
        "corpus": {"path": str(corpus_path), "sha256": _sha256(corpus_path), "functions": len(functions)},
        "queries": {"path": str(queries_path), "sha256": _sha256(queries_path), "count": len(queries)},
        "indexed": index_result,
        "index_seconds": round(index_seconds, 3),
        "recall_at_1": round(sum(rank == 1 for rank in ranks) / len(ranks), 4),
        "recall_at_5": round(sum(rank is not None and rank <= 5 for rank in ranks) / len(ranks), 4),
        "mrr": round(sum((1 / rank) if rank else 0 for rank in ranks) / len(ranks), 4),
        "ranks": ranks,
    }


def benchmark_ida(args: argparse.Namespace) -> dict[str, Any]:
    if not args.ida_dir and not args.idat:
        return {"status": "skipped", "reason": "--ida-dir or --idat is required"}
    command = [sys.executable, "scripts/run_live_agent_surface.py"]
    for flag, value in (("--ida-dir", args.ida_dir), ("--idat", args.idat), ("--binary", args.binary)):
        if value:
            command.extend([flag, value])
    return _run(command, timeout=args.ida_timeout)


def _markdown(report: dict[str, Any]) -> str:
    lines = [
        "# IDA Pro MCP benchmark run",
        "",
        f"- Package: `{report['metadata']['package_version']}`",
        f"- Commit: `{report['metadata']['git_commit'] or 'unknown'}`",
        f"- Runtime: Python `{report['metadata']['python']}` on `{report['metadata']['platform']}`",
        "",
        "| Scope | Status | Key metrics |",
        "|---|---|---|",
    ]
    for scope, result in report["scopes"].items():
        metrics = []
        for key in ("recall_at_1", "recall_at_5", "mrr", "index_seconds", "median_query_ms", "tests_passed"):
            if key in result:
                metrics.append(f"{key}={result[key]}")
        if "reason" in result:
            metrics.append(result["reason"])
        lines.append(f"| `{scope}` | **{result.get('status', 'unknown')}** | {'; '.join(metrics) or 'see JSON'} |")
    lines.extend(["", "Detailed command output and input hashes are in the JSON report."])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", nargs="+", choices=("contract", "host", "blackboard", "retrieval", "ida", "all"), default=["all"])
    parser.add_argument("--corpus", help="Function corpus JSON for the retrieval scope")
    parser.add_argument("--queries", help="Gold query JSON for the retrieval scope")
    parser.add_argument("--backend", choices=("native", "http", "gemini"), default="native")
    parser.add_argument("--query-limit", type=int, default=0)
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--ida-dir")
    parser.add_argument("--idat")
    parser.add_argument("--binary")
    parser.add_argument("--ida-timeout", type=int, default=1800)
    parser.add_argument("--out", default="benchmark-results/run")
    args = parser.parse_args()

    scopes = ("contract", "host", "blackboard", "retrieval", "ida") if "all" in args.scope else args.scope
    report = {"metadata": metadata(), "scopes": {}}
    runners = {
        "contract": benchmark_contract,
        "host": benchmark_host,
        "blackboard": benchmark_blackboard,
        "retrieval": lambda: benchmark_retrieval(args),
        "ida": lambda: benchmark_ida(args),
    }
    for scope in scopes:
        print(f"[benchmark] {scope}", file=sys.stderr)
        report["scopes"][scope] = runners[scope]()
    report["metadata"]["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    output_base = Path(args.out).expanduser()
    json_path = output_base.with_suffix(".json")
    markdown_path = output_base.with_suffix(".md")
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(_markdown(report), encoding="utf-8")
    print(_markdown(report))
    return 0 if all(result.get("status") in {"passed", "skipped"} for result in report["scopes"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
