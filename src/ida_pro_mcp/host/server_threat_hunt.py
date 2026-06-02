#!/usr/bin/env python3
"""Threat-hunt orchestration helpers extracted from the main server."""

from typing import Any, Optional

from .config import (
    ALLOW_HEURISTIC_FALLBACKS,
    EMBEDDING_FIRST_MODE,
    _bounded_int,
    _coerce_bool,
)
from .errors import MCPError, make_error
from .schemas_data import (
    THREAT_LEGACY_CONDITIONAL_PASSTHROUGH,
    THREAT_LEGACY_MALWARE_PASSTHROUGH_TOOLS,
    THREAT_LEGACY_REDIRECT_TOOLS,
    THREAT_LEGACY_TRACING_TOOLS,
    THREAT_LEGACY_VULN_TOOLS,
)
from .vuln_db import VULN_PATTERNS


class ServerThreatHuntMixin:
    @staticmethod
    def _legacy_passthrough_args(args: dict) -> dict:
        return {
            k: v
            for k, v in args.items()
            if k not in {"action", "legacy_tool", "legacy_action", "idb"}
        }

    def _threat_hunt_step(
        self, ip: str, tool: str, action: str, step_args: Optional[dict] = None
    ) -> dict:
        payload_args = dict(step_args or {})
        payload_args["action"] = action
        payload_args["idb"] = ip
        try:
            result = self.call_tool(tool, ip, **payload_args)
        except Exception as e:
            return {
                "ok": False,
                "tool": tool,
                "action": action,
                "error": str(e),
            }
        if isinstance(result, dict) and result.get("error"):
            return {
                "ok": False,
                "tool": tool,
                "action": action,
                "error": result.get("message")
                or result.get("error")
                or "unknown error",
                "code": result.get("code"),
                "payload": result,
            }
        return {
            "ok": True,
            "tool": tool,
            "action": action,
            "payload": result,
        }

    def _threat_hunt_extract_findings(self, step: dict) -> list[dict]:
        payload = step.get("payload")
        if not isinstance(payload, dict):
            return []
        out: list[dict] = []
        tool = str(step.get("tool", ""))
        action = str(step.get("action", ""))

        # Recursive extractor: collect any dict node that has an address and text-like field.
        def _walk(node):
            if isinstance(node, dict):
                keys = set(node.keys())
                has_addr = any(k in keys for k in ("addr", "address", "ea"))
                has_text = any(k in keys for k in ("text", "description", "summary", "title", "name", "value"))
                if has_addr and has_text:
                    e = dict(node)
                    e.setdefault("tool", tool)
                    e.setdefault("action", action)
                    out.append(e)
                for v in node.values():
                    _walk(v)
            elif isinstance(node, list):
                for it in node:
                    _walk(it)

        _walk(payload)

        for key in (
            "findings",
            "items",
            "matches",
            "results",
            "indicators",
            "iocs",
            "apis",
            "loops",
        ):
            val = payload.get(key)
            if isinstance(val, list):
                for entry in val:
                    if isinstance(entry, dict):
                        e = dict(entry)
                    else:
                        e = {"value": entry}
                    e.setdefault("tool", tool)
                    e.setdefault("action", action)
                    out.append(e)

        if not out and any(k in payload for k in ("summary", "count", "total")):
            out.append(
                {
                    "tool": tool,
                    "action": action,
                    "summary": payload.get("summary"),
                    "count": payload.get("count", payload.get("total", 0)),
                }
            )
        return out

    def _threat_hunt_vuln_db_pass(self, ip: str, limit: int = 120) -> list[dict]:
        """
        Deterministic first-pass scan using structured vulnerability pattern DB.
        Uses existing search surfaces to avoid IDA-runtime coupling in host process.
        """
        findings: list[dict] = []
        # Query broad signals once, then score against pattern indicators.
        s_vuln = self._threat_hunt_step(ip, "search", "vulnerable", {"limit": min(200, limit)})
        s_const = self._threat_hunt_step(ip, "search", "constants", {"limit": min(200, limit)})
        s_api = self._threat_hunt_step(ip, "search", "api", {"pattern": "*", "limit": min(200, limit)})
        corpus = []
        for st in (s_vuln, s_const, s_api):
            for row in self._threat_hunt_extract_findings(st):
                corpus.append(row)
        for row in corpus:
            text = " ".join(str(row.get(k) or "") for k in ("summary", "name", "title", "value", "kind", "type", "indicator", "description")).lower()
            if not text:
                continue
            for pat in VULN_PATTERNS:
                hit = 0
                for fn in pat.indicator_functions:
                    if fn.lower() in text:
                        hit += 1
                for s in pat.indicator_strings:
                    if s.lower() in text:
                        hit += 1
                for p in pat.indicator_patterns:
                    if p.lower() in text:
                        hit += 1
                if hit <= 0:
                    continue
                finding = dict(row)
                finding["tool"] = "vuln_db"
                finding["action"] = "pattern_match"
                finding["type"] = "vuln_pattern"
                finding["pattern_id"] = pat.id
                finding["pattern_name"] = pat.name
                finding["cwe_id"] = pat.cwe_id
                finding["severity"] = pat.severity
                finding["remediation"] = pat.remediation
                finding["support_count"] = max(int(finding.get("support_count", 1) or 1), hit)
                findings.append(finding)
        findings.sort(key=lambda x: (str(x.get("severity", "")), int(x.get("support_count", 1))), reverse=True)
        return findings[:limit]

    def _severity_classify(self, finding: dict) -> str:
        text = " ".join(
            str(finding.get(k) or "")
            for k in ("summary", "name", "title", "value", "kind", "type", "indicator", "description")
        ).lower()
        if ("network" in text or "http" in text or "socket" in text) and ("no auth" in text or "unauth" in text or "without auth" in text):
            return "Critical"
        if any(k in text for k in ("crypto misuse", "hardcoded key", "weak random", "insecure cipher", "buffer overflow", "format string", "command injection")):
            return "High"
        if any(k in text for k in ("anti-debug", "anti vm", "obfuscation", "packed")):
            return "Medium"
        return "Low"

    def _correlate_findings(self, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        """Group findings by 4KB page and emit hotspots when 3+ findings hit same page."""
        page_groups: dict[int, list[dict]] = {}
        for f in findings:
            try:
                a = str(f.get("addr") or f.get("address") or f.get("ea") or "").strip()
                if not a:
                    continue
                ai = int(a, 16) if a.lower().startswith("0x") else int(a)
                pg = ai & ~0xFFF
                page_groups.setdefault(pg, []).append(f)
            except Exception:
                continue
        hotspots = []
        for pg, rows in page_groups.items():
            if len(rows) < 3:
                continue
            score = sum(float(r.get("ml_score", 0.0) or 0.0) for r in rows)
            sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            sev = max((self._severity_classify(r) for r in rows), key=lambda s: sev_rank.get(s, 1))
            hotspots.append({
                "page": hex(pg),
                "finding_count": len(rows),
                "combined_score": round(score, 4),
                "severity": sev,
            })
        hotspots.sort(key=lambda x: (x["combined_score"], x["finding_count"]), reverse=True)
        return findings, hotspots

    def _synthesize_attack_paths(self, findings: list[dict]) -> list[dict]:
        """A -> B -> C synthesis from finding call relationships when available."""
        by_addr: dict[int, list[dict]] = {}
        for f in findings:
            try:
                a = str(f.get("addr") or f.get("address") or f.get("ea") or "").strip()
                if not a:
                    continue
                ai = int(a, 16) if a.lower().startswith("0x") else int(a)
                by_addr.setdefault(ai, []).append(f)
            except Exception:
                continue
        paths = []
        for f in findings:
            callees = f.get("callees") or f.get("calls") or []
            if not isinstance(callees, list):
                continue
            a_txt = str(f.get("title") or f.get("summary") or f.get("name") or "A")
            for c in callees[:10]:
                c_addr_txt = ""
                if isinstance(c, dict):
                    c_addr_txt = str(c.get("addr") or c.get("ea") or "").strip()
                else:
                    c_addr_txt = str(c).split()[0]
                if not c_addr_txt:
                    continue
                try:
                    ci = int(c_addr_txt, 16) if c_addr_txt.lower().startswith("0x") else int(c_addr_txt)
                except Exception:
                    continue
                linked = by_addr.get(ci, [])
                for f2 in linked[:3]:
                    c_txt = str(f2.get("title") or f2.get("summary") or f2.get("name") or "C")
                    paths.append({
                        "chain": f"{a_txt} -> {c_addr_txt} -> {c_txt}",
                        "from": str(f.get("addr") or f.get("address") or f.get("ea") or ""),
                        "via": c_addr_txt,
                        "to": str(f2.get("addr") or f2.get("address") or f2.get("ea") or ""),
                    })
        return paths[:100]

    def _threat_hunt_score_finding(self, finding: dict, freq: int = 1) -> float:
        """Embedding-first threat ranking with deterministic non-heuristic fallback."""
        if not isinstance(finding, dict):
            return 0.0
        text = " ".join(
            str(finding.get(k) or "")
            for k in ("summary", "name", "title", "value", "kind", "type", "indicator")
        ).lower()
        addr = str(finding.get("addr") or finding.get("address") or finding.get("ea") or "")
        if EMBEDDING_FIRST_MODE and text:
            try:
                from .intelligence_core import BgeCodeEmbedder
                embedder = BgeCodeEmbedder()
                query_vec = embedder.embed(text)
                anchors = [
                    "malware command and control beaconing persistence injection",
                    "memory corruption vulnerability overflow format string unsafe copy",
                    "obfuscation evasion anti debug anti vm packed encrypted payload",
                    "crypto misuse hardcoded key weak random insecure cipher mode",
                    "suspicious network exfiltration downloader shellcode loader",
                ]
                sims = []
                for a in anchors:
                    av = embedder.embed(a)
                    sims.append(BgeCodeEmbedder.cosine(query_vec, av))
                emb_score = max(sims) if sims else 0.0
                corroboration = min(0.2, 0.05 * max(0, freq - 1))
                structural = 0.05 if addr else 0.0
                return round(float(emb_score) + corroboration + structural, 4)
            except Exception:
                pass

        # Deterministic fallback: no lexical keyword heuristics.
        if not ALLOW_HEURISTIC_FALLBACKS:
            base = 0.1 if text else 0.0
            structural = 0.05 if addr else 0.0
            corroboration = min(0.2, 0.05 * max(0, freq - 1))
            return round(base + structural + corroboration, 4)

        # Legacy fallback path can still be explicitly enabled by env.
        tool = str(finding.get("tool") or "").lower()
        action = str(finding.get("action") or "").lower()
        score = 0.0
        if tool in {"yara_hunt", "crypto_id", "deobfuscate"}:
            score += 1.4
        elif tool in {"trace_analysis", "coverage", "trace"}:
            score += 1.1
        elif tool in {"search", "string_ops", "graph"}:
            score += 0.9
        if action in {"identify", "find_c2", "ioc_extract", "vulnerable", "detect"}:
            score += 1.0
        if action in {"analyze_coverage", "find_loops"}:
            score += 0.6
        if addr:
            score += 0.35
        score += min(1.5, 0.35 * max(0, freq - 1))
        return round(score, 4)

    def _threat_hunt_legacy_route(
        self, legacy_tool: str, legacy_action: str, args: dict
    ) -> tuple[str, list[tuple[str, str, dict]], dict]:
        tool = str(legacy_tool or "").strip().lower()
        action = str(legacy_action or "").strip().lower()
        profile = (
            str(args.get("profile") or args.get("scan_profile") or "balanced")
            .strip()
            .lower()
        )
        if profile not in {"quick", "balanced", "deep"}:
            profile = "balanced"
        passthrough = self._legacy_passthrough_args(args)

        mapped_module = "findings"
        steps: list[tuple[str, str, dict]] = []
        if tool in THREAT_LEGACY_TRACING_TOOLS - {"taint"}:
            mapped_module = "tracing"
            trace_map = {
                "get": [("trace", "get", {})],
                "clear": [("trace", "clear", {})],
                "set_options": [
                    (
                        "trace",
                        "set_options",
                        passthrough,
                    )
                ],
                "import_trace": [
                    (
                        "trace_analysis",
                        "import_trace",
                        passthrough,
                    )
                ],
                "analyze_coverage": [("trace_analysis", "analyze_coverage", {})],
                "find_loops": [("trace_analysis", "find_loops", {})],
                "extract_api_calls": [("trace_analysis", "extract_api_calls", {})],
                "basic_blocks_hit": [("trace_analysis", "basic_blocks_hit", {})],
                "import_drcov": [
                    (
                        "coverage",
                        "import_drcov",
                        passthrough,
                    )
                ],
                "import_lighthouse": [
                    (
                        "coverage",
                        "import_lighthouse",
                        passthrough,
                    )
                ],
                "highlight": [
                    (
                        "coverage",
                        "highlight",
                        passthrough,
                    )
                ],
                "report": [("coverage", "report", {})],
                "uncovered": [("coverage", "uncovered", {})],
                "filter": [
                    (
                        "coverage",
                        "filter",
                        passthrough,
                    )
                ],
            }
            steps = trace_map.get(
                action,
                self._threat_default_tracing_steps(include_loop_analysis=False),
            )
        elif tool in (THREAT_LEGACY_VULN_TOOLS | {"taint"}):
            mapped_module = "vuln"
            if tool == "taint" and action:
                mapped_module = "tracing"
                steps = [
                    (
                        "taint",
                        action,
                        passthrough,
                    )
                ]
            elif tool == "gadgets" and action:
                steps = [
                    (
                        "gadgets",
                        action,
                        passthrough,
                    )
                ]
            elif tool == "search" and action in {
                "vulnerable",
                "constants",
                "api",
                "find",
                "regex",
            }:
                steps = [("search", action, passthrough)]
            else:
                steps = self._threat_default_vuln_steps()
        else:
            mapped_module = "malware"
            if tool in THREAT_LEGACY_MALWARE_PASSTHROUGH_TOOLS and action:
                steps = [
                    (
                        tool,
                        action,
                        passthrough,
                    )
                ]
            elif tool in THREAT_LEGACY_REDIRECT_TOOLS and action:
                # Keep legacy compatibility, but route to canonical string_ops implementation.
                redirect_tool = THREAT_LEGACY_REDIRECT_TOOLS[tool]
                steps = [
                    (
                        redirect_tool,
                        action,
                        passthrough,
                    )
                ]
            elif tool in THREAT_LEGACY_CONDITIONAL_PASSTHROUGH and action:
                allowed_actions = THREAT_LEGACY_CONDITIONAL_PASSTHROUGH.get(tool)
                if allowed_actions is None or action in allowed_actions:
                    steps = [
                        (
                            tool,
                            action,
                            passthrough,
                        )
                    ]
            else:
                steps = self._threat_default_malware_steps()

        return (
            mapped_module,
            steps,
            {"legacy_tool": tool or None, "legacy_action": action or None},
        )

    def _handle_threat_hunt(self, args: dict) -> dict:
        action = str(args.get("action") or "run").strip().lower()
        profile = (
            str(args.get("profile") or args.get("scan_profile") or "balanced")
            .strip()
            .lower()
        )
        if (
            action in {"quick", "deep"}
            and "profile" not in args
            and "scan_profile" not in args
        ):
            profile = action
            action = "run"
        if action == "findings":
            action = "run"
        if profile not in {"quick", "balanced", "deep"}:
            profile = "balanced"

        include_vuln = _coerce_bool(
            args.get("include_vuln"), action in {"run", "vuln", "legacy"}
        )
        include_malware = _coerce_bool(
            args.get("include_malware"), action in {"run", "malware", "legacy"}
        )
        include_tracing = _coerce_bool(
            args.get("include_tracing"), action in {"run", "tracing", "legacy"}
        )
        if action == "vuln":
            include_vuln, include_malware, include_tracing = True, False, False
        elif action == "malware":
            include_vuln, include_malware, include_tracing = False, True, False
        elif action == "tracing":
            include_vuln, include_malware, include_tracing = False, False, True

        if not (include_vuln or include_malware or include_tracing):
            # Default: enable all modules for 'run' action
            if action in {"run", "legacy"}:
                include_vuln = include_malware = include_tracing = True
            else:
                return make_error(
                    MCPError.INVALID_ARGS,
                    "No threat_hunt modules enabled",
                    hint="Enable at least one of include_vuln/include_malware/include_tracing or use action run|vuln|malware|tracing.",
                )

        idb_path = args.get(
            "idb", self.current_session.idb_path if self.current_session else None
        )
        if not idb_path:
            return make_error(
                MCPError.SESSION_REQUIRED,
                "No active session. Create one first with: session(action='create', binary_path='path/to/binary')",
            )

        limit = _bounded_int(args.get("limit", 120), 120, min_value=1, max_value=1000)
        max_steps = _bounded_int(
            args.get("max_steps", 24), 24, min_value=1, max_value=128
        )
        include_evidence = _coerce_bool(args.get("include_evidence"), False)

        step_plan: list[tuple[str, str, dict]] = []
        legacy_meta: dict = {}
        if action == "legacy":
            module, legacy_steps, legacy_meta = self._threat_hunt_legacy_route(
                str(args.get("legacy_tool") or args.get("tool") or ""),
                str(args.get("legacy_action") or args.get("source_action") or ""),
                args,
            )
            include_vuln = module == "vuln"
            include_malware = module == "malware"
            include_tracing = module == "tracing"
            step_plan.extend(legacy_steps)

        if include_malware and not step_plan:
            step_plan.extend(self._threat_default_malware_steps())

        if include_tracing and not step_plan:
            step_plan.extend(self._threat_default_tracing_steps(include_loop_analysis=True))

        step_plan = step_plan[:max_steps]
        steps: list[dict] = []
        raw_findings: list[dict] = []
        # First-pass vuln DB signal injection before orchestrated modules.
        vuln_seed = self._threat_hunt_vuln_db_pass(idb_path, limit=max(20, min(limit, 200)))
        if vuln_seed:
            raw_findings.extend(vuln_seed)
        for tool, step_action, step_args in step_plan:
            st = self._threat_hunt_step(idb_path, tool, step_action, step_args)
            steps.append(
                {
                    "tool": tool,
                    "action": step_action,
                    "ok": bool(st.get("ok")),
                    "error": st.get("error"),
                }
            )
            if st.get("ok"):
                raw_findings.extend(self._threat_hunt_extract_findings(st))
            elif include_evidence:
                raw_findings.append(
                    {
                        "tool": tool,
                        "action": step_action,
                        "error": st.get("error"),
                        "code": st.get("code"),
                    }
                )

        dedup: dict[str, dict] = {}
        dedup_freq: dict[str, int] = {}
        for f in raw_findings:
            if not isinstance(f, dict):
                continue
            addr = str(f.get("addr") or f.get("address") or f.get("ea") or "")
            kind = str(f.get("type") or f.get("kind") or f.get("action") or "")
            text = str(
                f.get("name")
                or f.get("title")
                or f.get("summary")
                or f.get("value")
                or ""
            )
            key = f"{f.get('tool', '')}|{kind}|{addr}|{text}".strip().lower()
            if not key:
                continue
            if key not in dedup:
                dedup[key] = f
                dedup_freq[key] = 1
            else:
                dedup_freq[key] = dedup_freq.get(key, 1) + 1

        ranked_findings: list[dict] = []
        for k, f in dedup.items():
            row = dict(f)
            row["ml_score"] = self._threat_hunt_score_finding(row, dedup_freq.get(k, 1))
            row["support_count"] = dedup_freq.get(k, 1)
            row["severity"] = self._severity_classify(row)
            ranked_findings.append(row)
        ranked_findings.sort(key=lambda x: (x.get("ml_score", 0.0), x.get("support_count", 1)), reverse=True)
        findings = ranked_findings[:limit]
        findings, hotspots = self._correlate_findings(findings)
        attack_paths = self._synthesize_attack_paths(findings)
        ok_steps = sum(1 for s in steps if s.get("ok"))
        failed_steps = len(steps) - ok_steps
        out = {
            "ok": True,
            "action": "legacy" if action == "legacy" else "run",
            "profile": profile,
            "pipeline": {
                "modules": {
                    "vuln": include_vuln,
                    "malware": include_malware,
                    "tracing": include_tracing,
                },
                "steps_total": len(steps),
                "steps_ok": ok_steps,
                "steps_failed": failed_steps,
            },
            "steps": steps,
            "findings": findings,
            "count": len(findings),
            "total_raw_findings": len(raw_findings),
            "deduped": max(0, len(raw_findings) - len(findings)),
            "hotspots": hotspots,
            "attack_paths": attack_paths,
        }
        if legacy_meta:
            out["legacy"] = legacy_meta
        if include_evidence:
            out["evidence"] = {
                "raw_findings": raw_findings[: min(300, len(raw_findings))]
            }
        return out

    @staticmethod
    def _threat_default_malware_steps() -> list[tuple[str, str, dict]]:
        return [
            ("deobfuscate", "stack_strings", {}),
            ("deobfuscate", "api_hashing", {}),
            ("crypto_id", "identify", {}),
            ("yara_hunt", "list_rules", {}),
        ]

    @staticmethod
    def _threat_default_vuln_steps() -> list[tuple[str, str, dict]]:
        return [
            ("gadgets", "rop", {}),
            ("gadgets", "mitigations", {}),
            ("search", "vulnerable", {}),
        ]

    @staticmethod
    def _threat_default_tracing_steps(
        *, include_loop_analysis: bool
    ) -> list[tuple[str, str, dict]]:
        steps: list[tuple[str, str, dict]] = [
            ("trace", "get", {}),
            ("trace_analysis", "analyze_coverage", {}),
        ]
        if include_loop_analysis:
            steps.append(("trace_analysis", "find_loops", {}))
        steps.append(("coverage", "report", {}))
        return steps
