"""
NarrativeEngine — generates a human-readable firmware analysis story.

Reads from KnowledgeGraph + BlackboardStore and produces a structured
narrative that orients the LLM after a context reset.

The narrative has five sections:
  1. Identity    — what is this binary?
  2. Understanding — what systems have been found, coverage %
  3. Gaps        — what's expected but missing
  4. Threats     — attack surface + known vulns
  5. Next action — single most important thing to do next

Output is plain text (not JSON) so the LLM can read it naturally.
"""
from __future__ import annotations


class NarrativeEngine:
    """
    Generates a firmware analysis narrative from KnowledgeGraph + BlackboardStore.

    Usage:
        ne = NarrativeEngine(kg, bb_store)
        text = ne.generate()
        # Returns a ~500-word plain-text story
    """

    def __init__(self, kg, bb_store):
        self.kg = kg
        self.bb = bb_store

    def generate(self, binary_meta: dict | None = None) -> str:
        """Generate the full narrative. Returns plain text."""
        parts = []

        # 1. Identity
        parts.append(self._section_identity(binary_meta or {}))

        # 2. Understanding
        parts.append(self._section_understanding())

        # 3. Gaps
        parts.append(self._section_gaps())

        # 4. Threats
        parts.append(self._section_threats())

        # 5. Next action
        parts.append(self._section_next_action())

        return "\n\n".join(p for p in parts if p.strip())

    # ── sections ──────────────────────────────────────────────────────────────

    def _section_identity(self, meta: dict) -> str:
        name = meta.get("filename") or meta.get("input_file") or "unknown binary"
        arch = meta.get("processor") or meta.get("arch") or "unknown arch"
        bits = meta.get("bitness") or meta.get("bits") or 0
        size = meta.get("file_size") or 0
        size_str = f"{size // 1024}KB" if size else "unknown size"

        # Try to infer binary type from blackboard tags/categories
        binary_type = self._infer_binary_type()

        lines = [f"## Binary: {name}"]
        lines.append(f"Architecture: {arch}{f' {bits}-bit' if bits else ''}, {size_str}")
        if binary_type:
            lines.append(f"Type: {binary_type}")

        # Peripherals give hardware identity
        periphs = self.kg.list_peripherals()
        if periphs:
            pnames = [p.get("name") or p.get("periph_type", "unknown") for p in periphs[:4]]
            lines.append(f"Hardware: {', '.join(pnames)}")

        return "\n".join(lines)

    def _section_understanding(self) -> str:
        systems = self.kg.list_systems()
        structs = self.kg.list_structs()
        sms = self.kg.list_state_machines()
        bb_stats = self.bb.stats()

        bb_stats.get("by_category", {}).get("hypothesis", 0) + \
                      bb_stats.get("by_category", {}).get("general", 0)

        lines = ["## Understanding"]

        if not systems:
            lines.append("No systems identified yet. Analysis is in early stage.")
            lines.append(f"Blackboard: {bb_stats.get('total_entries', 0)} entries, "
                         f"{bb_stats.get('resolved', 0)} resolved, "
                         f"{bb_stats.get('contradicted', 0)} contradicted.")
            return "\n".join(lines)

        # Coverage estimate
        kg_summary = self.kg.summary()
        n_sys = kg_summary["systems"]
        n_gaps = kg_summary["gaps_open"]
        # Rough coverage: systems found / (systems found + open gaps)
        total_expected = n_sys + n_gaps
        coverage_pct = round(n_sys / total_expected * 100) if total_expected else 0
        lines.append(f"Coverage: ~{coverage_pct}% ({n_sys}/{total_expected} expected systems identified)")

        # Systems list
        lines.append("\nSystems identified:")
        for i, sys in enumerate(systems[:10], 1):
            n_members = len(sys.get("members", []))
            cov = sys.get("coverage_pct", 0)
            cov_str = f", {cov:.0f}% mapped" if cov > 0 else ""
            lines.append(f"  {i}. {sys['name']} ({n_members} functions{cov_str})")

        # State machines
        if sms:
            lines.append(f"\nState machines: {len(sms)} detected")
            for sm in sms[:3]:
                n_trans = len(sm.get("transitions", []))
                lines.append(f"  • {sm['name']}: {n_trans} transitions, "
                             f"state var @ {sm.get('state_var', '?')}")

        # Data structures
        if structs:
            lines.append(f"\nData structures: {len(structs)} inferred")
            for s in structs[:3]:
                n_members = len(s.get("members", []))
                n_seen = len(s.get("seen_at", []))
                lines.append(f"  • {s['name']}: {n_members} fields, "
                             f"seen in {n_seen} functions")

        # Blackboard summary
        by_cat = bb_stats.get("by_category", {})
        interesting = {k: v for k, v in by_cat.items()
                       if k not in ("general", "pointer", "string", "address")
                       and v > 0}
        if interesting:
            cat_str = ", ".join(f"{v} {k}" for k, v in
                                sorted(interesting.items(), key=lambda x: -x[1])[:5])
            lines.append(f"\nFindings: {cat_str}")

        return "\n".join(lines)

    def _section_gaps(self) -> str:
        gaps = self.kg.list_gaps(resolved=False)
        if not gaps:
            return ""

        lines = ["## Open Gaps"]
        lines.append(f"{len(gaps)} expected capabilities not yet found:\n")

        for g in sorted(gaps, key=lambda x: -x.get("priority", 0))[:6]:
            cands = g.get("candidates", [])
            cand_str = f" — {len(cands)} candidate(s)" if cands else ""
            hints = g.get("hints", [])
            hint_str = f"\n    Hint: {hints[0]}" if hints else ""
            lines.append(f"  • {g['expected']}{cand_str}{hint_str}")

        return "\n".join(lines)

    def _section_threats(self) -> str:
        attack_surface = self.kg.list_attack_surface()
        vulns = self.bb.list(category="vuln", include_resolved=False, limit=5)
        iocs = self.bb.list(category="ioc", include_resolved=False, limit=5)

        if not attack_surface and not vulns and not iocs:
            return ""

        lines = ["## Security"]

        if attack_surface:
            # Group by reachable_from
            by_reach: dict[str, list] = {}
            for a in attack_surface:
                r = a.get("reachable_from", "unknown")
                by_reach.setdefault(r, []).append(a)
            for reach, entries in sorted(by_reach.items()):
                lines.append(f"  {reach}: {len(entries)} entry point(s)")

        if vulns:
            lines.append(f"\nVulnerabilities: {len(vulns)} open")
            for v in vulns[:3]:
                lines.append(f"  ⚠ {v['title']} @ {v.get('addr', '?')} "
                             f"(confidence {v.get('confidence', 0):.0%})")

        if iocs:
            lines.append(f"\nIOCs: {len(iocs)}")
            for ioc in iocs[:3]:
                lines.append(f"  • {ioc.get('ioc_type', '?')}: {ioc.get('ioc_value', '?')}")

        return "\n".join(lines)

    def _section_next_action(self) -> str:
        lines = ["## Recommended Next Action"]

        # Priority 1: open vulns
        vulns = self.bb.list(category="vuln", include_resolved=False, limit=1)
        if vulns:
            v = vulns[0]
            lines.append(f"Investigate vulnerability: {v['title']}")
            lines.append(f"  → Decompile {v.get('addr', '?')} and trace the full call stack")
            return "\n".join(lines)

        # Priority 2: high-priority gap with candidates
        gaps = self.kg.list_gaps(resolved=False)
        for g in gaps:
            if g.get("candidates"):
                lines.append(f"Fill gap: {g['expected']}")
                lines.append(f"  → Analyze candidate at {g['candidates'][0]}")
                return "\n".join(lines)

        # Priority 3: next_target from blackboard
        try:
            targets = self.bb.next_target(limit=1)
            if targets:
                t = targets[0]
                lines.append(f"Analyze: {t['title']} @ {t['addr']}")
                lines.append(f"  → Decompile and classify (priority score: {t['priority_score']})")
                return "\n".join(lines)
        except Exception:
            pass

        # Priority 4: open gaps without candidates
        if gaps:
            g = gaps[0]
            hints = g.get("hints", [])
            lines.append(f"Find: {g['expected']}")
            if hints:
                lines.append(f"  → {hints[0]}")
            return "\n".join(lines)

        lines.append("Read ida://blackboard/next_target for the highest-priority address.")
        return "\n".join(lines)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _infer_binary_type(self) -> str:
        """Infer binary type from blackboard tags and IOC types."""
        try:
            stats = self.bb.stats()
            by_cat = stats.get("by_category", {})
            iocs = stats.get("iocs", {})

            # WiFi firmware signals
            wifi_signals = 0
            if by_cat.get("region", 0) > 2:
                wifi_signals += 1
            if iocs.get("ip_port", 0) > 0:
                wifi_signals += 1

            # Check tags in blackboard
            try:
                entries = self.bb.list(limit=50, include_resolved=True)
                all_tags = []
                for e in entries:
                    all_tags.extend(e.get("tags", []))
                tag_str = " ".join(all_tags).lower()
                if any(w in tag_str for w in ("wifi", "802.11", "wpa", "ssid", "beacon")):
                    return "WiFi firmware"
                if any(w in tag_str for w in ("router", "nat", "dhcp", "dns")):
                    return "Router firmware"
                if any(w in tag_str for w in ("ble", "bluetooth", "gatt")):
                    return "Bluetooth firmware"
                if any(w in tag_str for w in ("zigbee", "z-wave", "thread")):
                    return "IoT mesh firmware"
            except Exception:
                pass

            if wifi_signals >= 2:
                return "WiFi firmware (inferred)"
        except Exception:
            pass
        return ""
