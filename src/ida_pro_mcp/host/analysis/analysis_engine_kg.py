"""Knowledge-graph stage mixin for AnalysisEngine."""

from __future__ import annotations

import time


class AnalysisEngineKnowledgeGraphMixin:
    def _stage_knowledge_graph(self):
        """
        Run all KG analysis sub-stages:
          a) Detect binary type + seed gaps (once)
          b) System discovery from call graph clusters
          c) Struct inference from offset access patterns
          d) State machine detection
          e) Peripheral detection from MMIO accesses
          f) Attack surface mapping
          g) Try to fill open gaps
          h) Regenerate narrative if due
        """
        kg = self._get_kg()
        store = self._bb_store()
        if not kg or not store:
            return

        # a) Seed gaps once
        if not self._gaps_seeded:
            try:
                from .gap_engine import GapEngine
                ge = GapEngine(kg)
                if not self._binary_type:
                    self._binary_type = ge.detect_binary_type(store)
                ge.seed_gaps(self._binary_type)
                self._gaps_seeded = True
            except Exception:
                pass

        # b) System discovery
        self._kg_discover_systems(kg, store)

        # c) Struct inference
        self._kg_infer_structs(kg, store)

        # d) State machine detection
        self._kg_detect_state_machines(kg, store)

        # e) Peripheral detection
        self._kg_detect_peripherals(kg, store)

        # f) Attack surface
        self._kg_map_attack_surface(kg, store)

        # g) Fill gaps
        try:
            from .gap_engine import GapEngine
            GapEngine(kg).try_fill_gaps(store)
        except Exception:
            pass

        # h) Narrative
        now = time.time()
        if now - self._last_narrative_ts >= self._narrative_interval:
            self._regenerate_narrative(kg, store)
            self._last_narrative_ts = now

        self._push_resource_updated("ida://state")

    def _kg_discover_systems(self, kg, store):
        """
        Discover systems by clustering blackboard entries with the same tags.

        A system is a group of ≥3 functions sharing a dominant behavior tag
        (e.g. 'crypto_symmetric', 'network_http') that are connected by xrefs.
        """
        entries = store.list(limit=500, include_resolved=False)
        # Group by dominant tag
        tag_groups: Dict[str, List[str]] = {}
        for e in entries:
            addr = e.get("addr", "")
            if not addr:
                continue
            tags = [t for t in e.get("tags", [])
                    if t not in ("manual", "engine", "crawler", "rejected",
                                 "entropy", "cluster", "xref", "seed")]
            if not tags:
                continue
            dominant = tags[0]
            tag_groups.setdefault(dominant, []).append(addr)

        existing_systems = {s["name"] for s in kg.list_systems()}

        for tag, addrs in tag_groups.items():
            if len(addrs) < 3:
                continue
            sys_name = f"{tag} subsystem"
            if sys_name in existing_systems:
                # Update members
                for s in kg.list_systems():
                    if s["name"] == sys_name:
                        new_members = list(set(s["members"]) | set(addrs))
                        if len(new_members) != len(s["members"]):
                            kg.update_system(s["id"], members=new_members,
                                             coverage_pct=min(100.0, len(new_members) * 10))
                        break
                continue

            # New system
            sid = kg.add_system(
                name=sys_name,
                members=addrs,
                description=f"Functions classified as {tag}",
                tags=[tag],
                confidence=0.6,
            )
            self._notify({
                "jsonrpc": "2.0",
                "method": "notifications/message",
                "params": {
                    "level": "info",
                    "data": {
                        "type": "system_discovered",
                        "message": f"System discovered: {sys_name} ({len(addrs)} functions)",
                        "system_id": sid,
                        "members": addrs[:5],
                    },
                },
            })
            existing_systems.add(sys_name)

    def _kg_infer_structs(self, kg, store):
        """
        Infer data structures from data_flow entries.

        If multiple data_flow entries at different addresses reference the same
        register with different offsets, they likely access the same struct.
        """
        df_entries = store.list(category="data_flow", limit=200, include_resolved=True)
        if len(df_entries) < 3:
            return

        # Group by register name
        reg_groups: Dict[str, List[Dict]] = {}
        for e in df_entries:
            reg = e.get("register", "")
            if reg:
                reg_groups.setdefault(reg, []).append(e)

        for reg, entries in reg_groups.items():
            if len(entries) < 3:
                continue
            # Extract offsets from reg_type field (e.g. "wifi_frame_t+0x14")
            offsets = []
            for e in entries:
                rt = e.get("reg_type", "")
                import re as _re
                m = _re.search(r'\+0x([0-9a-f]+)', rt, _re.I)
                if m:
                    offsets.append(int(m.group(1), 16))

            if len(offsets) < 2:
                continue

            # Check if this matches an existing struct
            existing = kg.find_struct_by_offset_pattern(offsets)
            if existing:
                # Record new access sites
                for e in entries:
                    if e.get("addr"):
                        kg.record_struct_access(existing["id"], e["addr"],
                                                "read", offsets[0] if offsets else 0)
                continue

            # Infer new struct
            members = [{"offset": o, "size": 4, "type": "unknown",
                        "name": f"field_{o:03x}", "evidence": "data_flow"}
                       for o in sorted(set(offsets))]
            struct_name = f"struct_{reg}_t"
            existing_names = {s["name"] for s in kg.list_structs()}
            if struct_name not in existing_names:
                kg.add_struct(
                    name=struct_name,
                    members=members,
                    size_bytes=max(offsets) + 4 if offsets else 0,
                    confidence=0.5,
                )

    def _kg_detect_state_machines(self, kg, store):
        """
        Detect state machines from blackboard entries tagged 'state_machine'
        or from data_flow entries that write to a global.
        """
        # Look for entries that mention state variables
        entries = store.list(limit=200, include_resolved=False)
        state_vars: Dict[str, List[Dict]] = {}
        for e in entries:
            tags = e.get("tags", [])
            if "state_machine" in tags or "state_var" in tags:
                addr = e.get("addr", "")
                if addr:
                    state_vars.setdefault(addr, []).append(e)

        existing_vars = {sm.get("state_var") for sm in kg.list_state_machines()}

        for var_addr, entries_list in state_vars.items():
            if var_addr in existing_vars:
                continue
            # Infer state machine name from tags
            all_tags = []
            for e in entries_list:
                all_tags.extend(e.get("tags", []))
            name_tags = [t for t in all_tags
                         if t not in ("state_machine", "state_var", "engine", "manual")]
            sm_name = f"{name_tags[0]} state machine" if name_tags else f"state machine @ {var_addr}"

            kg.add_state_machine(
                name=sm_name,
                state_var=var_addr,
                confidence=0.55,
            )

    def _kg_detect_peripherals(self, kg, store):
        """
        Detect peripherals from high-entropy region entries and IOC entries
        that reference MMIO-like regions.
        """
        regions = store.list(category="region", include_resolved=True, limit=100)
        addr_vals: List[int] = []
        for r in regions:
            try:
                if r.get("addr"):
                    addr_vals.append(int(str(r.get("addr")), 16))
            except Exception:
                continue
        addr_vals.sort()
        high_addr_gate = addr_vals[int(round((len(addr_vals) - 1) * 0.85))] if addr_vals else 0

        for r in regions:
            addr = r.get("addr", "")
            if not addr:
                continue
            try:
                addr_int = int(addr, 16)
            except Exception:
                continue
            tags = r.get("tags", [])
            tag_text = " ".join(str(t).lower() for t in tags)
            is_mmio_tagged = "mmio" in tag_text or "peripheral" in tag_text or "io" in tag_text
            # Prefer explicit tags; otherwise use distribution-aware gate for
            # region addresses and alignment cues.
            if not is_mmio_tagged:
                if not high_addr_gate or addr_int < high_addr_gate:
                    continue
                if addr_int % 0x1000 != 0 and addr_int % 0x100 != 0:
                    continue
            # Infer peripheral type from tags/title
            title = r.get("title", "").lower()
            ptype = "unknown"
            if any(w in title for w in ("uart", "serial", "usart")):
                ptype = "uart"
            elif any(w in title for w in ("spi", "qspi")):
                ptype = "spi"
            elif any(w in title for w in ("dma",)):
                ptype = "dma"
            elif any(w in title for w in ("aes", "crypto", "cipher")):
                ptype = "crypto"
            elif any(w in title for w in ("timer", "pwm", "rtc")):
                ptype = "timer"
            elif any(w in title for w in ("gpio", "pin")):
                ptype = "gpio"
            elif "entropy" in tags:
                ptype = "crypto"  # high-entropy MMIO region → likely crypto accelerator

            kg.add_peripheral(
                base_addr=addr,
                name=r.get("title", f"peripheral @ {addr}"),
                periph_type=ptype,
                confidence=0.5,
            )

    def _kg_map_attack_surface(self, kg, store):
        """
        Map attack surface from IOC entries and vuln entries.
        """
        iocs = store.list(category="ioc", include_resolved=False, limit=50)
        existing_eps = {a["entry_point"] for a in kg.list_attack_surface()}

        for ioc in iocs:
            addr = ioc.get("addr", "")
            if not addr or addr in existing_eps:
                continue
            ioc_type = ioc.get("ioc_type", "")
            # Determine reachability
            if ioc_type in ("ip_port", "url", "domain"):
                reachable = "air_unauthenticated"
                input_type = "network_packet"
            elif ioc_type in ("crypto_key", "crypto_iv"):
                reachable = "air_authenticated"
                input_type = "encrypted_data"
            else:
                reachable = "unknown"
                input_type = "unknown"

            kg.add_attack_surface(
                entry_point=addr,
                name=ioc.get("title", ""),
                reachable_from=reachable,
                input_type=input_type,
                confidence=ioc.get("confidence", 0.5),
            )
            existing_eps.add(addr)

        # Vuln entries → update attack surface with known_vulns
        vulns = store.list(category="vuln", include_resolved=False, limit=20)
        for vuln in vulns:
            addr = vuln.get("addr", "")
            if not addr:
                continue
            for as_entry in kg.list_attack_surface():
                if as_entry["entry_point"] == addr:
                    known = as_entry.get("known_vulns", [])
                    if vuln["id"] not in known:
                        known.append(vuln["id"])
                        kg.update_attack_surface(as_entry["id"],
                                                  known_vulns=known,
                                                  fuzz_priority=min(0.99, as_entry.get("fuzz_priority", 0.5) + 0.2))

    def _regenerate_narrative(self, kg, store):
        """Generate narrative and write it to blackboard as a 'narrative' entry."""
        try:
            from .narrative_engine import NarrativeEngine
            ne = NarrativeEngine(kg, store)
            # Get binary meta from a recent idb call if possible
            try:
                meta = self._rpc("idb", {"action": "meta"})
            except Exception:
                meta = {}
            text = ne.generate(binary_meta=meta)
            if not text.strip():
                return

            # Write/update the narrative entry in blackboard
            existing = store.list(category="narrative", limit=1, include_resolved=True)
            if existing:
                store.update(existing[0]["id"], content=text, title="Analysis Narrative")
            else:
                store.write(
                    "Analysis Narrative",
                    content=text,
                    category="narrative",
                    confidence=1.0,
                    source="engine",
                    source_type="engine_narrative",
                    embed=False,
                )
            self._push_resource_updated("ida://state")
        except Exception:
            pass

    def _get_kg(self):
        """Lazy-init KnowledgeGraph."""
        if self._kg is None:
            try:
                from ..stores.knowledge_graph import KnowledgeGraph
                self._kg = KnowledgeGraph(self._bb_path)
            except Exception:
                pass
        return self._kg

