"""
GapEngine — auto-generates expected gaps from binary type + protocol specs.

For a WiFi firmware, we know it MUST have:
  - A packet RX interrupt handler
  - An 802.11 frame classifier
  - A WPA key derivation function
  - A beacon parser (station mode) or generator (AP mode)
  - A channel switching function
  - A regulatory domain table
  - A power management state machine
  - A host interface (SDIO/SPI/USB)

GapEngine seeds these gaps on first analysis, then tries to fill them
by matching against blackboard entries and classifier outputs.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional


# ── Gap specs per binary type ─────────────────────────────────────────────────

WIFI_GAPS = [
    {
        "expected": "Packet RX interrupt handler",
        "why": "All WiFi firmware must handle DMA/interrupt-driven packet reception",
        "hints": [
            "Look for functions called from interrupt vectors (low addresses in .vectors)",
            "Look for DMA descriptor reads followed by function dispatch",
            "Search for references to RX ring buffer or DMA status registers",
        ],
        "gap_type": "capability",
        "priority": 0.95,
    },
    {
        "expected": "802.11 frame classifier / demux",
        "why": "Must dispatch management, control, and data frames to separate handlers",
        "hints": [
            "Look for a switch on byte 0 of the frame (frame control field)",
            "Look for a function with 3+ call targets based on a small integer",
            "Search for string references to 'MGMT', 'DATA', 'CTRL'",
        ],
        "gap_type": "protocol",
        "priority": 0.9,
    },
    {
        "expected": "WPA2 key derivation (PBKDF2/PRF)",
        "why": "WPA2-PSK requires PBKDF2 for PMK and PRF-384/512 for PTK derivation",
        "hints": [
            "Look for HMAC-SHA1 or HMAC-SHA256 with 4096 iterations",
            "Look for functions with large loop counts and SHA operations",
            "Search for string 'PMK' or 'Pairwise key expansion'",
        ],
        "gap_type": "security",
        "priority": 0.85,
    },
    {
        "expected": "4-way handshake handler",
        "why": "WPA2 requires EAPOL 4-way handshake for key establishment",
        "hints": [
            "Look for EAPOL frame type (0x888E) in dispatch table",
            "Look for functions that write to PTK/GTK key slots",
            "Search for string 'EAPOL' or '4-way'",
        ],
        "gap_type": "security",
        "priority": 0.85,
    },
    {
        "expected": "Beacon parser (station mode) or generator (AP mode)",
        "why": "Station mode: parse beacons for SSID/BSSID/capabilities. AP mode: generate beacons.",
        "hints": [
            "Look for functions that parse 802.11 management frame IEs (information elements)",
            "Look for references to beacon interval timer",
            "Search for string 'SSID' or 'beacon'",
        ],
        "gap_type": "protocol",
        "priority": 0.8,
    },
    {
        "expected": "Channel switching / RF tuning",
        "why": "Must switch channels for scanning and operation",
        "hints": [
            "Look for writes to RF peripheral registers with channel frequency values",
            "Look for a table of channel-to-frequency mappings",
            "Search for references to regulatory domain or channel list",
        ],
        "gap_type": "hardware",
        "priority": 0.75,
    },
    {
        "expected": "Power management state machine",
        "why": "WiFi chips implement sleep/wake cycles for power saving (PS-Poll, U-APSD)",
        "hints": [
            "Look for writes to power control peripheral registers",
            "Look for functions that reference DTIM interval or listen interval",
            "Look for a state variable with values like AWAKE/DOZE/SLEEP",
        ],
        "gap_type": "capability",
        "priority": 0.7,
    },
    {
        "expected": "Host interface command handler (SDIO/SPI/USB)",
        "why": "WiFi chip communicates with host CPU via SDIO, SPI, or USB",
        "hints": [
            "Look for a command dispatch table indexed by command ID",
            "Look for DMA transfers to/from host memory",
            "Look for SDIO/SPI peripheral register accesses",
        ],
        "gap_type": "capability",
        "priority": 0.8,
    },
    {
        "expected": "Regulatory domain / country code table",
        "why": "Must restrict channels and TX power per regulatory domain",
        "hints": [
            "Look for a table of 2-character country codes",
            "Look for channel lists indexed by country code",
            "Search for string 'US', 'EU', 'JP' near channel data",
        ],
        "gap_type": "capability",
        "priority": 0.6,
    },
    {
        "expected": "Firmware version / build info",
        "why": "All firmware has a version string for identification",
        "hints": [
            "Search for strings matching version patterns (e.g. '1.2.3', 'v2.0')",
            "Look for a struct with build date + version number near .rodata start",
        ],
        "gap_type": "capability",
        "priority": 0.5,
    },
]

ROUTER_GAPS = [
    {
        "expected": "NAT/firewall packet processing",
        "why": "Routers perform NAT and packet filtering on forwarded traffic",
        "hints": ["Look for connection tracking table", "Look for iptables-style rule matching"],
        "gap_type": "capability", "priority": 0.9,
    },
    {
        "expected": "DHCP server",
        "why": "Routers serve DHCP to LAN clients",
        "hints": ["Look for UDP port 67/68 handling", "Search for string 'DHCP' or 'lease'"],
        "gap_type": "protocol", "priority": 0.85,
    },
    {
        "expected": "DNS resolver/proxy",
        "why": "Routers proxy DNS queries",
        "hints": ["Look for UDP port 53 handling", "Search for string 'DNS' or 'resolver'"],
        "gap_type": "protocol", "priority": 0.8,
    },
]

BLE_GAPS = [
    {
        "expected": "GATT server / attribute table",
        "why": "BLE devices expose services via GATT",
        "hints": ["Look for UUID tables", "Search for string 'GATT' or 'characteristic'"],
        "gap_type": "protocol", "priority": 0.9,
    },
    {
        "expected": "L2CAP packet handler",
        "why": "BLE uses L2CAP for logical link control",
        "hints": ["Look for CID-based dispatch", "Search for string 'L2CAP'"],
        "gap_type": "protocol", "priority": 0.85,
    },
]

GAPS_BY_TYPE: Dict[str, List[Dict]] = {
    "wifi_firmware": WIFI_GAPS,
    "router_firmware": ROUTER_GAPS,
    "ble_firmware": BLE_GAPS,
}

# Generic gaps for any firmware
GENERIC_GAPS = [
    {
        "expected": "Hardware initialization sequence",
        "why": "All firmware initializes peripherals at startup",
        "hints": ["Look for the reset/startup function (entry point or .init section)",
                  "Look for sequential writes to multiple peripheral base addresses"],
        "gap_type": "hardware", "priority": 0.7,
    },
    {
        "expected": "Interrupt vector table",
        "why": "All embedded firmware has an interrupt vector table",
        "hints": ["On ARM Cortex-M: first 4 bytes = initial SP, next 4 = reset handler",
                  "Look for a table of function pointers at the start of flash"],
        "gap_type": "hardware", "priority": 0.65,
    },
    {
        "expected": "Memory allocator (malloc/free or custom)",
        "why": "Firmware needs dynamic memory management",
        "hints": ["Look for functions that maintain a free list or heap pointer",
                  "Look for functions called with a size argument that return a pointer"],
        "gap_type": "capability", "priority": 0.6,
    },
]


class GapEngine:
    """
    Seeds and maintains the gap table in KnowledgeGraph.

    Usage:
        ge = GapEngine(kg)
        ge.seed_gaps("wifi_firmware")
        ge.try_fill_gaps(bb_store)  # attempt to fill gaps from blackboard
    """

    def __init__(self, kg):
        self.kg = kg

    def seed_gaps(self, binary_type: str = "unknown") -> int:
        """
        Seed expected gaps for the given binary type.
        Only adds gaps that don't already exist (by expected text).
        Returns number of gaps added.
        """
        existing = {g["expected"] for g in self.kg.list_gaps(resolved=False)}
        existing |= {g["expected"] for g in self.kg.list_gaps(resolved=True)}

        specs = GAPS_BY_TYPE.get(binary_type.lower().replace(" ", "_"), [])
        specs = specs + GENERIC_GAPS

        added = 0
        for spec in specs:
            if spec["expected"] in existing:
                continue
            self.kg.add_gap(
                expected=spec["expected"],
                why=spec.get("why", ""),
                hints=spec.get("hints", []),
                priority=spec.get("priority", 0.5),
                gap_type=spec.get("gap_type", "capability"),
                binary_type=binary_type,
            )
            added += 1
        return added

    def try_fill_gaps(self, bb_store) -> int:
        """
        Try to fill open gaps by matching against blackboard entries.
        Returns number of gaps filled.
        """
        gaps = self.kg.list_gaps(resolved=False)
        if not gaps:
            return 0

        # Get all blackboard entries with addresses
        try:
            entries = bb_store.list(limit=500, include_resolved=True)
        except Exception:
            return 0

        filled = 0
        for gap in gaps:
            candidate = self._find_candidate(gap, entries)
            if candidate:
                self.kg.add_gap_candidate(gap["id"], candidate)
                # Auto-fill if confidence is high
                matching_entry = next(
                    (e for e in entries if e.get("addr") == candidate), None
                )
                if matching_entry and matching_entry.get("confidence", 0) >= 0.8:
                    self.kg.fill_gap(gap["id"], candidate)
                    filled += 1

        return filled

    def _find_candidate(self, gap: Dict, entries: List[Dict]) -> Optional[str]:
        """
        Find a blackboard entry that might fill this gap.
        Uses keyword matching on title/content/tags against gap hints.
        """
        expected = gap["expected"].lower()
        hints = [h.lower() for h in gap.get("hints", [])]

        # Keywords to match
        keywords = set(re.findall(r'\b\w{4,}\b', expected))
        for hint in hints[:2]:
            keywords.update(re.findall(r'\b\w{4,}\b', hint))

        best_addr = None
        best_score = 0

        for entry in entries:
            if not entry.get("addr"):
                continue
            text = " ".join([
                entry.get("title", ""),
                entry.get("content", ""),
                " ".join(entry.get("tags", [])),
            ]).lower()

            score = sum(1 for kw in keywords if kw in text)
            if score > best_score:
                best_score = score
                best_addr = entry["addr"]

        return best_addr if best_score >= 2 else None

    def detect_binary_type(self, bb_store) -> str:
        """
        Infer binary type from blackboard content.
        Returns one of: wifi_firmware, router_firmware, ble_firmware, unknown
        """
        try:
            entries = bb_store.list(limit=100, include_resolved=True)
            all_text = " ".join(
                (e.get("title", "") + " " + e.get("content", "") +
                 " ".join(e.get("tags", [])))
                for e in entries
            ).lower()

            iocs = bb_store.list(category="ioc", limit=50, include_resolved=True)
            ioc_text = " ".join(
                i.get("ioc_value", "") + " " + i.get("ioc_type", "")
                for i in iocs
            ).lower()

            combined = all_text + " " + ioc_text

            if any(w in combined for w in ("802.11", "wpa", "ssid", "beacon",
                                            "wifi", "wlan", "bssid")):
                return "wifi_firmware"
            if any(w in combined for w in ("nat", "dhcp", "iptables", "router",
                                            "forwarding")):
                return "router_firmware"
            if any(w in combined for w in ("gatt", "ble", "bluetooth", "uuid",
                                            "characteristic")):
                return "ble_firmware"
        except Exception:
            pass
        return "unknown"
