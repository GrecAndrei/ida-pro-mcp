# Knowledge Graph

The knowledge graph is the structured firmware understanding layer. It lives in the same `.blackboard.db` SQLite file as the blackboard but in separate tables, so it's queryable independently.

## What It Models

| Node type | What it represents | Example |
|---|---|---|
| **System** | A cluster of functions implementing one capability | "Packet RX pipeline: 0x401000, 0x402000, 0x403000" |
| **Struct** | An inferred data structure with member offsets | "wifi_frame_t: {offset:0 frame_ctrl, offset:4 duration}" |
| **State machine** | A detected state machine with transitions | "802.11 auth SM: IDLE→SCANNING→AUTH→ASSOC" |
| **Gap** | An expected capability not yet found | "WPA key derivation — look for HMAC-SHA1 with 4096 iterations" |
| **Attack surface** | An entry point reachable from external input | "Management frame handler @ 0x401000, air_unauthenticated" |
| **Peripheral** | An MMIO peripheral | "AES accelerator @ 0xA0010000, crypto type" |

## Reading the KG

```json
{"name": "blackboard", "arguments": {"action": "kg_summary"}}
{"name": "blackboard", "arguments": {"action": "kg_systems"}}
{"name": "blackboard", "arguments": {"action": "kg_gaps"}}
{"name": "blackboard", "arguments": {"action": "kg_gaps", "resolved": true}}
{"name": "blackboard", "arguments": {"action": "kg_structs"}}
{"name": "blackboard", "arguments": {"action": "kg_state_machines"}}
{"name": "blackboard", "arguments": {"action": "kg_attack_surface"}}
{"name": "blackboard", "arguments": {"action": "kg_peripherals"}}
```

Or via MCP resources (no tool call needed):
```
ida://knowledge              — summary of all node counts
ida://knowledge/systems      — all systems
ida://knowledge/gaps         — open and filled gaps
ida://knowledge/structs      — inferred data structures
ida://knowledge/state_machines
ida://knowledge/attack_surface
ida://knowledge/peripherals
```

## Writing to the KG

### Add a system
```json
{"name": "blackboard", "arguments": {
  "action": "add_system",
  "title": "Packet RX pipeline",
  "content": "DMA interrupt → frame classifier → protocol demux",
  "members": ["0x401000", "0x402000", "0x403000"],
  "entry_points": ["0x401000"],
  "exit_points": ["0x403000"],
  "confidence": 0.85
}}
```

### Add a gap
```json
{"name": "blackboard", "arguments": {
  "action": "add_gap",
  "title": "WPA2 key derivation (PBKDF2/PRF)",
  "content": "All WPA2 firmware must derive PTK/GTK",
  "hints": ["Look for HMAC-SHA1 with 4096 iterations", "Search for string 'PMK'"],
  "confidence": 0.9,
  "gap_type": "security"
}}
```

### Fill a gap (once found)
```json
{"name": "blackboard", "arguments": {
  "action": "fill_gap",
  "gap_id": "abc123",
  "addr": "0x401234"
}}
```

### Add a struct
```json
{"name": "blackboard", "arguments": {
  "action": "add_struct",
  "title": "wifi_frame_t",
  "members": [
    {"offset": 0, "size": 2, "name": "frame_ctrl", "type": "u16"},
    {"offset": 2, "size": 2, "name": "duration", "type": "u16"},
    {"offset": 4, "size": 6, "name": "addr1", "type": "u8[6]"}
  ],
  "size_bytes": 24,
  "confidence": 0.8
}}
```

### Add a state machine
```json
{"name": "blackboard", "arguments": {
  "action": "add_state_machine",
  "title": "802.11 authentication state machine",
  "addr": "0x80420000",
  "states": [
    {"value": 0, "name": "IDLE"},
    {"value": 1, "name": "SCANNING"},
    {"value": 2, "name": "AUTHENTICATING"},
    {"value": 3, "name": "ASSOCIATED"}
  ],
  "confidence": 0.75
}}
```

### Add a peripheral
```json
{"name": "blackboard", "arguments": {
  "action": "add_peripheral",
  "addr": "0xA0010000",
  "title": "AES hardware accelerator",
  "periph_type": "crypto",
  "drivers": ["0x401234", "0x401500"],
  "confidence": 0.8
}}
```

### Add attack surface entry
```json
{"name": "blackboard", "arguments": {
  "action": "add_attack_surface",
  "addr": "0x401000",
  "title": "Management frame handler",
  "reachable_from": "air_unauthenticated",
  "input_type": "management_frame",
  "confidence": 0.9
}}
```

## Auto-Population

The analysis engine populates the KG automatically:

- **System discovery** — clusters functions by dominant behavior tag (≥3 functions with same tag = system)
- **Struct inference** — detects structs from `data_flow` entries with matching register+offset patterns
- **State machine detection** — finds switch-on-global patterns
- **Peripheral detection** — identifies MMIO regions from high-entropy/aligned addresses
- **Attack surface mapping** — maps IOC entries to attack surface with reachability
- **Gap seeding** — seeds expected gaps based on detected binary type (WiFi/Router/BLE)
- **Gap filling** — tries to fill gaps by keyword-matching blackboard entries against gap hints

The `response_enrichment` pipeline also updates the KG: when a function is classified with behavior tags, it's automatically added to the matching system and any relevant gaps get a candidate address.

## Gap Types

| Type | Meaning |
|---|---|
| `capability` | A functional capability the binary must have |
| `protocol` | A protocol handler or parser |
| `hardware` | A hardware interface or driver |
| `security` | A security-critical function (crypto, auth, validation) |

## Coverage Metric

`ida://state` shows coverage as `systems_found / (systems_found + open_gaps)`. Fill gaps to increase coverage. The narrative engine uses this to generate the "Understanding: X%" line.

## Firmware RE Workflow

1. Read `ida://state` — see what systems and gaps exist
2. Read `ida://knowledge/gaps` — see what's expected but missing
3. Analyze candidates for each gap
4. Call `blackboard(action="fill_gap", gap_id=..., addr=...)` when found
5. Call `blackboard(action="add_system", ...)` when you identify a new subsystem
6. Read `ida://state` again — coverage percentage increases
