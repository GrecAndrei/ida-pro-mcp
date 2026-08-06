# Signatures

FLIRT signature matching — apply offline `.sig` files to name known library functions.

| Operation | Purpose | Required |
| --- | --- | --- |
| `ida_list_sigs(query)` | List available `.sig` files on disk, optionally filtered by name. Also reports which signatures are already applied. | — |
| `ida_apply_sig(name)` | Apply a FLIRT signature file to the current IDB. `name` is the basename without `.sig` (e.g. `gnu`, `android_arm64`). | `name`, `risk_ack` |

## What FLIRT does

FLIRT (Fast Library Identification and Recognition Technology) matches byte
patterns in compiled code against a prebuilt database of known library
functions. When a match is found, IDA renames the `sub_XXXXXX` stub to the
library function name (e.g. `memcpy`, `pthread_create`). This is entirely
offline — no network connection, no cloud service.

## Working pattern

1. `ida_list_sigs` to see what is available and what is already applied.
2. Pick the right `.sig` for the target (architecture + libc/SDK variant).
3. `ida_apply_sig(name)` to apply it. Re-run analysis if needed to propagate
   the new names.

## Versus Lumina

FLIRT works from local `.sig` files and requires no connectivity. Lumina is
IDA's cloud-based crowdsourced naming service — it queries Hex-Rays servers
to pull function names matched by the community. Use FLIRT first (fast,
offline, deterministic); fall back to Lumina for functions that FLIRT doesn't
cover (available via `ida_python` through `ida_lumina` API calls).

## Notes

- `ida_apply_sig` requires `risk_ack: true` — applying a signature renames
  functions in the IDB permanently.
- RISC-V `.sig` files are not included in the standard IDA distribution;
  for RISC-V firmware, FLIRT coverage is minimal.
- Use `ida_list_sigs(query="arm")` to filter by architecture.
