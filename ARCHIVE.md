# Archived

**This project is no longer maintained. It was superseded, not retired by its
author's choice.**

On 2026-09-27, Hex-Rays SA released the
[Official Hex-Rays IDA MCP Server](https://github.com/HexRaysSA/ida-mcp)
together with [IDA Nexus](https://github.com/HexRaysSA/ida-nexus), the
shared-database runtime it is built on. Development of this repository stopped
at `1.0.0a4` the same day.

This document is the honest closing account: what the project was, what it did
well, why it lost, and what is still worth something to whoever picks it up.

---

## What this was

A local Model Context Protocol server for IDA Pro. It shipped 102 strict-schema
`ida_*` operations, a durable findings store, an installer covering 22+ agent
environments, and a deterministic retrieval layer — roughly 108,000 lines of
source and 5,552 offline tests.

It started in 2025, during the Opus 4.5 era, at the moment where "an agent can
actually drive IDA" stopped being a demo. The project's premise was that agents
needed a meticulously specified surface: exact schemas, typed results, policy
tiers, explicit risk acknowledgement, and deterministic ranking so that a model
could not hallucinate its way through a binary.

That premise was reasonable then. It stopped being true later, for reasons that
are worth recording precisely.

### A note on the surviving history

The project's Git history does not go back to 2025. The original `.git` was
destroyed by accident partway through, and the repository was re-initialized and
force-pushed, so the earliest surviving commit is `2ddb6e78` on **2026-01-17**
("Initial commit of ida-pro-mcp"). Everything before that date exists only in
this document and in whatever the author's other backups hold.

What survives is **1,493 commits over 253 days**, ending at `08133eef` on the
archiving date. The shape of that surviving history is itself a record of how the
project was built: a ramp through February and March (83 and 96 commits), a
quiet April (29), two heavy build pushes in May and June (306 and 398), a
maintenance stretch across July and August (123 and 88), and a final large push
in September (368) that included a single day of 116 commits.

## How it ended

The competitive position was lost on distribution, not on capability.

Hex-Rays shipped a server exposing **six tools**:

| Tool | Purpose |
|---|---|
| `open_database` | attach to a GUI database or a headless idalib worker |
| `execute_python` | run arbitrary Python against the open database |
| `reference` | search the ida-domain API reference |
| `list_databases` | discover registered GUI and idalib instances |
| `save_database` | explicitly save |
| `close_database` | release this client's handle and lease |

The design bet is the inverse of this project's. Where this repository concluded
that an agent needed 102 guarded operations, Hex-Rays concluded that an agent
needs a Python interpreter, an API reference so it does not guess at `idaapi`
shapes, and nothing else. Six stable tools that cover the common case beat a
hundred and two that must each be maintained and kept correct.

Three specific advantages went with it:

- **Ownership of the SDK.** The vendor can add any capability this project has
  whenever it chooses to.
- **Default placement.** Their README instructs users to *"disable other IDA
  MCP servers to reduce agent confusion."* That is a direct statement about
  which server an agent gets pointed at.
- **Native database sharing.** IDA Nexus transparently shares databases already
  open in the IDA GUI, and leases one IDB across several concurrent clients.

The last point had been this project's one structural gap. It is also worth
recording that it was never a requirement for them: the GUI is an *optional
second backend*. The default path is a headless `idalib` worker, exactly as this
project used. Their README states plainly that without the GUI plugin the server
still works headlessly. The only hard gate is **IDA 9.4+ with idalib, Python
3.11+**, against this project's **IDA 9.0 through 9.4**.

## The honest diagnosis: scaffolding versus substance

The deepest lesson is not about the vendor. It is about what this project was
compensating for.

Most of the meticulousness existed to make a weak model reliable. Schema
enumeration, exact typed results, `ida_help` for argument discovery, the
deterministic ranking that stopped the agent guessing which operation to call —
all of it was scaffolding against models that could not hold a shape in their
head. That deficiency is largely gone. When the deficiency is gone, the
scaffolding does not become a virtue. It becomes a permanent maintenance tax
charged against the exact problem it was built to solve.

Removing scaffolding when its cause is gone is not a defeat. It is the whole
reason the scaffolding was built. But it does mean the work that survives is a
much smaller thing than the work that was done, and the two were committed
together, so they have to be separated honestly.

**What was never scaffolding.** Some of this did not exist to compensate for a
model at all, and a better model never made it cheaper:

- The durable findings store — findings with provenance, confidence, lifecycle
  state, conflict detection, audit history, and idempotent migrations, surviving
  outside the IDB. A stateless request/response server has nowhere to put this,
  and it is the one thing an agent doing a multi-hour investigation genuinely
  needs. A session that ends should not erase the findings.
- The installer. Writing correct, atomic, backed-up, rollback-safe MCP client
  configuration across 22 environments in four config formats is unglamorous
  work that does not care how good the model is.
- Transactional schema migrations, and the version/rollback discipline around
  them.

**What was scaffolding, and is now redundant.** The 102-operation catalog itself,
the policy tier machinery, the risk-acknowledgement flow, and the 33-entry legacy
`tool(action=...)` surface. The risk-acknowledgement flow is the clearest case:
it was defensive engineering against a threat model this project never had. Its
own author did not use it and did not value it; it existed to satisfy imagined
stakeholders. There is no `idb_write` tool here, so the argument the guardrail
was defending is not real. It should not be counted as an asset.

## What is still worth something

If someone wants to continue this work, these parts carry independent value:

1. **The test suite (5,552 tests).** It encodes hard-won IDA behavior — version
   quirks, SDK edge cases, decompiler and loader semantics, `idat` process
   lifecycle details. That knowledge took real time to acquire and is
   expensive to rediscover. It is worth more than the product ever was.
2. **The documentation.** `docs/guide/architecture.md` and the wiki describe IDA
   integration in some depth, including the failure modes.
3. **The one live advantage: version range.** This project supported IDA 9.0
   through 9.4. The official server requires 9.4+. Anyone on an older IDA has
   nowhere else to go. That is a real and shrinking asset.

## Practical notes for a successor

- **Licensing.** This repository is **GPL-3.0**. The official server and IDA
  Nexus are **MIT**. Anyone incorporating code from here into a permissively
  licensed or proprietary product inherits GPL-3.0 obligations. That is a
  materially different starting position and should be checked first.
- **Dependency direction.** The official stack is `ida-mcp` (MCP server) on top
  of `ida-nexus` (shared database runtime) on top of `zeromcp`. This project
  vendored its own copy of zeromcp rather than depending on it, which was a
  mistake — it meant maintaining a fork of a dependency the vendor also uses.
- **Do not resurrect the catalog.** The one thing this project's history proves
  is that a large strictly-typed operation surface is a liability against a
  six-tool interpreter. If the durable store is the part worth keeping, it
  should be built as a small number of tools that write durable facts, not as a
  comprehensive API surface.
- **The reorg work is preserved.** The `host/server/` package was reorganized
  shortly before archiving (commit `08133eef`), removing a redundant `server_`
  prefix and grouping the blackboard and session families. That cleanup stands
  on its own merits if the code is ever revived.

## What this document is not

It is not a criticism of Hex-Rays, who built a well-designed server and
documented it honestly, including the line about disabling other servers. It is
not a claim that this project was badly built — the offline suite passed clean,
coverage sat at 95.88%, and the tests and docs are the work of people who cared.

It is a record of a project that was well-timed when it was built, that lost the
distribution war to the party that owns the platform, and whose main artifact
turned out to be scaffolding for a deficiency that has since been solved
upstream.

## Attribution

Written by the project's author, with the analysis assisted by Claude.
Original work is GPL-3.0; see `LICENSE`.
