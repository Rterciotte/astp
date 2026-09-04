# ASTP next steps

## Completed foundation

Milestones 0 through 1.4 establish conservative scope compilation, granular authorization, bounded
approvals, signed execution permits, replay protection, revocation, key IDs for rotation, and a
hash-linked local audit trail.

Milestone 2 adds the first permit-gated network component: a one-request HTTP observation worker for
`GET` and `HEAD`.

Milestone 2.1 adds canonical action identities, durable local per-target rate state, explicit
evidence IDs/sensitivity labels, and a hash-linked evidence manifest with artifact integrity checks.

Milestone 2.2 adds a transport interface, DNS/connection provenance, a bounded transport-failure
taxonomy, and structured failure evidence.

Milestone 2.3 binds connections to the addresses resolved for the authorized hostname, preserves TLS
hostname verification, adds engagement-specific redaction profiles, marks redirects as distinct
actions requiring new permits, and adds portable evidence bundles with verifiable receipts.

Milestone 2.4 introduces a local SQLite runtime for transactional worker admission, atomically
combines replay/lifecycle state with rate admission, adds explicit worker capability declarations,
and formalizes worker/admission/evidence dependency protocols. The CLI HTTP worker uses this runtime
by default while the older JSON lifecycle path remains available for compatibility.

## Milestone 2.5 — Durable evidence and execution receipts

1. execution-attempt IDs distinct from permits and evidence IDs;
2. durable execution receipts covering admission, transport result, and evidence registration;
3. recoverable evidence registration after a post-network process interruption;
4. explicit evidence-store adapter implementation behind the M2.4 protocol;
5. SQLite migrations and runtime health/introspection commands;
6. adversarial crash-boundary tests before browser execution is introduced.

## CTF track

When CTF implementation begins, update the complete project documentation—not only the CTF roadmap—
so README, architecture, security boundaries, terminology, CLI documentation, and milestone roadmap
all describe CTF mode consistently.

The first CTF implementation should define the challenge contract and isolated solver SDK described
in `CTF_MODE_ROADMAP.md`: artifact classification, flag-format validation, solve traces, and
reproducible retired/local challenges before category-specific autonomous solvers.

## Later milestones

Browser observation, context graph, external scanner adapters, unified finding schema, finding
correlation, proof validation, CVSS 4 + EPSS + KEV risk prioritization, reporting, retest,
white-box analysis, mobile analysis, and planner/LLM orchestration behind the same policy and permit
boundary.

Before distributed workers, replace shared-secret HMAC permits with asymmetric signatures and move
lifecycle/rate/audit state to transactional and independently protected storage.

## M2.5 completed — Bug Bounty Program Intake

- First-class `BugBountyProgram` model.
- Authenticated-browser intake is the preferred source path.
- Manifest V3 Browser Companion uses explicit `activeTab` access and loopback token auth.
- Deterministic scope/policy extraction preserves source provenance.
- Broad/qualitative rules become review issues rather than implicit permission.
- `compile-program` blocks executable engagement creation while blocking issues remain.
- Smart Fit / BugHunt fixture added as the first real-program intake case.

### M2.6 candidate — Program Review + Dynamic Operational Gates

1. Explicit review-resolution records instead of editing `issues` manually.
2. Program revision/diff model and policy snapshot history.
3. Runtime gate for ONLINE/OFFLINE program state.
4. Recommended HTTP identity metadata such as program User-Agent.
5. Program-specific excluded finding taxonomy.
6. First controlled Smart Fit field trial using only the existing GET/HEAD worker.

CTF documentation is intentionally not globally rewritten yet. The previously agreed full
CTF documentation update occurs when CTF implementation begins, not during intake work.


## M2.5.1 completed — Authenticated Program Discovery & Catalog

- Program-listing classification and same-origin candidate discovery.
- Sequential authenticated detail-page synchronization through the user's browser session.
- Persistent `BugBountyWorkspace` catalog with raw capture and normalized-program references.
- CLI catalog view and multi-program active selection.
- Plain-text DOM section parsing and automatic output-directory creation.

Next architectural block: target Browser/Discovery Worker. Multi-program target execution remains
deferred until worker scheduling can preserve independent engagement/policy/permit boundaries.

## M2.5.2 completed — Browser/Server Protocol Hardening

The first real authenticated BugHunt field trial exposed a browser-extension integration failure.
M2.5.2 adds protocol health negotiation, visible server logs, JSON errors, a two-step host
permission/discovery flow, persisted session progress, and end-to-end loopback HTTP tests.

Before M2.6, repeat the real BugHunt catalog synchronization and inspect any platform-specific
candidate-link or SPA-rendering failures that remain.

## M2.5.3 completed — Policy Review & Parser Correctness

M2.5.3 closes parser correctness findings from the first authenticated Smart Fit field trial:
constraint false positives, provenance section drift, constraint deduplication, capture timestamp
propagation, stable program identity, source-supported finding exclusions, and explicit policy
review. The next field step is to re-sync Smart Fit, inspect the regenerated policy, and resolve
only those blocking issues for which the operator can provide safe explicit mappings. Target-side
M2.6 work remains downstream of a READY engagement.
