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
