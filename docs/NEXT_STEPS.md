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
taxonomy, and structured failure evidence. Redirects are still recorded but never followed.

## Milestone 2.3 — Worker boundary completion

1. engagement-level redaction profiles;
2. evidence bundle export and receipt verification;
3. connection-bound DNS/TLS provenance to reduce DNS-rebinding ambiguity;
4. explicit same-origin redirect permits before any redirect following is enabled;
5. separate policy-service / signer / verifier / worker / evidence-store interfaces;
6. move local JSON lifecycle/rate state toward a transactional storage abstraction.

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
