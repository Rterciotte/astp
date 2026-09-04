# ASTP next steps

## Completed foundation

Milestones 0 through 1.4 establish conservative scope compilation, granular authorization, bounded
approvals, signed execution permits, replay protection, revocation, key IDs for rotation, and a
hash-linked local audit trail.

Milestone 2 adds the first permit-gated network component: a one-request HTTP observation worker for
`GET` and `HEAD`.

Milestone 2.1 adds canonical action identities, durable local per-target rate state, explicit
evidence IDs/sensitivity labels, and a hash-linked evidence manifest with artifact integrity checks.

## Milestone 2.2 — Evidence and transport hardening

1. configurable redaction profiles per engagement;
2. explicit DNS and connection metadata evidence without scope expansion;
3. structured failure evidence for DNS/TLS/timeout cases;
4. optional encrypted raw artifacts when explicitly required;
5. explicit redirect authorization if same-origin redirect following is introduced;
6. clearer policy-service / verifier / worker / evidence-store interfaces.

## CTF track

In parallel, define the non-network-heavy CTF challenge contract and isolated solver SDK described in
`CTF_MODE_ROADMAP.md`. Begin with artifact classification, flag-format validation, solve traces, and
reproducible retired/local challenges before adding category-specific autonomous solvers.

## Later milestones

Browser observation, context graph, external scanner adapters, unified finding schema, finding
correlation, proof validation, CVSS 4 + EPSS + KEV risk prioritization, reporting, retest,
white-box analysis, mobile analysis, and planner/LLM orchestration behind the same policy and permit
boundary.

Before distributed workers, replace shared-secret HMAC permits with asymmetric signatures and move
lifecycle/rate/audit state to transactional and independently protected storage.
