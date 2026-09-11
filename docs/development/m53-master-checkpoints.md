# M53 local master completion checkpoints

## M1 — real ProgramOperationalLease lifecycle

Status: `M53_HIGH_1_REAL_LEASE_PASS`

The authorization path now requires a durable `OperationalLeaseStore` before
a stale operational attestation can be extended by a lease. The store provides
atomic issuance, recovery, renewal/supersession and revocation state. Recovery
revalidates content integrity, revision and attestation binding, freshness,
activation and expiry; it cannot revive superseded, revoked, expired or
revision-invalid leases. Execution permits remain capped by the authoritative
lease validity boundary. `DetectorExecutionService` no longer trusts a
`lease_current` boolean: operationally bound programs must provide the real
engagement, attestation, durable lease authority and upstream signed execution
permit. Both authorities are revalidated before launch, and the detector-run
permit is capped by the lease boundary. All acceptance is local and performs
zero target I/O.

## M2 — full local intake to authorization and execution chain

Status: `M53_HIGH_2_AUTH_CHAIN_PASS`

`derive_local_authorized_detector_request` starts from fake browser listing and
detail captures, persists the capture and normalized program, compiles policy,
builds the target-bound semantic plan and fair queue, issues a durable real
operational lease, brokers an upstream signed execution permit, and constructs
the detector request only from those artifacts. `DetectorExecutionService`
revalidates the lease and permit before worker launch. The physical acceptance
ran the qualified Nuclei worker through the qualified counting proxy to the
isolated `astp-m52-lab` container with a one-request ceiling: attempted=1,
forwarded=1, responses=1, evidence=1, proof=`reproduced`. Missing permit and
revision drift both block before adapter invocation; the broader suite covers
offline/policy/scope/semantic/budget/method/runtime negative gates.

## M3 — physical chaos and durable recovery

Status: `M53_HIGH_3_PHYSICAL_CHAOS_PASS`

The eight-point chaos matrix now launches qualified detector workers only
through the Docker counting-proxy boundary and isolated synthetic lab. Faults
cover pre-launch, launched-before-I/O, first-forward, response-before-evidence,
normalized-evidence-before-persistence, proof/finding recovery, a real named
worker kill after the target response, and interrupted report generation.
Each scenario runs in a separate process and campaign. Host-side recovery
reopens the durable result and proxy ledger without replaying completed work.
The final physical acceptance passed 8/8 with nine unique permits, zero permit
reuse, two safe fresh-permit retries, two UNKNOWN outcomes, zero duplicate
evidence/findings, and zero orphan worker/proxy containers. Independent
container lifecycle artifacts confirm workers never attach directly to the
target network. Aggregate counts, evidence, proof states, and findings are
derived from SQLite ledgers and durable detector results rather than constants.

## M4 — scheduler/state-derived accelerated night

Status: `M53_HIGH_4_SCHEDULER_NIGHT_PASS`

The durable scheduler now owns physical dispatch. One eligible work decision
launches at most one `DetectorExecutionService` attempt; outcomes are persisted
before any retry becomes eligible. The local target's actual 429 and
`Retry-After` are read from the counting-proxy SQLite ledger. H remains pending
through durable restart and receives a fresh run, permit and renewed real lease
only in the later logical round, while other programs progress. G follows the
same scheduler-controlled fresh-authority retry after a physical worker failure.
F is not launched until its revision is replanned and a replacement lease is
installed. All physical dispatches carry a real program-bound engagement,
operational attestation, durable lease and upstream signed execution permit.

The injected clock produces T+0/T+2/T+5/T+8 and four scheduler rounds without
multi-hour sleeps. D exhaustion, E offline-to-online transition, process reopen,
deadline drain, run/permit counts, proof/finding counts and program terminal
states are derived from durable scheduler, detector result and proxy ledger
state. The final isolated Docker acceptance used nine scheduler dispatches with
nine unique run IDs and permits, zero reuse, one physical 429, two retries,
zero blind replay and zero orphan containers. Full validation passed with 798
tests. No real target traffic occurred.

## M5 — complete local A-H acceptance

Status: implemented and physically accepted; pending local checkpoint commit.

The acceptance report is reconstructed from durable artifacts instead of a
parallel expected-value narrative. It emits every required per-program field
for exactly A-H and independently rejects unauthorized or out-of-scope I/O,
permit reuse, blind replay, accounting mismatch, policy/semantic block I/O,
direct proxy fallback, sensitive signing-key leakage and Docker orphans.

Physical campaign: `.astp/physical/m53-m5-acceptance-v3`.

Program-specific acceptance proved policy-zero-I/O for B; semantic exclusion
before review and allowed execution after review for C; derived bounded
exhaustion for D; offline-to-online readiness for E; durable invalidation of
F's revision-1 lease, permit and plan before revision-2 launch; fresh retry
authority after G's worker crash; and H's physical 429 persisted backoff while
other programs progressed. The campaign manifest verifies offline.

Marker: `M53_LOCAL_AH_ACCEPTANCE_PASS`.

## M6/M7 — pre-push audit and HIGH remediation

The comprehensive local audit found one HIGH alternate execution path: the CLI
could still route non-accelerated local physical acceptance through the legacy
pass1 executor. M7 closed it at both CLI and direct-call boundaries. Regression
tests prove rejection happens before campaign state or adapter execution. The
post-remediation audit is CRITICAL=0, HIGH=0, MEDIUM=0, LOW=1 (dead-code cleanup
only). See `docs/development/m53-pre-push-audit.md`.

Marker: `M53_PRE_PUSH_AUDIT_PASS`.

Remaining roadmap: M8.
