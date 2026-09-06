# ASTP 1.0 stable security model

ASTP is policy-first. Its safety boundary is not a disclaimer; it is part of the execution architecture.

## Core invariants

1. Authorization exists before target execution. ASTP never creates permission to test a system.
2. Discovery, parsing, static analysis, and hypothesis generation are non-authorizing operations.
3. Every target-touching action must match the current engagement/test policy and a fresh exact execution permit.
4. Permits are bounded, short-lived, single-use, auditable, and fail closed when stale, mismatched, revoked, or consumed.
5. Redirects, newly discovered URLs, JavaScript hints, and API routes return to planning/policy review before any request.
6. Stored evidence is integrity checked before it is consumed or packaged.
7. Crash/recovery never silently replays a network action. A retry requires reconciliation and, where applicable, a fresh permit.
8. Findings preserve proof state. A signal does not become a confirmed vulnerability merely because a tool emitted it.
9. CTF rules are authoritative. If automation or AI is forbidden, ASTP refuses autonomous local solving.
10. CTF local acceptance never exercises the network branch. Network-capable CTF observations use the same exact permit path as other target actions.

## Secret handling

Authenticated observation stores secret references rather than raw credentials in ASTP profiles. Evidence from authenticated flows is treated as sensitive. Operators are responsible for the external secret store and for reviewing retained evidence before sharing it.

## Evidence and replay

Raw response body persistence is opt-in and bounded. Manifests bind artifacts by digest. Recovery can rebuild offline reports from verified stored artifacts, but it may not automatically repeat a consumed target action.

## Release qualification

`release-readiness` is offline. It validates the stored M48.0 Bug Bounty acceptance report and the M48.6 CTF acceptance report, checks package/repository version consistency, verifies the required 1.0 stable documentation surface, and records SHA-256 digests for the qualification reports.

The command does not contact a target and does not rerun historical network activity.
