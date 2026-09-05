# ASTP Next Steps

The M14.5-M16.4 block closes the autonomous two-identity differential executor and the safe verification execution bridge. Full pentest/bug-hunt readiness remains false.

## Remaining execution blockers

1. M16.5 — bundled isolated browser worker with permit consumption before navigation.
2. M16.6 — browser evidence store integration and screenshot/DOM provenance.
3. M16.7 — permit-consumed external adapter worker protocol.
4. M16.8 — bounded Nmap runtime adapter.
5. M16.9 — bounded Nuclei runtime adapter with template policy.
6. M17.0 — ZAP passive/baseline runtime adapter.
7. M17.1 — broad vulnerability-specific verifier registry and proof criteria.
8. M17.2 — verifier action compiler from finding candidates.
9. M17.3 — evidence-driven verification scheduler with safe resume.
10. M17.4 — browser/API evidence feedback into the planner.
11. M17.5 — executable retest loop with fresh policy, attestation, and permits.
12. M17.6 — operator-controlled state-changing worker path with exact-action approval consumption.
13. M17.7 — end-to-end assessment coordinator across all ready capabilities.
14. M17.8 — field recovery, interruption, and policy-drift validation.
15. M17.9 — full-pentest readiness acceptance suite.

`full_pentest_ready` must remain false until the acceptance suite demonstrates broad vulnerability verification, bundled browser execution, permit-consumed external adapters, executable retests, and operator-gated high-risk workflows without bypassing policy or permits.

## After M18.4
Prioritize vulnerability-specific proof families, operator-gated state-changing execution, real isolated runtime packaging, and coordinator-driven recovery/replanning. `full_pentest_ready` must remain false until these are field-tested.

## M18.5-M20.4 — Verification depth and coordinator gates

ASTP now derives conservative verifier signals from stored HTTP evidence, can propose bounded follow-up actions without bypassing policy, enforces sequential coordinator stage prerequisites, and distinguishes worker boundaries from real bundled/field-tested runtimes. Full pentest readiness remains false until broad active verification and physical browser/tool runtimes close.

## After M22.5-M24.4

- Build the Playwright and security-tool worker images in the intended Linux/Docker environment and record immutable image digests.
- Replace protocol stubs with permit-consuming worker entrypoints while preserving exact-action bindings.
- Run negative qualification tests proving no target I/O before permit consumption, no shell, no signing keys, and bounded output.
- Field-qualify the browser and tool runtimes against an explicitly authorized lab/program target before marking either runtime operational.
- Connect qualified worker receipts to the coordinator evidence gate and adaptive replan loop.
