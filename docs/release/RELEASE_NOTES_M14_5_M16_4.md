# Release notes — M14.5 to M16.4

Version: 0.151.0

This block advances the operational verification layer while preserving the invariant `Planner -> Policy -> Permit -> Worker -> Evidence`.

- M14.5: deterministic authorization evidence comparison.
- M14.6: fresh-permit two-identity differential executor.
- M14.7: foreign-object context aware authorization verifier.
- M14.8: proof-state ceiling that avoids automatic VERIFIED claims.
- M14.9: safe verification dispatcher bridge.
- M15.0: durable verification result repository.
- M15.1: retest outcome model with explicit human resolution.
- M15.2: optional browser runtime probe.
- M15.3: bounded browser observation interface.
- M15.4: redirect reauthorization guard.
- M15.5: allowlisted external adapter job model.
- M15.6: external adapter execution receipt hashing.
- M15.7: adapter evidence normalization without auto-findings.
- M15.8: exact-action operator gate for state-changing work.
- M15.9: autonomous state-changing execution remains disabled.
- M16.0: authenticated evidence sensitivity label correction.
- M16.1: authorization differential coverage closure.
- M16.2: safe verification coverage closure.
- M16.3: readiness model updated with remaining blockers.
- M16.4: regression and field harness.

Full pentest readiness remains false. Browser execution and external scanners are still runtime/worker blockers, and broad vulnerability-specific active verification is not yet complete.
