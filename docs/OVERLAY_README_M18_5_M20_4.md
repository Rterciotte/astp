# ASTP M18.5-M20.4 Overlay

This incremental overlay builds on the validated M16.5-M18.4 state.

## Theme

Verification depth, evidence-driven replanning, coordinator stage gates, and honest runtime qualification.

## Milestones

- M18.5 verifier-family expansion
- M18.6 stored-evidence verifier normalization
- M18.7 CSP posture verifier
- M18.8 HSTS posture verifier
- M18.9 conservative CORS signal handling
- M19.0 sensitive-response cache verifier
- M19.1 information-exposure header verifier
- M19.2 redirect reauthorization signal
- M19.3 bounded verification-action proposals
- M19.4 proof-ceiling preservation
- M19.5 coordinator one-stage transition guard
- M19.6 observation-to-verification evidence gate
- M19.7 verification-to-retest queue gate
- M19.8 report/review/closure prerequisites
- M19.9 durable coordinator transition history
- M20.0 browser/tool runtime manifests
- M20.1 runtime qualification separate from worker boundaries
- M20.2 assessment-depth status
- M20.3 CLI inspection/replanning surfaces
- M20.4 regression and field harness

## Security invariants

No new command performs network I/O. A verifier signal is not a confirmed vulnerability. A proposed active check still requires policy review, a fresh permit, and the existing worker boundary. Runtime contracts are not counted as operational readiness until they are bundled and field-tested.
