# Release notes — M42.5-M44.4

Version 0.431.0.

- Added physical adaptive assessment trace model.
- Added fresh-permit REPLAN gate.
- Added hard STOP semantics for policy drift, stale attestation, and permit reuse.
- Added exact-target and new-evidence requirements across adaptive stages.
- Added explicit zero-launch/zero-I/O state-changing gate without exact approval.
- Added authorized local physical runner: qualified Playwright observation -> fresh permit -> qualified ZAP passive verification.
- Added immutable adaptive trace persistence and Evidence Store registration.
- Added offline regression/field harness.

No public-target network execution is performed by tests or harnesses. Full-pentest readiness remains false.
