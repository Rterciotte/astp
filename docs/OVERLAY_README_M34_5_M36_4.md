# ASTP M34.5–M36.4 — Physical Runtime Qualification Bridge

This overlay moves ASTP from runtime-field contracts toward reproducible physical Docker qualification without self-certifying any runtime.

Milestones: M34.5 immutable build manifests; M34.6 pinned worker bases; M34.7 hardened Docker argv; M34.8 network-none default; M34.9 permit-consumed network boundary; M35.0 Playwright image; M35.1 security-tools image; M35.2 ZAP image; M35.3 typed worker entrypoints; M35.4 arbitrary-operation rejection; M35.5 physical probe plan; M35.6 qualification observations; M35.7 provenance hashing; M35.8 authorized-lab binding; M35.9 complete-probe decision; M36.0 field-readiness model; M36.1 runtime-specific qualification gates; M36.2 E2E field-assessment gate; M36.3 no self-certification; M36.4 regression/field harness.

The Dockerfiles are build candidates. Their image digests must be measured after a real build; no placeholder digest is treated as qualified evidence.
