# ASTP M6.9–M7.9 Release Notes

This block closes the first offline fingerprint-to-report assessment pipeline while preserving the execution-permit boundary.

- M6.9 defines evidence-backed technology fingerprint records with confidence and provenance.
- M7.0 fingerprints HTTP evidence from headers and bounded HTML previews.
- M7.1 adds stored-evidence analyzers for security headers, cookies, CORS, and HTTPS posture.
- M7.2 normalizes fingerprint/posture observations into typed signals.
- M7.3 converts only explicitly eligible security-review signals into finding candidates; informational observations are suppressed.
- M7.4 introduces a vulnerability-specific proof-verifier registry. No dedicated verifier auto-executes and generic evidence cannot silently establish VERIFIED impact.
- M7.5 connects stored evidence to fingerprinting, signal generation, registry feedback, and policy-based replanning.
- M7.6 adds a durable SQLite finding/retest repository with explicit transitions.
- M7.7 assembles scope, fingerprint, evidence summary, limitations, findings, and retest guidance into one assessment report.
- M7.8 adds the offline `astp assess` CLI for stored, integrity-checked evidence.
- M7.9 adds assessment recovery/invariant validation and a PowerShell field-test harness.

The invariant remains:

`Evidence -> signals -> candidate -> proof gate -> planner -> policy -> permit -> worker -> Evidence`

The new assessment command does **not** perform network execution. Target-side requests remain confined to the existing permit-gated observation worker.
