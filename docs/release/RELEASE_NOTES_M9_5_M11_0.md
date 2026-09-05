# M9.5-M11.0 release notes

This block strengthens the evidence, verification, worker, recovery, and finalization layers without adding an implicit network execution path.

- M9.5 derives DNS/TLS provenance records from already captured HTTP transport evidence.
- M9.6 performs static JavaScript signal extraction from local artifacts only.
- M9.7 creates permit-required JavaScript artifact retrieval plans.
- M9.8 binds human review to verification queue item hashes.
- M9.9 brokers reviewed verification items into authorization candidates, not execution.
- M10.0 persists isolated worker job envelopes in SQLite.
- M10.1 adds integrity-bound worker result receipts.
- M10.2 adds deterministic capability round-robin scheduling.
- M10.3 validates checkpoint integrity and policy continuity before resume.
- M10.4 adds durable evidence quarantine tracking.
- M10.5 fuses contextual risk, proof state, and confidence without claiming CVSS.
- M10.6 adds reviewed report finalization.
- M10.7 builds integrity-checkable publication bundles only after approval.
- M10.8 adds a hash-linked assessment session journal.
- M10.9 adds a deterministic readiness matrix for assessment prerequisites.
- M11.0 adds an explicit assessment closure gate.

The execution invariant remains: Planner -> Policy -> fresh Permit -> bounded Worker -> Evidence.
