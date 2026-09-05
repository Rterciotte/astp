# M5.1 — Operational Freshness Guard

Programs that require an ONLINE state must have a fresh attestation matching the program source revision before every controlled action. Stale, missing, offline, unknown, or mismatched attestations stop the loop before a request.
