# ASTP completion plan

Current repository line: M48.6 CTF acceptance foundation complete.

Bug Bounty v1 has passed the real authorized M48.0 field acceptance gate. CTF mode now has rules intake, bounded category-aware local solving, permit-gated HTTP observation, flag verification, solve traces, and a local acceptance harness.

## Completed

- M47.2–M47.5: stored-evidence assessment, findings, reporting, final packaging.
- M47.6–M47.8: portfolio, authenticated observation, verifier integration.
- M47.9: fail-closed recovery/resume/crash acceptance.
- M48.0: Bug Bounty v1 real field acceptance — PASS.
- M48.1–M48.4: CTF classifier, hypotheses, isolated solvers, permit path, flag verification/trace.
- M48.5: bounded category expansion for crypto/encoding, web/API hints, forensics metadata, reverse/pwn static metadata.
- M48.6: local acceptance suite with category/difficulty metrics and trace reproducibility.

## Remaining

### M49.0 — ASTP 1.0 release candidate

Consolidate CLI UX, examples, installation/configuration, security model, acceptance results, version metadata, release checklist, and stale-overlay cleanup. Run the complete regression/acceptance matrix and produce the 1.0 RC release notes.

## Shortest path to 1.0

```text
M48.6 CTF acceptance complete
        ↓
M49.0 ASTP 1.0 RC
```
