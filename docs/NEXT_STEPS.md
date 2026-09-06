# ASTP completion plan

Current repository line: M48.4 CTF bounded solver foundation.

Bug Bounty v1 has passed the real authorized end-to-end M48.0 acceptance gate. The remaining product path is CTF category expansion/acceptance followed by the 1.0 release candidate.

## Completed

### M47.2–M47.5 — COMPLETE
Unified stored-evidence assessment, evidence consumers, conservative finding synthesis, and verified final packaging.

### M47.6–M47.8 — COMPLETE
Portfolio isolation/fair planning, permit-gated authenticated observation, and active-verifier planning integration.

### M47.9 — COMPLETE
Recovery/resume/crash acceptance passed with fail-closed replay behavior.

### M48.0 — COMPLETE / FIELD ACCEPTED
The Smart Fit authorized field assessment passed every Bug Bounty v1 acceptance check: reviewed-program provenance, engagement/registry binding, 21 target records, stored evidence, evidence-manifest integrity, audit-chain integrity, final package integrity, 1/1 network-to-permit accounting, and one recorded authorized field action.

### M48.1 — COMPLETE
`ctf-analyze` classifies declared local artifacts and builds deterministic CTF hypotheses. Network hypotheses are marked as requiring a fresh permit; analysis itself is offline.

### M48.2 — COMPLETE
`ctf-solve-local` runs bounded built-in adapters only. No unrestricted shell, no external process spawning, and no network. Current families: text/pattern, safe printable strings, JSON structure, and ZIP inventory. Automation-prohibited challenges fail closed.

### M48.3 — COMPLETE
`ctf-observe-http` integrates CTF web/API observation with the normal ASTP permit lifecycle. Only GET/HEAD is exposed and the target must exactly match a declared challenge endpoint in addition to satisfying engagement/test/permit checks.

### M48.4 — COMPLETE
`ctf-verify-flags` validates candidates against the challenge's declared flag pattern and emits a reproducible solve trace with artifact/adapter provenance. Format verification is not silently equated with external server submission.

## Remaining

### M48.5 — CTF category expansion
Expand reverse, forensics, crypto, web/API, and selected sandboxed pwn capabilities incrementally. Each adapter family must remain capability-scoped, bounded, observable, and independently qualified.

### M48.6 — CTF acceptance suite
Evaluate local synthetic and retired/public challenges where automation is explicitly permitted. Track solve rate, false flags, time, resource cost, hypothesis efficiency, and reproducibility by category/difficulty.

### M49.0 — ASTP 1.0 release candidate
Consolidate CLI UX, examples, installation/configuration, migrations, security model, acceptance results, and release documentation. Remove stale overlay-era material from the primary user path while preserving historical release records.

## Shortest path to 1.0

```text
M48.5 category expansion
        ↓
M48.6 CTF acceptance suite
        ↓
M49.0 ASTP 1.0 RC
```
