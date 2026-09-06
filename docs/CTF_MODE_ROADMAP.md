# ASTP CTF Mode — implementation roadmap

CTF mode is now implemented through M48.4. The control plane remains rules-first: a challenge must explicitly permit the relevant automation, local artifacts stay inside the challenge directory, and network work is never implied by a declared endpoint.

## Implemented path

```text
ChallengeDefinition
  -> ctf-intake: rules + local artifact SHA-256 inventory
  -> ctf-analyze: artifact classifier + hypothesis graph
  -> ctf-solve-local: bounded built-in adapters
  -> ctf-verify-flags: candidate format verification + solve trace

Optional network branch:
  declared endpoint
  -> exact endpoint validation
  -> normal Engagement/Test policy
  -> fresh signed execution permit
  -> ctf-observe-http GET/HEAD
  -> evidence + manifest + audit
```

## M48.1 — Artifact classifier and hypothesis graph

Classification uses local bytes, extensions, and file magic for text, JSON, JavaScript, HTML, ZIP, PE, ELF, images, PCAP/PCAPNG, and generic binary data. Each artifact maps to bounded eligible adapters. Hypotheses are deterministic and network hypotheses explicitly carry `requires_fresh_permit: true`.

## M48.2 — Isolated local solver adapters

Current adapters are implemented inside ASTP and receive artifact bytes at the adapter boundary: `text-pattern`, `safe-strings`, `json-structure`, and `zip-inventory`. They do not expose arbitrary shell access, spawn external processes, or perform network requests. Local artifact processing is bounded by size/entry/candidate limits. If challenge rules disallow automation, the solver fails closed.

## M48.3 — Web/API permit path

`ctf-observe-http` supports a single GET/HEAD. The requested URL must canonicalize to an exact value present in `authorized_endpoints`. That check is additive: standard ASTP engagement scope, test policy, signed permit verification, lifecycle consumption, rate limiting, evidence registration, and audit behavior still apply. A declared endpoint is therefore **not an execution permit**.

## M48.4 — Flag verification and solve trace

Solver candidates carry artifact path, adapter ID, and artifact SHA-256. `ctf-verify-flags` verifies them against `flag_pattern` and appends trace events. A local pattern match is represented as format verification; ASTP does not claim a competition-side submission succeeded unless a future explicit authorized submission capability records that result.

## Remaining

### M48.5 — Category expansion
Add richer reverse engineering, forensics, crypto/encoding, web/API reasoning, and selected sandboxed pwn families. External tools, when introduced, must be wrapped by explicit capability contracts rather than generic shell access.

### M48.6 — Acceptance suite
Use local synthetic labs and retired/public challenge corpora whose rules allow automation. Measure solve rate, false-positive flag rate, time-to-flag, resource cost, hypothesis count, and trace reproducibility by category and difficulty.

### M49.0 — 1.0 release candidate
Consolidate the CTF and Bug Bounty workflows into the final documented product surface.
