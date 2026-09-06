# ASTP CTF Mode — implementation roadmap

CTF mode is implemented through M48.6. The control plane remains rules-first and fail-closed.

## Implemented path

```text
ChallengeDefinition
  -> ctf-intake: rules + local artifact SHA-256 inventory
  -> ctf-analyze: classifier + hypothesis graph
  -> ctf-solve-local: bounded category-aware adapters
  -> ctf-verify-flags: format verification + solve trace
  -> ctf-acceptance: local qualification + reproducibility metrics

Optional network branch:
  declared endpoint -> exact endpoint validation -> Engagement/Test -> fresh permit
  -> ctf-observe-http GET/HEAD -> evidence + manifest + audit
```

## M48.1–M48.4 — COMPLETE

Artifact classification, hypotheses, isolated local solving, exact permit-gated HTTP observation, candidate verification, and solve traces are implemented. Local artifact provenance is revalidated before solver execution.

## M48.5 — Category expansion — COMPLETE

The built-in capability set now covers safe printable strings and JSON/ZIP structure plus bounded encoding layers for crypto-style artifacts, web/API route hints, PNG/GIF/JPEG metadata, PCAP/PCAPNG inventory, and PE/ELF metadata. Reverse/pwn support remains static metadata/strings rather than arbitrary binary execution. External tools are still outside this milestone and must eventually use explicit sandbox/capability contracts.

## M48.6 — Acceptance suite — COMPLETE

`ctf-acceptance` runs declared local challenge cases without network access and records solve rate, false-positive flags, elapsed time, hypothesis efficiency, and trace reproducibility overall and by category/difficulty. Cases are rerun to prove deterministic trace reproduction. Suite paths cannot escape the suite directory and automation-prohibited challenges fail closed.

Synthetic coverage exercises every declared CTF category. Retired/public corpora may be added later only where their rules/license allow automated use; the acceptance mechanism does not silently fetch or execute them.

## M49.0 — COMPLETE

The 1.0 RC consolidates Bug Bounty and CTF workflows into the final documented product surface, qualification evidence, examples, installation/configuration, security model, and release checklist. `release-readiness` consumes the stored M48.0 and M48.6 acceptance outputs and produces the final offline RC gate.
