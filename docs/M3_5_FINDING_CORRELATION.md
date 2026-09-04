# Milestone 3.5 — Proof States & Finding Correlation

M3.5 formalizes proof states:

```text
SUSPECTED -> LIKELY -> VERIFIED -> IMPACT_CONFIRMED
```

Correlation merges signals that refer to the same vulnerability/asset/endpoint/role. It never promotes a finding beyond the strongest proof state supplied by evidence producers.

```powershell
astp correlate-findings .\examples\finding-candidates.yaml `
  --output .\.astp\findings.yaml
```
