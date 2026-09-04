# Milestone 3.4 — Hypothesis Graph v0.1

M3.4 introduces hypotheses as explicit control-plane objects. Current automatic hypotheses are intentionally conservative: an in-scope discovered HTTP asset may warrant another bounded observation.

Every hypothesis says that policy evaluation and a fresh execution permit are required. A hypothesis is not permission and is not a finding.

```powershell
astp build-hypotheses .\.astp\security-graph.yaml `
  --output .\.astp\hypotheses.yaml
```
