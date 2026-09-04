# Milestone 3.6 — Evidence Report & Retest Plan v0.1

M3.6 renders correlated findings into Markdown with proof states, evidence signals, standards mappings, remediation text and a retest checklist.

Retest checklist entries do not execute anything. The report explicitly requires every retest action to pass current policy and receive a fresh execution permit.

```powershell
astp render-report .\.astp\findings.yaml .\engagements\program.yaml `
  --output .\reports\program.md
```
