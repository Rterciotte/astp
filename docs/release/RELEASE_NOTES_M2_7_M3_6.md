# ASTP cumulative implementation — M2.7 through M3.6

Version: **0.23.0**

This archive is cumulative on top of M2.6 and includes the corrected CLI wording from the M2.6
field-validation pass.

Implemented milestones:

1. M2.7 — Redirect-Safe Target Expansion
2. M2.8 — Evidence-Derived Target Discovery
3. M2.9 — Target Registry & Provenance
4. M3.0 — Deterministic Observation Planner
5. M3.1 — Multi-Program Work Queue
6. M3.2 — Security Test DSL v0.1
7. M3.3 — Security Graph v0.1
8. M3.4 — Hypothesis Graph v0.1
9. M3.5 — Proof States & Finding Correlation
10. M3.6 — Evidence Report & Retest Plan v0.1

Validation in the generation environment:

```text
python -m compileall: PASS
pytest: 122 passed
CLI help/import smoke tests: PASS
source/test lines over 100 chars: 0
```

`ruff` and `black` are not installed in the generation environment, so run the project's normal
Windows validation before committing:

```powershell
ruff check . --fix
black .
ruff check .
pytest
```

No new command in M2.7-M3.6 performs a network action. The only network-capable command remains the
existing permit-gated `observe-http` worker. Discovery, planning, graph, hypotheses, queue, DSL,
correlation and reporting are control-plane operations.
