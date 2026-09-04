# Milestone 3.2 — Security Test DSL v0.1

The first tool-independent Security Test DSL formalizes preconditions, signals, strategy, success conditions, evidence requirements and standards mappings.

`observe_http` DSL tests are constrained to passive/safe-active risk classes. Validation never executes a test.

```powershell
astp validate-test-dsl .\examples\dsl\http-observation.yaml `
  --runtime-output .\.astp\runtime-test.yaml
```
