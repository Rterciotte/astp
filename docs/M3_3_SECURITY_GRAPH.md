# Milestone 3.3 — Security Graph v0.1

M3.3 creates a deterministic graph connecting assets to evidence and the actions that produced that evidence. The graph is derived from the Target Registry; it does not probe targets.

```powershell
astp build-security-graph .\.astp\target-registry.yaml `
  --output .\.astp\security-graph.yaml
```

Initial node types are `asset`, `evidence`, and `action`. Initial relationships preserve discovery and observation provenance.
