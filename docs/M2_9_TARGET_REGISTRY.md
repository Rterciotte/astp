# Milestone 2.9 — Target Registry & Provenance

The Target Registry deduplicates canonical targets while preserving every discovery path. Multiple observations can point to one registry entry without losing evidence provenance.

```powershell
astp merge-targets .\.astp\discovery.yaml .\engagements\program.yaml `
  --registry .\.astp\target-registry.yaml
```

The registry is a control-plane artifact. It grants no authorization.
