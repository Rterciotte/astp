# Milestone 2.8 — Evidence-Derived Target Discovery

M2.8 extracts a bounded number of HTTP(S) links from the already-redacted `body_preview` stored in observation evidence. It does not fetch the links.

The discovery source is intentionally limited to evidence already captured by a permit-gated worker. Every candidate records evidence/action provenance, stays `executable: false`, and requires a new permit before any future network action.

```powershell
astp discover-targets .\.astp\observation.json .\engagements\program.yaml `
  --links --max-links 50 --output .\.astp\discovery.yaml
```
