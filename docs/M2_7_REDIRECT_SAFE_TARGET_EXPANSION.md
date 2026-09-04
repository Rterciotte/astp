# Milestone 2.7 — Redirect-Safe Target Expansion

M2.7 turns a redirect recorded in existing HTTP evidence into a **candidate**, never an implicit request.

Invariant:

```text
observation evidence -> redirect candidate -> deterministic safety checks -> policy evaluation -> new permit -> worker
```

A redirect does not inherit the source action's authorization. HTTPS-to-HTTP downgrade, credential-bearing URLs, redacted URLs and private/loopback/link-local literal destinations are not auto-promotable. Out-of-scope destinations are retained as provenance but not executable.

Command:

```powershell
astp discover-targets .\.astp\observation.json .\engagements\program.yaml `
  --no-links --output .\.astp\discovery.yaml
```

This command performs no network action.
