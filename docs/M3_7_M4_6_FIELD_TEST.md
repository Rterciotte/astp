# M3.7–M4.6 field test

This block is designed to be field-tested against artifacts already collected by ASTP. The only operation that can create a new execution capability is `broker-permit`; it issues a signed exact-action permit but does not perform network I/O.

Suggested sequence after a fresh program-status attestation:

```powershell
astp show-adapters
astp check-adapter .\examples\dsl\http-observation.yaml

astp init-planner-state `
  .\.astp\smartfit-work-queue.yaml `
  --state-db .\.astp\planner.db

astp planner-item-status queue-0001 `
  --state-db .\.astp\planner.db

astp interpret-observation `
  .\.astp\smartfit-first-observation.json `
  --output .\.astp\smartfit-interpretation.yaml

astp map-surface `
  .\.astp\smartfit-target-registry.yaml `
  --output .\.astp\smartfit-surface-map.yaml

astp prioritize-targets `
  .\.astp\smartfit-target-registry.yaml `
  --output .\.astp\smartfit-priorities.yaml

astp prepare-autonomy-session `
  .\.astp\smartfit-work-queue.yaml `
  --max-actions 3 `
  --max-requests 3 `
  --max-errors 1 `
  --max-seconds 300 `
  --max-depth 2 `
  --output .\.astp\smartfit-session-plan.yaml

astp analyze-web-posture `
  .\.astp\smartfit-first-observation.json `
  --output .\.astp\smartfit-web-posture.yaml
```

To field-test the permit broker, first verify the program remains online and create a fresh attestation. Then:

```powershell
astp broker-permit `
  .\.astp\smartfit-work-queue.yaml `
  .\engagements\smartfit.yaml `
  .\examples\test-observation.yaml `
  --queue-id queue-0001 `
  --program-status-attestation .\.astp\smartfit-online.yaml `
  --semantic-clear semex-8a8bf1181d0a `
  --semantic-clear semex-99c27802d859 `
  --semantic-clear semex-999be0c07598 `
  --rps 1 `
  --ttl-seconds 120 `
  --output .\.astp\smartfit-queue-0001.permit.yaml
```

Expected broker property: one permit is issued for exactly the queued target/method, while `Network execution: NOT PERFORMED` remains true. Do not execute it merely to test the broker; permit issuance and verification are sufficient to validate M3.7.
