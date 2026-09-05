# M40.4a field-validation procedure

M40.4a corrects evidence integrity and must be validated with a fresh local qualification cycle. Do not reuse the pre-patch evidence manifest as the new qualification source of truth.

## Offline validation

```powershell
.\scripts\validate.ps1
.\scripts\field-tests\m40.4a.ps1
```

## Fresh evidence cycle

Archive the previous local state without deleting it:

```powershell
.\scripts\runtime-qualification\archive-qualification-cycle.ps1
```

Rebuild the physical workers so each current worker implementation has a new/current provenance record, then produce negative probe evidence:

```powershell
.\scripts\runtime-qualification\build-images.ps1 -Runtime all
.\scripts\runtime-qualification\offline-negative-probes.ps1 -Runtime all
.\scripts\runtime-qualification\signing-key-absence-probe.ps1 -Runtime all
```

Start the isolated local lab and execute each runtime with a fresh permit:

```powershell
.\scripts\runtime-qualification\start-local-lab.ps1
.\scripts\runtime-qualification\run-authorized-lab-qualification.ps1 -Runtime security-tools
.\scripts\runtime-qualification\run-authorized-lab-qualification.ps1 -Runtime playwright
.\scripts\runtime-qualification\run-authorized-lab-qualification.ps1 -Runtime zap
```

Produce bounded-output evidence for every runtime:

```powershell
.\scripts\runtime-qualification\run-bounded-output-probe.ps1 -Runtime security-tools
.\scripts\runtime-qualification\run-bounded-output-probe.ps1 -Runtime playwright
.\scripts\runtime-qualification\run-bounded-output-probe.ps1 -Runtime zap
```

Then evaluate the complete durable evidence set:

```powershell
.\scripts\runtime-qualification\qualification-status.ps1 -Runtime all
```

A runtime may report `qualified=true` only when every required physical probe is present for its current image digest, an authorized-lab permit-gated execution is present, and the entire evidence manifest plus every registered artifact verifies successfully.
