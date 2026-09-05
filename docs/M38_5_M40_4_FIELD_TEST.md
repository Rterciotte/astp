# M38.5-M40.4 field test

Run static/offline validation first:

```powershell
.\scripts\validate.ps1
.\scripts\field-tests\m38.5-m40.4.ps1
```

Then start the isolated local lab and execute each runtime serially:

```powershell
.\scripts\runtime-qualification\start-local-lab.ps1
.\scripts\runtime-qualification\run-authorized-lab-qualification.ps1 -Runtime playwright
.\scripts\runtime-qualification\run-authorized-lab-qualification.ps1 -Runtime zap
.\scripts\runtime-qualification\signing-key-absence-probe.ps1 -Runtime security-tools
.\scripts\runtime-qualification\signing-key-absence-probe.ps1 -Runtime playwright
.\scripts\runtime-qualification\signing-key-absence-probe.ps1 -Runtime zap
.\scripts\runtime-qualification\run-bounded-output-probe.ps1 -Runtime playwright
.\scripts\runtime-qualification\stop-local-lab.ps1
```

All network-capable commands above are restricted to the internal ASTP qualification lab. Each network run obtains and consumes a fresh permit before Docker receives the internal network.
