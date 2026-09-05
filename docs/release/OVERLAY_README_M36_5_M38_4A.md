# ASTP M36.5-M38.4a overlay

Apply this overlay on top of the already validated M36.5-M38.4 tree.

Purpose: connect the permit broker/lifecycle to the first real physical Docker worker execution against the ASTP-owned isolated local qualification lab.

After copying the overlay, run:

```powershell
.\scripts\validate.ps1
.\scripts\field-tests\m36.5-m38.4.ps1
```

Then, while the local lab is running:

```powershell
.\scripts\runtime-qualification\run-authorized-lab-qualification.ps1 -Runtime security-tools
```

Do not commit until all three commands pass and the generated local evidence has been inspected.
