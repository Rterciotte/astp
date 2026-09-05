# M8.0–M9.4 field test

Run the automated offline harness:

```powershell
.\scripts\field-tests\m8.0-m9.4.ps1
```

It validates the focused tests and, when `.astp/m79/` artifacts exist, builds confidence fusion, lineage, assessment manifest, and a review package. No target network action is performed.
