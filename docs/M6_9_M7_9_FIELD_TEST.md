# M6.9–M7.9 field test

The field test is intentionally offline. It consumes evidence already collected by the permit-gated worker and never contacts the target.

Run the repository validation first:

```powershell
.\scripts\validate.ps1
```

Then run:

```powershell
.\scripts\field-tests\m6.9-m7.9.ps1
```

The script validates CLI registration and, when the Smart Fit artifacts from previous field tests are present, performs fingerprint, protocol analysis, assessment report generation, and recovery validation using those local files only.

No command in this field test executes a network request. A future execution-oriented assessment loop must continue routing every target-side action through authorization, a fresh signed permit, and an isolated compatible worker.
