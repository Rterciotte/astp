# M9.5-M11.0 field test

Run the repository validation first:

```powershell
.\scripts\validate.ps1
```

Then run:

```powershell
.\scripts\field-tests\m9.5-m11.0.ps1
```

The harness is offline. It exercises the focused tests and, when the stored Smart Fit HTTP evidence exists, derives DNS/TLS provenance from that evidence without opening a new connection.
