# ASTP M11.1-M12.6 overlay

Apply over a validated M9.5-M11.0 checkout.

Then run:

```powershell
.\scripts\validate.ps1
.\scripts\field-tests\m11.1-m12.6.ps1
```

The field harness is network-free. Real DNS/TLS execution requires a separately
issued policy permit, an exact signed capability grant, and explicit `--execute`.
