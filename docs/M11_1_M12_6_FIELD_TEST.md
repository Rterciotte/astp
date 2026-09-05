# M11.1-M12.6 field validation

Run after `scripts/validate.ps1` succeeds:

```powershell
.\scripts\field-tests\m11.1-m12.6.ps1
```

The harness is network-free. It runs the focused regression suite, CLI registration
checks, the safe assessment profile, and pentest readiness. Real DNS/TLS execution is
never triggered by the harness; it requires a separately issued permit, capability
grant, and explicit `astp execute-capability ... --execute` invocation.
