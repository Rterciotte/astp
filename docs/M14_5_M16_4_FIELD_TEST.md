# M14.5-M16.4 field test

Run after `scripts/validate.ps1`:

```powershell
.\scripts\field-tests\m14.5-m16.4.ps1
```

The harness is offline. It runs focused tests, prints the browser runtime probe, external adapter binary availability, current assessment coverage, and pentest readiness. It does not invoke Playwright, Nmap, Nuclei, ZAP, DNS, TLS, or HTTP target traffic.
