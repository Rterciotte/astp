# M40.5-M42.4 Field Harness

Run:

```powershell
.\scripts\field-tests\m40.5-m42.4.ps1
```

Expected properties:
- qualified runtime admission is explicit;
- observation evidence produces bounded adaptive signals;
- signals produce deterministic hypotheses and verifier candidates;
- safe-active verification requires policy allowance, fresh attestation, and a fresh permit;
- verification evidence can progress a proof state conservatively to `likely`;
- new evidence drives `REPLAN`;
- state-changing work without exact approval is blocked before worker launch/network I/O;
- report readiness still requires operator review before closure;
- no network/container execution is performed by this harness.
