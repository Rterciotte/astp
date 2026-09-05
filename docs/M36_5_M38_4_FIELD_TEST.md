# M36.5–M38.4 field harness

The default field harness remains offline:

```powershell
.\scripts\field-tests\m36.5-m38.4.ps1
```

It validates target containment, resource envelopes, permit-before-network command compilation, provenance models, qualification no-self-certification, and worker source restrictions.

Physical Docker steps are separate so a normal regression run does not unexpectedly pull images or consume significant RAM:

```powershell
.\scripts\runtime-qualification\build-images.ps1 -Runtime security-tools
.\scripts\runtime-qualification\offline-negative-probes.ps1 -Runtime security-tools
```

Repeat for Playwright and ZAP only after the lighter security-tools worker is healthy. Execute workers serially on small Docker Desktop VMs.

The local lab may be prepared with:

```powershell
.\scripts\runtime-qualification\start-local-lab.ps1
```

It uses the internal Docker network `astp-qualification-net`, publishes no host port, and uses the fixed service name `astp-qualification-lab`.

This overlay does not claim a runtime is field-qualified merely because the image builds or the offline negative probes pass.
