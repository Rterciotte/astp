# ASTP M24.5-M26.4 — Executable worker bridge

This block moves the isolated runtime work from packaging-only blueprints toward bounded executable worker primitives while preserving the policy/permit boundary.

## Milestones

- **M24.5** bounded Nmap command compiler
- **M24.6** bounded Nmap light service-detection mode
- **M24.7** bounded Nuclei safe-template command compiler
- **M24.8** ZAP passive-baseline command compiler
- **M24.9** browser/subprocess execution separation
- **M25.0** shell-free subprocess runner
- **M25.1** bounded stdout/stderr capture
- **M25.2** permit-before-tool-I/O execution bridge
- **M25.3** permit-before-browser-I/O execution bridge
- **M25.4** browser redirect reauthorization enforcement
- **M25.5** worker receipt evidence normalization
- **M25.6** runtime qualification record model
- **M25.7** runtime execution qualification gate
- **M25.8** independent runtime readiness progression
- **M25.9** active-verifier action compiler
- **M26.0** fresh-permit requirement on compiled verification actions
- **M26.1** passive-signal execution suppression
- **M26.2** arbitrary external-tool mode rejection
- **M26.3** absolute HTTP target validation for web tools
- **M26.4** regression and field harness

## Invariant

```text
Planner -> Policy -> fresh exact-action permit -> consume permit
        -> bounded browser/tool worker -> receipt -> evidence gate
```

Command compilation and runtime qualification inspection are offline. Browser/tool runtimes remain **not field-qualified** until their real OCI images are built, digest-pinned, negatively tested, and exercised against an explicitly authorized target.
