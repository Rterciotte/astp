# ASTP completion plan

Current repository line: M49.0 ASTP 1.0 release candidate.

Bug Bounty v1 has passed real authorized end-to-end field acceptance. CTF mode has bounded category-aware local solving, exact permit-gated HTTP observation, flag verification, solve traces, and local acceptance/reproducibility coverage. M49.0 consolidates both lines into `1.0.0rc1`.

## Completed

- M47.2–M47.5: stored-evidence assessment, findings, reporting, final packaging.
- M47.6–M47.8: portfolio, authenticated observation, verifier integration.
- M47.9: fail-closed recovery/resume/crash acceptance.
- M48.0: Bug Bounty v1 real field acceptance — PASS.
- M48.1–M48.4: CTF classifier, hypotheses, isolated solvers, permit path, flag verification/trace.
- M48.5: bounded CTF category expansion.
- M48.6: local CTF acceptance suite and trace reproducibility.
- M49.0: ASTP 1.0 RC version metadata, release readiness gate, security model, release checklist, and RC example qualification suite.

## After the RC

M49.0 is the final implementation milestone in this roadmap. Work after this point is release qualification and maintenance rather than another planned feature block:

1. run the full local regression suite;
2. run the deterministic CTF RC suite;
3. use the already generated real M48.0 Bug Bounty acceptance artifact;
4. run `release-readiness` and retain the PASS YAML;
5. tag/publish `1.0.0rc1` only after the operator reviews staged files and qualification evidence;
6. promote to stable `1.0.0` only after RC soak/feedback and any resulting fixes.
