# ASTP Next Steps after M28.4

The remaining work is now concentrated in operational field qualification and vulnerability-specific verification depth rather than generic control-plane scaffolding.

1. M28.5 — build and pin the Playwright isolated worker image.
2. M28.6 — field-test browser permit consumption before navigation.
3. M28.7 — register browser DOM/screenshot evidence with provenance.
4. M28.8 — build and pin the security-tools isolated worker image.
5. M28.9 — field-test bounded Nmap runtime.
6. M29.0 — field-test bounded Nuclei safe-template runtime.
7. M29.1 — field-test ZAP passive/baseline runtime.
8. M29.2 — store qualification bundles for both runtime families.
9. M29.3 — expand vulnerability-specific verifier criteria and action compilation.
10. M29.4 — proof-state progression tests for safe active verification.
11. M29.5 — execute the evidence → signal → verification → replan loop with real qualified workers.
12. M29.6 — interruption/recovery and policy-drift tests across the adaptive loop.
13. M29.7 — operator-gated state-changing execution path with exact approval consumption.
14. M29.8 — retest loop through the same policy/permit/evidence chain.
15. M29.9 — complete authorized assessment coordinator field run.
16. M30.0 — full-pentest readiness acceptance suite and documentation closure.

`full_pentest_ready` must not become true simply because these modules exist. The terminal acceptance gate requires real field evidence.
