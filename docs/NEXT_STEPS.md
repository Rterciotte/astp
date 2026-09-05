# Next steps

After M28.5-M30.4, the remaining acceptance work is operational rather than architectural:

1. Build the Playwright worker image and record an immutable digest.
2. Build the security-tools worker image with pinned Nmap/Nuclei/ZAP versions and record an immutable digest.
3. Run negative qualification tests proving no network before permit consumption, no arbitrary shell, no signing-key visibility, and bounded output.
4. Field-qualify browser and external-tool workers in an authorized lab/program context.
5. Expand vulnerability-specific active verifiers and prove their ceilings with evidence-backed fixtures and authorized field tests.
6. Connect accepted worker evidence to the adaptive coordinator in a real assessment run.
7. Exercise interruption, resume, policy drift, stale attestation, and error-budget recovery.
8. Run one authorized end-to-end assessment from intake through reviewed report/closure.
9. Only then allow the strict acceptance gate to return full_pentest_ready=true.
