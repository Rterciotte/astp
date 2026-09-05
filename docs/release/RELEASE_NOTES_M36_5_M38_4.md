# Release notes — M36.5–M38.4

Version: 0.371.0

ASTP now has a physical runtime execution bridge tailored for serial use on constrained Docker Desktop environments. It records immutable local image IDs, applies explicit CPU/memory/PID envelopes, provides hardened network-none probes, and introduces an isolated local qualification lab with strict target containment.

Security-tool, Playwright, and ZAP workers now require an exact `ASTP_ALLOWED_TARGET` and use bounded, shell-free execution paths. Physical qualification records remain incomplete until every required probe has evidence and the session is explicitly bound to the authorized lab.

No public or bug-bounty target is contacted by the default regression/field harness.
