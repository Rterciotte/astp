# ASTP overlay M36.5–M38.4 — physical runtime execution bridge

This overlay moves ASTP from Docker runtime candidates toward reproducible physical qualification while preserving the policy-first invariant.

Milestones:

- M36.5 local immutable image identity capture
- M36.6 build provenance records
- M36.7 low-resource serial runtime envelopes
- M36.8 hardened offline Docker launch compiler
- M36.9 physical unknown-operation rejection probe
- M37.0 fixed internal qualification network
- M37.1 local lab target containment
- M37.2 local lab container blueprint
- M37.3 exact target injection at worker boundary
- M37.4 network disabled until permit-consumed state
- M37.5 bounded Nmap local-lab execution
- M37.6 bounded Playwright local-lab observation
- M37.7 bounded ZAP passive local-lab execution
- M37.8 output truncation at physical worker boundary
- M37.9 shell-free subprocess invariant
- M38.0 physical execution observation model
- M38.1 qualification journal/provenance hashing
- M38.2 no-self-certification qualification bundle
- M38.3 operator-run physical qualification scripts
- M38.4 regression + offline field harness

The build and negative-probe scripts are safe to run independently. They either build images or run worker containers with `--network none`. The local lab script creates an internal Docker network with no published host port.

A free-form network launcher is intentionally absent. Physical network execution must still pass through the ASTP exact-permit consumption boundary; the fixed local lab is preparation for that bridge, not a bypass around it.
