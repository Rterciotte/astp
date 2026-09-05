# Physical runtime qualification scripts

Run these scripts serially. `build-images.ps1` may access container registries to pull build dependencies, but it does not contact an assessment target. `offline-negative-probes.ps1` always launches worker containers with `--network none`.

`start-local-lab.ps1` creates an **internal Docker network** and does not publish a host port. This lab exists for the later permit-gated local-network qualification path. Do not replace its fixed service name with a public target.

The M36.5–M38.4 overlay deliberately does **not** provide a free-form network execution script. A network-capable worker launch still needs to come through an exact ASTP permit-consuming bridge. This avoids turning a qualification helper into a policy bypass.
