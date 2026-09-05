# M34.5–M36.4 field harness

The included harness is offline. It verifies manifest identity, hardened Docker command generation, permit-before-network gating, complete probe coverage, and strict readiness semantics. It does not build images, start containers, or perform network I/O.

A later physical qualification run must build each image, record its real `sha256:` digest, run every negative/positive probe in an explicitly authorized lab, ingest receipts, and preserve the resulting qualification record.
