# ASTP M42.5-M44.4 — Physical Adaptive Assessment Loop

This overlay connects the already-qualified physical runtimes to an adaptive local-lab assessment trace without weakening the permit boundary.

The explicit physical operator script performs exactly two serial local-lab actions: Playwright observation and ZAP passive verification. Each action is brokered independently and therefore consumes a distinct fresh permit before I/O. The resulting evidence IDs are bound into an immutable adaptive trace and registered in the existing evidence manifest.

The offline field harness never launches containers or performs network I/O.

Important: this milestone does **not** claim ASTP v1/full-pentest readiness and does not authorize public bug-bounty targets.
