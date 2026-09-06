# ASTP — M44.5-M46.4 overlay

This overlay adds the strict Full Pentest Readiness Closure gate.

Apply it over the validated M42.5-M44.4 tree. Run the normal validation and offline harness first. Then evaluate the already-persisted physical evidence with `scripts/runtime-qualification/full-pentest-readiness.ps1`.

Version: 0.451.0

The readiness evaluator launches no containers and performs no network I/O.
