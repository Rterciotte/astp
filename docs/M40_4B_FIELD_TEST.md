# M40.4b field test

The offline harness validates the deterministic output generator and exact
qualification-marker allowlist without starting containers or performing
network I/O.

The operator physical test must rebuild security-tools and ZAP, keep the
existing authorized local lab running, execute the bounded-output probe once
for each runtime, and then require `qualification-status.ps1 -Runtime all` to
report `qualified: true`, `manifest_valid: true`, and `missing_probes: []` for
all three runtimes.

No internet or assessment target is required for this qualification test.
