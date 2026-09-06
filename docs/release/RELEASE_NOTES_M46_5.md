# Release notes — M46.5

Version 0.461.0 adds a unified, fail-closed program pre-flight flow.

Highlights:

- live authenticated refresh using the existing loopback browser intake;
- exact program URL binding;
- structured DOM online/offline status capture without prose inference;
- source freshness enforcement;
- execution-relevant policy fingerprint and drift classification;
- carry-forward of existing reviewed semantic exclusions through the existing catalog sync;
- compilation of the current normalized policy into an engagement snapshot;
- current operational attestation bound to the fresh capture revision;
- strict full-pentest readiness re-evaluation;
- immutable hash-named pre-flight report and artifacts;
- one PowerShell entry point for the whole flow.

The pre-flight does not launch assessment workers and does not contact Smart Fit assets. The only network service started by the command is the loopback authenticated browser-intake server used to receive the operator's already-authenticated browser capture.
