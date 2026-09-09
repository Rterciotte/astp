# ASTP counting proxy

External detector workers do not treat their own request counters as authoritative. A detector-run receives a signed HMAC-SHA256 authorization binding campaign, program/revision, detector, operation, origin/path, methods, request/concurrency/rate ceilings, policy and semantic-review digests, action, run ID and expiry.

For physical execution the worker and target occupy separate Docker `--internal` networks. The proxy is the only container attached to both. Workers are configured with a mandatory HTTP proxy and cannot resolve the target container directly.

Before forwarding every request the proxy revalidates the signature and expiry, exact scheme/host/port, path prefix, method, budget, concurrency and circuit state. It assigns a deterministic request ID and persists attempted, forwarded, response, blocked-before-I/O, failed-after-I/O and byte counters in a SQLite WAL ledger. `CONNECT` is disabled; HTTPS field support remains unavailable until a scoped interception design is qualified. Authorization and cookie-like headers are neither logged nor forwarded.

Scanner-reported totals are diagnostic only. Detector execution must reconcile its worker receipt with the proxy ledger; campaign accounting uses the ledger. A scanner may report success after receiving budget errors, but the proxy never forwards request `max_requests + 1`.

Current physical local-lab evidence:

- ffuf: 5 attempted, 4 forwarded, 4 responses, 1 blocked before I/O;
- Nuclei: 1 attempted/forwarded/response;
- Playwright DOM navigation: 1 attempted/forwarded/response;
- Dalfox reflected: 8 attempted, 6 forwarded, 2 blocked before I/O;
- sqlmap: 44 attempted, 40 forwarded, 4 blocked before I/O. The tool reported 39, demonstrating why proxy accounting is authoritative.

ZAP field remains unqualified: the daemon did not become API-ready within the bounded 45-second startup window in the current Docker Desktop environment.
