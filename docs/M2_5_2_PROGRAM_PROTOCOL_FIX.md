# M2.5.2 — Authenticated Program Discovery Protocol Fix

M2.5.2 hardens the browser-companion ↔ local ASTP integration discovered during the first
real BugHunt field trial.

## What changed

- Adds authenticated `POST /v1/health` with protocol negotiation (`protocol_version = 2`).
- Keeps the discovery contract explicit:
  - `POST /v1/browser-capture`
  - `POST /v1/discover-programs`
  - `POST /v1/program-detail`
- Returns JSON errors for bad token, malformed payloads, unknown endpoints, and oversized
  requests.
- Adds visible, non-sensitive operational logs to the local intake server.
- Separates browser host-permission grant from discovery so Chrome permission prompts cannot
  silently terminate an in-progress popup action.
- Stores only the short-lived ASTP intake token in `chrome.storage.session`; no BugHunt cookies,
  passwords, authorization headers, localStorage, or sessionStorage are exported.
- Adds browser-side health checking and a protocol mismatch error.
- Persists background progress in session storage so reopening the popup shows the latest state.
- Waits for dynamically rendered program-detail DOM content to settle before capture.
- Adds real HTTP integration tests that exercise discovery and detail sync through a loopback
  server rather than only calling Python functions directly.

## Browser workflow

1. Start `astp browser-intake-server --platform bughunt`.
2. Reload the unpacked ASTP extension.
3. Paste the one-time intake token.
4. Click **Check ASTP connection** and verify server/token/protocol.
5. From the authenticated BugHunt program listing, click **Grant access to current platform**.
   Chrome may close the popup while showing its permission prompt; this is expected.
6. Reopen the ASTP popup. The token is retained only for the browser session.
7. Click **Discover & sync all programs on this platform page**.
8. Watch both the popup state and the local server logs.
9. Run `astp programs` in a second terminal after synchronization.

## Expected server trace

```text
[12:34:00] POST /v1/health
[12:34:00] Browser companion health check passed
[12:34:05] POST /v1/discover-programs
[12:34:05] Listing classified as program_listing; candidates discovered: 7
[12:34:07] POST /v1/program-detail
[12:34:07] Synced Grupo Smart Fit ...
```

The server logs metadata only. Captured page content and authentication material are not printed.

## Integration invariant

Browser discovery is a control-plane activity. It does not issue target execution permits and it
must not export the authenticated platform session into ASTP.
