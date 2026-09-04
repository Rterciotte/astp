# ASTP Browser Companion

The Browser Companion is a small Chromium Manifest V3 extension used only for program
intake. It reads the currently active page after an explicit click and sends a constrained
snapshot to ASTP over loopback.

## Security properties

- `activeTab` instead of persistent access to all pages.
- No `cookies` permission.
- No collection of `localStorage` or `sessionStorage`.
- No password-field extraction.
- Loopback destination only: `http://127.0.0.1:8765/`.
- A one-time token printed by `astp browser-intake-server` is required on POST requests.
- Maximum accepted capture body is 5 MB.
- The extension performs no security testing and has no execution permit capability.

## Local development installation

In Chromium/Chrome/Edge, open the extensions management page, enable developer mode and
load `browser-companion/` as an unpacked extension.

The port is fixed at 8765 in M2.5. A configurable/native-messaging transport can replace
this during later browser-worker work.
