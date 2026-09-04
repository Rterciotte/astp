from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit, urlunsplit


def canonical_http_target(target: str) -> str:
    parsed = urlsplit(target)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if not scheme or not host:
        raise ValueError("HTTP target must include a scheme and hostname.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("HTTP target contains an invalid port.") from exc
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    netloc = rendered_host if port is None or default_port else f"{rendered_host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def http_action_id(target: str, method: str, identity: str | None) -> str:
    payload = {
        "identity": identity,
        "method": method.upper(),
        "target": canonical_http_target(target),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def http_target_rate_key(target: str) -> str:
    return hashlib.sha256(canonical_http_target(target).encode("utf-8")).hexdigest()
