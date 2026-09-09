from __future__ import annotations

import re
from urllib.parse import parse_qsl, urljoin, urlsplit

from pydantic import BaseModel, Field


class DiscoveryHint(BaseModel):
    target: str
    kind: str
    parameters: tuple[str, ...] = ()
    requires_policy_replanning: bool = True
    executable: bool = False


class BoundedDiscoveryResult(BaseModel):
    hints: list[DiscoveryHint] = Field(default_factory=list)
    truncated: bool = False


_PATHS = re.compile(
    r"(?i)(?:href|src|action)=[\"']([^\"']+)|(?:https?://[^\s\"'<>]+)|(?:/[A-Za-z0-9_.~/-]+(?:\?[A-Za-z0-9_=&%.-]+)?)"
)


def discover_bounded(
    base_url: str, body: str, *, max_candidates: int = 50
) -> BoundedDiscoveryResult:
    known = {
        "/robots.txt": "robots",
        "/sitemap.xml": "sitemap",
        "/openapi.json": "openapi",
        "/swagger.json": "swagger",
        "/graphql": "graphql",
    }
    rows: dict[str, DiscoveryHint] = {}
    for path, kind in known.items():
        target = urljoin(base_url, path)
        rows[target] = DiscoveryHint(target=target, kind=kind)
    for match in _PATHS.finditer(body):
        value = match.group(1) or match.group(0)
        target = urljoin(base_url, value)
        parsed = urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        kind = "source_map" if parsed.path.endswith(".map") else "body_route"
        rows[target] = DiscoveryHint(
            target=target,
            kind=kind,
            parameters=tuple(sorted({name for name, _ in parse_qsl(parsed.query)})),
        )
    values = sorted(rows.values(), key=lambda item: item.target)
    return BoundedDiscoveryResult(
        hints=values[:max_candidates], truncated=len(values) > max_candidates
    )


def deterministic_wordlist(fingerprints: set[str]) -> tuple[str, ...]:
    base = {"robots.txt", "sitemap.xml", "openapi.json", "swagger.json", ".well-known/security.txt"}
    lower = {item.lower() for item in fingerprints}
    if "wordpress" in lower:
        base.update({"wp-json", "wp-login.php"})
    if "graphql" in lower:
        base.add("graphql")
    return tuple(sorted(base))
