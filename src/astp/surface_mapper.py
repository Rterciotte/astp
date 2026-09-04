from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, Field

from astp.target_registry import TargetRegistry


class SurfaceEndpoint(BaseModel):
    id: str
    origin: str
    path: str
    query_keys: list[str] = Field(default_factory=list)
    target: str
    source_candidate_ids: list[str] = Field(default_factory=list)


class SurfaceMap(BaseModel):
    schema_version: str = "1"
    engagement_id: str
    created_at: datetime
    endpoints: list[SurfaceEndpoint] = Field(default_factory=list)
    truncated: bool = False


def build_surface_map(
    registry: TargetRegistry,
    *,
    max_endpoints: int = 250,
    now: datetime | None = None,
) -> SurfaceMap:
    if max_endpoints < 1 or max_endpoints > 5000:
        raise ValueError("max_endpoints must be between 1 and 5000")
    endpoints: list[SurfaceEndpoint] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    truncated = False
    for entry in registry.entries:
        parsed = urlsplit(entry.canonical_target)
        port = parsed.port
        default_port = 443 if parsed.scheme == "https" else 80
        authority = parsed.hostname or ""
        if port and port != default_port:
            authority = f"{authority}:{port}"
        origin = f"{parsed.scheme}://{authority}"
        path = parsed.path or "/"
        query_keys = tuple(
            sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        )
        key = (origin, path, query_keys)
        if key in seen:
            continue
        if len(endpoints) >= max_endpoints:
            truncated = True
            break
        seen.add(key)
        digest = hashlib.sha256(repr(key).encode("utf-8")).hexdigest()[:16]
        endpoints.append(
            SurfaceEndpoint(
                id=f"surface-{digest}",
                origin=origin,
                path=path,
                query_keys=list(query_keys),
                target=entry.canonical_target,
                source_candidate_ids=list(entry.candidate_ids),
            )
        )
    return SurfaceMap(
        engagement_id=registry.engagement_id,
        created_at=now or datetime.now(UTC),
        endpoints=endpoints,
        truncated=truncated,
    )
