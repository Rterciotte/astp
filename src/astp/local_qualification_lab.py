from __future__ import annotations

from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field


class LocalQualificationLab(BaseModel):
    model_config = ConfigDict(frozen=True)

    engagement_id: str = "astp-local-qualification"
    docker_network: str = "astp-qualification-net"
    service_name: str = "astp-qualification-lab"
    port: int = 8080
    allowed_paths: tuple[str, ...] = Field(default=("/", "/health", "/large"))

    def base_url(self) -> str:
        return f"http://{self.service_name}:{self.port}"

    def authorize_url(self, url: str) -> str:
        parsed = urlsplit(url)
        if parsed.scheme != "http":
            raise ValueError(
                "qualification lab only permits plain HTTP on the isolated Docker network"
            )
        if parsed.hostname != self.service_name or parsed.port != self.port:
            raise ValueError("target is outside the fixed qualification lab service")
        if parsed.path not in self.allowed_paths:
            raise ValueError("path is outside the qualification lab allowlist")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("qualification lab URL cannot contain credentials, query, or fragment")
        return url
