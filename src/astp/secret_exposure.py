from __future__ import annotations

import hashlib
import math
import re
from enum import StrEnum

from pydantic import BaseModel, Field


class SecretKind(StrEnum):
    AWS_ACCESS_KEY = "aws_access_key"
    JWT = "jwt"
    BEARER_TOKEN = "bearer_token"
    PRIVATE_KEY = "private_key"
    DATABASE_URL = "database_url"
    GENERIC_TOKEN = "generic_token"
    HIGH_ENTROPY = "high_entropy"
    SOURCE_MAP = "source_map"
    DEBUG_CONFIG = "debug_config"


class SecretExposureSignal(BaseModel):
    kind: SecretKind
    redacted_value: str
    value_sha256: str
    confidence: float = Field(ge=0, le=1)
    context: str
    sensitive: bool = True
    valid_secret_proven: bool = False


_PATTERNS = (
    (SecretKind.AWS_ACCESS_KEY, re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), 0.95),
    (
        SecretKind.JWT,
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        0.82,
    ),
    (SecretKind.BEARER_TOKEN, re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{16,})"), 0.84),
    (
        SecretKind.PRIVATE_KEY,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        0.99,
    ),
    (
        SecretKind.DATABASE_URL,
        re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s\"']+"),
        0.93,
    ),
    (
        SecretKind.GENERIC_TOKEN,
        re.compile(
            r"(?i)(?:api[_-]?key|client[_-]?secret|webhook[_-]?secret)\s*[:=]\s*[\"']?([A-Za-z0-9._~+/-]{16,})"
        ),
        0.72,
    ),
)


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}…{value[-4:]}"


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum(
        (value.count(char) / len(value)) * math.log2(value.count(char) / len(value))
        for char in set(value)
    )


def secret_signal_identity(
    kind: SecretKind, value_sha256: str, *, context_class: str
) -> tuple[SecretKind, str, str]:
    """Return a stable privacy-preserving identity for one logical secret signal."""
    return kind, value_sha256, context_class.strip().lower()


def analyze_exposed_content(
    data: bytes, *, content_type: str = "text/plain"
) -> tuple[SecretExposureSignal, ...]:
    text = data.decode("utf-8", errors="replace")
    signals: list[SecretExposureSignal] = []
    context_class = content_type.strip().lower()
    seen: set[tuple[SecretKind, str, str]] = set()
    for kind, pattern, confidence in _PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group(0)
            digest = hashlib.sha256(value.encode()).hexdigest()
            key = secret_signal_identity(kind, digest, context_class=context_class)
            if key in seen or value.lower() in {"changeme", "example", "your_api_key_here"}:
                continue
            seen.add(key)
            signals.append(
                SecretExposureSignal(
                    kind=kind,
                    redacted_value=_redact(value),
                    value_sha256=digest,
                    confidence=confidence,
                    context=f"pattern in {content_type}",
                )
            )
    for token in re.findall(r"\b[A-Za-z0-9+/=_-]{32,128}\b", text):
        digest = hashlib.sha256(token.encode()).hexdigest()
        key = secret_signal_identity(
            SecretKind.HIGH_ENTROPY,
            digest,
            context_class=context_class,
        )
        if _entropy(token) >= 4.2 and not token.isdigit() and key not in seen:
            seen.add(key)
            signals.append(
                SecretExposureSignal(
                    kind=SecretKind.HIGH_ENTROPY,
                    redacted_value=_redact(token),
                    value_sha256=digest,
                    confidence=0.45,
                    context=f"high entropy in {content_type}",
                )
            )
    if re.search(r"(?m)^\s*//# sourceMappingURL=|\"sourceRoot\"\s*:", text):
        marker = "source-map"
        signals.append(
            SecretExposureSignal(
                kind=SecretKind.SOURCE_MAP,
                redacted_value=marker,
                value_sha256=hashlib.sha256(marker.encode()).hexdigest(),
                confidence=0.8,
                context="source map reference",
                sensitive=False,
            )
        )
    return tuple(signals)
