from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from astp.action import http_action_id, http_target_rate_key
from astp.evidence_store import SensitivityLabel, register_evidence
from astp.lifecycle import append_audit_event, consume_execution_permit
from astp.models import Engagement, TestDefinition, target_in_scope
from astp.permits import PermitVerificationRequest, SignedExecutionPermit
from astp.rate_limit import acquire_rate_slot
from astp.transport import (
    ObservationTransport,
    ObservationTransportError,
    PinnedObservationTransport,
    ResolvedEndpoint,
)

DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_BODY_BYTES = 262_144
MAX_BODY_BYTES = 1_048_576
MAX_PREVIEW_CHARS = 4096

_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
}
_SENSITIVE_QUERY_NAMES = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "key",
    "password",
    "passwd",
    "secret",
    "session",
    "sig",
    "signature",
    "token",
}
_INLINE_SECRET_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+\-/]+=*"),
    re.compile(
        r'(?i)(["\']?(?:access_token|api_key|apikey|password|secret|token)["\']?\s*[:=]\s*["\']?)'
        r"[^\s,;\"\']+"
    ),
)


class ObservationError(RuntimeError):
    """Raised when a bounded observation cannot be completed safely."""


class RedirectObservation(BaseModel):
    target: str
    in_scope: bool
    same_origin: bool
    requires_new_permit: bool = True
    followed: bool = False


class HttpObservationEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "2"
    evidence_id: str
    action_id: str
    sensitivity: SensitivityLabel = SensitivityLabel.INTERNAL
    permit_id: str
    engagement_id: str
    test_id: str
    observed_at: datetime
    method: str
    target: str
    status_code: int
    reason: str | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    content_type: str | None = None
    body_bytes_captured: int = 0
    body_truncated: bool = False
    body_sha256: str
    body_preview: str | None = None
    redirect: RedirectObservation | None = None
    resolved_endpoint: ResolvedEndpoint | None = None
    transport_failure: str | None = None
    evidence_hash: str

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        return value


class HttpObservationFailureEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    evidence_id: str
    action_id: str
    sensitivity: SensitivityLabel = SensitivityLabel.INTERNAL
    permit_id: str
    engagement_id: str
    test_id: str
    observed_at: datetime
    method: str
    target: str
    failure_kind: str
    evidence_hash: str


class ObservationResult(BaseModel):
    evidence: HttpObservationEvidence
    evidence_path: Path
    manifest_path: Path


def _canonical_json(data: object) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _redact_inline_secrets(value: str) -> str:
    redacted = value
    for pattern in _INLINE_SECRET_PATTERNS:
        redacted = pattern.sub(r"\1[REDACTED]", redacted)
    return redacted


def redact_url(value: str, extra_query_names: set[str] | None = None) -> str:
    parsed = urlsplit(value)
    sensitive_names = _SENSITIVE_QUERY_NAMES | (extra_query_names or set())
    query = []
    for name, item_value in parse_qsl(parsed.query, keep_blank_values=True):
        replacement = "[REDACTED]" if name.lower() in sensitive_names else item_value
        query.append((name, replacement))
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(query, doseq=True),
            parsed.fragment,
        )
    )


def _redact_headers(
    headers: Mapping[str, str],
    extra_header_names: set[str] | None = None,
) -> dict[str, str]:
    sensitive_names = _SENSITIVE_HEADER_NAMES | (extra_header_names or set())
    rendered: dict[str, str] = {}
    for name, value in headers.items():
        rendered[name] = (
            "[REDACTED]" if name.lower() in sensitive_names else _redact_inline_secrets(value)
        )
    return rendered


def _is_textual(content_type: str | None) -> bool:
    if not content_type:
        return False
    media_type = content_type.split(";", 1)[0].strip().lower()
    return (
        media_type.startswith("text/")
        or media_type.endswith(("+json", "+xml"))
        or media_type in {"application/json", "application/xml", "application/javascript"}
    )


def _redact_json_fields(value: object, sensitive_fields: set[str]) -> object:
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if str(key).lower() in sensitive_fields
                else _redact_json_fields(item, sensitive_fields)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json_fields(item, sensitive_fields) for item in value]
    return value


def _decode_preview(
    body: bytes,
    content_type: str | None,
    sensitive_body_fields: set[str] | None = None,
) -> str | None:
    if not body or not _is_textual(content_type):
        return None
    charset = "utf-8"
    if content_type:
        for part in content_type.split(";")[1:]:
            name, separator, value = part.strip().partition("=")
            if separator and name.lower() == "charset" and value:
                charset = value.strip().strip('"')
                break
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    preview = text[:MAX_PREVIEW_CHARS]
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if sensitive_body_fields and (media_type == "application/json" or media_type.endswith("+json")):
        try:
            parsed = json.loads(preview)
        except json.JSONDecodeError:
            pass
        else:
            preview = json.dumps(
                _redact_json_fields(parsed, sensitive_body_fields),
                ensure_ascii=False,
                sort_keys=True,
            )
    return _redact_inline_secrets(preview)


def _validate_observation_request(
    permit: SignedExecutionPermit,
    target: str,
    method: str,
    timeout_seconds: float,
    max_body_bytes: int,
) -> None:
    parsed = urlsplit(target)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ObservationError("Observation target must use http or https.")
    if not parsed.hostname:
        raise ObservationError("Observation target must contain a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise ObservationError("Credentials embedded in observation URLs are not allowed.")
    if method not in {"GET", "HEAD"}:
        raise ObservationError("M2 observation worker only permits GET and HEAD.")
    if permit.payload.http_method not in {"GET", "HEAD"}:
        raise ObservationError("Execution permit is not bound to an observation-only HTTP method.")
    if timeout_seconds <= 0 or timeout_seconds > MAX_TIMEOUT_SECONDS:
        raise ObservationError(
            f"Timeout must be greater than 0 and at most {MAX_TIMEOUT_SECONDS:g} seconds."
        )
    if max_body_bytes < 0 or max_body_bytes > MAX_BODY_BYTES:
        raise ObservationError(f"Maximum body size must be between 0 and {MAX_BODY_BYTES} bytes.")


def _read_bounded(response, method: str, max_body_bytes: int) -> tuple[bytes, bool]:
    if method == "HEAD" or max_body_bytes == 0:
        return b"", False
    body = response.read(max_body_bytes + 1)
    if len(body) > max_body_bytes:
        return body[:max_body_bytes], True
    return body, False


def verify_observation_evidence(evidence: HttpObservationEvidence) -> bool:
    payload = evidence.model_dump(mode="json", exclude={"evidence_hash"})
    return hashlib.sha256(_canonical_json(payload)).hexdigest() == evidence.evidence_hash


def _write_evidence(path: Path, evidence: HttpObservationEvidence) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(evidence.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _evidence_hash(payload: dict[str, object]) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _write_failure_evidence(
    *,
    permit: SignedExecutionPermit,
    engagement: Engagement,
    test: TestDefinition,
    action_id: str,
    target: str,
    method: str,
    failure_kind: str,
    evidence_path: Path,
    manifest_path: Path,
    sensitivity: SensitivityLabel,
    now: datetime | None,
) -> HttpObservationFailureEvidence:
    observed_at = now or datetime.now(UTC)
    preliminary = HttpObservationFailureEvidence(
        evidence_id=str(uuid4()),
        action_id=action_id,
        sensitivity=sensitivity,
        permit_id=permit.payload.permit_id,
        engagement_id=engagement.id,
        test_id=test.id,
        observed_at=observed_at,
        method=method,
        target=redact_url(target, engagement.constraints.redaction.sensitive_query_parameters),
        failure_kind=failure_kind,
        evidence_hash="pending",
    )
    payload = preliminary.model_dump(mode="json", exclude={"evidence_hash"})
    evidence = preliminary.model_copy(update={"evidence_hash": _evidence_hash(payload)})
    _write_evidence(evidence_path, evidence)
    register_evidence(
        manifest_path,
        evidence_path,
        evidence_type="http.observation.failure",
        evidence_id=evidence.evidence_id,
        permit_id=permit.payload.permit_id,
        action_id=action_id,
        sensitivity=sensitivity,
        now=now,
    )
    return evidence


def observe_http(
    permit: SignedExecutionPermit,
    engagement: Engagement,
    test: TestDefinition,
    keys: str | bytes | Mapping[str, str | bytes],
    *,
    target: str,
    method: str,
    identity: str | None,
    requested_rps: float | None,
    state_path: Path,
    audit_path: Path,
    evidence_path: Path,
    manifest_path: Path,
    rate_state_path: Path,
    sensitivity: SensitivityLabel = SensitivityLabel.INTERNAL,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    now: datetime | None = None,
    transport: ObservationTransport | None = None,
) -> ObservationResult:
    normalized_method = method.upper()
    action_id = http_action_id(target, normalized_method, identity)
    _validate_observation_request(
        permit,
        target,
        normalized_method,
        timeout_seconds,
        max_body_bytes,
    )

    consume_result = consume_execution_permit(
        permit,
        engagement,
        test,
        PermitVerificationRequest(
            target=target,
            http_method=normalized_method,
            identity=identity,
            requested_requests_per_second=requested_rps,
            now=now,
        ),
        keys,
        state_path,
    )
    if not consume_result.accepted:
        append_audit_event(
            audit_path,
            "observation.rejected",
            permit_id=permit.payload.permit_id,
            details={
                "status": consume_result.lifecycle_status.value,
                "message": consume_result.message,
                "target": redact_url(
                    target, engagement.constraints.redaction.sensitive_query_parameters
                ),
            },
            now=now,
        )
        raise ObservationError(consume_result.message)

    rate_limit = requested_rps or permit.payload.max_requests_per_second
    acquired, retry_after = acquire_rate_slot(
        rate_state_path,
        http_target_rate_key(target),
        rate_limit,
        now=now,
    )
    if not acquired:
        append_audit_event(
            audit_path,
            "observation.rate_limited",
            permit_id=permit.payload.permit_id,
            details={
                "action_id": action_id,
                "retry_after_seconds": retry_after,
                "target": redact_url(
                    target, engagement.constraints.redaction.sensitive_query_parameters
                ),
            },
            now=now,
        )
        raise ObservationError(
            f"Durable target rate limit reached; retry after {retry_after:.3f} seconds."
        )

    append_audit_event(
        audit_path,
        "observation.started",
        permit_id=permit.payload.permit_id,
        details={
            "method": normalized_method,
            "target": redact_url(
                target, engagement.constraints.redaction.sensitive_query_parameters
            ),
        },
        now=now,
    )

    active_transport = transport or PinnedObservationTransport()
    request = Request(
        target,
        method=normalized_method,
        headers={
            "User-Agent": "ASTP/0.10 observation-worker",
            "Accept": "*/*",
        },
    )

    try:
        transport_result = active_transport.open(request, timeout=timeout_seconds)
        response = transport_result.response
        resolved_endpoint = transport_result.resolved_endpoint
        status_code = int(response.getcode())
        reason = getattr(response, "reason", None)
        headers = {name: value for name, value in response.headers.items()}
        content_type = response.headers.get("Content-Type")
        body, truncated = _read_bounded(response, normalized_method, max_body_bytes)
    except ObservationTransportError as exc:
        failure_evidence = _write_failure_evidence(
            permit=permit,
            engagement=engagement,
            test=test,
            action_id=action_id,
            target=target,
            method=normalized_method,
            failure_kind=exc.kind.value,
            evidence_path=evidence_path,
            manifest_path=manifest_path,
            sensitivity=sensitivity,
            now=now,
        )
        append_audit_event(
            audit_path,
            "observation.failed",
            permit_id=permit.payload.permit_id,
            details={
                "failure_kind": exc.kind.value,
                "evidence_id": failure_evidence.evidence_id,
                "target": redact_url(
                    target, engagement.constraints.redaction.sensitive_query_parameters
                ),
            },
            now=now,
        )
        raise ObservationError(f"Observation transport failed: {exc.kind.value}.") from exc
    finally:
        if "response" in locals():
            response.close()

    location = headers.get("Location")
    redirect = None
    if location and 300 <= status_code < 400:
        redirect_target = urljoin(target, location)
        current = urlsplit(target)
        redirected = urlsplit(redirect_target)
        current_port = current.port or (443 if current.scheme.lower() == "https" else 80)
        redirected_port = redirected.port or (443 if redirected.scheme.lower() == "https" else 80)
        same_origin = (
            current.scheme.lower() == redirected.scheme.lower()
            and (current.hostname or "").lower() == (redirected.hostname or "").lower()
            and current_port == redirected_port
        )
        redirect = RedirectObservation(
            target=redact_url(
                redirect_target, engagement.constraints.redaction.sensitive_query_parameters
            ),
            in_scope=target_in_scope(redirect_target, engagement.scope),
            same_origin=same_origin,
            requires_new_permit=True,
            followed=False,
        )

    observed_at = now or datetime.now(UTC)
    preliminary = HttpObservationEvidence(
        schema_version="2",
        evidence_id=str(uuid4()),
        action_id=action_id,
        sensitivity=sensitivity,
        permit_id=permit.payload.permit_id,
        engagement_id=engagement.id,
        test_id=test.id,
        observed_at=observed_at,
        method=normalized_method,
        target=redact_url(target, engagement.constraints.redaction.sensitive_query_parameters),
        status_code=status_code,
        reason=str(reason) if reason is not None else None,
        response_headers=_redact_headers(
            headers, engagement.constraints.redaction.sensitive_headers
        ),
        content_type=content_type,
        body_bytes_captured=len(body),
        body_truncated=truncated,
        body_sha256=hashlib.sha256(body).hexdigest(),
        body_preview=_decode_preview(
            body,
            content_type,
            engagement.constraints.redaction.sensitive_body_fields,
        ),
        redirect=redirect,
        resolved_endpoint=resolved_endpoint,
        transport_failure=None,
        evidence_hash="pending",
    )
    canonical_payload = preliminary.model_dump(mode="json", exclude={"evidence_hash"})
    evidence = preliminary.model_copy(update={"evidence_hash": _evidence_hash(canonical_payload)})
    _write_evidence(evidence_path, evidence)
    manifest_entry = register_evidence(
        manifest_path,
        evidence_path,
        evidence_type="http.observation",
        evidence_id=evidence.evidence_id,
        permit_id=permit.payload.permit_id,
        action_id=action_id,
        sensitivity=sensitivity,
        now=now,
    )
    append_audit_event(
        audit_path,
        "observation.completed",
        permit_id=permit.payload.permit_id,
        details={
            "status_code": status_code,
            "evidence_hash": evidence.evidence_hash,
            "evidence_id": evidence.evidence_id,
            "manifest_entry_hash": manifest_entry.entry_hash,
            "evidence_path": str(evidence_path),
            "redirect_followed": False,
        },
        now=now,
    )
    return ObservationResult(
        evidence=evidence, evidence_path=evidence_path, manifest_path=manifest_path
    )
