from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from astp.ctf_analysis import CtfAnalysisResult, CtfArtifactKind
from astp.ctf_categories import run_category_adapter
from astp.ctf_mode import ChallengeDefinition

MAX_LOCAL_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_STRINGS = 500
MAX_ZIP_ENTRIES = 500
MAX_CANDIDATES = 100


class CtfTraceKind(str, Enum):
    ADAPTER = "adapter"
    CANDIDATE = "candidate"
    VERIFICATION = "verification"


class CtfFlagCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    value: str
    artifact_path: str
    adapter_id: str
    artifact_sha256: str


class CtfSolveTraceEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    sequence: int
    kind: CtfTraceKind
    adapter_id: str | None = None
    artifact_path: str | None = None
    detail: str


class CtfLocalSolveResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    challenge_id: str
    adapters_run: tuple[str, ...] = Field(default_factory=tuple)
    candidates: tuple[CtfFlagCandidate, ...] = Field(default_factory=tuple)
    trace: tuple[CtfSolveTraceEvent, ...] = Field(default_factory=tuple)
    skipped: tuple[str, ...] = Field(default_factory=tuple)
    external_processes_spawned: bool = False
    network_performed: bool = False


class CtfFlagVerification(BaseModel):
    model_config = ConfigDict(frozen=True)

    candidate: CtfFlagCandidate
    matches_declared_pattern: bool


class CtfVerificationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    challenge_id: str
    verified: tuple[CtfFlagVerification, ...] = Field(default_factory=tuple)
    solved: bool = False
    solve_trace: tuple[CtfSolveTraceEvent, ...] = Field(default_factory=tuple)
    network_performed: bool = False


def _candidate_pattern(challenge: ChallengeDefinition) -> re.Pattern[str]:
    try:
        return re.compile(challenge.flag_pattern)
    except re.error as exc:
        raise ValueError(f"invalid challenge flag_pattern: {exc}") from exc


def _candidate_values(text: str, pattern: re.Pattern[str]) -> list[str]:
    values: list[str] = []
    for match in pattern.finditer(text):
        value = match.group(0)
        if value and value not in values:
            values.append(value)
        if len(values) >= MAX_CANDIDATES:
            break
    return values


def _ascii_strings(data: bytes, minimum: int = 4) -> list[str]:
    strings = re.findall(rb"[\x20-\x7e]{%d,}" % minimum, data)
    return [item.decode("ascii", errors="ignore") for item in strings[:MAX_STRINGS]]


def _run_adapter(adapter_id: str, data: bytes) -> str:
    if adapter_id == "text-pattern":
        return data.decode("utf-8", errors="replace")
    if adapter_id == "safe-strings":
        return "\n".join(_ascii_strings(data))
    if adapter_id == "json-structure":
        payload = json.loads(data.decode("utf-8"))
        return json.dumps(payload, sort_keys=True, ensure_ascii=False)
    if adapter_id == "zip-inventory":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()[:MAX_ZIP_ENTRIES]
            return "\n".join(
                f"{entry.filename}\t{entry.file_size}\t{entry.CRC}" for entry in entries
            )
    return run_category_adapter(adapter_id, data).rendered


def run_local_ctf_solvers(
    challenge: ChallengeDefinition,
    base_dir: Path,
    analysis: CtfAnalysisResult,
) -> CtfLocalSolveResult:
    if not challenge.allow_automation:
        raise ValueError("challenge rules do not allow automation")

    pattern = _candidate_pattern(challenge)
    candidates: list[CtfFlagCandidate] = []
    trace: list[CtfSolveTraceEvent] = []
    skipped: list[str] = []
    adapters_run: list[str] = []
    sequence = 0

    for classification in analysis.classifications:
        path = base_dir / classification.path
        data = path.read_bytes()
        if len(data) != classification.size_bytes:
            raise ValueError(f"artifact size changed after analysis: {classification.path}")
        current_sha256 = hashlib.sha256(data).hexdigest()
        if current_sha256 != classification.sha256:
            raise ValueError(f"artifact SHA-256 changed after analysis: {classification.path}")
        if len(data) > MAX_LOCAL_ARTIFACT_BYTES:
            skipped.append(
                f"{classification.path}: exceeds local adapter limit of "
                f"{MAX_LOCAL_ARTIFACT_BYTES} bytes"
            )
            continue
        for adapter_id in classification.eligible_adapters:
            # Avoid duplicate broad strings pass for text-like artifacts.
            if adapter_id == "safe-strings" and classification.kind in {
                CtfArtifactKind.TEXT,
                CtfArtifactKind.JSON,
                CtfArtifactKind.JAVASCRIPT,
                CtfArtifactKind.HTML,
            }:
                continue
            sequence += 1
            try:
                rendered = _run_adapter(adapter_id, data)
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                zipfile.BadZipFile,
                ValueError,
            ) as exc:
                skipped.append(f"{classification.path}/{adapter_id}: {exc}")
                continue
            adapters_run.append(adapter_id)
            trace.append(
                CtfSolveTraceEvent(
                    sequence=sequence,
                    kind=CtfTraceKind.ADAPTER,
                    adapter_id=adapter_id,
                    artifact_path=classification.path,
                    detail="isolated local adapter completed",
                )
            )
            for value in _candidate_values(rendered, pattern):
                candidate = CtfFlagCandidate(
                    value=value,
                    artifact_path=classification.path,
                    adapter_id=adapter_id,
                    artifact_sha256=classification.sha256,
                )
                duplicate = any(
                    existing.value == candidate.value
                    and existing.artifact_path == candidate.artifact_path
                    and existing.artifact_sha256 == candidate.artifact_sha256
                    for existing in candidates
                )
                if not duplicate:
                    candidates.append(candidate)
                    sequence += 1
                    trace.append(
                        CtfSolveTraceEvent(
                            sequence=sequence,
                            kind=CtfTraceKind.CANDIDATE,
                            adapter_id=adapter_id,
                            artifact_path=classification.path,
                            detail=f"flag candidate discovered: {value}",
                        )
                    )
                if len(candidates) >= MAX_CANDIDATES:
                    break

    return CtfLocalSolveResult(
        challenge_id=challenge.id,
        adapters_run=tuple(adapters_run),
        candidates=tuple(candidates),
        trace=tuple(trace),
        skipped=tuple(skipped),
    )


def verify_flag_candidates(
    challenge: ChallengeDefinition,
    solve: CtfLocalSolveResult,
) -> CtfVerificationResult:
    if solve.challenge_id != challenge.id:
        raise ValueError("solve result belongs to a different challenge")
    pattern = _candidate_pattern(challenge)
    verified: list[CtfFlagVerification] = []
    trace = list(solve.trace)
    sequence = max((event.sequence for event in trace), default=0)
    solved = False

    for candidate in solve.candidates:
        matched = pattern.fullmatch(candidate.value) is not None
        verified.append(CtfFlagVerification(candidate=candidate, matches_declared_pattern=matched))
        sequence += 1
        trace.append(
            CtfSolveTraceEvent(
                sequence=sequence,
                kind=CtfTraceKind.VERIFICATION,
                adapter_id=candidate.adapter_id,
                artifact_path=candidate.artifact_path,
                detail=(
                    "candidate matches declared flag pattern"
                    if matched
                    else "candidate rejected by declared flag pattern"
                ),
            )
        )
        solved = solved or matched

    return CtfVerificationResult(
        challenge_id=challenge.id,
        verified=tuple(verified),
        solved=solved,
        solve_trace=tuple(trace),
    )
