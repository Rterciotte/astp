from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class RateLimitState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamps: dict[str, list[float]] = Field(default_factory=dict)


@contextmanager
def _file_lock(path: Path, timeout_seconds: float = 10.0) -> Iterator[None]:
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout_seconds
    handle = None
    while handle is None:
        try:
            handle = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(handle, f"{os.getpid()}\n".encode())
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Timed out waiting for lock {lock_path}.") from None
            time.sleep(0.025)
    try:
        yield
    finally:
        os.close(handle)
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def _read(path: Path) -> RateLimitState:
    if not path.exists():
        return RateLimitState()
    return RateLimitState.model_validate_json(path.read_text(encoding="utf-8"))


def _write(path: Path, state: RateLimitState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(state.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def acquire_rate_slot(
    path: Path,
    action_key: str,
    max_requests_per_second: float,
    *,
    now: datetime | None = None,
) -> tuple[bool, float]:
    if max_requests_per_second <= 0:
        raise ValueError("Rate limit must be greater than zero.")
    instant = (now or datetime.now(UTC)).timestamp()
    window_start = instant - 1.0
    with _file_lock(path):
        state = _read(path)
        recent = [stamp for stamp in state.timestamps.get(action_key, []) if stamp > window_start]
        minimum_interval = 1.0 / max_requests_per_second
        if recent and instant - max(recent) < minimum_interval:
            wait = max(0.0, minimum_interval - (instant - max(recent)))
            state.timestamps[action_key] = recent
            _write(path, state)
            return False, wait
        recent.append(instant)
        state.timestamps[action_key] = recent
        _write(path, state)
        return True, 0.0
