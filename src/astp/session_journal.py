from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

GENESIS = "0" * 64


class SessionJournalEntry(BaseModel):
    sequence: int
    session_id: str
    event: str
    created_at: datetime
    previous_hash: str
    entry_hash: str


def _digest(payload: object) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def append_session_event(path: Path, session_id: str, event: str) -> SessionJournalEntry:
    entries = read_session_journal(path)
    previous = entries[-1].entry_hash if entries else GENESIS
    partial = {
        "sequence": len(entries) + 1,
        "session_id": session_id,
        "event": event,
        "created_at": datetime.now(UTC),
        "previous_hash": previous,
    }
    entry = SessionJournalEntry(**partial, entry_hash=_digest(partial))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(entry.model_dump_json() + "\n")
    return entry


def read_session_journal(path: Path) -> list[SessionJournalEntry]:
    if not path.exists():
        return []
    return [
        SessionJournalEntry.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def verify_session_journal(path: Path) -> bool:
    previous = GENESIS
    for sequence, entry in enumerate(read_session_journal(path), start=1):
        payload = entry.model_dump(mode="python", exclude={"entry_hash"})
        if entry.sequence != sequence or entry.previous_hash != previous:
            return False
        if _digest(payload) != entry.entry_hash:
            return False
        previous = entry.entry_hash
    return True
