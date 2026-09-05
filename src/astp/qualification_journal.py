from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field


class QualificationJournalEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    stage: str
    event: str
    evidence_path: str = ""
    details: dict[str, object] = Field(default_factory=dict)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def entry_hash(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()


def render_jsonl(entries: tuple[QualificationJournalEntry, ...]) -> str:
    return "\n".join(
        json.dumps(entry.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        for entry in entries
    ) + ("\n" if entries else "")
