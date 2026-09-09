from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from astp.orchestrator_models import (
    ACTION_TRANSITIONS,
    CAMPAIGN_TRANSITIONS,
    ActionState,
    AutonomousCampaignConfig,
    CampaignState,
    StateTransition,
    validate_transition,
)


class OrchestratorStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(
                """
            CREATE TABLE IF NOT EXISTS campaigns(id TEXT PRIMARY KEY,state TEXT NOT NULL,config_json TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS program_states(campaign_id TEXT NOT NULL,program_id TEXT NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL DEFAULT '',PRIMARY KEY(campaign_id,program_id));
            CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY,campaign_id TEXT NOT NULL,program_id TEXT NOT NULL,state TEXT NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,permit_id TEXT,evidence_id TEXT,retry_count INTEGER NOT NULL DEFAULT 0,next_retry_at TEXT);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,campaign_id TEXT NOT NULL,event TEXT NOT NULL,payload_json TEXT NOT NULL,created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS counters(campaign_id TEXT PRIMARY KEY,permits_issued INTEGER NOT NULL DEFAULT 0,permits_consumed INTEGER NOT NULL DEFAULT 0,network_actions INTEGER NOT NULL DEFAULT 0,requests INTEGER NOT NULL DEFAULT 0,failed_before_io INTEGER NOT NULL DEFAULT 0,unknown_outcomes INTEGER NOT NULL DEFAULT 0,evidence INTEGER NOT NULL DEFAULT 0,findings INTEGER NOT NULL DEFAULT 0,detector_runs_started INTEGER NOT NULL DEFAULT 0,detector_runs_completed INTEGER NOT NULL DEFAULT 0,requests_attempted INTEGER NOT NULL DEFAULT 0,requests_forwarded INTEGER NOT NULL DEFAULT 0,responses_received INTEGER NOT NULL DEFAULT 0,requests_blocked_before_io INTEGER NOT NULL DEFAULT 0,requests_failed_after_io INTEGER NOT NULL DEFAULT 0,permits_expired INTEGER NOT NULL DEFAULT 0,permits_revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS checkpoints(id INTEGER PRIMARY KEY AUTOINCREMENT,campaign_id TEXT NOT NULL,reason TEXT NOT NULL,created_at TEXT NOT NULL);
            """
            )
            columns = {row[1] for row in db.execute("PRAGMA table_info(counters)")}
            for column in (
                "requests",
                "detector_runs_started",
                "detector_runs_completed",
                "requests_attempted",
                "requests_forwarded",
                "responses_received",
                "requests_blocked_before_io",
                "requests_failed_after_io",
                "permits_expired",
                "permits_revoked",
            ):
                if column not in columns:
                    db.execute(
                        f"ALTER TABLE counters ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0"
                    )

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def create_campaign(self, config: AutonomousCampaignConfig) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connect() as db:
            db.execute(
                "INSERT INTO campaigns VALUES(?,?,?,?,?)",
                (
                    config.campaign_id,
                    CampaignState.CREATED.value,
                    config.model_dump_json(),
                    now,
                    now,
                ),
            )
            db.execute("INSERT INTO counters(campaign_id) VALUES(?)", (config.campaign_id,))
        self.event(config.campaign_id, "campaign.created", {"dry_run": config.dry_run})

    def campaign_state(self, campaign_id: str) -> CampaignState:
        with self.connect() as db:
            row = db.execute("SELECT state FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
        if row is None:
            raise ValueError("unknown campaign")
        return CampaignState(row["state"])

    def transition_campaign(
        self, campaign_id: str, state: CampaignState, reason: str, actor: str = "orchestrator"
    ) -> StateTransition:
        previous = self.campaign_state(campaign_id)
        validate_transition(previous, state, CAMPAIGN_TRANSITIONS)
        now = datetime.now(UTC)
        with self.connect() as db:
            db.execute(
                "UPDATE campaigns SET state=?,updated_at=? WHERE id=?",
                (state.value, now.isoformat(), campaign_id),
            )
        transition = StateTransition(
            entity_type="campaign",
            entity_id=campaign_id,
            previous_state=previous.value,
            state=state.value,
            timestamp=now,
            reason=reason,
            actor=actor,
        )
        self.event(campaign_id, "campaign.state", transition.model_dump(mode="json"))
        return transition

    def create_action(
        self, action_id: str, campaign_id: str, program_id: str, idempotency_key: str
    ) -> bool:
        try:
            with self.connect() as db:
                db.execute(
                    "INSERT INTO actions(id,campaign_id,program_id,state,idempotency_key) VALUES(?,?,?,?,?)",
                    (
                        action_id,
                        campaign_id,
                        program_id,
                        ActionState.DISCOVERED.value,
                        idempotency_key,
                    ),
                )
        except sqlite3.IntegrityError:
            return False
        return True

    def action_state(self, action_id: str) -> ActionState:
        with self.connect() as db:
            row = db.execute("SELECT state FROM actions WHERE id=?", (action_id,)).fetchone()
        if row is None:
            raise ValueError("unknown action")
        return ActionState(row["state"])

    def transition_action(
        self,
        action_id: str,
        state: ActionState,
        *,
        permit_id: str | None = None,
        evidence_id: str | None = None,
    ) -> None:
        previous = self.action_state(action_id)
        validate_transition(previous, state, ACTION_TRANSITIONS)
        with self.connect() as db:
            row = db.execute("SELECT campaign_id FROM actions WHERE id=?", (action_id,)).fetchone()
            db.execute(
                "UPDATE actions SET state=?,permit_id=COALESCE(?,permit_id),evidence_id=COALESCE(?,evidence_id) WHERE id=?",
                (state.value, permit_id, evidence_id, action_id),
            )
        self.event(
            row["campaign_id"],
            "action.state",
            {"action_id": action_id, "previous": previous.value, "state": state.value},
        )

    def increment(self, campaign_id: str, field: str, amount: int = 1) -> None:
        allowed = {
            "permits_issued",
            "permits_consumed",
            "network_actions",
            "requests",
            "failed_before_io",
            "unknown_outcomes",
            "evidence",
            "findings",
            "detector_runs_started",
            "detector_runs_completed",
            "requests_attempted",
            "requests_forwarded",
            "responses_received",
            "requests_blocked_before_io",
            "requests_failed_after_io",
            "permits_expired",
            "permits_revoked",
        }
        if field not in allowed:
            raise ValueError("unknown accounting field")
        with self.connect() as db:
            db.execute(
                f"UPDATE counters SET {field}={field}+? WHERE campaign_id=?", (amount, campaign_id)
            )

    def reconcile_detector_run(
        self, campaign_id: str, accounting: dict[str, int], *, authorized_budget: int
    ) -> None:
        attempted = accounting["requests_attempted"]
        forwarded = accounting["requests_forwarded"]
        responses = accounting["responses_received"]
        blocked = accounting["requests_blocked_before_io"]
        failed = accounting["requests_failed_after_io"]
        unknown = accounting.get("unknown_outcomes", 0)
        if forwarded > authorized_budget:
            raise ValueError("forwarded requests exceed detector-run authorization")
        if attempted != forwarded + blocked or forwarded != responses + failed + unknown:
            raise ValueError("detector-run request accounting invariant failed")
        with self.connect() as db:
            db.execute(
                """UPDATE counters SET
                detector_runs_completed=detector_runs_completed+1,
                requests_attempted=requests_attempted+?, requests_forwarded=requests_forwarded+?,
                responses_received=responses_received+?,
                requests_blocked_before_io=requests_blocked_before_io+?,
                requests_failed_after_io=requests_failed_after_io+?,
                unknown_outcomes=unknown_outcomes+?, requests=requests+?
                WHERE campaign_id=?""",
                (
                    attempted,
                    forwarded,
                    responses,
                    blocked,
                    failed,
                    unknown,
                    forwarded,
                    campaign_id,
                ),
            )
        self.event(
            campaign_id,
            "detector_run.accounting_reconciled",
            {**accounting, "authorized_budget": authorized_budget},
        )

    def event(self, campaign_id: str, event: str, payload: dict) -> None:
        safe = json.dumps(payload, sort_keys=True, default=str)
        if any(term in safe.lower() for term in ('"authorization"', '"cookie"', '"password"')):
            raise ValueError("secret-like event fields are prohibited")
        with self.connect() as db:
            db.execute(
                "INSERT INTO events(campaign_id,event,payload_json,created_at) VALUES(?,?,?,?)",
                (campaign_id, event, safe, datetime.now(UTC).isoformat()),
            )

    def checkpoint(self, campaign_id: str, reason: str) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT INTO checkpoints(campaign_id,reason,created_at) VALUES(?,?,?)",
                (campaign_id, reason, datetime.now(UTC).isoformat()),
            )
        self.event(campaign_id, "checkpoint.saved", {"reason": reason})

    def snapshot(self, campaign_id: str) -> dict:
        with self.connect() as db:
            campaign = dict(
                db.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
            )
            counters = dict(
                db.execute("SELECT * FROM counters WHERE campaign_id=?", (campaign_id,)).fetchone()
            )
            programs = [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM program_states WHERE campaign_id=?", (campaign_id,)
                )
            ]
            actions = [
                dict(row)
                for row in db.execute("SELECT * FROM actions WHERE campaign_id=?", (campaign_id,))
            ]
        return {
            "campaign": campaign,
            "counters": counters,
            "programs": programs,
            "actions": actions,
        }
