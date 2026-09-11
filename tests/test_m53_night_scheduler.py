from datetime import UTC, datetime, timedelta

from astp.counting_proxy import ProxyAccounting
from astp.m53_night_scheduler import (
    DurableNightScheduler,
    NightAttemptOutcome,
    NightProgramState,
    NightWork,
)


def _program(name: str, count: int = 1) -> NightProgramState:
    return NightProgramState(
        program_id=name,
        lease_id=f"lease-{name}",
        exhaust_on_empty_no_progress=name == "D",
        pending=[
            NightWork(work_id=f"{name}-{index}", program_id=name, duration_seconds=60)
            for index in range(count)
        ],
    )


def test_scheduler_persists_fairness_backoff_restart_and_deadline_drain(tmp_path):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    scheduler = DurableNightScheduler(tmp_path / "scheduler.json")
    scheduler.create("night", started_at=start, programs=(_program("A", 2), _program("H", 2)))
    scheduler.advance(start)
    assert [work.program_id for work in scheduler.select()] == ["A", "H"]
    scheduler.rate_limit("H", 7200)
    scheduler.complete(scheduler.select()[0], progress=True)

    restarted = DurableNightScheduler(scheduler.path)
    restarted.advance(start + timedelta(hours=2))
    assert [work.program_id for work in restarted.select()] == ["A", "H"]
    restarted.advance(start + timedelta(hours=8))
    assert restarted.select() == ()
    assert restarted.reopen().draining


def test_scheduler_derives_exhaustion_revision_and_fresh_run_retry(tmp_path):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    scheduler = DurableNightScheduler(tmp_path / "scheduler.json")
    scheduler.create("night", started_at=start, programs=(_program("D", 2), _program("F")))
    scheduler.advance(start)
    scheduler.complete(_program("D", 2).pending[0], progress=False)
    scheduler.complete(
        NightWork(work_id="D-1", program_id="D", duration_seconds=60), progress=False
    )
    scheduler.replace_revision("F", "2", "lease-F-2")
    scheduler.mark_retry("F", "run-old", "run-new")

    state = DurableNightScheduler(scheduler.path).reopen()
    assert state.programs["D"].exhausted_reason
    assert state.programs["F"].revision == "2"
    assert {event["event"] for event in state.events} >= {
        "revision.replanned",
        "runtime.retry",
    }


def test_scheduler_consumes_real_429_retry_after_from_proxy_ledger(tmp_path):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    scheduler = DurableNightScheduler(tmp_path / "scheduler.json")
    scheduler.create("night", started_at=start, programs=(_program("H"),))
    scheduler.advance(start)
    ledger = ProxyAccounting(tmp_path / "proxy.db")
    ledger.start("request", "permit", "run", "GET", "http://lab/api", "forwarding")
    ledger.finish("request", "response_received", 429, 0, 11, "retry_after_seconds=2")

    retry_at = scheduler.apply_backoff_from_proxy_ledger("H", ledger.path)

    assert retry_at == start + timedelta(seconds=2)
    assert scheduler.select() == ()


def test_one_scheduler_decision_launches_each_attempt_exactly_once(tmp_path):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    scheduler = DurableNightScheduler(tmp_path / "scheduler.json")
    scheduler.create("night", started_at=start, programs=(_program("A"),))
    scheduler.advance(start)
    calls = []

    def execute(work):
        calls.append(work.work_id)
        return NightAttemptOutcome(
            work_id=work.work_id,
            program_id=work.program_id,
            run_id="run-1",
            permit_id="permit-1",
            status="completed",
            progress=True,
        )

    assert len(scheduler.dispatch_round(execute)) == 1
    assert scheduler.dispatch_round(execute) == ()
    assert calls == ["A-0"]


def test_stale_revision_or_lease_work_is_ineligible_until_replanned(tmp_path):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    scheduler = DurableNightScheduler(tmp_path / "scheduler.json")
    program = _program("F")
    program.pending[0] = program.pending[0].model_copy(
        update={"required_revision": "1", "required_lease_id": "lease-F"}
    )
    scheduler.create("night", started_at=start, programs=(program,))
    scheduler.advance(start)
    state = scheduler.reopen()
    state.programs["F"].revision = "2"
    scheduler.save(state)
    assert scheduler.select() == ()
    scheduler.replace_revision("F", "2", "lease-F-2")
    assert scheduler.select()[0].required_lease_id == "lease-F-2"


def test_deadline_refuses_work_that_cannot_finish(tmp_path):
    start = datetime(2026, 1, 1, tzinfo=UTC)
    scheduler = DurableNightScheduler(tmp_path / "scheduler.json")
    scheduler.create("night", started_at=start, programs=(_program("A"),))
    scheduler.advance(start + timedelta(hours=8) - timedelta(seconds=30))
    assert scheduler.select() == ()
