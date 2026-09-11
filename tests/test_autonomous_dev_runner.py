from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "autonomous-dev" / "autonomous_dev.py"
SPEC = importlib.util.spec_from_file_location("astp_autodev_tests", SCRIPT)
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


@pytest.fixture
def repo(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "tests@local.invalid"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "ASTP Tests"], cwd=tmp_path, check=True)
    (tmp_path / "README.md").write_text("test\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True)
    return tmp_path


def fake_invoke(marker, code=0):
    def invoke(_command, _repo, _prompt, logs, _timeout):
        stdout = f"ASTP_AUTODEV_RESULT={marker}\n" if marker else "ambiguous\n"
        logs.joinpath("codex.stdout.log").write_text(stdout, encoding="utf-8")
        logs.joinpath("codex.stderr.log").write_text("", encoding="utf-8")
        return code, stdout, ""

    return invoke


def structured_invoke(marker, reason, resumable, mutate=None):
    def invoke(_command, repo, _prompt, logs, _timeout):
        if mutate:
            mutate(repo)
        stdout = (
            f"ASTP_AUTODEV_RESULT={marker}\nASTP_AUTODEV_REASON={reason}\n"
            f"ASTP_AUTODEV_RESUMABLE={'true' if resumable else 'false'}\n"
        )
        logs.joinpath("codex.stdout.log").write_text(stdout, encoding="utf-8")
        logs.joinpath("codex.stderr.log").write_text("", encoding="utf-8")
        return 0, stdout, ""

    return invoke


def fake_validate(passed):
    def validate(_repo, _command, log, _timeout):
        log.write_text(str(passed), encoding="utf-8")
        return passed

    return validate


def execute(repo, marker, *, validation=True):
    runtime = repo / ".astp" / "autonomous-dev"
    runner.initialize(repo, runtime)
    return runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=fake_invoke(marker),
        validate=fake_validate(validation),
    )


def continuous_config(**overrides):
    config = runner.load_config(SCRIPT.parent / "config.json")
    config.update(overrides)
    return config


def queued_invoke(items):
    queue = list(items)

    def invoke(_command, repo, _prompt, logs, _timeout):
        marker, mutate = queue.pop(0)
        if mutate:
            mutate(repo)
        stdout = f"ASTP_AUTODEV_RESULT={marker}\n"
        logs.joinpath("codex.stdout.log").write_text(stdout, encoding="utf-8")
        logs.joinpath("codex.stderr.log").write_text("", encoding="utf-8")
        return 0, stdout, ""

    invoke.remaining = queue
    return invoke


def test_initialize_creates_valid_runtime_state(repo):
    state = runner.initialize(repo)
    runner.validate_state(state)
    assert state["status"] == "READY" and (repo / ".astp/autonomous-dev/state.json").exists()


def test_initialize_is_idempotent(repo):
    assert runner.initialize(repo) == runner.initialize(repo)


def test_state_schema_rejects_missing_fields(repo):
    with pytest.raises(runner.RunnerError, match="missing"):
        runner.validate_state({})


def test_valid_and_illegal_transitions(repo):
    runtime = repo / ".astp/autonomous-dev"
    state = runner.initialize(repo, runtime)
    state = runner.transition(runtime / "state.json", state, "RUNNING")
    assert state["status"] == "RUNNING"
    with pytest.raises(runner.RunnerError, match="illegal"):
        runner.transition(runtime / "state.json", state, "COMPLETE")


def test_lock_acquisition_and_second_rejection(tmp_path):
    first = runner.RunnerLock(tmp_path / "runner.lock")
    first.acquire("one")
    try:
        with pytest.raises(runner.RunnerError, match="active process"):
            runner.RunnerLock(tmp_path / "runner.lock").acquire("two")
    finally:
        first.release()


def test_stale_lock_is_recovered(tmp_path):
    path = tmp_path / "runner.lock"
    path.mkdir()
    runner.atomic_json(path / "owner.json", {"pid": 99999999, "process_identity": "old"})
    lock = runner.RunnerLock(path)
    lock.acquire("new")
    assert lock.owner["run_id"] == "new"
    lock.release()


def test_active_lock_is_not_removed(tmp_path):
    lock = runner.RunnerLock(tmp_path / "runner.lock")
    lock.acquire("active")
    try:
        with pytest.raises(runner.RunnerError):
            runner.RunnerLock(lock.path).acquire("other")
        assert lock.path.exists()
    finally:
        lock.release()


def test_run_ids_are_unique():
    now = datetime(2026, 9, 10, tzinfo=UTC)
    assert runner.run_id(now) != runner.run_id(now)


def test_history_is_append_only_and_redacted(tmp_path):
    path = tmp_path / "history.jsonl"
    runner.append_history(path, "ONE", token="secret")
    runner.append_history(path, "TWO")
    lines = path.read_text().splitlines()
    assert len(lines) == 2 and "secret" not in lines[0] and "[REDACTED]" in lines[0]


@pytest.mark.parametrize("marker", sorted(runner.MARKERS))
def test_result_markers_parse(marker):
    assert runner.parse_result(f"ASTP_AUTODEV_RESULT={marker}", "", 0) == marker


def test_ambiguous_or_duplicate_result_blocks():
    assert runner.parse_result("none", "", 0) == "BLOCKED"
    text = "ASTP_AUTODEV_RESULT=CONTINUE\nASTP_AUTODEV_RESULT=MILESTONE_COMPLETE"
    assert runner.parse_result(text, "", 0) == "BLOCKED"


def test_stderr_transcript_cannot_duplicate_or_spoof_stdout_result():
    stderr = "prompt ASTP_AUTODEV_RESULT=BLOCKED\nASTP_AUTODEV_RESULT=CONTINUE"
    assert runner.parse_result("ASTP_AUTODEV_RESULT=CONTINUE\n", stderr, 0) == "CONTINUE"


def test_stderr_marker_without_stdout_result_blocks():
    assert runner.parse_result("", "ASTP_AUTODEV_RESULT=CONTINUE", 0) == "BLOCKED"


def test_explicit_usage_limit_and_generic_error_differ():
    assert runner.parse_result("", "Codex usage limit reached", 1) == "USAGE_LIMIT"
    assert runner.parse_result("", "connection failed", 1) == "BLOCKED"


@pytest.mark.parametrize(
    "error",
    [
        "authentication required",
        "DNS lookup failed",
        "TLS handshake failed",
        "CODEX_TIMEOUT",
        "internal server error",
        "malformed response",
    ],
)
def test_non_usage_failures_never_wait_for_reset(error):
    assert runner.parse_result("", error, 1) == "BLOCKED"


def test_usage_limit_waits_without_invented_timestamp(repo):
    state = execute(repo, "USAGE_LIMIT")
    assert state["status"] == "WAITING_FOR_RESET" and state["resume_after"] is None


def test_continue_preserves_same_milestone_and_work_for_next_wake(repo):
    runtime = repo / ".astp/autonomous-dev"
    state = runner.initialize(repo, runtime)
    state["milestone"] = "M1"
    runner.atomic_json(runtime / "state.json", state)
    work = repo / "partial-m1.txt"
    work.write_text("preserve me\n", encoding="utf-8")
    first = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=fake_invoke("CONTINUE"),
        validate=fake_validate(True),
    )
    assert first["status"] == "READY" and first["milestone"] == "M1"
    assert work.read_text(encoding="utf-8") == "preserve me\n"
    second = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=fake_invoke("CONTINUE"),
        validate=fake_validate(True),
    )
    assert second["status"] == "READY" and second["milestone"] == "M1"
    assert second["attempt"] == 2


@pytest.mark.parametrize(
    ("marker", "expected"),
    [("HUMAN_GATE", "HUMAN_GATE"), ("BLOCKED", "BLOCKED"), ("FAILED", "BLOCKED")],
)
def test_explicit_stop_results_have_fail_closed_semantics(repo, marker, expected):
    assert execute(repo, marker)["status"] == expected


def test_continue_with_nonzero_exit_blocks(repo):
    runtime = repo / ".astp/autonomous-dev"
    runner.initialize(repo, runtime)
    state = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=fake_invoke("CONTINUE", code=1),
        validate=fake_validate(True),
    )
    assert state["status"] == "BLOCKED"


def test_structured_recoverable_block_returns_ready_without_immediate_retry(repo):
    runtime = repo / ".astp/autonomous-dev"
    runner.initialize(repo, runtime)
    state = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=structured_invoke("BLOCKED", "LOCAL_TOOL_TRANSIENT", True),
        validate=fake_validate(True),
    )
    assert state["status"] == "READY" and state["attempt"] == 1


@pytest.mark.parametrize(
    "stdout",
    [
        "ASTP_AUTODEV_RESULT=BLOCKED\n",
        "ASTP_AUTODEV_RESULT=BLOCKED\nASTP_AUTODEV_REASON=UNKNOWN\nASTP_AUTODEV_RESUMABLE=true\n",
        "ASTP_AUTODEV_RESULT=BLOCKED\nASTP_AUTODEV_REASON=LOCAL_TOOL_TRANSIENT\nASTP_AUTODEV_REASON=LOCAL_VALIDATION_REPAIR\nASTP_AUTODEV_RESUMABLE=true\n",
        "ASTP_AUTODEV_RESULT=BLOCKED\nASTP_AUTODEV_REASON=LOCAL_TOOL_TRANSIENT\nASTP_AUTODEV_RESUMABLE=yes\n",
        "ASTP_AUTODEV_RESULT=BLOCKED\nASTP_AUTODEV_REASON=SAFETY_POLICY\nASTP_AUTODEV_RESUMABLE=true\n",
    ],
)
def test_unsafe_or_malformed_block_metadata_fails_closed(repo, stdout):
    runtime = repo / ".astp/autonomous-dev"
    runner.initialize(repo, runtime)

    def invoke(*_args):
        return 0, stdout, ""

    state = runner.run_once(
        repo, runtime, ["fake"], ["validate"], invoke=invoke, validate=fake_validate(True)
    )
    assert state["status"] == "BLOCKED"


def test_owned_tracked_diff_resumes_and_foreign_change_blocks(repo):
    runtime = repo / ".astp/autonomous-dev"
    runner.initialize(repo, runtime)

    def mutate(target):
        (target / "README.md").write_text("owned\n", encoding="utf-8")

    first = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=structured_invoke("CONTINUE", "PARTIAL_WORK_CHECKPOINTED", True, mutate),
        validate=fake_validate(True),
    )
    assert first["status"] == "READY"
    second = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=fake_invoke("CONTINUE"),
        validate=fake_validate(True),
    )
    assert second["status"] == "READY"
    (repo / "README.md").write_text("foreign change\n", encoding="utf-8")
    third = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=fake_invoke("CONTINUE"),
        validate=fake_validate(True),
    )
    assert third["status"] == "BLOCKED"


def test_untracked_files_do_not_enter_owned_work(repo):
    runtime = repo / ".astp/autonomous-dev"
    runner.initialize(repo, runtime)
    (repo / "preexisting-untracked.txt").write_text("untouched\n", encoding="utf-8")
    state = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=fake_invoke("CONTINUE"),
        validate=fake_validate(True),
    )
    owned = json.loads((runtime / "owned-work.json").read_text(encoding="utf-8"))
    assert state["status"] == "READY" and owned["tracked_paths"] == []
    assert (repo / "preexisting-untracked.txt").read_text(encoding="utf-8") == "untouched\n"


def test_continuous_continue_invokes_again_immediately_and_usage_stops(repo):
    runtime = repo / ".astp/autonomous-dev"
    runner.initialize(repo, runtime)
    counter = {"n": 0}

    def progress(target):
        counter["n"] += 1
        (target / "README.md").write_text(f"progress {counter['n']}\n", encoding="utf-8")

    invoke = queued_invoke([("CONTINUE", progress), ("USAGE_LIMIT", None)])
    state = runner.run_continuous(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        continuous_config(),
        invoke=invoke,
        validate=fake_validate(True),
    )
    assert state["status"] == "WAITING_FOR_RESET" and state["session_iterations"] == 2
    assert not invoke.remaining


def test_three_no_progress_results_stop_session(repo):
    runtime = repo / ".astp/autonomous-dev"
    runner.initialize(repo, runtime)
    invoke = queued_invoke([("CONTINUE", None)] * 3)
    state = runner.run_continuous(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        continuous_config(),
        invoke=invoke,
        validate=fake_validate(True),
    )
    assert state["status"] == "BLOCKED" and state["last_exit_reason"] == "NO_PROGRESS_LIMIT"
    assert state["session_iterations"] == 3


def test_milestone_completion_advances_and_invokes_next_milestone(repo):
    runtime = repo / ".astp/autonomous-dev"
    state = runner.initialize(repo, runtime)
    state["milestone"] = "M1"
    runner.atomic_json(runtime / "state.json", state)

    def commit_progress(target):
        (target / "README.md").write_text("completed M1\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=target, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "complete M1"], cwd=target, check=True)

    state = runner.run_continuous(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        continuous_config(),
        invoke=queued_invoke([("MILESTONE_COMPLETE", commit_progress), ("USAGE_LIMIT", None)]),
        validate=fake_validate(True),
    )
    assert state["milestone"] == "M2" and state["status"] == "WAITING_FOR_RESET"
    assert state["session_iterations"] == 2


def test_m8_completion_stops_continuous_session_at_human_gate(repo):
    runtime = repo / ".astp/autonomous-dev"
    state = runner.initialize(repo, runtime)
    state["milestone"] = "M8"
    runner.atomic_json(runtime / "state.json", state)
    state = runner.run_continuous(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        continuous_config(),
        invoke=queued_invoke([("MILESTONE_COMPLETE", None)]),
        validate=fake_validate(True),
    )
    assert state["milestone"] == "M9" and state["status"] == "HUMAN_GATE"


def test_invocation_ceiling_and_single_invocation_debug_mode(repo):
    runtime = repo / ".astp/autonomous-dev"
    runner.initialize(repo, runtime)
    state = runner.run_continuous(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        continuous_config(max_invocations_per_session=1),
        invoke=queued_invoke([("CONTINUE", None)]),
        validate=fake_validate(True),
    )
    assert state["status"] == "READY" and state["session_iterations"] == 1

    runtime2 = repo / ".astp/single"
    runner.initialize(repo, runtime2)
    state = runner.run_continuous(
        repo,
        runtime2,
        ["fake"],
        ["validate"],
        continuous_config(continuous_mode=False),
        invoke=fake_invoke("CONTINUE"),
        validate=fake_validate(True),
    )
    assert state["attempt"] == 1 and "session_id" not in state


def test_fake_continuous_session_acceptance_sequence(repo):
    runtime = repo / ".astp/autonomous-dev"
    state = runner.initialize(repo, runtime)
    state["milestone"] = "M1"
    runner.atomic_json(runtime / "state.json", state)
    counter = {"n": 0}

    def progress(target):
        counter["n"] += 1
        (target / "README.md").write_text(f"progress {counter['n']}\n", encoding="utf-8")

    def complete(target):
        progress(target)
        subprocess.run(["git", "add", "README.md"], cwd=target, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "M1 checkpoint"], cwd=target, check=True)

    invoke = queued_invoke(
        [
            ("CONTINUE", progress),
            ("CONTINUE", progress),
            ("MILESTONE_COMPLETE", complete),
            ("CONTINUE", progress),
            ("USAGE_LIMIT", None),
        ]
    )
    state = runner.run_continuous(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        continuous_config(),
        invoke=invoke,
        validate=fake_validate(True),
    )
    assert state["status"] == "WAITING_FOR_RESET"
    assert state["milestone"] == "M2" and state["session_iterations"] == 5
    assert not invoke.remaining


def test_human_gate_and_complete_are_terminal_noops(repo):
    runtime = repo / ".astp/autonomous-dev"
    state = execute(repo, "HUMAN_GATE")
    attempt = state["attempt"]
    state = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=fake_invoke("CONTINUE"),
        validate=fake_validate(True),
    )
    assert state["status"] == "HUMAN_GATE" and state["attempt"] == attempt


def test_complete_handling_runs_authoritative_validation(repo):
    state = execute(repo, "MILESTONE_COMPLETE")
    assert state["status"] == "COMPLETE" and state["last_validation"]["passed"]


def test_validation_failure_returns_ready_for_repair(repo):
    state = execute(repo, "MILESTONE_COMPLETE", validation=False)
    assert state["status"] == "READY" and not state["last_validation"]["passed"]


def test_authorized_milestone_progresses_only_after_validation(repo):
    runtime = repo / ".astp/autonomous-dev"
    state = runner.initialize(repo, runtime)
    state["milestone"] = "M1"
    runner.atomic_json(runtime / "state.json", state)
    result = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=fake_invoke("MILESTONE_COMPLETE"),
        validate=fake_validate(True),
    )
    assert result["status"] == "READY" and result["milestone"] == "M2"


def test_m8_completion_stops_at_m9_human_gate(repo):
    runtime = repo / ".astp/autonomous-dev"
    state = runner.initialize(repo, runtime)
    state["milestone"] = "M8"
    runner.atomic_json(runtime / "state.json", state)
    result = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=fake_invoke("MILESTONE_COMPLETE"),
        validate=fake_validate(True),
    )
    assert result["status"] == "HUMAN_GATE" and result["milestone"] == "M9"
    assert result["last_exit_reason"] == "PRE_PUSH_REVIEW_REQUIRED"


def test_head_divergence_blocks_before_invocation(repo):
    runtime = repo / ".astp/autonomous-dev"
    state = runner.initialize(repo, runtime)
    state["head"] = "f" * 40
    runner.atomic_json(runtime / "state.json", state)
    result = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=fake_invoke("CONTINUE"),
        validate=fake_validate(True),
    )
    assert result["status"] == "BLOCKED" and result["attempt"] == 0


def test_safety_flags_cannot_be_true(repo):
    state = runner.initialize(repo)
    state["push_allowed"] = True
    with pytest.raises(runner.RunnerError, match="unsafe"):
        runner.validate_state(state)


def test_scheduler_has_hour_minimum_and_ignore_new():
    text = (SCRIPT.parent / "install-task.ps1").read_text(encoding="utf-8")
    assert "ValidateRange(1, 168)" in text and "MultipleInstances IgnoreNew" in text
    assert "Disable-ScheduledTask" in text


def test_runtime_files_are_git_ignored():
    root = Path(__file__).parents[1]
    completed = subprocess.run(
        ["git", "check-ignore", ".astp/autonomous-dev/state.json"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0


def test_restart_from_running_recovers_without_completion_claim(repo):
    runtime = repo / ".astp/autonomous-dev"
    state = runner.initialize(repo, runtime)
    state["status"] = "RUNNING"
    runner.atomic_json(runtime / "state.json", state)
    result = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["validate"],
        invoke=fake_invoke("CONTINUE"),
        validate=fake_validate(True),
    )
    assert result["status"] == "READY" and result["attempt"] == 1


def test_prompt_and_invocation_use_data_not_shell(repo, tmp_path):
    state = runner.initialize(repo)
    prompt = runner.build_prompt(repo, repo / ".astp/autonomous-dev", state)
    assert "Never push" in prompt and str(repo) in prompt
    source = SCRIPT.read_text(encoding="utf-8")
    assert "shell=False" in source and '"-C"' in source and "str(repo)" in source


def test_codex_global_approval_flag_precedes_exec(repo):
    argv = runner.build_codex_argv([r"C:\Program Files\nodejs\codex.cmd"], repo)
    assert argv.index("--ask-for-approval") < argv.index("exec")
    assert argv[argv.index("--ask-for-approval") + 1] == "never"


def test_environment_validation_is_local_and_rejects_substitution(repo, monkeypatch):
    config = runner.load_config(SCRIPT.parent / "config.json")
    monkeypatch.setattr(Path, "is_file", lambda path: True)
    result = runner.validate_environment(repo, repo / ".astp/autonomous-dev", config)
    assert result["status"] == "ENVIRONMENT_READY" and result["model_invoked"] is False
    config["codex_executable"] = str(repo / "codex.cmd")
    with pytest.raises(runner.RunnerError, match="substituted"):
        runner.validate_environment(repo, repo / ".astp/autonomous-dev", config)


def test_corrupt_state_fails_closed(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{broken", encoding="utf-8")
    with pytest.raises(runner.RunnerError, match="corrupt"):
        runner.load_state(path)
