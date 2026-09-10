from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("astp_autodev", HERE / "autonomous_dev.py")
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


def make_repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "acceptance@local.invalid"], cwd=repo, check=True
    )
    subprocess.run(["git", "config", "user.name", "ASTP Acceptance"], cwd=repo, check=True)
    (repo / "README.md").write_text("local acceptance\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True)
    return repo


def invoke_result(marker: str, code: int = 0):
    def invoke(_command, _repo, _prompt, log_root, _timeout):
        stdout = f"ASTP_AUTODEV_RESULT={marker}\n" if marker else "malformed\n"
        (log_root / "codex.stdout.log").write_text(stdout, encoding="utf-8")
        (log_root / "codex.stderr.log").write_text("", encoding="utf-8")
        return code, stdout, ""

    return invoke


def validate_result(passed: bool):
    def validate(_repo, _command, log_path, _timeout):
        log_path.write_text("PASS\n" if passed else "FAIL\n", encoding="utf-8")
        return passed

    return validate


def scenario(marker: str, *, validation: bool = True):
    temp = tempfile.TemporaryDirectory()
    repo = make_repo(Path(temp.name))
    runtime = repo / ".astp" / "autonomous-dev"
    runner.initialize(repo, runtime)
    state = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["fake-validation"],
        invoke=invoke_result(marker),
        validate=validate_result(validation),
    )
    return temp, repo, runtime, state


def main() -> int:
    results: list[tuple[str, bool, str]] = []
    keep: list[tempfile.TemporaryDirectory] = []

    temp, _, _, state = scenario("MILESTONE_COMPLETE")
    keep.append(temp)
    results.append(("CASE 1 — NORMAL COMPLETION", state["status"] == "COMPLETE", state["status"]))

    temp, repo, runtime, state = scenario("USAGE_LIMIT")
    keep.append(temp)
    results.append(
        (
            "CASE 2 — USAGE LIMIT",
            state["status"] == "WAITING_FOR_RESET" and state["resume_after"] is None,
            state["status"],
        )
    )

    resumed = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["fake-validation"],
        invoke=invoke_result("MILESTONE_COMPLETE"),
        validate=validate_result(True),
    )
    results.append(
        (
            "CASE 3 — RESUME AFTER RESET",
            resumed["status"] == "COMPLETE" and resumed["attempt"] == 2,
            resumed["status"],
        )
    )

    temp = tempfile.TemporaryDirectory()
    keep.append(temp)
    repo = make_repo(Path(temp.name))
    runtime = repo / ".astp" / "autonomous-dev"
    state = runner.initialize(repo, runtime)
    state["status"] = "RUNNING"
    runner.atomic_json(runtime / "state.json", state)
    recovered = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["fake-validation"],
        invoke=invoke_result("CONTINUE"),
        validate=validate_result(True),
    )
    results.append(
        (
            "CASE 4 — PROCESS CRASH",
            recovered["status"] == "READY" and recovered["attempt"] == 1,
            recovered["status"],
        )
    )

    temp, repo, runtime, state = scenario("HUMAN_GATE")
    keep.append(temp)
    attempt = state["attempt"]
    noop = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["fake-validation"],
        invoke=invoke_result("MILESTONE_COMPLETE"),
        validate=validate_result(True),
    )
    results.append(
        (
            "CASE 5 — HUMAN GATE",
            noop["status"] == "HUMAN_GATE" and noop["attempt"] == attempt,
            noop["status"],
        )
    )

    temp, _, _, state = scenario("MILESTONE_COMPLETE", validation=False)
    keep.append(temp)
    results.append(
        (
            "CASE 6 — VALIDATION FAILURE",
            state["status"] == "READY" and not state["last_validation"]["passed"],
            state["status"],
        )
    )

    temp = tempfile.TemporaryDirectory()
    keep.append(temp)
    lock_path = Path(temp.name) / "runner.lock"
    first = runner.RunnerLock(lock_path)
    first.acquire("one")
    try:
        try:
            runner.RunnerLock(lock_path).acquire("two")
            double = False
        except runner.RunnerError:
            double = True
    finally:
        first.release()
    results.append(("CASE 7 — DOUBLE START", double, "second rejected"))

    temp = tempfile.TemporaryDirectory()
    keep.append(temp)
    repo = make_repo(Path(temp.name))
    runtime = repo / ".astp" / "autonomous-dev"
    state = runner.initialize(repo, runtime)
    state["head"] = "0" * 40
    runner.atomic_json(runtime / "state.json", state)
    diverged = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["fake-validation"],
        invoke=invoke_result("CONTINUE"),
        validate=validate_result(True),
    )
    results.append(
        (
            "CASE 8 — HEAD DIVERGENCE",
            diverged["status"] == "BLOCKED" and diverged["attempt"] == 0,
            diverged["status"],
        )
    )

    temp, _, _, state = scenario("")
    keep.append(temp)
    results.append(
        ("CASE 9 — MALFORMED CODEX RESULT", state["status"] == "BLOCKED", state["status"])
    )

    temp = tempfile.TemporaryDirectory()
    keep.append(temp)
    repo = make_repo(Path(temp.name))
    runtime = repo / ".astp" / "autonomous-dev"
    state = runner.initialize(repo, runtime)
    first_process_state = {**state, "status": "RUNNING", "last_run_id": "dead-process"}
    runner.atomic_json(runtime / "state.json", first_process_state)
    second = runner.run_once(
        repo,
        runtime,
        ["fake"],
        ["fake-validation"],
        invoke=invoke_result("MILESTONE_COMPLETE"),
        validate=validate_result(True),
    )
    results.append(
        (
            "CASE 10 — REBOOT-LIKE RESUME",
            second["status"] == "COMPLETE" and second["last_run_id"] != "dead-process",
            second["status"],
        )
    )

    output_root = (
        Path(sys.argv[1]).resolve()
        if len(sys.argv) > 1
        else Path.cwd() / ".astp" / "autonomous-dev" / "acceptance"
    )
    output_root.mkdir(parents=True, exist_ok=True)
    report = ["# ASTP Autonomous Development Runner V1 — Local Acceptance", ""]
    report.extend(
        f"- {name}: **{'PASS' if passed else 'FAIL'}** (`{detail}`)"
        for name, passed, detail in results
    )
    report.extend(
        [
            "",
            "No real Codex invocation, external target, push, deploy, or scheduler installation was used.",
            "",
        ]
    )
    (output_root / "ACCEPTANCE-REPORT.md").write_text("\n".join(report), encoding="utf-8")
    print("\n".join(report))
    return 0 if all(item[1] for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
