from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Self

SCHEMA_VERSION = 1
STATUSES = {
    "UNINITIALIZED",
    "READY",
    "RUNNING",
    "VALIDATING",
    "WAITING_FOR_RESET",
    "HUMAN_GATE",
    "BLOCKED",
    "COMPLETE",
    "RECOVERING",
}
TERMINAL_NOOP = {"HUMAN_GATE", "COMPLETE"}
TRANSITIONS = {
    "UNINITIALIZED": {"READY", "BLOCKED"},
    "READY": {"RUNNING", "BLOCKED"},
    "RUNNING": {"READY", "VALIDATING", "WAITING_FOR_RESET", "HUMAN_GATE", "BLOCKED"},
    "VALIDATING": {"READY", "HUMAN_GATE", "COMPLETE", "BLOCKED"},
    "WAITING_FOR_RESET": {"RUNNING", "BLOCKED"},
    "RECOVERING": {"READY", "BLOCKED"},
    "HUMAN_GATE": set(),
    "BLOCKED": {"READY"},
    "COMPLETE": set(),
}
MARKERS = {"MILESTONE_COMPLETE", "CONTINUE", "USAGE_LIMIT", "HUMAN_GATE", "BLOCKED", "FAILED"}
RESULT_ACTIONS = {
    "MILESTONE_COMPLETE": "VALIDATE",
    "CONTINUE": "RESUME_SAME_MILESTONE",
    "USAGE_LIMIT": "WAIT_FOR_RESET",
    "HUMAN_GATE": "STOP_FOR_HUMAN",
    "BLOCKED": "BLOCK",
    # FAILED carries no structured proof that autonomous repair is safe.
    "FAILED": "BLOCK",
}
AUTONOMOUS_MILESTONES = tuple(f"M{number}" for number in range(1, 9))
MARKER_RE = re.compile(r"(?m)^ASTP_AUTODEV_RESULT=([A-Z_]+)\s*$")
USAGE_PATTERNS = (
    re.compile(r"\busage limit\b", re.IGNORECASE),
    re.compile(r"\bquota (?:is )?exceeded\b", re.IGNORECASE),
    re.compile(r"\bcodex[^\n]{0,80}\brate limit\b", re.IGNORECASE),
)
REDACTIONS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*)(\S+)"),
    re.compile(
        r'(?i)(["\']?(?:api[_-]?key|token|password|cookie)["\']?\s*[:=]\s*["\']?)([^"\'\s,}]+)'
    ),
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._~+/-]+)"),
)


class RunnerError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def run_id(now: datetime | None = None) -> str:
    moment = now or datetime.now(UTC)
    return f"autodev-{moment.strftime('%Y%m%dT%H%M%S%fZ')}-{secrets.token_hex(3)}"


def redact(text: str) -> str:
    clean = text
    for pattern in REDACTIONS:
        clean = pattern.sub(r"\1[REDACTED]", clean)
    return clean


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def append_history(path: Path, event: str, **fields: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"schema_version": 1, "at": utc_now(), "event": event, **fields}
    line = redact(json.dumps(record, ensure_ascii=False, separators=(",", ":"))) + "\n"
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(line)
        stream.flush()
        os.fsync(stream.fileno())


def validate_state(state: dict) -> None:
    required = {
        "schema_version",
        "status",
        "milestone",
        "head",
        "attempt",
        "started_at",
        "updated_at",
        "last_run_id",
        "last_validation",
        "last_exit_reason",
        "resume_after",
        "push_allowed",
        "deploy_allowed",
        "real_target_network_allowed",
    }
    if set(state) < required:
        raise RunnerError(f"state missing fields: {sorted(required - set(state))}")
    if state["schema_version"] != SCHEMA_VERSION or state["status"] not in STATUSES:
        raise RunnerError("unsupported or invalid state")
    if state["attempt"] < 0:
        raise RunnerError("attempt must be non-negative")
    for field in ("push_allowed", "deploy_allowed", "real_target_network_allowed"):
        if state[field] is not False:
            raise RunnerError(f"unsafe state flag: {field}")


def load_state(path: Path) -> dict:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError("state is missing or corrupt") from exc
    validate_state(state)
    return state


def load_config(path: Path) -> dict:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError("configuration is missing or corrupt") from exc
    required = {
        "schema_version",
        "codex_executable",
        "wake_interval_hours",
        "codex_timeout_seconds",
        "validation_timeout_seconds",
        "task_name",
        "push_allowed",
        "deploy_allowed",
        "real_target_network_allowed",
        "allow_local_commits",
    }
    if set(config) < required or config["schema_version"] != 1:
        raise RunnerError("invalid configuration schema")
    if config["wake_interval_hours"] < 1:
        raise RunnerError("wake interval must be at least one hour")
    if config["codex_timeout_seconds"] < 60 or config["validation_timeout_seconds"] < 60:
        raise RunnerError("timeouts must be at least 60 seconds")
    if config.get("logs_retention_runs", 0) < 1 or config.get("max_log_bytes", 0) < 1024:
        raise RunnerError("invalid log retention configuration")
    for field in ("push_allowed", "deploy_allowed", "real_target_network_allowed"):
        if config[field] is not False:
            raise RunnerError(f"unsafe configuration flag: {field}")
    executable = Path(config["codex_executable"])
    if not executable.is_absolute() or executable.name.lower() not in {"codex.cmd", "codex.exe"}:
        raise RunnerError("Codex executable must be an absolute codex.cmd or codex.exe path")
    if config["task_name"] != "ASTP-Autonomous-Development":
        raise RunnerError("unexpected scheduler task name")
    return config


def transition(path: Path, state: dict, status: str, *, reason: str | None = None) -> dict:
    if status not in TRANSITIONS[state["status"]]:
        raise RunnerError(f"illegal transition {state['status']} -> {status}")
    updated = {**state, "status": status, "updated_at": utc_now()}
    if reason is not None:
        updated["last_exit_reason"] = reason
    validate_state(updated)
    atomic_json(path, updated)
    return updated


def git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments], cwd=repo, text=True, capture_output=True, check=False, timeout=30
    )
    if completed.returncode:
        raise RunnerError(f"git command failed: {' '.join(arguments)}")
    return completed.stdout.strip()


def initialize(repo: Path, runtime: Path | None = None) -> dict:
    repo = repo.resolve()
    root = (runtime or repo / ".astp" / "autonomous-dev").resolve()
    if repo not in root.parents:
        raise RunnerError("runtime root must remain inside repository")
    state_path = root / "state.json"
    if state_path.exists():
        return load_state(state_path)
    root.mkdir(parents=True, exist_ok=True)
    (root / "logs").mkdir(exist_ok=True)
    head = git(repo, "rev-parse", "HEAD")
    state = {
        "schema_version": 1,
        "status": "READY",
        "milestone": "M0",
        "head": head,
        "attempt": 0,
        "started_at": None,
        "updated_at": utc_now(),
        "last_run_id": None,
        "last_validation": None,
        "last_exit_reason": "initialized",
        "resume_after": None,
        "push_allowed": False,
        "deploy_allowed": False,
        "real_target_network_allowed": False,
    }
    atomic_json(state_path, state)
    template = Path(__file__).parent / "templates"
    for name in ("ROADMAP.md", "NEXT_TASK.md", "LAST_RUN.md"):
        shutil.copyfile(template / name, root / name)
    append_history(root / "history.jsonl", "INITIALIZED", head=head, milestone="M0")
    return state


def _process_identity(pid: int) -> str | None:
    if pid <= 0:
        return None
    try:
        if os.name == "nt":
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"(Get-Process -Id {pid} -ErrorAction Stop).StartTime.ToUniversalTime().Ticks",
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            return result.stdout.strip() if result.returncode == 0 else None
        os.kill(pid, 0)
        return str(pid)
    except (OSError, subprocess.SubprocessError):
        return None


@dataclass
class RunnerLock:
    path: Path
    owner: dict | None = None

    def acquire(self, current_run_id: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        identity = _process_identity(os.getpid())
        owner = {
            "pid": os.getpid(),
            "process_identity": identity,
            "run_id": current_run_id,
            "acquired_at": utc_now(),
        }
        for _ in range(2):
            try:
                self.path.mkdir()
                atomic_json(self.path / "owner.json", owner)
                self.owner = owner
                return
            except FileExistsError:
                existing = self._read_owner()
                active_identity = (
                    _process_identity(int(existing.get("pid", -1))) if existing else None
                )
                if (
                    existing
                    and active_identity
                    and active_identity == existing.get("process_identity")
                ):
                    raise RunnerError("runner lock is held by an active process")
                stale = self.path.with_name(f"runner.lock.stale-{secrets.token_hex(4)}")
                try:
                    os.replace(self.path, stale)
                    shutil.rmtree(stale)
                except OSError as exc:
                    raise RunnerError("stale lock recovery race") from exc
        raise RunnerError("unable to acquire runner lock")

    def _read_owner(self) -> dict | None:
        try:
            return json.loads((self.path / "owner.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def release(self) -> None:
        if not self.owner:
            return
        current = self._read_owner()
        if current != self.owner:
            raise RunnerError("lock ownership changed")
        (self.path / "owner.json").unlink()
        self.path.rmdir()
        self.owner = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()


def parse_result(stdout: str, stderr: str, exit_code: int) -> str:
    # stdout is the result channel. Codex diagnostic stderr can contain an
    # echoed prompt/transcript with marker-shaped text and is never authoritative.
    markers = MARKER_RE.findall(stdout)
    if len(markers) == 1 and markers[0] in MARKERS:
        marker = markers[0]
        if exit_code == 0 or marker in {"USAGE_LIMIT", "HUMAN_GATE", "BLOCKED", "FAILED"}:
            return marker
    combined = stdout + "\n" + stderr
    if exit_code != 0 and any(pattern.search(combined) for pattern in USAGE_PATTERNS):
        return "USAGE_LIMIT"
    return "BLOCKED"


def build_prompt(repo: Path, runtime: Path, state: dict) -> str:
    return f"""You are continuing ASTP autonomous local engineering.

Authoritative durable sources, in order:
1. working tree and Git HEAD/history in {repo}
2. {runtime / 'state.json'}
3. {runtime / 'ROADMAP.md'}
4. {runtime / 'NEXT_TASK.md'}
5. {runtime / 'LAST_RUN.md'}
6. repository AGENTS.md, tests, and documentation

Do not assume conversational memory. Continue ONLY milestone {state['milestone']}.
Local source edits, tests, local containers, local fake-platform acceptance and coherent local commits are allowed.
Never push, deploy, tag, access a real bug-bounty target, expand scope, acquire credentials, or weaken policy, permit, lease, provenance, semantic-review, counting-proxy, or budget controls.
Never commit .astp runtime, credentials, field artifacts, OVERLAY.txt, or unrelated files.
Output exactly one final marker on its own line:
ASTP_AUTODEV_RESULT=MILESTONE_COMPLETE|CONTINUE|USAGE_LIMIT|HUMAN_GATE|BLOCKED|FAILED
"""


def build_codex_argv(
    command: Sequence[str], repo: Path, sandbox: str = "workspace-write"
) -> list[str]:
    if sandbox not in {"read-only", "workspace-write"}:
        raise RunnerError("unsafe Codex sandbox")
    return [
        *command,
        "--ask-for-approval",
        "never",
        "exec",
        "-",
        "-C",
        str(repo),
        "--sandbox",
        sandbox,
        "--ephemeral",
        "--color",
        "never",
    ]


def invoke_codex(
    command: Sequence[str], repo: Path, prompt: str, log_root: Path, timeout: int
) -> tuple[int, str, str]:
    stdout_path, stderr_path = log_root / "codex.stdout.log", log_root / "codex.stderr.log"
    argv = build_codex_argv(command, repo)
    try:
        completed = subprocess.run(
            argv,
            input=prompt,
            text=True,
            capture_output=True,
            cwd=repo,
            timeout=timeout,
            shell=False,
            check=False,
        )
        stdout, stderr, code = (
            redact(completed.stdout),
            redact(completed.stderr),
            completed.returncode,
        )
    except subprocess.TimeoutExpired as exc:
        stdout, stderr, code = (
            redact(exc.stdout or ""),
            redact((exc.stderr or "") + "\nCODEX_TIMEOUT"),
            124,
        )
    atomic_text(stdout_path, stdout)
    atomic_text(stderr_path, stderr)
    return code, stdout, stderr


def run_validation(repo: Path, command: Sequence[str], log_path: Path, timeout: int) -> bool:
    try:
        completed = subprocess.run(
            command,
            cwd=repo,
            text=True,
            capture_output=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
        output = redact(completed.stdout + "\n" + completed.stderr)
        atomic_text(log_path, output)
        return completed.returncode == 0
    except subprocess.TimeoutExpired:
        atomic_text(log_path, "VALIDATION_TIMEOUT\n")
        return False


def run_once(
    repo: Path,
    runtime: Path,
    codex_command: Sequence[str],
    validation_command: Sequence[str],
    *,
    codex_timeout: int = 3600,
    validation_timeout: int = 900,
    invoke: Callable = invoke_codex,
    validate: Callable = run_validation,
) -> dict:
    state_path, history = runtime / "state.json", runtime / "history.jsonl"
    state = load_state(state_path)
    if state["status"] in TERMINAL_NOOP:
        append_history(history, "NOOP_TERMINAL_STATE", status=state["status"])
        return state
    current_run = run_id()
    lock = RunnerLock(runtime / "runner.lock")
    lock.acquire(current_run)
    try:
        append_history(history, "LOCK_ACQUIRED", run_id=current_run)
        state = load_state(state_path)
        current_head = git(repo, "rev-parse", "HEAD")
        if current_head != state["head"]:
            state = transition(
                state_path, state, "BLOCKED", reason="unexpected Git HEAD divergence"
            )
            append_history(history, "BLOCKED", run_id=current_run, reason=state["last_exit_reason"])
            return state
        if state["status"] == "RUNNING":
            state = {
                **state,
                "status": "RECOVERING",
                "updated_at": utc_now(),
                "last_exit_reason": "orphaned RUNNING state",
            }
            atomic_json(state_path, state)
            append_history(history, "RECOVERING", run_id=current_run)
            state = transition(
                state_path, state, "READY", reason="orphaned run recovered without completion claim"
            )
        if state["status"] == "BLOCKED":
            return state
        if state["status"] not in {"READY", "WAITING_FOR_RESET"}:
            raise RunnerError(f"state cannot be invoked: {state['status']}")
        state = transition(state_path, state, "RUNNING")
        state.update(
            {
                "attempt": state["attempt"] + 1,
                "started_at": utc_now(),
                "last_run_id": current_run,
                "resume_after": None,
            }
        )
        atomic_json(state_path, state)
        log_root = runtime / "logs" / current_run
        log_root.mkdir(parents=True)
        append_history(history, "RUN_STARTED", run_id=current_run, head=current_head)
        append_history(history, "CODEX_STARTED", run_id=current_run)
        code, stdout, stderr = invoke(
            codex_command, repo, build_prompt(repo, runtime, state), log_root, codex_timeout
        )
        result = parse_result(stdout, stderr, code)
        append_history(history, "CODEX_FINISHED", run_id=current_run, exit_code=code, result=result)
        action = RESULT_ACTIONS[result]
        if action == "WAIT_FOR_RESET":
            state = transition(state_path, state, "WAITING_FOR_RESET", reason="Codex usage limit")
            state["resume_after"] = None
            atomic_json(state_path, state)
        elif action == "STOP_FOR_HUMAN":
            state = transition(state_path, state, "HUMAN_GATE", reason="human review required")
        elif action == "RESUME_SAME_MILESTONE":
            state = transition(state_path, state, "READY", reason="Codex requested next wake-up")
        elif action == "VALIDATE":
            state = transition(state_path, state, "VALIDATING")
            append_history(history, "VALIDATION_STARTED", run_id=current_run)
            passed = validate(
                repo, validation_command, log_root / "validation.log", validation_timeout
            )
            state["last_validation"] = {"passed": passed, "at": utc_now(), "run_id": current_run}
            atomic_json(state_path, state)
            if passed:
                state["head"] = git(repo, "rev-parse", "HEAD")
                atomic_json(state_path, state)
                append_history(history, "CHECKPOINT_SAVED", run_id=current_run, head=state["head"])
                completed_milestone = state["milestone"]
                if completed_milestone in AUTONOMOUS_MILESTONES:
                    number = int(completed_milestone[1:])
                    if number == 8:
                        state["milestone"] = "M9"
                        atomic_json(state_path, state)
                        state = transition(
                            state_path,
                            state,
                            "HUMAN_GATE",
                            reason="PRE_PUSH_REVIEW_REQUIRED",
                        )
                    else:
                        state["milestone"] = f"M{number + 1}"
                        atomic_json(state_path, state)
                        state = transition(
                            state_path,
                            state,
                            "READY",
                            reason=f"{completed_milestone} validated; next milestone ready",
                        )
                    append_history(
                        history,
                        "MILESTONE_COMPLETED",
                        run_id=current_run,
                        milestone=completed_milestone,
                        next_milestone=state["milestone"],
                    )
                else:
                    state = transition(
                        state_path,
                        state,
                        "COMPLETE",
                        reason="validated milestone complete",
                    )
                append_history(history, "VALIDATION_PASSED", run_id=current_run)
            else:
                state = transition(
                    state_path, state, "READY", reason="validation failed; repair next wake-up"
                )
                append_history(history, "VALIDATION_FAILED", run_id=current_run)
        else:
            state = transition(state_path, state, "BLOCKED", reason=f"Codex result {result}")
        atomic_text(
            runtime / "LAST_RUN.md",
            f"# Last run\n\n- Run: `{current_run}`\n- Result: `{result}`\n- Exit: `{code}`\n- Updated: `{utc_now()}`\n",
        )
        append_history(history, "RUN_FINISHED", run_id=current_run, status=state["status"])
        return state
    finally:
        lock.release()


def validate_environment(repo: Path, runtime: Path, config: dict) -> dict:
    executable = Path(config["codex_executable"])
    expected = Path(r"C:\Program Files\nodejs\codex.cmd")
    if executable.resolve() != expected.resolve() or not executable.is_file():
        raise RunnerError("independent Codex executable is unavailable or substituted")
    python = repo / ".venv" / "Scripts" / "python.exe"
    if not python.is_file():
        raise RunnerError("repository virtualenv Python is unavailable")
    head = git(repo, "rev-parse", "HEAD")
    runtime.mkdir(parents=True, exist_ok=True)
    probe = runtime / f"environment-probe-{secrets.token_hex(4)}.tmp"
    atomic_text(probe, "local-only\n")
    probe.unlink()
    lock = RunnerLock(runtime / "runner.lock")
    lock.acquire(run_id())
    lock.release()
    return {
        "status": "ENVIRONMENT_READY",
        "repo": str(repo),
        "head": head,
        "python": str(python),
        "codex": str(executable),
        "user": os.environ.get("USERNAME", "unknown"),
        "model_invoked": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="ASTP autonomous local-development runner")
    parser.add_argument("command", choices=("initialize", "status", "environment", "run"))
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--codex-timeout", type=int, default=3600)
    args = parser.parse_args()
    repo = args.repo.resolve()
    runtime = (args.runtime or repo / ".astp" / "autonomous-dev").resolve()
    config = load_config(Path(__file__).parent / "config.json")
    try:
        if args.command == "initialize":
            state = initialize(repo, runtime)
        elif args.command == "status":
            state = load_state(runtime / "state.json")
        elif args.command == "environment":
            state = validate_environment(repo, runtime, config)
        else:
            state = run_once(
                repo,
                runtime,
                [config["codex_executable"]],
                [
                    "powershell",
                    "-NoProfile",
                    "-File",
                    str(repo / "scripts" / "validate.ps1"),
                    "-CheckOnly",
                ],
                codex_timeout=max(60, min(args.codex_timeout, config["codex_timeout_seconds"])),
                validation_timeout=config["validation_timeout_seconds"],
            )
        print(json.dumps(state, ensure_ascii=False, indent=2))
        return 0 if state["status"] not in {"BLOCKED"} else 2
    except RunnerError as exc:
        print(f"ASTP autonomous runner blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
