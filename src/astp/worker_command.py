from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from astp.worker_protocol import WorkerOperation, WorkerRequest, validate_worker_request


@dataclass(frozen=True)
class CompiledWorkerCommand:
    executable: str
    argv: tuple[str, ...]
    target: str
    network_operation: bool = True


def _host_from_target(target: str) -> str:
    parsed = urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname
    if host is None:
        raise ValueError("worker target must resolve to a hostname")
    return host


def _url_target(target: str) -> str:
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("HTTP tool target must be an absolute http(s) URL")
    return target


def compile_worker_command(request: WorkerRequest) -> CompiledWorkerCommand:
    blockers = validate_worker_request(request)
    if blockers:
        raise ValueError("; ".join(blockers))

    operation = request.operation
    if operation == WorkerOperation.NMAP_DISCOVERY:
        host = _host_from_target(request.target)
        mode = request.arguments[0] if request.arguments else "tcp-connect-bounded"
        if mode == "tcp-connect-bounded":
            argv = ("-sT", "-Pn", "--max-retries", "1", "--host-timeout", "30s", host)
        elif mode == "service-detection-bounded":
            argv = (
                "-sT",
                "-sV",
                "--version-light",
                "-Pn",
                "--max-retries",
                "1",
                "--host-timeout",
                "30s",
                host,
            )
        else:
            raise ValueError("unsupported bounded Nmap mode")
        return CompiledWorkerCommand(executable="nmap", argv=argv, target=host)

    if operation == WorkerOperation.NUCLEI_SAFE:
        target = _url_target(request.target)
        mode = request.arguments[0] if request.arguments else "info"
        severity = "info" if mode == "info" else "info,low"
        return CompiledWorkerCommand(
            executable="nuclei",
            argv=("-u", target, "-severity", severity, "-jsonl", "-silent"),
            target=target,
        )

    if operation == WorkerOperation.ZAP_BASELINE:
        target = _url_target(request.target)
        return CompiledWorkerCommand(
            executable="zap-baseline.py",
            argv=("-t", target, "-J", "/tmp/astp-zap-report.json", "-I"),
            target=target,
        )

    raise ValueError("browser operations are not subprocess tool commands")
