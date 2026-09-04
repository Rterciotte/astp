from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from astp.browser_intake import BrowserCapture
from astp.io import load_model
from astp.program_catalog import BugBountyWorkspace
from astp.program_server import (
    PROGRAM_INTAKE_PROTOCOL_VERSION,
    create_program_intake_server,
)

TOKEN = "test-intake-token"


def _listing_payload() -> dict[str, object]:
    return BrowserCapture(
        url="https://admin.bughunt.test/programs",
        title="Programs",
        text=(
            "Programas Timeline!\nMostrando 10 de 2 resultados.\n"
            "Grupo Smart Fit - Bug Bounty Público\nPublicado há 6 meses\n"
            "OLX Brasil Bug Bounty\nPublicado há 5 anos"
        ),
        links=[
            {
                "text": "Grupo Smart Fit - Bug Bounty Público",
                "href": "https://admin.bughunt.test/program/detail?smartfit",
                "context": "Grupo Smart Fit - Bug Bounty Público\nEscopo 5",
            },
            {
                "text": "OLX Brasil Bug Bounty",
                "href": "https://admin.bughunt.test/program/detail?olx",
                "context": "OLX Brasil Bug Bounty\nEscopo 13",
            },
        ],
    ).model_dump(mode="json")


def _detail_payload() -> dict[str, object]:
    return BrowserCapture(
        url="https://admin.bughunt.test/program/detail?smartfit",
        title="Grupo Smart Fit",
        text=(
            "Política do Programa\nPrograma Público\n"
            "EXCLUSÃO DE ENDPOINTS / ATIVOS\n"
            "https://universidade.smartfit.com.br/\n"
            "Escopo\nLista de escopo do programa!\n"
            "*.smartfit.com.br\nhttps://smartfit.com\n"
            "Recompensas\nRecompensas com valores financeiros"
        ),
    ).model_dump(mode="json")


@contextmanager
def _server(tmp_path: Path) -> Iterator[str]:
    server = create_program_intake_server(
        intake_token=TOKEN,
        platform="bughunt",
        latest_capture_path=tmp_path / ".astp" / "browser-capture.json",
        catalog_path=tmp_path / ".astp" / "program-catalog.yaml",
        captures_dir=tmp_path / ".astp" / "program-captures",
        programs_dir=tmp_path / "programs",
        port=0,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _post(
    base_url: str,
    path: str,
    payload: dict[str, object],
    *,
    token: str = TOKEN,
) -> tuple[int, dict[str, object]]:
    request = Request(
        f"{base_url}{path}",
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-ASTP-Intake-Token": token,
        },
    )
    try:
        with urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_health_endpoint_validates_token_and_protocol(tmp_path: Path) -> None:
    with _server(tmp_path) as base_url:
        status, body = _post(base_url, "/v1/health", {})
        assert status == 200
        assert body["ok"] is True
        assert body["protocol_version"] == PROGRAM_INTAKE_PROTOCOL_VERSION
        assert body["platform"] == "bughunt"

        status, body = _post(base_url, "/v1/health", {}, token="wrong")
        assert status == 403
        assert body == {"ok": False, "error": "invalid intake token"}


def test_unknown_endpoint_returns_json_404(tmp_path: Path) -> None:
    with _server(tmp_path) as base_url:
        status, body = _post(base_url, "/v1/does-not-exist", {})
    assert status == 404
    assert body == {"ok": False, "error": "unknown intake endpoint"}


def test_real_http_discovery_and_detail_sync_update_catalog(tmp_path: Path) -> None:
    catalog_path = tmp_path / ".astp" / "program-catalog.yaml"
    with _server(tmp_path) as base_url:
        status, discovery = _post(base_url, "/v1/discover-programs", _listing_payload())
        assert status == 200
        assert discovery["page_type"] == "program_listing"
        candidates = discovery["candidates"]
        assert isinstance(candidates, list)
        assert len(candidates) == 2

        candidate = candidates[0]
        status, detail = _post(
            base_url,
            "/v1/program-detail",
            {"candidate": candidate, "capture": _detail_payload()},
        )
        assert status == 200
        assert detail["ok"] is True
        assert detail["allowed_scope"] >= 2
        assert detail["denied_scope"] >= 1

    workspace = load_model(catalog_path, BugBountyWorkspace)
    assert len(workspace.programs) == 2
    synced = workspace.programs[0]
    assert synced.capture_path is not None
    assert synced.normalized_path is not None
    assert Path(synced.capture_path).exists()
    assert Path(synced.normalized_path).exists()


def test_repeated_discovery_and_sync_do_not_duplicate_program(tmp_path: Path) -> None:
    catalog_path = tmp_path / ".astp" / "program-catalog.yaml"
    with _server(tmp_path) as base_url:
        _, first = _post(base_url, "/v1/discover-programs", _listing_payload())
        candidate = first["candidates"][0]
        _post(
            base_url,
            "/v1/program-detail",
            {"candidate": candidate, "capture": _detail_payload()},
        )

        _, second = _post(base_url, "/v1/discover-programs", _listing_payload())
        candidate_again = second["candidates"][0]
        _post(
            base_url,
            "/v1/program-detail",
            {"candidate": candidate_again, "capture": _detail_payload()},
        )

    workspace = load_model(catalog_path, BugBountyWorkspace)
    detail_url = "https://admin.bughunt.test/program/detail?smartfit"
    assert sum(item.candidate.detail_url == detail_url for item in workspace.programs) == 1


def test_malformed_capture_returns_json_400(tmp_path: Path) -> None:
    with _server(tmp_path) as base_url:
        status, body = _post(
            base_url,
            "/v1/discover-programs",
            {"url": "not-http", "text": "broken"},
        )
    assert status == 400
    assert body["ok"] is False
    assert "browser capture URL" in str(body["error"])
