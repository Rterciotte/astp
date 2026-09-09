from __future__ import annotations

from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import BaseModel, Field

from astp.differential_access import IdentityObservation, compare_identity_observations
from astp.proof_model import ProofStateV2
from astp.secret_exposure import analyze_exposed_content


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object):
        return None


class AcceptanceCase(BaseModel):
    name: str
    detected: bool
    negative_control_passed: bool
    requests: int
    detail: str


class M52AcceptanceResult(BaseModel):
    cases: list[AcceptanceCase] = Field(default_factory=list)
    requests: int
    passed: bool


def _get(url: str, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    request = Request(url, headers=headers or {})
    try:
        response = build_opener(_NoRedirect).open(request, timeout=3)
    except HTTPError as exc:
        response = exc
    with response:
        return response.status, dict(response.headers), response.read()


def run_m52_local_acceptance(base_url: str) -> M52AcceptanceResult:
    cases = []
    requests = 0

    def add(name: str, detected: bool, negative: bool, count: int, detail: str) -> None:
        nonlocal requests
        requests += count
        cases.append(
            AcceptanceCase(
                name=name,
                detected=detected,
                negative_control_passed=negative,
                requests=count,
                detail=detail,
            )
        )

    _, _, reflected = _get(base_url + "/reflect?q=" + quote("<svg/onload=alert(1)>"))
    _, _, benign = _get(base_url + "/reflect?q=hello")
    add(
        "reflected_xss",
        b"<svg/onload" in reflected,
        b"<svg/onload" not in benign,
        2,
        "reflection candidate; browser proof still required",
    )
    _, _, dom = _get(base_url + "/dom")
    add("dom_xss", b"innerHTML=location.hash" in dom, True, 1, "dangerous source/sink candidate")
    _, _, secret = _get(base_url + "/secret")
    signals = analyze_exposed_content(secret, content_type="application/json")
    add(
        "secret_exposure",
        bool(signals),
        all(b"AKIAABCDEFGHIJKLMNOP" not in item.redacted_value.encode() for item in signals),
        1,
        "redacted static evidence",
    )
    status, headers, _ = _get(base_url + "/cve-fixture")
    add(
        "known_cve_fixture",
        {name.lower(): value for name, value in headers.items()}.get("x-astp-cve-fixture")
        == "CVE-2099-0001-vulnerable",
        status == 200,
        1,
        "deterministic lab template",
    )
    a_status, _, a_body = _get(base_url + "/idor/object/A", {"X-ASTP-Identity": "identity-a"})
    b_status, _, b_body = _get(base_url + "/idor/object/A", {"X-ASTP-Identity": "identity-b"})
    diff = compare_identity_observations(
        IdentityObservation(
            identity_ref="identity-a",
            status_code=a_status,
            body=a_body.decode(),
            expected_owner=True,
        ),
        IdentityObservation(
            identity_ref="identity-b",
            status_code=b_status,
            body=b_body.decode(),
            expected_owner=False,
        ),
    )
    secure_status, _, _ = _get(base_url + "/secure/object/A", {"X-ASTP-Identity": "identity-b"})
    add(
        "idor",
        diff.state is ProofStateV2.CONFIRMED,
        secure_status in {403, 404},
        3,
        "semantic owner/non-owner differential",
    )
    normal, _, _ = _get(base_url + "/sql?id=1")
    injected, _, _ = _get(base_url + "/sql?id=" + quote("1'"))
    add(
        "sql_injection",
        normal == 200 and injected == 500,
        normal == 200,
        2,
        "database error differential candidate",
    )
    redirect, headers, _ = _get(base_url + "/redirect?next=https://evil.test")
    add(
        "open_redirect",
        redirect == 302 and headers.get("Location") == "https://evil.test",
        True,
        1,
        "redirect observed without following",
    )
    _, cors_headers, _ = _get(base_url + "/cors", {"Origin": "https://attacker.test"})
    add(
        "cors",
        cors_headers.get("Access-Control-Allow-Origin") == "https://attacker.test"
        and cors_headers.get("Access-Control-Allow-Credentials") == "true",
        True,
        1,
        "controlled origin reflection",
    )
    hidden, _, _ = _get(base_url + "/.astp-hidden")
    missing, _, _ = _get(base_url + "/.not-present")
    add("bounded_discovery", hidden == 200, missing == 404, 2, "deterministic small wordlist")
    passed = all(item.detected and item.negative_control_passed for item in cases)
    return M52AcceptanceResult(cases=cases, requests=requests, passed=passed)
