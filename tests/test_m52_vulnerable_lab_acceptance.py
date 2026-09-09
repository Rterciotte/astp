import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from astp.m52_acceptance_lab import LocalAcceptanceLab
from astp.m52_local_acceptance import run_m52_local_acceptance
from astp.oast import LocalFakeOastProvider, correlate_oast
from astp.proof_model import ProofStateV2


def test_m52_vulnerable_and_negative_lab_acceptance():
    with LocalAcceptanceLab() as lab:
        result = run_m52_local_acceptance(lab.base_url)
    assert result.passed
    assert result.requests == sum(item.requests for item in result.cases)
    assert {item.name for item in result.cases} >= {
        "reflected_xss",
        "dom_xss",
        "secret_exposure",
        "known_cve_fixture",
        "idor",
        "sql_injection",
        "open_redirect",
        "cors",
        "bounded_discovery",
    }


def test_local_auth_rotation_logout_and_negative_session_control():
    with LocalAcceptanceLab() as lab:
        login = Request(lab.base_url + "/login", method="POST", headers={"X-ASTP-Session": "fixed"})
        token = json.loads(urlopen(login, timeout=3).read())["session_ref"]
        assert token != "fixed"
        assert (
            urlopen(
                Request(lab.base_url + "/session", headers={"X-ASTP-Session": token}), timeout=3
            ).status
            == 200
        )
        urlopen(
            Request(lab.base_url + "/logout", method="POST", headers={"X-ASTP-Session": token}),
            timeout=3,
        )
        try:
            urlopen(
                Request(lab.base_url + "/session", headers={"X-ASTP-Session": token}), timeout=3
            )
        except HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("logged-out session remained valid")


def test_local_ssrf_oast_exact_end_to_end_correlation():
    provider = LocalFakeOastProvider()
    payload = provider.issue(
        program_id="lab", target="local", action_id="a", permit_id="p", detector_id="ssrf"
    )
    with LocalAcceptanceLab() as lab:
        urlopen(lab.base_url + "/ssrf?payload=" + payload.payload_id, timeout=3).read()
        assert payload.payload_id in lab.server.RequestHandlerClass.oast_callbacks
    callback = provider.record_callback(payload.payload_id, "http", source="local-lab")
    assert correlate_oast(payload, callback).state is ProofStateV2.CONFIRMED
