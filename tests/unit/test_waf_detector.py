"""Unit tests for WAF detector checks and detectors."""

from __future__ import annotations

import pytest

from gotestwaf.scanner.waf_detector.detectors.checks import (
    Responses,
    and_checks,
    check_content,
    check_cookie,
    check_header,
    check_reason,
    check_status_code,
    or_checks,
)
from gotestwaf.scanner.waf_detector.detectors.detectors import get_detectors
from gotestwaf.scanner.types.response import ResponseMeta


def _make_resp(
    status: int = 200,
    reason: str = "OK",
    headers: dict[str, list[str]] | None = None,
    content: bytes = b"",
) -> ResponseMeta:
    return ResponseMeta(
        status_code=status,
        status_reason=reason,
        headers=headers or {},
        content=content,
    )


class TestCheckFunctions:
    def test_check_status_code_match(self) -> None:
        check = check_status_code(403, attack=True)
        resps = Responses(resp_to_attack=_make_resp(status=403))
        assert check(resps) is True

    def test_check_status_code_no_match(self) -> None:
        check = check_status_code(403, attack=True)
        resps = Responses(resp_to_attack=_make_resp(status=200))
        assert check(resps) is False

    def test_check_status_code_none_resp(self) -> None:
        check = check_status_code(403, attack=True)
        resps = Responses(resp_to_attack=None)
        assert check(resps) is False

    def test_check_header_match(self) -> None:
        check = check_header("Server", "AkamaiGHost", attack=False)
        resps = Responses(resp=_make_resp(headers={"Server": ["AkamaiGHost/1.0"]}))
        assert check(resps) is True

    def test_check_header_no_match(self) -> None:
        check = check_header("Server", "AkamaiGHost", attack=False)
        resps = Responses(resp=_make_resp(headers={"Server": ["nginx"]}))
        assert check(resps) is False

    def test_check_cookie(self) -> None:
        check = check_cookie("^incap_ses", attack=False)
        resps = Responses(resp=_make_resp(headers={"Set-Cookie": ["incap_ses_123=abc"]}))
        assert check(resps) is True

    def test_check_content_match(self) -> None:
        check = check_content("Access Denied", attack=True)
        resps = Responses(resp_to_attack=_make_resp(content=b"<h1>Access Denied</h1>"))
        assert check(resps) is True

    def test_check_content_no_match(self) -> None:
        check = check_content("Access Denied", attack=True)
        resps = Responses(resp_to_attack=_make_resp(content=b"<h1>Welcome</h1>"))
        assert check(resps) is False

    def test_check_content_empty_body(self) -> None:
        check = check_content("anything", attack=True)
        resps = Responses(resp_to_attack=_make_resp(content=b""))
        assert check(resps) is False

    def test_check_reason_match(self) -> None:
        check = check_reason("ModSecurity Action", attack=True)
        resps = Responses(resp_to_attack=_make_resp(reason="ModSecurity Action"))
        assert check(resps) is True

    def test_and_checks_all_true(self) -> None:
        c = and_checks(check_status_code(403, True), check_content("Denied", True))
        resps = Responses(resp_to_attack=_make_resp(status=403, content=b"Access Denied"))
        assert c(resps) is True

    def test_and_checks_one_false(self) -> None:
        c = and_checks(check_status_code(403, True), check_content("Welcome", True))
        resps = Responses(resp_to_attack=_make_resp(status=403, content=b"Access Denied"))
        assert c(resps) is False

    def test_or_checks_one_true(self) -> None:
        c = or_checks(check_status_code(403, True), check_status_code(503, True))
        resps = Responses(resp_to_attack=_make_resp(status=503))
        assert c(resps) is True

    def test_or_checks_none_true(self) -> None:
        c = or_checks(check_status_code(403, True), check_status_code(503, True))
        resps = Responses(resp_to_attack=_make_resp(status=200))
        assert c(resps) is False


class TestDetectorRegistry:
    def test_all_detectors_loaded(self) -> None:
        detectors = get_detectors()
        assert len(detectors) == 52

    def test_detector_names(self) -> None:
        detectors = get_detectors()
        names = [d.waf_name for d in detectors]
        assert "Kona SiteDefender" in names
        assert "Incapsula" in names
        assert "ModSecurity" in names

    def test_modsec_detection(self) -> None:
        detectors = get_detectors()
        modsec = next(d for d in detectors if d.waf_name == "ModSecurity")
        resps = Responses(
            resp=_make_resp(),
            resp_to_attack=_make_resp(status=403, reason="ModSecurity Action"),
        )
        assert modsec.is_waf(resps) is True

    def test_akamai_detection(self) -> None:
        detectors = get_detectors()
        akamai = next(d for d in detectors if d.waf_name == "Kona SiteDefender")
        resps = Responses(
            resp=_make_resp(headers={"Server": ["AkamaiGHost"]}),
            resp_to_attack=_make_resp(),
        )
        assert akamai.is_waf(resps) is True

    def test_no_waf_detected(self) -> None:
        detectors = get_detectors()
        resps = Responses(
            resp=_make_resp(headers={"Server": ["nginx/1.20"]}),
            resp_to_attack=_make_resp(status=200, content=b"OK"),
        )
        assert all(not d.is_waf(resps) for d in detectors)
