"""Regression tests for bugs found and fixed during the audit rounds.

Each test locks in one specific bug fix so future commits can't silently
re-break it. Bug numbers reference the audit-round bug list.

Bugs covered:
    Bug 1  — Scanner._load_prior_ml_model re-applies baseline after load
    Bug 2  — _apply_ml_fast_filter falls back to reorder-only when threshold drops all
    Bug 3  — engine save/load round-trips baseline_status AND baseline_body
    Bug 4  — Config YAML loader uses utf-8 (Windows cp1252 safety)
    Bug 5  — OpenAPI spec loader uses utf-8 (Windows cp1252 safety)
    Bug 6  — gen_random_string honors maxLength constraint
    Bug 7  — db/load.py coalesces null payload/encoder/placeholder lists
    Bug 8  — bypass_predictor _PLACEHOLDER_MAP has unique values
    Bug 9  — Chrome _execute_fetch refetches page after session force_refresh
    Bug 10 — openapi/template.py handles null requestBody.content
    Bug 11 — RawRequest URL build preserves query strings and fragments
    Bug 12 — URLPath URL build preserves query strings and fragments
    Bug 13 — _solve_captcha_if_needed honors cfg.tls_verify
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ───────────────────────────── Bug 3 ─────────────────────────────

def test_bug3_engine_save_load_restores_baseline_body():
    """ml/engine.py: save() must persist baseline_body and load() must restore it.

    Before the fix, save() only stored baseline_status. After load() the
    baseline_body silently reverted to b"" — any feature extraction that
    compared against the baseline body would produce skewed numbers.
    """
    from gotestwaf.ml.engine import HybridMLEngine
    from gotestwaf.ml.model_store import load_ml_model, save_ml_model

    engine = HybridMLEngine()
    engine.set_baseline(418, b"i am a teapot baseline body")
    engine._is_trained = True  # mark eligible for save

    with tempfile.TemporaryDirectory() as td:
        model_dir = Path(td)
        path = save_ml_model("Test WAF Bug3", engine, model_dir=model_dir)
        assert path is not None and path.exists()

        loaded = HybridMLEngine()
        ok = load_ml_model("Test WAF Bug3", loaded, model_dir=model_dir)
        assert ok is True
        assert loaded._baseline_status == 418
        assert loaded._baseline_body == b"i am a teapot baseline body"


def test_bug3_load_missing_returns_false():
    from gotestwaf.ml.engine import HybridMLEngine
    from gotestwaf.ml.model_store import load_ml_model

    with tempfile.TemporaryDirectory() as td:
        engine = HybridMLEngine()
        ok = load_ml_model("nonexistent-waf-xyz", engine, model_dir=Path(td))
        assert ok is False


# ───────────────────────────── Bug 4 ─────────────────────────────

def test_bug4_config_yaml_loader_uses_utf8():
    """config/config.py: load_config_from_yaml must specify encoding='utf-8'.

    Without explicit encoding, Windows cp1252 default crashes on any non-ASCII
    content (URLs with IDN, non-English WAF names, etc.).
    """
    from gotestwaf.config.config import load_config_from_yaml

    yaml_content = (
        "url: https://例え.テスト/\n"
        "wafName: \"Müller-WAF\"\n"
        "comment: \"über encoding — café\"\n"
    )
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "config.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        data = load_config_from_yaml(str(path))
        assert data["url"] == "https://例え.テスト/"
        assert data["wafName"] == "Müller-WAF"
        assert "café" in data["comment"]


# ───────────────────────────── Bug 5 ─────────────────────────────

def test_bug5_openapi_loader_uses_utf8():
    """openapi/loader.py: load_openapi_spec must specify encoding='utf-8'.

    Real-world OpenAPI specs frequently contain non-ASCII descriptions
    and example values. Without encoding, Windows cp1252 default crashes.
    """
    from gotestwaf.openapi.loader import load_openapi_spec

    yaml_content = (
        "openapi: 3.0.0\n"
        "info:\n"
        "  title: Тест API\n"
        "  description: \"Café — über design\"\n"
        "  version: 1.0.0\n"
        "paths:\n"
        "  /users:\n"
        "    get:\n"
        "      summary: 用户列表\n"
        "      responses:\n"
        "        '200':\n"
        "          description: OK\n"
    )
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "spec.yaml"
        path.write_text(yaml_content, encoding="utf-8")
        doc = load_openapi_spec(str(path))
        assert doc["info"]["title"] == "Тест API"
        assert "Café" in doc["info"]["description"]


# ───────────────────────────── Bug 6 ─────────────────────────────

def test_bug6_gen_random_string_honors_max_length():
    """openapi/helpers.py: gen_random_string must NOT exceed max_length.

    Before the fix, the helper unconditionally bumped min_length to
    DEFAULT_STRING_SIZE (16), then widened max_length to match — silently
    producing 16-char strings even when the OpenAPI spec said max_length=5.
    """
    from gotestwaf.openapi.helpers import gen_random_string

    # Tight bounds (the regression case): max_length < DEFAULT_STRING_SIZE
    for _ in range(200):
        s = gen_random_string(2, 5)
        assert 2 <= len(s) <= 5, f"violated tight bounds: len={len(s)}"

    # Wide bounds: should still pad min up to DEFAULT_STRING_SIZE
    for _ in range(200):
        s = gen_random_string(2, 32)
        assert 16 <= len(s) <= 32, f"unexpected wide bound: len={len(s)}"

    # Exact length
    for _ in range(50):
        assert len(gen_random_string(4, 4)) == 4

    # Zero length
    assert gen_random_string(0, 0) == ""


# ───────────────────────────── Bug 7 ─────────────────────────────

def test_bug7_db_load_handles_null_payload_field(tmp_path):
    """db/load.py: must coalesce explicit YAML `null` to empty list.

    Before the fix, a test case YAML with `payload:` (no value) returned
    None from .get(), causing 'TypeError: NoneType is not iterable' in the
    scanner's payload loop and aborting the entire scan.
    """
    from gotestwaf.config.config import Config
    from gotestwaf.db.load import load_test_cases

    test_dir = tmp_path / "testcases" / "regression"
    test_dir.mkdir(parents=True)
    # Valid case to keep load_test_cases from raising "no tests selected"
    (test_dir / "valid.yml").write_text(
        "payload:\n  - 'good payload'\n"
        "encoder:\n  - Plain\n"
        "placeholder:\n  - URLParam\n"
        "type: test\n",
        encoding="utf-8",
    )
    # The regression case: explicit nulls
    (test_dir / "null_fields.yml").write_text(
        "payload:\n"
        "encoder:\n"
        "placeholder:\n"
        "type:\n",
        encoding="utf-8",
    )

    cfg = Config(test_cases_path=str(tmp_path / "testcases"))
    cases = load_test_cases(cfg)
    # Both files should load — null-fields case must come back as empty lists
    null_case = next(c for c in cases if c.name == "null_fields")
    assert null_case.payloads == []
    assert null_case.encoders == []
    assert null_case.placeholders == []
    assert null_case.type == "unknown"


# ───────────────────────────── Bug 8 ─────────────────────────────

def test_bug8_placeholder_map_has_unique_values():
    """ml/bypass_predictor.py: _PLACEHOLDER_MAP must have unique integer values.

    Before the fix, both HTMLMultipartForm and URLPath mapped to 8, so the
    feature vector couldn't distinguish them.
    """
    from gotestwaf.ml.bypass_predictor import _PLACEHOLDER_MAP

    values = list(_PLACEHOLDER_MAP.values())
    assert len(values) == len(set(values)), \
        f"Duplicate values in _PLACEHOLDER_MAP: {sorted(values)}"
    assert _PLACEHOLDER_MAP["HTMLMultipartForm"] != _PLACEHOLDER_MAP["URLPath"]


def test_bug8_features_placeholder_map_unique():
    """ml/features.py: PLACEHOLDER_MAP must also have unique values."""
    from gotestwaf.ml.features import PLACEHOLDER_MAP

    values = list(PLACEHOLDER_MAP.values())
    assert len(values) == len(set(values))


# ───────────────────────────── Bug 10 ─────────────────────────────

def test_bug10_openapi_template_handles_null_content():
    """openapi/template.py: requestBody.content=null must not crash.

    Before the fix, .get('content', {}) returned None when the YAML had
    `content:` with no value, then .items() raised AttributeError, killing
    OpenAPI fuzz mode entirely on slightly-malformed user specs.
    """
    from gotestwaf.openapi.template import _operation_template

    # null content directly under requestBody
    op_null_content = {"requestBody": {"content": None}}
    t = _operation_template({}, "", "/users", "POST", op_null_content)
    assert t is not None
    assert t.request_body == {}

    # null media_type entry inside content dict
    op_null_media = {"requestBody": {"content": {"application/json": None}}}
    t = _operation_template({}, "", "/users", "POST", op_null_media)
    assert t is not None

    # nested value-with-null-content (Postman-style)
    op_nested_null = {"requestBody": {"value": {"content": None}}}
    t = _operation_template({}, "", "/users", "POST", op_nested_null)
    assert t is not None


# ───────────────────────────── Bug 11 ─────────────────────────────

class TestBug11RawRequestUrlPreserved:
    """rawrequest.py: URL build must preserve query strings and fragments.

    Before the fix, naive string concat pushed the configured path INTO
    the query string for URLs like "https://target.com/api?token=secret".
    """

    @pytest.fixture
    def placeholder(self):
        from gotestwaf.payload.placeholder.rawrequest import RawRequestPlaceholder
        return RawRequestPlaceholder()

    @pytest.fixture
    def cfg(self):
        from gotestwaf.payload.placeholder.rawrequest import RawRequestConfig
        return RawRequestConfig(method="GET", path="/admin", headers={}, body="")

    def _make(self, ph, cfg, url):
        from gotestwaf.scanner.types.clients import HTTPClientType
        return ph.create_request(url, "PAYLOAD", cfg, HTTPClientType.GO_HTTP_CLIENT)

    def test_query_string_preserved(self, placeholder, cfg):
        req = self._make(placeholder, cfg, "https://target.com/api?token=secret&v=2")
        assert req.url == "https://target.com/api/admin?token=secret&v=2"

    def test_fragment_preserved(self, placeholder, cfg):
        req = self._make(placeholder, cfg, "https://target.com/path#section")
        assert req.url == "https://target.com/path/admin#section"

    def test_clean_url(self, placeholder, cfg):
        req = self._make(placeholder, cfg, "https://target.com/api")
        assert req.url == "https://target.com/api/admin"

    def test_trailing_slash(self, placeholder, cfg):
        req = self._make(placeholder, cfg, "https://target.com/api/")
        assert req.url == "https://target.com/api/admin"

    def test_bare_host(self, placeholder, cfg):
        req = self._make(placeholder, cfg, "https://target.com")
        assert req.url == "https://target.com/admin"


# ───────────────────────────── Bug 12 ─────────────────────────────

class TestBug12URLPathUrlPreserved:
    """urlpath.py: URL build must preserve query strings and fragments.

    Same family as Bug 11. Before the fix, payload ended up inside the
    query string for URLs containing query params.
    """

    @pytest.fixture
    def placeholder(self):
        from gotestwaf.payload.placeholder.urlpath import URLPathPlaceholder
        return URLPathPlaceholder()

    def _make(self, ph, url, payload="XSS"):
        from gotestwaf.scanner.types.clients import HTTPClientType
        return ph.create_request(url, payload, None, HTTPClientType.GO_HTTP_CLIENT)

    def test_query_string_preserved(self, placeholder):
        req = self._make(placeholder, "https://target.com/api?token=secret")
        assert req.url == "https://target.com/api/XSS?token=secret"

    def test_fragment_preserved(self, placeholder):
        req = self._make(placeholder, "https://target.com/path#section", "X")
        assert req.url == "https://target.com/path/X#section"

    def test_multi_param_query_preserved(self, placeholder):
        req = self._make(placeholder, "https://target.com/v1/users?limit=10&offset=0", "sqli")
        assert req.url == "https://target.com/v1/users/sqli?limit=10&offset=0"

    def test_clean_url(self, placeholder):
        req = self._make(placeholder, "https://target.com/api", "X")
        assert req.url == "https://target.com/api/X"

    def test_trailing_slash(self, placeholder):
        req = self._make(placeholder, "https://target.com/api/", "X")
        assert req.url == "https://target.com/api/X"

    def test_bare_host(self, placeholder):
        req = self._make(placeholder, "https://target.com", "X")
        assert req.url == "https://target.com/X"


# ───────────────────────────── Bug 1 ─────────────────────────────

class TestBug1LoadPriorMlModelRestoresBaseline:
    """Scanner._load_prior_ml_model: must re-apply current baseline after load.

    engine.load() overwrites the engine's internal baseline_status with the
    prior scan's value. The fix re-applies the CURRENT target's baseline so
    predictions stay consistent with this scan's target.
    """

    def _make_scanner(self, baseline_set: bool, baseline_status: int, baseline_body: bytes):
        """Build a Scanner with mocked ml_engine and set baseline state."""
        from gotestwaf.scanner.scanner import Scanner

        scanner = Scanner.__new__(Scanner)  # bypass __init__ — we only need the helper
        scanner._cfg = SimpleNamespace(waf_name="TestWAF")
        scanner.ml_engine = MagicMock()
        scanner._ml_baseline_set = baseline_set
        scanner._baseline_status = baseline_status
        scanner._baseline_body = baseline_body
        return scanner

    def test_load_success_reapplies_current_baseline(self):
        scanner = self._make_scanner(
            baseline_set=True, baseline_status=418, baseline_body=b"current target"
        )
        with patch("gotestwaf.ml.model_store.load_ml_model", return_value=True) as mock_load:
            ok = scanner._load_prior_ml_model()

        assert ok is True
        mock_load.assert_called_once()
        # The fix: set_baseline must be called AFTER load with CURRENT values
        scanner.ml_engine.set_baseline.assert_called_once_with(418, b"current target")

    def test_load_failure_does_not_reapply_baseline(self):
        scanner = self._make_scanner(
            baseline_set=True, baseline_status=200, baseline_body=b"x"
        )
        with patch("gotestwaf.ml.model_store.load_ml_model", return_value=False):
            ok = scanner._load_prior_ml_model()

        assert ok is False
        # No baseline restoration if no model was loaded
        scanner.ml_engine.set_baseline.assert_not_called()

    def test_baseline_not_set_yet_skips_reapply(self):
        scanner = self._make_scanner(
            baseline_set=False, baseline_status=0, baseline_body=b""
        )
        with patch("gotestwaf.ml.model_store.load_ml_model", return_value=True):
            ok = scanner._load_prior_ml_model()

        assert ok is True
        # If baseline isn't set yet (e.g., load runs before _set_ml_baseline),
        # don't re-apply garbage values
        scanner.ml_engine.set_baseline.assert_not_called()

    def test_load_exception_returns_false_silently(self):
        scanner = self._make_scanner(
            baseline_set=True, baseline_status=200, baseline_body=b"x"
        )
        with patch(
            "gotestwaf.ml.model_store.load_ml_model",
            side_effect=RuntimeError("disk error"),
        ):
            ok = scanner._load_prior_ml_model()
        assert ok is False  # Never raises — silent fallback


# ───────────────────────────── Bug 2 ─────────────────────────────

class TestBug2ApplyMlFastFilter:
    """_apply_ml_fast_filter: must fall back to reorder-only when threshold
    would drop every payload — otherwise the scan produces an empty report.
    """

    def test_no_threshold_just_reorders_by_score_desc(self):
        from gotestwaf.scanner.scanner import _apply_ml_fast_filter

        payloads = ["low", "high", "mid"]
        scores = [0.1, 0.9, 0.5]
        result, skipped = _apply_ml_fast_filter(payloads, scores, threshold=0.0)
        assert result == ["high", "mid", "low"]
        assert skipped == 0

    def test_threshold_drops_low_scoring_payloads(self):
        from gotestwaf.scanner.scanner import _apply_ml_fast_filter

        payloads = ["a", "b", "c", "d"]
        scores = [0.05, 0.5, 0.9, 0.02]
        result, skipped = _apply_ml_fast_filter(payloads, scores, threshold=0.1)
        assert result == ["c", "b"]  # sorted desc
        assert skipped == 2  # "a" and "d" dropped

    def test_threshold_dropping_all_falls_back_to_reorder(self):
        """The Bug 2 regression case: threshold > max(scores)."""
        from gotestwaf.scanner.scanner import _apply_ml_fast_filter

        payloads = ["a", "b", "c"]
        scores = [0.1, 0.2, 0.3]
        result, skipped = _apply_ml_fast_filter(payloads, scores, threshold=0.99)
        # MUST NOT return [] — would produce an empty scan
        assert len(result) == 3
        assert skipped == 0  # Fallback also resets the skip count
        assert set(result) == {"a", "b", "c"}
        # Still sorted by score desc
        assert result == ["c", "b", "a"]

    def test_empty_input(self):
        from gotestwaf.scanner.scanner import _apply_ml_fast_filter
        result, skipped = _apply_ml_fast_filter([], [], threshold=0.5)
        assert result == []
        assert skipped == 0

    def test_exact_threshold_match_kept(self):
        from gotestwaf.scanner.scanner import _apply_ml_fast_filter
        result, skipped = _apply_ml_fast_filter(["a"], [0.5], threshold=0.5)
        assert result == ["a"]  # >= comparison includes equal
        assert skipped == 0


# ───────────────────────────── Bug 9 ─────────────────────────────

class TestBug9ChromeStalePageRefetched:
    """chrome/client.py: after force_refresh in the consecutive-failures path,
    the page reference must be re-fetched. The session manager may have created
    a new browser page during force_refresh, making the captured `page` stale.
    """

    def _build_client(self, session_mgr):
        from gotestwaf.scanner.clients.chrome.client import Client

        client = Client.__new__(Client)
        client._headers = {}
        client._target_url = "https://target.example/"
        client._tls_verify = False
        client._session_mgr = session_mgr
        client._use_navigation = False
        client._page = None
        client._pw = None
        client._browser = None
        client._context = None
        client._fetch_lock = asyncio.Semaphore(3)
        client._consecutive_failures = 9  # one more failure triggers refresh
        client._standalone_init = False
        return client

    def test_refresh_refetches_page_and_uses_new_one(self):
        # Two distinct page objects with distinct evaluate side-effects
        stale_page = MagicMock(name="stale_page")
        stale_page.evaluate = AsyncMock(
            return_value={"status": 503, "body": "", "headers": {}}
        )
        fresh_page = MagicMock(name="fresh_page")
        fresh_page.evaluate = AsyncMock(
            return_value={"status": 200, "body": "ok", "headers": {}}
        )

        # Session manager returns stale_page first, then fresh_page after refresh
        session_mgr = MagicMock()
        session_mgr.get_page = MagicMock(side_effect=[stale_page, fresh_page])
        session_mgr.force_refresh = AsyncMock()

        client = self._build_client(session_mgr)

        result = asyncio.run(
            client._execute_fetch("https://target.example/x", "GET", {}, None)
        )

        # The fix in action: force_refresh was called, and the FRESH page
        # was the one used for the retry — not the stale one captured initially.
        session_mgr.force_refresh.assert_awaited_once()
        assert session_mgr.get_page.call_count == 2  # initial + post-refresh refetch
        fresh_page.evaluate.assert_awaited_once()
        # The retry result is what's returned, proving fresh_page was used
        assert result["status"] == 200

    def test_refresh_then_page_unavailable_returns_error(self):
        """Defensive: if get_page returns None after refresh, no crash."""
        stale_page = MagicMock(name="stale_page")
        stale_page.evaluate = AsyncMock(
            return_value={"status": 503, "body": "", "headers": {}}
        )
        session_mgr = MagicMock()
        session_mgr.get_page = MagicMock(side_effect=[stale_page, None])
        session_mgr.force_refresh = AsyncMock()

        client = self._build_client(session_mgr)
        result = asyncio.run(
            client._execute_fetch("https://target.example/x", "GET", {}, None)
        )
        assert result["status"] == 0
        assert "page unavailable" in result["error"].lower()


# ───────────────────────────── Bug 13 ─────────────────────────────

class TestBug13SolveCaptchaUsesTlsVerify:
    """Scanner._solve_captcha_if_needed: must pass cfg.tls_verify to httpx.

    Before the fix, the captcha-detection request used httpx.AsyncClient without
    a verify= flag, defaulting to verify=True regardless of user config. On a
    self-signed staging target with --tlsVerify=false, captcha detection
    silently failed with SSLError.
    """

    def _build_scanner(self, tls_verify: bool):
        from gotestwaf.scanner.scanner import Scanner
        scanner = Scanner.__new__(Scanner)
        scanner._cfg = SimpleNamespace(url="https://target.example/", tls_verify=tls_verify)
        return scanner

    def _run_with_captured_kwargs(self, scanner) -> dict:
        """Patch httpx.AsyncClient to capture init kwargs and short-circuit."""
        captured: dict = {}

        class FakeResponse:
            status_code = 200
            text = "totally normal page, no challenge here"
            headers: dict = {}

        class FakeClient:
            def __init__(self, *args, **kwargs):
                captured.update(kwargs)
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return False
            async def get(self, url):
                return FakeResponse()

        with patch("httpx.AsyncClient", FakeClient):
            asyncio.run(scanner._solve_captcha_if_needed(force=False))
        return captured

    def test_tls_verify_false_propagates(self):
        scanner = self._build_scanner(tls_verify=False)
        captured = self._run_with_captured_kwargs(scanner)
        assert "verify" in captured, "verify kwarg must be passed to httpx.AsyncClient"
        assert captured["verify"] is False

    def test_tls_verify_true_propagates(self):
        scanner = self._build_scanner(tls_verify=True)
        captured = self._run_with_captured_kwargs(scanner)
        assert captured["verify"] is True
