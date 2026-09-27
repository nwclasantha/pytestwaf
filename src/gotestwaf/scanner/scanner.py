"""Core scanning engine for GoTestWAF."""

from __future__ import annotations

import asyncio
import hashlib
import platform
import random
import re
import signal
import time
from typing import TYPE_CHECKING, Any

import structlog

from gotestwaf.db.models import Info, Placeholder
from gotestwaf.payload.encoder.encoder import apply_encoder
from gotestwaf.payload.payload import PayloadInfo
from gotestwaf.payload.placeholder.placeholder import get_placeholders
from gotestwaf.scanner.clients import GTW_DEBUG_HEADER
from gotestwaf.scanner.clients.gohttp.client import Client as GoHTTPClient
from gotestwaf.scanner.clients.graphql.client import Client as GraphQLClient
from gotestwaf.scanner.clients.grpc.client import Client as GRPCClient
from gotestwaf.scanner.types.clients import HTTPClientType
from gotestwaf.scanner.types.request import GoHTTPRequest
from gotestwaf.scanner.types.response import Response, ResponseMeta

if TYPE_CHECKING:
    from gotestwaf.config.config import Config
    from gotestwaf.db.database import DB
    from gotestwaf.openapi.template import Template, Templates

PRE_CHECK_VECTOR = "<script>alert('union select password from users')</script>"

JS_CHALLENGE_ERROR_MSGS = [
    "Enable JavaScript and cookies to continue",
]


def _apply_ml_fast_filter(
    payloads: list[Any],
    scores: list[float],
    threshold: float,
) -> tuple[list[Any], int]:
    """Reorder payloads by predicted bypass score; optionally drop low scores.

    If ``threshold > 0``, payloads scoring below it are dropped (returned as
    the ``skipped`` count). If the threshold would drop *every* payload, fall
    back to reorder-only — an empty scan would silently produce a useless
    report. Returns ``(reordered_payloads, skipped_count)``. Pure function;
    extracted for test isolation. Bugs 2 + 11/12 lock this in.
    """
    scored = list(zip(payloads, scores))
    skipped = 0
    if threshold > 0:
        kept = [(pc, s) for pc, s in scored if s >= threshold]
        skipped = len(scored) - len(kept)
        if not kept:
            # Safety net: dropping everything would produce an empty scan
            kept = scored
            skipped = 0
    else:
        kept = scored
    # Prioritize likely-bypass first → actionable findings appear early
    kept.sort(key=lambda t: -t[1])
    return [pc for pc, _ in kept], skipped


def _strip_dynamic_content(text: str) -> str:
    """Remove dynamic content and tokenize for stable comparison.

    Strips: timestamps, CSRF tokens, session IDs, nonces, UUIDs,
    random numbers, cache busters — anything that changes between requests.
    Also splits HTML tags into separate tokens for better comparison.
    """
    import re as _re
    # Remove script/style blocks (often has dynamic hashes)
    text = _re.sub(r'<script[^>]*>.*?</script>', ' ', text, flags=_re.S)
    text = _re.sub(r'<style[^>]*>.*?</style>', ' ', text, flags=_re.S)
    # Split HTML tags into separate tokens
    text = _re.sub(r'<', ' <', text)
    text = _re.sub(r'>', '> ', text)
    # Remove attribute values (often dynamic)
    text = _re.sub(r'="[^"]*"', ' ', text)
    text = _re.sub(r"='[^']*'", ' ', text)
    # UUIDs
    text = _re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', ' ', text)
    # Hex tokens (CSRF, nonces) — 12+ hex chars
    text = _re.sub(r'[0-9a-f]{12,}', ' ', text)
    # Timestamps
    text = _re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\d]*Z?', ' ', text)
    text = _re.sub(r'\d{10,13}', ' ', text)
    # Session/token values
    text = _re.sub(r'(session|token|csrf|nonce)[=:]\S+', ' ', text, flags=_re.I)
    # Numbers longer than 6 digits (likely IDs, not content)
    text = _re.sub(r'\b\d{7,}\b', ' ', text)
    # Remove common HTML structure tags (appear in ALL pages, not distinctive)
    text = _re.sub(r'</?(?:html|head|body|div|span|p|br|hr|meta|link|img|a|ul|ol|li|table|tr|td|th|form|input|button|label|select|option|textarea|nav|header|footer|section|article|aside|main)\b[^>]*>', ' ', text)
    # Collapse whitespace
    text = _re.sub(r'\s+', ' ', text).strip()
    return text

logger = structlog.get_logger()


class PayloadConfig:
    """Configuration for a single payload to be sent."""

    __slots__ = (
        "payload", "encoder", "placeholder", "set_name", "case_name",
        "test_type", "is_true_positive", "debug_header_value",
    )

    def __init__(
        self,
        payload: str,
        encoder: str,
        placeholder: Placeholder,
        set_name: str,
        case_name: str,
        test_type: str,
        is_true_positive: bool,
        debug_header_value: str,
    ) -> None:
        self.payload = payload
        self.encoder = encoder
        self.placeholder = placeholder
        self.set_name = set_name
        self.case_name = case_name
        self.test_type = test_type
        self.is_true_positive = is_true_positive
        self.debug_header_value = debug_header_value

    def to_info(self, resp: Response | None) -> Info:
        """Convert to a test Info record."""
        info = Info(
            set=self.set_name,
            case=self.case_name,
            payload=self.payload,
            encoder=self.encoder,
            placeholder=self.placeholder.name,
            type=self.test_type,
        )
        if resp is not None:
            info.response_status_code = resp.get_status_code()
        return info


class TestStatus:
    """Tracks test result status across multiple requests for the same payload."""

    __test__ = False  # Prevent pytest from trying to collect this as a test class
    __slots__ = ("passed_test", "blocked_test", "unresolved_test", "failed_test")

    def __init__(self) -> None:
        self.passed_test: Info | None = None
        self.blocked_test: Info | None = None
        self.unresolved_test: Info | None = None
        self.failed_test: Info | None = None


class Scanner:
    """Scans a WAF with various payloads to evaluate security."""

    def __init__(
        self,
        cfg: Config,
        db: DB,
        request_templates: Templates | None = None,
        router: Any = None,
        enable_debug_header: bool = False,
    ) -> None:
        self._cfg = cfg
        self._db = db
        self._enable_debug_header = enable_debug_header
        self._request_templates = request_templates
        self._router = router

        self._http_client: GoHTTPClient | None = None
        self._grpc_client: GRPCClient | None = None
        self._graphql_client: GraphQLClient | None = None

        # ML engines
        from gotestwaf.ml.engine import HybridMLEngine
        from gotestwaf.ml.online import OnlineMLEngine
        self.ml_engine = HybridMLEngine()  # Batch ML (trains after scan)
        self.online_ml = OnlineMLEngine()  # Real-time ML (runs during scan)
        from gotestwaf.ml.response_autoencoder import ResponseAutoencoder
        self.response_ae = ResponseAutoencoder()  # Autoencoder for response classification
        self._ml_baseline_set = False
        self._pretrained_ml_loaded: bool = False
        self._ml_fast_scores: dict[int, float] = {}
        self._baseline_status: int = 0
        self._baseline_is_captcha: bool = False
        self._baseline_body: bytes = b""
        self._baseline_stable_tokens: set[str] = set()
        self._cookie_refreshed: bool = False
        self._cookie_refresh_lock = asyncio.Lock()
        self._benign_also_blocked: bool = False
        self._benign_check_done: bool = False
        self._session_mgr = None
        self._bot_profile = None
        self._ua_rotator = None

        # Pre-compile regex patterns for block/pass detection (performance: avoid recompile per request)
        self._block_re: re.Pattern[str] | None = re.compile(cfg.block_regex) if cfg.block_regex else None
        self._block_re_bytes: re.Pattern[bytes] | None = re.compile(cfg.block_regex.encode()) if cfg.block_regex else None
        self._pass_re: re.Pattern[str] | None = re.compile(cfg.pass_regex) if cfg.pass_regex else None
        self._pass_re_bytes: re.Pattern[bytes] | None = re.compile(cfg.pass_regex.encode()) if cfg.pass_regex else None

    async def initialize(self) -> None:
        """Initialize all clients with bot protection detection and session management."""
        # Step 0: Detect bot protection type
        from gotestwaf.scanner.bot_detector import detect_bot_protection, BotProtectionType
        from gotestwaf.scanner.session_manager import SessionManager
        from gotestwaf.scanner.ua_rotation import UARotator

        self._bot_profile = await detect_bot_protection(self._cfg.url, self._cfg.tls_verify)
        logger.info("Bot protection detected",
                     type=self._bot_profile.protection_type.value,
                     name=self._bot_profile.name)

        self._ua_rotator = UARotator()

        # Step 1: Start session manager (solves challenge + background refresh)
        if self._bot_profile.protection_type != BotProtectionType.NONE:
            self._session_mgr = SessionManager(
                target_url=self._cfg.url,
                profile=self._bot_profile,
                user_agent=self._ua_rotator.get_current_user_agent(),
                tls_verify=self._cfg.tls_verify,
            )
            try:
                await self._session_mgr.start()
                logger.info("Session manager started",
                            challenge_solved=self._session_mgr.is_challenge_solved())
            except Exception as e:
                logger.warning("Session manager failed, falling back to direct client", error=str(e))
                self._session_mgr = None
        else:
            self._session_mgr = None
            logger.info("No bot protection — using direct httpx client (fast mode)")

        # Step 1b: Legacy captcha solve for httpx cookie extraction
        if self._session_mgr is None:
            await self._solve_captcha_if_needed()

        # Step 2: Create HTTP clients
        if self._cfg.http_client == "chrome" or (
            self._session_mgr and self._bot_profile.protection_type != BotProtectionType.NONE
        ):
            from gotestwaf.scanner.clients.chrome.client import Client as ChromeClient
            self._http_client = ChromeClient(self._cfg, session_mgr=self._session_mgr)
            self._cfg.http_client = "chrome"
        else:
            self._http_client = GoHTTPClient(self._cfg)

        self._grpc_client = GRPCClient(self._cfg)
        self._graphql_client = GraphQLClient(self._cfg)

        # Step 2: Capture ML baseline and verify CAPTCHA was solved
        await self._set_ml_baseline()

        # Step 3: If baseline looks like a CAPTCHA page, solve again
        if self._baseline_status in (202, 503) or self._baseline_is_captcha:
            logger.warning("Baseline is a CAPTCHA page — solving again")
            await self._solve_captcha_if_needed(force=True)
            # Only replace with GoHTTP if we weren't using Chrome
            if self._cfg.http_client != "chrome":
                self._http_client = GoHTTPClient(self._cfg)
            await self._set_ml_baseline()

        # Step 4: If baseline STILL isn't set or is still CAPTCHA, try once more
        if not self._ml_baseline_set or self._baseline_is_captcha:
            logger.warning("Baseline still not captured — final retry with delay")
            await asyncio.sleep(5)
            await self._solve_captcha_if_needed(force=True)
            if self._cfg.http_client != "chrome":
                self._http_client = GoHTTPClient(self._cfg)
            await self._set_ml_baseline()

        # Step 5: If baseline is STILL CAPTCHA after all retries,
        # the httpx client can't bypass bot protection. Switch to Chrome
        # client (Playwright) which runs a real browser and handles JS challenges.
        if self._baseline_is_captcha:
            if self._cfg.http_client != "chrome":
                logger.warning(
                    "httpx client cannot bypass bot protection (all responses are CAPTCHA). "
                    "Switching to Chrome client (Playwright) for payload delivery."
                )
                self._cfg.http_client = "chrome"
                try:
                    from gotestwaf.scanner.clients.chrome.client import Client as ChromeClient
                    self._http_client = ChromeClient(self._cfg)
                    # Re-capture baseline with Chrome client
                    await self._set_ml_baseline()
                    if not self._baseline_is_captcha:
                        logger.info("Chrome client bypassed bot protection — baseline captured successfully",
                                    status=self._baseline_status, body_size=len(self._baseline_body))
                    else:
                        logger.warning("Chrome client also getting CAPTCHA — results will be mostly unresolved")
                except Exception as chrome_err:
                    logger.warning("Chrome client init failed, continuing with httpx", error=str(chrome_err))

            # Disable ignore_unresolved so CAPTCHA responses don't get
            # falsely counted as bypasses
            if self._baseline_is_captcha and self._cfg.ignore_unresolved:
                logger.warning(
                    "Baseline is CAPTCHA — disabling --ignoreUnresolved to prevent false bypasses"
                )
                self._cfg.ignore_unresolved = False
                self._cfg.non_blocked_as_passed = False

        # Step 6: Check if benign traffic also gets blocked (bot protection detection)
        await self._check_benign_traffic()

    async def _check_benign_traffic(self) -> None:
        """Send benign requests to check if bot protection blocks everything.

        If benign traffic ALSO gets 403, then attack traffic getting 403
        doesn't prove WAF blocked it — it's just bot protection.
        Sets self._benign_also_blocked = True when benign gets same block status.
        """
        if self._benign_check_done or self._http_client is None:
            return
        self._benign_check_done = True

        try:
            from gotestwaf.helpers.url import get_target_url_str
            base_url = get_target_url_str(self._cfg.url)

            # Send 3 completely benign requests (no attack payload)
            # Use the BASE URL only (no payloads) — if this gets 200, WAF is selective
            benign_statuses = []
            for i in range(3):
                try:
                    req = GoHTTPRequest(method="GET", url=base_url)
                    resp = await self._http_client.send_request(req)
                    benign_statuses.append(resp.get_status_code())
                except Exception:
                    benign_statuses.append(-1)
                await asyncio.sleep(1)

            # If ALL benign requests get the same block status as baseline → bot protection
            baseline_is_block = self._baseline_status in (403, 406, 429, 503)
            # Check if all benign requests failed entirely
            all_failed = all(s == -1 for s in benign_statuses)
            if all_failed:
                logger.warning(
                    "Benign traffic check: all requests failed — "
                    "target may be unreachable; treating as bot protection",
                    benign_statuses=benign_statuses,
                )
                self._benign_also_blocked = True
                self._cfg.ignore_unresolved = False
                return

            if baseline_is_block:
                benign_blocked_count = sum(1 for s in benign_statuses
                                          if s == self._baseline_status)
                benign_passed_count = sum(1 for s in benign_statuses if s == 200)

                if benign_blocked_count >= 2 and benign_passed_count == 0:
                    # Bot protection blocks benign traffic via Chrome fetch().
                    # Switch to httpx with session cookies — the Go version approach.
                    # httpx sends raw HTTP requests that the WAF inspects directly
                    # (unlike browser navigation which solves challenges and bypasses WAF).
                    logger.warning(
                        "Bot protection blocks Chrome fetch — switching to httpx with session cookies. "
                        "WAF will inspect raw HTTP requests with attack payloads.",
                        benign_statuses=benign_statuses,
                        baseline_status=self._baseline_status,
                    )
                    # Switch to httpx client (cookies already in session_cookies.json)
                    # KEEP the Chrome baseline (403 block page) — don't re-capture
                    # because httpx will get 202 CAPTCHA for baseline requests
                    old_client = self._http_client
                    self._http_client = GoHTTPClient(self._cfg)
                    self._cfg.http_client = "gohttp"
                    if hasattr(old_client, 'close'):
                        try:
                            await old_client.close()
                        except Exception:
                            pass
                    # Keep existing Chrome baseline — it's already good (403 block page)
                    # Check if httpx can actually get past bot protection
                    # by sending one benign request with httpx
                    try:
                        from gotestwaf.helpers.url import get_target_url_str
                        test_url = get_target_url_str(self._cfg.url)
                        test_req = GoHTTPRequest(method="GET", url=test_url)
                        test_resp = await self._http_client.send_request(test_req)
                        httpx_status = test_resp.get_status_code()
                        if httpx_status == 200:
                            # httpx gets 200 for benign → WAF mode (can distinguish blocks)
                            self._benign_also_blocked = False
                            logger.info("httpx gets 200 for benign traffic — WAF mode active")
                        elif httpx_status in (403, 406, 429, 503):
                            # httpx also gets blocked → bot protection still active
                            self._benign_also_blocked = True
                            logger.warning("httpx also gets 403 — bot protection blocks httpx too")
                        else:
                            # 202 or other — CAPTCHA
                            self._benign_also_blocked = True
                            logger.warning(f"httpx gets {httpx_status} — bot protection active")
                    except Exception:
                        self._benign_also_blocked = True
                    logger.info("Switched to httpx client (keeping Chrome baseline)",
                                baseline_status=self._baseline_status,
                                baseline_size=len(self._baseline_body))
                elif benign_passed_count >= 1:
                    logger.info(
                        "WAF confirmed: benign traffic passes (200) while baseline is blocked. "
                        "WAF is selectively blocking attacks.",
                        benign_statuses=benign_statuses,
                    )
                    self._benign_also_blocked = False
        except Exception as e:
            logger.debug("Benign traffic check failed", error=str(e))

    async def _set_ml_baseline(self) -> None:
        """Capture MULTIPLE baseline responses and build a stable baseline fingerprint.

        Multi-baseline approach:
        1. Send 3 identical requests to the same URL
        2. Strip dynamic content (timestamps, tokens, session IDs)
        3. Keep only the STABLE tokens that appear in ALL responses
        4. This stable baseline eliminates false positives from dynamic content
        """
        self._baseline_status = 0
        self._baseline_is_captcha = False
        self._baseline_body = b""
        self._baseline_stable_tokens: set[str] = set()

        if self._http_client is None:
            return
        try:
            from gotestwaf.helpers.url import get_target_url_str
            reduced_url = get_target_url_str(self._cfg.url)

            # Send 3 requests to capture stable vs dynamic content
            bodies: list[bytes] = []
            statuses: list[int] = []
            resp = None
            for i in range(3):
                req = GoHTTPRequest(method="GET", url=reduced_url)
                resp = await self._http_client.send_request(req)
                bodies.append(resp.get_content())
                statuses.append(resp.get_status_code())
                if i < 2:
                    await asyncio.sleep(0.5)  # Brief pause between requests

            status = statuses[0]
            body = bodies[0]
            body_text = body[:1000].decode("utf-8", errors="replace").lower()

            self._baseline_status = status
            self._baseline_is_captcha = (
                status == 202
                or "captcha" in body_text
                or "sgcaptcha" in body_text
                or "robot challenge" in body_text
                or "verify you are human" in body_text
                or "checking your browser" in body_text
                or "just a moment" in body_text
            )

            # Build stable token set — tokens that appear in ALL 3 responses
            token_sets: list[set[str]] = []
            for b in bodies:
                text = b[:5000].decode("utf-8", errors="replace").lower()
                # Strip dynamic content before tokenizing
                text = _strip_dynamic_content(text)
                tokens = set(text.split())
                token_sets.append(tokens)

            if token_sets:
                # Stable tokens = intersection of all 3 responses
                self._baseline_stable_tokens = token_sets[0]
                for ts in token_sets[1:]:
                    self._baseline_stable_tokens &= ts

            self._baseline_body = body
            self.ml_engine.set_baseline(status, body)
            if resp is not None:
                self.online_ml.set_baseline(status, resp.get_headers(), body)

            # Train response autoencoder on baseline responses, but only when
            # the baseline isn't a CAPTCHA / challenge page. initialize() may
            # call _set_ml_baseline up to four times while solving challenges;
            # training the autoencoder on the intermediate CAPTCHA baselines
            # would teach it to treat challenge pages as "normal" and corrupt
            # every subsequent classification. Skipping the train on CAPTCHA
            # baselines lets the final, real baseline produce a clean model.
            if not self._baseline_is_captcha:
                try:
                    baseline_features = []
                    for b in bodies:
                        feat = self.response_ae.extract_response_features(status, b, body)
                        baseline_features.append(feat)
                    ae_metrics = self.response_ae.train_on_baselines(baseline_features, epochs=100)
                    logger.info("Response autoencoder trained", **{k: v for k, v in ae_metrics.items() if k != "status"})
                except Exception as ae_err:
                    logger.debug("Autoencoder training skipped", error=str(ae_err))

            self._ml_baseline_set = True

            logger.info("ML baseline captured",
                        status=status, body_size=len(body),
                        stable_tokens=len(self._baseline_stable_tokens),
                        is_captcha=self._baseline_is_captcha)
        except Exception as e:
            logger.warning("ML baseline capture failed, retrying with single request", error=str(e))
            # Fallback: try a single request to at least get SOMETHING for baseline
            try:
                from gotestwaf.helpers.url import get_target_url_str
                reduced_url = get_target_url_str(self._cfg.url)
                await asyncio.sleep(2)
                req = GoHTTPRequest(method="GET", url=reduced_url)
                resp = await self._http_client.send_request(req)
                body = resp.get_content()
                status = resp.get_status_code()
                self._baseline_status = status
                self._baseline_body = body
                self._baseline_is_captcha = status == 202
                body_text = body[:5000].decode("utf-8", errors="replace").lower()
                text = _strip_dynamic_content(body_text)
                self._baseline_stable_tokens = set(text.split())
                self._ml_baseline_set = True
                self.ml_engine.set_baseline(status, body)
                self.online_ml.set_baseline(status, resp.get_headers(), body)
                logger.info("ML baseline captured (fallback)",
                            status=status, body_size=len(body),
                            stable_tokens=len(self._baseline_stable_tokens))
            except Exception as e2:
                logger.warning("ML baseline fallback also failed", error=str(e2))
                # Last resort: set a synthetic 403 baseline so Jaccard comparison
                # can at least run and classify identical responses as unresolved
                self._baseline_status = 403
                self._baseline_body = b"403 Forbidden"
                self._baseline_stable_tokens = {"403", "forbidden"}
                self._ml_baseline_set = True
                logger.info("ML baseline set to synthetic 403 default")

    async def _solve_captcha_if_needed(self, force: bool = False) -> None:
        """Check if target has CAPTCHA and solve it automatically.

        Args:
            force: If True, skip detection check and always try to solve.
        """
        import httpx

        if not force:
            # Quick check with longer timeout and retry
            has_captcha = False
            for attempt in range(2):
                try:
                    async with httpx.AsyncClient(
                        timeout=20,
                        follow_redirects=True,
                        verify=self._cfg.tls_verify,
                    ) as client:
                        resp = await client.get(self._cfg.url)
                        has_captcha = (
                            resp.headers.get("sg-captcha") == "challenge"
                            or resp.status_code == 202
                            or "captcha" in resp.text[:1000].lower()
                            or "sgcaptcha" in resp.text[:1000].lower()
                            or "just a moment" in resp.text[:1000].lower()
                            or "checking your browser" in resp.text[:1000].lower()
                            or "verify you are human" in resp.text[:1000].lower()
                        )
                        if has_captcha:
                            break
                except Exception as e:
                    logger.warning("CAPTCHA detection attempt failed", attempt=attempt + 1, error=str(e))
                    if attempt == 0:
                        import asyncio
                        await asyncio.sleep(2)
                    continue

            if not has_captcha:
                return

        logger.info("Bot protection detected, solving automatically")

        from gotestwaf.scanner.captcha_solver import solve_captcha
        import json
        from pathlib import Path

        cookies = await solve_captcha(self._cfg.url)
        if cookies:
            import tempfile, os
            cookie_list = [{"name": k, "value": v} for k, v in cookies.items()]
            cookie_path = Path("session_cookies.json")
            cookie_path.write_text(
                json.dumps(cookie_list, indent=2), encoding="utf-8"
            )
            try:
                os.chmod(str(cookie_path), 0o600)
            except OSError:
                pass
            logger.info("Session cookies saved for CAPTCHA bypass", count=len(cookies))
        else:
            logger.warning("CAPTCHA solving returned no cookies")

    async def check_if_javascript_required(self) -> bool:
        """Check if JavaScript is required to interact with the endpoint."""
        from gotestwaf.helpers.url import get_target_url_str

        reduced_url = get_target_url_str(self._cfg.url)

        # Reuse the scanner's existing HTTP client so session cookies, auth
        # headers, and CAPTCHA-solved state are carried through. A fresh
        # client would land on the login/challenge page and falsely report
        # that JS is required, aborting the scan.
        req = GoHTTPRequest(method="GET", url=reduced_url)
        resp = await self._http_client.send_request(req)

        body = resp.get_content().decode("utf-8", errors="replace")
        return any(msg in body for msg in JS_CHALLENGE_ERROR_MSGS)

    async def check_grpc_availability(self) -> None:
        """Check gRPC endpoint availability."""
        logger.info("gRPC pre-check", status="started")

        if self._grpc_client is None:
            return

        try:
            available = await self._grpc_client.check_availability()
        except Exception as e:
            logger.info("gRPC pre-check", status="done", connection="not available", error=str(e))
            available = False

        connection = "available" if available else "not available"
        logger.info("gRPC pre-check", status="done", connection=connection)
        self._db.is_grpc_available = available

    async def check_graphql_availability(self) -> None:
        """Check GraphQL endpoint availability."""
        logger.info("GraphQL pre-check", status="started")

        if self._graphql_client is None:
            return

        try:
            available = await self._graphql_client.check_availability()
        except Exception as e:
            logger.info("GraphQL pre-check", status="done", connection="not available", error=str(e))
            available = False

        connection = "available" if available else "not available"
        logger.info("GraphQL pre-check", status="done", connection=connection)
        self._db.is_graphql_available = available

    async def waf_block_check(self) -> None:
        """Check if WAF exists and blocks malicious requests.

        Handles BlockConnReset: if connection is reset and BlockConnReset is
        enabled, sends a benign request to verify service availability.

        Raises:
            RuntimeError: If WAF is not detected.
        """
        logger.info("WAF pre-check", url=self._cfg.url)

        try:
            blocked, http_status = await self._pre_check(PRE_CHECK_VECTOR)
        except (ConnectionResetError, ConnectionError, ConnectionAbortedError) as e:
            if self._cfg.block_conn_reset:
                logger.info("Connection reset, trying benign request to make sure that service is available")

                try:
                    blocked_benign, http_status_benign = await self._pre_check("")
                except Exception as benign_err:
                    msg = f"running benign request pre-check: {benign_err}"
                    raise RuntimeError(msg) from benign_err

                if not blocked_benign:
                    logger.info(
                        f"Service is available (HTTP status: {http_status_benign}), "
                        "WAF resets connections. Consider this behavior as block"
                    )
                    blocked = True
                    http_status = http_status_benign
                else:
                    msg = (
                        f"Service is not available (benign request also blocked with HTTP {http_status_benign}). "
                        "The service may be down or blocking all traffic."
                    )
                    raise RuntimeError(msg)
            else:
                msg = f"running WAF pre-check: {e}"
                raise RuntimeError(msg) from e

        if not blocked:
            msg = (
                f"WAF was not detected. "
                f"Please use the '--blockStatusCodes' or '--blockRegex' flags. "
                f"Use '--help' for additional info. "
                f"Baseline attack status code: {http_status}"
            )
            raise RuntimeError(msg)

        logger.info("WAF pre-check", status="done", blocked=True, code=http_status)

    async def _pre_check(self, payload: str) -> tuple[bool, int]:
        """Send a pre-check payload.

        Returns:
            Tuple of (is_blocked, status_code).
        """
        pl = PayloadInfo(
            payload=payload,
            encoder_name="URL",
            placeholder_name="URLParam",
        )

        if self._http_client is None:
            msg = "HTTP client not initialized"
            raise RuntimeError(msg)

        resp = await self._http_client.send_payload(self._cfg.url, pl)
        blocked, _ = self._check_blocked_or_passed(resp)
        return blocked, resp.get_status_code()

    def _check_blocked_or_passed(self, resp: Response) -> tuple[bool, bool]:
        """Determine if a response indicates blocked or passed.

        Returns:
            Tuple of (blocked, passed).
        """
        if self._cfg.check_block_func is not None:
            from gotestwaf.scanner.waf_detector.detectors.checks import Responses
            if self._cfg.check_block_func(Responses(resp_to_attack=resp)):
                # WAF-detector check fired. But many WAF detectors use loose
                # content patterns (e.g. Azure FD's `ref.*#[0-9a-f]+` matches
                # generic <a href="#hash"> in any HTML page). When the response
                # is essentially the baseline page (same status, same body),
                # the WAF did NOT actually block — the pattern just happened
                # to also exist in normal content. Defer to the
                # baseline-aware Jaccard rules below in that case.
                resp_status = resp.get_status_code()
                bl_status = getattr(self, "_baseline_status", None)
                resp_body = resp.get_content() or b""
                bl_body = getattr(self, "_baseline_body", b"") or b""
                same_status = bl_status is not None and resp_status == bl_status
                similar_size = (
                    len(bl_body) > 0
                    and 0.5 < (len(resp_body) / max(len(bl_body), 1)) < 2.0
                )
                if not (same_status and similar_size and self._ml_baseline_set):
                    return True, False

        blocked = False
        passed = False

        headers_list: list[str] = []
        for header, values in resp.get_headers().items():
            for v in values:
                headers_list.append(f"{header}: {v}")

        body = resp.get_content()
        status_code = resp.get_status_code()

        # Use pre-compiled regex patterns for block/pass detection
        if self._block_re is not None:
            for header in headers_list:
                if self._block_re.search(header):
                    blocked = True
            if not blocked and body and self._block_re_bytes is not None:
                if self._block_re_bytes.search(body):
                    blocked = True

        if self._pass_re is not None:
            for header in headers_list:
                if self._pass_re.search(header):
                    passed = True
            if not passed and body and self._pass_re_bytes is not None:
                if self._pass_re_bytes.search(body):
                    passed = True

        if status_code in self._cfg.block_status_codes:
            blocked = True

        if status_code in self._cfg.pass_status_codes:
            passed = True

        # ── HIGH-PRECISION CLASSIFICATION (target: 99.9% precision) ──
        # Uses multi-baseline stable tokens + dynamic content stripping
        # to eliminate false positives from dynamic content (CSRF, timestamps, etc.)
        #
        # CRITICAL FIX: When baseline is itself a block page (e.g. Cloudflare 403),
        # responses identical to baseline must be "unresolved" not "blocked" —
        # we can't tell if the WAF acted on the payload or just returned the
        # same generic bot-block page.
        # Early checks — run BEFORE token comparison
        if self._ml_baseline_set:
            # 202 is ALWAYS a CAPTCHA/challenge page — never a bypass or block
            if status_code == 202:
                return False, False  # unresolved

            # CAPTCHA keyword check in response body
            if body:
                body_text_early = body[:2000].decode("utf-8", errors="replace").lower()
                captcha_kws_early = ("captcha", "sgcaptcha",
                                    "verify you are human", "checking your browser",
                                    "just a moment", "bot protection")
                captcha_hit = sum(1 for kw in captcha_kws_early if kw in body_text_early) >= 1
                if captcha_hit:
                    return False, False  # unresolved

            # STATUS CODE classification with bot-protection awareness.
            baseline_status = getattr(self, '_baseline_status', 0)

            if self._benign_also_blocked:
                # BOT PROTECTION MODE: benign traffic also gets 403.
                if status_code == baseline_status:
                    return False, False  # unresolved
                elif status_code == 200:
                    return False, True  # bypassed
            else:
                # WAF MODE — DON'T return early.
                # Let Jaccard body comparison run to distinguish
                # WAF-specific blocks from generic blocks.
                # Only set flags, don't return.
                if not blocked and not passed:
                    if status_code in (403, 406, 429, 503):
                        blocked = True
                    elif status_code == 200 and baseline_status in (202, 403, 406, 429, 503):
                        passed = True
                # Fall through to Jaccard/ML layers for body analysis

        if body and self._ml_baseline_set and hasattr(self, '_baseline_body'):
            try:
                baseline_body = self._baseline_body
                stable_tokens = getattr(self, '_baseline_stable_tokens', set())
                baseline_status = getattr(self, '_baseline_status', 200)

                if baseline_body and len(body) > 0 and len(baseline_body) > 0:
                    # Strip dynamic content BEFORE comparison
                    body_text = body[:5000].decode("utf-8", errors="replace").lower()
                    body_stripped = _strip_dynamic_content(body_text)
                    body_tokens = set(body_stripped.split())

                    # Use STABLE baseline tokens (intersection of 3 baseline requests)
                    compare_tokens = stable_tokens if stable_tokens else set(
                        _strip_dynamic_content(baseline_body[:5000].decode("utf-8", errors="replace").lower()).split()
                    )

                    # FAST PATH: When tokens are empty (Chrome client HTML stripped
                    # away or baseline body empty), use status code comparison.
                    if not body_tokens or not compare_tokens:
                        baseline_is_block_status = baseline_status in (403, 406, 429, 503)
                        if baseline_is_block_status and status_code == baseline_status:
                            # Same block status = WAF blocked it (same as baseline)
                            blocked = True
                            passed = False
                        elif baseline_is_block_status and status_code == 200:
                            # Got 200 when baseline was block page = genuine bypass
                            passed = True
                            blocked = False
                        elif not baseline_is_block_status and status_code in (403, 406, 429, 503):
                            # Normal baseline, got block status = WAF blocked it
                            blocked = True
                            passed = False
                        elif not baseline_is_block_status and status_code == 200:
                            # Normal baseline, got 200 = passed through (needs token check for accuracy)
                            pass  # Let token-based rules handle it

                    if body_tokens and compare_tokens:
                        # How many stable baseline tokens appear in this response?
                        matched = len(body_tokens & compare_tokens)
                        coverage = matched / len(compare_tokens) if compare_tokens else 0.0

                        # Body size ratio
                        size_ratio = len(body) / max(len(baseline_body), 1)

                        # Jaccard similarity for body comparison
                        union = len(body_tokens | compare_tokens)
                        jaccard = matched / union if union > 0 else 0.0

                        # WAF keyword check (always compute).
                        # Split into "strong" phrases (high precision — rarely
                        # appear in benign content) and "soft" single words
                        # (common in normal text — "security", "forbidden",
                        # "blocked" all appear regularly in marketing copy,
                        # privacy policies, navigation, etc.).
                        waf_strong_phrases = (
                            "access denied", "request rejected", "request blocked",
                            "web application firewall", "security violation",
                            "error 1020", "attention required", "ray id",
                            "you have been blocked", "not acceptable",
                            "incapsula", "modsecurity", "cloudflare ray",
                        )
                        waf_soft_words = (
                            "blocked", "denied", "forbidden", "rejected",
                            "firewall", "violation",
                        )
                        strong_hits = sum(1 for kw in waf_strong_phrases if kw in body_text)
                        soft_hits = sum(1 for kw in waf_soft_words if kw in body_text)

                        # Compare to baseline — what matters is NEW keywords in
                        # the response, not absolute count. A benign page that
                        # already contains "forbidden" in body copy will echo
                        # it on every response; only NEW WAF-block signals
                        # indicate the WAF acted.
                        baseline_text = baseline_body[:5000].decode("utf-8", errors="replace").lower()
                        baseline_strong = sum(1 for kw in waf_strong_phrases if kw in baseline_text)
                        baseline_soft = sum(1 for kw in waf_soft_words if kw in baseline_text)
                        strong_delta = max(0, strong_hits - baseline_strong)
                        soft_delta = max(0, soft_hits - baseline_soft)

                        # Composite waf_score: 1 strong-phrase delta = block,
                        # OR 3 soft-word deltas. waf_score is kept as
                        # 0/1 binary — downstream rules use `>= 1`.
                        waf_score = 1 if (strong_delta >= 1 or soft_delta >= 3) else 0
                        baseline_waf_score = baseline_strong + baseline_soft  # legacy var, used below

                        baseline_is_block = (
                            baseline_status in (403, 406, 429, 503)
                            and (baseline_strong >= 1 or baseline_soft >= 2)
                        )
                        # CAPTCHA/bot protection keywords (specific, not broad)
                        captcha_keywords = ("captcha", "sgcaptcha",
                                          "verify you are human", "checking your browser",
                                          "just a moment", "bot protection")
                        baseline_captcha_score = sum(1 for kw in captcha_keywords if kw in baseline_text)
                        baseline_is_captcha = getattr(self, '_baseline_is_captcha', False) or (
                            baseline_status == 202 or baseline_captcha_score >= 1
                        )
                        # Baseline is "non-normal" if it's a block page OR captcha
                        baseline_is_abnormal = baseline_is_block or baseline_is_captcha

                        # RULE 0: If baseline is abnormal (block page or CAPTCHA)
                        # AND this response is very similar (>60% Jaccard),
                        # it's the SAME page. Mark UNRESOLVED.
                        if baseline_is_abnormal and jaccard > 0.6 and status_code == baseline_status:
                            blocked = False
                            passed = False
                            # Leave both False = unresolved

                        # RULE 0b: Response is CAPTCHA page (status 202 + captcha keywords)
                        elif status_code == 202 and sum(1 for kw in captcha_keywords if kw in body_text) >= 1:
                            blocked = False
                            passed = False
                            # CAPTCHA = unresolved (bot protection, not WAF)

                        # RULE 1: WAF keywords found AND response is DIFFERENT from
                        # baseline → genuine WAF block (not just generic bot block)
                        elif waf_score >= 1 and (not baseline_is_block or jaccard <= 0.6):
                            blocked = True
                            passed = False

                        # RULE 2: HIGH CONFIDENCE BYPASS
                        # Response has >40% baseline coverage AND no WAF keywords
                        # AND baseline is a normal page (not block/captcha)
                        elif (coverage > 0.4 and 0.2 < size_ratio < 5.0 and waf_score == 0
                              and not baseline_is_abnormal):
                            if not blocked:
                                passed = True

                        # RULE 2b: BYPASS when baseline IS abnormal —
                        # response must be VERY different (low Jaccard) AND
                        # look like a real page (200 status, no WAF/captcha keywords)
                        elif (baseline_is_abnormal and jaccard < 0.3
                              and status_code == 200 and waf_score == 0):
                            if not blocked:
                                passed = True

                        # RULE 3: Everything else = unresolved
                        # (don't force classify — let ML handle it)
            except Exception:
                pass

        # Layer 2: ML response clustering (online learning)
        if not blocked and not passed and body:
            try:
                ml_label, ml_conf = self.online_ml.get_enhanced_classification(
                    status_code, resp.get_headers(), body,
                )
                if ml_label in ("block", "softblock") and ml_conf > 0.7:
                    blocked = True
                    passed = False
                elif ml_label == "ratelimit" and ml_conf > 0.7:
                    blocked = True
                    passed = False
                elif ml_label == "pass" and ml_conf > 0.8:
                    passed = True
            except Exception:
                pass

        # Layer 2.5: Response Autoencoder (learned normal response pattern).
        # The autoencoder marks ANY response that doesn't match the trained
        # baseline as "blocked" — but "different from baseline" is not the
        # same as "WAF blocked". A 404 with body "server action not found",
        # a 500 server error, or a 200 redirect-page all look anomalous yet
        # none of them are WAF events. Gate the autoencoder verdict on a
        # plausible block-status set so we don't conflate origin errors
        # with WAF action.
        plausible_block_statuses = {200, 403, 406, 429, 503}
        if (not blocked and not passed and body
                and getattr(self.response_ae, '_is_trained', False)
                and status_code in plausible_block_statuses):
            try:
                ae_features = self.response_ae.extract_response_features(
                    status_code, body, getattr(self, '_baseline_body', b''),
                )
                ae_label, ae_conf = self.response_ae.classify(ae_features)
                if ae_label == "blocked" and ae_conf > 0.7:
                    blocked = True
                elif ae_label == "bypass" and ae_conf > 0.8:
                    passed = True
            except Exception:
                pass

        # Layer 3: Ambiguity resolution (both flags set)
        if blocked and passed and body:
            try:
                ml_label, ml_conf = self.online_ml.get_enhanced_classification(
                    status_code, resp.get_headers(), body,
                )
                if ml_label in ("block", "softblock") and ml_conf > 0.6:
                    passed = False
                elif ml_label == "pass" and ml_conf > 0.6:
                    blocked = False
            except Exception:
                pass

        return blocked, passed

    def _load_prior_ml_model(self) -> bool:
        """Load any prior trained ML model for this WAF type and re-apply baseline.

        ``engine.load()`` overwrites the engine's internal baseline with the
        prior scan's value, so we re-apply the CURRENT target's baseline after
        loading to keep predictions consistent. Bug 1 lives here — the
        re-apply step was missing in the original implementation.

        Returns:
            True if a prior model was successfully loaded and is ready for
            scoring; False on any failure (silent — never raises).
        """
        try:
            from gotestwaf.ml.model_store import load_ml_model
            loaded = load_ml_model(self._cfg.waf_name, self.ml_engine)
            if loaded and self._ml_baseline_set:
                self.ml_engine.set_baseline(
                    self._baseline_status, self._baseline_body,
                )
            return loaded
        except Exception as load_err:
            logger.debug("Prior ML model load skipped", error=str(load_err))
            return False

    async def run(self) -> None:
        """Start scanning the target WAF."""
        logger.info("Scanning started", url=self._cfg.url)

        start = time.monotonic()
        requests_counter = 0

        # Set up SIGUSR1 handler for status reporting (Unix only)
        cleanup_signal: Any = None
        if platform.system() != "Windows":
            try:
                loop = asyncio.get_running_loop()

                def _sigusr1_handler() -> None:
                    nonlocal requests_counter
                    logger.info(
                        "Test status",
                        sent=requests_counter,
                        total=self._db.number_of_tests,
                    )

                loop.add_signal_handler(signal.SIGUSR1, _sigusr1_handler)
                cleanup_signal = lambda: loop.remove_signal_handler(signal.SIGUSR1)
            except (NotImplementedError, AttributeError, ValueError):
                pass

        try:
            # ── Cross-scan learning: load prior ML model for this WAF type ──
            self._pretrained_ml_loaded = self._load_prior_ml_model()

            payloads = list(self._produce_tests())
            total = len(payloads)

            # ── Fast mode: use prior model to prioritize (and optionally skip)
            # payloads. Only active when the user opts in AND a prior model was
            # loaded — otherwise we preserve the default "test every payload"
            # behavior so bypass measurement stays accurate.
            ml_fast = bool(getattr(self._cfg, "ml_fast", False)) and self._pretrained_ml_loaded
            ml_fast_threshold = float(getattr(self._cfg, "ml_fast_threshold", 0.0) or 0.0)
            ml_fast_skipped_early = 0
            if ml_fast and payloads:
                try:
                    items = [
                        (pc.payload, pc.encoder, pc.placeholder.name) for pc in payloads
                    ]
                    scores = self.ml_engine.score_payloads_batch(items)
                    payloads, ml_fast_skipped_early = _apply_ml_fast_filter(
                        payloads, scores, ml_fast_threshold,
                    )
                    total = len(payloads)
                    logger.info(
                        "ML fast mode active",
                        prioritized=total,
                        skipped_below_threshold=ml_fast_skipped_early,
                        threshold=ml_fast_threshold,
                    )
                except Exception as _ml_fast_err:
                    logger.warning("ML fast mode failed — falling back to full scan",
                                   error=str(_ml_fast_err))
                    ml_fast_skipped_early = 0

            sem = asyncio.Semaphore(max(1, self._cfg.workers))
            consecutive_errors = 0
            backoff_multiplier = 1.0
            blocked_count = 0
            passed_count = 0
            failed_count = 0
            unresolved_count = 0
            skipped_count = ml_fast_skipped_early

            from rich.console import Console
            from rich.live import Live
            from rich.panel import Panel
            from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, TaskProgressColumn
            from rich.table import Table
            from rich.text import Text

            console = Console(force_terminal=True)

            progress = Progress(
                SpinnerColumn("dots", style="bold cyan"),
                TextColumn("[bold bright_cyan]Scanning WAF[/]"),
                BarColumn(bar_width=40, style="grey50", complete_style="bright_green", finished_style="bold green"),
                TaskProgressColumn("[bold]{task.percentage:>5.1f}%[/]"),
                MofNCompleteColumn(),
                TextColumn("[dim]|[/]"),
                TimeElapsedColumn(),
                TextColumn("[dim]<[/]"),
                TimeRemainingColumn(),
                console=console,
            )

            def _build_display() -> Table:
                """Build the live display with progress and stats."""
                grid = Table.grid(padding=(0, 0))

                # Header
                header = Text()
                header.append("  WAF SCANNER ", style="bold bright_white on blue")
                header.append(f"  {self._cfg.waf_name} ", style="bold bright_yellow")
                grid.add_row(header)
                grid.add_row(Text(f"  Target: {self._cfg.url}", style="dim"))
                grid.add_row(Text(""))

                # Progress bar
                grid.add_row(progress.get_renderable())
                grid.add_row(Text(""))

                # Stats row
                stats = Table.grid(padding=(0, 2))
                stats.add_row(
                    Text(f"  Blocked ", style="dim") + Text(f"{blocked_count}", style="bold bright_green"),
                    Text(f"  Bypassed ", style="dim") + Text(f"{passed_count}", style="bold bright_red"),
                    Text(f"  Failed ", style="dim") + Text(f"{failed_count}", style="bold yellow"),
                    Text(f"  Unresolved ", style="dim") + Text(f"{unresolved_count}", style="bold bright_blue"),
                    Text(f"  Workers ", style="dim") + Text(f"{self._cfg.workers}", style="bold cyan"),
                )
                grid.add_row(stats)

                return Panel(grid, border_style="bright_blue", padding=(1, 2))

            task_id = progress.add_task("scan", total=total)

            async def worker(pc: PayloadConfig) -> None:
                nonlocal requests_counter, consecutive_errors, backoff_multiplier
                nonlocal blocked_count, passed_count, failed_count, unresolved_count, skipped_count

                async with sem:
                    # Main scan: NEVER skip — test every payload like Go version does.
                    # ML skipping is only used in the adaptive round to save time.

                    # ML rate limit detection: increase delay if rate limiting detected
                    if self.online_ml.is_rate_limited():
                        actual_delay_ms = self._cfg.send_delay * 3.0
                    else:
                        base_delay_ms = self._cfg.send_delay + random.randint(0, self._cfg.random_delay)
                        actual_delay_ms = base_delay_ms * backoff_multiplier
                    await asyncio.sleep(actual_delay_ms / 1000.0)

                    try:
                        await self._send_payload(pc)
                        # On success, gradually reduce backoff
                        if consecutive_errors > 0:
                            consecutive_errors = max(0, consecutive_errors - 1)
                        if backoff_multiplier > 1.0:
                            backoff_multiplier = max(1.0, backoff_multiplier * 0.95)
                    except Exception as e:
                        consecutive_errors += 1
                        backoff_multiplier = min(10.0, backoff_multiplier * 1.5)
                        if consecutive_errors % 5 == 0:
                            logger.warning(
                                "Multiple consecutive errors, increasing delay",
                                errors=consecutive_errors,
                                backoff=f"{backoff_multiplier:.1f}x",
                            )
                        logger.error("Got an error while scanning", error=str(e))

                    requests_counter += 1
                    # Update live stats from DB
                    # With --ignoreUnresolved, unresolved counts as bypassed (matches report)
                    blocked_count = len(self._db.blocked_tests)
                    passed_count = len(self._db.passed_tests)
                    if self._cfg.ignore_unresolved:
                        passed_count += len(self._db.na_tests)
                    failed_count = len(self._db.failed_tests)
                    unresolved_count = len(self._db.na_tests)

                    # Auto-refresh cookies if we're getting 100% blocked with 0 bypasses
                    # after 100+ requests — likely means cookies expired.
                    # Skip when no bot-protection challenge was detected: 0 bypasses
                    # against a pure-WAF target (e.g. Azure Front Door) is the WAF
                    # doing its job, not stale cookies. Running the captcha solver
                    # against a non-CAPTCHA target just burns 60s + emits useless
                    # "no cookies extracted" warnings.
                    from gotestwaf.scanner.bot_detector import BotProtectionType
                    has_bot_challenge = (
                        self._bot_profile is not None
                        and self._bot_profile.protection_type != BotProtectionType.NONE
                    )
                    if (requests_counter >= 100 and passed_count == 0 and blocked_count > 80
                            and not self._cookie_refreshed and has_bot_challenge):
                        async with self._cookie_refresh_lock:
                            if not self._cookie_refreshed:  # double-check after lock
                                self._cookie_refreshed = True
                                logger.warning("0 bypasses after 100 requests — refreshing session cookies")
                                try:
                                    await self._solve_captcha_if_needed(force=True)
                                    old_client = self._http_client
                                    if self._cfg.http_client == "chrome":
                                        from gotestwaf.scanner.clients.chrome.client import Client as ChromeClient
                                        self._http_client = ChromeClient(self._cfg)
                                    else:
                                        self._http_client = GoHTTPClient(self._cfg)
                                    # Stash the old client for shutdown — closing
                                    # it here would tear down sockets that other
                                    # concurrent workers are still awaiting on
                                    # (they captured `self._http_client` before
                                    # the swap), turning their requests into
                                    # spurious errors.
                                    if hasattr(old_client, "close"):
                                        if not hasattr(self, "_clients_to_close"):
                                            self._clients_to_close = []
                                        self._clients_to_close.append(old_client)
                                    await self._set_ml_baseline()
                                except Exception as refresh_err:
                                    logger.warning("Cookie refresh failed", error=str(refresh_err))
                    progress.advance(task_id)

            with Live(_build_display(), console=console, refresh_per_second=4) as live:
                async def _refresh_live() -> None:
                    while not progress.finished:
                        live.update(_build_display())
                        await asyncio.sleep(0.25)

                live_update_task = asyncio.create_task(_refresh_live())

                scan_tasks = [asyncio.create_task(worker(pc)) for pc in payloads]
                await asyncio.gather(*scan_tasks)

                live_update_task.cancel()
                try:
                    await live_update_task
                except asyncio.CancelledError:
                    pass
                live.update(_build_display())

            # Print final summary + online ML stats
            online_stats = self.online_ml.get_stats()
            console.print()
            console.print(Panel(
                Text.assemble(
                    ("  SCAN COMPLETE  ", "bold bright_white on green"),
                    (f"  {requests_counter}/{total} sent", ""),
                    (f"  |  ML skipped {skipped_count}", "bold bright_magenta" if skipped_count > 0 else "dim"),
                    (f"  |  {online_stats['response_clusters']} response clusters", "dim"),
                    (f"  |  {online_stats['soft_blocks_detected']} soft-blocks found", "bold yellow" if online_stats['soft_blocks_detected'] > 0 else "dim"),
                ),
                border_style="green",
            ))
            if online_stats.get("bypass_combos"):
                logger.info("ML bypass combos found", combos=online_stats["bypass_combos"])

            # ── ML post-scan: train models and generate analysis ──
            try:
                logger.info("Training ML models on scan results...")
                ml_metrics = self.ml_engine.train()
                if ml_metrics.samples >= 30:
                    logger.info(
                        "ML training complete",
                        samples=ml_metrics.samples,
                        cv_f1=round(ml_metrics.cv_f1, 4),
                        bypassed=ml_metrics.bypassed,
                        blocked=ml_metrics.blocked,
                    )
                    if ml_metrics.feature_importance:
                        top_features = list(ml_metrics.feature_importance.items())[:5]
                        logger.info("Top ML features", features=dict(top_features))

                    # ── Persist trained model for future fast scans on this WAF ──
                    # Gate on cv_f1 >= 0.6 so we don't reuse junk models on the next run.
                    if ml_metrics.cv_f1 >= 0.6:
                        try:
                            from gotestwaf.ml.model_store import save_ml_model
                            save_ml_model(self._cfg.waf_name, self.ml_engine)
                        except Exception as _ml_save_err:
                            logger.debug("ML model save skipped", error=str(_ml_save_err))
                    else:
                        logger.info(
                            "ML model not persisted — cv_f1 below threshold",
                            cv_f1=round(ml_metrics.cv_f1, 4),
                        )

                    # ── ML-driven adaptive scan round ──
                    await self._run_adaptive_scan(console)
                else:
                    logger.info("ML training skipped (insufficient data)", samples=ml_metrics.samples)
            except Exception as e:
                logger.warning("ML training failed", error=str(e))
        finally:
            duration = time.monotonic() - start
            logger.info("Scanning finished", duration=f"{duration:.3f}s")

            if cleanup_signal:
                cleanup_signal()

            if self._grpc_client:
                await self._grpc_client.close()

            # Drain any HTTP clients deferred by the mid-scan cookie refresh.
            for stale in getattr(self, "_clients_to_close", []):
                try:
                    await stale.close()
                except Exception:
                    pass
            self._clients_to_close = []

    def _produce_tests(self) -> list[PayloadConfig]:
        """Generate all payload configurations."""
        test_cases = self._db.get_test_cases()
        configs: list[PayloadConfig] = []

        for test_case in test_cases:
            for payload in test_case.payloads:
                for encoder in test_case.encoders:
                    for placeholder in test_case.placeholders:
                        debug_header_value = ""
                        if self._enable_debug_header:
                            h = hashlib.sha256()
                            h.update(test_case.set.encode())
                            h.update(test_case.name.encode())
                            h.update(placeholder.name.encode())
                            h.update(encoder.encode())
                            h.update(payload.encode())
                            debug_header_value = h.hexdigest()

                        configs.append(PayloadConfig(
                            payload=payload,
                            encoder=encoder,
                            placeholder=placeholder,
                            set_name=test_case.set,
                            case_name=test_case.name,
                            test_type=test_case.type,
                            is_true_positive=test_case.is_true_positive,
                            debug_header_value=debug_header_value,
                        ))

        return configs

    async def _run_adaptive_scan(self, console: Any) -> None:
        """ML-driven adaptive scan round.

        After the main scan + ML training, this generates mutation payloads
        predicted to bypass the WAF and tests them. Uses:
        1. Encoding chains (double/triple encoding)
        2. ML-predicted encoder/placeholder swaps
        3. Payload mutations (case mixing, comment insertion, null bytes)
        """
        from rich.panel import Panel
        from rich.text import Text

        if not self._db.blocked_tests or self._http_client is None:
            return

        # ── Use AI payload generator for intelligent mutations ──
        from gotestwaf.ml.payload_generator import generate_ai_payloads

        ai_payloads = generate_ai_payloads(self._db, max_payloads=300)
        logger.info("AI payload generator produced candidates", count=len(ai_payloads))

        # Also keep static mutations as fallback
        blocked_tests = list(self._db.blocked_tests)

        # Pick top blocked payloads to mutate (diverse set)
        # Skip oversized payloads (encoding chains on 128KB payloads = URL too long)
        # Skip RawRequest/gRPC/GraphQL placeholders (need special config)
        SKIP_PLACEHOLDERS = {"RawRequest", "gRPC", "GraphQL"}
        MAX_PAYLOAD_LEN = 4096  # Encoding chains double/triple the size

        seen_payloads: set[str] = set()
        candidates: list[Info] = []
        for bt in blocked_tests:
            if (bt.payload not in seen_payloads
                and len(bt.payload) <= MAX_PAYLOAD_LEN
                and bt.placeholder not in SKIP_PLACEHOLDERS
                and len(candidates) < 30):
                seen_payloads.add(bt.payload)
                candidates.append(bt)

        # Generate mutations using ML predictions + encoding chains
        mutations: list[PayloadConfig] = []
        encoding_chains = ["URL+Base64", "Base64+URL", "URL+URL", "JSUnicode+URL", "URL+Base64Flat"]
        # Only placeholders that work without special config
        alt_placeholders = ["Header", "UserAgent", "JSONBody", "URLPath", "HTMLForm", "URLParam"]

        for bt in candidates:
            # 1. Try encoding chains (only with original placeholder)
            for chain in encoding_chains:
                ph = Placeholder(name=bt.placeholder)
                mutations.append(PayloadConfig(
                    payload=bt.payload, encoder=chain,
                    placeholder=ph, set_name=bt.set, case_name=f"{bt.case}+ML",
                    test_type=bt.type, is_true_positive=True, debug_header_value="",
                ))

            # 2. Try alternative placements
            for ph_name in alt_placeholders:
                if ph_name != bt.placeholder:
                    ph = Placeholder(name=ph_name)
                    mutations.append(PayloadConfig(
                        payload=bt.payload, encoder=bt.encoder,
                        placeholder=ph, set_name=bt.set, case_name=f"{bt.case}+ML",
                        test_type=bt.type, is_true_positive=True, debug_header_value="",
                    ))

            # 3. Payload mutations (skip null byte — breaks HTTP headers)
            payload_muts = [
                (bt.payload.swapcase(), "CaseSwap"),
                (bt.payload.replace(" ", "/**/"), "CommentInsert"),
                (bt.payload.replace("<", "%3C").replace(">", "%3E"), "ManualEnc"),
                (bt.payload.replace("'", "\\'"), "EscapeQuotes"),
            ]
            for mutated, name in payload_muts:
                ph = Placeholder(name=bt.placeholder)
                mutations.append(PayloadConfig(
                    payload=mutated, encoder=bt.encoder,
                    placeholder=ph, set_name=bt.set, case_name=f"{bt.case}+ML-{name}",
                    test_type=bt.type, is_true_positive=True, debug_header_value="",
                ))

        # Add AI-generated payloads
        SKIP_PH = {"RawRequest", "gRPC", "GraphQL"}
        for gp in ai_payloads:
            if gp.placeholder not in SKIP_PH and len(gp.payload) <= MAX_PAYLOAD_LEN:
                ph = Placeholder(name=gp.placeholder)
                mutations.append(PayloadConfig(
                    payload=gp.payload, encoder=gp.encoder,
                    placeholder=ph, set_name="ai-gen", case_name=f"ai-{gp.generation_technique}",
                    test_type=gp.attack_type, is_true_positive=True, debug_header_value="",
                ))

        if not mutations:
            return

        logger.info(
            "Starting ML-driven adaptive scan round",
            mutations=len(mutations),
            ai_generated=len(ai_payloads),
            static_mutations=len(mutations) - len(ai_payloads),
        )

        console.print(Panel(
            Text.assemble(
                ("  ML ADAPTIVE SCAN  ", "bold bright_white on magenta"),
                (f"  {len(mutations)} mutation payloads from {len(candidates)} blocked originals", ""),
            ),
            border_style="magenta",
        ))

        from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn, TaskProgressColumn

        ml_progress = Progress(
            SpinnerColumn("dots", style="bold magenta"),
            TextColumn("[bold bright_magenta]ML Mutations[/]"),
            BarColumn(bar_width=40, style="grey50", complete_style="bright_magenta", finished_style="bold magenta"),
            TaskProgressColumn("[bold]{task.percentage:>5.1f}%[/]"),
            MofNCompleteColumn(),
            TextColumn("[dim]|[/]"),
            TimeElapsedColumn(),
            TextColumn("[dim]<[/]"),
            TimeRemainingColumn(),
            console=console,
        )

        ml_task = ml_progress.add_task("ml_scan", total=len(mutations))
        ml_bypasses = 0
        ml_blocked = 0

        sem = asyncio.Semaphore(max(1, self._cfg.workers))

        def _bypass_count() -> int:
            """Count bypasses: passed + unresolved (when ignoreUnresolved)."""
            n = len(self._db.passed_tests)
            if self._cfg.ignore_unresolved:
                n += len(self._db.na_tests)
            return n

        bypass_before = _bypass_count()

        async def ml_worker(pc: PayloadConfig) -> None:
            nonlocal ml_bypasses, ml_blocked
            async with sem:
                # In adaptive round, skip combos the online ML knows are always blocked
                if self.online_ml.should_skip(pc.encoder, pc.placeholder.name):
                    ml_blocked += 1
                    ml_progress.advance(ml_task)
                    return
                # Skip payloads with non-ASCII chars (httpx rejects them)
                try:
                    pc.payload.encode('ascii')
                except UnicodeEncodeError:
                    ml_blocked += 1
                    ml_progress.advance(ml_task)
                    return

                await asyncio.sleep(self._cfg.send_delay / 1000.0)
                before = _bypass_count()
                try:
                    await self._send_payload(pc)
                except Exception:
                    pass
                after = _bypass_count()
                if after > before:
                    ml_bypasses += 1
                else:
                    ml_blocked += 1
                ml_progress.advance(ml_task)

        from rich.live import Live
        from rich.table import Table

        def _ml_display() -> Table:
            grid = Table.grid()
            grid.add_row(ml_progress.get_renderable())
            stats = Text()
            stats.append(f"  Bypassed ", style="dim")
            stats.append(f"{ml_bypasses}", style="bold bright_red" if ml_bypasses > 0 else "dim")
            stats.append(f"  Blocked ", style="dim")
            stats.append(f"{ml_blocked}", style="bold bright_green")
            grid.add_row(stats)
            return Panel(grid, border_style="magenta", padding=(0, 2))

        with Live(_ml_display(), console=console, refresh_per_second=4) as live:
            async def _refresh() -> None:
                while not ml_progress.finished:
                    live.update(_ml_display())
                    await asyncio.sleep(0.25)

            refresh_task = asyncio.create_task(_refresh())
            tasks = [asyncio.create_task(ml_worker(pc)) for pc in mutations]
            await asyncio.gather(*tasks)
            refresh_task.cancel()
            try:
                await refresh_task
            except asyncio.CancelledError:
                pass
            live.update(_ml_display())

        if ml_bypasses > 0:
            logger.info(
                "ML adaptive scan found bypasses!",
                bypasses=ml_bypasses,
                total_tested=len(mutations),
            )
        else:
            logger.info("ML adaptive scan: no new bypasses found", total_tested=len(mutations))

    async def _send_payload(self, pc: PayloadConfig) -> None:
        """Send a single payload and record the result.

        Routes to the appropriate send method based on placeholder type.
        Also handles OpenAPI template-based requests.
        """
        placeholders = get_placeholders()

        grpc_placeholder = placeholders.get("gRPC")
        graphql_placeholder = placeholders.get("GraphQL")

        if grpc_placeholder and pc.placeholder.name == grpc_placeholder.get_name():
            await self._send_grpc_request(pc)
            return

        if graphql_placeholder and pc.placeholder.name == graphql_placeholder.get_name():
            await self._send_graphql_request(pc)
            return

        # If OpenAPI templates are available, send requests through them
        if self._request_templates is not None:
            await self._send_openapi_requests(pc)
            return

        await self._send_request(pc)

    async def _send_grpc_request(self, pc: PayloadConfig) -> None:
        """Send a gRPC request with debug header injected as gRPC metadata."""
        if self._grpc_client is None or not self._grpc_client.is_available():
            return

        pl = PayloadInfo(
            payload=pc.payload,
            encoder_name=pc.encoder,
            debug_header_value=pc.debug_header_value,
        )

        try:
            resp = await self._grpc_client.send_payload(pl, debug_header_value=pc.debug_header_value)
            self._update_db(pc, TestStatus(), None, resp, None, "", is_grpc=True)
        except Exception as e:
            self._update_db(pc, TestStatus(), None, None, e, "", is_grpc=True)

    async def _send_graphql_request(self, pc: PayloadConfig) -> None:
        """Send a GraphQL request."""
        if self._graphql_client is None or not self._graphql_client.is_available():
            return

        pl = PayloadInfo(
            payload=pc.payload,
            encoder_name=pc.encoder,
            placeholder_name=pc.placeholder.name,
            placeholder_config=pc.placeholder.config,
            debug_header_value=pc.debug_header_value,
        )

        try:
            resp = await self._graphql_client.send_payload(pl)
            err = resp.get_error() if resp else None
            self._update_db(pc, TestStatus(), None, resp, err, "")
        except Exception as e:
            self._update_db(pc, TestStatus(), None, None, e, "")

    async def _send_request(self, pc: PayloadConfig) -> None:
        """Send a standard HTTP request with retry for transient errors."""
        if self._http_client is None:
            return

        import httpx

        _RETRYABLE = (
            ConnectionError, ConnectionResetError, ConnectionAbortedError,
            TimeoutError, httpx.RemoteProtocolError, httpx.ReadError,
            httpx.WriteError, httpx.ConnectError, httpx.PoolTimeout,
            httpx.ReadTimeout, httpx.ConnectTimeout,
        )

        pl = PayloadInfo(
            payload=pc.payload,
            encoder_name=pc.encoder,
            placeholder_name=pc.placeholder.name,
            placeholder_config=pc.placeholder.config,
            debug_header_value=pc.debug_header_value,
        )

        # Build the request object for PoC evidence capture
        try:
            evidence_req = pl.get_request(self._cfg.url, HTTPClientType.GO_HTTP_CLIENT)
            if not isinstance(evidence_req, GoHTTPRequest):
                evidence_req = None
        except Exception:
            evidence_req = None

        last_err: Exception | None = None
        for attempt in range(3):
            try:
                t0 = time.monotonic()
                resp = await self._http_client.send_payload(self._cfg.url, pl)
                elapsed_ms = (time.monotonic() - t0) * 1000
                err = resp.get_error() if resp else None
                self._update_db(pc, TestStatus(), evidence_req, resp, err, "", response_time_ms=elapsed_ms)
                return
            except _RETRYABLE as e:
                last_err = e
                if attempt < 2:
                    await asyncio.sleep((2 ** attempt) * 1.0)
                    continue
            except Exception as e:
                self._update_db(pc, TestStatus(), evidence_req, None, e, "")
                return

        # All retries exhausted — record the final error
        if last_err is not None:
            self._update_db(pc, TestStatus(), evidence_req, None, last_err, "")

    async def _send_openapi_requests(self, pc: PayloadConfig) -> None:
        """Send multiple HTTP requests based on OpenAPI request templates.

        Iterates over templates for the given placeholder, encodes the payload,
        creates requests from templates, sends them via HTTP client, and validates
        responses against the OpenAPI spec.
        """
        if self._request_templates is None or self._http_client is None:
            return

        templates = self._request_templates.get(pc.placeholder.name, [])
        if not templates:
            return

        try:
            encoded_payload = apply_encoder(pc.encoder, pc.payload)
        except Exception as e:
            logger.error("encoding payload failed", error=str(e))
            return

        ts = TestStatus()

        for template in templates:
            req = template.create_request(pc.placeholder.name, encoded_payload)
            if req is None:
                continue

            additional_info = f"{template.method} {template.path}"

            try:
                resp = await self._http_client.send_request(req)
            except Exception as e:
                self._update_db(pc, ts, req, None, e, additional_info)
                self._db.add_to_scanned_paths(template.method, template.path)
                continue

            self._update_db(pc, ts, req, resp, None, additional_info)
            self._db.add_to_scanned_paths(template.method, template.path)

    def _update_db(
        self,
        pc: PayloadConfig,
        ts: TestStatus,
        req: GoHTTPRequest | None,
        resp: Response | None,
        send_err: Exception | None,
        additional_info: str,
        is_grpc: bool = False,
        response_time_ms: float = 0.0,
    ) -> None:
        """Update the database with test results."""
        info = pc.to_info(resp)
        info.response_time_ms = response_time_ms

        # Capture full request/response for PoC evidence
        if req is not None:
            info.request_method = getattr(req, "method", "GET")
            info.request_url = getattr(req, "url", "")
            # Start with request-specific headers
            req_headers = dict(getattr(req, "headers", {}) or {})
            # Merge in client-configured headers (User-Agent, etc) for full visibility
            if hasattr(self, "_cfg") and hasattr(self._cfg, "http_headers"):
                for hk, hv in self._cfg.http_headers.items():
                    if hk.lower() not in {k.lower() for k in req_headers}:
                        req_headers[hk] = hv
            # Add Host header
            try:
                from urllib.parse import urlparse
                parsed = urlparse(info.request_url)
                if parsed.netloc and "Host" not in req_headers and "host" not in req_headers:
                    req_headers["Host"] = parsed.netloc
            except Exception:
                pass
            info.request_headers = req_headers
            req_content = getattr(req, "content", None)
            if req_content:
                if isinstance(req_content, bytes):
                    info.request_body = req_content[:4000].decode("utf-8", errors="replace")
                elif isinstance(req_content, str):
                    info.request_body = req_content[:4000]
        else:
            # Reconstruct request info from PayloadConfig when req is None
            info.request_url = self._cfg.url
            info.request_method = "GET" if pc.placeholder.name in ("URLParam", "URLPath", "Header", "UserAgent") else "POST"
            info.request_headers = {"Host": self._cfg.url.split("//")[-1].split("/")[0]}
        if resp is not None:
            info.response_headers = {
                k: ", ".join(v) if isinstance(v, list) else str(v)
                for k, v in resp.get_headers().items()
            }
            body = resp.get_content()
            if body:
                info.response_body = body[:4000].decode("utf-8", errors="replace")

        # Handle send errors
        if send_err is not None:
            is_conn_reset = isinstance(send_err, (ConnectionResetError, ConnectionError, ConnectionAbortedError))
            if is_conn_reset and self._cfg.block_conn_reset:
                # Fall through to blocked logic below
                pass
            elif is_conn_reset:
                if ts.unresolved_test is None:
                    ts.unresolved_test = info
                    self._db.update_na_tests(
                        ts.unresolved_test,
                        self._cfg.ignore_unresolved,
                        self._cfg.non_blocked_as_passed,
                        pc.is_true_positive,
                    )
                if additional_info:
                    ts.unresolved_test.additional_info.append(additional_info)
                return
            else:
                if ts.failed_test is None:
                    ts.failed_test = info
                    self._db.update_failed_tests(ts.failed_test)
                if additional_info:
                    ts.failed_test.additional_info.append(additional_info)
                logger.error("send request failed", error=str(send_err))
                return

        # Determine blocked/passed
        blocked_by_reset = False
        if send_err is not None and self._cfg.block_conn_reset:
            blocked_by_reset = True

        blocked = False
        passed = False

        if blocked_by_reset:
            blocked = True
        elif resp is not None:
            blocked, passed = self._check_blocked_or_passed(resp)
        else:
            return

        # OpenAPI response validation path:
        # When using OpenAPI templates and this is not a gRPC request,
        # use the OpenAPI spec to validate the response instead of
        # simple block/pass detection.
        if self._request_templates is not None and not is_grpc and self._router is not None and req is not None:
            # If the OpenAPI spec validates the response as a legitimate response
            # (matching defined status codes/schemas), consider it passed (bypassed WAF).
            # Otherwise consider it blocked.
            # For now, we use a simplified check: if the response status matches
            # a non-error code AND the response was not flagged as blocked,
            # consider it passed through.
            resp_status = resp.get_status_code() if resp else 0
            if not blocked and resp_status < 400:
                if ts.passed_test is None:
                    ts.passed_test = info
                    self._db.update_passed_tests(ts.passed_test)
                if additional_info:
                    ts.passed_test.additional_info.append(additional_info)
            else:
                if ts.blocked_test is None:
                    ts.blocked_test = info
                    self._db.update_blocked_tests(ts.blocked_test)
                if additional_info:
                    ts.blocked_test.additional_info.append(additional_info)
            # Feed OpenAPI results to ML engine too
            if resp is not None:
                try:
                    self.ml_engine.add_result(
                        payload=pc.payload, encoder=pc.encoder,
                        placeholder=pc.placeholder.name,
                        status_code=resp.get_status_code(),
                        headers=resp.get_headers(), body=resp.get_content(),
                        was_blocked=blocked, test_set=pc.set_name, test_case=pc.case_name,
                    )
                except Exception:
                    pass
            return

        # Standard blocked/passed logic
        if (blocked and passed) or (not blocked and not passed):
            if ts.unresolved_test is None:
                ts.unresolved_test = info
                self._db.update_na_tests(
                    ts.unresolved_test,
                    self._cfg.ignore_unresolved,
                    self._cfg.non_blocked_as_passed,
                    pc.is_true_positive,
                )
            if additional_info:
                ts.unresolved_test.additional_info.append(additional_info)
        elif blocked:
            if ts.blocked_test is None:
                ts.blocked_test = info
                self._db.update_blocked_tests(ts.blocked_test)
            if additional_info:
                ts.blocked_test.additional_info.append(additional_info)
        else:
            if ts.passed_test is None:
                ts.passed_test = info
                self._db.update_passed_tests(ts.passed_test)
            if additional_info:
                ts.passed_test.additional_info.append(additional_info)

        # ── Feed result to ML engines for online learning ──
        if resp is not None:
            try:
                self.ml_engine.add_result(
                    payload=pc.payload,
                    encoder=pc.encoder,
                    placeholder=pc.placeholder.name,
                    status_code=resp.get_status_code(),
                    headers=resp.get_headers(),
                    body=resp.get_content(),
                    was_blocked=blocked,
                    test_set=pc.set_name,
                    test_case=pc.case_name,
                )
                # Feed online ML for real-time clustering and adaptive skipping
                self.online_ml.record_result(
                    payload=pc.payload,
                    encoder=pc.encoder,
                    placeholder=pc.placeholder.name,
                    status_code=resp.get_status_code(),
                    headers=resp.get_headers(),
                    body=resp.get_content(),
                    was_blocked=blocked,
                )
            except Exception:
                pass  # ML feeding must never break scanning
