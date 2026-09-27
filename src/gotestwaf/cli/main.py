"""GoTestWAF CLI entry point using Typer."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional
from urllib.parse import urlparse, urlunparse

import structlog
import typer

from gotestwaf.config.config import Config, load_config_from_yaml
from gotestwaf.errors import GoTestWAFError
from gotestwaf.version import VERSION

app = typer.Typer(
    name="gotestwaf",
    help=(
        "GoTestWAF is a tool for API and OWASP attack simulation that supports a\n"
        "wide range of API protocols including REST, GraphQL, gRPC, SOAP, XMLRPC, and others.\n"
        "Homepage: https://github.com/wallarm/gotestwaf"
    ),
    add_completion=False,
)

logger = structlog.get_logger()

DEFAULT_REPORT_NAME = "waf-evaluation-report-%Y-%B-%d-%H-%M-%S"
DEFAULT_REPORT_PATH = "reports"
DEFAULT_TEST_CASES_PATH = "testcases"
DEFAULT_CONFIG_PATH = "config.yaml"
MAX_REPORT_FILENAME_LENGTH = 249


def _validate_url(raw_url: str, protocol: str = "http") -> str:
    """Validate URL and URL scheme. Returns the validated URL string."""
    parsed = urlparse(raw_url)
    if not re.match(rf"^{protocol}s?$", parsed.scheme):
        msg = f"invalid URL scheme: {parsed.scheme}"
        raise typer.BadParameter(msg)
    if not parsed.hostname:
        msg = "empty host"
        raise typer.BadParameter(msg)
    return raw_url


def _craft_graphql_url(graphql_url: str, http_url: str) -> str:
    """Create a GraphQL URL from the HTTP URL if graphql_url is empty.

    Mirrors Go's checkOrCraftProtocolURL behavior.
    """
    if graphql_url:
        _validate_url(graphql_url, "http")
        return graphql_url

    parsed = urlparse(http_url)
    # GraphQL uses the same scheme and path as HTTP — preserve the path so
    # that sub-path API deployments (e.g. /v1/graphql) still resolve correctly.
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def _is_terminal() -> bool:
    """Check if stdin is a terminal (interactive session)."""
    try:
        return os.isatty(sys.stdin.fileno())
    except (AttributeError, ValueError, OSError):
        return False


def _normalize_args(
    url: str,
    grpc_port: int,
    graphql_url: str,
    openapi_file: str,
    http_client: str,
    workers: int,
    waf_name: str,
    report_format: str,
    no_email_report: bool,
    email: str,
    include_payloads: bool,
) -> list[str]:
    """Build normalized CLI args list from changed parameters.

    Mirrors Go's normalizeArgs function.
    """
    args: list[str] = []

    # We build args from the explicitly provided values
    if url:
        args.append(f"--url={url}")
    if grpc_port:
        args.append(f"--grpcPort={grpc_port}")
    if graphql_url:
        args.append(f"--graphqlURL={graphql_url}")
    if openapi_file:
        args.append(f"--openapiFile={openapi_file}")
    if http_client != "gohttp":
        args.append(f"--httpClient={http_client}")
    if workers != 5:
        args.append(f"--workers={workers}")
    if waf_name != "generic":
        args.append(f"--wafName={waf_name}")
    if report_format != "pdf":
        args.append(f"--reportFormat={report_format}")
    if no_email_report:
        args.append("--noEmailReport")
    if email:
        args.append(f"--email={email}")
    if include_payloads:
        args.append("--includePayloads")

    return args


@app.command()
def main(
    # Target settings
    url: Annotated[str, typer.Option("--url", help="URL to check")] = "",
    grpc_port: Annotated[int, typer.Option("--grpcPort", help="gRPC port to check")] = 0,
    graphql_url: Annotated[str, typer.Option("--graphqlURL", help="GraphQL URL to check")] = "",
    openapi_file: Annotated[str, typer.Option("--openapiFile", help="Path to openAPI file")] = "",
    # Test cases settings
    test_case: Annotated[str, typer.Option("--testCase", help="If set then only this test case will be run")] = "",
    test_cases_path: Annotated[str, typer.Option("--testCasesPath", help="Path to a folder with test cases")] = DEFAULT_TEST_CASES_PATH,
    test_set: Annotated[str, typer.Option("--testSet", help="If set then only this test set's cases will be run")] = "",
    # HTTP client settings
    http_client: Annotated[str, typer.Option("--httpClient", help="Which HTTP client to use: chrome, gohttp")] = "gohttp",
    tls_verify: Annotated[bool, typer.Option("--tlsVerify", help="Verify TLS certificate")] = False,
    proxy: Annotated[str, typer.Option("--proxy", help="Proxy URL to use")] = "",
    add_header: Annotated[str, typer.Option("--addHeader", help="An HTTP header to add to requests")] = "",
    add_debug_header: Annotated[bool, typer.Option("--addDebugHeader", help="Add debug header")] = False,
    # GoHTTP client settings
    max_idle_conns: Annotated[int, typer.Option("--maxIdleConns", help="Max keep-alive connections")] = 2,
    max_redirects: Annotated[int, typer.Option("--maxRedirects", help="Max redirects")] = 50,
    idle_conn_timeout: Annotated[int, typer.Option("--idleConnTimeout", help="Idle connection timeout")] = 2,
    follow_cookies: Annotated[bool, typer.Option("--followCookies", help="Use cookies from server")] = False,
    renew_session: Annotated[bool, typer.Option("--renewSession", help="Renew cookies before each test")] = False,
    # Performance settings
    workers: Annotated[int, typer.Option("--workers", help="Number of workers (0=auto)")] = 0,
    send_delay: Annotated[int, typer.Option("--sendDelay", help="Delay in ms between requests")] = 500,
    random_delay: Annotated[int, typer.Option("--randomDelay", help="Random delay in ms")] = 400,
    # Analysis settings (smart defaults — no flags needed for typical scans)
    skip_waf_block_check: Annotated[bool, typer.Option("--skipWAFBlockCheck", help="Skip WAF detection tests")] = True,
    skip_waf_identification: Annotated[bool, typer.Option("--skipWAFIdentification", help="Skip WAF identification")] = False,
    block_status_codes: Annotated[Optional[str], typer.Option("--blockStatusCodes", help="Block status codes (comma-separated)")] = "401,403,406,429,503",
    pass_status_codes: Annotated[Optional[str], typer.Option("--passStatusCodes", help="Pass status codes (comma-separated)")] = "200",
    block_regex: Annotated[str, typer.Option("--blockRegex", help="Regex to detect blocking")] = "Blocked|Access Denied|Forbidden|Request Rejected|security violation",
    pass_regex: Annotated[str, typer.Option("--passRegex", help="Regex to detect passing")] = "",
    non_blocked_as_passed: Annotated[bool, typer.Option("--nonBlockedAsPassed", help="Count non-blocked as passed")] = False,
    ignore_unresolved: Annotated[bool, typer.Option("--ignoreUnresolved", help="Ignore unresolved test cases")] = True,
    block_conn_reset: Annotated[bool, typer.Option("--blockConnReset", help="Treat conn reset as block")] = True,
    # Report settings (smart defaults — auto-generates everything)
    waf_name: Annotated[str, typer.Option("--wafName", help="WAF product name (auto-detected if empty)")] = "",
    include_payloads: Annotated[bool, typer.Option("--includePayloads", help="Include payloads in report")] = True,
    report_path: Annotated[str, typer.Option("--reportPath", help="Directory to store reports")] = DEFAULT_REPORT_PATH,
    report_name: Annotated[str, typer.Option("--reportName", help="Report file name (auto from hostname if empty)")] = "",
    report_format: Annotated[str, typer.Option("--reportFormat", help="Report formats (comma-separated)")] = "html,xlsx",
    no_email_report: Annotated[bool, typer.Option("--noEmailReport", help="Save report locally")] = True,
    email: Annotated[str, typer.Option("--email", help="Email for report")] = "",
    hide_args_in_report: Annotated[bool, typer.Option("--hideArgsInReport", help="Hide CLI args in report")] = False,
    # Authentication
    auth_header: Annotated[str, typer.Option("--authHeader", help="Auth header (e.g. 'Authorization: Bearer xxx')")] = "",
    auth_cookie: Annotated[str, typer.Option("--cookie", help="Cookies (e.g. 'session=abc; token=xyz')")] = "",
    login_url: Annotated[str, typer.Option("--loginURL", help="Login endpoint URL for form-based auth")] = "",
    login_body: Annotated[str, typer.Option("--loginBody", help="Login request body (JSON or form)")] = "",
    # Multi-target
    targets: Annotated[str, typer.Option("--targets", help="File with target URLs (one per line)")] = "",
    # Advanced testing
    test_rate_limit: Annotated[bool, typer.Option("--testRateLimit", help="Test WAF rate limiting thresholds")] = False,
    fuzz_openapi: Annotated[bool, typer.Option("--fuzzOpenAPI", help="Generate attack payloads from OpenAPI spec")] = False,
    test_cve: Annotated[bool, typer.Option("--testCVE", help="Test against recent CVE payloads")] = False,
    cve_days: Annotated[int, typer.Option("--cveDays", help="CVE lookback days")] = 30,
    payload_pack: Annotated[str, typer.Option("--payloadPack", help="Payload pack: owasp, community, healthcare, finance, government, all")] = "",
    # Compliance & comparison
    compliance: Annotated[str, typer.Option("--compliance", help="Compliance frameworks (comma-separated: pci-dss,soc2,iso27001,nist)")] = "",
    compare: Annotated[str, typer.Option("--compare", help="Path to previous scan JSON for comparison")] = "",
    # Notifications
    slack_webhook: Annotated[str, typer.Option("--slackWebhook", help="Slack webhook URL for scan notifications")] = "",
    teams_webhook: Annotated[str, typer.Option("--teamsWebhook", help="Teams webhook URL for scan notifications")] = "",
    # Scheduling
    schedule: Annotated[str, typer.Option("--schedule", help="Cron schedule (e.g. '0 2 * * *' for daily at 2am)")] = "",
    score_threshold: Annotated[float, typer.Option("--threshold", help="Alert if score drops below this (0-100)")] = 0.0,
    # Cross-scan ML fast mode
    ml_fast: Annotated[bool, typer.Option("--mlFast", help="Use prior trained ML model (if any) to reorder payloads — likely-bypass fire first")] = False,
    ml_fast_threshold: Annotated[float, typer.Option("--mlFastThreshold", help="Skip payloads whose predicted bypass probability is below this (0-1). 0 = reorder only, no skip")] = 0.0,
    # General
    config_path: Annotated[str, typer.Option("--configPath", help="Path to config file")] = DEFAULT_CONFIG_PATH,
    quiet: Annotated[bool, typer.Option("--quiet", help="Disable verbose logging")] = False,
    log_level: Annotated[str, typer.Option("--logLevel", help="Logging level")] = "info",
    log_format: Annotated[str, typer.Option("--logFormat", help="Log format: text, json")] = "text",
    version: Annotated[bool, typer.Option("--version", help="Show version and exit")] = False,
) -> None:
    """Run GoTestWAF scanner."""
    if version:
        print(f"GoTestWAF {VERSION}")
        raise SystemExit(0)

    # ── Multi-target: --targets file or --url pointing to a .txt file ──
    target_urls: list[str] = []
    if targets and os.path.isfile(targets):
        target_urls = [line.strip() for line in Path(targets).read_text(encoding="utf-8").splitlines()
                       if line.strip() and not line.strip().startswith("#")]
        logger.info("Loaded target URLs from file", file=targets, count=len(target_urls))
        # Use first URL as default --url if not provided
        if not url and target_urls:
            url = target_urls[0]
    elif url and url.endswith(".txt") and os.path.isfile(url):
        target_urls = [line.strip() for line in Path(url).read_text(encoding="utf-8").splitlines()
                       if line.strip() and not line.strip().startswith("#")]
        logger.info("Loaded target URLs from file", file=url, count=len(target_urls))
        if target_urls:
            url = target_urls[0]

    if not url and not target_urls:
        print("Error: --url flag is required (or --targets file)", file=sys.stderr)
        raise SystemExit(1)

    # ── Auto-detect smart defaults ──
    # Workers: auto from CPU count
    if workers <= 0:
        import multiprocessing
        workers = max(2, min(5, multiprocessing.cpu_count()))

    # Report name: auto from hostname
    if not report_name:
        parsed_host = urlparse(url).hostname or "scan"
        report_name = f"waf-scan-{parsed_host.replace('.', '-')}"

    # WAF name: will be auto-detected during scan, use "generic" as placeholder
    if not waf_name:
        waf_name = "generic"

    # Non-interactive terminal detection (mirrors Go's terminal.IsTerminal check)
    if not _is_terminal():
        if not no_email_report and not email:
            print(
                "GoTestWAF is running in a non-interactive session. "
                "Please use the '-it' flag if you are running GTW in Docker or use the "
                "'--email' (or '--noEmailReport') and '--includePayloads' ('true' or 'false') options",
                file=sys.stderr,
            )
            raise SystemExit(1)

    # Validate email if provided
    if not no_email_report and email:
        from gotestwaf.helpers.email import validate_email
        try:
            email = validate_email(email)
        except Exception as e:
            logger.error("couldn't validate email", error=str(e))
            raise SystemExit(1) from e

    # Configure logging
    if quiet:
        structlog.configure(
            wrapper_class=structlog.make_filtering_bound_logger(50),
        )
    else:
        import logging as logging_module
        level = getattr(logging_module, log_level.upper(), logging_module.INFO)
        structlog.configure(
            wrapper_class=structlog.make_filtering_bound_logger(level),
        )

    # Parse status codes
    try:
        block_codes = [int(c.strip()) for c in (block_status_codes or "403").split(",")]
    except ValueError as e:
        logger.error("Invalid --blockStatusCodes value (must be comma-separated integers)", error=str(e))
        raise SystemExit(1) from e
    try:
        pass_codes = [int(c.strip()) for c in (pass_status_codes or "200,404").split(",")]
    except ValueError as e:
        logger.error("Invalid --passStatusCodes value (must be comma-separated integers)", error=str(e))
        raise SystemExit(1) from e
    formats = [f.strip() for f in report_format.split(",")]

    # Validate URL
    try:
        url = _validate_url(url)
    except typer.BadParameter as e:
        logger.error("URL is not valid", error=str(e))
        raise SystemExit(1) from e

    # Derive GraphQL URL from HTTP URL if not provided
    resolved_graphql_url = _craft_graphql_url(graphql_url, url)

    # Force GoHTTP client when using OpenAPI file
    effective_http_client = http_client
    if openapi_file:
        effective_http_client = "gohttp"

    # Validate regexes
    if block_regex:
        try:
            re.compile(block_regex)
        except re.error as e:
            logger.error("bad blockRegex", error=str(e))
            raise SystemExit(1) from e

    if pass_regex:
        try:
            re.compile(pass_regex)
        except re.error as e:
            logger.error("bad passRegex", error=str(e))
            raise SystemExit(1) from e

    # Validate report filename length
    _, report_file_name = os.path.split(report_name)
    if len(report_file_name) > MAX_REPORT_FILENAME_LENGTH:
        logger.error("report filename too long")
        raise SystemExit(1)

    # Build normalized args (mirrors Go's normalizeArgs)
    normalized_args = _normalize_args(
        url=url,
        grpc_port=grpc_port,
        graphql_url=graphql_url,
        openapi_file=openapi_file,
        http_client=effective_http_client,
        workers=workers,
        waf_name=waf_name,
        report_format=report_format,
        no_email_report=no_email_report,
        email=email,
        include_payloads=include_payloads,
    )

    # Load YAML config
    yaml_config = load_config_from_yaml(config_path)
    http_headers: dict[str, str] = {}
    if "headers" in yaml_config:
        http_headers = {str(k): str(v) for k, v in yaml_config["headers"].items()}

    # Track if --includePayloads was explicitly used (detect via sys.argv since Typer defaults hide intent)
    is_include_payloads_flag_used = any("includePayloads" in arg for arg in sys.argv[1:])

    # Build config
    cfg = Config(
        url=url,
        grpc_port=grpc_port,
        graphql_url=resolved_graphql_url,
        openapi_file=openapi_file,
        test_case=test_case,
        test_cases_path=test_cases_path,
        test_set=test_set,
        http_client=effective_http_client,
        tls_verify=tls_verify,
        proxy=proxy,
        add_header=add_header,
        add_debug_header=add_debug_header,
        max_idle_conns=max_idle_conns,
        max_redirects=max_redirects,
        idle_conn_timeout=idle_conn_timeout,
        follow_cookies=follow_cookies,
        renew_session=renew_session,
        workers=workers,
        send_delay=send_delay,
        random_delay=random_delay,
        skip_waf_block_check=skip_waf_block_check,
        skip_waf_identification=skip_waf_identification,
        block_status_codes=block_codes,
        pass_status_codes=pass_codes,
        block_regex=block_regex,
        pass_regex=pass_regex,
        non_blocked_as_passed=non_blocked_as_passed,
        ignore_unresolved=ignore_unresolved,
        block_conn_reset=block_conn_reset,
        waf_name=waf_name,
        include_payloads=include_payloads,
        report_path=report_path,
        report_name=report_name,
        report_format=formats,
        no_email_report=no_email_report,
        email=email,
        hide_args_in_report=hide_args_in_report,
        http_headers=http_headers,
        log_level=log_level,
        auth_header=auth_header,
        auth_cookie=auth_cookie,
        login_url=login_url,
        login_body=login_body,
        targets_file=targets,
        payload_pack=payload_pack,
        test_rate_limit=test_rate_limit,
        fuzz_openapi=fuzz_openapi,
        test_cve=test_cve,
        cve_days=cve_days,
        compliance_frameworks=[f.strip() for f in compliance.split(",") if f.strip()] if compliance else [],
        compare=compare,
        slack_webhook=slack_webhook,
        teams_webhook=teams_webhook,
        schedule=schedule,
        threshold=score_threshold,
        ml_fast=ml_fast,
        ml_fast_threshold=ml_fast_threshold,
    )

    if not cfg.hide_args_in_report:
        cfg.args = normalized_args

    # ── Batch mode: scan multiple URLs from file ──
    if target_urls:
        results_summary: list[dict[str, object]] = []
        for idx, target_url in enumerate(target_urls, 1):
            logger.info(f"Batch scan {idx}/{len(target_urls)}", url=target_url)

            # Create per-target config copy
            import copy
            target_cfg = copy.deepcopy(cfg)
            target_cfg.url = target_url

            # Re-derive GraphQL URL from THIS target's URL when the user
            # didn't pass --graphqlURL. Previously every batch target
            # inherited the first target's auto-derived graphql URL, so
            # GraphQL pre-checks for targets 2..N hit the wrong host.
            if not graphql_url:
                target_cfg.graphql_url = _craft_graphql_url("", target_url)

            # Auto-generate per-target report name. Include port when it's
            # non-default (80/443) so two targets sharing a hostname but
            # different ports don't overwrite each other's reports.
            parsed = urlparse(target_url)
            host_part = (parsed.hostname or f"target-{idx}").replace(".", "-")
            if parsed.port and parsed.port not in (80, 443):
                host_part = f"{host_part}-{parsed.port}"
            target_cfg.report_name = f"waf-scan-{host_part}"

            try:
                asyncio.run(_run(target_cfg, log_format, is_include_payloads_flag_used))
                results_summary.append({"url": target_url, "status": "completed"})
            except KeyboardInterrupt:
                logger.info("Batch scan interrupted", completed=idx - 1, total=len(target_urls))
                raise SystemExit(0) from None
            except Exception as e:
                # Catch ANY exception (not just GoTestWAFError) so one
                # unreachable target doesn't kill the whole batch. The previous
                # narrow catch let RuntimeError / ConnectError / TimeoutError
                # propagate and silently abort remaining targets with no entry
                # in results_summary.
                logger.error(f"Scan failed for {target_url}", error=str(e), error_type=type(e).__name__)
                results_summary.append({"url": target_url, "status": "failed", "error": str(e)})

        # Print batch summary
        logger.info("=" * 60)
        logger.info(f"BATCH SCAN COMPLETE: {len(target_urls)} targets")
        for r in results_summary:
            status = r["status"]
            icon = "OK" if status == "completed" else "FAIL"
            logger.info(f"  [{icon}] {r['url']}")
        completed = sum(1 for r in results_summary if r["status"] == "completed")
        logger.info(f"Results: {completed}/{len(target_urls)} completed")
        logger.info(f"Reports saved to: {cfg.report_path}/")
        return

    # ── Single target mode ──
    try:
        if cfg.schedule:
            # Scheduled mode: run on cron schedule
            from gotestwaf.scheduler.scheduler import run_scheduled
            asyncio.run(run_scheduled(cfg, _run, log_format, is_include_payloads_flag_used))
        else:
            asyncio.run(_run(cfg, log_format, is_include_payloads_flag_used))
    except GoTestWAFError as e:
        logger.error("caught error in main function", error=str(e))
        raise SystemExit(1) from e
    except KeyboardInterrupt:
        logger.info("scan canceled", signal="SIGINT")
        raise SystemExit(0) from None


async def _run(cfg: Config, log_format: str, is_include_payloads_flag_used: bool) -> None:
    """Main async execution flow."""
    # Always clear the module-level report cache when this function exits,
    # whether normally or via exception. If an exception escaped after
    # `once_prepare_html_full_report` populated the cache (e.g. inside the
    # email path), the cache would have held the previous target's data
    # and the next batch iteration's email report would silently render
    # Target N-1's payload data with Target N's URL. Wrap with try/finally.
    from gotestwaf.report.html import reset_report_cache as _reset_report_cache
    try:
        await _run_impl(cfg, log_format, is_include_payloads_flag_used)
    finally:
        _reset_report_cache()


async def _run_impl(cfg: Config, log_format: str, is_include_payloads_flag_used: bool) -> None:
    """Main async execution flow (wrapped by `_run` for cache cleanup)."""
    from gotestwaf.db.database import DB
    from gotestwaf.db.export import export_payloads
    from gotestwaf.db.load import load_test_cases
    from gotestwaf.db.statistics import get_statistics
    from gotestwaf.report.console import render_console_report
    from gotestwaf.report.report import (
        ExportFullReport,
        IsNoneReportFormat,
        IsPdfOrHtmlReportFormat,
    )
    from gotestwaf.scanner.scanner import Scanner
    from gotestwaf.scanner.waf_detector.detector import WAFDetector

    logger.info("GoTestWAF started", version=VERSION)

    # ── Authentication (before any requests) ──
    if cfg.login_url and cfg.login_body:
        from gotestwaf.scanner.auth import perform_login, apply_auth_to_config
        login_cookies = await perform_login(cfg.login_url, cfg.login_body, cfg.tls_verify)
        apply_auth_to_config(cfg, cfg.auth_header, cfg.auth_cookie, login_cookies)
    elif cfg.auth_header or cfg.auth_cookie:
        from gotestwaf.scanner.auth import apply_auth_to_config
        apply_auth_to_config(cfg, cfg.auth_header, cfg.auth_cookie)

    # Load OpenAPI spec if provided
    request_templates = None
    router = None
    if cfg.openapi_file:
        from gotestwaf.openapi.loader import load_openapi_spec
        from gotestwaf.openapi.template import new_templates

        openapi_doc = load_openapi_spec(cfg.openapi_file)
        request_templates = new_templates(openapi_doc, cfg.url)

    # Load test cases
    logger.info("Test cases loading started")
    test_cases = load_test_cases(cfg)
    logger.info("Test cases loading finished")

    db = DB.from_test_cases(test_cases)
    logger.info("Test cases fingerprint", fp=db.hash)

    logger.info(f"{cfg.http_client} is used as an HTTP client to make requests", http_client=cfg.http_client)

    # Create and initialize scanner (solves CAPTCHA, sets up clients)
    scanner = Scanner(
        cfg, db,
        request_templates=request_templates,
        router=router,
        enable_debug_header=cfg.add_debug_header,
    )
    await scanner.initialize()

    try:
        # WAF identification — AFTER scanner init so session cookies are available
        if not cfg.skip_waf_identification:
            logger.info("Try to identify WAF solution")
            detector = WAFDetector(cfg)
            waf_name, vendor, check_func = await detector.detect_waf()

            if waf_name and vendor:
                logger.info("WAF identified", solution=waf_name, vendor=vendor)
                cfg.check_block_func = check_func
                cfg.waf_name = f"{waf_name} ({vendor})"

                SESSION_WAFS = {"Incapsula", "SecureSphere", "BIG-IP", "FirePass", "Trafficshield"}
                if any(sw in waf_name for sw in SESSION_WAFS):
                    cfg.follow_cookies = True
                    cfg.renew_session = True
                    logger.info("Session-based WAF: enabling followCookies and renewSession")
            else:
                logger.info("WAF was not identified")

        # JavaScript check (only for non-Chrome clients)
        if cfg.http_client != "chrome":
            is_js_required = await scanner.check_if_javascript_required()
            if is_js_required:
                msg = "JavaScript is required to interact with the endpoint"
                raise RuntimeError(msg)

        # Pre-checks
        if not cfg.skip_waf_block_check:
            await scanner.waf_block_check()
        else:
            logger.info("WAF pre-check", status="skipped")

        await scanner.check_grpc_availability()
        await scanner.check_graphql_availability()

        # Run scan
        await scanner.run()
    finally:
        # Always clean up browser processes
        if hasattr(scanner, '_session_mgr') and scanner._session_mgr:
            try:
                await scanner._session_mgr.stop()
            except Exception:
                pass
        if hasattr(scanner, '_http_client') and hasattr(scanner._http_client, 'close'):
            try:
                await scanner._http_client.close()
            except Exception:
                pass

    # ── Rate limit testing (opt-in only — takes 5+ minutes) ──
    rate_limit_result = None
    if cfg.test_rate_limit:
        try:
            from gotestwaf.scanner.rate_limit_tester import test_rate_limits
            logger.info("Starting rate limit test...")
            rate_limit_result = await test_rate_limits(cfg)
            logger.info("Rate limit result", **rate_limit_result.to_dict())
        except Exception as e:
            logger.debug("Rate limit test skipped", error=str(e))

    # ── CVE simulation (opt-in via --testCVE) ──
    cve_results = []
    if cfg.test_cve:
        try:
            from gotestwaf.scanner.cve_tester import fetch_recent_cves, generate_cve_payloads
            logger.info("Fetching recent web CVEs...", days=cfg.cve_days)
            cves = await fetch_recent_cves(cfg.cve_days)
            if cves:
                logger.info(f"Found {len(cves)} web-related CVEs from last {cfg.cve_days} days")
                for cve in cves[:10]:
                    payloads = generate_cve_payloads(cve)
                    cve_results.append({"id": cve["id"], "severity": cve.get("severity", "N/A"), "payloads": len(payloads)})
                    logger.info(f"  {cve['id']} ({cve.get('severity', '?')}): {len(payloads)} payloads")
        except Exception as e:
            logger.debug("CVE fetch skipped", error=str(e))

    # ── OpenAPI fuzzing (auto if spec was provided) ──
    if cfg.openapi_file:
        try:
            from gotestwaf.openapi.fuzzer import generate_ml_fuzz_payloads
            from gotestwaf.openapi.loader import load_openapi_spec
            fuzz_doc = load_openapi_spec(cfg.openapi_file)
            from gotestwaf.ml.model_store import load_scan_knowledge
            knowledge = load_scan_knowledge(cfg.waf_name)
            fuzz_payloads = generate_ml_fuzz_payloads(fuzz_doc, bypass_knowledge=knowledge)
            logger.info("OpenAPI ML fuzzer generated payloads", count=len(fuzz_payloads))
        except Exception as e:
            logger.warning("OpenAPI fuzzing failed", error=str(e))

    # ── ML post-scan analysis ──
    ml_analysis: dict[str, object] = {}
    try:
        ml_engine = scanner.ml_engine
        ml_metrics = ml_engine.get_metrics()

        if ml_metrics.get("is_trained"):
            logger.info("Running ML-enhanced bypass analysis...")

            # Use ACTUAL bypassed payloads as candidates (not re-prediction with empty data)
            bypass_candidates = []
            seen_payloads: set[str] = set()
            for bypassed_test in db.passed_tests[:200]:
                if bypassed_test.payload in seen_payloads:
                    continue
                seen_payloads.add(bypassed_test.payload)
                bypass_candidates.append({
                    "payload": bypassed_test.payload[:150],
                    "encoder": bypassed_test.encoder,
                    "placeholder": bypassed_test.placeholder,
                    "test_set": bypassed_test.set,
                    "test_case": bypassed_test.case,
                    "bypass_probability": 1.0,
                    "confidence": 0.95,
                    "attack_type": bypassed_test.type or "unknown",
                    "verdict": "passed",
                })

            bypass_candidates.sort(key=lambda x: x["test_case"])

            # Get top mutation suggestions for highest-probability bypasses
            mutation_suggestions = []
            for candidate in bypass_candidates[:5]:
                mutations = ml_engine.suggest_mutations(
                    candidate["payload"],
                    candidate["encoder"],
                    candidate["placeholder"],
                    top_k=3,
                )
                mutation_suggestions.append({
                    "payload": candidate["payload"][:100],
                    "test_case": candidate["test_case"],
                    "mutations": mutations[:3],
                })

            ml_analysis = {
                "metrics": ml_metrics,
                "bypass_candidates": bypass_candidates[:20],
                "mutation_suggestions": mutation_suggestions,
                "total_analyzed": len(db.blocked_tests),
                "high_bypass_risk": len([c for c in bypass_candidates if c["bypass_probability"] > 0.5]),
            }

            logger.info(
                "ML analysis complete",
                bypass_candidates=len(bypass_candidates),
                high_risk=ml_analysis["high_bypass_risk"],
            )
        else:
            logger.info("ML models not trained (insufficient data), skipping enhanced analysis")
    except Exception as e:
        logger.warning("ML post-scan analysis failed", error=str(e))

    # ── Auto Cloud WAF API Query (auto-detects provider from WAF name + env credentials) ──
    cloud_waf_config = None
    try:
        from gotestwaf.scanner.cloud_waf_query import auto_query_cloud_waf
        cloud_waf_config = auto_query_cloud_waf(cfg.waf_name, cfg.url)
        if cloud_waf_config and cloud_waf_config.rules:
            logger.info(f"Cloud WAF config loaded: {cloud_waf_config.waf_name}", rules=cloud_waf_config.rule_count)
            for rule in cloud_waf_config.rules:
                action = f"[{rule.action.upper()}]" if rule.action else ""
                transforms = f" transforms={rule.text_transformations}" if rule.text_transformations else ""
                logger.info(f"  {action} {rule.name}", type=rule.rule_type, vendor=rule.vendor or rule.managed_vendor, desc=(rule.description[:80] + transforms) if rule.description else "")
        elif cloud_waf_config and cloud_waf_config.error:
            logger.debug("Cloud WAF auto-query not available", reason=cloud_waf_config.error)
    except Exception as e:
        logger.debug("Cloud WAF auto-query skipped", error=str(e))

    # ── WAF Ruleset Inference ──
    ruleset_inference = None
    try:
        from gotestwaf.scanner.ruleset_inference import infer_rulesets
        ruleset_inference = infer_rulesets(db, cfg.waf_name)

        # Print to console
        logger.info("WAF Ruleset Inference:")
        for rs in ruleset_inference.detected:
            if rs.status == "detected":
                logger.info(f"  [DETECTED]  {rs.name}", confidence=f"{rs.confidence:.0%}", evidence=rs.evidence)
            elif rs.status == "cannot_verify":
                logger.info(f"  [UNVERIFIABLE] {rs.name}", evidence=rs.evidence)
        for rs in ruleset_inference.partial:
            logger.warning(f"  [PARTIAL]   {rs.name}", evidence=rs.evidence, fix=rs.recommendation)
        for rs in ruleset_inference.missing:
            logger.warning(f"  [MISSING]   {rs.name}", evidence=rs.evidence, fix=rs.recommendation)
    except Exception as e:
        logger.warning("Ruleset inference failed", error=str(e))

    # Generate reports
    report_dir = Path(cfg.report_path)
    report_dir.mkdir(parents=True, exist_ok=True)

    report_time = datetime.now()
    report_name_str = cfg.report_name
    if cfg.report_name == DEFAULT_REPORT_NAME:
        report_name_str = report_time.strftime(cfg.report_name)

    report_file = str(report_dir / report_name_str)

    stat = get_statistics(db, cfg.ignore_unresolved, cfg.non_blocked_as_passed)

    # ── Dump full ML metrics (per-class P/R/F1, calibration, ablation, LC) ──
    # Always emitted when training succeeded so the research-article
    # build can read verified numbers instead of fabricated ones.
    try:
        if ml_metrics.get("is_trained"):
            import json as _json
            metrics_path = report_file + "_metrics.json"
            n_blocked = int(ml_metrics.get("blocked", 0))
            n_bypassed = int(ml_metrics.get("bypassed", 0))
            with open(metrics_path, "w", encoding="utf-8") as f:
                _json.dump({
                    "scan": {
                        "url": cfg.url,
                        "waf_name": cfg.waf_name,
                        "blocked": n_blocked,
                        "bypassed": n_bypassed,
                        "samples_trained": ml_metrics.get("samples", 0),
                    },
                    "metrics": ml_metrics,
                }, f, indent=2, default=str)
            logger.info("ML metrics JSON written", path=metrics_path)
    except Exception as e:
        logger.warning("ML metrics JSON dump failed", error=str(e))

    # ── Compliance mapping (before reports so results are included) ──
    compliance_results = {}
    try:
        from gotestwaf.report.compliance import map_findings_to_compliance
        frameworks = cfg.compliance_frameworks if cfg.compliance_frameworks else ["pci-dss", "soc2", "iso27001", "nist"]
        compliance_results = map_findings_to_compliance(stat, frameworks)
        for fw, summary in compliance_results.items():
            logger.info(
                f"Compliance: {summary.framework}",
                passed=summary.passed, failed=summary.failed,
                partial=summary.partial, pct=f"{summary.compliance_pct:.0f}%",
            )
    except Exception as e:
        logger.debug("Compliance mapping failed", error=str(e))

    render_console_report(stat, report_time, cfg.waf_name, cfg.url, cfg.args, cfg.ignore_unresolved, log_format)

    if IsNoneReportFormat(cfg.report_format):
        return

    # Interactive payload prompt (mirrors Go behavior)
    effective_include_payloads = cfg.include_payloads
    if IsPdfOrHtmlReportFormat(cfg.report_format):
        ask_for_payloads = True
        if is_include_payloads_flag_used or cfg.no_email_report or cfg.email:
            ask_for_payloads = False

        if ask_for_payloads and _is_terminal():
            try:
                user_input = input("Do you want to include payload details to the report? ([y/N]): ")
                if user_input.strip().lower() == "y":
                    effective_include_payloads = True
            except (EOFError, KeyboardInterrupt):
                pass

    report_files = await ExportFullReport(
        stat, report_file, report_time, cfg.waf_name, cfg.url,
        cfg.openapi_file, cfg.args, cfg.ignore_unresolved,
        effective_include_payloads, cfg.report_format,
        ml_analysis=ml_analysis,
        ruleset_inference=ruleset_inference,
        compliance_results=compliance_results,
    )

    for f in report_files:
        ext = Path(f).suffix.upper().lstrip(".")
        logger.info(f"Export {ext} full report", filename=f)

    # Export payloads CSV
    payloads_file = f"{report_file}.csv"
    export_payloads(db, payloads_file)

    # Clear report cache to prevent stale data if run again in same process
    from gotestwaf.report.html import reset_report_cache
    reset_report_cache()

    # ── Save scan knowledge for cross-scan learning ──
    try:
        from gotestwaf.ml.model_store import save_scan_knowledge
        bypass_patterns = {}
        online_stats = scanner.online_ml.get_stats() if hasattr(scanner, 'online_ml') else {}
        for combo in online_stats.get("bypass_combos", []):
            if len(combo) >= 3:
                bypass_patterns[f"{combo[0]}|{combo[1]}"] = {"bypass_rate": combo[2]}
        save_scan_knowledge(
            waf_name=cfg.waf_name, target_url=cfg.url,
            bypass_patterns=bypass_patterns,
            model_metrics=ml_analysis.get("metrics", {}) if ml_analysis else {},
            inference_result=ruleset_inference,
        )
    except Exception as e:
        logger.debug("Failed to save scan knowledge", error=str(e))

    # ── Generate auto-fix configs ──
    autofix = None
    try:
        from gotestwaf.report.autofix import generate_autofix
        bypassed_cats = [
            {"name": r.test_case, "bypassed": r.bypassed, "sent": r.sent}
            for r in stat.true_positive_tests.summary_table if r.bypassed > 0
        ]
        autofix = generate_autofix(cfg.waf_name, ruleset_inference, bypassed_cats)
        # Save autofix JSON if EITHER primary fixes OR multi-cloud companion
        # fixes (AWS/Azure/GCP) are present. Previously this only fired when
        # the primary WAF generator produced fixes — for a generic WAF that
        # left the user with no recommendations even though Azure/GCP
        # equivalents were available.
        mc = autofix.get("multi_cloud") or {}
        mc_total = sum(len((mc.get(k) or {}).get("fixes", [])) for k in ("aws", "azure", "gcp"))
        if autofix.get("fixes") or mc_total > 0:
            autofix_path = f"{report_file}_autofix.json"
            from pathlib import Path as P
            P(autofix_path).write_text(json.dumps(autofix, indent=2), encoding="utf-8")
            primary_total = autofix.get("summary", {}).get("total_fixes", 0)
            logger.info(
                "Auto-fix config generated",
                path=autofix_path,
                primary_fixes=primary_total,
                multi_cloud_fixes=mc_total,
            )

            # Print summary
            for fix in (autofix.get("fixes") or [])[:5]:
                logger.info(f"  [{fix['priority']}] {fix['name']}: {fix['description'][:80]}")
            for cloud in ("aws", "azure", "gcp"):
                cloud_fixes = (mc.get(cloud) or {}).get("fixes", [])
                if cloud_fixes:
                    logger.info(f"  {cloud.upper()} companion: {len(cloud_fixes)} fixes available")

            # Generate boto3 deploy script for AWS WAF (uses primary aws_rules
            # OR multi-cloud aws.aws_rules so non-AWS targets still get the
            # AWS deployment helper).
            aws_rules_for_deploy = autofix.get("aws_rules") or (mc.get("aws") or {}).get("aws_rules") or []
            if aws_rules_for_deploy:
                deploy_path = f"{report_file}_deploy_fix.py"
                _generate_boto3_deploy_script(deploy_path, aws_rules_for_deploy)
                logger.info("Boto3 deploy script generated", path=deploy_path)
    except Exception as e:
        logger.debug("Auto-fix generation failed", error=str(e))

    # ── Generate Terraform/CloudFormation/Bicep/gcloud (IaC) ──
    # Always run if autofix exists — the IaC generator now emits
    # AWS Terraform+CloudFormation, Azure Bicep+az-CLI, and GCP
    # Terraform+gcloud scripts. The previous gate of `autofix.aws_rules`
    # meant non-AWS targets received NO IaC files at all.
    try:
        if autofix:
            from gotestwaf.report.iac_generator import generate_iac_files
            iac_files = generate_iac_files(report_file, cfg.waf_name, autofix)
            for f in iac_files:
                logger.info("IaC template generated", path=f)
    except Exception as e:
        logger.debug("IaC generation failed", error=str(e))

    # (Compliance already computed before report generation above)

    # ── Slack/Teams notifications ──
    if cfg.slack_webhook:
        try:
            from gotestwaf.helpers.notifications import send_slack_notification
            await send_slack_notification(cfg.slack_webhook, stat, cfg.waf_name, cfg.url, [f for f in report_files])
        except Exception as e:
            logger.debug("Slack notification failed", error=str(e))

    if cfg.teams_webhook:
        try:
            from gotestwaf.helpers.notifications import send_teams_notification
            await send_teams_notification(cfg.teams_webhook, stat, cfg.waf_name, cfg.url, [f for f in report_files])
        except Exception as e:
            logger.debug("Teams notification failed", error=str(e))

    # Email report handling
    if not cfg.no_email_report:
        email_addr = cfg.email

        if not email_addr and _is_terminal():
            try:
                email_addr = input("Email to send the report (ENTER to skip): ").strip()
            except (EOFError, KeyboardInterrupt):
                email_addr = ""

        if not email_addr:
            logger.info("Skip report sending to email")
            return

        from gotestwaf.helpers.email import validate_email
        try:
            email_addr = validate_email(email_addr)
        except Exception as e:
            logger.error("couldn't validate email", error=str(e))
            return

        from gotestwaf.report.email import send_email
        from gotestwaf.report.html import once_prepare_html_full_report
        report_data = once_prepare_html_full_report(
            stat, report_time, cfg.waf_name, cfg.url, cfg.openapi_file,
            cfg.args, cfg.ignore_unresolved, effective_include_payloads,
        )
        try:
            await send_email(report_data, email_addr)
        except Exception as e:
            logger.error("couldn't send report by email", error=str(e))
            return
        logger.info("The report has been sent to the specified email", email=email_addr)


def _generate_boto3_deploy_script(path: str, aws_rules: list) -> None:
    """Generate a complete boto3 Python script that merges new rules into existing Web ACL."""
    script = '''#!/usr/bin/env python3
"""Auto-generated AWS WAF fix deployment script.

Generated by GoTestWAF scanner. This script:
1. Lists all Web ACLs in your account
2. Lets you pick which one to update
3. Fetches existing rules
4. Merges the new rules (does NOT overwrite existing ones)
5. Applies the update

Prerequisites:
    pip install boto3
    aws configure  (or set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY)

Usage:
    python {filename}
    python {filename} --acl-name YourACLName --region us-east-1
    python {filename} --dry-run  (preview only, no changes)
"""

import argparse
import json
import sys

# Loaded via json.loads so JSON `true`/`false`/`null` literals are
# converted to Python `True`/`False`/`None` instead of crashing at
# import time with `NameError: name 'true' is not defined`.
NEW_RULES = json.loads(r"""{new_rules_json}""")

def main():
    parser = argparse.ArgumentParser(description="Deploy WAF fixes to AWS WAF")
    parser.add_argument("--acl-name", help="Web ACL name (auto-detect if not specified)")
    parser.add_argument("--acl-id", help="Web ACL ID")
    parser.add_argument("--region", default="", help="AWS region (auto-detect if not specified)")
    parser.add_argument("--scope", default="REGIONAL", choices=["REGIONAL", "CLOUDFRONT"])
    parser.add_argument("--profile", default="", help="AWS CLI profile name")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying")
    args = parser.parse_args()

    try:
        import boto3
    except ImportError:
        print("ERROR: boto3 not installed. Run: pip install boto3")
        sys.exit(1)

    # Create session
    session_kwargs = {{}}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    if args.region:
        session_kwargs["region_name"] = args.region

    session = boto3.Session(**session_kwargs)

    # Auto-detect region if not specified
    regions_to_try = [args.region] if args.region else [
        session.region_name or "us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"
    ]

    client = None
    web_acls = []
    used_region = ""

    for region in regions_to_try:
        try:
            client = session.client("wafv2", region_name=region)
            resp = client.list_web_acls(Scope=args.scope)
            web_acls = resp.get("WebACLs", [])
            if web_acls:
                used_region = region
                break
        except Exception:
            continue

    if not web_acls:
        print("ERROR: No Web ACLs found. Check your AWS credentials and region.")
        sys.exit(1)

    print(f"Found {{len(web_acls)}} Web ACL(s) in {{used_region}}:")
    for i, acl in enumerate(web_acls):
        print(f"  [{{i+1}}] {{acl['Name']}} ({{acl['Id'][:12]}}...)")

    # Select ACL
    if args.acl_name:
        matched = [a for a in web_acls if a["Name"] == args.acl_name]
        if not matched:
            print(f"ERROR: Web ACL '{{args.acl_name}}' not found")
            sys.exit(1)
        selected = matched[0]
    elif args.acl_id:
        matched = [a for a in web_acls if a["Id"] == args.acl_id]
        if not matched:
            print(f"ERROR: Web ACL ID '{{args.acl_id}}' not found")
            sys.exit(1)
        selected = matched[0]
    elif len(web_acls) == 1:
        selected = web_acls[0]
        print(f"Auto-selected: {{selected['Name']}}")
    else:
        choice = input(f"Select Web ACL [1-{{len(web_acls)}}]: ").strip()
        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(web_acls):
            print("Invalid choice")
            sys.exit(1)
        selected = web_acls[int(choice) - 1]

    acl_name = selected["Name"]
    acl_id = selected["Id"]

    # Fetch current config
    print(f"\\nFetching current config for '{{acl_name}}'...")
    resp = client.get_web_acl(Name=acl_name, Scope=args.scope, Id=acl_id)
    acl = resp["WebACL"]
    lock_token = resp["LockToken"]
    existing_rules = acl.get("Rules", [])
    existing_names = {{r["Name"] for r in existing_rules}}

    print(f"  Current rules: {{len(existing_rules)}}")
    for r in existing_rules:
        print(f"    [{{r.get('Priority', '?')}}] {{r['Name']}}")

    # Merge new rules (skip duplicates)
    rules_to_add = []
    max_priority = max((r.get("Priority", 0) for r in existing_rules), default=0)

    for new_rule in NEW_RULES:
        if new_rule["Name"] in existing_names:
            print(f"  SKIP: '{{new_rule['Name']}}' already exists")
        else:
            max_priority += 1
            new_rule["Priority"] = max_priority
            rules_to_add.append(new_rule)
            print(f"  ADD:  '{{new_rule['Name']}}' (priority {{max_priority}})")

    if not rules_to_add:
        print("\\nNo new rules to add. All fixes already applied!")
        sys.exit(0)

    merged_rules = existing_rules + rules_to_add

    print(f"\\nMerged rules: {{len(merged_rules)}} ({{len(existing_rules)}} existing + {{len(rules_to_add)}} new)")

    if args.dry_run:
        print("\\n[DRY RUN] Would update Web ACL with:")
        print(json.dumps(rules_to_add, indent=2))
        print("\\nRe-run without --dry-run to apply.")
        sys.exit(0)

    confirm = input(f"\\nApply {{len(rules_to_add)}} new rules to '{{acl_name}}'? [y/N]: ").strip().lower()
    if confirm != "y":
        print("Cancelled.")
        sys.exit(0)

    # Apply update
    try:
        client.update_web_acl(
            Name=acl_name,
            Scope=args.scope,
            Id=acl_id,
            LockToken=lock_token,
            DefaultAction=acl.get("DefaultAction", {{"Allow": {{}}}}),
            Rules=merged_rules,
            VisibilityConfig=acl.get("VisibilityConfig", {{
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": acl_name,
            }}),
        )
        print(f"\\nSUCCESS: {{len(rules_to_add)}} rules added to '{{acl_name}}'!")
        print("\\nNew rules added:")
        for r in rules_to_add:
            print(f"  [{{r['Priority']}}] {{r['Name']}}")
        print("\\nRe-run GoTestWAF scan to verify the fixes.")
    except Exception as e:
        print(f"\\nERROR: Failed to update Web ACL: {{e}}")
        print("\\nThe rules JSON has been saved — you can apply manually in AWS Console.")
        sys.exit(1)

if __name__ == "__main__":
    main()
'''.format(
        filename=os.path.basename(path),
        new_rules_json=json.dumps(aws_rules, indent=4),
    )
    from pathlib import Path as P
    P(path).write_text(script, encoding="utf-8")


if __name__ == "__main__":
    app()
