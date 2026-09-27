"""Configuration loading and parsing for GoTestWAF."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from gotestwaf.scanner.waf_detector.detectors.checks import Responses


@dataclass
class Config:
    """GoTestWAF configuration mirroring the Go Config struct."""

    # Target settings
    url: str = ""
    grpc_port: int = 0
    graphql_url: str = ""
    openapi_file: str = ""

    # Test cases settings
    test_case: str = ""
    test_cases_path: str = "testcases"
    test_set: str = ""

    # HTTP client settings
    http_client: str = "gohttp"
    tls_verify: bool = False
    proxy: str = ""
    add_header: str = ""
    add_debug_header: bool = False

    # GoHTTP client only settings
    max_idle_conns: int = 2
    max_redirects: int = 50
    idle_conn_timeout: int = 2
    follow_cookies: bool = False
    renew_session: bool = False

    # Performance settings
    workers: int = 5
    random_delay: int = 400
    send_delay: int = 400

    # Analysis settings
    skip_waf_block_check: bool = False
    skip_waf_identification: bool = False
    block_status_codes: list[int] = field(default_factory=lambda: [403])
    pass_status_codes: list[int] = field(default_factory=lambda: [200, 404])
    block_regex: str = ""
    pass_regex: str = ""
    non_blocked_as_passed: bool = False
    ignore_unresolved: bool = False
    block_conn_reset: bool = False

    # Report settings
    waf_name: str = "generic"
    include_payloads: bool = False
    report_path: str = "reports"
    report_name: str = "waf-evaluation-report-2006-January-02-15-04-05"
    report_format: list[str] = field(default_factory=lambda: ["pdf"])
    no_email_report: bool = False
    email: str = ""
    hide_args_in_report: bool = False

    # Config file headers
    http_headers: dict[str, str] = field(default_factory=dict)

    # Other settings
    log_level: str = "info"

    # Authentication
    auth_header: str = ""
    auth_cookie: str = ""
    login_url: str = ""
    login_body: str = ""

    # Multi-target
    targets_file: str = ""

    # Payload packs
    payload_pack: str = ""

    # Rate limit testing
    test_rate_limit: bool = False

    # OpenAPI fuzzing
    fuzz_openapi: bool = False

    # CVE testing
    test_cve: bool = False
    cve_days: int = 30

    # Compliance
    compliance_frameworks: list[str] = field(default_factory=list)

    # WAF comparison
    compare: str = ""

    # Notifications
    slack_webhook: str = ""
    teams_webhook: str = ""

    # Scheduling
    schedule: str = ""
    threshold: float = 0.0

    # Cross-scan ML fast mode. When ml_fast is on AND a prior trained model
    # for this WAF type exists on disk, payloads are reordered by predicted
    # bypass probability so high-value cases fire first. If ml_fast_threshold
    # > 0, payloads scoring below the threshold are skipped entirely (trades
    # coverage for speed). Default: off — preserves full-coverage behavior.
    ml_fast: bool = False
    ml_fast_threshold: float = 0.0

    # Runtime-set fields (not from config file).
    check_block_func: Any = None
    args: list[str] = field(default_factory=list)


def load_config_from_yaml(config_path: str) -> dict[str, Any]:
    """Load configuration from a YAML file.

    Args:
        config_path: Path to the YAML config file.

    Returns:
        Dictionary of configuration values from the YAML file.
    """
    from ruamel.yaml import YAML

    yaml = YAML()
    from pathlib import Path

    path = Path(config_path)
    if not path.exists():
        return {}

    with path.open(encoding="utf-8") as f:
        data = yaml.load(f)

    if data is None:
        return {}

    return dict(data)
