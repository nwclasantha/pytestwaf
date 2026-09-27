"""Console report rendering in text and JSON formats."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

import orjson
from tabulate import tabulate

if TYPE_CHECKING:
    from gotestwaf.db.statistics import Statistics


def render_console_report(
    s: Statistics,
    report_time: datetime,
    waf_name: str,
    url: str,
    args: list[str],
    ignore_unresolved: bool,
    fmt: str,
) -> None:
    """Print a console report in the specified format.

    Args:
        s: Test statistics.
        report_time: Report generation time.
        waf_name: WAF product name.
        url: Target URL.
        args: CLI arguments.
        ignore_unresolved: Whether unresolved tests are ignored.
        fmt: Output format ('text' or 'json').
    """
    match fmt:
        case "text":
            _print_console_report_table(s, report_time, waf_name, ignore_unresolved)
        case "json":
            _print_console_report_json(s, report_time, waf_name, url, args)
        case _:
            msg = f"unknown report format: {fmt}"
            raise ValueError(msg)


def _print_console_report_table(
    s: Statistics,
    report_time: datetime,
    waf_name: str,
    ignore_unresolved: bool,
) -> None:
    """Print tabular console report."""
    base_header = ["Test set", "Test case", "Percentage, %", "Blocked", "Bypassed"]
    if not ignore_unresolved:
        base_header.append("Unresolved")
    base_header.extend(["Sent", "Failed"])

    print("True-Positive Tests:")
    rows = []
    for row in s.true_positive_tests.summary_table:
        r = [row.test_set, row.test_case, f"{row.percentage:.2f}", str(row.blocked), str(row.bypassed)]
        if not ignore_unresolved:
            r.append(str(row.unresolved))
        r.extend([str(row.sent), str(row.failed)])
        rows.append(r)
    print(tabulate(rows, headers=base_header, tablefmt="grid"))

    tp = s.true_positive_tests
    print(f"\n  Date: {report_time.strftime('%Y-%m-%d')}")
    print(f"  Project Name: {waf_name}")
    print(f"  True-Positive Score: {tp.resolved_blocked_requests_percentage:.2f}%")
    print(
        f"  Blocked (Resolved): {tp.req_stats.blocked_requests_number}/{tp.req_stats.resolved_requests_number}"
        f" ({tp.resolved_blocked_requests_percentage:.2f}%)"
    )
    print(
        f"  Bypassed (Resolved): {tp.req_stats.bypassed_requests_number}/{tp.req_stats.resolved_requests_number}"
        f" ({tp.resolved_bypassed_requests_percentage:.2f}%)"
    )
    print(f"  Total Sent: {tp.req_stats.all_requests_number}")
    print(
        f"  Failed (Total): {tp.req_stats.failed_requests_number}/{tp.req_stats.all_requests_number}"
        f" ({tp.failed_requests_percentage:.2f}%)"
    )

    print("\nTrue-Negative Tests:")
    rows = []
    for row in s.true_negative_tests.summary_table:
        r = [row.test_set, row.test_case, f"{row.percentage:.2f}", str(row.blocked), str(row.bypassed)]
        if not ignore_unresolved:
            r.append(str(row.unresolved))
        r.extend([str(row.sent), str(row.failed)])
        rows.append(r)
    print(tabulate(rows, headers=base_header, tablefmt="grid"))

    tn = s.true_negative_tests
    print(f"\n  Date: {report_time.strftime('%Y-%m-%d')}")
    print(f"  Project Name: {waf_name}")
    print(f"  True-Negative Score: {tn.resolved_bypassed_requests_percentage:.2f}%")
    print(f"  Total Sent: {tn.req_stats.all_requests_number}")

    print("\nSummary:")
    summary_header = ["Type", "True-Positive tests blocked", "True-Negative tests passed", "Average"]
    summary_rows = []

    def fmt_score(v: float) -> str:
        return f"{v:.2f}%" if v != -1.0 else "n/a"

    summary_rows.append([
        "API Security",
        fmt_score(s.score.api_sec.true_positive),
        fmt_score(s.score.api_sec.true_negative),
        fmt_score(s.score.api_sec.average),
    ])
    summary_rows.append([
        "Application Security",
        fmt_score(s.score.app_sec.true_positive),
        fmt_score(s.score.app_sec.true_negative),
        fmt_score(s.score.app_sec.average),
    ])

    print(tabulate(summary_rows, headers=summary_header, tablefmt="grid"))
    print(f"\n  Score: {fmt_score(s.score.average)}")


def _build_request_stats(rs: object) -> dict[str, int]:
    """Build request stats dict matching Go's requestStats JSON struct."""
    from gotestwaf.db.statistics import RequestStats
    if not isinstance(rs, RequestStats):
        return {}
    return {
        "total_sent": rs.all_requests_number,
        "resolved_tests": rs.resolved_requests_number,
        "blocked_tests": rs.blocked_requests_number,
        "bypassed_tests": rs.bypassed_requests_number,
        "unresolved_tests": rs.unresolved_requests_number,
        "failed_tests": rs.failed_requests_number,
    }


def _build_tests_info(tests: object, use_blocked_pct: bool = True) -> dict[str, object] | None:
    """Build testsInfo JSON matching Go's struct."""
    from gotestwaf.db.statistics import TestsSummary
    if not isinstance(tests, TestsSummary) or not tests.summary_table:
        return None

    test_sets: dict[str, dict[str, object]] = {}
    for row in tests.summary_table:
        test_sets.setdefault(row.test_set, {})
        test_sets[row.test_set][row.test_case] = {
            "percentage": row.percentage,
            "sent": row.sent,
            "blocked": row.blocked,
            "bypassed": row.bypassed,
            "unresolved": row.unresolved,
            "failed": row.failed,
        }

    score = tests.resolved_blocked_requests_percentage if use_blocked_pct else tests.resolved_bypassed_requests_percentage

    return {
        "score": score,
        "summary": _build_request_stats(tests.req_stats),
        "api_sec": _build_request_stats(tests.api_sec_req_stats),
        "app_sec": _build_request_stats(tests.app_sec_req_stats),
        "test_sets": test_sets,
    }


def _print_console_report_json(
    s: Statistics,
    report_time: datetime,
    waf_name: str,
    url: str,
    args: list[str],
) -> None:
    """Print JSON console report matching Go's printConsoleReportJson output."""
    report: dict[str, object] = {
        "date": report_time.strftime("%c"),
        "project_name": waf_name,
        "url": url,
        "fp": s.test_cases_fingerprint,
        "args": " ".join(args),
        "score": s.score.average,
    }

    tp_info = _build_tests_info(s.true_positive_tests, use_blocked_pct=True)
    if tp_info is not None:
        report["true_positive_tests"] = tp_info

    tn_info = _build_tests_info(s.true_negative_tests, use_blocked_pct=False)
    if tn_info is not None:
        report["true_negative_tests"] = tn_info

    data = orjson.dumps(report)
    print(data.decode("utf-8"))
