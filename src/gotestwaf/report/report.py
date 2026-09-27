"""Report generation, validation, and export orchestration."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from gotestwaf.errors import ReportError

if TYPE_CHECKING:
    from gotestwaf.db.statistics import Statistics

NONE_FORMAT = "none"
JSON_FORMAT = "json"
HTML_FORMAT = "html"
PDF_FORMAT = "pdf"
XLSX_FORMAT = "xlsx"

REPORT_FORMATS_SET = {NONE_FORMAT, JSON_FORMAT, HTML_FORMAT, PDF_FORMAT, XLSX_FORMAT}
ReportFormats = sorted(REPORT_FORMATS_SET)

MAX_REPORT_FILENAME_LENGTH = 249


def ValidateReportFormat(formats: list[str]) -> None:
    """Validate report format list.

    Raises:
        ReportError: If formats are invalid.
    """
    if not formats:
        msg = "no report format specified"
        raise ReportError(msg)

    seen: set[str] = set()
    for fmt in formats:
        if fmt not in REPORT_FORMATS_SET:
            msg = f"unknown report format: {fmt}"
            raise ReportError(msg)
        if fmt in seen:
            msg = f"found duplicated values: {','.join(formats)}"
            raise ReportError(msg)
        seen.add(fmt)

    if NONE_FORMAT in seen and len(seen) > 1:
        others = seen - {NONE_FORMAT}
        msg = f'"none" conflicts with other formats: {",".join(sorted(others))}'
        raise ReportError(msg)


def IsNoneReportFormat(report_format: list[str]) -> bool:
    """Check if report format is 'none'."""
    return len(report_format) > 0 and report_format[0] == NONE_FORMAT


def IsPdfOrHtmlReportFormat(report_formats: list[str]) -> bool:
    """Check if any format is PDF or HTML."""
    return any(fmt in (PDF_FORMAT, HTML_FORMAT) for fmt in report_formats)


async def ExportFullReport(
    stat: Statistics,
    report_file: str,
    report_time: datetime,
    waf_name: str,
    url: str,
    openapi_file: str,
    args: list[str],
    ignore_unresolved: bool,
    include_payloads: bool,
    formats: list[str],
    ml_analysis: dict[str, object] | None = None,
    ruleset_inference: object | None = None,
    compliance_results: dict[str, object] | None = None,
    rate_limit_result: object | None = None,
    cve_results: list[dict] | None = None,
) -> list[str]:
    """Export full report in specified formats.

    Args:
        stat: Test statistics.
        report_file: Base path for report file (without extension).
        report_time: Time of report generation.
        waf_name: WAF product name.
        url: Target URL.
        openapi_file: OpenAPI file path (if used).
        args: CLI arguments.
        ignore_unresolved: Whether unresolved tests are ignored.
        include_payloads: Whether to include payload details.
        formats: List of output formats.

    Returns:
        List of generated report file paths.
    """
    filename = Path(report_file).name
    if len(filename) > MAX_REPORT_FILENAME_LENGTH:
        msg = "report filename too long"
        raise ReportError(msg)

    report_files: list[str] = []

    for fmt in formats:
        match fmt:
            case "html":
                report_name = f"{report_file}.html"
                _print_full_report_to_html(
                    stat, report_name, report_time, waf_name, url, openapi_file,
                    args, ignore_unresolved, include_payloads, ml_analysis,
                    ruleset_inference, compliance_results,
                )
                report_files.append(report_name)

            case "pdf":
                report_name = f"{report_file}.pdf"
                await _print_full_report_to_pdf(
                    stat, report_name, report_time, waf_name, url, openapi_file,
                    args, ignore_unresolved, include_payloads, ml_analysis,
                    ruleset_inference, compliance_results,
                )
                report_files.append(report_name)

            case "json":
                report_name = f"{report_file}.json"
                _print_full_report_to_json(
                    stat, report_name, report_time, waf_name, url,
                    args, ignore_unresolved,
                )
                report_files.append(report_name)

            case "xlsx" | "excel":
                report_name = f"{report_file}.xlsx"
                from gotestwaf.report.excel import generate_excel_report
                generate_excel_report(
                    stat, report_name, report_time, waf_name, url,
                    args, ignore_unresolved, include_payloads, ml_analysis,
                    ruleset_inference, compliance_results,
                )
                report_files.append(report_name)

            case "none":
                return []

    # Generate Excel alongside other formats if not already requested
    xlsx_name = f"{report_file}.xlsx"
    if not any(f.endswith(".xlsx") for f in report_files):
        try:
            from gotestwaf.report.excel import generate_excel_report
            generate_excel_report(
                stat, xlsx_name, report_time, waf_name, url,
                args, ignore_unresolved, include_payloads, ml_analysis,
                ruleset_inference, compliance_results,
            )
            report_files.append(xlsx_name)
        except Exception as exc:
            structlog.get_logger().debug("Bonus Excel generation skipped", error=str(exc))

    return report_files


def _print_full_report_to_json(
    s: Statistics,
    report_file: str,
    report_time: datetime,
    waf_name: str,
    url: str,
    args: list[str],
    ignore_unresolved: bool,
) -> None:
    """Generate JSON report file."""
    import orjson

    report = {
        "date": report_time.strftime("%c"),
        "project_name": waf_name,
        "url": url,
        "score": s.score.average,
        "fp": s.test_cases_fingerprint,
        "args": " ".join(args),
        "summary": _build_summary(s),
    }

    data = orjson.dumps(report, option=orjson.OPT_INDENT_2)
    Path(report_file).write_bytes(data)


def _print_full_report_to_html(
    s: Statistics,
    report_file: str,
    report_time: datetime,
    waf_name: str,
    url: str,
    openapi_file: str,
    args: list[str],
    ignore_unresolved: bool,
    include_payloads: bool,
    ml_analysis: dict[str, object] | None = None,
    ruleset_inference: object | None = None,
    compliance_results: dict[str, object] | None = None,
) -> None:
    """Generate 3D HTML report with Three.js, Chart.js, Kill Chain, and MITRE ATT&CK."""
    from gotestwaf.report.report3d import generate_3d_html_report

    html_content = generate_3d_html_report(
        s, report_time, waf_name, url, args, ignore_unresolved, include_payloads,
        ml_analysis=ml_analysis,
        ruleset_inference=ruleset_inference,
        compliance_results=compliance_results,
    )
    Path(report_file).write_text(html_content, encoding="utf-8")


def _build_summary(s: Statistics) -> dict[str, object]:
    """Build summary dict for JSON report."""

    def _tests_info(tests: object) -> dict[str, object]:
        from gotestwaf.db.statistics import TestsSummary
        if not isinstance(tests, TestsSummary):
            return {}

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

        return {
            "score": tests.resolved_blocked_requests_percentage,
            "summary": {
                "total_sent": tests.req_stats.all_requests_number,
                "resolved_tests": tests.req_stats.resolved_requests_number,
                "blocked_tests": tests.req_stats.blocked_requests_number,
                "bypassed_tests": tests.req_stats.bypassed_requests_number,
                "unresolved_tests": tests.req_stats.unresolved_requests_number,
                "failed_tests": tests.req_stats.failed_requests_number,
            },
            "test_sets": test_sets,
        }

    return {
        "true_positive_tests": _tests_info(s.true_positive_tests),
        "true_negative_tests": _tests_info(s.true_negative_tests),
    }


async def _print_full_report_to_pdf(
    s: Statistics,
    report_file: str,
    report_time: datetime,
    waf_name: str,
    url: str,
    openapi_file: str,
    args: list[str],
    ignore_unresolved: bool,
    include_payloads: bool,
    ml_analysis: dict[str, object] | None = None,
    ruleset_inference: object | None = None,
    compliance_results: dict[str, object] | None = None,
) -> None:
    """Generate PDF report via HTML rendering with Playwright."""
    import tempfile

    from gotestwaf.report.render import render_to_pdf

    # Generate HTML to a temp file
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as tmp:
        tmp_path = tmp.name

    _print_full_report_to_html(
        s, tmp_path, report_time, waf_name, url, openapi_file,
        args, ignore_unresolved, include_payloads, ml_analysis,
        ruleset_inference, compliance_results,
    )

    # Convert file path to file:// URL
    file_url = Path(tmp_path).as_uri()

    try:
        await render_to_pdf(file_url, report_file)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
