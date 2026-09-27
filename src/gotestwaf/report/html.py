"""HTML report preparation and rendering.

Mirrors Go's internal/report/html.go — prepares the full HtmlReport data
structure and renders it using the Jinja2 template.
"""

from __future__ import annotations

import html
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from gotestwaf.db.helpers import round_value
from gotestwaf.report.chart import generate_chart_data
from gotestwaf.report.helpers import get_grade, truncate_payload
from gotestwaf.version import VERSION

if TYPE_CHECKING:
    from gotestwaf.db.statistics import Statistics

NA_MARK = "N/A"

# Comparison table data (matches Go's comparisonTable)
COMPARISON_TABLE = [
    {"name": "ModSecurity PARANOIA=1", "api_sec": get_grade(42.86), "app_sec": get_grade(68.16), "overall_score": get_grade(55.51)},
    {"name": "ModSecurity PARANOIA=2", "api_sec": get_grade(57.14), "app_sec": get_grade(60.12), "overall_score": get_grade(58.63)},
    {"name": "ModSecurity PARANOIA=3", "api_sec": get_grade(78.57), "app_sec": get_grade(51.24), "overall_score": get_grade(64.91)},
    {"name": "ModSecurity PARANOIA=4", "api_sec": get_grade(100.00), "app_sec": get_grade(36.74), "overall_score": get_grade(68.37)},
]

WALLARM_RESULT = {
    "name": "Wallarm",
    "api_sec": get_grade(100.0),
    "app_sec": get_grade(97.74),
    "overall_score": get_grade(98.87),
}

# Cache for once-prepared report data
_prepare_lock = threading.Lock()
_cached_report_data: dict[str, Any] | None = None


def map_keys_to_string(m: dict[str, Any], sep: str) -> str:
    """Concatenate all keys of a map with a separator."""
    return sep.join(m.keys())


def prepare_html_full_report(
    s: Statistics,
    report_time: datetime,
    waf_name: str,
    url: str,
    openapi_file: str,
    args: list[str],
    ignore_unresolved: bool,
    include_payloads: bool,
) -> dict[str, Any]:
    """Prepare data for the HTML template. Mirrors Go's prepareHTMLFullReport."""
    data: dict[str, Any] = {
        "ignore_unresolved": ignore_unresolved,
        "include_payloads": include_payloads,
        "waf_name": waf_name,
        "url": url,
        "waf_testing_date": report_time.strftime("%d %B %Y"),
        "gtw_version": VERSION,
        "test_cases_fp": s.test_cases_fingerprint,
        "open_api_file": openapi_file,
        "args": args,
        "comparison_table": COMPARISON_TABLE,
        "wallarm_result": WALLARM_RESULT,
    }

    # Grade computation
    data["api_sec"] = {
        "true_positive_grade": get_grade(s.score.api_sec.true_positive, na=s.score.api_sec.true_positive < 0),
        "true_negative_grade": get_grade(s.score.api_sec.true_negative, na=s.score.api_sec.true_negative < 0),
        "grade": get_grade(s.score.api_sec.average, na=s.score.api_sec.average < 0),
    }
    data["app_sec"] = {
        "true_positive_grade": get_grade(s.score.app_sec.true_positive, na=s.score.app_sec.true_positive < 0),
        "true_negative_grade": get_grade(s.score.app_sec.true_negative, na=s.score.app_sec.true_negative < 0),
        "grade": get_grade(s.score.app_sec.average, na=s.score.app_sec.average < 0),
    }
    data["overall"] = get_grade(s.score.average, na=s.score.average < 0)

    # Chart data
    api_indicators, api_items, app_indicators, app_items = generate_chart_data(s)
    data["api_sec_chart_data"] = {"indicators": api_indicators, "items": api_items}
    data["app_sec_chart_data"] = {"indicators": app_indicators, "items": app_items}

    # True Positive summary table grouped by test set
    tp_summary: dict[str, dict[str, Any]] = {}
    for row in s.true_positive_tests.summary_table:
        if row.test_set not in tp_summary:
            tp_summary[row.test_set] = {
                "test_cases": [], "percentage": 0.0, "sent": 0, "blocked": 0,
                "bypassed": 0, "unresolved": 0, "failed": 0, "resolved_test_cases_number": 0,
            }
        ts = tp_summary[row.test_set]
        ts["test_cases"].append(row)
        ts["sent"] += row.sent
        ts["blocked"] += row.blocked
        ts["bypassed"] += row.bypassed
        ts["unresolved"] += row.unresolved
        ts["failed"] += row.failed
        if row.blocked + row.bypassed != 0:
            ts["resolved_test_cases_number"] += 1
            ts["percentage"] += row.percentage
    for ts in tp_summary.values():
        if ts["resolved_test_cases_number"] > 0:
            ts["percentage"] = round_value(ts["percentage"] / ts["resolved_test_cases_number"])

    # True Negative summary table grouped by test set
    tn_summary: dict[str, dict[str, Any]] = {}
    for row in s.true_negative_tests.summary_table:
        if row.test_set not in tn_summary:
            tn_summary[row.test_set] = {
                "test_cases": [], "percentage": 0.0, "sent": 0, "blocked": 0,
                "bypassed": 0, "unresolved": 0, "failed": 0, "resolved_test_cases_number": 0,
            }
        ts = tn_summary[row.test_set]
        ts["test_cases"].append(row)
        ts["sent"] += row.sent
        ts["blocked"] += row.blocked
        ts["bypassed"] += row.bypassed
        ts["unresolved"] += row.unresolved
        ts["failed"] += row.failed
        if row.blocked + row.bypassed != 0:
            ts["resolved_test_cases_number"] += 1
            ts["percentage"] += row.percentage
    for ts in tn_summary.values():
        if ts["resolved_test_cases_number"] > 0:
            ts["percentage"] = round_value(ts["percentage"] / ts["resolved_test_cases_number"])

    # Payload deduplication for include_payloads mode
    tp_bypassed: dict[str, dict[str, dict[int, dict[str, Any]]]] = {}
    tp_unresolved: dict[str, dict[int, dict[str, Any]]] = {}
    tn_blocked: dict[str, dict[int, dict[str, Any]]] = {}
    tn_bypassed: dict[str, dict[int, dict[str, Any]]] = {}
    tn_unresolved: dict[str, dict[int, dict[str, Any]]] = {}

    # Collect full request/response evidence for bypasses (non-deduplicated)
    bypass_evidence: list[dict[str, Any]] = []

    if include_payloads:
        for d in s.true_positive_tests.bypasses:
            paths = "\n".join(d.additional_info)
            payload = truncate_payload(d.payload)
            tp_bypassed.setdefault(paths, {}).setdefault(payload, {}).setdefault(d.response_status_code, {
                "test_case": "", "encoders": {}, "placeholders": {},
            })
            entry = tp_bypassed[paths][payload][d.response_status_code]
            entry["test_case"] = d.test_case
            entry["encoders"][d.encoder] = None
            entry["placeholders"][d.placeholder] = None

            # Collect full evidence for each bypass
            if d.request_url or d.response_body:
                bypass_evidence.append({
                    "payload": d.payload[:500],
                    "test_set": d.test_set,
                    "test_case": d.test_case,
                    "encoder": d.encoder,
                    "placeholder": d.placeholder,
                    "status_code": d.response_status_code,
                    "request_method": d.request_method,
                    "request_url": d.request_url,
                    "request_headers": d.request_headers,
                    "request_body": d.request_body,
                    "response_headers": d.response_headers,
                    "response_body": d.response_body[:2000] if d.response_body else "",
                })

        for d in s.true_positive_tests.unresolved:
            payload = truncate_payload(d.payload)
            tp_unresolved.setdefault(payload, {}).setdefault(d.response_status_code, {
                "test_case": "", "encoders": {}, "placeholders": {},
            })
            entry = tp_unresolved[payload][d.response_status_code]
            entry["test_case"] = d.test_case
            entry["encoders"][d.encoder] = None
            entry["placeholders"][d.placeholder] = None

        for d in s.true_negative_tests.blocked:
            payload = truncate_payload(d.payload)
            tn_blocked.setdefault(payload, {}).setdefault(d.response_status_code, {
                "test_case": "", "encoders": {}, "placeholders": {},
            })
            entry = tn_blocked[payload][d.response_status_code]
            entry["test_case"] = d.test_case
            entry["encoders"][d.encoder] = None
            entry["placeholders"][d.placeholder] = None

        for d in s.true_negative_tests.bypasses:
            payload = truncate_payload(d.payload)
            tn_bypassed.setdefault(payload, {}).setdefault(d.response_status_code, {
                "test_case": "", "encoders": {}, "placeholders": {},
            })
            entry = tn_bypassed[payload][d.response_status_code]
            entry["test_case"] = d.test_case
            entry["encoders"][d.encoder] = None
            entry["placeholders"][d.placeholder] = None

        for d in s.true_negative_tests.unresolved:
            payload = truncate_payload(d.payload)
            tn_unresolved.setdefault(payload, {}).setdefault(d.response_status_code, {
                "test_case": "", "encoders": {}, "placeholders": {},
            })
            entry = tn_unresolved[payload][d.response_status_code]
            entry["test_case"] = d.test_case
            entry["encoders"][d.encoder] = None
            entry["placeholders"][d.placeholder] = None

    data["true_positive_tests"] = {
        "summary_table": tp_summary,
        "bypassed": tp_bypassed,
        "unresolved": tp_unresolved,
        "failed": s.true_positive_tests.failed,
        "percentage": s.true_positive_tests.resolved_blocked_requests_percentage,
        "total_sent": s.true_positive_tests.req_stats.all_requests_number,
        "blocked_requests_number": s.true_positive_tests.req_stats.blocked_requests_number,
        "bypassed_requests_number": s.true_positive_tests.req_stats.bypassed_requests_number,
        "unresolved_requests_number": s.true_positive_tests.req_stats.unresolved_requests_number,
        "failed_requests_number": s.true_positive_tests.req_stats.failed_requests_number,
    }

    data["bypass_evidence"] = bypass_evidence

    data["true_negative_tests"] = {
        "summary_table": tn_summary,
        "blocked": tn_blocked,
        "bypassed": tn_bypassed,
        "unresolved": tn_unresolved,
        "failed": s.true_negative_tests.failed,
        "percentage": s.true_negative_tests.resolved_bypassed_requests_percentage,
        "total_sent": s.true_negative_tests.req_stats.all_requests_number,
        "blocked_requests_number": s.true_negative_tests.req_stats.blocked_requests_number,
        "bypassed_requests_number": s.true_negative_tests.req_stats.bypassed_requests_number,
        "unresolved_requests_number": s.true_negative_tests.req_stats.unresolved_requests_number,
        "failed_requests_number": s.true_negative_tests.req_stats.failed_requests_number,
    }

    data["total_sent"] = (
        data["true_positive_tests"]["total_sent"] + data["true_negative_tests"]["total_sent"]
    )
    data["blocked_requests_number"] = (
        data["true_positive_tests"]["blocked_requests_number"]
        + data["true_negative_tests"]["blocked_requests_number"]
    )
    data["bypassed_requests_number"] = (
        data["true_positive_tests"]["bypassed_requests_number"]
        + data["true_negative_tests"]["bypassed_requests_number"]
    )
    data["unresolved_requests_number"] = (
        data["true_positive_tests"]["unresolved_requests_number"]
        + data["true_negative_tests"]["unresolved_requests_number"]
    )
    data["failed_requests_number"] = (
        data["true_positive_tests"]["failed_requests_number"]
        + data["true_negative_tests"]["failed_requests_number"]
    )

    data["scanned_paths"] = s.paths

    return data


def once_prepare_html_full_report(
    s: Statistics,
    report_time: datetime,
    waf_name: str,
    url: str,
    openapi_file: str,
    args: list[str],
    ignore_unresolved: bool,
    include_payloads: bool,
) -> dict[str, Any]:
    """Cache-once version of prepare_html_full_report. Mirrors Go's sync.Once."""
    global _cached_report_data
    with _prepare_lock:
        if _cached_report_data is None:
            _cached_report_data = prepare_html_full_report(
                s, report_time, waf_name, url, openapi_file,
                args, ignore_unresolved, include_payloads,
            )
        return _cached_report_data


def reset_report_cache() -> None:
    """Clear the cached report data. Must be called between scans."""
    global _cached_report_data
    with _prepare_lock:
        _cached_report_data = None


def render_full_report_to_html(report_data: dict[str, Any]) -> str:
    """Render the full HTML report using Jinja2 template.

    Uses the Go HTML template converted to Jinja2 syntax, or falls back
    to a Python-native template if the Go template is not available.
    """
    from jinja2 import Environment, FileSystemLoader

    template_dir = Path(__file__).parent
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=True,
    )

    # Register custom filters matching Go's template functions
    env.filters["map_keys"] = lambda m, sep=", ": sep.join(m.keys()) if isinstance(m, dict) else ""
    env.globals["MapKeysToString"] = map_keys_to_string

    # Try loading the native Python Jinja2 template
    try:
        tmpl = env.get_template("report_template_jinja2.html")
    except Exception:
        # Fall back to generating HTML programmatically
        return _generate_html_fallback(report_data)

    return tmpl.render(**report_data)


def _svg_gauge(percentage: float, label: str, size: int = 120) -> str:
    """Generate an SVG circular gauge chart."""
    r = size // 2 - 10
    cx = cy = size // 2
    circumference = 2 * 3.14159 * r
    offset = circumference * (1 - percentage / 100)
    color = "#56CC54" if percentage >= 80 else "#FDBE10" if percentage >= 60 else "#FC7303" if percentage >= 40 else "#F24444"
    return f'''<svg width="{size}" height="{size + 30}" viewBox="0 0 {size} {size + 30}">
      <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#eee" stroke-width="8"/>
      <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="8"
        stroke-dasharray="{circumference}" stroke-dashoffset="{offset}"
        stroke-linecap="round" transform="rotate(-90 {cx} {cy})"/>
      <text x="{cx}" y="{cy + 5}" text-anchor="middle" font-size="18" font-weight="bold" fill="{color}">{percentage:.1f}%</text>
      <text x="{cx}" y="{size + 20}" text-anchor="middle" font-size="11" fill="#333">{html.escape(label)}</text>
    </svg>'''


def _svg_bar(label: str, value: int, max_val: int, color: str = "#3942EA") -> str:
    """Generate an SVG horizontal bar."""
    pct = (value / max_val * 100) if max_val > 0 else 0
    return f'''<div style="margin:4px 0;display:flex;align-items:center;gap:8px">
      <span style="width:180px;font-size:11px;text-align:right">{html.escape(label)}</span>
      <div style="flex:1;background:#eee;border-radius:4px;height:18px;position:relative">
        <div style="width:{pct:.1f}%;background:{color};border-radius:4px;height:100%"></div>
        <span style="position:absolute;right:6px;top:1px;font-size:10px;font-weight:bold">{value}/{max_val} ({pct:.1f}%)</span>
      </div>
    </div>'''


def _generate_html_fallback(data: dict[str, Any]) -> str:
    """Generate comprehensive HTML report with charts and detailed analysis."""
    overall = data.get("overall", {})
    api_sec = data.get("api_sec", {})
    app_sec = data.get("app_sec", {})
    tp = data.get("true_positive_tests", {})
    tn = data.get("true_negative_tests", {})

    def grade_badge(g: dict[str, Any]) -> str:
        colors = {"a": "#56CC54", "b": "#FDBE10", "c": "#FC7303", "d": "#F26344", "f": "#F24444", "na": "#999"}
        c = colors.get(g.get("css_class_suffix", "na"), "#999")
        return f'<span style="display:inline-block;padding:2px 10px;border-radius:4px;background:{c};color:#fff;font-weight:bold;font-size:13px">{g.get("mark","N/A")}</span> <span style="font-size:12px">{g.get("percentage",0):.1f}%</span>'

    def grade_text(g: dict[str, Any]) -> str:
        return f'{g.get("mark", "N/A")} ({g.get("percentage", 0):.1f}%)'

    o = []
    o.append('''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>GoTestWAF Security Assessment Report</title>
<style>
:root{--black:#000;--white:#fff;--green:#56CC54;--yellow:#FDBE10;--orange:#FC7303;--red:#F24444;--blue:#3942EA;--grey:#f5f7fa;--border:#e0e3e8}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Inter,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;font-size:12px;line-height:1.6;color:#1a1a2e;background:#fff}
.container{max-width:900px;margin:0 auto;padding:40px}
h1{font-size:26px;font-weight:900;margin-bottom:4px}
h2{font-size:20px;font-weight:700;margin:32px 0 16px;padding-bottom:8px;border-bottom:2px solid var(--blue)}
h3{font-size:15px;font-weight:700;margin:20px 0 10px;color:#444}
.header{display:flex;align-items:center;gap:20px;margin-bottom:24px}
.subtitle{color:#666;font-size:14px}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:16px 0;font-size:12px}
.info-grid .label{font-weight:700;color:#555}
.gauges{display:flex;gap:24px;justify-content:center;margin:24px 0;flex-wrap:wrap}
.card{background:var(--grey);border-radius:8px;padding:16px;margin:12px 0}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:11px}
th{background:#f0f2f5;font-weight:700;padding:8px 10px;text-align:left;border:1px solid var(--border)}
td{padding:6px 10px;border:1px solid var(--border)}
tr:nth-child(even){background:#fafbfc}
.summary-row{font-weight:bold;background:#e8eaf0 !important}
.bar-chart{margin:16px 0}
.grade-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:16px 0}
.grade-cell{background:var(--grey);border-radius:6px;padding:12px;text-align:center}
.grade-cell .name{font-size:11px;color:#666;margin-bottom:4px}
.weakness{background:#fff3f3;border-left:4px solid var(--red);padding:12px;margin:8px 0;border-radius:0 6px 6px 0}
.strength{background:#f0fff0;border-left:4px solid var(--green);padding:12px;margin:8px 0;border-radius:0 6px 6px 0}
.mono{font-family:Consolas,Monaco,monospace;font-size:11px}
@media print{.container{padding:20px}h2{break-before:auto}}
</style></head><body><div class="container">''')

    # Header
    o.append(f'''<div class="header">
<div><h1>WAF Security Assessment Report</h1>
<p class="subtitle">GoTestWAF — API &amp; OWASP Attack Simulation Results</p></div></div>''')

    # Info section
    o.append('<div class="info-grid">')
    o.append(f'<div><span class="label">WAF Product:</span> {html.escape(data.get("waf_name",""))}</div>')
    o.append(f'<div><span class="label">Target URL:</span> {html.escape(data.get("url",""))}</div>')
    o.append(f'<div><span class="label">Testing Date:</span> {html.escape(str(data.get("waf_testing_date","")))}</div>')
    o.append(f'<div><span class="label">GoTestWAF Version:</span> <span class="mono">{html.escape(str(data.get("gtw_version","")))}</span></div>')
    o.append(f'<div><span class="label">Test Cases FP:</span> <span class="mono">{html.escape(str(data.get("test_cases_fp","")))}</span></div>')
    if data.get("open_api_file"):
        o.append(f'<div><span class="label">OpenAPI File:</span> {html.escape(data["open_api_file"])}</div>')
    if data.get("args"):
        o.append(f'<div style="grid-column:span 2"><span class="label">CLI Arguments:</span> <span class="mono">{html.escape(" ".join(data["args"]))}</span></div>')
    o.append('</div>')

    # Overall Score Gauges
    overall_pct = overall.get("percentage", 0)
    api_pct = api_sec.get("grade", {}).get("percentage", 0)
    app_pct = app_sec.get("grade", {}).get("percentage", 0)
    tp_pct = tp.get("percentage", 0)
    tn_pct = tn.get("percentage", 0)

    o.append('<h2>Overall Security Score</h2>')
    o.append('<div class="gauges">')
    o.append(_svg_gauge(overall_pct, "Overall Score", 140))
    o.append(_svg_gauge(tp_pct, "True-Positive (Attack Blocked)", 120))
    o.append(_svg_gauge(tn_pct if tn_pct > 0 else 0, "True-Negative (FP Passed)", 120))
    o.append(_svg_gauge(api_pct, "API Security", 110))
    o.append(_svg_gauge(app_pct, "App Security", 110))
    o.append('</div>')

    # Grade Summary Grid
    o.append('<h2>Security Grade Summary</h2>')
    o.append('<div class="grade-grid">')
    o.append(f'<div class="grade-cell"><div class="name">Overall</div>{grade_badge(overall)}</div>')
    o.append(f'<div class="grade-cell"><div class="name">API Security</div>{grade_badge(api_sec.get("grade",{}))}</div>')
    o.append(f'<div class="grade-cell"><div class="name">App Security</div>{grade_badge(app_sec.get("grade",{}))}</div>')
    o.append(f'<div class="grade-cell"><div class="name">TP Blocked</div>{grade_badge(app_sec.get("true_positive_grade",{}))}</div>')
    o.append('</div>')

    # Request Statistics Bar Chart
    total = data.get("total_sent", 0)
    blocked = data.get("blocked_requests_number", 0)
    bypassed = data.get("bypassed_requests_number", 0)
    unresolved = data.get("unresolved_requests_number", 0)
    failed = data.get("failed_requests_number", 0)

    o.append('<h2>Request Statistics</h2>')
    o.append(f'<div class="card"><p style="font-size:14px;font-weight:bold;margin-bottom:12px">Total Requests: {total}</p>')
    o.append('<div class="bar-chart">')
    o.append(_svg_bar("Blocked by WAF", blocked, total, "#56CC54"))
    o.append(_svg_bar("Bypassed WAF", bypassed, total, "#F24444"))
    o.append(_svg_bar("Unresolved", unresolved, total, "#FDBE10"))
    o.append(_svg_bar("Failed", failed, total, "#999"))
    o.append('</div></div>')

    # Comparison Table
    o.append('<h2>Benchmarks Against Other Solutions</h2>')
    o.append('<table><tr><th>Solution</th><th>API Security</th><th>Application Security</th><th>Overall Score</th></tr>')
    for row in data.get("comparison_table", []):
        o.append(f'<tr><td>{html.escape(row["name"])}</td><td>{grade_text(row["api_sec"])}</td><td>{grade_text(row["app_sec"])}</td><td>{grade_text(row["overall_score"])}</td></tr>')
    wr = data.get("wallarm_result", {})
    if wr:
        o.append(f'<tr><td><b>{html.escape(wr["name"])}</b></td><td>{grade_text(wr["api_sec"])}</td><td>{grade_text(wr["app_sec"])}</td><td>{grade_text(wr["overall_score"])}</td></tr>')
    o.append(f'<tr class="summary-row"><td>Your WAF ({html.escape(data.get("waf_name",""))})</td><td>{grade_text(api_sec.get("grade",{}))}</td><td>{grade_text(app_sec.get("grade",{}))}</td><td>{grade_text(overall)}</td></tr>')
    o.append('</table>')

    # True Positive Tests Detail
    tp_summary = tp.get("summary_table", {})
    if tp_summary:
        o.append('<h2>True-Positive Tests (Attack Detection)</h2>')
        o.append('<p>These tests send known malicious payloads. <b>Higher block rate = stronger WAF.</b></p>')
        o.append('<table><tr><th>Test Set</th><th>Test Case</th><th>Block Rate</th><th>Blocked</th><th>Bypassed</th>')
        if not data.get("ignore_unresolved"):
            o.append('<th>Unresolved</th>')
        o.append('<th>Sent</th><th>Failed</th></tr>')
        for set_name, set_sum in tp_summary.items():
            for row in set_sum["test_cases"]:
                bypassed_style = ' style="color:red;font-weight:bold"' if row.bypassed > 0 else ""
                o.append(f'<tr><td>{html.escape(row.test_set)}</td><td>{html.escape(row.test_case)}</td><td>{row.percentage:.1f}%</td><td>{row.blocked}</td><td{bypassed_style}>{row.bypassed}</td>')
                if not data.get("ignore_unresolved"):
                    o.append(f'<td>{row.unresolved}</td>')
                o.append(f'<td>{row.sent}</td><td>{row.failed}</td></tr>')
            if len(tp_summary) > 1:
                o.append(f'<tr class="summary-row"><td colspan="2">Subtotal: {html.escape(set_name)}</td><td>{set_sum["percentage"]:.1f}%</td><td>{set_sum["blocked"]}</td><td>{set_sum["bypassed"]}</td>')
                if not data.get("ignore_unresolved"):
                    o.append(f'<td>{set_sum["unresolved"]}</td>')
                o.append(f'<td>{set_sum["sent"]}</td><td>{set_sum["failed"]}</td></tr>')
        o.append(f'<tr class="summary-row"><td colspan="2"><b>TOTAL</b></td><td><b>{tp.get("percentage",0):.1f}%</b></td><td>{tp.get("blocked_requests_number",0)}</td><td>{tp.get("bypassed_requests_number",0)}</td>')
        if not data.get("ignore_unresolved"):
            o.append(f'<td>{tp.get("unresolved_requests_number",0)}</td>')
        o.append(f'<td>{tp.get("total_sent",0)}</td><td>{tp.get("failed_requests_number",0)}</td></tr></table>')

    # True Negative Tests
    tn_summary = tn.get("summary_table", {})
    if tn_summary:
        o.append('<h2>True-Negative Tests (False Positive Detection)</h2>')
        o.append('<p>These tests send benign/normal traffic. <b>Lower block rate = fewer false positives.</b></p>')
        o.append('<table><tr><th>Test Set</th><th>Test Case</th><th>Pass Rate</th><th>Blocked (Bad)</th><th>Passed (Good)</th>')
        if not data.get("ignore_unresolved"):
            o.append('<th>Unresolved</th>')
        o.append('<th>Sent</th></tr>')
        for set_name, set_sum in tn_summary.items():
            for row in set_sum["test_cases"]:
                blocked_style = ' style="color:red;font-weight:bold"' if row.blocked > 0 else ""
                o.append(f'<tr><td>{html.escape(row.test_set)}</td><td>{html.escape(row.test_case)}</td><td>{row.percentage:.1f}%</td><td{blocked_style}>{row.blocked}</td><td>{row.bypassed}</td>')
                if not data.get("ignore_unresolved"):
                    o.append(f'<td>{row.unresolved}</td>')
                o.append(f'<td>{row.sent}</td></tr>')
        o.append('</table>')

    # Security Findings - Strengths & Weaknesses
    o.append('<h2>Security Findings</h2>')

    # Find weaknesses (bypassed attacks)
    weaknesses_found = False
    if tp_summary:
        for set_name, set_sum in tp_summary.items():
            for row in set_sum["test_cases"]:
                if row.bypassed > 0:
                    if not weaknesses_found:
                        o.append('<h3>Weaknesses Identified (Attacks That Bypassed WAF)</h3>')
                        weaknesses_found = True
                    o.append(f'<div class="weakness"><b>{html.escape(row.test_set)}/{html.escape(row.test_case)}</b> — {row.bypassed} of {row.sent} attacks bypassed ({100-row.percentage:.1f}% bypass rate)</div>')

    if not weaknesses_found:
        o.append('<div class="strength"><b>No attack bypasses detected!</b> All malicious payloads were successfully blocked by the WAF.</div>')

    # Find false positives
    tn_blocked = tn.get("blocked_requests_number", 0)
    if tn_blocked > 0:
        o.append(f'<h3>False Positives (Legitimate Traffic Blocked)</h3>')
        o.append(f'<div class="weakness"><b>{tn_blocked} legitimate requests were incorrectly blocked.</b> This may cause issues for normal users. Consider tuning WAF rules to reduce false positives.</div>')
    else:
        o.append('<div class="strength"><b>No false positive issues detected in the true-negative test suite.</b></div>')

    # Recommendations
    o.append('<h2>Recommendations</h2>')
    o.append('<div class="card">')
    if tp.get("percentage", 0) >= 95:
        o.append('<p>&#9989; <b>Attack blocking:</b> Excellent. Your WAF blocks the vast majority of known attack patterns.</p>')
    elif tp.get("percentage", 0) >= 70:
        o.append('<p>&#9888;&#65039; <b>Attack blocking:</b> Good but with gaps. Review the bypassed test cases above and add rules for those attack categories.</p>')
    else:
        o.append('<p>&#10060; <b>Attack blocking:</b> Significant gaps. Many known attack patterns bypass your WAF. Immediate rule updates recommended.</p>')

    if tn_blocked == 0:
        o.append('<p>&#9989; <b>False positives:</b> No false positives detected. WAF rules are well-tuned.</p>')
    elif tn_blocked < 10:
        o.append(f'<p>&#9888;&#65039; <b>False positives:</b> {tn_blocked} legitimate requests blocked. Minor tuning needed.</p>')
    else:
        o.append(f'<p>&#10060; <b>False positives:</b> {tn_blocked} legitimate requests blocked. Significant rule tuning required to avoid blocking real users.</p>')
    o.append('</div>')

    # ========== ATTACK CATEGORY BREAKDOWN CHART ==========
    o.append('<h2>Attack Category Breakdown</h2>')
    o.append('<p>Detection rate per attack category. Shows which attack types your WAF handles well and where gaps exist.</p>')

    # Gather per-test-set stats
    if tp_summary:
        # Build data for horizontal bar chart
        o.append('<div class="card" style="padding:24px">')
        max_sent = max((s["sent"] for s in tp_summary.values()), default=1) or 1
        for set_name in sorted(tp_summary.keys()):
            set_data = tp_summary[set_name]
            blocked_pct = (set_data["blocked"] / set_data["sent"] * 100) if set_data["sent"] > 0 else 0
            bypassed_pct = (set_data["bypassed"] / set_data["sent"] * 100) if set_data["sent"] > 0 else 0
            unresolved_pct = 100 - blocked_pct - bypassed_pct
            bar_w = set_data["sent"] / max_sent * 100

            o.append(f'''<div style="margin:10px 0">
<div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
  <span style="width:120px;font-weight:bold;font-size:12px;text-align:right">{html.escape(set_name)}</span>
  <span style="font-size:11px;color:#666">{set_data["sent"]} requests</span>
</div>
<div style="display:flex;align-items:center;gap:8px">
  <span style="width:120px"></span>
  <div style="flex:1;display:flex;height:22px;border-radius:4px;overflow:hidden;background:#eee">
    <div style="width:{blocked_pct:.1f}%;background:#56CC54" title="Blocked {set_data['blocked']}"></div>
    <div style="width:{bypassed_pct:.1f}%;background:#F24444" title="Bypassed {set_data['bypassed']}"></div>
    <div style="width:{unresolved_pct:.1f}%;background:#FDBE10" title="Unresolved {set_data.get('unresolved',0)}"></div>
  </div>
  <span style="width:60px;font-size:11px;font-weight:bold;color:{'#56CC54' if blocked_pct>=90 else '#F24444' if blocked_pct<50 else '#FC7303'}">{blocked_pct:.0f}%</span>
</div></div>''')

        o.append('<div style="display:flex;gap:16px;margin-top:16px;font-size:11px">')
        o.append('<span><span style="display:inline-block;width:12px;height:12px;background:#56CC54;border-radius:2px"></span> Blocked</span>')
        o.append('<span><span style="display:inline-block;width:12px;height:12px;background:#F24444;border-radius:2px"></span> Bypassed</span>')
        o.append('<span><span style="display:inline-block;width:12px;height:12px;background:#FDBE10;border-radius:2px"></span> Unresolved</span>')
        o.append('</div></div>')

    # ========== RADAR CHART (SVG) ==========
    if tp_summary:
        categories = sorted(tp_summary.keys())
        n = len(categories)
        if n >= 3:
            o.append('<h2>WAF Coverage Radar</h2>')
            o.append('<p>Radar view of block rates across attack categories. Larger area = better coverage.</p>')

            import math
            cx, cy, r = 200, 200, 150
            o.append(f'<div style="text-align:center"><svg width="420" height="440" viewBox="0 0 420 440">')

            # Draw grid circles
            for level in [0.25, 0.5, 0.75, 1.0]:
                lr = r * level
                o.append(f'<circle cx="{cx}" cy="{cy}" r="{lr}" fill="none" stroke="#e0e3e8" stroke-width="0.5"/>')
                if level < 1.0:
                    o.append(f'<text x="{cx+4}" y="{cy - lr + 4}" font-size="8" fill="#999">{int(level*100)}%</text>')

            # Draw axes and labels
            points: list[str] = []
            for i, cat in enumerate(categories):
                angle = (2 * math.pi * i / n) - math.pi / 2
                ax = cx + r * math.cos(angle)
                ay = cy + r * math.sin(angle)
                o.append(f'<line x1="{cx}" y1="{cy}" x2="{ax}" y2="{ay}" stroke="#e0e3e8" stroke-width="0.5"/>')

                # Label position (push outward)
                lx = cx + (r + 25) * math.cos(angle)
                ly = cy + (r + 25) * math.sin(angle)
                anchor = "middle"
                if lx < cx - 10:
                    anchor = "end"
                elif lx > cx + 10:
                    anchor = "start"

                pct_val = (tp_summary[cat]["blocked"] / tp_summary[cat]["sent"] * 100) if tp_summary[cat]["sent"] > 0 else 0
                o.append(f'<text x="{lx}" y="{ly}" text-anchor="{anchor}" font-size="9" fill="#333">{html.escape(cat)}</text>')
                o.append(f'<text x="{lx}" y="{ly + 12}" text-anchor="{anchor}" font-size="8" fill="#666">{pct_val:.0f}%</text>')

                # Data point
                val = pct_val / 100 * r
                px = cx + val * math.cos(angle)
                py = cy + val * math.sin(angle)
                points.append(f"{px},{py}")

            # Draw filled polygon
            poly = " ".join(points)
            o.append(f'<polygon points="{poly}" fill="rgba(57,66,234,0.2)" stroke="#3942EA" stroke-width="2"/>')

            # Draw data dots
            for pt in points:
                px, py = pt.split(",")
                o.append(f'<circle cx="{px}" cy="{py}" r="4" fill="#3942EA"/>')

            o.append('</svg></div>')

    # ========== DETAILED BYPASS ANALYSIS ==========
    bypassed_details: list[tuple[str, str, int, int]] = []
    if tp_summary:
        for set_name, set_data in tp_summary.items():
            for row in set_data["test_cases"]:
                if row.bypassed > 0:
                    bypassed_details.append((row.test_set, row.test_case, row.bypassed, row.sent))

    if bypassed_details:
        o.append('<h2>WAF Bypass Details</h2>')
        o.append('<p style="color:#c0392b;font-weight:bold">The following attack payloads bypassed WAF detection. These represent security gaps that should be addressed.</p>')
        o.append('<table><tr><th>Test Set</th><th>Test Case</th><th>Bypassed</th><th>Total Sent</th><th>Bypass Rate</th><th>Risk Level</th></tr>')
        for test_set, test_case, bypassed_count, sent_count in sorted(bypassed_details, key=lambda x: x[2], reverse=True):
            bypass_rate = bypassed_count / sent_count * 100 if sent_count > 0 else 0
            risk = "CRITICAL" if bypass_rate >= 50 else "HIGH" if bypass_rate >= 25 else "MEDIUM"
            risk_color = "#F24444" if risk == "CRITICAL" else "#FC7303" if risk == "HIGH" else "#FDBE10"
            o.append(f'<tr><td>{html.escape(test_set)}</td><td>{html.escape(test_case)}</td><td style="color:red;font-weight:bold">{bypassed_count}</td><td>{sent_count}</td><td>{bypass_rate:.1f}%</td><td style="color:{risk_color};font-weight:bold">{risk}</td></tr>')
        o.append('</table>')

    # ========== PAYLOAD DETAIL TABLES (if includePayloads) ==========
    if data.get("include_payloads"):
        # True-Positive Bypasses
        tp_bypassed = tp.get("bypassed", {})
        if tp_bypassed:
            o.append('<h2>Bypassed Payloads (True-Positive)</h2>')
            o.append('<p>Malicious payloads that were NOT blocked by the WAF:</p>')
            o.append('<table><tr><th>Payload</th><th>Test Case</th><th>Encoders</th><th>Placeholders</th><th>Status</th></tr>')
            for paths, path_map in tp_bypassed.items():
                if paths:
                    o.append(f'<tr><td colspan="5" style="background:#fff3f3;font-size:10px"><b>Path:</b> {html.escape(paths)}</td></tr>')
                for payload_text, code_map in path_map.items():
                    for code, details in code_map.items():
                        encoders = ", ".join(details.get("encoders", {}).keys())
                        placeholders = ", ".join(details.get("placeholders", {}).keys())
                        o.append(f'<tr><td class="mono" style="word-break:break-all;max-width:350px;font-size:10px">{html.escape(str(payload_text))}</td><td>{html.escape(details.get("test_case",""))}</td><td>{html.escape(encoders)}</td><td>{html.escape(placeholders)}</td><td>{code}</td></tr>')
            o.append('</table>')

        # True-Positive Unresolved
        tp_unresolved = tp.get("unresolved", {})
        if tp_unresolved:
            o.append('<h2>Unresolved Payloads (True-Positive)</h2>')
            o.append('<p>Payloads where WAF response could not be determined as blocked or passed:</p>')
            o.append('<table><tr><th>Payload</th><th>Test Case</th><th>Encoders</th><th>Placeholders</th><th>Status</th></tr>')
            for payload_text, code_map in tp_unresolved.items():
                for code, details in code_map.items():
                    encoders = ", ".join(details.get("encoders", {}).keys())
                    placeholders = ", ".join(details.get("placeholders", {}).keys())
                    o.append(f'<tr><td class="mono" style="word-break:break-all;max-width:350px;font-size:10px">{html.escape(str(payload_text))}</td><td>{html.escape(details.get("test_case",""))}</td><td>{html.escape(encoders)}</td><td>{html.escape(placeholders)}</td><td>{code}</td></tr>')
            o.append('</table>')

        # True-Negative Blocked (False Positives)
        tn_blocked_data = tn.get("blocked", {})
        if tn_blocked_data:
            o.append('<h2>False Positives (Legitimate Traffic Blocked)</h2>')
            o.append('<p>Normal/benign requests that were incorrectly blocked by the WAF:</p>')
            o.append('<table><tr><th>Payload</th><th>Test Case</th><th>Encoders</th><th>Placeholders</th><th>Status</th></tr>')
            for payload_text, code_map in tn_blocked_data.items():
                for code, details in code_map.items():
                    encoders = ", ".join(details.get("encoders", {}).keys())
                    placeholders = ", ".join(details.get("placeholders", {}).keys())
                    o.append(f'<tr><td class="mono" style="word-break:break-all;max-width:350px;font-size:10px">{html.escape(str(payload_text))}</td><td>{html.escape(details.get("test_case",""))}</td><td>{html.escape(encoders)}</td><td>{html.escape(placeholders)}</td><td>{code}</td></tr>')
            o.append('</table>')

    # ========== FULL REQUEST/RESPONSE EVIDENCE ==========
    evidence = data.get("bypass_evidence", [])
    if evidence:
        o.append('<h2>Full Request/Response Evidence</h2>')
        o.append(f'<p>Complete HTTP request and response for each bypassed payload ({len(evidence)} total). '
                 'This provides full visibility into exactly what was sent and received.</p>')
        o.append('<style>')
        o.append('.evidence{background:#fff;border:1px solid #e0e3e8;border-radius:6px;margin:16px 0;overflow:hidden}')
        o.append('.evidence-hdr{background:#2c3e50;color:#fff;padding:10px 14px;font-size:12px;display:flex;justify-content:space-between;align-items:center}')
        o.append('.evidence-hdr .tag{margin-left:8px}')
        o.append('.evidence-body{display:flex;gap:0}')
        o.append('.evidence-req,.evidence-resp{flex:1;min-width:0}')
        o.append('.evidence-label{background:#34495e;color:#ecf0f1;padding:6px 12px;font-size:11px;font-weight:700;letter-spacing:0.5px}')
        o.append('.evidence-req .evidence-label{background:#2980b9}')
        o.append('.evidence-resp .evidence-label{background:#27ae60}')
        o.append('.http-block{padding:10px 12px;font-family:Consolas,Monaco,monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;'
                 'background:#fafbfc;border-right:1px solid #e0e3e8;max-height:400px;overflow-y:auto;line-height:1.5}')
        o.append('.http-line-method{color:#e74c3c;font-weight:700}')
        o.append('.http-line-header{color:#2c3e50}.http-line-hname{color:#8e44ad;font-weight:600}')
        o.append('.http-line-status{font-weight:700}.http-line-body{color:#555;margin-top:4px;padding-top:4px;border-top:1px dashed #ddd}')
        o.append('</style>')

        for idx, ev in enumerate(evidence[:200]):  # Cap at 200 to avoid huge reports
            risk_color = "#F24444" if ev["status_code"] == 200 else "#FC7303"
            o.append(f'<div class="evidence">')
            o.append(f'<div class="evidence-hdr">')
            o.append(f'<span><b>#{idx+1}</b> &mdash; {html.escape(ev["test_set"])}/{html.escape(ev["test_case"])}'
                     f' [{html.escape(ev["encoder"])}/{html.escape(ev["placeholder"])}]</span>')
            o.append(f'<span>HTTP {ev["status_code"]} <span class="tag" style="background:{risk_color}">BYPASSED</span></span>')
            o.append('</div>')

            # Build request text
            o.append('<div class="evidence-body">')
            o.append('<div class="evidence-req"><div class="evidence-label">REQUEST</div><div class="http-block">')
            method = html.escape(ev.get("request_method", "GET"))
            url = html.escape(ev.get("request_url", "/"))
            o.append(f'<span class="http-line-method">{method} {url} HTTP/1.1</span>\n')
            for hk, hv in (ev.get("request_headers") or {}).items():
                o.append(f'<span class="http-line-header"><span class="http-line-hname">{html.escape(str(hk))}</span>: {html.escape(str(hv))}</span>\n')
            req_body = ev.get("request_body", "")
            if req_body:
                o.append(f'\n<span class="http-line-body">{html.escape(req_body[:1500])}</span>')
            o.append('</div></div>')

            # Build response text
            o.append('<div class="evidence-resp"><div class="evidence-label">RESPONSE</div><div class="http-block">')
            o.append(f'<span class="http-line-status">HTTP/1.1 {ev["status_code"]}</span>\n')
            for hk, hv in (ev.get("response_headers") or {}).items():
                o.append(f'<span class="http-line-header"><span class="http-line-hname">{html.escape(str(hk))}</span>: {html.escape(str(hv))}</span>\n')
            resp_body = ev.get("response_body", "")
            if resp_body:
                o.append(f'\n<span class="http-line-body">{html.escape(resp_body[:1500])}</span>')
            o.append('</div></div>')
            o.append('</div></div>')  # Close evidence-body and evidence

        if len(evidence) > 200:
            o.append(f'<p style="color:#999;font-size:11px">Showing 200 of {len(evidence)} bypass evidence entries. See XLSX export for complete data.</p>')

    # ========== ATTACK TYPES USED ==========
    o.append('<h2>Attack Types Used in Testing</h2>')
    o.append('<p>GoTestWAF tests WAF detection capabilities across the following attack categories:</p>')
    o.append('<div class="card">')
    attack_types = [
        ("XSS (Cross-Site Scripting)", "Script injection via URL, headers, body, forms. Tests alert(), prompt(), event handlers, DOM manipulation."),
        ("SQL Injection", "Database query manipulation via UNION SELECT, OR 1=1, SLEEP(), information_schema access."),
        ("Remote Code Execution (RCE)", "Command injection via shell commands, /etc/passwd access, curl/wget execution."),
        ("Local File Inclusion (LFI)", "Path traversal via ../ sequences to access server files."),
        ("XML External Entity (XXE)", "XML parser exploitation via ENTITY declarations and external file references."),
        ("Server-Side Template Injection (SSTI)", "Template engine exploitation via {{}} and {%%} expressions."),
        ("CRLF Injection", "HTTP header injection via carriage return/line feed characters."),
        ("LDAP Injection", "Directory service query manipulation."),
        ("Mail Injection", "Email header injection for spam relay."),
        ("NoSQL Injection", "MongoDB/NoSQL query manipulation."),
        ("Shell Injection", "OS command injection via pipes, semicolons, backticks."),
        ("Server-Side Include (SSI)", "Web server directive injection via <!--# tags."),
        ("Path Traversal", "File system navigation beyond web root."),
        ("GraphQL Attacks", "GraphQL query injection (GET and POST methods)."),
        ("gRPC Attacks", "Protocol buffer payload injection."),
        ("SOAP/XML Attacks", "SOAP envelope and XML body injection."),
        ("Raw Request Attacks", "Custom HTTP request construction with arbitrary headers/body."),
    ]
    o.append('<table><tr><th style="width:220px">Attack Category</th><th>Description &amp; Test Method</th></tr>')
    for name, desc in attack_types:
        o.append(f'<tr><td><b>{html.escape(name)}</b></td><td style="font-size:11px">{html.escape(desc)}</td></tr>')
    o.append('</table>')

    o.append('<p style="margin-top:12px"><b>Encoding strategies applied:</b> Base64, Base64Flat, URL encoding, JSUnicode, Plain, XML Entity encoding</p>')
    o.append('<p><b>Payload delivery methods:</b> URL parameters, URL path, HTTP headers, User-Agent, JSON body, HTML forms, multipart forms, SOAP body, XML body, raw HTTP requests, GraphQL queries, gRPC messages</p>')
    o.append('</div>')

    # ========== FOOTER ==========
    o.append(f'<div style="margin-top:40px;padding-top:16px;border-top:1px solid #ddd;font-size:10px;color:#999;text-align:center">')
    o.append(f'Generated by GoTestWAF (Python) v{data.get("gtw_version","unknown")} | Test cases fingerprint: {data.get("test_cases_fp","")}</div>')

    o.append('</div></body></html>')
    return "\n".join(o)
