"""Excel report generator — comprehensive multi-sheet XLSX output."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from openpyxl import Workbook
from openpyxl.chart import BarChart, PieChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
import re as _re

if TYPE_CHECKING:
    from gotestwaf.db.statistics import Statistics

# ── Styles ──
HEADER_FONT = Font(name="Calibri", bold=True, color="FFFFFF", size=11)
HEADER_FILL = PatternFill(start_color="2B3990", end_color="2B3990", fill_type="solid")
SUBHEADER_FILL = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
PASS_FILL = PatternFill(start_color="E2EFDA", end_color="E2EFDA", fill_type="solid")
FAIL_FILL = PatternFill(start_color="FCE4EC", end_color="FCE4EC", fill_type="solid")
WARN_FILL = PatternFill(start_color="FFF3E0", end_color="FFF3E0", fill_type="solid")
SCORE_FONT_GOOD = Font(name="Calibri", bold=True, color="2E7D32", size=14)
SCORE_FONT_MED = Font(name="Calibri", bold=True, color="F57F17", size=14)
SCORE_FONT_BAD = Font(name="Calibri", bold=True, color="C62828", size=14)
THIN_BORDER = Border(
    left=Side(style="thin", color="D0D0D0"),
    right=Side(style="thin", color="D0D0D0"),
    top=Side(style="thin", color="D0D0D0"),
    bottom=Side(style="thin", color="D0D0D0"),
)
TITLE_FONT = Font(name="Calibri", bold=True, size=16, color="1A237E")
SUBTITLE_FONT = Font(name="Calibri", bold=True, size=12, color="37474F")


def _style_header_row(ws: Any, row: int, col_count: int) -> None:
    for col in range(1, col_count + 1):
        cell = ws.cell(row=row, column=col)
        cell.font = HEADER_FONT
        cell.fill = HEADER_FILL
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border = THIN_BORDER


def _style_data_row(ws: Any, row: int, col_count: int) -> None:
    for col in range(1, col_count + 1):
        cell = ws.cell(row=row, column=col)
        cell.border = THIN_BORDER
        cell.alignment = Alignment(vertical="center", horizontal="left", wrap_text=True)


def _auto_filter(ws: Any, row: int, col_count: int) -> None:
    """Add auto-filter to header row."""
    last_col = get_column_letter(col_count)
    ws.auto_filter.ref = f"A{row}:{last_col}{ws.max_row}"


_CONTROL_CHAR_RE = _re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

def _safe_str(value: str) -> str:
    """Strip illegal XML characters that openpyxl rejects (null bytes, control chars)."""
    return _CONTROL_CHAR_RE.sub("", value)


def _auto_width(ws: Any) -> None:
    for col_cells in ws.columns:
        max_len = 0
        col_letter = get_column_letter(col_cells[0].column)
        for cell in col_cells:
            val = str(cell.value) if cell.value else ""
            max_len = max(max_len, len(val))
        ws.column_dimensions[col_letter].width = min(max_len + 4, 60)


def _score_font(score: float) -> Font:
    if score >= 80:
        return SCORE_FONT_GOOD
    if score >= 50:
        return SCORE_FONT_MED
    return SCORE_FONT_BAD


def generate_excel_report(
    stat: Statistics,
    report_file: str,
    report_time: datetime,
    waf_name: str,
    url: str,
    args: list[str],
    ignore_unresolved: bool,
    include_payloads: bool,
    ml_analysis: dict[str, object] | None = None,
    ruleset_inference: object | None = None,
    compliance_results: dict[str, object] | None = None,
) -> None:
    """Generate comprehensive Excel report with multiple sheets."""

    wb = Workbook()

    # ═══════════════════════════════════════════════════════════
    # Sheet 1: Executive Summary
    # ═══════════════════════════════════════════════════════════
    ws = wb.active
    ws.title = "Executive Summary"
    ws.sheet_properties.tabColor = "2B3990"

    ws.merge_cells("A1:F1")
    ws["A1"] = "WAF Security Assessment Report"
    ws["A1"].font = TITLE_FONT

    ws.merge_cells("A2:F2")
    ws["A2"] = f"Target: {url}"
    ws["A2"].font = SUBTITLE_FONT

    row = 4
    info = [
        ("WAF Product", waf_name),
        ("Scan Date", report_time.strftime("%Y-%m-%d %H:%M:%S")),
        ("Test Fingerprint", stat.test_cases_fingerprint),
        ("CLI Arguments", " ".join(args) if args else "N/A"),
        ("gRPC Available", "Yes" if stat.is_grpc_available else "No"),
        ("GraphQL Available", "Yes" if stat.is_graphql_available else "No"),
    ]
    for label, value in info:
        ws.cell(row=row, column=1, value=label).font = Font(bold=True)
        ws.cell(row=row, column=2, value=str(value))
        row += 1

    row += 1
    ws.cell(row=row, column=1, value="SCORES").font = SUBTITLE_FONT
    row += 1

    headers = ["Category", "True-Positive (Attack Blocked)", "True-Negative (Benign Passed)", "Average"]
    for c, h in enumerate(headers, 1):
        ws.cell(row=row, column=c, value=h)
    _style_header_row(ws, row, len(headers))
    row += 1

    def _fmt(v: float) -> str:
        return f"{v:.2f}%" if v >= 0 else "N/A"

    scores = [
        ("API Security", stat.score.api_sec.true_positive, stat.score.api_sec.true_negative, stat.score.api_sec.average),
        ("Application Security", stat.score.app_sec.true_positive, stat.score.app_sec.true_negative, stat.score.app_sec.average),
    ]
    for name, tp, tn, avg in scores:
        ws.cell(row=row, column=1, value=name)
        ws.cell(row=row, column=2, value=_fmt(tp))
        ws.cell(row=row, column=3, value=_fmt(tn))
        ws.cell(row=row, column=4, value=_fmt(avg))
        _style_data_row(ws, row, 4)
        row += 1

    row += 1
    ws.cell(row=row, column=1, value="Overall Score").font = Font(bold=True, size=13)
    cell = ws.cell(row=row, column=2, value=_fmt(stat.score.average))
    cell.font = _score_font(stat.score.average)

    # Request stats
    row += 2
    ws.cell(row=row, column=1, value="REQUEST SUMMARY").font = SUBTITLE_FONT
    row += 1
    tp = stat.true_positive_tests
    tn = stat.true_negative_tests
    req_headers = ["Metric", "True-Positive", "True-Negative"]
    for c, h in enumerate(req_headers, 1):
        ws.cell(row=row, column=c, value=h)
    _style_header_row(ws, row, 3)
    row += 1
    req_data = [
        ("Total Sent", tp.req_stats.all_requests_number, tn.req_stats.all_requests_number),
        ("Blocked", tp.req_stats.blocked_requests_number, tn.req_stats.blocked_requests_number),
        ("Bypassed", tp.req_stats.bypassed_requests_number, tn.req_stats.bypassed_requests_number),
        ("Unresolved", tp.req_stats.unresolved_requests_number, tn.req_stats.unresolved_requests_number),
        ("Failed", tp.req_stats.failed_requests_number, tn.req_stats.failed_requests_number),
    ]
    for label, tp_val, tn_val in req_data:
        ws.cell(row=row, column=1, value=label)
        ws.cell(row=row, column=2, value=tp_val)
        ws.cell(row=row, column=3, value=tn_val)
        _style_data_row(ws, row, 3)
        row += 1

    # Pie chart: blocked vs bypassed vs unresolved
    row += 2
    ws.cell(row=row, column=1, value="Distribution").font = SUBTITLE_FONT
    row += 1
    ws.cell(row=row, column=1, value="Category")
    ws.cell(row=row, column=2, value="Count")
    _style_header_row(ws, row, 2)
    chart_start = row
    row += 1
    ws.cell(row=row, column=1, value="Blocked")
    ws.cell(row=row, column=2, value=tp.req_stats.blocked_requests_number)
    row += 1
    ws.cell(row=row, column=1, value="Bypassed")
    ws.cell(row=row, column=2, value=tp.req_stats.bypassed_requests_number)
    row += 1
    ws.cell(row=row, column=1, value="Unresolved")
    ws.cell(row=row, column=2, value=tp.req_stats.unresolved_requests_number)
    row += 1
    ws.cell(row=row, column=1, value="Failed")
    ws.cell(row=row, column=2, value=tp.req_stats.failed_requests_number)
    chart_end = row

    pie = PieChart()
    pie.title = "Test Result Distribution"
    pie.style = 10
    data = Reference(ws, min_col=2, min_row=chart_start, max_row=chart_end)
    cats = Reference(ws, min_col=1, min_row=chart_start + 1, max_row=chart_end)
    pie.add_data(data, titles_from_data=True)
    pie.set_categories(cats)
    pie.width = 16
    pie.height = 12
    pie.dataLabels = DataLabelList()
    pie.dataLabels.showPercent = True
    pie.dataLabels.showVal = True
    ws.add_chart(pie, f"D{chart_start - 1}")

    _auto_width(ws)

    # ═══════════════════════════════════════════════════════════
    # Sheet 2: True-Positive Test Results
    # ═══════════════════════════════════════════════════════════
    ws2 = wb.create_sheet("True-Positive Tests")
    ws2.sheet_properties.tabColor = "2E7D32"

    tp_headers = ["Test Set", "Test Case", "Block Rate %", "Sent", "Blocked", "Bypassed", "Unresolved", "Failed"]
    for c, h in enumerate(tp_headers, 1):
        ws2.cell(row=1, column=c, value=h)
    _style_header_row(ws2, 1, len(tp_headers))

    for r, row_data in enumerate(stat.true_positive_tests.summary_table, 2):
        ws2.cell(row=r, column=1, value=row_data.test_set)
        ws2.cell(row=r, column=2, value=row_data.test_case)
        ws2.cell(row=r, column=3, value=round(row_data.percentage, 2))
        ws2.cell(row=r, column=4, value=row_data.sent)
        ws2.cell(row=r, column=5, value=row_data.blocked)
        ws2.cell(row=r, column=6, value=row_data.bypassed)
        ws2.cell(row=r, column=7, value=row_data.unresolved)
        ws2.cell(row=r, column=8, value=row_data.failed)
        _style_data_row(ws2, r, len(tp_headers))

        # Color code by block rate
        pct_cell = ws2.cell(row=r, column=3)
        if row_data.percentage >= 95:
            pct_cell.fill = PASS_FILL
        elif row_data.percentage >= 50:
            pct_cell.fill = WARN_FILL
        else:
            pct_cell.fill = FAIL_FILL

        # Highlight bypassed > 0
        if row_data.bypassed > 0:
            ws2.cell(row=r, column=6).fill = FAIL_FILL
            ws2.cell(row=r, column=6).font = Font(bold=True, color="C62828")

    _auto_filter(ws2, 1, len(tp_headers))
    _auto_width(ws2)

    # Add chart
    if stat.true_positive_tests.summary_table:
        last_row = len(stat.true_positive_tests.summary_table) + 1
        chart = BarChart()
        chart.type = "col"
        chart.title = "True-Positive Block Rate by Test Case"
        chart.y_axis.title = "Block Rate %"
        chart.x_axis.title = "Test Case"
        chart.style = 10
        data = Reference(ws2, min_col=3, min_row=1, max_row=last_row)
        cats = Reference(ws2, min_col=2, min_row=2, max_row=last_row)
        chart.add_data(data, titles_from_data=True)
        chart.set_categories(cats)
        chart.width = 30
        chart.height = 15
        ws2.add_chart(chart, f"A{last_row + 3}")

    # ═══════════════════════════════════════════════════════════
    # Sheet 3: True-Negative Test Results
    # ═══════════════════════════════════════════════════════════
    ws3 = wb.create_sheet("True-Negative Tests")
    ws3.sheet_properties.tabColor = "C62828"

    tn_headers = ["Test Set", "Test Case", "Pass Rate %", "Sent", "Blocked", "Bypassed", "Unresolved", "Failed"]
    for c, h in enumerate(tn_headers, 1):
        ws3.cell(row=1, column=c, value=h)
    _style_header_row(ws3, 1, len(tn_headers))

    for r, row_data in enumerate(stat.true_negative_tests.summary_table, 2):
        ws3.cell(row=r, column=1, value=row_data.test_set)
        ws3.cell(row=r, column=2, value=row_data.test_case)
        ws3.cell(row=r, column=3, value=round(row_data.percentage, 2))
        ws3.cell(row=r, column=4, value=row_data.sent)
        ws3.cell(row=r, column=5, value=row_data.blocked)
        ws3.cell(row=r, column=6, value=row_data.bypassed)
        ws3.cell(row=r, column=7, value=row_data.unresolved)
        ws3.cell(row=r, column=8, value=row_data.failed)
        _style_data_row(ws3, r, len(tn_headers))

    _auto_filter(ws3, 1, len(tn_headers))
    _auto_width(ws3)

    # ═══════════════════════════════════════════════════════════
    # Sheet 4: Bypassed Payloads (attacks that got through)
    # ═══════════════════════════════════════════════════════════
    if include_payloads:
        ws4 = wb.create_sheet("Bypassed Payloads")
        ws4.sheet_properties.tabColor = "F44336"

        bp_headers = ["Test Set", "Test Case", "Payload", "Encoder", "Placeholder", "Status Code", "Attack Type",
                      "Request Method", "Request URL", "Request Headers", "Request Body",
                      "Response Headers", "Response Body"]
        for c, h in enumerate(bp_headers, 1):
            ws4.cell(row=1, column=c, value=h)
        _style_header_row(ws4, 1, len(bp_headers))

        r = 2
        for td in stat.true_positive_tests.bypasses:
            ws4.cell(row=r, column=1, value=td.test_set)
            ws4.cell(row=r, column=2, value=td.test_case)
            ws4.cell(row=r, column=3, value=_safe_str(td.payload[:500]))
            ws4.cell(row=r, column=4, value=td.encoder)
            ws4.cell(row=r, column=5, value=td.placeholder)
            ws4.cell(row=r, column=6, value=td.response_status_code)
            ws4.cell(row=r, column=7, value=td.type)
            # Full request/response evidence
            ws4.cell(row=r, column=8, value=getattr(td, "request_method", ""))
            ws4.cell(row=r, column=9, value=_safe_str(getattr(td, "request_url", "")))
            req_hdrs = getattr(td, "request_headers", {})
            ws4.cell(row=r, column=10, value=_safe_str("\n".join(f"{k}: {v}" for k, v in req_hdrs.items()))[:2000] if req_hdrs else "")
            ws4.cell(row=r, column=11, value=_safe_str(getattr(td, "request_body", ""))[:2000])
            resp_hdrs = getattr(td, "response_headers", {})
            ws4.cell(row=r, column=12, value=_safe_str("\n".join(f"{k}: {v}" for k, v in resp_hdrs.items()))[:2000] if resp_hdrs else "")
            ws4.cell(row=r, column=13, value=_safe_str(getattr(td, "response_body", ""))[:2000])
            _style_data_row(ws4, r, len(bp_headers))
            r += 1

        if r == 2:
            ws4.cell(row=2, column=1, value="No bypasses detected")
        _auto_filter(ws4, 1, len(bp_headers))
        _auto_width(ws4)

        # Sheet 5: Blocked Payloads
        ws5 = wb.create_sheet("Blocked Payloads")
        ws5.sheet_properties.tabColor = "4CAF50"

        bl_headers = ["Test Set", "Test Case", "Payload", "Encoder", "Placeholder", "Status Code", "Attack Type"]
        for c, h in enumerate(bl_headers, 1):
            ws5.cell(row=1, column=c, value=h)
        _style_header_row(ws5, 1, len(bl_headers))

        r = 2
        # `_safe_str` strips illegal XML control chars and dodges Excel
        # formula-injection. Apply it to every text-typed cell, not just the
        # payload — a custom YAML test set could ship a test_set/case name
        # that contains a NUL byte (illegal-XML crash) or starts with an
        # Excel formula trigger.
        for td in stat.true_positive_tests.blocked[:500]:  # Cap at 500 for file size
            ws5.cell(row=r, column=1, value=_safe_str(td.test_set))
            ws5.cell(row=r, column=2, value=_safe_str(td.test_case))
            ws5.cell(row=r, column=3, value=_safe_str(td.payload[:300]))
            ws5.cell(row=r, column=4, value=_safe_str(td.encoder))
            ws5.cell(row=r, column=5, value=_safe_str(td.placeholder))
            ws5.cell(row=r, column=6, value=td.response_status_code)
            ws5.cell(row=r, column=7, value=_safe_str(td.type))
            _style_data_row(ws5, r, len(bl_headers))
            r += 1
        _auto_filter(ws5, 1, len(bl_headers))
        _auto_width(ws5)

    # ═══════════════════════════════════════════════════════════
    # Sheet 6: ML Intelligence (if available)
    # ═══════════════════════════════════════════════════════════
    if ml_analysis and ml_analysis.get("metrics"):
        ws6 = wb.create_sheet("ML Intelligence")
        ws6.sheet_properties.tabColor = "9C27B0"

        metrics = ml_analysis.get("metrics", {})
        ws6.cell(row=1, column=1, value="ML Engine Metrics").font = SUBTITLE_FONT

        row = 3
        ml_info = [
            ("Model Trained", "Yes" if metrics.get("is_trained") else "No"),
            ("Training Samples", metrics.get("training_samples", 0)),
            ("Cross-Validation F1", metrics.get("cv_f1_score", 0)),
            ("Blocked Samples", metrics.get("blocked", 0)),
            ("Bypassed Samples", metrics.get("bypassed", 0)),
        ]
        for label, value in ml_info:
            ws6.cell(row=row, column=1, value=label).font = Font(bold=True)
            ws6.cell(row=row, column=2, value=str(value))
            row += 1

        # Feature importance
        feat_imp = metrics.get("feature_importance", {})
        if feat_imp:
            row += 1
            ws6.cell(row=row, column=1, value="Top Predictive Features").font = SUBTITLE_FONT
            row += 1
            fi_headers = ["Feature", "Importance"]
            for c, h in enumerate(fi_headers, 1):
                ws6.cell(row=row, column=c, value=h)
            _style_header_row(ws6, row, 2)
            row += 1
            for fname, fval in feat_imp.items():
                ws6.cell(row=row, column=1, value=fname)
                ws6.cell(row=row, column=2, value=round(float(fval), 4))
                _style_data_row(ws6, row, 2)
                row += 1

        # Bypass candidates
        candidates = ml_analysis.get("bypass_candidates", [])
        if candidates:
            row += 1
            ws6.cell(row=row, column=1, value="ML Bypass Predictions").font = SUBTITLE_FONT
            row += 1
            bc_headers = ["Payload", "Test Case", "Bypass Probability", "Confidence", "Attack Type"]
            for c, h in enumerate(bc_headers, 1):
                ws6.cell(row=row, column=c, value=h)
            _style_header_row(ws6, row, len(bc_headers))
            row += 1
            for bc in candidates[:30]:
                ws6.cell(row=row, column=1, value=_safe_str(str(bc.get("payload", ""))[:200]))
                ws6.cell(row=row, column=2, value=str(bc.get("test_case", "")))
                prob = bc.get("bypass_probability", 0)
                ws6.cell(row=row, column=3, value=f"{prob:.1%}")
                ws6.cell(row=row, column=4, value=f"{bc.get('confidence', 0):.1%}")
                ws6.cell(row=row, column=5, value=str(bc.get("attack_type", "")))
                _style_data_row(ws6, row, len(bc_headers))
                if prob > 0.5:
                    ws6.cell(row=row, column=3).fill = FAIL_FILL
                row += 1

        # Mutation suggestions
        mutations = ml_analysis.get("mutation_suggestions", [])
        if mutations:
            row += 1
            ws6.cell(row=row, column=1, value="Suggested Bypass Mutations").font = SUBTITLE_FONT
            row += 1
            mt_headers = ["Source Payload", "Mutation", "Encoder", "Placement", "Bypass Prob."]
            for c, h in enumerate(mt_headers, 1):
                ws6.cell(row=row, column=c, value=h)
            _style_header_row(ws6, row, len(mt_headers))
            row += 1
            for ms in mutations:
                for mut in ms.get("mutations", []):
                    ws6.cell(row=row, column=1, value=_safe_str(str(ms.get("payload", ""))[:100]))
                    ws6.cell(row=row, column=2, value=str(mut.get("mutation", "")))
                    ws6.cell(row=row, column=3, value=str(mut.get("encoder", "")))
                    ws6.cell(row=row, column=4, value=str(mut.get("placeholder", "")))
                    ws6.cell(row=row, column=5, value=f"{mut.get('bypass_probability', 0):.1%}")
                    _style_data_row(ws6, row, len(mt_headers))
                    row += 1

        _auto_width(ws6)

    # ═══════════════════════════════════════════════════════════
    # Sheet 7: Scanned Paths (if OpenAPI was used)
    # ═══════════════════════════════════════════════════════════
    if stat.paths:
        ws7 = wb.create_sheet("Scanned Paths")
        ws7.sheet_properties.tabColor = "607D8B"
        path_headers = ["Method", "Path"]
        for c, h in enumerate(path_headers, 1):
            ws7.cell(row=1, column=c, value=h)
        _style_header_row(ws7, 1, 2)
        for r, p in enumerate(stat.paths, 2):
            ws7.cell(row=r, column=1, value=p.method)
            ws7.cell(row=r, column=2, value=p.path)
            _style_data_row(ws7, r, 2)
        _auto_width(ws7)

    # ═══════════════════════════════════════════════════════════
    # Sheet 8: WAF Ruleset Detection (inferred)
    # ═══════════════════════════════════════════════════════════
    if ruleset_inference is not None:
        from gotestwaf.scanner.ruleset_inference import InferenceResult
        if isinstance(ruleset_inference, InferenceResult):
            ri = ruleset_inference
            ws8 = wb.create_sheet("WAF Ruleset Detection")
            ws8.sheet_properties.tabColor = "FF6F00"

            ri_headers = ["Status", "Ruleset / Configuration", "Vendor", "Confidence", "Evidence", "Recommendation"]
            for c, hdr in enumerate(ri_headers, 1):
                ws8.cell(row=1, column=c, value=hdr)
            _style_header_row(ws8, 1, len(ri_headers))

            r = 2
            for rs in ri.detected:
                status = "DETECTED" if rs.status == "detected" else "UNVERIFIABLE"
                ws8.cell(row=r, column=1, value=status)
                ws8.cell(row=r, column=2, value=rs.name)
                ws8.cell(row=r, column=3, value=rs.vendor)
                ws8.cell(row=r, column=4, value=f"{rs.confidence:.0%}" if rs.confidence > 0 else "N/A")
                ws8.cell(row=r, column=5, value=rs.evidence)
                ws8.cell(row=r, column=6, value=rs.recommendation or "None needed")
                _style_data_row(ws8, r, len(ri_headers))
                ws8.cell(row=r, column=1).fill = PASS_FILL
                r += 1

            for rs in ri.partial:
                ws8.cell(row=r, column=1, value="PARTIAL")
                ws8.cell(row=r, column=2, value=rs.name)
                ws8.cell(row=r, column=3, value=rs.vendor)
                ws8.cell(row=r, column=4, value=f"{rs.confidence:.0%}")
                ws8.cell(row=r, column=5, value=rs.evidence)
                ws8.cell(row=r, column=6, value=rs.recommendation)
                _style_data_row(ws8, r, len(ri_headers))
                ws8.cell(row=r, column=1).fill = WARN_FILL
                r += 1

            for rs in ri.missing:
                ws8.cell(row=r, column=1, value="MISSING")
                ws8.cell(row=r, column=2, value=rs.name)
                ws8.cell(row=r, column=3, value=rs.vendor)
                ws8.cell(row=r, column=4, value=f"{rs.confidence:.0%}")
                ws8.cell(row=r, column=5, value=rs.evidence)
                ws8.cell(row=r, column=6, value=rs.recommendation)
                _style_data_row(ws8, r, len(ri_headers))
                ws8.cell(row=r, column=1).fill = FAIL_FILL
                ws8.cell(row=r, column=1).font = Font(bold=True, color="C62828")
                r += 1

            _auto_filter(ws8, 1, len(ri_headers))
            _auto_width(ws8)

    # ═══════════════════════════════════════════════════════════
    # Sheet 9: Compliance Assessment
    # ═══════════════════════════════════════════════════════════
    if compliance_results:
        from gotestwaf.report.compliance import ComplianceSummary
        ws9 = wb.create_sheet("Compliance")
        ws9.sheet_properties.tabColor = "1565C0"

        comp_headers = ["Framework", "Control ID", "Control Name", "Status", "Block Rate", "Evidence"]
        for c, hdr in enumerate(comp_headers, 1):
            ws9.cell(row=1, column=c, value=hdr)
        _style_header_row(ws9, 1, len(comp_headers))

        r = 2
        for fw_key, summary in compliance_results.items():
            if not isinstance(summary, ComplianceSummary):
                continue
            for ctrl in summary.controls:
                ws9.cell(row=r, column=1, value=summary.framework)
                ws9.cell(row=r, column=2, value=ctrl.control_id)
                ws9.cell(row=r, column=3, value=ctrl.name)
                ws9.cell(row=r, column=4, value=ctrl.status.upper())
                ws9.cell(row=r, column=5, value=f"{ctrl.block_rate:.0%}")
                ws9.cell(row=r, column=6, value=ctrl.evidence)
                _style_data_row(ws9, r, len(comp_headers))
                status_cell = ws9.cell(row=r, column=4)
                if ctrl.status == "pass":
                    status_cell.fill = PASS_FILL
                elif ctrl.status == "fail":
                    status_cell.fill = FAIL_FILL
                    status_cell.font = Font(bold=True, color="C62828")
                elif ctrl.status == "partial":
                    status_cell.fill = WARN_FILL
                r += 1

        _auto_filter(ws9, 1, len(comp_headers))
        _auto_width(ws9)

    # Save
    wb.save(report_file)
