"""3D HTML report generator with Three.js, Chart.js, Cyber Kill Chain, and MITRE ATT&CK.

Generates a self-contained HTML file with interactive 3D visualizations.
No external dependencies needed at runtime — CDN scripts loaded in browser.
"""

from __future__ import annotations

import html as h
import json
import math
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gotestwaf.db.statistics import Statistics

# MITRE technique mapping for WAF attack categories
ATTACK_MITRE_MAP = [
    {"a": "XSS", "mid": "T1059.007", "tac": "Execution", "kc": "Exploitation"},
    {"a": "SQL Injection", "mid": "T1190", "tac": "Initial Access", "kc": "Exploitation"},
    {"a": "RCE", "mid": "T1059", "tac": "Execution", "kc": "Exploitation"},
    {"a": "Path Traversal", "mid": "T1083", "tac": "Discovery", "kc": "Exploitation"},
    {"a": "NoSQL Injection", "mid": "T1190", "tac": "Initial Access", "kc": "Exploitation"},
    {"a": "CRLF", "mid": "T1557", "tac": "Collection", "kc": "Exploitation"},
    {"a": "LDAP Injection", "mid": "T1071.001", "tac": "C2", "kc": "Exploitation"},
    {"a": "Shell Injection", "mid": "T1059.004", "tac": "Execution", "kc": "Exploitation"},
    {"a": "XXE", "mid": "T1221", "tac": "Defense Evasion", "kc": "Weaponization"},
    {"a": "SSTI", "mid": "T1059", "tac": "Execution", "kc": "Exploitation"},
    {"a": "SSI", "mid": "T1505.003", "tac": "Persistence", "kc": "Installation"},
    {"a": "Mail Injection", "mid": "T1566.001", "tac": "Initial Access", "kc": "Delivery"},
    {"a": "XML Injection", "mid": "T1221", "tac": "Defense Evasion", "kc": "Weaponization"},
    {"a": "REST API", "mid": "T1106", "tac": "Execution", "kc": "Exploitation"},
    {"a": "SOAP", "mid": "T1106", "tac": "Execution", "kc": "Exploitation"},
]

# Attack type keyword → MITRE map index
_ATTACK_KEYWORDS = {
    "xss": 0, "scripting": 0, "sql": 1, "sqli": 1, "rce": 2, "command": 2,
    "path": 3, "traversal": 3, "lfi": 3, "nosql": 4, "crlf": 5,
    "ldap": 6, "shell": 7, "xxe": 8, "sst": 9, "template": 9,
    "ss-include": 10, "ssi": 10, "mail": 11, "xml": 12,
    "rest": 13, "non-crud": 13, "soap": 14, "graphql": 13, "grpc": 13,
}

KC_PHASES = ["Reconnaissance", "Weaponization", "Delivery", "Exploitation", "Installation", "C2", "Actions"]
KC_COLORS = ["#6366f1", "#8b5cf6", "#a855f7", "#d946ef", "#ec4899", "#f43f5e", "#ef4444"]


def generate_3d_html_report(
    stat: Statistics,
    report_time: datetime,
    waf_name: str,
    url: str,
    args: list[str],
    ignore_unresolved: bool,
    include_payloads: bool,
    ml_analysis: dict[str, object] | None = None,
    ruleset_inference: object | None = None,
    compliance_results: dict[str, object] | None = None,
) -> str:
    """Generate complete 3D HTML report from scan statistics."""

    # Build per-category data from summary table
    categories: dict[str, dict[str, int]] = {}
    for row in stat.true_positive_tests.summary_table:
        key = row.test_case
        if key not in categories:
            categories[key] = {"blocked": 0, "bypassed": 0, "unresolved": 0, "sent": 0}
        categories[key]["blocked"] += row.blocked
        categories[key]["bypassed"] += row.bypassed
        categories[key]["unresolved"] += row.unresolved
        categories[key]["sent"] += row.sent

    # Map categories to MITRE — keep separate blocked/bypassed/unresolved counts
    attacks_data = []
    for cat_name, counts in categories.items():
        mitre_idx = _match_mitre(cat_name)
        mitre = ATTACK_MITRE_MAP[mitre_idx]
        attacks_data.append({
            "a": cat_name, "mid": mitre["mid"], "tac": mitre["tac"], "kc": mitre["kc"],
            "t": counts["sent"],
            "b": counts["blocked"],
            "bp": counts["bypassed"],
            "ur": counts["unresolved"],
        })

    # Kill chain aggregation
    kc_data: dict[str, dict[str, int]] = {}
    for phase in KC_PHASES:
        pa = [a for a in attacks_data if a["kc"] == phase]
        kc_data[phase] = {"t": sum(a["t"] for a in pa), "b": sum(a["b"] for a in pa)}

    # Tactic aggregation
    tac_data: dict[str, dict[str, int]] = {}
    for a in attacks_data:
        tac_data.setdefault(a["tac"], {"t": 0, "b": 0})
        tac_data[a["tac"]]["t"] += a["t"]
        tac_data[a["tac"]]["b"] += a["b"]

    # Scores
    tp = stat.true_positive_tests
    tn = stat.true_negative_tests
    tp_pct = tp.resolved_blocked_requests_percentage
    tn_pct = tn.resolved_bypassed_requests_percentage
    overall = stat.score.average if stat.score.average >= 0 else 0

    # Sphere positions for 3D
    sphere_data = []
    for i, a in enumerate(attacks_data):
        pct = a["b"] / a["t"] * 100 if a["t"] > 0 else 0
        radius = math.sqrt(max(a["t"], 1)) * 0.12 + 0.25
        angle = (i / max(len(attacks_data), 1)) * math.pi * 2
        dist = 5 + (1 - pct / 100) * 3
        sphere_data.append({
            "x": round(math.cos(angle) * dist, 2),
            "y": round(radius + (i % 3) * 1.2, 2),
            "z": round(math.sin(angle) * dist, 2),
            "r": round(radius, 2),
            "c": "0x22c55e" if pct >= 95 else "0xeab308" if pct >= 50 else "0xef4444",
            "name": a["a"], "pct": round(pct, 1),
        })

    # Strengths / weaknesses — based on RESOLVED tests only, not unresolved
    strengths = [a for a in attacks_data if (a["b"] + a.get("bp", 0)) > 0 and a.get("bp", 0) == 0]
    weaknesses = [a for a in attacks_data if a.get("bp", 0) > 0]
    unresolved_cats = [a for a in attacks_data if a.get("ur", 0) > 0 and a.get("bp", 0) == 0 and a["b"] == 0]

    # Bypassed payloads
    bypasses = stat.true_positive_tests.bypasses

    now = report_time.strftime("%Y-%m-%d %H:%M")

    # ── BUILD HTML ──
    return _build_html(
        url, waf_name, now, overall, tp_pct, tn_pct, tp, tn, stat,
        attacks_data, kc_data, tac_data, sphere_data,
        strengths, weaknesses, unresolved_cats, bypasses, args, include_payloads,
        ml_analysis=ml_analysis,
        ruleset_inference=ruleset_inference,
        compliance_results=compliance_results,
    )


def _match_mitre(cat_name: str) -> int:
    """Match a test case name to a MITRE mapping index."""
    lower = cat_name.lower()
    for keyword, idx in _ATTACK_KEYWORDS.items():
        if keyword in lower:
            return idx
    return 0  # Default to XSS


def _diagnose_bypass(bp: Any) -> str:
    """Diagnose WHY a payload bypassed the WAF."""
    pl = bp.placeholder.lower() if bp.placeholder else ""
    enc = bp.encoder.lower() if bp.encoder else ""
    payload = bp.payload.lower() if bp.payload else ""

    if "useragent" in pl or "user-agent" in pl:
        return "WAF does not inspect User-Agent header for malicious content."
    if "rawrequest" in pl:
        return "WAF does not inspect custom/raw HTTP request constructions."
    if "header" in pl and "url" not in pl:
        return "WAF does not inspect custom HTTP headers for attack payloads."
    if "jsunicode" in enc:
        return "JSUnicode encoding evaded WAF pattern matching — WAF does not decode Unicode escapes before inspection."
    if "base64" in enc:
        return "Base64 encoding evaded WAF — WAF does not decode Base64 payloads before inspection."
    if "xmlentity" in enc:
        return "XML entity encoding bypassed WAF rules — WAF does not normalize XML entities."
    if "graphql" in pl:
        return "WAF does not inspect GraphQL query parameters for injection payloads."
    if "soap" in pl:
        return "WAF does not inspect SOAP body content for attack patterns."
    if "multipart" in pl:
        return "WAF does not inspect multipart form data fields for malicious content."
    if "__proto__" in payload or "constructor" in payload:
        return "Prototype pollution / indirect function calls evade WAF string matching rules."
    if "setinterval" in payload or "settimeout" in payload:
        return "Timer-based XSS (setInterval/setTimeout) not covered by WAF rules."
    if "confirm.call" in payload or "alert.apply" in payload:
        return "Indirect function invocation (call/apply) not matched by WAF regex rules."
    return "Payload pattern not covered by current WAF ruleset."


def _suggest_fix(bp: Any, waf_type: str = "") -> str:
    """Suggest a WAF-specific step-by-step fix for a bypassed payload."""
    pl = bp.placeholder.lower() if bp.placeholder else ""
    enc = bp.encoder.lower() if bp.encoder else ""
    payload = bp.payload.lower() if bp.payload else ""
    attack = bp.type.lower() if bp.type else ""
    waf = waf_type.lower()

    is_xss = "xss" in attack or "<script" in payload or "alert(" in payload
    is_sqli = "sql" in attack or "union" in payload or "select" in payload
    is_rce = "rce" in attack or "shell" in attack or "/etc/passwd" in payload
    is_lfi = "lfi" in attack or "traversal" in attack or "../" in payload

    if "cloudflare" in waf:
        if is_xss: return "Cloudflare > Security > WAF > Managed Rules > Enable Cloudflare Managed Ruleset (Block). Custom Rules > Field: URI+Body, match: script/alert/onerror, Action: Block"
        if is_sqli: return "Cloudflare > Security > WAF > Enable OWASP Core Ruleset (Paranoia 2+). Custom Rules > Field: Body, match: union/select/information_schema, Block"
        if is_rce: return "Cloudflare > Security > WAF > Custom Rules > Field: URI+Body, match: /etc/passwd, /bin/sh, cmd.exe, Action: Block"
        if "base64" in enc: return "Cloudflare > Security > WAF > Transform Rules > Decode Base64 in query/body before inspection. Enable OWASP with body decoding"
        if "header" in pl or "useragent" in pl: return "Cloudflare > Security > WAF > Custom Rules > Field: Request Headers (User-Agent, X-*), match attack patterns, Action: Block"
        return "Cloudflare > Security > WAF > Enable ALL Cloudflare+OWASP rulesets. Set sensitivity HIGH. Enable body+header inspection"

    if "siteground" in waf:
        if is_xss: return "SiteGround > Site Tools > Security > XSS Protection ON. Add ModSecurity: SecRule ARGS|REQUEST_BODY \"<script|alert\\\\(|onerror\" \"id:1001,deny,status:403\""
        if is_sqli: return "SiteGround > Site Tools > Security > SQLi Protection. Add ModSecurity: SecRule ARGS|REQUEST_BODY \"(?i)(union\\\\s+select|1=1|sleep\\\\()\" \"id:1002,deny,status:403\""
        if is_rce: return "Add ModSecurity: SecRule ARGS|REQUEST_BODY \"(?i)(/etc/passwd|/bin/sh|system\\\\()\" \"id:1003,deny,status:403,msg:RCE\""
        if "base64" in enc: return "Add ModSecurity with transform: SecRule ARGS \"@base64Decode\" \"chain,id:1004\"; SecRule MATCHED_VAR \"(?i)(script|select|passwd)\" \"deny,status:403\""
        if "header" in pl or "useragent" in pl: return "Add ModSecurity: SecRule REQUEST_HEADERS \"(?i)(<script|alert\\\\(|union\\\\s+select)\" \"id:1005,deny,status:403\""
        return "SiteGround > Site Tools > Security > Enable ALL protections. Add custom ModSecurity rules for bypassed patterns"

    if "aws" in waf:
        if is_xss: return "AWS WAF > Web ACL > Add AWSManagedRulesCommonRuleSet (XSS rules). Set override to Block (not Count)"
        if is_sqli: return "AWS WAF > Web ACL > Add AWSManagedRulesSQLiRuleSet + CommonRuleSet. Override all to Block"
        if is_rce: return "AWS WAF > Web ACL > Add AWSManagedRulesLinuxRuleSet + UnixRuleSet. Detects /etc/passwd, shell cmds"
        if "base64" in enc: return "AWS WAF > Rule > Text Transformation: BASE64_DECODE + URL_DECODE. Apply to Body, QueryString, Headers"
        return "AWS WAF > Add ALL Managed Rule Groups: Common, SQLi, Linux, KnownBadInputs. Set all to Block"

    if "azure" in waf:
        if is_xss: return "Azure WAF Policy > Managed Rules > OWASP 3.2 > Enable rules 941100-941340 (XSS). Set Mode to Prevention"
        if is_sqli: return "Azure WAF Policy > OWASP 3.2 > Enable rules 942100-942440 (SQLi). Add custom rule with UrlDecode+Lowercase transform"
        return "Azure WAF Policy > Switch to Prevention mode. Enable complete OWASP 3.2 ruleset. Add Base64Decode transforms"

    if "modsec" in waf or "naxsi" in waf:
        if is_xss: return "Enable CRS 941xxx (XSS). SecRule ARGS|REQUEST_BODY \"(?i)(<script|onerror=)\" \"id:941001,phase:2,deny,status:403\". SecRuleEngine On"
        if is_sqli: return "Enable CRS 942xxx (SQLi). SecRule ARGS|REQUEST_BODY \"(?i)(union\\\\s+select|sleep\\\\()\" \"id:942001,phase:2,deny,status:403\""
        return "SecRuleEngine On. Enable full OWASP CRS. Increase Paranoia Level to 2+"

    if is_xss: return "Enable XSS rules. Match: <script, javascript:, onerror=, alert(. Apply to URL, body, AND headers"
    if is_sqli: return "Enable SQLi rules. Match: union select, information_schema, sleep(). Apply URL+Base64 decode transforms"
    if is_rce: return "Enable RCE rules. Block: /etc/passwd, /bin/sh, system(), exec(). Inspect URL, body, AND headers"
    if is_lfi: return "Enable LFI rules. Block: ../, ..\\\\, /etc/, /proc/. URL-decode before matching"
    if "base64" in enc: return "Enable Base64 decode transform. All rules should match AFTER decoding Base64+URL encoding"
    if "header" in pl or "useragent" in pl: return "Enable header inspection for ALL headers including User-Agent and custom X-* headers"
    return "Review WAF ruleset. Enable all rule groups. Set to blocking mode (not monitor/detect only)"


def _render_http_exchange(bp: Any, max_body: int = 600, max_headers: int = 12) -> str:
    """Render the raw HTTP request sent and response received for a finding."""
    method = h.escape(getattr(bp, "request_method", "") or "")
    url = h.escape(getattr(bp, "request_url", "") or "")
    req_headers = getattr(bp, "request_headers", {}) or {}
    req_body = getattr(bp, "request_body", "") or ""
    resp_status = getattr(bp, "response_status_code", 0)
    resp_headers = getattr(bp, "response_headers", {}) or {}
    resp_body = getattr(bp, "response_body", "") or ""

    if not (method or url or req_headers or req_body or resp_headers or resp_body):
        return '<div style="color:#374151;font-size:11px;margin-top:8px">No raw HTTP exchange captured for this finding.</div>'

    def _fmt_headers(hdrs: dict) -> str:
        items = list(hdrs.items())[:max_headers]
        extra = len(hdrs) - len(items)
        lines = [f"{h.escape(str(k))}: {h.escape(str(v))}" for k, v in items]
        if extra > 0:
            lines.append(f"... (+{extra} more)")
        return "\n".join(lines) if lines else "(none)"

    req_start = f"{method} {url}".strip() or "(request line not captured)"
    body_display = req_body[:max_body] + ("..." if len(req_body) > max_body else "")
    resp_body_display = resp_body[:max_body] + ("..." if len(resp_body) > max_body else "")

    box_style = (
        "background:#f9fafb;border:1px solid #e5e7eb;"
        "border-radius:8px;padding:10px 12px;margin:6px 0;font-family:ui-monospace,Consolas,monospace;"
        "font-size:11px;white-space:pre-wrap;word-break:break-all;color:#000000;max-height:260px;overflow:auto"
    )
    out = ['<div style="margin-top:10px">']
    out.append('<div style="font-weight:700;color:#60a5fa;font-size:11px;margin-top:8px">&#128228; REQUEST SENT</div>')
    out.append(f'<div style="{box_style}">{h.escape(req_start)}\n{_fmt_headers(req_headers)}'
               f'{chr(10) + chr(10) + h.escape(body_display) if body_display else ""}</div>')
    out.append('<div style="font-weight:700;color:#a78bfa;font-size:11px;margin-top:8px">&#128229; RESPONSE RECEIVED</div>')
    out.append(f'<div style="{box_style}">HTTP {resp_status}\n{_fmt_headers(resp_headers)}'
               f'{chr(10) + chr(10) + h.escape(resp_body_display) if resp_body_display else ""}</div>')
    out.append('</div>')
    return "".join(out)


def _get_mitre_for_type(attack_type: str) -> str:
    """Get MITRE technique ID and name for an attack type."""
    if not attack_type:
        return "N/A"
    t = attack_type.lower()
    mapping = {
        "xss": "T1059.007 — Command and Scripting Interpreter: JavaScript",
        "sql injection": "T1190 — Exploit Public-Facing Application",
        "rce": "T1059 — Command and Scripting Interpreter",
        "lfi": "T1083 — File and Directory Discovery",
        "path traversal": "T1083 — File and Directory Discovery",
        "nosql": "T1190 — Exploit Public-Facing Application",
        "crlf": "T1557 — Adversary-in-the-Middle",
        "ldap": "T1071.001 — Application Layer Protocol",
        "shell": "T1059.004 — Unix Shell",
        "xxe": "T1221 — Template Injection",
        "ssti": "T1059 — Command and Scripting Interpreter",
        "ssi": "T1505.003 — Web Shell",
        "rest": "T1106 — Native API",
        "soap": "T1106 — Native API",
    }
    for key, val in mapping.items():
        if key in t:
            return val
    return "T1190 — Exploit Public-Facing Application"


def _diagnose_false_positive(payload: str) -> str:
    """Explain why a benign payload was blocked."""
    pl = payload.lower()
    if any(kw in pl for kw in ["select", "union", "drop", "insert", "update", "delete"]):
        return "SQL-like keywords in normal text triggered SQLi rules. Consider whitelisting common English words."
    if "<" in payload and ">" in payload:
        return "Angle brackets in normal text triggered XSS rules. Consider context-aware rules that distinguish HTML tags from regular text."
    if "'" in payload or '"' in payload:
        return "Quote characters triggered injection detection. Consider allowing quotes in non-parameterized contexts."
    if "../" in payload:
        return "Path-like pattern in normal text triggered LFI rules."
    if len(payload) > 1000:
        return "Large payload size triggered length-based blocking rules."
    return "Overly aggressive WAF rule matched benign content. Review and tune WAF sensitivity."


def _build_html(
    url: str, waf_name: str, now: str, overall: float, tp_pct: float, tn_pct: float,
    tp: Any, tn: Any, stat: Any,
    attacks_data: list[dict], kc_data: dict, tac_data: dict, sphere_data: list[dict],
    strengths: list[dict], weaknesses: list[dict], unresolved_cats: list[dict],
    bypasses: list, args: list[str], include_payloads: bool,
    ml_analysis: dict[str, object] | None = None,
    ruleset_inference: object | None = None,
    compliance_results: dict[str, object] | None = None,
) -> str:
    """Build the complete HTML string."""

    attack_labels = json.dumps([a["a"] for a in attacks_data])
    attack_blocked = json.dumps([a["b"] for a in attacks_data])
    attack_bypassed = json.dumps([a.get("bp", 0) for a in attacks_data])
    attack_unresolved = json.dumps([a.get("ur", 0) for a in attacks_data])
    kc_blocked_js = json.dumps([kc_data[p]["b"] for p in KC_PHASES])
    kc_bypassed_js = json.dumps([sum(a.get("bp", 0) for a in attacks_data if a["kc"] == p) for p in KC_PHASES])
    tac_labels_js = json.dumps(list(tac_data.keys()))
    tac_rates_js = json.dumps([round(v["b"] / v["t"] * 100, 1) if v["t"] > 0 else 0 for v in tac_data.values()])

    # ── ML / research-quality aggregations (must live inside _build_html
    # because the ML chart blocks reference these names) ──
    blocked_attacks = stat.true_positive_tests.blocked
    bypassed_attacks = stat.true_positive_tests.bypasses
    fp_blocked_count = stat.true_negative_tests.req_stats.blocked_requests_number
    fp_passed_count = stat.true_negative_tests.req_stats.bypassed_requests_number

    from collections import Counter as _Counter
    enc_stats: dict[str, dict[str, int]] = {}
    plc_stats: dict[str, dict[str, int]] = {}
    pair_stats: dict[tuple, dict[str, int]] = {}      # (encoder, placement) → counts
    status_counter: dict[str, _Counter] = {           # status code distribution per outcome
        "blocked": _Counter(), "bypassed": _Counter(),
    }
    attack_type_bypassed: _Counter = _Counter()       # bypasses bucketed by attack type

    for grp_name, grp in (("blocked", blocked_attacks), ("bypassed", bypassed_attacks)):
        for t in grp:
            enc = (t.encoder or "Plain") or "Plain"
            plc = (t.placeholder or "Unknown") or "Unknown"
            enc_stats.setdefault(enc, {"blocked": 0, "bypassed": 0})[grp_name] += 1
            plc_stats.setdefault(plc, {"blocked": 0, "bypassed": 0})[grp_name] += 1
            pair_stats.setdefault((enc, plc), {"blocked": 0, "bypassed": 0})[grp_name] += 1
            # Don't collapse status 0 into "n/a": HTTP status 0 commonly
            # represents a connection-level failure (no response received),
            # which is meaningful diagnostic information distinct from an
            # actually-missing field.
            sc = getattr(t, "response_status_code", None)
            status = str(sc) if sc is not None else "n/a"
            status_counter[grp_name][status] += 1
            if grp_name == "bypassed":
                # Use test_set+case as a proxy for attack type
                attack_type_bypassed[f"{t.test_set}/{t.test_case}"] += 1

    enc_labels = sorted(enc_stats.keys())
    enc_blocked = [enc_stats[e]["blocked"] for e in enc_labels]
    enc_bypassed = [enc_stats[e]["bypassed"] for e in enc_labels]
    plc_labels = sorted(plc_stats.keys())
    plc_blocked = [plc_stats[p]["blocked"] for p in plc_labels]
    plc_bypassed = [plc_stats[p]["bypassed"] for p in plc_labels]

    # Encoder × Placement bypass % (heatmap-style stacked bars)
    pair_rows = []
    for (enc, plc), counts in pair_stats.items():
        total = counts["blocked"] + counts["bypassed"]
        if total >= 1:
            bypass_pct = round(100 * counts["bypassed"] / total, 1)
            pair_rows.append({"label": f"{enc} / {plc}", "pct": bypass_pct, "n": total})
    pair_rows.sort(key=lambda r: -r["pct"])
    pair_rows = pair_rows[:15]
    pair_labels = [r["label"] for r in pair_rows]
    pair_pct = [r["pct"] for r in pair_rows]

    # Response-status code distribution (combined blocked + bypassed)
    all_status = _Counter()
    for c in status_counter.values():
        all_status.update(c)
    status_labels_sorted = sorted(all_status.keys(), key=lambda s: -all_status[s])[:10]
    status_counts_sorted = [all_status[s] for s in status_labels_sorted]

    cat_rate_rows = sorted(
        [(a["a"], a["t"], a["b"], a.get("bp", 0)) for a in attacks_data
         if (a["b"] + a.get("bp", 0)) >= 1],
        key=lambda r: -(r[1]),
    )[:12]
    cat_rate_labels = [r[0][:35] for r in cat_rate_rows]
    cat_rate_blocked_pct = [round(100 * r[2] / max(r[2] + r[3], 1), 1) for r in cat_rate_rows]
    cat_rate_bypassed_pct = [round(100 * r[3] / max(r[2] + r[3], 1), 1) for r in cat_rate_rows]

    # ML candidate scatter: bypass-probability × confidence
    bc_list = []
    if ml_analysis and isinstance(ml_analysis, dict):
        bc_list = ml_analysis.get("bypass_candidates") or []
    bc_scatter = [
        {"x": float(bc.get("bypass_probability", 0)),
         "y": float(bc.get("confidence", 0))}
        for bc in bc_list[:200]
    ]

    o: list[str] = []

    # Head
    o.append(f'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>3D WAF Assessment - {h.escape(waf_name)}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:Inter,-apple-system,sans-serif;background:#ffffff;color:#000000;font-size:13px;line-height:1.7}}
.w{{max-width:1100px;margin:0 auto;padding:30px 20px}}
h1{{font-size:28px;font-weight:900;color:#000000}}
h2{{font-size:19px;font-weight:700;color:#000000;margin:36px 0 14px;padding-bottom:7px;border-bottom:2px solid #1d4ed8}}
h3{{font-size:14px;font-weight:700;color:#000000;margin:18px 0 10px}}
.card{{background:#ffffff;border:1px solid #d4d4d8;border-radius:10px;padding:20px;margin:14px 0;box-shadow:0 1px 3px rgba(0,0,0,0.04)}}
.glow{{}}
.ms{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:16px 0}}
.m{{background:#f9fafb;border-radius:8px;padding:16px;text-align:center;border:1px solid #e5e7eb}}
.mv{{font-size:28px;font-weight:900;color:#000000}}
.ml{{font-size:11px;color:#374151;margin-top:4px}}
table{{border-collapse:collapse;width:100%;font-size:12px;margin:10px 0;background:#ffffff;color:#000000}}
th{{background:#f3f4f6;padding:9px;text-align:left;border:1px solid #d4d4d8;color:#000000;font-weight:700}}
td{{padding:7px 9px;border:1px solid #e5e7eb;color:#000000}}
tr:nth-child(even){{background:#fafafa}}
.tag{{display:inline-block;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:700;color:#ffffff}}
.tc{{background:#dc2626}}.th{{background:#ea580c}}.tm{{background:#ca8a04;color:#ffffff}}.tl{{background:#16a34a}}.ti{{background:#475569}}
.detail-btn{{background:#1d4ed8;color:#ffffff;border:none;padding:6px 16px;border-radius:5px;font-size:11px;font-weight:700;cursor:pointer;transition:background 0.15s}}
.detail-btn:hover{{background:#1e40af}}
.detail-btn.open{{background:#374151}}
.detail-content{{display:none;margin-top:10px;animation:fadeIn 0.3s ease}}
.detail-content.show{{display:block}}
@keyframes fadeIn{{from{{opacity:0;transform:translateY(-5px)}}to{{opacity:1;transform:translateY(0)}}}}
#scene{{width:100%;height:480px;border-radius:10px;cursor:grab;background:#f9fafb;border:1px solid #d4d4d8}}
#scene:active{{cursor:grabbing}}
.ch{{position:relative;height:440px;background:#ffffff;padding:14px;border:1px solid #d4d4d8;border-radius:6px}}.chs{{height:360px}}
.chart-wrap{{position:relative;background:#ffffff;border-radius:6px;padding:0;margin:6px 0 14px}}
.dl-btn{{position:absolute;top:10px;right:10px;background:#1d4ed8;color:#ffffff;border:none;padding:6px 14px;border-radius:5px;font-size:12px;font-weight:700;cursor:pointer;z-index:10;transition:background 0.15s;letter-spacing:0.02em}}
.dl-btn:hover{{background:#1e40af}}
.kc{{display:flex;align-items:center;justify-content:center;flex-wrap:wrap;gap:4px;margin:20px 0}}
.kn{{padding:10px 14px;border-radius:6px;color:#ffffff;font-weight:700;font-size:11px;text-align:center;min-width:100px;box-shadow:0 1px 4px rgba(0,0,0,0.12);transition:transform 0.2s}}.kn:hover{{transform:translateY(-2px)}}
.ka{{color:#374151;font-size:16px;margin:0 2px}}
.str{{border-left:3px solid #16a34a;background:#f0fdf4;padding:10px 14px;margin:5px 0;border-radius:0 6px 6px 0;font-size:12px;color:#000000}}
.wk{{border-left:3px solid #dc2626;background:#fef2f2;padding:10px 14px;margin:5px 0;border-radius:0 6px 6px 0;font-size:12px;color:#000000}}
.bp{{border-left:3px solid #dc2626;background:#fef2f2;padding:10px;margin:5px 0;border-radius:0 6px 6px 0;font-size:12px;color:#000000}}
.vuln{{border-left:3px solid #1d4ed8;background:#eff6ff;padding:10px 14px;margin:8px 0;border-radius:0 6px 6px 0;font-size:12px;color:#000000}}
.mono{{font-family:Consolas,Monaco,monospace;font-size:11px;word-break:break-all;color:#000000}}
code{{font-family:Consolas,Monaco,monospace;background:#f3f4f6;color:#000000;padding:1px 5px;border-radius:3px;font-size:11px}}
pre{{font-family:Consolas,Monaco,monospace;background:#f3f4f6;color:#000000;padding:8px 10px;border-radius:5px;font-size:10px;border:1px solid #e5e7eb;max-height:200px;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:0}}
@media print{{body{{background:#ffffff}}.dl-btn{{display:none}}}}
</style>
<script>
// Publication-grade PNG export.
// Chart.js with devicePixelRatio=2 already doubles the canvas backing-store,
// so an 800px CSS chart yields a 1600x1600px PNG — sharp at print sizes.
// Composite onto white before save so transparent regions don't render black.
function downloadChartPNG(canvasId, filename){{
    var c=document.getElementById(canvasId);
    if(!c){{console.warn('Canvas not found:',canvasId);return;}}
    if(c.width===0||c.height===0){{console.warn('Canvas not yet rendered:',canvasId);return;}}
    var tmp=document.createElement('canvas');
    tmp.width=c.width;tmp.height=c.height;
    var tx=tmp.getContext('2d');
    tx.fillStyle='#ffffff';tx.fillRect(0,0,tmp.width,tmp.height);
    tx.drawImage(c,0,0);
    var a=document.createElement('a');
    a.href=tmp.toDataURL('image/png',1.0);
    a.download=filename;
    document.body.appendChild(a);a.click();document.body.removeChild(a);
}}
function downloadAllCharts(){{
    document.querySelectorAll('canvas').forEach(function(c){{
        if(c.id) downloadChartPNG(c.id, 'waf-chart-'+c.id+'.png');
    }});
}}
</script></head><body><div class="w">''')

    # Title
    o.append(f'<h1>3D WAF &amp; Firewall Security Assessment</h1>')
    o.append(f'<p style="color:#000000">Target: <b style="color:#000000">{h.escape(url)}</b> | {now} | WAF: {h.escape(waf_name)}</p>')
    if args:
        o.append(f'<p style="color:#374151;font-size:11px">Args: {h.escape(" ".join(args))}</p>')

    # Global download-all-charts button (sticks at top so reviewers can grab everything)
    o.append('<div style="margin:14px 0"><button class="detail-btn" onclick="downloadAllCharts()">Download All Charts as PNG</button></div>')

    # Scores
    o.append('<h2>Security Scores</h2><div class="ms">')
    for val, lbl in [(f"{overall:.1f}%", "Overall"), (f"{tp_pct:.1f}%", "Attack Detection"),
                     (str(tp.req_stats.blocked_requests_number), "Blocked"),
                     (str(tp.req_stats.bypassed_requests_number), "Bypassed"),
                     (str(tp.req_stats.unresolved_requests_number), "Unresolved"),
                     (str(tp.req_stats.all_requests_number), "Total Sent")]:
        o.append(f'<div class="m glow"><div class="mv">{val}</div><div class="ml">{lbl}</div></div>')
    o.append('</div>')

    # 3D Scene
    o.append('<h2>3D Attack Surface</h2><div class="card glow"><div id="scene"></div>')
    o.append('<p style="font-size:11px;color:#374151;text-align:center;margin-top:8px">Drag to rotate. Scroll to zoom. Green=blocked, Red=bypassed, Size=volume.</p></div>')

    # Kill Chain
    o.append('<h2>Cyber Kill Chain</h2><div class="card glow"><div class="kc">')
    for i, (phase, color) in enumerate(zip(KC_PHASES, KC_COLORS)):
        d = kc_data.get(phase, {"t": 0, "b": 0})
        pct = d["b"] / d["t"] * 100 if d["t"] > 0 else 0
        op = "1" if d["t"] > 0 else "0.3"
        o.append(f'<div class="kn" style="background:{color};opacity:{op}">{phase}<br><small>{d["b"]}/{d["t"]} ({pct:.0f}%)</small></div>')
        if i < len(KC_PHASES) - 1:
            o.append('<span class="ka">&#9654;</span>')
    o.append('</div><div class="chart-wrap"><button class="dl-btn" onclick="downloadChartPNG(\'kcC\',\'waf-kill-chain.png\')">Download PNG</button>'
             '<div class="ch chs"><canvas id="kcC"></canvas></div></div></div>')

    # MITRE heatmap
    o.append('<h2>MITRE ATT&amp;CK Detection</h2><div class="card glow"><div class="chart-wrap">'
             '<button class="dl-btn" onclick="downloadChartPNG(\'miC\',\'waf-mitre-attack.png\')">Download PNG</button>'
             '<div class="ch"><canvas id="miC"></canvas></div></div></div>')

    # Radar
    o.append('<h2>Tactic Radar</h2><div class="card glow"><div class="chart-wrap">'
             '<button class="dl-btn" onclick="downloadChartPNG(\'raC\',\'waf-tactic-radar.png\')">Download PNG</button>'
             '<div class="ch chs"><canvas id="raC"></canvas></div></div></div>')

    # Doughnut — raw counts
    o.append('<h2>Detection Distribution</h2><div class="card glow"><div class="chart-wrap">'
             '<button class="dl-btn" onclick="downloadChartPNG(\'doC\',\'waf-detection-distribution.png\')">Download PNG</button>'
             '<div class="ch chs"><canvas id="doC"></canvas></div></div></div>')

    # ── PIE CHARTS: Overall Attack Prevention & Bypass Ratios ──
    tp_blocked_n = tp.req_stats.blocked_requests_number
    tp_bypassed_n = tp.req_stats.bypassed_requests_number
    tp_unresolved_n = tp.req_stats.unresolved_requests_number
    tp_resolved_n = tp_blocked_n + tp_bypassed_n
    tn_blocked_n = tn.req_stats.blocked_requests_number
    tn_bypassed_n = tn.req_stats.bypassed_requests_number

    o.append('<h2>Overall Attack Prevention &amp; Bypass Ratios</h2>')
    o.append('<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px">')
    # Pie 1: Attack Prevention Rate
    o.append('<div class="card glow"><div class="chart-wrap">'
             '<button class="dl-btn" onclick="downloadChartPNG(\'pieAP\',\'waf-attack-prevention.png\')">PNG</button>'
             '<div class="ch chs"><canvas id="pieAP"></canvas></div></div></div>')
    # Pie 2: True-Positive vs True-Negative
    o.append('<div class="card glow"><div class="chart-wrap">'
             '<button class="dl-btn" onclick="downloadChartPNG(\'pieTP\',\'waf-accuracy-breakdown.png\')">PNG</button>'
             '<div class="ch chs"><canvas id="pieTP"></canvas></div></div></div>')
    # Pie 3: Top Weakness Categories
    o.append('<div class="card glow"><div class="chart-wrap">'
             '<button class="dl-btn" onclick="downloadChartPNG(\'pieWK\',\'waf-top-weaknesses.png\')">PNG</button>'
             '<div class="ch chs"><canvas id="pieWK"></canvas></div></div></div>')
    o.append('</div>')

    # Build top weakness data (categories with most bypasses)
    weakness_sorted = sorted(weaknesses, key=lambda x: x.get("bp", 0), reverse=True)[:8]
    # Labels are placed into a <script> block via json.dumps below; json.dumps
    # already escapes for the JS string context (e.g. </script> -> </script>).
    # Pre-applying h.escape here would corrupt the displayed text (& -> &amp;)
    # without adding any safety.
    wk_labels = [w["a"][:25] for w in weakness_sorted]
    wk_data = [w.get("bp", 0) for w in weakness_sorted]
    wk_colors = ['#ef4444', '#f97316', '#f59e0b', '#eab308', '#84cc16', '#06b6d4', '#8b5cf6', '#ec4899']

    # Strengths
    o.append('<h2>Firewall Strengths</h2><div class="card">')
    if strengths:
        for a in strengths:
            o.append(f'<div class="str"><b>{h.escape(a["a"])}</b> ({a["mid"]}) — <span style="color:#16a34a">100% blocked</span> ({a["b"]}/{a["t"]})</div>')
    else:
        o.append('<div class="str">No fully blocked categories found in resolved tests.</div>')
    o.append('</div>')

    # Weaknesses — only categories with actual bypasses
    o.append('<h2>Firewall Weaknesses</h2><div class="card">')
    if weaknesses:
        for a in weaknesses:
            resolved = a["b"] + a.get("bp", 0)
            pct = a["b"] / resolved * 100 if resolved > 0 else 0
            o.append(f'<div class="wk"><b>{h.escape(a["a"])}</b> ({a["mid"]}) — <span style="color:#ef4444">{pct:.1f}% blocked, {a.get("bp",0)} bypassed</span></div>')
    else:
        o.append('<div class="str">No confirmed bypasses detected in resolved tests.</div>')
    if unresolved_cats:
        o.append(f'<p style="color:#ca8a04;font-size:12px;margin-top:10px"><b>Note:</b> {len(unresolved_cats)} categories had only unresolved results (could not determine if blocked or bypassed). These are NOT counted as weaknesses.</p>')
    o.append('</div>')

    # ══════ TRUE FINDINGS WITH PoC — COLLAPSIBLE ══════
    finding_id = 0

    # ── PER-CATEGORY PoC — show evidence for EVERY category ──
    o.append(f'<h2>&#128270; Per-Category PoC Evidence</h2>')
    o.append('<p style="color:#374151">Click <b>"Show PoC Details"</b> on any finding to see the exact payload, HTTP response, root cause analysis, and fix recommendation.</p>')
    o.append('<div class="card">')
    for a in sorted(attacks_data, key=lambda x: x.get("bp", 0), reverse=True):
        finding_id += 1
        fid = f"cat{finding_id}"
        resolved = a["b"] + a.get("bp", 0)
        pct = a["b"] / resolved * 100 if resolved > 0 else 0
        bp = a.get("bp", 0)
        ur = a.get("ur", 0)

        if bp > 0:
            border_color = "#ef4444"
            status_tag = f'<span class="tag tc">{bp} BYPASSED</span>'
        elif a["b"] > 0 and ur == 0:
            border_color = "#22c55e"
            status_tag = f'<span class="tag tl">100% BLOCKED</span>'
        elif ur > 0 and a["b"] == 0:
            border_color = "#eab308"
            status_tag = f'<span class="tag tm">UNRESOLVED</span>'
        else:
            border_color = "#64748b"
            status_tag = f'<span class="tag ti">NO DATA</span>'

        o.append(f'<div style="border-left:4px solid {border_color};padding:12px;margin:8px 0;background:rgba(255,255,255,0.02);border-radius:0 10px 10px 0">')
        o.append(f'<div style="display:flex;justify-content:space-between;align-items:center">')
        o.append(f'<div><b>{h.escape(a["a"])}</b> <span class="mono" style="color:#374151">({a["mid"]})</span> {status_tag} <span style="color:#374151;font-size:11px">| {a["b"]} blocked, {bp} bypassed, {ur} unresolved of {a["t"]} sent</span></div>')
        o.append(f'<button class="detail-btn" onclick="toggleDetail(\'{fid}\',this)">Show PoC Details</button></div>')
        o.append(f'<div class="detail-content" id="{fid}">')

        # Find actual payloads for this category from the stats
        cat_bypasses = [x for x in bypasses if x.test_case == a["a"]] if bypasses else []
        cat_blocked = [x for x in (stat.true_positive_tests.blocked or []) if x.test_case == a["a"]][:2]
        cat_unresolved = [x for x in (stat.true_positive_tests.unresolved or []) if x.test_case == a["a"]][:2]

        if cat_bypasses:
            o.append(f'<h3 style="color:#dc2626;font-size:13px;margin:10px 0 6px">&#128308; Bypassed Payloads</h3>')
            for j, bp_item in enumerate(cat_bypasses[:3], 1):
                cause = _diagnose_bypass(bp_item)
                fix = _suggest_fix(bp_item, waf_type=waf_name)
                o.append(f'<table style="font-size:11px;margin:4px 0 10px"><tr><th style="width:120px">PoC #{j}</th><th></th></tr>')
                o.append(f'<tr><td><b>Payload</b></td><td><span class="mono" style="color:#000000;background:#fef9c3;padding:2px 6px;border-radius:4px">{h.escape(bp_item.payload[:250])}</span></td></tr>')
                o.append(f'<tr><td><b>Encoder</b></td><td>{h.escape(bp_item.encoder)}</td></tr>')
                o.append(f'<tr><td><b>Placement</b></td><td>{h.escape(bp_item.placeholder)}</td></tr>')
                o.append(f'<tr><td><b>HTTP Status</b></td><td><span style="color:#ef4444;font-weight:700">{bp_item.response_status_code}</span> — NOT blocked</td></tr>')
                o.append(f'<tr><td><b>Root Cause</b></td><td style="color:#000000">{h.escape(cause)}</td></tr>')
                o.append(f'<tr><td><b>Remediation</b></td><td style="color:#16a34a">{h.escape(fix)}</td></tr>')
                o.append(f'<tr><td><b>MITRE</b></td><td>{h.escape(_get_mitre_for_type(bp_item.type))}</td></tr>')
                # Full HTTP Request
                req_method = getattr(bp_item, 'request_method', '') or 'GET'
                req_url = getattr(bp_item, 'request_url', '') or ''
                req_hdrs = getattr(bp_item, 'request_headers', {}) or {}
                req_body = getattr(bp_item, 'request_body', '') or ''
                if req_url:
                    req_lines = f'{h.escape(req_method)} {h.escape(req_url)} HTTP/1.1'
                    for hk, hv in req_hdrs.items():
                        req_lines += f'\n{h.escape(str(hk))}: {h.escape(str(hv))}'
                    if req_body:
                        req_lines += f'\n\n{h.escape(req_body[:800])}'
                    o.append(f'<tr><td><b>Full Request</b></td><td><pre style="background:#f3f4f6;color:#000000;padding:8px 10px;border-radius:6px;font-size:10px;max-height:200px;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:0">{req_lines}</pre></td></tr>')
                # Full HTTP Response
                resp_hdrs = getattr(bp_item, 'response_headers', {}) or {}
                resp_body = getattr(bp_item, 'response_body', '') or ''
                if resp_hdrs or resp_body:
                    resp_lines = f'HTTP/1.1 {bp_item.response_status_code}'
                    for hk, hv in resp_hdrs.items():
                        resp_lines += f'\n{h.escape(str(hk))}: {h.escape(str(hv))}'
                    if resp_body:
                        resp_lines += f'\n\n{h.escape(resp_body[:800])}'
                    o.append(f'<tr><td><b>Full Response</b></td><td><pre style="background:#f3f4f6;color:#000000;padding:8px 10px;border-radius:6px;font-size:10px;max-height:200px;overflow:auto;white-space:pre-wrap;word-break:break-all;margin:0">{resp_lines}</pre></td></tr>')
                o.append(f'</table>')

        if cat_blocked:
            o.append(f'<h3 style="color:#16a34a;font-size:13px;margin:10px 0 6px">&#128994; Blocked Samples</h3>')
            for j, bl_item in enumerate(cat_blocked, 1):
                o.append(f'<table style="font-size:11px;margin:4px 0 10px"><tr><th style="width:120px">Sample #{j}</th><th></th></tr>')
                o.append(f'<tr><td><b>Payload</b></td><td class="mono">{h.escape(bl_item.payload[:200])}</td></tr>')
                o.append(f'<tr><td><b>Encoder</b></td><td>{h.escape(bl_item.encoder)} / {h.escape(bl_item.placeholder)}</td></tr>')
                o.append(f'<tr><td><b>HTTP Status</b></td><td><span style="color:#16a34a;font-weight:700">{bl_item.response_status_code}</span> — Correctly blocked</td></tr>')
                o.append(f'</table>')

        if cat_unresolved:
            o.append(f'<h3 style="color:#ca8a04;font-size:13px;margin:10px 0 6px">&#128992; Unresolved Samples</h3>')
            for j, ur_item in enumerate(cat_unresolved, 1):
                reason = "Response ambiguous"
                if ur_item.response_status_code == 202:
                    reason = "CAPTCHA challenge page returned — cookie may have expired"
                o.append(f'<table style="font-size:11px;margin:4px 0 10px"><tr><th style="width:120px">Sample #{j}</th><th></th></tr>')
                o.append(f'<tr><td><b>Payload</b></td><td class="mono">{h.escape(ur_item.payload[:200])}</td></tr>')
                o.append(f'<tr><td><b>Status</b></td><td>{ur_item.response_status_code} — {reason}</td></tr>')
                o.append(f'</table>')

        if not cat_bypasses and not cat_blocked and not cat_unresolved:
            o.append(f'<p style="color:#374151;font-size:12px">No individual payload data available for this category (gRPC/GraphQL not connected).</p>')

        o.append(f'</div></div>')
    o.append('</div>')

    # ── BYPASSES (legacy section — keep for compatibility) ──
    if bypasses:
        o.append(f'<h2>&#128308; True Findings — Bypassed Attacks ({len(bypasses)})</h2>')
        o.append('<p style="color:#dc2626">Verified: these payloads reached the application without being blocked by the WAF.</p>')
        o.append('<div class="card" style="border:1px solid rgba(239,68,68,0.3)">')
        for i, bp in enumerate(bypasses[:30], 1):
            finding_id += 1
            fid = f"f{finding_id}"
            cause = _diagnose_bypass(bp)
            fix = _suggest_fix(bp)
            o.append(f'<div style="border-left:4px solid #ef4444;padding:14px;margin:10px 0;background:rgba(239,68,68,0.04);border-radius:0 10px 10px 0">')
            o.append(f'<div style="display:flex;justify-content:space-between;align-items:center">')
            o.append(f'<div><span style="font-weight:700;color:#dc2626">Finding #{finding_id}</span> <span class="tag tc">BYPASS</span> <span style="color:#374151;font-size:11px">{h.escape(bp.test_set)}/{h.escape(bp.test_case)}</span></div>')
            o.append(f'<button class="detail-btn" onclick="toggleDetail(\'{fid}\',this)">Show PoC Details</button></div>')
            o.append(f'<div class="detail-content" id="{fid}">')
            o.append(f'<table style="font-size:11px;margin:8px 0 0"><tr><th style="width:130px">Evidence</th><th>Detail</th></tr>')
            o.append(f'<tr><td><b>Attack Type</b></td><td>{h.escape(bp.type) if bp.type else "N/A"}</td></tr>')
            o.append(f'<tr><td><b>Encoder</b></td><td>{h.escape(bp.encoder)}</td></tr>')
            o.append(f'<tr><td><b>Delivery Method</b></td><td>{h.escape(bp.placeholder)}</td></tr>')
            o.append(f'<tr><td><b>Payload Sent</b></td><td><span class="mono" style="color:#000000;background:#fef9c3;padding:2px 6px;border-radius:4px">{h.escape(bp.payload[:300])}</span></td></tr>')
            o.append(f'<tr><td><b>Response Status</b></td><td><span style="color:#ef4444;font-weight:700">HTTP {bp.response_status_code}</span> — WAF did NOT block this request</td></tr>')
            o.append(f'<tr><td><b>Root Cause</b></td><td style="color:#000000">{h.escape(cause)}</td></tr>')
            o.append(f'<tr><td><b>Remediation</b></td><td style="color:#16a34a">{h.escape(fix)}</td></tr>')
            o.append(f'<tr><td><b>MITRE ATT&amp;CK</b></td><td>{h.escape(_get_mitre_for_type(bp.type))}</td></tr>')
            o.append(f'</table>')
            o.append(_render_http_exchange(bp))
            o.append(f'</div></div>')
        o.append('</div>')

    # ── BLOCKED (sample proof) ──
    blocked_all = stat.true_positive_tests.blocked or []
    if blocked_all:
        o.append(f'<h2>&#128994; True Findings — Blocked Attacks ({len(blocked_all)} total)</h2>')
        o.append('<p style="color:#16a34a">Verified: these attacks were correctly detected and blocked by the WAF.</p>')
        o.append('<div class="card" style="border:1px solid rgba(34,197,94,0.3)">')
        for i, bp in enumerate(blocked_all[:10], 1):
            finding_id += 1
            fid = f"f{finding_id}"
            o.append(f'<div style="border-left:4px solid #22c55e;padding:14px;margin:10px 0;background:rgba(34,197,94,0.04);border-radius:0 10px 10px 0">')
            o.append(f'<div style="display:flex;justify-content:space-between;align-items:center">')
            o.append(f'<div><span style="font-weight:700;color:#16a34a">Finding #{finding_id}</span> <span class="tag tl">BLOCKED &#10003;</span> <span style="color:#374151;font-size:11px">{h.escape(bp.test_set)}/{h.escape(bp.test_case)}</span></div>')
            o.append(f'<button class="detail-btn" onclick="toggleDetail(\'{fid}\',this)">Show PoC Details</button></div>')
            o.append(f'<div class="detail-content" id="{fid}">')
            o.append(f'<table style="font-size:11px;margin:8px 0 0"><tr><th style="width:130px">Evidence</th><th>Detail</th></tr>')
            o.append(f'<tr><td><b>Attack Type</b></td><td>{h.escape(bp.type) if bp.type else "N/A"}</td></tr>')
            o.append(f'<tr><td><b>Encoder / Placement</b></td><td>{h.escape(bp.encoder)} / {h.escape(bp.placeholder)}</td></tr>')
            o.append(f'<tr><td><b>Payload Sent</b></td><td><span class="mono">{h.escape(bp.payload[:200])}</span></td></tr>')
            o.append(f'<tr><td><b>Response Status</b></td><td><span style="color:#16a34a;font-weight:700">HTTP {bp.response_status_code}</span> — WAF blocked correctly</td></tr>')
            o.append(f'</table>')
            o.append(_render_http_exchange(bp))
            o.append(f'</div></div>')
        if len(blocked_all) > 10:
            o.append(f'<p style="color:#374151;font-size:12px;margin-top:8px">+ {len(blocked_all) - 10} more blocked attacks (showing top 10)</p>')
        o.append('</div>')

    # ── UNRESOLVED ──
    unresolved_all = stat.true_positive_tests.unresolved or []
    if unresolved_all:
        o.append(f'<h2>&#128992; Unresolved Requests ({len(unresolved_all)})</h2>')
        o.append('<p style="color:#ca8a04">Could not classify — response matched neither block nor pass criteria.</p>')
        o.append('<div class="card" style="border:1px solid rgba(234,179,8,0.3)">')
        for i, bp in enumerate(unresolved_all[:5], 1):
            finding_id += 1
            fid = f"f{finding_id}"
            cause = "Response ambiguous."
            if bp.response_status_code == 202:
                cause = "CAPTCHA page returned (202) — session cookie expired mid-scan."
            elif bp.response_status_code == 0:
                cause = "No response — connection reset or timeout."
            elif bp.response_status_code in (403, 200):
                cause = "Status matched both block AND pass criteria simultaneously."
            o.append(f'<div style="border-left:4px solid #eab308;padding:14px;margin:10px 0;background:rgba(234,179,8,0.04);border-radius:0 10px 10px 0">')
            o.append(f'<div style="display:flex;justify-content:space-between;align-items:center">')
            o.append(f'<div><span style="font-weight:700;color:#ca8a04">Finding #{finding_id}</span> <span class="tag tm">UNRESOLVED</span> <span style="color:#374151;font-size:11px">{h.escape(bp.test_set)}/{h.escape(bp.test_case)}</span></div>')
            o.append(f'<button class="detail-btn" onclick="toggleDetail(\'{fid}\',this)">Show Details</button></div>')
            o.append(f'<div class="detail-content" id="{fid}">')
            o.append(f'<table style="font-size:11px;margin:8px 0 0"><tr><th style="width:130px">Field</th><th>Value</th></tr>')
            o.append(f'<tr><td><b>Payload</b></td><td class="mono">{h.escape(bp.payload[:200])}</td></tr>')
            o.append(f'<tr><td><b>HTTP Status</b></td><td>{bp.response_status_code}</td></tr>')
            o.append(f'<tr><td><b>Reason</b></td><td style="color:#ca8a04">{h.escape(cause)}</td></tr>')
            o.append(f'</table></div></div>')
        if len(unresolved_all) > 5:
            o.append(f'<p style="color:#374151;font-size:12px;margin-top:8px">+ {len(unresolved_all) - 5} more unresolved</p>')
        o.append('</div>')

    # ══════ FULL RESULTS TABLE — ACCURATE COUNTS ══════
    o.append('<h2>Full Results Table</h2><div class="card"><table><tr><th>Category</th><th>MITRE</th><th>Tactic</th><th>Sent</th><th>Blocked</th><th>Bypassed</th><th>Unresolved</th><th>Block Rate</th></tr>')
    for a in sorted(attacks_data, key=lambda x: x["b"] / max(x["b"] + x.get("bp", 0), 1) * 100):
        resolved = a["b"] + a.get("bp", 0)
        pct = a["b"] / resolved * 100 if resolved > 0 else 0
        ur = a.get("ur", 0)
        bp = a.get("bp", 0)
        tcls = "tc" if pct < 80 else "th" if pct < 95 else "tm" if pct < 100 else "tl"
        if resolved == 0 and a["t"] > 0:
            tcls = "ti"  # All unresolved — grey
            pct_str = "N/R"
        else:
            pct_str = f"{pct:.0f}%"
        bp_style = 'color:#ef4444;font-weight:700' if bp > 0 else ''
        ur_style = 'color:#ca8a04' if ur > 0 else ''
        o.append(f'<tr><td><b>{h.escape(a["a"])}</b></td><td class="mono">{a["mid"]}</td><td>{h.escape(a["tac"])}</td><td>{a["t"]}</td><td>{a["b"]}</td><td style="{bp_style}">{bp}</td><td style="{ur_style}">{ur}</td><td><span class="tag {tcls}">{pct_str}</span></td></tr>')
    o.append('</table></div>')

    # Footer
    o.append(f'<p style="margin-top:40px;border-top:1px solid #e5e7eb;padding:12px;font-size:10px;color:#374151;text-align:center">GoTestWAF Advanced Report | {now}</p>')
    o.append('</div>')

    # ── SCRIPTS ──
    blocked_total = tp.req_stats.blocked_requests_number
    bypassed_total = tp.req_stats.bypassed_requests_number
    unresolved_total = tp.req_stats.unresolved_requests_number

    o.append(f'''<script>
// Toggle detail panels
function toggleDetail(id, btn) {{
  const el = document.getElementById(id);
  if (!el) return;
  const isOpen = el.classList.contains('show');
  el.classList.toggle('show');
  btn.textContent = isOpen ? 'Show PoC Details' : 'Hide Details';
  btn.classList.toggle('open');
}}

// 3D Scene
(function(){{
const el=document.getElementById('scene');
if(!el)return;
const W=el.clientWidth,H=el.clientHeight;
const scene=new THREE.Scene();
scene.background=new THREE.Color(0xf9fafb);
scene.fog=new THREE.Fog(0xf9fafb,22,50);
const cam=new THREE.PerspectiveCamera(55,W/H,0.1,100);
const ren=new THREE.WebGLRenderer({{antialias:true,preserveDrawingBuffer:true}});
ren.setSize(W,H);ren.setPixelRatio(Math.min(window.devicePixelRatio,2));
el.appendChild(ren.domElement);
scene.add(new THREE.AmbientLight(0xffffff,0.7));
const dl=new THREE.DirectionalLight(0xffffff,0.6);dl.position.set(5,10,7);scene.add(dl);
const grid=new THREE.GridHelper(24,24,0xd4d4d8,0xe5e7eb);grid.position.y=-0.5;scene.add(grid);
const ms=[];
{json.dumps(sphere_data)}.forEach(s=>{{
const g=new THREE.SphereGeometry(s.r,24,24);
const m=new THREE.MeshPhongMaterial({{color:parseInt(s.c),transparent:true,opacity:0.85,shininess:80}});
const mesh=new THREE.Mesh(g,m);mesh.position.set(s.x,s.y,s.z);scene.add(mesh);ms.push(mesh);
const rg=new THREE.TorusGeometry(s.r*1.4,0.03,8,32);
const rm=new THREE.MeshBasicMaterial({{color:parseInt(s.c),transparent:true,opacity:0.25}});
const ring=new THREE.Mesh(rg,rm);ring.position.copy(mesh.position);ring.rotation.x=Math.PI/2;scene.add(ring);
const lg=new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(s.x,-0.5,s.z),new THREE.Vector3(s.x,s.y-s.r,s.z)]);
scene.add(new THREE.Line(lg,new THREE.LineBasicMaterial({{color:parseInt(s.c),transparent:true,opacity:0.15}})));
}});
let ang=0,dist=16,ht=8,drag=false,lx=0,ly=0;
el.addEventListener('mousedown',e=>{{drag=true;lx=e.clientX;ly=e.clientY}});
el.addEventListener('mousemove',e=>{{if(!drag)return;ang+=(e.clientX-lx)*0.008;ht+=(e.clientY-ly)*0.04;ht=Math.max(2,Math.min(18,ht));lx=e.clientX;ly=e.clientY}});
el.addEventListener('mouseup',()=>drag=false);
el.addEventListener('mouseleave',()=>drag=false);
el.addEventListener('wheel',e=>{{dist+=e.deltaY*0.015;dist=Math.max(6,Math.min(30,dist))}});
el.addEventListener('touchstart',e=>{{drag=true;lx=e.touches[0].clientX;ly=e.touches[0].clientY}});
el.addEventListener('touchmove',e=>{{if(!drag)return;ang+=(e.touches[0].clientX-lx)*0.008;ht+=(e.touches[0].clientY-ly)*0.04;ht=Math.max(2,Math.min(18,ht));lx=e.touches[0].clientX;ly=e.touches[0].clientY}});
el.addEventListener('touchend',()=>drag=false);
function anim(){{requestAnimationFrame(anim);if(!drag)ang+=0.004;
cam.position.x=Math.sin(ang)*dist;cam.position.z=Math.cos(ang)*dist;cam.position.y=ht;cam.lookAt(0,2,0);
const t=Date.now()*0.001;ms.forEach((m,i)=>m.scale.setScalar(1+Math.sin(t*2+i)*0.04));
ren.render(scene,cam)}}anim();
window.addEventListener('resize',()=>{{const w=el.clientWidth,hh=el.clientHeight;cam.aspect=w/hh;cam.updateProjectionMatrix();ren.setSize(w,hh)}});
}})();

// Journal-quality defaults — large readable fonts, black axes, color-blind-friendly palette
Chart.defaults.color='#000000';
Chart.defaults.borderColor='#9ca3af';
Chart.defaults.font.family='"Helvetica Neue",Helvetica,Arial,sans-serif';
Chart.defaults.font.size=13;
Chart.defaults.font.weight='500';
Chart.defaults.devicePixelRatio=2;  // Crisper PNG export

// Reusable styling fragments — keep all charts consistent
var TITLE_FONT={{size:17,weight:'bold',family:'"Helvetica Neue",Helvetica,Arial,sans-serif'}};
var AXIS_TITLE_FONT={{size:14,weight:'bold'}};
var TICK_FONT={{size:13,weight:'500'}};
var LEGEND_FONT={{size:13,weight:'600'}};
var GRID_COLOR='#d4d4d8';

new Chart(document.getElementById('kcC'),{{type:'bar',
  data:{{labels:{json.dumps(KC_PHASES)},datasets:[
    {{label:'Blocked',data:{kc_blocked_js},backgroundColor:{json.dumps(KC_COLORS)},borderColor:'#000000',borderWidth:1,borderRadius:4}},
    {{label:'Bypassed',data:{kc_bypassed_js},backgroundColor:'#dc2626',borderColor:'#000000',borderWidth:1,borderRadius:4}}
  ]}},
  options:{{responsive:true,maintainAspectRatio:false,layout:{{padding:{{top:10,bottom:10,left:6,right:6}}}},
    plugins:{{title:{{display:true,text:'Cyber Kill-Chain Coverage',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{position:'top',labels:{{color:'#000000',font:LEGEND_FONT,padding:14,boxWidth:18}}}}}},
    scales:{{y:{{stacked:true,beginAtZero:true,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,precision:0}},title:{{display:true,text:'Number of payloads',color:'#000000',font:AXIS_TITLE_FONT}}}},
      x:{{stacked:true,grid:{{display:false}},ticks:{{color:'#000000',font:TICK_FONT}}}}}}}}}});

new Chart(document.getElementById('miC'),{{type:'bar',
  data:{{labels:{attack_labels},datasets:[
    {{label:'Blocked',data:{attack_blocked},backgroundColor:'#16a34a',borderColor:'#000000',borderWidth:0.5,borderRadius:3}},
    {{label:'Bypassed',data:{attack_bypassed},backgroundColor:'#dc2626',borderColor:'#000000',borderWidth:0.5,borderRadius:3}},
    {{label:'Unresolved',data:{attack_unresolved},backgroundColor:'#ca8a04',borderColor:'#000000',borderWidth:0.5,borderRadius:3}}
  ]}},
  options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,layout:{{padding:{{top:10,bottom:10,left:6,right:6}}}},
    plugins:{{title:{{display:true,text:'MITRE ATT&CK Coverage by Attack Category',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{position:'top',labels:{{color:'#000000',font:LEGEND_FONT,padding:14,boxWidth:18}}}}}},
    scales:{{x:{{stacked:true,beginAtZero:true,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,precision:0}},title:{{display:true,text:'Number of payloads',color:'#000000',font:AXIS_TITLE_FONT}}}},
      y:{{stacked:true,grid:{{display:false}},ticks:{{color:'#000000',font:{{size:12,weight:'500'}}}}}}}}}}}});

new Chart(document.getElementById('raC'),{{type:'radar',
  data:{{labels:{tac_labels_js},datasets:[{{label:'Detection rate (%)',data:{tac_rates_js},
    backgroundColor:'rgba(29,78,216,0.20)',borderColor:'#1d4ed8',borderWidth:2.5,
    pointBackgroundColor:'#1d4ed8',pointBorderColor:'#ffffff',pointBorderWidth:2,pointRadius:6,pointHoverRadius:8}}]}},
  options:{{responsive:true,maintainAspectRatio:false,layout:{{padding:14}},
    scales:{{r:{{min:0,max:100,ticks:{{stepSize:25,color:'#000000',backdropColor:'#ffffff',font:TICK_FONT}},
      grid:{{color:GRID_COLOR}},angleLines:{{color:GRID_COLOR}},
      pointLabels:{{color:'#000000',font:{{size:13,weight:'600'}}}}}}}},
    plugins:{{title:{{display:true,text:'MITRE Tactic Coverage (Detection %)',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{position:'top',labels:{{color:'#000000',font:LEGEND_FONT,padding:12}}}}}}}}}});

new Chart(document.getElementById('doC'),{{type:'doughnut',
  data:{{labels:['Blocked ({blocked_total})','Bypassed ({bypassed_total})','Unresolved ({unresolved_total})'],
    datasets:[{{data:[{blocked_total},{bypassed_total},{unresolved_total}],
      backgroundColor:['#16a34a','#dc2626','#ca8a04'],borderColor:'#ffffff',borderWidth:3,hoverOffset:14}}]}},
  options:{{responsive:true,maintainAspectRatio:false,cutout:'55%',layout:{{padding:14}},
    plugins:{{title:{{display:true,text:'Outcome Distribution (All Tests)',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{position:'bottom',labels:{{color:'#000000',padding:14,font:LEGEND_FONT,boxWidth:18}}}}}}}}}});

new Chart(document.getElementById('pieAP'),{{type:'pie',
  data:{{labels:['Attacks Blocked ({tp_blocked_n})','Attacks Bypassed ({tp_bypassed_n})','Unresolved ({tp_unresolved_n})'],
    datasets:[{{data:[{tp_blocked_n},{tp_bypassed_n},{tp_unresolved_n}],
      backgroundColor:['#16a34a','#dc2626','#ca8a04'],borderColor:'#ffffff',borderWidth:3,hoverOffset:12}}]}},
  options:{{responsive:true,maintainAspectRatio:false,layout:{{padding:14}},
    plugins:{{title:{{display:true,text:'Attack Prevention — {tp_pct:.1f}% Blocked',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{position:'bottom',labels:{{color:'#000000',padding:12,font:LEGEND_FONT,boxWidth:16}}}}}}}}}});

new Chart(document.getElementById('pieTP'),{{type:'pie',
  data:{{labels:['Attacks Blocked ({tp_blocked_n})','Attacks Bypassed ({tp_bypassed_n})','Benign Blocked ({tn_blocked_n})','Benign Passed ({tn_bypassed_n})'],
    datasets:[{{data:[{tp_blocked_n},{tp_bypassed_n},{tn_blocked_n},{tn_bypassed_n}],
      backgroundColor:['#16a34a','#dc2626','#ea580c','#1d4ed8'],borderColor:'#ffffff',borderWidth:3,hoverOffset:12}}]}},
  options:{{responsive:true,maintainAspectRatio:false,layout:{{padding:14}},
    plugins:{{title:{{display:true,text:'WAF Accuracy Breakdown — Composite {overall:.1f}%',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{position:'bottom',labels:{{color:'#000000',padding:12,font:LEGEND_FONT,boxWidth:16}}}}}}}}}});

new Chart(document.getElementById('pieWK'),{{type:'pie',
  data:{{labels:{json.dumps(wk_labels)},datasets:[{{data:{json.dumps(wk_data)},
    backgroundColor:{json.dumps(wk_colors[:len(wk_data)])},borderColor:'#ffffff',borderWidth:3,hoverOffset:12}}]}},
  options:{{responsive:true,maintainAspectRatio:false,layout:{{padding:14}},
    plugins:{{title:{{display:true,text:'Top Bypassed Attack Categories',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{position:'bottom',labels:{{color:'#000000',padding:10,font:{{size:12,weight:'600'}},boxWidth:14}}}}}}}}}});
</script>
''')

    # ── ML Intelligence Section (before closing body/html) ──
    if ml_analysis and ml_analysis.get("metrics"):
        metrics = ml_analysis.get("metrics", {})
        bypass_candidates = ml_analysis.get("bypass_candidates", [])
        mutation_suggestions = ml_analysis.get("mutation_suggestions", [])
        high_risk = ml_analysis.get("high_bypass_risk", 0)
        is_trained = metrics.get("is_trained", False)

        o.append('<h2>ML Intelligence Engine</h2>')
        o.append('<div class="card glow">')

        if is_trained:
            # `dict.get(k, default)` returns None when the key exists with a
            # value of None — that crashed `{cv_f1:.2f}` with TypeError.
            # `or 0` collapses both missing-key AND key-with-None to 0.
            cv_f1 = float(metrics.get("cv_f1_score") or 0)
            samples = int(metrics.get("training_samples") or 0)
            feat_imp = metrics.get("feature_importance") or {}

            o.append(f'''<div class="ms">
<div class="m"><div class="mv">{cv_f1:.2f}</div><div class="ml">Model F1 Score</div></div>
<div class="m"><div class="mv">{samples}</div><div class="ml">Training Samples</div></div>
<div class="m"><div class="mv">{len(bypass_candidates)}</div><div class="ml">Bypass Candidates</div></div>
<div class="m"><div class="mv" style="color:#dc2626">{high_risk}</div><div class="ml">High Risk (&gt;50%)</div></div>
</div>''')

            o.append('<div style="background:#eff6ff;border-left:4px solid #1d4ed8;padding:8px 14px;margin:18px 0 6px;border-radius:0 6px 6px 0"><strong style="color:#1d4ed8">GROUP 1 — MODEL PERFORMANCE</strong> &nbsp;<span style="color:#374151;font-size:11px">Confusion matrix, class balance, cross-validation, predictive features, anomaly detection</span></div>')

            # ── Confusion Matrix (TP/FP/TN/FN) ──
            tp_blocked = tp_blocked_n
            tp_bypassed = tp_bypassed_n
            tn_passed = fp_passed_count
            fp_blocked = fp_blocked_count
            o.append('<h3>WAF Confusion Matrix</h3>')
            o.append('<p style="color:#374151;font-size:12px">'
                     'Ground truth (rows) vs WAF action (columns). '
                     'Strong WAFs have most weight on the green diagonal cells.</p>')
            o.append('<div class="chart-wrap">'
                     '<button class="dl-btn" onclick="downloadChartPNG(\'mlCM\',\'waf-ml-confusion-matrix.png\')">Download PNG</button>'
                     '<div class="ch chs"><canvas id="mlCM"></canvas></div></div>')
            o.append(f'''<script>
new Chart(document.getElementById('mlCM'),{{type:'bar',
  data:{{labels:['Attack (ground-truth malicious)','Benign (ground-truth safe)'],
    datasets:[
      {{label:'WAF blocked',data:[{tp_blocked},{fp_blocked}],
        backgroundColor:['#16a34a','#dc2626']}},
      {{label:'WAF allowed',data:[{tp_bypassed},{tn_passed}],
        backgroundColor:['#dc2626','#16a34a']}}
    ]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{title:{{display:true,text:'WAF Confusion Matrix (TP/FN/FP/TN)',color:'#000000',font:TITLE_FONT}},
      legend:{{position:'top',labels:{{color:'#000000',font:LEGEND_FONT,padding:14,boxWidth:18}}}},
      tooltip:{{callbacks:{{label:function(ctx){{
        var labels=[['True Positive (correct block)','False Negative (missed attack)'],
                    ['False Positive (over-block)','True Negative (correct allow)']];
        var di=ctx.datasetIndex,ii=ctx.dataIndex;
        return labels[di][ii]+': '+ctx.parsed.y;
      }}}}}}}},
    scales:{{y:{{stacked:true,beginAtZero:true,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000'}},title:{{display:true,text:'Number of requests',color:'#000000',font:AXIS_TITLE_FONT}}}},
      x:{{stacked:true,grid:{{display:false}},ticks:{{color:'#000000'}}}}}}}}}});
</script>''')

            # ── Class Balance Donut (training set) ──
            # Coerce to int — `metrics` originates from the ML engine but the
            # type isn't statically guaranteed. Without `int()` a string
            # value would land unescaped inside a JS string literal.
            blocked_train = int(metrics.get("blocked") or tp_blocked or 0)
            bypassed_train = int(metrics.get("bypassed") or tp_bypassed or 0)
            o.append('<h3>Training Class Balance</h3>')
            o.append('<div class="chart-wrap">'
                     '<button class="dl-btn" onclick="downloadChartPNG(\'mlCB\',\'waf-ml-class-balance.png\')">Download PNG</button>'
                     '<div class="ch chs"><canvas id="mlCB"></canvas></div></div>')
            o.append(f'''<script>
new Chart(document.getElementById('mlCB'),{{type:'doughnut',
  data:{{labels:['Blocked ({blocked_train})','Bypassed ({bypassed_train})'],
    datasets:[{{data:[{blocked_train},{bypassed_train}],
      backgroundColor:['#16a34a','#dc2626'],borderColor:'#ffffff',borderWidth:3,hoverOffset:10}}]}},
  options:{{responsive:true,maintainAspectRatio:false,cutout:'55%',
    plugins:{{title:{{display:true,text:'Training Set Class Balance ({blocked_train+bypassed_train} samples)',color:'#000000',font:TITLE_FONT}},
      legend:{{position:'bottom',labels:{{color:'#000000',padding:14,font:LEGEND_FONT,boxWidth:18}}}}}}}}}});
</script>''')

            # ── Cross-validation gauge ──
            cv_pct = max(0.0, min(1.0, float(cv_f1))) * 100
            o.append('<h3>ML Model Performance — Cross-Validation F1</h3>')
            o.append('<div class="chart-wrap">'
                     '<button class="dl-btn" onclick="downloadChartPNG(\'mlCV\',\'waf-ml-cv-f1.png\')">Download PNG</button>'
                     '<div class="ch chs"><canvas id="mlCV"></canvas></div></div>')
            cv_color = '#16a34a' if cv_pct >= 70 else '#ca8a04' if cv_pct >= 50 else '#dc2626'
            o.append(f'''<script>
new Chart(document.getElementById('mlCV'),{{type:'doughnut',
  data:{{labels:['CV F1','Headroom'],
    datasets:[{{data:[{cv_pct:.2f},{100-cv_pct:.2f}],
      backgroundColor:['{cv_color}','#e5e7eb'],borderColor:'#ffffff',borderWidth:3}}]}},
  options:{{responsive:true,maintainAspectRatio:false,cutout:'72%',rotation:-90,circumference:180,
    plugins:{{title:{{display:true,text:'5-Fold Cross-Validation F1: {cv_pct:.1f}%',color:'#000000',font:TITLE_FONT}},
      legend:{{display:false}},
      tooltip:{{enabled:false}}}}}}}});
</script>''')

            # ── Feature importance — Chart.js horizontal bar (research-quality) ──
            if feat_imp:
                feat_items = list(feat_imp.items())[:10]
                feat_labels = [k for k, _ in feat_items]
                feat_values = [round(float(v), 4) for _, v in feat_items]
                o.append('<h3>Top Predictive Features (Hybrid ML)</h3>')
                o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlFeatC\',\'waf-ml-feature-importance.png\')">Download PNG</button>'
                         '<div class="ch"><canvas id="mlFeatC"></canvas></div></div>')
                o.append(f'''<script>
new Chart(document.getElementById('mlFeatC'),{{type:'bar',
  data:{{labels:{json.dumps(feat_labels)},
    datasets:[{{label:'Feature importance',data:{json.dumps(feat_values)},
      backgroundColor:'#1d4ed8',borderRadius:3}}]}},
  options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,
    plugins:{{title:{{display:true,text:'Hybrid ML — Top {len(feat_labels)} Predictive Features',color:'#000000',font:TITLE_FONT}},
      legend:{{display:false}}}},
    scales:{{x:{{grid:{{color:GRID_COLOR}},ticks:{{color:'#000000'}},title:{{display:true,text:'Importance score',color:'#000000',font:AXIS_TITLE_FONT}}}},
      y:{{grid:{{display:false}},ticks:{{color:'#000000',font:{{family:'Consolas,Monaco,monospace',size:12,weight:'500'}}}}}}}}}}}});
</script>''')
                o.append('<table><tr><th>Feature</th><th>Importance</th></tr>')
                for fname, fval in feat_items:
                    o.append(f'<tr><td><code>{h.escape(fname)}</code></td><td>{fval:.4f}</td></tr>')
                o.append('</table>')

            # ── Per-Class Precision / Recall / F1 (from OOF predictions) ──
            per_class = metrics.get("per_class") or {}
            if per_class.get("blocked") and per_class.get("bypassed"):
                pc_b = per_class["blocked"]; pc_p = per_class["bypassed"]
                pc_metrics = ['Precision', 'Recall', 'F1']
                pc_blocked_vals = [round(pc_b['precision']*100,1), round(pc_b['recall']*100,1), round(pc_b['f1']*100,1)]
                pc_bypass_vals = [round(pc_p['precision']*100,1), round(pc_p['recall']*100,1), round(pc_p['f1']*100,1)]
                o.append('<h3>Per-Class Precision / Recall / F1</h3>')
                o.append('<p style="color:#374151;font-size:12px">'
                         'Out-of-fold metrics measured at threshold 0.5. Strong model = both classes have high P/R. '
                         f'Class support: blocked={pc_b["support"]} / bypassed={pc_p["support"]}.</p>')
                o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlPRF\',\'waf-ml-per-class-prf.png\')">Download PNG</button>'
                         '<div class="ch chs"><canvas id="mlPRF"></canvas></div></div>')
                o.append(f'''<script>
new Chart(document.getElementById('mlPRF'),{{type:'bar',
  data:{{labels:{json.dumps(pc_metrics)},
    datasets:[
      {{label:'Blocked class',data:{json.dumps(pc_blocked_vals)},backgroundColor:'#16a34a',borderColor:'#000000',borderWidth:0.5,borderRadius:3}},
      {{label:'Bypassed class',data:{json.dumps(pc_bypass_vals)},backgroundColor:'#dc2626',borderColor:'#000000',borderWidth:0.5,borderRadius:3}}
    ]}},
  options:{{responsive:true,maintainAspectRatio:false,layout:{{padding:14}},
    plugins:{{title:{{display:true,text:'Per-Class Performance (Out-of-Fold @ 0.5)',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{position:'top',labels:{{color:'#000000',font:LEGEND_FONT,padding:14,boxWidth:18}}}}}},
    scales:{{y:{{beginAtZero:true,max:100,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,callback:function(v){{return v+'%'}}}}}},
      x:{{grid:{{display:false}},ticks:{{color:'#000000',font:TICK_FONT}}}}}}}}}});
</script>''')

            # ── Calibration / Reliability Diagram ──
            calibration = metrics.get("calibration") or []
            if calibration:
                cal_pred = [c.get("predicted_mean", 0) for c in calibration]
                cal_actual = [c.get("actual_freq", 0) for c in calibration]
                cal_count = [c.get("count", 0) for c in calibration]
                cal_points = [{"x": p, "y": a} for p, a in zip(cal_pred, cal_actual)]
                # Diagonal reference line for perfect calibration
                cal_diag = [{"x": 0, "y": 0}, {"x": 1, "y": 1}]
                o.append('<h3>Reliability Diagram (Calibration Plot)</h3>')
                o.append('<p style="color:#374151;font-size:12px">'
                         'Out-of-fold predicted probability (x) vs actual class frequency (y), binned by decile. '
                         'A well-calibrated model lies on the dashed diagonal — points above = under-confident, points below = over-confident.</p>')
                o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlCalib\',\'waf-ml-calibration-plot.png\')">Download PNG</button>'
                         '<div class="ch chs"><canvas id="mlCalib"></canvas></div></div>')
                o.append(f'''<script>
new Chart(document.getElementById('mlCalib'),{{type:'scatter',
  data:{{datasets:[
    {{label:'Perfect calibration',data:{json.dumps(cal_diag)},
      type:'line',borderColor:'#475569',borderDash:[6,6],borderWidth:1.5,pointRadius:0,fill:false}},
    {{label:'Model (binned)',data:{json.dumps(cal_points)},
      backgroundColor:'#1d4ed8',borderColor:'#000000',pointRadius:7,pointHoverRadius:9,
      borderWidth:1,showLine:true,fill:false,tension:0.1}}
  ]}},
  options:{{responsive:true,maintainAspectRatio:false,layout:{{padding:14}},
    plugins:{{title:{{display:true,text:'Calibration / Reliability Diagram',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{position:'top',labels:{{color:'#000000',font:LEGEND_FONT,padding:14,boxWidth:24}}}},
      tooltip:{{callbacks:{{label:function(ctx){{
        if(ctx.datasetIndex===0) return null;
        var counts={json.dumps(cal_count)};
        return 'Predicted '+(ctx.parsed.x*100).toFixed(0)+'% → Actual '+(ctx.parsed.y*100).toFixed(0)+'% (n='+counts[ctx.dataIndex]+')';
      }}}}}}}},
    scales:{{x:{{type:'linear',min:0,max:1,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,callback:function(v){{return (v*100).toFixed(0)+'%'}}}},title:{{display:true,text:'Predicted probability (mean of bin)',color:'#000000',font:AXIS_TITLE_FONT}}}},
      y:{{type:'linear',min:0,max:1,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,callback:function(v){{return (v*100).toFixed(0)+'%'}}}},title:{{display:true,text:'Actual class-1 frequency in bin',color:'#000000',font:AXIS_TITLE_FONT}}}}}}}}}});
</script>''')

            # ── Anomaly Detection (model intrinsic, lives with performance) ──
            anomaly_stats = metrics.get("anomaly_stats", {})
            if anomaly_stats:
                o.append('<h3>Anomaly Detection</h3>')
                o.append(f'<div class="ms">')
                o.append(f'<div class="m"><div class="mv">{anomaly_stats.get("anomaly_pct", 0):.1%}</div><div class="ml">Anomalous Responses</div></div>')
                o.append(f'<div class="m"><div class="mv">{anomaly_stats.get("mean_score", 0):.3f}</div><div class="ml">Mean Anomaly Score</div></div>')
                o.append(f'</div>')

            o.append('<div style="background:#fef3c7;border-left:4px solid #ca8a04;padding:8px 14px;margin:24px 0 6px;border-radius:0 6px 6px 0"><strong style="color:#92400e">GROUP 2 — OPERATIONAL RESULTS</strong> &nbsp;<span style="color:#374151;font-size:11px">Per-category, per-encoder, per-placement bypass breakdowns</span></div>')

            # ── Bypass rate per attack category ──
            o.append('<h3>Bypass Rate by Attack Category</h3>')
            o.append('<p style="color:#374151;font-size:12px">'
                     'For each test category, the share of attacks the WAF blocked vs bypassed (out of resolved tests).</p>')
            o.append('<div class="chart-wrap">'
                     '<button class="dl-btn" onclick="downloadChartPNG(\'mlCat\',\'waf-ml-bypass-by-category.png\')">Download PNG</button>'
                     '<div class="ch"><canvas id="mlCat"></canvas></div></div>')
            o.append(f'''<script>
new Chart(document.getElementById('mlCat'),{{type:'bar',
  data:{{labels:{json.dumps(cat_rate_labels)},
    datasets:[
      {{label:'Blocked %',data:{json.dumps(cat_rate_blocked_pct)},backgroundColor:'#16a34a'}},
      {{label:'Bypassed %',data:{json.dumps(cat_rate_bypassed_pct)},backgroundColor:'#dc2626'}}
    ]}},
  options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,
    plugins:{{title:{{display:true,text:'Bypass / Block Rate per Attack Category (% of resolved)',color:'#000000',font:TITLE_FONT}},
      legend:{{position:'top',labels:{{color:'#000000',font:LEGEND_FONT,padding:14,boxWidth:18}}}}}},
    scales:{{x:{{stacked:true,beginAtZero:true,max:100,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',callback:function(v){{return v+'%'}}}}}},
      y:{{stacked:true,grid:{{display:false}},ticks:{{color:'#000000',font:TICK_FONT}}}}}}}}}});
</script>''')

            # ── Bypass count by Encoder ──
            o.append('<h3>Block / Bypass by Encoder</h3>')
            o.append('<p style="color:#374151;font-size:12px">'
                     'Which payload encoders the WAF struggles with. A tall red bar means the WAF does not normalize that encoding before inspection.</p>')
            o.append('<div class="chart-wrap">'
                     '<button class="dl-btn" onclick="downloadChartPNG(\'mlEnc\',\'waf-ml-bypass-by-encoder.png\')">Download PNG</button>'
                     '<div class="ch chs"><canvas id="mlEnc"></canvas></div></div>')
            o.append(f'''<script>
new Chart(document.getElementById('mlEnc'),{{type:'bar',
  data:{{labels:{json.dumps(enc_labels)},
    datasets:[
      {{label:'Blocked',data:{json.dumps(enc_blocked)},backgroundColor:'#16a34a'}},
      {{label:'Bypassed',data:{json.dumps(enc_bypassed)},backgroundColor:'#dc2626'}}
    ]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{title:{{display:true,text:'Block / Bypass by Encoder',color:'#000000',font:TITLE_FONT}},
      legend:{{position:'top',labels:{{color:'#000000',font:LEGEND_FONT,padding:14,boxWidth:18}}}}}},
    scales:{{y:{{beginAtZero:true,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,precision:0}},title:{{display:true,text:'Number of payloads',color:'#000000',font:AXIS_TITLE_FONT}}}},
      x:{{grid:{{display:false}},ticks:{{color:'#000000'}}}}}}}}}});
</script>''')

            # ── Bypass count by Placement ──
            o.append('<h3>Block / Bypass by Placement</h3>')
            o.append('<p style="color:#374151;font-size:12px">'
                     'Which request location (URL param, header, JSON body, etc.) is hardest for the WAF to inspect.</p>')
            o.append('<div class="chart-wrap">'
                     '<button class="dl-btn" onclick="downloadChartPNG(\'mlPlc\',\'waf-ml-bypass-by-placement.png\')">Download PNG</button>'
                     '<div class="ch chs"><canvas id="mlPlc"></canvas></div></div>')
            o.append(f'''<script>
new Chart(document.getElementById('mlPlc'),{{type:'bar',
  data:{{labels:{json.dumps(plc_labels)},
    datasets:[
      {{label:'Blocked',data:{json.dumps(plc_blocked)},backgroundColor:'#16a34a'}},
      {{label:'Bypassed',data:{json.dumps(plc_bypassed)},backgroundColor:'#dc2626'}}
    ]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{title:{{display:true,text:'Block / Bypass by Request Placement',color:'#000000',font:TITLE_FONT}},
      legend:{{position:'top',labels:{{color:'#000000',font:LEGEND_FONT,padding:14,boxWidth:18}}}}}},
    scales:{{y:{{beginAtZero:true,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,precision:0}},title:{{display:true,text:'Number of payloads',color:'#000000',font:AXIS_TITLE_FONT}}}},
      x:{{grid:{{display:false}},ticks:{{color:'#000000'}}}}}}}}}});
</script>''')

            # ── Encoder × Placement bypass heatmap (top-15 combos) ──
            if pair_labels:
                o.append('<h3>Encoder &times; Placement Bypass Heatmap</h3>')
                o.append('<p style="color:#374151;font-size:12px">'
                         'Bypass rate (%) for the top combinations of encoding + request placement. '
                         'Tall bars indicate WAF rule gaps when payloads are encoded that way and placed there.</p>')
                o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlPair\',\'waf-ml-encoder-placement-heatmap.png\')">Download PNG</button>'
                         '<div class="ch"><canvas id="mlPair"></canvas></div></div>')
                pair_colors_js = json.dumps([
                    '#dc2626' if p > 75 else '#ea580c' if p > 50 else '#ca8a04' if p > 25 else '#16a34a'
                    for p in pair_pct
                ])
                o.append(f'''<script>
new Chart(document.getElementById('mlPair'),{{type:'bar',
  data:{{labels:{json.dumps(pair_labels)},
    datasets:[{{label:'Bypass %',data:{json.dumps(pair_pct)},
      backgroundColor:{pair_colors_js},borderRadius:3}}]}},
  options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,
    plugins:{{title:{{display:true,text:'Encoder × Placement Bypass Rate (top {len(pair_labels)})',color:'#000000',font:TITLE_FONT}},
      legend:{{display:false}}}},
    scales:{{x:{{beginAtZero:true,max:100,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',callback:function(v){{return v+'%'}}}}}},
      y:{{grid:{{display:false}},ticks:{{color:'#000000',font:{{family:'Consolas,Monaco,monospace',size:12,weight:'500'}}}}}}}}}}}});
</script>''')

            # ── Response Status Code Distribution ──
            if status_labels_sorted:
                status_colors = ['#16a34a','#dc2626','#ea580c','#ca8a04','#1d4ed8','#475569','#86198f','#0f766e','#7c2d12','#1e40af']
                o.append('<h3>Response Status Code Distribution</h3>')
                o.append('<p style="color:#374151;font-size:12px">'
                         'Distribution of HTTP status codes returned during the scan. 200 = WAF allowed; 403/406 = WAF blocked; '
                         '404/500 = origin error (not a WAF event).</p>')
                o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlStatus\',\'waf-ml-status-distribution.png\')">Download PNG</button>'
                         '<div class="ch chs"><canvas id="mlStatus"></canvas></div></div>')
                o.append(f'''<script>
new Chart(document.getElementById('mlStatus'),{{type:'doughnut',
  data:{{labels:{json.dumps(["HTTP " + s for s in status_labels_sorted])},
    datasets:[{{data:{json.dumps(status_counts_sorted)},
      backgroundColor:{json.dumps(status_colors[:len(status_labels_sorted)])},
      borderColor:'#ffffff',borderWidth:3,hoverOffset:10}}]}},
  options:{{responsive:true,maintainAspectRatio:false,cutout:'55%',
    plugins:{{title:{{display:true,text:'HTTP Status Code Distribution',color:'#000000',font:TITLE_FONT}},
      legend:{{position:'bottom',labels:{{color:'#000000',padding:10,font:{{size:12,weight:'600'}},boxWidth:14}}}}}}}}}});
</script>''')

            # ── Attack-type concentration of bypasses ──
            if attack_type_bypassed:
                top_attack_types = attack_type_bypassed.most_common(15)
                at_labels = [k[:35] for k, _ in top_attack_types]
                at_counts = [v for _, v in top_attack_types]
                o.append('<h3>Bypass Concentration by Attack Type</h3>')
                o.append('<p style="color:#374151;font-size:12px">'
                         'Top 15 attack categories by number of WAF bypasses. Categories at the top represent the largest WAF-rule blind spots.</p>')
                o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlAttackBypass\',\'waf-ml-bypass-by-attack-type.png\')">Download PNG</button>'
                         '<div class="ch"><canvas id="mlAttackBypass"></canvas></div></div>')
                o.append(f'''<script>
new Chart(document.getElementById('mlAttackBypass'),{{type:'bar',
  data:{{labels:{json.dumps(at_labels)},
    datasets:[{{label:'Bypassed payloads',data:{json.dumps(at_counts)},
      backgroundColor:'#dc2626',borderRadius:3}}]}},
  options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,
    plugins:{{title:{{display:true,text:'Bypass Concentration — Top 15 Attack Categories',color:'#000000',font:TITLE_FONT}},
      legend:{{display:false}}}},
    scales:{{x:{{beginAtZero:true,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,precision:0}},title:{{display:true,text:'Bypassed payload count',color:'#000000',font:AXIS_TITLE_FONT}}}},
      y:{{grid:{{display:false}},ticks:{{color:'#000000',font:TICK_FONT}}}}}}}}}});
</script>''')

            o.append('<div style="background:#fef2f2;border-left:4px solid #dc2626;padding:8px 14px;margin:24px 0 6px;border-radius:0 6px 6px 0"><strong style="color:#7f1d1d">GROUP 3 — ML PREDICTIONS</strong> &nbsp;<span style="color:#374151;font-size:11px">Bypass probability distribution, probability×confidence scatter, mutation coverage</span></div>')

            # ── ML candidate scatter: Bypass Probability × Confidence ──
            if bc_scatter:
                o.append('<h3>ML Bypass Predictions — Probability vs Confidence</h3>')
                o.append('<p style="color:#374151;font-size:12px">'
                         'Each point is one ML-flagged bypass candidate. Top-right quadrant '
                         '(high probability + high confidence) = highest priority security gaps.</p>')
                o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlScatter\',\'waf-ml-bypass-scatter.png\')">Download PNG</button>'
                         '<div class="ch"><canvas id="mlScatter"></canvas></div></div>')
                o.append(f'''<script>
new Chart(document.getElementById('mlScatter'),{{type:'scatter',
  data:{{datasets:[{{label:'Bypass candidates',data:{json.dumps(bc_scatter)},
    backgroundColor:'rgba(220,38,38,0.55)',borderColor:'#7f1d1d',pointRadius:5,pointHoverRadius:7}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{title:{{display:true,text:'ML Bypass Probability × Confidence',color:'#000000',font:TITLE_FONT}},
      legend:{{display:false}}}},
    scales:{{x:{{min:0,max:1,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',callback:function(v){{return (v*100).toFixed(0)+'%'}}}},title:{{display:true,text:'Bypass probability',color:'#000000',font:AXIS_TITLE_FONT}}}},
      y:{{min:0,max:1,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',callback:function(v){{return (v*100).toFixed(0)+'%'}}}},title:{{display:true,text:'Model confidence',color:'#000000',font:AXIS_TITLE_FONT}}}}}}}}}});
</script>''')

            # ── Mutation suggestions count by attack type ──
            mutation_suggestions = (ml_analysis or {}).get("mutation_suggestions") or []
            if mutation_suggestions:
                from collections import Counter as _C2
                mut_by_case = _C2()
                for ms in mutation_suggestions:
                    case = str(ms.get("test_case") or "unknown")
                    mut_by_case[case] += len(ms.get("mutations", []) or [])
                top_mut = mut_by_case.most_common(12)
                mut_labels = [k[:35] for k, _ in top_mut]
                mut_counts = [v for _, v in top_mut]
                o.append('<h3>ML Mutation Suggestions — Coverage by Attack Type</h3>')
                o.append('<p style="color:#374151;font-size:12px">'
                         'Number of ML-generated bypass mutations the engine suggested per attack type. '
                         'Use these payloads to test whether WAF rules are robust against the suggested transformations.</p>')
                o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlMutation\',\'waf-ml-mutation-coverage.png\')">Download PNG</button>'
                         '<div class="ch"><canvas id="mlMutation"></canvas></div></div>')
                o.append(f'''<script>
new Chart(document.getElementById('mlMutation'),{{type:'bar',
  data:{{labels:{json.dumps(mut_labels)},
    datasets:[{{label:'Mutations suggested',data:{json.dumps(mut_counts)},
      backgroundColor:'#1d4ed8',borderRadius:3}}]}},
  options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,
    plugins:{{title:{{display:true,text:'ML Mutation Suggestion Coverage',color:'#000000',font:TITLE_FONT}},
      legend:{{display:false}}}},
    scales:{{x:{{beginAtZero:true,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,precision:0}},title:{{display:true,text:'Mutation count',color:'#000000',font:AXIS_TITLE_FONT}}}},
      y:{{grid:{{display:false}},ticks:{{color:'#000000',font:TICK_FONT}}}}}}}}}});
</script>''')

            # Bypass candidates — histogram + table
            if bypass_candidates:
                # Bin probabilities into 5 buckets
                buckets = [0]*5  # [0-20, 20-40, 40-60, 60-80, 80-100]
                for bc in bypass_candidates:
                    p = bc.get("bypass_probability", 0)
                    idx = min(4, int(p * 5))
                    buckets[idx] += 1
                bucket_labels = ['0-20%', '20-40%', '40-60%', '60-80%', '80-100%']
                bucket_colors = ['#16a34a', '#ca8a04', '#ea580c', '#dc2626', '#7f1d1d']

                o.append('<h3>ML Bypass Probability Distribution</h3>')
                o.append('<p style="color:#374151;font-size:12px">Distribution of predicted bypass probability across all candidate payloads. Higher buckets = greater risk.</p>')
                o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlBypassC\',\'waf-ml-bypass-distribution.png\')">Download PNG</button>'
                         '<div class="ch chs"><canvas id="mlBypassC"></canvas></div></div>')
                o.append(f'''<script>
new Chart(document.getElementById('mlBypassC'),{{type:'bar',
  data:{{labels:{json.dumps(bucket_labels)},
    datasets:[{{label:'Payload count',data:{json.dumps(buckets)},
      backgroundColor:{json.dumps(bucket_colors)},borderRadius:4}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{title:{{display:true,text:'Bypass-Probability Histogram (Hybrid ML predictions)',color:'#000000',font:TITLE_FONT}},
      legend:{{display:false}}}},
    scales:{{y:{{beginAtZero:true,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,precision:0}},title:{{display:true,text:'Number of payloads',color:'#000000',font:AXIS_TITLE_FONT}}}},
      x:{{grid:{{display:false}},ticks:{{color:'#000000'}},title:{{display:true,text:'Predicted bypass probability',color:'#000000',font:AXIS_TITLE_FONT}}}}}}}}}});
</script>''')

                # ── Confidence Score Histogram (10-bucket) ──
                conf_buckets = [0]*10
                for bc_ in bypass_candidates:
                    c = float(bc_.get("confidence", 0) or 0)
                    idx = min(9, max(0, int(c * 10)))
                    conf_buckets[idx] += 1
                conf_labels = [f"{i*10}-{(i+1)*10}%" for i in range(10)]
                o.append('<h3>ML Confidence Score Distribution</h3>')
                o.append('<p style="color:#374151;font-size:12px">'
                         'Distribution of model confidence across all bypass candidates. '
                         'A right-skewed distribution means the ensemble is decisive about its predictions.</p>')
                o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlConfidence\',\'waf-ml-confidence-distribution.png\')">Download PNG</button>'
                         '<div class="ch chs"><canvas id="mlConfidence"></canvas></div></div>')
                o.append(f'''<script>
new Chart(document.getElementById('mlConfidence'),{{type:'bar',
  data:{{labels:{json.dumps(conf_labels)},
    datasets:[{{label:'Candidate count',data:{json.dumps(conf_buckets)},
      backgroundColor:'#1d4ed8',borderColor:'#000000',borderWidth:0.5,borderRadius:3}}]}},
  options:{{responsive:true,maintainAspectRatio:false,layout:{{padding:14}},
    plugins:{{title:{{display:true,text:'Model Confidence Score Distribution',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{display:false}}}},
    scales:{{y:{{beginAtZero:true,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,precision:0}},title:{{display:true,text:'Number of candidates',color:'#000000',font:AXIS_TITLE_FONT}}}},
      x:{{grid:{{display:false}},ticks:{{color:'#000000',font:TICK_FONT}},title:{{display:true,text:'Confidence score',color:'#000000',font:AXIS_TITLE_FONT}}}}}}}}}});
</script>''')

                # ── Bypass Probability CDF (cumulative density) ──
                probs_sorted = sorted([float(bc_.get("bypass_probability", 0) or 0) for bc_ in bypass_candidates])
                if probs_sorted:
                    n_cdf = len(probs_sorted)
                    cdf_x = [round(p, 4) for p in probs_sorted]
                    cdf_y = [round(100 * (i + 1) / n_cdf, 2) for i in range(n_cdf)]
                    cdf_data = [{"x": x, "y": y} for x, y in zip(cdf_x, cdf_y)]
                    o.append('<h3>Bypass-Probability Cumulative Distribution (CDF)</h3>')
                    o.append('<p style="color:#374151;font-size:12px">'
                         'Empirical CDF of predicted bypass probabilities across all candidates. '
                         'A steep right-side curve means most predictions are clustered at high probability — many likely-bypassing payloads.</p>')
                    o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlCDF\',\'waf-ml-bypass-cdf.png\')">Download PNG</button>'
                         '<div class="ch chs"><canvas id="mlCDF"></canvas></div></div>')
                    o.append(f'''<script>
new Chart(document.getElementById('mlCDF'),{{type:'line',
  data:{{datasets:[{{label:'Empirical CDF',data:{json.dumps(cdf_data)},
    backgroundColor:'rgba(29,78,216,0.18)',borderColor:'#1d4ed8',borderWidth:2.5,
    pointRadius:0,fill:true,tension:0.1}}]}},
  options:{{responsive:true,maintainAspectRatio:false,layout:{{padding:14}},
    plugins:{{title:{{display:true,text:'Empirical CDF of Bypass Probability ({n_cdf} candidates)',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{position:'top',labels:{{color:'#000000',font:LEGEND_FONT,padding:14,boxWidth:18}}}}}},
    scales:{{x:{{type:'linear',min:0,max:1,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,callback:function(v){{return (v*100).toFixed(0)+'%'}}}},title:{{display:true,text:'Bypass probability',color:'#000000',font:AXIS_TITLE_FONT}}}},
      y:{{beginAtZero:true,max:100,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,callback:function(v){{return v+'%'}}}},title:{{display:true,text:'Cumulative % of candidates',color:'#000000',font:AXIS_TITLE_FONT}}}}}}}}}});
</script>''')

                # ── Attack Type Composition (of bypass candidates) ──
                from collections import Counter as _C3
                at_comp = _C3()
                for bc_ in bypass_candidates:
                    at_comp[str(bc_.get("attack_type") or "unknown")] += 1
                if at_comp:
                    at_comp_items = at_comp.most_common(8)
                    at_comp_labels = [k for k, _ in at_comp_items]
                    at_comp_counts = [v for _, v in at_comp_items]
                    at_comp_colors = ['#dc2626','#ea580c','#ca8a04','#16a34a','#1d4ed8','#7c3aed','#86198f','#475569']
                    o.append('<h3>ML Bypass Candidates — Attack Type Composition</h3>')
                    o.append('<p style="color:#374151;font-size:12px">'
                         'Share of ML-flagged bypass candidates by attack type. '
                         'A skewed pie shows which class of attacks the WAF is most vulnerable to (per the ML model).</p>')
                    o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlAttackComp\',\'waf-ml-attack-type-composition.png\')">Download PNG</button>'
                         '<div class="ch chs"><canvas id="mlAttackComp"></canvas></div></div>')
                    o.append(f'''<script>
new Chart(document.getElementById('mlAttackComp'),{{type:'doughnut',
  data:{{labels:{json.dumps(at_comp_labels)},
    datasets:[{{data:{json.dumps(at_comp_counts)},
      backgroundColor:{json.dumps(at_comp_colors[:len(at_comp_labels)])},
      borderColor:'#ffffff',borderWidth:3,hoverOffset:12}}]}},
  options:{{responsive:true,maintainAspectRatio:false,cutout:'55%',layout:{{padding:14}},
    plugins:{{title:{{display:true,text:'Bypass Candidates — Attack Type Composition',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{position:'bottom',labels:{{color:'#000000',padding:14,font:LEGEND_FONT,boxWidth:18}}}}}}}}}});
</script>''')

                # ── Top-N Risk Score (probability × confidence) ──
                risk_ranked = sorted(
                    bypass_candidates,
                    key=lambda b: -(float(b.get("bypass_probability", 0) or 0) * float(b.get("confidence", 0) or 0)),
                )[:12]
                if risk_ranked:
                    risk_labels = []
                    risk_scores = []
                    for bc_ in risk_ranked:
                        case = str(bc_.get("test_case") or "?")
                        atype = str(bc_.get("attack_type") or "?")
                        risk_labels.append(f"{atype}/{case}"[:40])
                        p = float(bc_.get("bypass_probability", 0) or 0)
                        c = float(bc_.get("confidence", 0) or 0)
                        risk_scores.append(round(p * c * 100, 1))
                    o.append('<h3>Top-12 Risk-Ranked Bypass Candidates (Probability × Confidence)</h3>')
                    o.append('<p style="color:#374151;font-size:12px">'
                         'Composite risk score = bypass probability × model confidence (higher = more credible bypass). '
                         'Use this ranking to triage which payload classes to fix first.</p>')
                    o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlTopRisk\',\'waf-ml-top-risk-ranked.png\')">Download PNG</button>'
                         '<div class="ch"><canvas id="mlTopRisk"></canvas></div></div>')
                    risk_colors = json.dumps([
                        '#dc2626' if s > 70 else '#ea580c' if s > 50 else '#ca8a04' if s > 30 else '#16a34a'
                        for s in risk_scores
                    ])
                    o.append(f'''<script>
new Chart(document.getElementById('mlTopRisk'),{{type:'bar',
  data:{{labels:{json.dumps(risk_labels)},
    datasets:[{{label:'Risk score (P × C)',data:{json.dumps(risk_scores)},
      backgroundColor:{risk_colors},borderColor:'#000000',borderWidth:0.5,borderRadius:3}}]}},
  options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,layout:{{padding:14}},
    plugins:{{title:{{display:true,text:'Top-12 Risk-Ranked Bypass Candidates',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{display:false}}}},
    scales:{{x:{{beginAtZero:true,max:100,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,callback:function(v){{return v+'%'}}}},title:{{display:true,text:'Composite risk score',color:'#000000',font:AXIS_TITLE_FONT}}}},
      y:{{grid:{{display:false}},ticks:{{color:'#000000',font:{{family:'Consolas,Monaco,monospace',size:11,weight:'500'}}}}}}}}}}}});
</script>''')

                # ── Mutation-Type Effectiveness (avg bypass probability per mutation type) ──
                if mutation_suggestions:
                    from collections import defaultdict as _DD
                    mut_type_probs = _DD(list)
                    for ms in mutation_suggestions:
                        for mut in (ms.get("mutations") or []):
                            mtype = str(mut.get("mutation") or "unknown")[:50]
                            mt_p = float(mut.get("bypass_probability", 0) or 0)
                            mut_type_probs[mtype].append(mt_p)
                    if mut_type_probs:
                        mt_avg = sorted(
                            [(t, round(100 * sum(ps) / len(ps), 1), len(ps)) for t, ps in mut_type_probs.items()],
                            key=lambda r: -r[1],
                        )[:12]
                        mt_labels = [r[0] for r in mt_avg]
                        mt_scores = [r[1] for r in mt_avg]
                        mt_counts = [r[2] for r in mt_avg]
                        o.append('<h3>Mutation Type Effectiveness — Avg Bypass Probability</h3>')
                        o.append('<p style="color:#374151;font-size:12px">'
                         'Average bypass probability for each ML-suggested mutation type, ranked. '
                         'Higher = mutation type that more reliably evades the WAF.</p>')
                        o.append('<div class="chart-wrap">'
                         '<button class="dl-btn" onclick="downloadChartPNG(\'mlMutEff\',\'waf-ml-mutation-effectiveness.png\')">Download PNG</button>'
                         '<div class="ch"><canvas id="mlMutEff"></canvas></div></div>')
                        o.append(f'''<script>
new Chart(document.getElementById('mlMutEff'),{{type:'bar',
  data:{{labels:{json.dumps(mt_labels)},
    datasets:[{{label:'Avg bypass probability',data:{json.dumps(mt_scores)},
      backgroundColor:'#7c3aed',borderColor:'#000000',borderWidth:0.5,borderRadius:3}}]}},
  options:{{indexAxis:'y',responsive:true,maintainAspectRatio:false,layout:{{padding:14}},
    plugins:{{title:{{display:true,text:'Mutation Type Effectiveness (avg bypass %)',color:'#000000',font:TITLE_FONT,padding:{{bottom:14}}}},
      legend:{{display:false}},
      tooltip:{{callbacks:{{label:function(ctx){{
        var counts={json.dumps(mt_counts)};
        return ctx.parsed.x.toFixed(1)+'% (n='+counts[ctx.dataIndex]+')';
      }}}}}}}}}},
    scales:{{x:{{beginAtZero:true,max:100,grid:{{color:GRID_COLOR}},ticks:{{color:'#000000',font:TICK_FONT,callback:function(v){{return v+'%'}}}},title:{{display:true,text:'Avg bypass probability',color:'#000000',font:AXIS_TITLE_FONT}}}},
      y:{{grid:{{display:false}},ticks:{{color:'#000000',font:TICK_FONT}}}}}}}}}});
</script>''')

                o.append('<div style="background:#f3f4f6;border-left:4px solid #475569;padding:8px 14px;margin:24px 0 6px;border-radius:0 6px 6px 0"><strong style="color:#1f2937">GROUP 4 — DETAIL TABLES</strong> &nbsp;<span style="color:#374151;font-size:11px">Top-risk candidates and per-payload mutation recommendations</span></div>')
                o.append('<h3>Top-Risk Bypass Candidates (Detail)</h3>')
                o.append('<table><tr><th>Payload</th><th>Test Case</th><th>Bypass Prob.</th><th>Confidence</th><th>Attack Type</th></tr>')
                for bc in bypass_candidates[:15]:
                    prob = bc.get("bypass_probability", 0)
                    prob_color = "#dc2626" if prob > 0.7 else "#ea580c" if prob > 0.4 else "#ca8a04"
                    payload_esc = h.escape(str(bc.get("payload", ""))[:80])
                    o.append(f'<tr><td><code style="font-size:10px">{payload_esc}</code></td>'
                             f'<td>{h.escape(str(bc.get("test_case", "")))}</td>'
                             f'<td style="color:{prob_color};font-weight:700">{prob:.1%}</td>'
                             f'<td>{bc.get("confidence", 0):.1%}</td>'
                             f'<td><span class="tag ti">{h.escape(str(bc.get("attack_type", "unknown")))}</span></td></tr>')
                o.append('</table>')

            # Mutation suggestions
            if mutation_suggestions:
                o.append('<h3>Suggested Bypass Mutations</h3>')
                o.append('<p style="color:#374151;font-size:12px">ML-predicted payload mutations most likely to evade the WAF:</p>')
                for ms in mutation_suggestions[:5]:
                    payload_esc = h.escape(str(ms.get("payload", ""))[:60])
                    o.append(f'<div class="vuln">')
                    o.append(f'<strong>Target: </strong><code>{payload_esc}</code> '
                             f'<span style="color:#374151">({h.escape(str(ms.get("test_case", "")))})</span>')
                    mutations = ms.get("mutations", [])
                    if mutations:
                        o.append('<table style="margin-top:8px"><tr><th>Mutation</th><th>Encoder</th><th>Placement</th><th>Bypass Prob.</th></tr>')
                        for mut in mutations[:3]:
                            mprob = mut.get("bypass_probability", 0)
                            mcolor = "#dc2626" if mprob > 0.5 else "#ea580c" if mprob > 0.3 else "#374151"
                            o.append(f'<tr><td>{h.escape(str(mut.get("mutation", "")))}</td>'
                                     f'<td><code>{h.escape(str(mut.get("encoder", "")))}</code></td>'
                                     f'<td><code>{h.escape(str(mut.get("placeholder", "")))}</code></td>'
                                     f'<td style="color:{mcolor};font-weight:700">{mprob:.1%}</td></tr>')
                        o.append('</table>')
                    o.append('</div>')

        else:
            o.append('<p style="color:#374151">ML models were not trained (insufficient data — need 30+ samples with both blocked and bypassed results).</p>')

        o.append('</div>')

    # ── WAF Ruleset Inference Section ──
    if ruleset_inference is not None:
        from gotestwaf.scanner.ruleset_inference import InferenceResult
        if isinstance(ruleset_inference, InferenceResult):
            ri = ruleset_inference
            o.append('<h2>WAF Ruleset Detection (Auto-Inferred)</h2>')
            o.append('<div class="card glow">')
            o.append('<p style="color:#374151;font-size:12px;margin-bottom:12px">Automatically detected active and missing WAF rulesets based on scan block/bypass patterns.</p>')

            # Detected
            if ri.detected:
                o.append('<h3 style="color:#16a34a;margin:14px 0 8px">\u2705 Detected (Active Rulesets)</h3>')
                o.append('<table><tr><th>Ruleset / Configuration</th><th>Vendor</th><th>Confidence</th><th>Evidence</th></tr>')
                for rs in ri.detected:
                    status_icon = "\u2705" if rs.status == "detected" else "\u2753"
                    conf = f"{rs.confidence:.0%}" if rs.confidence > 0 else "N/A"
                    o.append(f'<tr><td><b>{status_icon} {h.escape(rs.name)}</b></td>'
                             f'<td>{h.escape(rs.vendor)}</td>'
                             f'<td style="text-align:center">{conf}</td>'
                             f'<td style="color:#374151;font-size:11px">{h.escape(rs.evidence)}</td></tr>')
                o.append('</table>')

            # Partial
            if ri.partial:
                o.append('<h3 style="color:#ca8a04;margin:14px 0 8px">\u26a0\ufe0f Partial Coverage</h3>')
                o.append('<table><tr><th>Ruleset</th><th>Vendor</th><th>Confidence</th><th>Evidence</th><th>Recommendation</th></tr>')
                for rs in ri.partial:
                    o.append(f'<tr><td><b>\u26a0\ufe0f {h.escape(rs.name)}</b></td>'
                             f'<td>{h.escape(rs.vendor)}</td>'
                             f'<td style="text-align:center">{rs.confidence:.0%}</td>'
                             f'<td style="color:#ca8a04;font-size:11px">{h.escape(rs.evidence)}</td>'
                             f'<td style="color:#16a34a;font-size:11px">{h.escape(rs.recommendation)}</td></tr>')
                o.append('</table>')

            # Missing
            if ri.missing:
                o.append('<h3 style="color:#ef4444;margin:14px 0 8px">\u274c Missing (Not Detected)</h3>')
                o.append('<table><tr><th>Ruleset / Configuration</th><th>Vendor</th><th>Confidence</th><th>Evidence</th><th>Recommendation</th></tr>')
                for rs in ri.missing:
                    o.append(f'<tr><td><b>\u274c {h.escape(rs.name)}</b></td>'
                             f'<td>{h.escape(rs.vendor)}</td>'
                             f'<td style="text-align:center;color:#ef4444;font-weight:700">{rs.confidence:.0%}</td>'
                             f'<td style="color:#ef4444;font-size:11px">{h.escape(rs.evidence)}</td>'
                             f'<td style="color:#16a34a;font-size:11px">{h.escape(rs.recommendation)}</td></tr>')
                o.append('</table>')

            o.append('</div>')

    # ── Compliance Section ──
    if compliance_results:
        from gotestwaf.report.compliance import ComplianceSummary
        o.append('<h2>Compliance Assessment</h2>')
        o.append('<div class="card glow">')
        o.append('<p style="color:#374151;font-size:12px;margin-bottom:12px">Automated mapping of scan findings to regulatory compliance frameworks.</p>')

        # Summary metrics. compliance_pct == -1.0 is a sentinel meaning
        # "no controls assessed" — display "n/a" instead of an unsightly
        # "-1%" tile.
        o.append('<div class="ms">')
        for fw_key, summary in compliance_results.items():
            if isinstance(summary, ComplianceSummary):
                if summary.compliance_pct < 0:
                    color = "#475569"
                    score_str = "n/a"
                else:
                    color = "#22c55e" if summary.compliance_pct >= 80 else "#eab308" if summary.compliance_pct >= 50 else "#ef4444"
                    score_str = f"{summary.compliance_pct:.0f}%"
                o.append(f'<div class="m"><div class="mv" style="color:{color}">{score_str}</div><div class="ml">{h.escape(summary.framework)}</div></div>')
        o.append('</div>')

        # Per-framework detail tables
        for fw_key, summary in compliance_results.items():
            if not isinstance(summary, ComplianceSummary):
                continue
            # Distinguish full pass vs partial in the heading so reviewers see
            # WAFs that block 30-79% of relevant attacks aren't reported as
            # "0 passed" — they pass partially.
            na_count = summary.total_controls - summary.passed - summary.failed - summary.partial
            score_h = "n/a" if summary.compliance_pct < 0 else f"{summary.compliance_pct:.0f}%"
            o.append(
                f'<h3 style="margin:14px 0 8px">{h.escape(summary.framework)} '
                f'({summary.passed} pass / {summary.partial} partial / {summary.failed} fail / {na_count} n/a, '
                f'score {score_h})</h3>'
            )
            o.append('<table><tr><th>Control</th><th>Name</th><th>Status</th><th>Block Rate</th><th>Evidence</th></tr>')
            for ctrl in summary.controls:
                if ctrl.status == "pass":
                    status_html = '<span style="color:#16a34a;font-weight:700">PASS</span>'
                elif ctrl.status == "fail":
                    status_html = '<span style="color:#ef4444;font-weight:700">FAIL</span>'
                elif ctrl.status == "partial":
                    status_html = '<span style="color:#ca8a04;font-weight:700">PARTIAL</span>'
                else:
                    status_html = '<span style="color:#374151">N/A</span>'
                o.append(f'<tr><td><b>{h.escape(ctrl.control_id)}</b></td>'
                         f'<td>{h.escape(ctrl.name)}</td>'
                         f'<td>{status_html}</td>'
                         f'<td>{ctrl.block_rate:.0%}</td>'
                         f'<td style="color:#374151;font-size:11px">{h.escape(ctrl.evidence)}</td></tr>')
            o.append('</table>')

        o.append('</div>')

    o.append('</body></html>')
    return "\n".join(o)
