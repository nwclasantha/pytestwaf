"""Generate comprehensive WAF assessment with Cyber Kill Chain + MITRE ATT&CK mapping."""
import html as h
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Load MITRE data
try:
    with open("mitre_cache.json", encoding="utf-8") as f:
        mitre = json.load(f)
except FileNotFoundError:
    print("ERROR: mitre_cache.json not found. Place it in the project root directory.")
    sys.exit(1)
except json.JSONDecodeError as e:
    print(f"ERROR: mitre_cache.json is malformed: {e}")
    sys.exit(1)

objects = mitre["objects"]
techniques = {
    obj["external_references"][0]["external_id"]: obj
    for obj in objects
    if obj.get("type") == "attack-pattern"
    and not obj.get("revoked")
    and not obj.get("x_mitre_deprecated")
    and obj.get("external_references")
}
tactics = {
    obj["external_references"][0]["external_id"]: obj["name"]
    for obj in objects
    if obj.get("type") == "x-mitre-tactic" and obj.get("external_references")
}

# WAF test results mapped to MITRE techniques
attack_mitre_map = [
    {"attack": "XSS (Cross-Site Scripting)", "mitre_id": "T1059.007", "tactic": "Execution",
     "kill_chain": "Weaponization", "tested": 328, "blocked": 327, "rate": 99.7,
     "desc": "JavaScript execution via injected script tags, event handlers, DOM manipulation"},
    {"attack": "SQL Injection", "mitre_id": "T1190", "tactic": "Initial Access",
     "kill_chain": "Exploitation", "tested": 60, "blocked": 60, "rate": 100.0,
     "desc": "Database query manipulation via UNION SELECT, OR 1=1, SLEEP(), information_schema"},
    {"attack": "Remote Code Execution", "mitre_id": "T1059", "tactic": "Execution",
     "kill_chain": "Exploitation", "tested": 18, "blocked": 15, "rate": 83.3,
     "desc": "OS command injection via /etc/passwd, shell commands, curl/wget"},
    {"attack": "Path Traversal / LFI", "mitre_id": "T1083", "tactic": "Discovery",
     "kill_chain": "Exploitation", "tested": 28, "blocked": 28, "rate": 100.0,
     "desc": "File system access via ../ sequences, /etc/passwd, php://filter"},
    {"attack": "NoSQL Injection", "mitre_id": "T1190", "tactic": "Initial Access",
     "kill_chain": "Exploitation", "tested": 50, "blocked": 50, "rate": 100.0,
     "desc": "MongoDB/NoSQL query manipulation via $gt, $ne operators"},
    {"attack": "CRLF Injection", "mitre_id": "T1557", "tactic": "Collection",
     "kill_chain": "Exploitation", "tested": 7, "blocked": 7, "rate": 100.0,
     "desc": "HTTP header injection via carriage return/line feed characters"},
    {"attack": "LDAP Injection", "mitre_id": "T1071.001", "tactic": "Command and Control",
     "kill_chain": "Exploitation", "tested": 24, "blocked": 24, "rate": 100.0,
     "desc": "Directory service query manipulation"},
    {"attack": "Shell Injection", "mitre_id": "T1059.004", "tactic": "Execution",
     "kill_chain": "Exploitation", "tested": 32, "blocked": 32, "rate": 100.0,
     "desc": "OS command injection via pipes, semicolons, backticks"},
    {"attack": "XXE (XML External Entity)", "mitre_id": "T1221", "tactic": "Defense Evasion",
     "kill_chain": "Weaponization", "tested": 2, "blocked": 2, "rate": 100.0,
     "desc": "XML parser exploitation via ENTITY declarations"},
    {"attack": "SSTI (Server-Side Template)", "mitre_id": "T1059", "tactic": "Execution",
     "kill_chain": "Exploitation", "tested": 24, "blocked": 24, "rate": 100.0,
     "desc": "Template engine exploitation via {{}} and {%%} expressions"},
    {"attack": "SSI (Server-Side Include)", "mitre_id": "T1505.003", "tactic": "Persistence",
     "kill_chain": "Installation", "tested": 24, "blocked": 24, "rate": 100.0,
     "desc": "Web server directive injection via <!--# tags"},
    {"attack": "Mail Injection", "mitre_id": "T1566.001", "tactic": "Initial Access",
     "kill_chain": "Delivery", "tested": 24, "blocked": 24, "rate": 100.0,
     "desc": "Email header injection for spam relay"},
    {"attack": "XML Injection", "mitre_id": "T1221", "tactic": "Defense Evasion",
     "kill_chain": "Weaponization", "tested": 7, "blocked": 7, "rate": 100.0,
     "desc": "XML structure manipulation"},
    {"attack": "REST API Attacks", "mitre_id": "T1106", "tactic": "Execution",
     "kill_chain": "Exploitation", "tested": 7, "blocked": 7, "rate": 100.0,
     "desc": "API endpoint exploitation via malicious JSON payloads"},
    {"attack": "SOAP Attacks", "mitre_id": "T1106", "tactic": "Execution",
     "kill_chain": "Exploitation", "tested": 5, "blocked": 5, "rate": 100.0,
     "desc": "SOAP envelope injection"},
]

# Kill chain phases
kill_chain_phases = [
    ("Reconnaissance", "#6366f1", "TA0043", "Scanning, enumeration"),
    ("Weaponization", "#8b5cf6", "N/A", "Payload crafting, encoding"),
    ("Delivery", "#a855f7", "TA0001", "Sending malicious requests"),
    ("Exploitation", "#d946ef", "TA0002", "Executing attack payloads"),
    ("Installation", "#ec4899", "TA0003", "Persistence mechanisms"),
    ("Command & Control", "#f43f5e", "TA0011", "C2 communication"),
    ("Actions on Objectives", "#ef4444", "TA0040", "Data exfil, impact"),
]

now = datetime.now().strftime("%Y-%m-%d %H:%M")
o = []

# Header
o.append("""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Advanced WAF Security Assessment - kernernorland.com</title>
<style>
body{font-family:Inter,-apple-system,sans-serif;margin:0;padding:0;color:#1a1a2e;font-size:13px;line-height:1.6;background:#f8fafc}
.container{max-width:1100px;margin:0 auto;padding:40px}
h1{font-size:28px;font-weight:900;margin:0 0 4px}
h2{font-size:20px;font-weight:700;margin:35px 0 14px;padding-bottom:8px;border-bottom:3px solid #3942EA}
h3{font-size:15px;font-weight:700;margin:22px 0 10px}
.card{background:#fff;border-radius:10px;padding:20px;margin:14px 0;box-shadow:0 1px 3px rgba(0,0,0,0.08)}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:12px}
th{background:#f0f2f5;font-weight:700;padding:8px 10px;text-align:left;border:1px solid #e0e3e8}
td{padding:6px 10px;border:1px solid #e0e3e8}
tr:nth-child(even){background:#fafbfc}
.tag{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700;color:#fff}
.crit{background:#F24444}.high{background:#FC7303}.med{background:#FDBE10;color:#000}.low{background:#56CC54}.info{background:#999}
.gauges{display:flex;gap:20px;justify-content:center;flex-wrap:wrap;margin:20px 0}
.bar{height:20px;border-radius:3px;display:inline-block}
.mono{font-family:Consolas,Monaco,monospace;font-size:11px;word-break:break-all}
.vuln{border-left:4px solid;padding:14px;margin:10px 0;border-radius:0 8px 8px 0;background:#fff}
.vuln-c{border-color:#F24444}.vuln-h{border-color:#FC7303}.vuln-m{border-color:#FDBE10}.vuln-i{border-color:#999}
.kc-phase{display:inline-flex;align-items:center;justify-content:center;padding:8px 14px;border-radius:6px;color:#fff;font-weight:700;font-size:11px;margin:3px;min-width:120px;text-align:center}
.kc-arrow{font-size:18px;color:#ccc;margin:0 2px}
.mitre-cell{padding:6px;border-radius:4px;font-size:10px;margin:2px;text-align:center;min-height:40px;display:flex;align-items:center;justify-content:center}
.metric{text-align:center;padding:14px}.metric-val{font-size:30px;font-weight:900}.metric-lbl{font-size:11px;color:#666;margin-top:4px}
</style></head><body><div class="container">""")

o.append(f'<h1>Advanced WAF &amp; Firewall Security Assessment</h1>')
o.append(f'<p style="color:#666">Target: <b>kernernorland.com</b> | {now} | GoTestWAF ML Engine (F1: 0.9333) | MITRE ATT&CK v15</p>')

# Score gauges
def gauge(pct, label, size=130):
    r = size//2 - 12; cx = cy = size//2; circ = 2*3.14159*r
    off = circ*(1-pct/100)
    c = "#56CC54" if pct>=80 else "#FDBE10" if pct>=50 else "#F24444"
    return f'<svg width="{size}" height="{size+30}" viewBox="0 0 {size} {size+30}"><circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#eee" stroke-width="9"/><circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{c}" stroke-width="9" stroke-dasharray="{circ}" stroke-dashoffset="{off}" stroke-linecap="round" transform="rotate(-90 {cx} {cy})"/><text x="{cx}" y="{cy+6}" text-anchor="middle" font-size="20" font-weight="bold" fill="{c}">{pct:.1f}%</text><text x="{cx}" y="{size+20}" text-anchor="middle" font-size="11" fill="#333">{h.escape(label)}</text></svg>'

o.append('<h2>Overall Security Scores</h2><div class="card"><div class="gauges">')
o.append(gauge(74.81, "Overall Score", 150))
o.append(gauge(99.26, "Attack Detection", 130))
o.append(gauge(93.33, "ML Confidence", 120))
o.append(gauge(0.74, "Bypass Rate", 120))
o.append('</div>')
o.append('<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:16px 0">')
for val, lbl in [("673", "Attacks Tested"), ("668", "Blocked"), ("5", "Bypassed"), ("141", "FP Tests"), ("816", "Total Payloads")]:
    o.append(f'<div class="metric"><div class="metric-val">{val}</div><div class="metric-lbl">{lbl}</div></div>')
o.append('</div></div>')

# ══════ CYBER KILL CHAIN ══════
o.append('<h2>Cyber Kill Chain Analysis</h2>')
o.append('<div class="card"><p>Mapping WAF test results to the Lockheed Martin Cyber Kill Chain framework. Each phase shows how effectively the WAF blocks attacks at that stage.</p>')

# Kill chain visualization
o.append('<div style="display:flex;align-items:center;justify-content:center;flex-wrap:wrap;margin:20px 0">')
for i, (phase, color, tactic, desc) in enumerate(kill_chain_phases):
    attacks_in_phase = [a for a in attack_mitre_map if a["kill_chain"] == phase]
    total = sum(a["tested"] for a in attacks_in_phase)
    blocked = sum(a["blocked"] for a in attacks_in_phase)
    pct = blocked / total * 100 if total > 0 else 0
    opacity = "1.0" if total > 0 else "0.4"
    o.append(f'<div class="kc-phase" style="background:{color};opacity:{opacity}" title="{desc}">{phase}<br><span style="font-size:9px;font-weight:400">{blocked}/{total} ({pct:.0f}%)</span></div>')
    if i < len(kill_chain_phases) - 1:
        o.append('<span class="kc-arrow">&#9654;</span>')
o.append('</div>')

# Kill chain detail table
o.append('<table><tr><th>Kill Chain Phase</th><th>Attacks Tested</th><th>Blocked</th><th>Bypassed</th><th>Block Rate</th><th>MITRE Tactic</th></tr>')
for phase, color, tactic, desc in kill_chain_phases:
    attacks_in_phase = [a for a in attack_mitre_map if a["kill_chain"] == phase]
    total = sum(a["tested"] for a in attacks_in_phase)
    blocked = sum(a["blocked"] for a in attacks_in_phase)
    bypassed = total - blocked
    pct = blocked / total * 100 if total > 0 else 0
    tag_cls = "low" if pct >= 95 else "med" if pct >= 80 else "high" if pct > 0 else "info"
    tactic_name = tactics.get(tactic, tactic)
    o.append(f'<tr><td><span style="color:{color};font-weight:700">&#9632;</span> {phase}</td><td>{total}</td><td>{blocked}</td><td style="{"color:red;font-weight:bold" if bypassed>0 else ""}">{bypassed}</td><td><span class="tag {tag_cls}">{pct:.0f}%</span></td><td>{h.escape(tactic_name)}</td></tr>')
o.append('</table></div>')

# ══════ MITRE ATT&CK MATRIX ══════
o.append('<h2>MITRE ATT&CK Mapping</h2>')
o.append('<div class="card"><p>Each tested attack category mapped to its MITRE ATT&CK technique with detection effectiveness.</p>')

# Heatmap-style table
o.append('<table><tr><th>Attack Category</th><th>MITRE ID</th><th>Technique Name</th><th>Tactic</th><th>Tested</th><th>Blocked</th><th>Rate</th><th>Coverage</th></tr>')
for atk in sorted(attack_mitre_map, key=lambda x: -x["tested"]):
    mid = atk["mitre_id"]
    tech_name = techniques.get(mid, {}).get("name", mid)
    pct = atk["rate"]
    bar_color = "#56CC54" if pct >= 95 else "#FDBE10" if pct >= 80 else "#F24444"
    bar_w = max(pct, 2)
    o.append(f'<tr><td><b>{h.escape(atk["attack"])}</b><br><span style="font-size:10px;color:#666">{h.escape(atk["desc"][:80])}</span></td>')
    o.append(f'<td class="mono">{mid}</td><td>{h.escape(tech_name[:40])}</td><td>{h.escape(atk["tactic"])}</td>')
    o.append(f'<td>{atk["tested"]}</td><td>{atk["blocked"]}</td>')
    o.append(f'<td><span class="tag {"low" if pct>=95 else "med" if pct>=80 else "high"}">{pct:.1f}%</span></td>')
    o.append(f'<td><div style="width:100px;background:#eee;border-radius:3px;height:14px"><div style="width:{bar_w}%;background:{bar_color};border-radius:3px;height:100%"></div></div></td></tr>')
o.append('</table>')

# MITRE Tactic coverage
o.append('<h3>MITRE Tactic Coverage</h3>')
tactic_coverage = {}
for atk in attack_mitre_map:
    t = atk["tactic"]
    if t not in tactic_coverage:
        tactic_coverage[t] = {"tested": 0, "blocked": 0}
    tactic_coverage[t]["tested"] += atk["tested"]
    tactic_coverage[t]["blocked"] += atk["blocked"]

o.append('<div style="display:flex;flex-wrap:wrap;gap:10px;margin:16px 0">')
for tactic_name, counts in sorted(tactic_coverage.items()):
    pct = counts["blocked"] / counts["tested"] * 100 if counts["tested"] > 0 else 0
    bg = "#f0fff0" if pct >= 95 else "#fffcf0" if pct >= 80 else "#fff0f0"
    border = "#56CC54" if pct >= 95 else "#FDBE10" if pct >= 80 else "#F24444"
    o.append(f'<div style="border:2px solid {border};background:{bg};border-radius:8px;padding:10px;min-width:140px;text-align:center"><div style="font-weight:700;font-size:12px">{h.escape(tactic_name)}</div><div style="font-size:22px;font-weight:900;color:{border}">{pct:.0f}%</div><div style="font-size:10px;color:#666">{counts["blocked"]}/{counts["tested"]} blocked</div></div>')
o.append('</div></div>')

# ══════ PROTECTION ARCHITECTURE ══════
o.append('<h2>Protection Layer Architecture</h2>')
o.append("""<div class="card">
<svg width="100%" height="160" viewBox="0 0 820 160" style="display:block;margin:10px auto">
<rect x="10" y="30" width="120" height="60" rx="8" fill="#f0f0f0" stroke="#666" stroke-width="2"/>
<text x="70" y="58" text-anchor="middle" font-size="11" font-weight="bold" fill="#666">Internet</text>
<text x="70" y="105" text-anchor="middle" font-size="10" fill="#56CC54">&#10003;</text>
<line x1="130" y1="60" x2="175" y2="60" stroke="#ccc" stroke-width="2" marker-end="url(#a)"/>
<rect x="180" y="30" width="120" height="60" rx="8" fill="#f0fff0" stroke="#3942EA" stroke-width="2"/>
<text x="240" y="50" text-anchor="middle" font-size="11" font-weight="bold" fill="#3942EA">Cloudflare</text>
<text x="240" y="65" text-anchor="middle" font-size="9" fill="#3942EA">CDN/Proxy</text>
<text x="240" y="105" text-anchor="middle" font-size="10" fill="#FC7303">Forwards All</text>
<line x1="300" y1="60" x2="345" y2="60" stroke="#ccc" stroke-width="2" marker-end="url(#a)"/>
<rect x="350" y="30" width="120" height="60" rx="8" fill="#fff8f0" stroke="#FC7303" stroke-width="2"/>
<text x="410" y="50" text-anchor="middle" font-size="11" font-weight="bold" fill="#FC7303">SG CAPTCHA</text>
<text x="410" y="65" text-anchor="middle" font-size="9" fill="#FC7303">Bot Protection</text>
<text x="410" y="105" text-anchor="middle" font-size="10" fill="#F24444">Bypassed (4s)</text>
<line x1="470" y1="60" x2="515" y2="60" stroke="#ccc" stroke-width="2" marker-end="url(#a)"/>
<rect x="520" y="30" width="120" height="60" rx="8" fill="#fff0f0" stroke="#F24444" stroke-width="3"/>
<text x="580" y="50" text-anchor="middle" font-size="11" font-weight="bold" fill="#F24444">Origin Server</text>
<text x="580" y="65" text-anchor="middle" font-size="9" fill="#F24444">SiteGround</text>
<text x="580" y="105" text-anchor="middle" font-size="10" fill="#F24444">403 ALL</text>
<line x1="640" y1="60" x2="685" y2="60" stroke="#F24444" stroke-width="2" stroke-dasharray="5,3"/>
<text x="663" y="50" text-anchor="middle" font-size="22" fill="#F24444">&#10007;</text>
<rect x="690" y="30" width="120" height="60" rx="8" fill="#f5f5f5" stroke="#999" stroke-width="1" stroke-dasharray="4,2"/>
<text x="750" y="58" text-anchor="middle" font-size="11" font-weight="bold" fill="#999">WordPress App</text>
<text x="750" y="105" text-anchor="middle" font-size="10" fill="#999">Unreachable</text>
<defs><marker id="a" markerWidth="6" markerHeight="6" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#ccc"/></marker></defs>
</svg></div>""")

# ══════ VULNERABILITIES ══════
o.append('<h2>Identified Vulnerabilities</h2>')
vulns = [
    ("V-001", "CRITICAL", "c", "SiteGround Bot Protection Bypassed in 4 Seconds",
     "The sgcaptcha JS proof-of-work challenge auto-solves without human interaction.",
     "Any automated attack tool can bypass the bot protection layer.",
     "Replace with Cloudflare Turnstile or hCaptcha."),
    ("V-002", "CRITICAL", "c", "Origin Server Returns 403 for ALL Requests",
     "Every URL returns identical 403 (75,193 bytes). Site is completely inaccessible.",
     "Website is offline for all visitors. Business impact: total service outage.",
     "Check SiteGround settings, .htaccess, WordPress plugins immediately."),
    ("V-003", "HIGH", "h", "Cloudflare WAF Not Blocking at Edge",
     "Cloudflare forwards all requests to origin without WAF inspection.",
     "No edge protection. If origin fails, attacks reach the application.",
     "Enable Cloudflare WAF Managed Rules and Bot Fight Mode."),
    ("V-004", "HIGH", "h", "3 RCE Payloads Bypassed WAF (When Site Was Live)",
     "Raw HTTP request RCE payloads evaded detection (83.3% rate vs 100% for others).",
     "Remote code execution attacks could succeed through crafted HTTP requests.",
     "Add WAF rules for raw request inspection and RCE pattern detection."),
    ("V-005", "HIGH", "h", "2 User-Agent Header Attacks Bypassed WAF",
     "Malicious payloads in User-Agent header not inspected by WAF.",
     "Attackers can deliver payloads via User-Agent header undetected.",
     "Enable User-Agent header inspection in WAF rules."),
    ("V-006", "MEDIUM", "m", "AWS WAF Not Detected",
     "No AWS WAF signatures in response chain.",
     "Expected security layer may be misconfigured or missing.",
     "Verify AWS WAF Web ACL attachment."),
]
for vid, sev, cls, title, desc, impact, rec in vulns:
    sev_cls = {"c": "crit", "h": "high", "m": "med"}[cls]
    o.append(f'<div class="vuln vuln-{cls}"><b>{vid}</b> <span class="tag {sev_cls}">{sev}</span> <b>{h.escape(title)}</b><br>')
    o.append(f'<b>Finding:</b> {h.escape(desc)}<br><b>Impact:</b> {h.escape(impact)}<br><b>Fix:</b> {h.escape(rec)}</div>')

# ══════ PREVIOUS RESULTS DETAIL ══════
o.append('<h2>Attack Detection Results (Previous Successful Scan)</h2>')
o.append('<div class="card">')
for atk in sorted(attack_mitre_map, key=lambda x: x["rate"]):
    pct = atk["rate"]
    bar_color = "#56CC54" if pct >= 95 else "#FDBE10" if pct >= 80 else "#F24444"
    bypassed = atk["tested"] - atk["blocked"]
    o.append(f'<div style="margin:6px 0;display:flex;align-items:center;gap:8px">')
    o.append(f'<span style="width:180px;font-size:11px;text-align:right;font-weight:600">{h.escape(atk["attack"])}</span>')
    o.append(f'<div style="flex:1;display:flex;height:20px;border-radius:3px;overflow:hidden;background:#eee">')
    if pct > 0:
        o.append(f'<div style="width:{pct}%;background:{bar_color}"></div>')
    if bypassed > 0:
        o.append(f'<div style="width:{100-pct}%;background:#F24444"></div>')
    o.append(f'</div><span style="width:80px;font-size:11px;font-weight:700;color:{bar_color}">{pct:.0f}% ({atk["blocked"]}/{atk["tested"]})</span></div>')
o.append('</div>')

# Priority actions
o.append('<h2>Priority Action Plan</h2><div class="card"><ol>')
o.append('<li><span class="tag crit">P0</span> <b>Fix origin server 403</b> — site is completely down</li>')
o.append('<li><span class="tag crit">P0</span> <b>Replace sgcaptcha</b> — bypassed by bots in 4 seconds</li>')
o.append('<li><span class="tag high">P1</span> <b>Enable Cloudflare WAF</b> — currently only proxying</li>')
o.append('<li><span class="tag high">P1</span> <b>Fix RCE bypass</b> — add raw request inspection rules</li>')
o.append('<li><span class="tag high">P1</span> <b>Fix User-Agent bypass</b> — add header inspection</li>')
o.append('<li><span class="tag med">P2</span> <b>Verify AWS WAF</b> — not detected in chain</li>')
o.append('<li><span class="tag info">P3</span> <b>Re-scan after fixes</b> to validate remediation</li>')
o.append('</ol></div>')

o.append(f'<div style="margin-top:40px;border-top:1px solid #ddd;padding:12px;font-size:10px;color:#999;text-align:center">')
o.append(f'Generated by GoTestWAF ML Engine | MITRE ATT&CK v15 ({len(techniques)} techniques) | {now}</div>')
o.append('</div></body></html>')

path = Path("reports/kernernorland-full-assessment.html")
path.parent.mkdir(exist_ok=True)
path.write_text("\n".join(o), encoding="utf-8")
print(f"Report: {path} ({path.stat().st_size:,} bytes)")
import webbrowser
webbrowser.open(path.resolve().as_uri())
print("Opened in browser")
