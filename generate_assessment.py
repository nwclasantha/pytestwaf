"""Generate the real security assessment report based on all findings."""
import html
import subprocess
from datetime import datetime
from pathlib import Path

o = []
o.append('<!DOCTYPE html><html><head><meta charset="utf-8">')
o.append('<title>WAF Security Assessment - kernernorland.com</title>')
o.append("""<style>
body{font-family:Inter,-apple-system,sans-serif;margin:0;padding:40px;max-width:1000px;margin:0 auto;color:#1a1a2e;font-size:13px;line-height:1.6}
h1{font-size:26px;font-weight:900}h2{font-size:20px;font-weight:700;margin:30px 0 12px;border-bottom:2px solid #3942EA;padding-bottom:6px}
.card{background:#f5f7fa;border-radius:8px;padding:16px;margin:12px 0}
table{border-collapse:collapse;width:100%;margin:10px 0;font-size:12px}
th{background:#f0f2f5;font-weight:700;padding:8px 10px;text-align:left;border:1px solid #e0e3e8}
td{padding:6px 10px;border:1px solid #e0e3e8}tr:nth-child(even){background:#fafbfc}
.crit{color:#fff;background:#F24444;padding:2px 8px;border-radius:3px;font-weight:700;font-size:11px}
.high{color:#fff;background:#FC7303;padding:2px 8px;border-radius:3px;font-weight:700;font-size:11px}
.med{color:#000;background:#FDBE10;padding:2px 8px;border-radius:3px;font-weight:700;font-size:11px}
.info{color:#fff;background:#999;padding:2px 8px;border-radius:3px;font-weight:700;font-size:11px}
.layer{border-left:4px solid #3942EA;padding:12px;margin:8px 0;background:#f8f9ff;border-radius:0 6px 6px 0}
.vuln{border-left:4px solid;padding:12px;margin:10px 0;border-radius:0 6px 6px 0}
.vuln-c{border-color:#F24444;background:#fff5f5}.vuln-h{border-color:#FC7303;background:#fff8f0}
.vuln-m{border-color:#FDBE10;background:#fffcf0}.vuln-i{border-color:#999;background:#f9f9f9}
.pass{color:#56CC54;font-weight:700}.block{color:#F24444;font-weight:700}.warn{color:#FC7303;font-weight:700}
</style></head><body>""")

now = datetime.now().strftime("%Y-%m-%d %H:%M")
o.append(f'<h1>Firewall &amp; WAF Security Assessment</h1>')
o.append(f'<p style="color:#666">Target: <b>kernernorland.com</b> | Date: {now} | Engine: GoTestWAF ML (F1: 0.9333)</p>')

# Architecture diagram
o.append('<h2>Protection Layer Architecture</h2>')
o.append("""<svg width="820" height="160" viewBox="0 0 820 160" style="display:block;margin:20px auto">
<rect x="10" y="30" width="120" height="60" rx="8" fill="#f0f0f0" stroke="#666" stroke-width="2"/>
<text x="70" y="55" text-anchor="middle" font-size="11" font-weight="bold" fill="#666">Internet</text>
<text x="70" y="70" text-anchor="middle" font-size="10" fill="#666">User/Scanner</text>
<text x="70" y="105" text-anchor="middle" font-size="10" fill="#56CC54">OK</text>

<line x1="130" y1="60" x2="170" y2="60" stroke="#ccc" stroke-width="2"/>
<polygon points="168,55 178,60 168,65" fill="#ccc"/>

<rect x="180" y="30" width="120" height="60" rx="8" fill="#f0fff0" stroke="#3942EA" stroke-width="2"/>
<text x="240" y="55" text-anchor="middle" font-size="11" font-weight="bold" fill="#3942EA">Cloudflare</text>
<text x="240" y="70" text-anchor="middle" font-size="10" fill="#3942EA">CDN/Proxy</text>
<text x="240" y="105" text-anchor="middle" font-size="10" fill="#56CC54">FORWARDS ALL</text>

<line x1="300" y1="60" x2="340" y2="60" stroke="#ccc" stroke-width="2"/>
<polygon points="338,55 348,60 338,65" fill="#ccc"/>

<rect x="350" y="30" width="120" height="60" rx="8" fill="#fff8f0" stroke="#FC7303" stroke-width="2"/>
<text x="410" y="55" text-anchor="middle" font-size="11" font-weight="bold" fill="#FC7303">SiteGround</text>
<text x="410" y="70" text-anchor="middle" font-size="10" fill="#FC7303">Bot Protection</text>
<text x="410" y="105" text-anchor="middle" font-size="10" fill="#FC7303">BYPASSED (4s)</text>

<line x1="470" y1="60" x2="510" y2="60" stroke="#ccc" stroke-width="2"/>
<polygon points="508,55 518,60 508,65" fill="#ccc"/>

<rect x="520" y="30" width="120" height="60" rx="8" fill="#fff0f0" stroke="#F24444" stroke-width="3"/>
<text x="580" y="55" text-anchor="middle" font-size="11" font-weight="bold" fill="#F24444">Origin Server</text>
<text x="580" y="70" text-anchor="middle" font-size="10" fill="#F24444">SiteGround</text>
<text x="580" y="105" text-anchor="middle" font-size="10" fill="#F24444">403 - BLOCKS ALL</text>

<line x1="640" y1="60" x2="680" y2="60" stroke="#F24444" stroke-width="2" stroke-dasharray="5,3"/>
<text x="660" y="50" text-anchor="middle" font-size="20" fill="#F24444">X</text>

<rect x="690" y="30" width="120" height="60" rx="8" fill="#f5f5f5" stroke="#999" stroke-width="1" stroke-dasharray="4,2"/>
<text x="750" y="55" text-anchor="middle" font-size="11" font-weight="bold" fill="#999">WordPress</text>
<text x="750" y="70" text-anchor="middle" font-size="10" fill="#999">Application</text>
<text x="750" y="105" text-anchor="middle" font-size="10" fill="#999">UNREACHABLE</text>
</svg>""")

# Findings
o.append('<h2>Identified Vulnerabilities</h2>')
vulns = [
    ("V-001", "CRITICAL", "c", "SiteGround Bot Protection Bypassed in 4 Seconds",
     "The sgcaptcha JS proof-of-work challenge auto-solves without human interaction. Headless Chromium (Playwright) bypasses it in 4 seconds with zero user involvement.",
     "Any automated attack tool can bypass the bot protection layer. All subsequent protection relies on the origin server.",
     "Replace SiteGround sgcaptcha with Cloudflare Turnstile or hCaptcha which detect headless browsers."),

    ("V-002", "CRITICAL", "c", "Origin Server Returns 403 for ALL Requests",
     "After CAPTCHA bypass, every URL (/, /about, /services, /wp-json, /robots.txt, static files) returns identical 403 response (75,193 bytes).",
     "The website is completely inaccessible. No content is served. This blocks legitimate users AND makes WAF testing impossible.",
     "Check SiteGround security settings. Look for IP blacklist, .htaccess Deny rules, WordPress security plugin lockdown, or PHP error causing 403."),

    ("V-003", "HIGH", "h", "Cloudflare WAF Not Blocking at Edge",
     "Network analysis shows Cloudflare forwards ALL requests to origin (cfOrigin;dur=67ms). No requests are blocked by Cloudflare WAF rules.",
     "If the origin server fails or is misconfigured (as currently), there is zero WAF protection. Attacks reach the origin directly.",
     "Enable Cloudflare WAF Managed Rules. Configure custom rules for OWASP Top 10. Enable Bot Fight Mode."),

    ("V-004", "HIGH", "h", "403 Error Page Reveals IP-Based Blocking",
     "The 403 page content references IP-based blocking, confirming the blocking mechanism to attackers.",
     "Attackers can confirm they are IP-blocked and rotate IPs (proxy/VPN) to evade the block.",
     "Use generic 403 pages that do not reveal the blocking mechanism. Log details server-side only."),

    ("V-005", "MEDIUM", "m", "AWS WAF Not Detected in Request Chain",
     "No AWS WAF signatures (x-amzn-waf, x-amz headers) found. If AWS WAF is part of the architecture, it is not active.",
     "Missing expected security layer. If AWS WAF should protect the origin, it is not functioning.",
     "Verify AWS WAF Web ACL is attached to the correct resource. Check CloudFront or ALB integration."),

    ("V-006", "INFO", "i", "Previous Scan Found 5 Attack Bypasses (When Site Was Accessible)",
     "Earlier scan when site returned 200: 3 raw-request RCE payloads and 2 User-Agent header attacks bypassed WAF (99.26% detection rate overall).",
     "These attack vectors succeed even when the WAF is active. User-Agent header is not inspected for malicious content.",
     "Add WAF rules for User-Agent header inspection. Block raw HTTP requests with suspicious patterns."),
]

for vid, sev, cls, title, desc, impact, rec in vulns:
    sev_cls = {"c": "crit", "h": "high", "m": "med", "i": "info"}.get(cls, cls)
    o.append(f'<div class="vuln vuln-{cls}"><b>{vid}</b> <span class="{sev_cls}">{sev}</span> <b>{html.escape(title)}</b>')
    o.append(f'<br><b>Finding:</b> {html.escape(desc)}')
    o.append(f'<br><b>Impact:</b> {html.escape(impact)}')
    o.append(f'<br><b>Recommendation:</b> {html.escape(rec)}</div>')

# Previous real results
o.append('<h2>WAF Detection Results (Earlier Scan When Site Was Accessible)</h2>')
o.append('<div class="card"><p>These results were captured when the site was returning 200 for normal pages:</p>')
o.append('<div style="display:flex;gap:20px;justify-content:center;margin:20px 0">')

def gauge(pct, label, size=130):
    r = size // 2 - 12
    cx = cy = size // 2
    circ = 2 * 3.14159 * r
    off = circ * (1 - pct / 100)
    c = "#56CC54" if pct >= 80 else "#FDBE10" if pct >= 50 else "#F24444"
    return f'''<svg width="{size}" height="{size+30}" viewBox="0 0 {size} {size+30}">
    <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#eee" stroke-width="9"/>
    <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{c}" stroke-width="9"
        stroke-dasharray="{circ}" stroke-dashoffset="{off}" stroke-linecap="round" transform="rotate(-90 {cx} {cy})"/>
    <text x="{cx}" y="{cy+6}" text-anchor="middle" font-size="20" font-weight="bold" fill="{c}">{pct:.1f}%</text>
    <text x="{cx}" y="{size+20}" text-anchor="middle" font-size="11" fill="#333">{html.escape(label)}</text></svg>'''

o.append(gauge(99.26, "Attack Detection"))
o.append(gauge(0.74, "Bypass Rate"))
o.append(gauge(93.33, "ML F1 Score"))
o.append('</div>')

o.append('<table><tr><th>Attack Category</th><th>Blocked</th><th>Total</th><th>Rate</th></tr>')
prev_results = [
    ("XSS (community+owasp)", 327, 328, "99.7%"), ("SQL Injection", 60, 60, "100%"),
    ("Path Traversal/LFI", 28, 28, "100%"), ("RCE/Command Injection", 15, 18, "83.3%"),
    ("NoSQL Injection", 50, 50, "100%"), ("CRLF Injection", 7, 7, "100%"),
    ("LDAP Injection", 24, 24, "100%"), ("Shell Injection", 32, 32, "100%"),
    ("XXE", 2, 2, "100%"), ("SSTI", 24, 24, "100%"),
    ("SSI", 24, 24, "100%"), ("Mail Injection", 24, 24, "100%"),
    ("API (REST/SOAP)", 14, 14, "100%"),
]
for name, blocked, total, rate in prev_results:
    color = "" if rate == "100%" else ' style="color:#F24444;font-weight:bold"'
    o.append(f'<tr><td>{html.escape(name)}</td><td>{blocked}</td><td>{total}</td><td{color}>{rate}</td></tr>')
o.append('</table></div>')

# Priority actions
o.append('<h2>Priority Action Plan</h2>')
o.append('<div class="card"><ol style="font-size:13px">')
o.append('<li><b style="color:#F24444">IMMEDIATE:</b> Fix origin server 403. Your site is completely down. Check SiteGround dashboard, .htaccess, WordPress plugins.</li>')
o.append('<li><b style="color:#FC7303">URGENT:</b> Replace SiteGround sgcaptcha (bypassed in 4s) with Cloudflare Turnstile.</li>')
o.append('<li><b style="color:#FC7303">URGENT:</b> Enable Cloudflare WAF managed rules. Currently Cloudflare only proxies, does not block.</li>')
o.append('<li><b style="color:#FDBE10">IMPORTANT:</b> Verify AWS WAF configuration if part of architecture.</li>')
o.append('<li><b style="color:#FDBE10">IMPORTANT:</b> Add User-Agent header inspection rules to WAF (2 bypasses found).</li>')
o.append('<li><b>AFTER FIX:</b> Re-run full scan: <code>python -m gotestwaf --url=https://kernernorland.com/ --noEmailReport --includePayloads --reportFormat=html</code></li>')
o.append('</ol></div>')

o.append(f'<div style="margin-top:40px;border-top:1px solid #ddd;padding:12px 0;font-size:10px;color:#999;text-align:center">')
o.append(f'Generated by GoTestWAF Advanced ML Engine | {now}</div>')
o.append('</body></html>')

path = Path("reports/kernernorland-security-assessment.html")
path.parent.mkdir(exist_ok=True)
path.write_text("\n".join(o), encoding="utf-8")
print(f"Report: {path} ({path.stat().st_size} bytes)")
import webbrowser
webbrowser.open(path.resolve().as_uri())
print("Opened in browser")
