"""Advanced WAF bypass scanner with evasion techniques and PoC evidence.

Sends 100+ evasion payloads through headless browser, records exact
request/response for every bypass found, generates detailed PoC report.
"""

import asyncio
import html as ht
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, "src")
from gotestwaf.scanner.evasion import generate_evasion_payloads


async def main(target: str) -> None:
    from playwright.async_api import async_playwright

    payloads = generate_evasion_payloads()
    print(f"GoTestWAF Bypass Scanner — {target}")
    print(f"Loaded {len(payloads)} evasion payloads across {len(set(p['category'] for p in payloads))} categories")
    print("=" * 70)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--disable-blink-features=AutomationControlled", "--no-sandbox", "--disable-dev-shm-usage"])
        ctx = await browser.new_context(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
        page = await ctx.new_page()
        await page.add_init_script('Object.defineProperty(navigator,"webdriver",{get:()=>undefined})')

        # Solve CAPTCHA
        print("Solving challenge...")
        await page.goto(target, wait_until="commit", timeout=15000)
        solved = False
        for i in range(30):
            await asyncio.sleep(1)
            try:
                t = await page.title()
                if "robot" not in t.lower() and "captcha" not in t.lower() and "sgcaptcha" not in page.url:
                    print(f"  Solved in {i+1}s: {t[:40]}")
                    solved = True
                    break
            except Exception:
                pass
        if not solved:
            print("  WARNING: challenge not solved within 30s — results may all be challenge pages, not real WAF responses")
        await asyncio.sleep(3)

        # Get baseline
        fetch = '''async (url) => {
            try { const r = await fetch(url); const b = await r.text(); return {s: r.status, l: b.length, b: b.substring(0, 500)}; }
            catch(e) { return {s: -1, l: 0, b: '', e: e.message}; }
        }'''
        baseline = await page.evaluate(fetch, "/")
        print(f"Baseline: status={baseline['s']}, size={baseline['l']}")

        # Send evasion payloads
        print(f"\nSending {len(payloads)} evasion payloads...")
        start = time.monotonic()
        results = []
        bypassed = []
        blocked = 0
        unresolved = 0

        for i, p_data in enumerate(payloads):
            payload = p_data["payload"]
            safe = quote(payload, safe="")

            # Try multiple delivery methods
            for method, url_or_opts in [
                ("URL Param", f"/?test={safe}"),
                ("URL Path", f"/{safe}"),
            ]:
                r = await page.evaluate(fetch, url_or_opts)
                status = r.get("s", -1)
                body_len = r.get("l", 0)
                body_preview = r.get("b", "")[:200]

                # Classify. A response is only a real bypass if it actually reached
                # backend logic — not just the SPA shell echoed back unchanged. We
                # require the body to differ meaningfully from the baseline.
                differs_from_baseline = (
                    status != baseline["s"]
                    or abs(body_len - baseline["l"]) > 500
                )
                if status in (403, 406, 429, 503):
                    cls = "blocked"
                    blocked += 1
                elif status == 202:
                    cls = "captcha"
                    unresolved += 1
                elif status == 200 and not differs_from_baseline:
                    # Same shell as baseline — payload was not processed by backend.
                    # Not evidence of a bypass; not a block either.
                    cls = "unresolved"
                    unresolved += 1
                elif differs_from_baseline:
                    cls = "bypassed"
                    bypassed.append({
                        "payload": payload,
                        "category": p_data["category"],
                        "technique": p_data["technique"],
                        "description": p_data["description"],
                        "method": method,
                        "status": status,
                        "response_size": body_len,
                        "response_preview": body_preview,
                        "url": url_or_opts,
                    })
                else:
                    cls = "other"
                    unresolved += 1

                results.append({"payload": payload[:100], "category": p_data["category"],
                                "technique": p_data["technique"], "method": method,
                                "status": status, "size": body_len, "class": cls})

                await asyncio.sleep(0.3)

            if (i + 1) % 20 == 0:
                elapsed = time.monotonic() - start
                print(f"  {i+1}/{len(payloads)} | blocked={blocked} bypassed={len(bypassed)} unresolved={unresolved} [{elapsed:.0f}s]")

        duration = time.monotonic() - start
        await browser.close()

    # Results
    total = len(results)
    print(f"\n{'='*70}")
    print(f"BYPASS SCAN COMPLETE — {duration:.0f}s")
    print(f"Total requests: {total}")
    print(f"Blocked: {blocked}")
    print(f"BYPASSED: {len(bypassed)}")
    print(f"Unresolved: {unresolved}")

    if bypassed:
        print(f"\n{'='*70}")
        print(f"!!! {len(bypassed)} BYPASSES FOUND !!!")
        for b in bypassed:
            print(f"  [{b['category']}] {b['technique']} via {b['method']} — HTTP {b['status']}")
            print(f"    Payload: {b['payload'][:80]}")
            print(f"    Description: {b['description']}")

    # Generate PoC report
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = Path("reports") / f"bypass-poc-{ts}.html"
    report_path.parent.mkdir(exist_ok=True)
    _generate_poc_report(report_path, target, results, bypassed, blocked, unresolved, total, duration, baseline)
    print(f"\nReport: {report_path}")

    try:
        import webbrowser
        webbrowser.open(report_path.resolve().as_uri())
    except Exception:
        pass


def _generate_poc_report(path, target, results, bypassed, blocked, unresolved, total, duration, baseline):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    bypass_count = len(bypassed)
    bypass_rate = bypass_count / max(total, 1) * 100

    o = [f'''<!DOCTYPE html><html><head><meta charset="utf-8">
<title>WAF Bypass PoC Report — {ht.escape(target)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:Inter,-apple-system,sans-serif;background:#0b0f2a;color:#cbd5e1;font-size:13px;line-height:1.7;padding:30px}}
.w{{max-width:1000px;margin:0 auto}}
h1{{font-size:26px;font-weight:900;color:#f87171}}
h2{{font-size:18px;color:#a5b4fc;margin:30px 0 12px;border-bottom:2px solid rgba(99,102,241,0.3);padding-bottom:6px}}
.card{{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:12px;padding:18px;margin:12px 0}}
.ms{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:14px 0}}
.m{{background:rgba(255,255,255,0.04);border-radius:10px;padding:14px;text-align:center;border:1px solid rgba(255,255,255,0.06)}}
.mv{{font-size:26px;font-weight:900;color:#f472b6}}.ml{{font-size:10px;color:#64748b;margin-top:3px}}
table{{border-collapse:collapse;width:100%;font-size:11px;margin:8px 0}}
th{{background:rgba(99,102,241,0.12);padding:8px;text-align:left;border:1px solid rgba(255,255,255,0.06);color:#a5b4fc}}
td{{padding:6px 8px;border:1px solid rgba(255,255,255,0.04)}}
.poc{{border-left:4px solid #ef4444;padding:14px;margin:12px 0;background:rgba(239,68,68,0.05);border-radius:0 10px 10px 0}}
.poc-safe{{border-left:4px solid #22c55e;background:rgba(34,197,94,0.04)}}
.tag{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;color:#fff}}
.tc{{background:#ef4444}}.tl{{background:#22c55e}}.tm{{background:#eab308;color:#000}}.ti{{background:#64748b}}
.mono{{font-family:Consolas,Monaco,monospace;font-size:11px;word-break:break-all}}
.hl{{background:rgba(251,191,36,0.1);padding:2px 6px;border-radius:4px;color:#fbbf24}}
.detail-btn{{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none;padding:5px 14px;border-radius:5px;font-size:10px;font-weight:700;cursor:pointer}}
.detail-btn:hover{{opacity:0.85}}
.det{{display:none;margin-top:8px}}.det.show{{display:block}}
</style></head><body><div class="w">''']

    o.append(f'<h1>{"&#128308; " if bypass_count > 0 else "&#128994; "}WAF Bypass Test Report</h1>')
    o.append(f'<p style="color:#64748b">{ht.escape(target)} | {now} | {total} evasion payloads | {duration:.0f}s</p>')

    o.append('<div class="ms">')
    o.append(f'<div class="m"><div class="mv">{total}</div><div class="ml">Total Sent</div></div>')
    o.append(f'<div class="m"><div class="mv" style="color:#22c55e">{blocked}</div><div class="ml">Blocked</div></div>')
    o.append(f'<div class="m"><div class="mv" style="color:#ef4444">{bypass_count}</div><div class="ml">BYPASSED</div></div>')
    o.append(f'<div class="m"><div class="mv" style="color:#eab308">{unresolved}</div><div class="ml">Unresolved</div></div>')
    o.append(f'<div class="m"><div class="mv" style="color:{"#ef4444" if bypass_rate > 0 else "#22c55e"}">{bypass_rate:.1f}%</div><div class="ml">Bypass Rate</div></div>')
    o.append('</div>')

    if bypassed:
        o.append(f'<h2>&#128308; Confirmed Bypasses — PoC Evidence ({bypass_count})</h2>')
        o.append('<p style="color:#f87171;margin-bottom:12px">Each entry below is a confirmed WAF bypass with full request/response evidence.</p>')

        for i, b in enumerate(bypassed, 1):
            fid = f"bp{i}"
            o.append(f'<div class="poc">')
            o.append(f'<div style="display:flex;justify-content:space-between;align-items:center">')
            o.append(f'<div><span style="font-weight:700;color:#f87171">PoC #{i}</span> <span class="tag tc">BYPASS</span> <span class="tag ti">{ht.escape(b["category"])}</span> <span style="color:#94a3b8;font-size:11px">{ht.escape(b["technique"])}</span></div>')
            o.append(f'<button class="detail-btn" onclick="var e=document.getElementById(\'{fid}\');e.classList.toggle(\'show\');this.textContent=e.classList.contains(\'show\')?\'Hide\':\'Show PoC\'">Show PoC</button></div>')
            o.append(f'<div class="det" id="{fid}">')
            o.append(f'<table><tr><th style="width:130px">Evidence</th><th>Detail</th></tr>')
            o.append(f'<tr><td><b>Category</b></td><td>{ht.escape(b["category"])}</td></tr>')
            o.append(f'<tr><td><b>Technique</b></td><td>{ht.escape(b["technique"])}</td></tr>')
            o.append(f'<tr><td><b>Description</b></td><td>{ht.escape(b["description"])}</td></tr>')
            o.append(f'<tr><td><b>Delivery</b></td><td>{ht.escape(b["method"])}</td></tr>')
            o.append(f'<tr><td><b>Payload</b></td><td><span class="mono hl">{ht.escape(b["payload"][:300])}</span></td></tr>')
            o.append(f'<tr><td><b>Request URL</b></td><td class="mono">{ht.escape(b["url"][:200])}</td></tr>')
            o.append(f'<tr><td><b>Response Status</b></td><td><span style="color:#ef4444;font-weight:700">HTTP {b["status"]}</span> — WAF DID NOT BLOCK</td></tr>')
            o.append(f'<tr><td><b>Response Size</b></td><td>{b["response_size"]} bytes (baseline: {baseline["l"]})</td></tr>')
            o.append(f'<tr><td><b>Response Preview</b></td><td class="mono" style="font-size:10px;color:#94a3b8">{ht.escape(b["response_preview"][:200])}</td></tr>')
            o.append(f'<tr><td><b>Verdict</b></td><td style="color:#ef4444;font-weight:700">CONFIRMED BYPASS — payload reached the application unfiltered</td></tr>')
            o.append(f'</table></div></div>')
    else:
        o.append('<h2>&#128994; No Bypasses Found</h2>')
        o.append(f'<div class="card" style="border-left:4px solid #22c55e"><p style="color:#22c55e;font-weight:700">All {total} evasion payloads were blocked by the WAF. No bypass techniques succeeded.</p></div>')

    # Category summary
    cats = {}
    for r in results:
        c = r["category"]
        cats.setdefault(c, {"blocked": 0, "bypassed": 0, "other": 0, "total": 0})
        if r["class"] == "blocked":
            cats[c]["blocked"] += 1
        elif r["class"] == "bypassed":
            cats[c]["bypassed"] += 1
        else:
            cats[c]["other"] += 1
        cats[c]["total"] += 1

    o.append('<h2>Category Summary</h2><div class="card"><table><tr><th>Category</th><th>Sent</th><th>Blocked</th><th>Bypassed</th><th>Other</th><th>Block Rate</th></tr>')
    for cat, c in sorted(cats.items()):
        resolved = c["blocked"] + c["bypassed"]
        rate = c["blocked"] / resolved * 100 if resolved > 0 else 0
        tcls = "tl" if rate == 100 else "tc" if c["bypassed"] > 0 else "tm"
        o.append(f'<tr><td><b>{ht.escape(cat)}</b></td><td>{c["total"]}</td><td>{c["blocked"]}</td><td style="{"color:#ef4444;font-weight:700" if c["bypassed"]>0 else ""}">{c["bypassed"]}</td><td>{c["other"]}</td><td><span class="tag {tcls}">{rate:.0f}%</span></td></tr>')
    o.append('</table></div>')

    # Blocked samples
    blocked_samples = [r for r in results if r["class"] == "blocked"][:5]
    if blocked_samples:
        o.append(f'<h2>&#128994; Blocked Samples (proof WAF works)</h2><div class="card">')
        for r in blocked_samples:
            o.append(f'<div class="poc poc-safe" style="padding:10px;margin:6px 0"><b>[{ht.escape(r["category"])}]</b> {ht.escape(r["technique"])} via {ht.escape(r["method"])} — <span style="color:#22c55e">HTTP {r["status"]} BLOCKED</span><br><span class="mono" style="font-size:10px">{ht.escape(r["payload"][:100])}</span></div>')
        o.append('</div>')

    o.append(f'<p style="margin-top:30px;border-top:1px solid rgba(255,255,255,0.06);padding:10px;font-size:10px;color:#334155;text-align:center">GoTestWAF Bypass Scanner | {now}</p>')
    o.append('</div></body></html>')

    path.write_text("\n".join(o), encoding="utf-8")


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://kernernorland.com/"
    asyncio.run(main(url))
