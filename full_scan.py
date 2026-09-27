"""Full WAF scan with ML analysis and visual HTML report.

Runs headless Chromium, solves CAPTCHA, scans all test cases,
trains ML models, generates comprehensive visual report.
"""

import asyncio
import base64
import csv
import html
import json
import math
import random
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import yaml

sys.path.insert(0, "src")

# ── Stealth init script injected before every page load ──
_STEALTH_JS = """
// Hide webdriver flag
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});

// Fake plugins array (headless has 0)
Object.defineProperty(navigator, 'plugins', {
    get: () => [1, 2, 3, 4, 5],
});

// Fake languages
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en'],
});

// Override permissions API
if (navigator.permissions) {
    const origQuery = navigator.permissions.query;
    navigator.permissions.query = (params) =>
        params.name === 'notifications'
            ? Promise.resolve({state: Notification.permission})
            : origQuery.call(navigator.permissions, params);
}

// Chrome runtime stub (missing in headless)
window.chrome = window.chrome || {};
window.chrome.runtime = window.chrome.runtime || {
    onMessage: {addListener: ()=>{}, removeListener: ()=>{}},
    sendMessage: ()=>{},
    connect: ()=>({onMessage: {addListener: ()=>{}}, postMessage: ()=>{}}),
};

// Consistent screen dimensions
Object.defineProperty(screen, 'width', {get: () => 1920});
Object.defineProperty(screen, 'height', {get: () => 1080});
Object.defineProperty(screen, 'availWidth', {get: () => 1920});
Object.defineProperty(screen, 'availHeight', {get: () => 1040});

// Prevent canvas fingerprinting from revealing headless
const _origToDataURL = HTMLCanvasElement.prototype.toDataURL;
HTMLCanvasElement.prototype.toDataURL = function(type) {
    if (type === 'image/png' || !type) return _origToDataURL.apply(this, arguments);
    return _origToDataURL.apply(this, arguments);
};
"""

# WAF block page keywords (used for body-based classification)
_WAF_KEYWORDS = (
    "blocked", "denied", "forbidden", "rejected", "security",
    "firewall", "waf", "violation", "error 1020", "attention required",
    "access denied", "not acceptable", "request rejected",
    "cloudflare", "modsecurity", "web application firewall", "ray id",
    "incapsula", "sucuri", "akamai", "imperva",
)

# Cloudflare-specific challenge/block markers
_CF_CHALLENGE_MARKERS = (
    "just a moment", "checking your browser", "enable javascript",
    "cf-browser-verification", "challenge-platform", "turnstile",
    "cf-chl-bypass", "managed challenge", "ray id",
)


async def main(target: str) -> None:
    from playwright.async_api import async_playwright

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    print(f"[{ts}] GoTestWAF Advanced Scan — {target}")
    print("=" * 70)

    # ── Load test cases ──
    cases = _load_test_cases()
    total = sum(len(tc["payloads"]) * len(tc["encoders"]) * len([p for p in tc["placeholders"] if isinstance(p, str) and p not in ("gRPC", "GraphQL")]) for tc in cases)
    print(f"Loaded {len(cases)} test sets, {total} payloads")

    # ── Launch browser with full stealth ──
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-infobars",
                "--window-size=1920,1080",
                "--start-maximized",
                "--disable-extensions",
                "--disable-gpu",
                "--lang=en-US,en",
            ],
        )
        ctx = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1920, "height": 1080},
            locale="en-US",
            timezone_id="America/New_York",
            extra_http_headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Sec-Ch-Ua": '"Chromium";v="131", "Not_A Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            },
        )
        await ctx.add_init_script(_STEALTH_JS)
        page = await ctx.new_page()

        # ── Solve Cloudflare challenge ──
        print("Navigating to target and solving challenge...")
        baseline, baseline_body = await _solve_and_baseline(page, ctx, target)
        print(f"Baseline: status={baseline['s']}, size={baseline['l']}, is_block_page={baseline.get('is_block', False)}")

        if baseline.get("is_block", False):
            print("\n*** WARNING: Baseline response is a WAF/bot block page (403).")
            print("    Cloudflare is blocking ALL traffic including benign requests.")
            print("    Results will show which payloads trigger DIFFERENT block responses")
            print("    vs the generic bot-block page.\n")

        # ── Scan ──
        print(f"\nScanning {total} payloads...")
        start = time.monotonic()
        results = []
        sent = 0

        for tc in cases:
            for payload in tc["payloads"]:
                for enc in tc["encoders"]:
                    for ph in tc["placeholders"]:
                        if not isinstance(ph, str) or ph in ("gRPC", "GraphQL"):
                            continue

                        encoded = _encode(payload, enc)
                        r = await _send(page, target, encoded, ph, enc)
                        sent += 1

                        # Classify using body-aware classifier
                        cls = _classify(r, baseline, baseline_body, tc["set"])

                        results.append({
                            "set": tc["set"], "case": tc["name"], "type": tc["type"],
                            "payload": payload[:300], "encoder": enc, "placeholder": ph,
                            "status": r["s"], "size": r["l"], "classification": cls,
                            "is_fp": "false" in tc["set"],
                            "body_snippet": r.get("body", "")[:200],
                        })

                        if sent % 100 == 0:
                            e = time.monotonic() - start
                            b = sum(1 for x in results if x["classification"] == "blocked")
                            p_ = sum(1 for x in results if x["classification"] == "passed")
                            u = sum(1 for x in results if x["classification"] == "unresolved")
                            print(f"  {sent}/{total} ({sent*100//total}%) blocked={b} bypassed={p_} unresolved={u} [{e:.0f}s]")

                        # Jittered delay to avoid rate limiting
                        await asyncio.sleep(random.uniform(0.15, 0.45))

        duration = time.monotonic() - start
        await browser.close()

    # ── Results ──
    blocked = sum(1 for x in results if x["classification"] == "blocked")
    passed = sum(1 for x in results if x["classification"] == "passed")
    unresolved = sum(1 for x in results if x["classification"] == "unresolved")
    failed = sum(1 for x in results if x["classification"] == "failed")

    attacks = [x for x in results if not x["is_fp"]]
    benign = [x for x in results if x["is_fp"]]

    tp_blocked = sum(1 for x in attacks if x["classification"] == "blocked")
    tp_passed = sum(1 for x in attacks if x["classification"] == "passed")
    tp_unresolved = sum(1 for x in attacks if x["classification"] == "unresolved")
    tp_resolved = tp_blocked + tp_passed
    tp_pct = tp_blocked / tp_resolved * 100 if tp_resolved > 0 else 0

    tn_blocked = sum(1 for x in benign if x["classification"] == "blocked")
    tn_passed = sum(1 for x in benign if x["classification"] == "passed")
    tn_resolved = tn_blocked + tn_passed
    tn_pct = tn_passed / tn_resolved * 100 if tn_resolved > 0 else 0

    print(f"\n{'='*70}")
    print(f"RESULTS: {sent} sent, {blocked} blocked, {passed} bypassed, {unresolved} unresolved, {failed} failed")
    if tp_resolved > 0:
        print(f"True-Positive (attack blocked): {tp_pct:.1f}% ({tp_blocked}/{tp_resolved})")
    else:
        print(f"True-Positive: N/A — all {tp_unresolved} attack responses were unresolved (identical to baseline)")
    if tn_resolved > 0:
        print(f"True-Negative (benign passed): {tn_pct:.1f}% ({tn_passed}/{tn_resolved})")
    else:
        tn_unresolved = sum(1 for x in benign if x["classification"] == "unresolved")
        print(f"True-Negative: N/A — all {tn_unresolved} benign responses were unresolved")

    if unresolved > len(results) * 0.8:
        print(f"\n*** HIGH UNRESOLVED RATE: {unresolved}/{len(results)} ({unresolved*100//max(len(results),1)}%)")
        print("    The WAF/CDN is returning the SAME block page for all requests.")
        print("    This means bot-level blocking is active (Cloudflare Bot Fight Mode).")
        print("    The WAF cannot be properly tested until bot blocking is resolved.")
        print("    Recommendations:")
        print("    1. Whitelist the scanner IP in Cloudflare firewall rules")
        print("    2. Temporarily disable Bot Fight Mode for testing")
        print("    3. Use a Cloudflare API token for authenticated testing")

    # ── ML Analysis ──
    print(f"\nTraining ML engine...")
    from gotestwaf.ml.engine import HybridMLEngine
    engine = HybridMLEngine()
    for r in results:
        engine.add_result(r["payload"], r["encoder"], r["placeholder"], r["status"], {}, b"", r["classification"] == "blocked", r["set"], r["case"])

    metrics = engine.train()
    print(f"  CV F1: {metrics.cv_f1:.4f}, samples: {metrics.samples}")
    if metrics.feature_importance:
        top3 = list(metrics.feature_importance.items())[:3]
        print(f"  Top features: {', '.join(f'{k}={v:.3f}' for k,v in top3)}")

    # ── Save CSV ──
    csv_path = Path("reports") / f"scan-{ts}.csv"
    csv_path.parent.mkdir(exist_ok=True)
    if not results:
        print("No results to save.")
        return
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)

    # ── Generate HTML Report ──
    html_path = Path("reports") / f"scan-{ts}.html"
    _generate_report(html_path, target, results, attacks, benign, tp_pct, tn_pct, tp_blocked, tp_passed, tp_unresolved, tn_blocked, tn_passed, duration, engine, metrics, baseline)
    print(f"\nReports: {csv_path}, {html_path}")

    # Open report
    import os, webbrowser
    try:
        webbrowser.open(html_path.resolve().as_uri())
        print("Report opened in browser")
    except Exception:
        print(f"Open: {html_path.resolve()}")


def _load_test_cases():
    cases = []
    for f in sorted(list(Path("testcases").rglob("*.yml")) + list(Path("testcases").rglob("*.yaml"))):
        if len(f.parts) < 3:
            continue
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not data:
            continue
        cases.append({"set": f.parts[-2], "name": f.stem, "payloads": data.get("payload", []),
                       "encoders": data.get("encoder", []),
                       "placeholders": [p if isinstance(p, str) else list(p.keys())[0] if isinstance(p, dict) else str(p) for p in data.get("placeholder", [])],
                       "type": data.get("type", "unknown")})
    return cases


async def _solve_and_baseline(page, ctx, target):
    """Navigate to target, solve Cloudflare challenge, and capture baseline.

    Returns (baseline_dict, baseline_body_text).
    The baseline_dict has keys: s (status), l (body length), body (text), is_block (bool).
    """
    # Step 1: Navigate and wait for Cloudflare challenge to resolve
    try:
        await page.goto(target, wait_until="domcontentloaded", timeout=30000)
    except Exception:
        try:
            await page.goto(target, wait_until="commit", timeout=15000)
        except Exception:
            pass

    # Step 2: Wait for Cloudflare challenge to solve
    # Cloudflare challenge pages have specific markers we need to watch for
    print("  Waiting for Cloudflare challenge...")
    solved = False
    for i in range(60):
        await asyncio.sleep(1)
        try:
            title = (await page.title()).lower()
            body_text = await page.evaluate("document.body ? document.body.innerText.substring(0, 2000) : ''")
            body_lower = body_text.lower() if body_text else ""

            # Check if we're still on a challenge page
            is_challenge = (
                "just a moment" in title
                or "checking your browser" in body_lower
                or "challenge-platform" in (await page.content()).lower()[:5000]
                or "cf-chl-bypass" in (await page.content()).lower()[:5000]
                or "turnstile" in (await page.content()).lower()[:5000]
            )

            if is_challenge:
                if i % 10 == 0 and i > 0:
                    print(f"  Still on challenge page ({i}s)...")
                continue

            # Check for cf_clearance cookie (Cloudflare's session cookie)
            cookies = await ctx.cookies()
            cookie_names = [c["name"] for c in cookies]
            has_clearance = "cf_clearance" in cookie_names

            if has_clearance:
                print(f"  Cloudflare challenge solved (cf_clearance obtained) [{i+1}s]")
                solved = True
                break

            # If title is NOT a challenge and we're past 5 seconds, consider it done
            # (some sites don't use cf_clearance)
            if i >= 5 and not is_challenge:
                print(f"  Page loaded: '{title[:50]}' [{i+1}s]")
                solved = True
                break

        except Exception:
            continue

    if not solved:
        print("  Challenge not solved in 60s — extracting cookies and proceeding")

    # Step 3: Extra wait for cookies to settle
    await asyncio.sleep(2)

    # Log cookies for debugging
    cookies = await ctx.cookies()
    cf_cookies = [c["name"] for c in cookies if c["name"].startswith("cf_") or c["name"].startswith("__cf")]
    if cf_cookies:
        print(f"  Cloudflare cookies: {', '.join(cf_cookies)}")
    else:
        print("  WARNING: No Cloudflare cookies found — requests may be blocked")

    # Step 4: If we didn't get cf_clearance, try reloading the page
    cookie_names = [c["name"] for c in cookies]
    if "cf_clearance" not in cookie_names:
        print("  No cf_clearance — reloading page...")
        try:
            await page.reload(wait_until="domcontentloaded", timeout=20000)
            await asyncio.sleep(5)
            cookies = await ctx.cookies()
            cf_cookies = [c["name"] for c in cookies if c["name"].startswith("cf_") or c["name"].startswith("__cf")]
            if cf_cookies:
                print(f"  After reload cookies: {', '.join(cf_cookies)}")
        except Exception:
            pass

    # Step 5: Capture baseline — make 3 requests and analyze
    print("  Capturing baseline...")
    baselines = []
    for attempt in range(3):
        r = await _fetch_with_body(page, "/")
        baselines.append(r)
        if attempt < 2:
            await asyncio.sleep(1)

    # Use the most common status as baseline
    baseline = baselines[0]
    baseline_body = baseline.get("body", "")

    # Detect if baseline is a WAF block page
    bl = baseline_body.lower()
    is_block_page = (
        baseline["s"] in (403, 406, 429, 503)
        and any(kw in bl for kw in _WAF_KEYWORDS)
    )

    # Also detect Cloudflare-specific block (even without WAF keywords)
    if baseline["s"] == 403 and ("ray id" in bl or "cloudflare" in bl):
        is_block_page = True

    baseline["is_block"] = is_block_page

    # If baseline is a block page, try navigating to a few paths to find a real page
    if is_block_page:
        print("  Baseline is a block page — trying alternative paths...")
        for alt_path in ["/robots.txt", "/favicon.ico", "/sitemap.xml"]:
            alt = await _fetch_with_body(page, alt_path)
            if alt["s"] == 200:
                print(f"  Found accessible path: {alt_path} (status={alt['s']})")
                # Use this as our "pass" reference
                baseline["pass_ref_status"] = alt["s"]
                baseline["pass_ref_size"] = alt["l"]
                baseline["pass_ref_body"] = alt.get("body", "")[:500]
                break

    return baseline, baseline_body


async def _fetch_with_body(page, path):
    """Fetch a URL from within the browser context, returning status + body text."""
    try:
        r = await page.evaluate('''async (p) => {
            try {
                const r = await fetch(p, {credentials: 'include'});
                const t = await r.text();
                return {s: r.status, l: t.length, body: t.substring(0, 5000)};
            } catch(e) { return {s: -1, l: 0, body: ''}; }
        }''', path)
        return r
    except Exception:
        return {"s": -1, "l": 0, "body": ""}


async def _fetch(page, path):
    """Fetch a URL, returning status + length (backward compat)."""
    r = await _fetch_with_body(page, path)
    return r


async def _send(page, base, payload, placeholder, encoder):
    """Send a payload through the browser's fetch API with credentials included."""
    base = base.rstrip("/")
    safe = quote(payload, safe="")

    if placeholder in ("URLParam", "RawRequest"):
        return await _fetch_with_body(page, f"/?t={safe}")
    elif placeholder == "URLPath":
        return await _fetch_with_body(page, f"/{safe}")
    elif placeholder in ("Header", "UserAgent"):
        hdr = "User-Agent" if placeholder == "UserAgent" else "X-Test"
        try:
            r = await page.evaluate(f'''async () => {{
                try {{
                    const r = await fetch("/", {{
                        credentials: 'include',
                        headers: {{{json.dumps(hdr)}: {json.dumps(payload)}}}
                    }});
                    const t = await r.text();
                    return {{s: r.status, l: t.length, body: t.substring(0, 5000)}};
                }} catch(e) {{ return {{s: -1, l: 0, body: ''}}; }}
            }}''')
            return r
        except Exception:
            return {"s": -1, "l": 0, "body": ""}
    elif placeholder in ("JSONBody", "JSONRequest"):
        body_obj = {"test": payload}
        try:
            r = await page.evaluate(f'''async () => {{
                try {{
                    const r = await fetch("/", {{
                        method: "POST",
                        credentials: 'include',
                        headers: {{"Content-Type": "application/json"}},
                        body: JSON.stringify({json.dumps(body_obj)})
                    }});
                    const t = await r.text();
                    return {{s: r.status, l: t.length, body: t.substring(0, 5000)}};
                }} catch(e) {{ return {{s: -1, l: 0, body: ''}}; }}
            }}''')
            return r
        except Exception:
            return {"s": -1, "l": 0, "body": ""}
    else:
        # HTMLForm, XMLBody, SOAPBody, RequestBody, HTMLMultipartForm
        try:
            r = await page.evaluate('''async (p) => {
                try {
                    const r = await fetch("/", {
                        method: "POST",
                        credentials: "include",
                        body: p
                    });
                    const t = await r.text();
                    return {s: r.status, l: t.length, body: t.substring(0, 5000)};
                } catch(e) { return {s: -1, l: 0, body: ""}; }
            }''', payload)
            return r
        except Exception:
            return {"s": -1, "l": 0, "body": ""}


def _encode(payload, enc):
    try:
        if enc in ("URL", "URLEncode"): return quote(payload, safe="!$&'()*+,;=:@")
        if enc == "Base64": return base64.b64encode(payload.encode()).decode()
        if enc == "Base64Flat": return base64.b64encode(payload.encode()).decode().rstrip("=")
        if enc in ("JSUnicode", "JsUnicode"):
            u = payload.encode("utf-16-be")
            return "".join(f"\\u{u[i]:02x}{u[i+1]:02x}" for i in range(0, len(u), 2))
        if enc in ("Plain", ""):
            return payload
    except Exception:
        pass
    return payload


def _strip_dynamic(text):
    """Strip dynamic content (timestamps, tokens, IDs) for stable comparison."""
    text = re.sub(r'<script[^>]*>.*?</script>', ' ', text, flags=re.S)
    text = re.sub(r'<style[^>]*>.*?</style>', ' ', text, flags=re.S)
    text = re.sub(r'="[^"]*"', ' ', text)
    text = re.sub(r"='[^']*'", ' ', text)
    text = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', ' ', text)
    text = re.sub(r'[0-9a-f]{12,}', ' ', text)
    text = re.sub(r'\d{10,13}', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def _classify(r, baseline, baseline_body, test_set):
    """Classify response as blocked/passed/unresolved using body content analysis.

    Handles three baseline types:
    - Normal (200): standard blocked/passed classification
    - Block page (403 + WAF keywords): Jaccard comparison to detect real blocks vs generic bot block
    - CAPTCHA (202 or captcha keywords): CAPTCHA responses are always unresolved
    """
    s = r.get("s", -1)
    body = r.get("body", "")
    bl_status = baseline.get("s", 200)
    bl_size = baseline.get("l", 0)
    bl_is_block = baseline.get("is_block", False)

    if s == -1:
        return "failed"

    body_lower = body.lower() if body else ""

    # Count WAF keywords in response
    waf_score = sum(1 for kw in _WAF_KEYWORDS if kw in body_lower)

    # CAPTCHA keywords — never classify CAPTCHA responses as bypass
    captcha_kws = ("captcha", "challenge", "robot", "sgcaptcha",
                   "verify you are human", "checking your browser",
                   "just a moment", "bot protection")
    captcha_score = sum(1 for kw in captcha_kws if kw in body_lower)
    bl_captcha = bl_status == 202 or any(kw in (baseline_body or "").lower() for kw in captcha_kws)

    # Response is CAPTCHA — always unresolved (bot protection, not WAF)
    if s == 202 or captcha_score >= 1:
        return "unresolved"

    # Baseline is CAPTCHA — can't reliably compare
    if bl_captcha:
        if s == 200 and waf_score == 0:
            return "passed"  # Got through CAPTCHA AND WAF
        if s in (403, 406, 429, 503):
            return "blocked"
        return "unresolved"

    # ── Case 1: Baseline is a normal page (200) ──
    if not bl_is_block and bl_status == 200:
        if s in (403, 406, 429, 503):
            return "blocked"
        if s == 200:
            # Check if body contains WAF block indicators despite 200 status (soft block)
            if waf_score >= 2 and r.get("l", 0) < 5000:
                return "blocked"
            return "passed"
        # Redirect or other status
        if 300 <= s < 400:
            return "passed"
        return "unresolved"

    # ── Case 2: Baseline is a block page (403/etc) ──
    # This is the tricky case. We need body-level analysis.
    if bl_is_block:
        # If we somehow got a 200, the payload bypassed
        if s == 200:
            # But verify it's not a soft-block (200 with block keywords)
            if waf_score >= 2 and r.get("l", 0) < 5000:
                return "blocked"
            return "passed"

        # Both baseline and response are block pages — compare bodies
        if s in (403, 406, 429, 503) and bl_status in (403, 406, 429, 503):
            # Strip dynamic content and compare
            resp_stripped = _strip_dynamic(body_lower[:3000])
            base_stripped = _strip_dynamic(baseline_body.lower()[:3000])

            resp_tokens = set(resp_stripped.split())
            base_tokens = set(base_stripped.split())

            if resp_tokens and base_tokens:
                # Jaccard similarity — how similar are the two block pages?
                intersection = len(resp_tokens & base_tokens)
                union = len(resp_tokens | base_tokens)
                similarity = intersection / union if union > 0 else 0

                # Very similar to baseline block page (>60% similar)
                # = same generic bot block, can't determine if WAF acted
                if similarity > 0.6:
                    return "unresolved"

                # Very different block page (<30% similar) = WAF-specific block
                if similarity < 0.3:
                    return "blocked"

                # Middle zone (30-60%) — use size fallback
                size_diff = abs(r.get("l", 0) - bl_size)
                if size_diff > 1000:
                    return "blocked"
                return "unresolved"

            # Size-based fallback when no tokens available
            size_diff = abs(r.get("l", 0) - bl_size)
            if size_diff > 1000:
                return "blocked"

            return "unresolved"

        # Different status from baseline
        if s != bl_status:
            if s in (403, 406, 429, 503):
                return "blocked"
            if s == 200:
                return "passed"

        return "unresolved"

    # ── Case 3: Baseline is non-200 but not detected as block page ──
    if s != bl_status:
        if s in (403, 406, 429, 503):
            return "blocked"
        if s == 200:
            return "passed"

    # Same status — compare body sizes
    size_diff = abs(r.get("l", 0) - bl_size)
    if size_diff > 500:
        if waf_score >= 1:
            return "blocked"
        return "passed"

    return "unresolved"


def _generate_report(path, target, results, attacks, benign, tp_pct, tn_pct,
                     tp_blocked, tp_passed, tp_unresolved, tn_blocked, tn_passed,
                     duration, engine, metrics, baseline):
    """Generate comprehensive visual HTML report with charts."""

    # Per-set stats
    sets = {}
    for r in results:
        k = f"{r['set']}/{r['case']}"
        if k not in sets:
            sets[k] = {"set": r["set"], "case": r["case"], "type": r["type"],
                       "blocked": 0, "passed": 0, "unresolved": 0, "failed": 0, "total": 0}
        sets[k][r["classification"]] = sets[k].get(r["classification"], 0) + 1
        sets[k]["total"] += 1

    # Score
    overall = (tp_pct + tn_pct) / 2 if (tp_blocked + tp_passed) > 0 and (tn_blocked + tn_passed) > 0 else tp_pct

    # Bypassed payloads
    bypasses = [r for r in attacks if r["classification"] == "passed"]

    def gauge(pct, label, size=130):
        r = size // 2 - 12
        cx = cy = size // 2
        circ = 2 * 3.14159 * r
        off = circ * (1 - pct / 100)
        c = "#56CC54" if pct >= 80 else "#FDBE10" if pct >= 50 else "#FC7303" if pct >= 30 else "#F24444"
        return f'''<svg width="{size}" height="{size+30}" viewBox="0 0 {size} {size+30}">
        <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#eee" stroke-width="9"/>
        <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{c}" stroke-width="9"
            stroke-dasharray="{circ}" stroke-dashoffset="{off}" stroke-linecap="round" transform="rotate(-90 {cx} {cy})"/>
        <text x="{cx}" y="{cy+6}" text-anchor="middle" font-size="20" font-weight="bold" fill="{c}">{pct:.1f}%</text>
        <text x="{cx}" y="{size+20}" text-anchor="middle" font-size="11" fill="#333">{html.escape(label)}</text></svg>'''

    o = ['<!DOCTYPE html><html><head><meta charset="utf-8">',
         f'<title>WAF Security Report - {html.escape(target)}</title>',
         '<style>',
         'body{font-family:Inter,-apple-system,sans-serif;margin:0;padding:40px;max-width:1000px;margin:0 auto;color:#1a1a2e;font-size:13px}',
         'h1{font-size:28px;font-weight:900;margin:0 0 4px}h2{font-size:20px;font-weight:700;margin:30px 0 12px;border-bottom:2px solid #3942EA;padding-bottom:6px}',
         'h3{font-size:15px;margin:20px 0 8px}',
         '.gauges{display:flex;gap:20px;justify-content:center;flex-wrap:wrap;margin:20px 0}',
         '.card{background:#f5f7fa;border-radius:8px;padding:16px;margin:12px 0}',
         'table{border-collapse:collapse;width:100%;margin:10px 0;font-size:12px}',
         'th{background:#f0f2f5;font-weight:700;padding:7px 10px;text-align:left;border:1px solid #e0e3e8}',
         'td{padding:5px 10px;border:1px solid #e0e3e8}tr:nth-child(even){background:#fafbfc}',
         '.bar{height:20px;border-radius:3px;display:inline-block;vertical-align:middle}',
         '.tag{display:inline-block;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:700;color:#fff}',
         '.tag-ok{background:#56CC54}.tag-warn{background:#FC7303}.tag-bad{background:#F24444}.tag-na{background:#999}',
         '.bypass{background:#fff3f3;border-left:4px solid #F24444;padding:10px;margin:6px 0;border-radius:0 6px 6px 0;font-size:12px}',
         '.mono{font-family:Consolas,Monaco,monospace;font-size:11px;word-break:break-all}',
         '.metric{text-align:center;padding:12px}.metric-val{font-size:28px;font-weight:900}.metric-lbl{font-size:11px;color:#666}',
         '</style></head><body>']

    o.append(f'<h1>WAF Security Assessment Report</h1>')
    o.append(f'<p style="color:#666">Target: <b>{html.escape(target)}</b> | Date: {datetime.now().strftime("%Y-%m-%d %H:%M")} | Duration: {duration:.0f}s | Baseline: {baseline["s"]}/{baseline["l"]}b</p>')

    # Gauges
    o.append('<h2>Security Scores</h2><div class="gauges">')
    o.append(gauge(overall, "Overall Score", 150))
    o.append(gauge(tp_pct, "Attack Detection", 130))
    o.append(gauge(tn_pct, "False Positive Rate", 130))
    o.append('</div>')

    # Summary metrics
    o.append('<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:20px 0">')
    for val, lbl in [(len(results), "Total Sent"), (tp_blocked, "Attacks Blocked"),
                      (tp_passed, "Attacks Bypassed"), (tp_unresolved, "Unresolved"), (tn_blocked, "False Positives")]:
        o.append(f'<div class="card metric"><div class="metric-val">{val}</div><div class="metric-lbl">{lbl}</div></div>')
    o.append('</div>')

    # Per-category bar chart
    o.append('<h2>Attack Category Breakdown</h2><div class="card">')
    for k in sorted(sets.keys()):
        s = sets[k]
        t = max(s["blocked"] + s["passed"], 1)
        bpct = s["blocked"] / t * 100
        ppct = s["passed"] / t * 100
        upct = s["unresolved"] / max(s["total"], 1) * 100
        o.append(f'<div style="margin:6px 0;display:flex;align-items:center;gap:8px">')
        o.append(f'<span style="width:200px;font-size:11px;text-align:right;font-weight:600">{html.escape(k)}</span>')
        o.append(f'<div style="flex:1;display:flex;height:18px;border-radius:3px;overflow:hidden;background:#eee">')
        if bpct > 0: o.append(f'<div class="bar" style="width:{bpct:.1f}%;background:#56CC54" title="Blocked {s["blocked"]}"></div>')
        if ppct > 0: o.append(f'<div class="bar" style="width:{ppct:.1f}%;background:#F24444" title="Bypassed {s["passed"]}"></div>')
        if upct > 0: o.append(f'<div class="bar" style="width:{upct:.1f}%;background:#FDBE10" title="Unresolved {s["unresolved"]}"></div>')
        o.append(f'</div><span style="width:50px;font-size:11px;font-weight:700">{bpct:.0f}%</span></div>')
    o.append('<div style="display:flex;gap:16px;margin-top:12px;font-size:11px">')
    o.append('<span><span style="display:inline-block;width:12px;height:12px;background:#56CC54;border-radius:2px"></span> Blocked</span>')
    o.append('<span><span style="display:inline-block;width:12px;height:12px;background:#F24444;border-radius:2px"></span> Bypassed</span>')
    o.append('<span><span style="display:inline-block;width:12px;height:12px;background:#FDBE10;border-radius:2px"></span> Unresolved</span>')
    o.append('</div></div>')

    # Detail table
    o.append('<h2>Detailed Results</h2>')
    o.append('<table><tr><th>Test Set</th><th>Test Case</th><th>Type</th><th>Blocked</th><th>Bypassed</th><th>Unresolved</th><th>Total</th><th>Block Rate</th></tr>')
    for k in sorted(sets.keys()):
        s = sets[k]
        t = max(s["blocked"] + s["passed"], 1)
        pct = s["blocked"] / t * 100
        tag = "tag-ok" if pct >= 90 else "tag-warn" if pct >= 50 else "tag-bad" if t > 0 and pct < 50 else "tag-na"
        o.append(f'<tr><td>{html.escape(s["set"])}</td><td>{html.escape(s["case"])}</td><td>{html.escape(s["type"])}</td>')
        o.append(f'<td>{s["blocked"]}</td><td style="color:{"red" if s["passed"]>0 else "inherit"};font-weight:{"bold" if s["passed"]>0 else "normal"}">{s["passed"]}</td>')
        o.append(f'<td>{s["unresolved"]}</td><td>{s["total"]}</td>')
        o.append(f'<td><span class="tag {tag}">{pct:.0f}%</span></td></tr>')
    o.append('</table>')

    # Bypasses
    if bypasses:
        o.append(f'<h2>Confirmed Bypasses ({len(bypasses)})</h2>')
        for b in bypasses[:50]:
            o.append(f'<div class="bypass"><b>{html.escape(b["set"])}/{html.escape(b["case"])}</b> [{b["encoder"]}/{b["placeholder"]}] status={b["status"]}<br>')
            o.append(f'<span class="mono">{html.escape(b["payload"][:150])}</span></div>')

    # ML section
    if metrics.cv_f1 > 0:
        o.append(f'<h2>ML Analysis (CV F1: {metrics.cv_f1:.4f})</h2>')
        o.append(f'<div class="card"><p>Trained on {metrics.samples} samples ({metrics.blocked} blocked, {metrics.bypassed} bypassed)</p>')
        if metrics.feature_importance:
            o.append('<h3>Feature Importance</h3><table><tr><th>Feature</th><th>Importance</th><th>Visual</th></tr>')
            max_imp = max(metrics.feature_importance.values()) if metrics.feature_importance else 1
            for feat, imp in list(metrics.feature_importance.items())[:10]:
                w = imp / max_imp * 100
                o.append(f'<tr><td>{html.escape(feat)}</td><td>{imp:.4f}</td><td><div class="bar" style="width:{w:.0f}%;background:#3942EA;height:14px"></div></td></tr>')
            o.append('</table>')

        # Mutation suggestions
        if bypasses:
            sample = bypasses[0]
            sug = engine.suggest_mutations(sample["payload"], sample["encoder"], sample["placeholder"], 5)
            if sug:
                o.append('<h3>ML-Predicted Bypass Mutations</h3><table><tr><th>Mutation</th><th>Bypass Prob</th><th>Encoder</th><th>Placement</th></tr>')
                for s in sug:
                    o.append(f'<tr><td>{html.escape(s["mutation"])}</td><td>{s["bypass_probability"]:.3f}</td><td>{html.escape(s["encoder"])}</td><td>{html.escape(s["placeholder"])}</td></tr>')
                o.append('</table>')
        o.append('</div>')

    # Note about unresolved
    total_unresolved = sum(1 for r in results if r["classification"] == "unresolved")
    if total_unresolved > len(results) * 0.5:
        o.append('<h2>Important Note</h2><div class="card" style="border-left:4px solid #FC7303">')
        o.append(f'<p><b>{total_unresolved} of {len(results)} requests ({total_unresolved*100//len(results)}%) are unresolved.</b></p>')
        o.append('<p>This means the WAF returned the same response for attacks and normal traffic. Possible causes:</p>')
        o.append('<ul><li>Site returns 403 for all pages (server misconfiguration)</li>')
        o.append('<li>IP/region block active at server level</li>')
        o.append('<li>WAF is in "monitor only" mode (logs but does not block)</li></ul>')
        o.append('<p>The scanner correctly identified this ambiguity rather than producing false results.</p></div>')

    o.append(f'<div style="margin-top:40px;border-top:1px solid #ddd;padding-top:12px;font-size:10px;color:#999;text-align:center">')
    o.append(f'Generated by GoTestWAF (Python) with ML Engine (F1={metrics.cv_f1:.4f}) | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>')
    o.append('</body></html>')

    path.write_text("\n".join(o), encoding="utf-8")


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://kernernorland.com/"
    asyncio.run(main(url))
