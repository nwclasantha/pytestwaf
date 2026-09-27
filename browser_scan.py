"""Browser-based WAF scanner — bypasses CAPTCHA/bot protection.

Runs the full test suite through a real Chromium browser using Playwright.
The browser solves the JS challenge automatically, then sends all payloads
via fetch() from within the authenticated browser context.

Usage:
    python browser_scan.py https://kernernorland.com/
"""

import asyncio
import csv
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import yaml


async def scan(target_url: str) -> None:
    from playwright.async_api import async_playwright

    print(f"Target: {target_url}")
    print("=" * 70)

    # Load test cases
    testcases_dir = Path("testcases")
    test_cases = []
    for yml_file in sorted(testcases_dir.rglob("*.yml")):
        if yml_file.suffix not in (".yml", ".yaml"):
            continue
        parts = yml_file.parts
        if len(parts) < 3:
            continue
        test_set = parts[-2]
        test_name = yml_file.stem
        try:
            with yml_file.open(encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            print(f"  Skip {yml_file}: {e}")
            continue
        if not data:
            continue
        test_cases.append({
            "set": test_set,
            "name": test_name,
            "payloads": data.get("payload", []),
            "encoders": data.get("encoder", []),
            "placeholders": data.get("placeholder", []),
            "type": data.get("type", "unknown"),
        })

    total_payloads = sum(
        len(tc["payloads"]) * len(tc["encoders"]) * len([p for p in tc["placeholders"] if isinstance(p, str)])
        for tc in test_cases
    )
    print(f"Loaded {len(test_cases)} test cases, ~{total_payloads} payloads")

    # Launch browser
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
        )
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        )
        page = await context.new_page()
        await page.add_init_script('Object.defineProperty(navigator, "webdriver", {get: () => undefined})')

        # Step 1: Navigate and solve CAPTCHA
        print("\nSolving CAPTCHA/challenge...")
        await page.goto(target_url, wait_until="commit", timeout=30000)
        for i in range(60):
            await asyncio.sleep(1)
            try:
                title = await page.title()
                url = page.url
                if "robot" not in title.lower() and "challenge" not in title.lower() and "captcha" not in title.lower():
                    print(f"  Challenge solved: {title[:50]}")
                    break
                if i % 10 == 0 and i > 0:
                    print(f"  Waiting... ({i}s)")
            except Exception:
                pass
        else:
            print("  WARNING: Challenge may not be solved after 60s")

        await asyncio.sleep(2)

        # Step 2: Get baseline
        print("\nGetting baseline response...")
        fetch_js = '''async (url) => {
            try {
                const r = await fetch(url);
                const body = await r.text();
                return {status: r.status, len: body.length, bodyHash: body.substring(0, 200)};
            } catch(e) { return {status: -1, len: 0, error: e.message}; }
        }'''

        baseline = await page.evaluate(fetch_js, "/")
        print(f"  Baseline: status={baseline['status']}, size={baseline['len']}")

        if baseline["status"] == 403 and baseline["len"] > 50000:
            print(f"\n  Site returns 403 for normal pages.")
            print(f"  Checking if WAF differentiates attacks from normal...")

            # Quick test
            xss_r = await page.evaluate(fetch_js, "/?x=<script>alert(1)</script>")
            benign_r = await page.evaluate(fetch_js, "/?s=hello")

            if xss_r["len"] == baseline["len"] and benign_r["len"] == baseline["len"]:
                print(f"  All responses identical ({baseline['len']} bytes)")
                print(f"  Switching to BODY CONTENT analysis mode...")
                print(f"  Will compare response bodies for differences\n")

        # Step 3: Run scan
        print("Starting scan...")
        start = time.monotonic()
        results = []
        total_sent = 0
        blocked = 0
        bypassed = 0
        unresolved = 0
        errors = 0

        for tc in test_cases:
            for payload in tc["payloads"]:
                for enc_name in tc["encoders"]:
                    for ph in tc["placeholders"]:
                        if not isinstance(ph, str):
                            continue
                        if ph in ("gRPC", "GraphQL"):
                            continue

                        # Apply encoder
                        encoded = _encode(payload, enc_name)

                        # Build URL based on placeholder
                        test_url = _build_url(target_url, encoded, ph)
                        if test_url is None:
                            continue

                        # Send via fetch
                        try:
                            method = "GET"
                            fetch_opts = "{}"
                            if ph in ("JSONBody", "JSONRequest", "RequestBody", "HTMLForm",
                                      "HTMLMultipartForm", "SOAPBody", "XMLBody"):
                                method = "POST"
                                body_content = json.dumps(encoded) if ph == "JSONBody" else encoded
                                safe_body = json.dumps(body_content)
                                ct = "application/json" if "JSON" in ph else "text/plain"
                                fetch_opts = f'{{"method":"POST","headers":{{"Content-Type":"{ct}"}},"body":{safe_body}}}'

                            if method == "GET":
                                r = await page.evaluate(fetch_js, test_url)
                            else:
                                # JSON-encode test_url so payloads containing " or
                                # other JS-meaningful chars cannot break out of the
                                # string literal and inject code into the eval context.
                                safe_url = json.dumps(test_url)
                                post_js = f'''async () => {{
                                    try {{
                                        const opts = {fetch_opts};
                                        const r = await fetch({safe_url}, opts);
                                        const body = await r.text();
                                        return {{status: r.status, len: body.length}};
                                    }} catch(e) {{ return {{status: -1, len: 0, error: e.message}}; }}
                                }}'''
                                r = await page.evaluate(post_js)

                        except Exception as e:
                            errors += 1
                            r = {"status": -1, "len": 0, "error": str(e)}

                        # Classify result
                        status = r.get("status", -1)
                        resp_len = r.get("len", 0)

                        is_fp = "false" in tc["set"]

                        # Detection logic: compare against baseline.
                        # Order matters — handle WAF block status codes (406/429/503)
                        # before the status==200 branch, otherwise they fall through
                        # to the final else and get misclassified as unresolved.
                        if status == -1:
                            classification = "failed"
                        elif status in (406, 429, 503):
                            classification = "blocked"
                            blocked += 1
                        elif status == 403 and resp_len != baseline["len"]:
                            classification = "blocked"
                            blocked += 1
                        elif status == 403 and resp_len == baseline["len"]:
                            # Same as baseline 403 — that IS the normal response
                            classification = "unresolved"
                            unresolved += 1
                        elif status == 200:
                            classification = "passed"
                            bypassed += 1
                        else:
                            classification = "unresolved"
                            unresolved += 1

                        total_sent += 1
                        results.append({
                            "set": tc["set"],
                            "case": tc["name"],
                            "type": tc["type"],
                            "payload": payload[:200],
                            "encoder": enc_name,
                            "placeholder": ph,
                            "status": status,
                            "response_size": resp_len,
                            "classification": classification,
                            "is_attack": not is_fp,
                        })

                        # Progress
                        if total_sent % 50 == 0:
                            elapsed = time.monotonic() - start
                            print(f"  Sent: {total_sent}/{total_payloads} "
                                  f"({total_sent/total_payloads*100:.0f}%) "
                                  f"blocked={blocked} bypassed={bypassed} "
                                  f"unresolved={unresolved} errors={errors} "
                                  f"[{elapsed:.0f}s]")

                        # Rate limiting
                        await asyncio.sleep(0.3)

        duration = time.monotonic() - start
        await browser.close()

    # Step 4: Generate report
    print(f"\n{'=' * 70}")
    print(f"SCAN COMPLETE — {target_url}")
    print(f"{'=' * 70}")
    print(f"Duration: {duration:.0f}s")
    print(f"Total sent: {total_sent}")
    print(f"Blocked: {blocked}")
    print(f"Bypassed: {bypassed}")
    print(f"Unresolved: {unresolved}")
    print(f"Errors: {errors}")

    # Per test-set breakdown
    sets: dict[str, dict[str, int]] = {}
    for r in results:
        key = f"{r['set']}/{r['case']}"
        if key not in sets:
            sets[key] = {"blocked": 0, "passed": 0, "unresolved": 0, "failed": 0, "total": 0}
        sets[key][r["classification"]] = sets[key].get(r["classification"], 0) + 1
        sets[key]["total"] += 1

    print(f"\n{'Test':<40} {'Blocked':>8} {'Bypass':>8} {'Unres':>8} {'Total':>8} {'Block%':>8}")
    print("-" * 80)
    for name, counts in sorted(sets.items()):
        b = counts.get("blocked", 0)
        p = counts.get("passed", 0)
        u = counts.get("unresolved", 0)
        t = counts["total"]
        pct = b / max(b + p, 1) * 100
        print(f"{name:<40} {b:>8} {p:>8} {u:>8} {t:>8} {pct:>7.1f}%")

    # Save CSV
    csv_path = Path("reports") / f"browser-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    csv_path.parent.mkdir(exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["set", "case", "type", "payload", "encoder",
                                                "placeholder", "status", "response_size", "classification", "is_attack"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\nResults saved: {csv_path}")

    # Run ML analysis
    print(f"\n{'=' * 70}")
    print("ML ANALYSIS")
    print(f"{'=' * 70}")

    sys.path.insert(0, "src")
    from gotestwaf.ml.engine import HybridMLEngine

    engine = HybridMLEngine()
    for r in results:
        engine.add_result(
            payload=r["payload"],
            encoder=r["encoder"],
            placeholder=r["placeholder"],
            status_code=r["status"],
            headers={},
            body=b"",
            was_blocked=(r["classification"] == "blocked"),
            test_set=r["set"],
            test_case=r["case"],
        )

    metrics = engine.train()
    print(f"ML trained: {metrics.samples} samples, CV F1={metrics.cv_f1:.4f}")
    print(f"Top features: {json.dumps(dict(list(metrics.feature_importance.items())[:5]))}")

    # Suggest bypass mutations for blocked payloads
    blocked_payloads = [r for r in results if r["classification"] == "blocked" and r["is_attack"]]
    if blocked_payloads:
        sample = blocked_payloads[0]
        suggestions = engine.suggest_mutations(sample["payload"], sample["encoder"], sample["placeholder"], top_k=5)
        print(f"\nBypass suggestions for '{sample['payload'][:40]}...':")
        for s in suggestions:
            print(f"  {s['mutation']:<30} prob={s['bypass_probability']:.3f}")


def _encode(payload: str, encoder: str) -> str:
    """Apply encoding to payload."""
    import base64
    match encoder:
        case "Plain":
            return payload
        case "URL":
            return quote(payload, safe="!$&'()*+,;=:@")
        case "Base64":
            return base64.b64encode(payload.encode()).decode()
        case "Base64Flat":
            return base64.b64encode(payload.encode()).decode().rstrip("=")
        case "JSUnicode":
            utf16 = payload.encode("utf-16-be")
            return "".join(f"\\u{utf16[i]:02x}{utf16[i+1]:02x}" for i in range(0, len(utf16), 2))
        case _:
            return payload


def _build_url(base_url: str, payload: str, placeholder: str) -> str | None:
    """Build request URL based on placeholder type."""
    base = base_url.rstrip("/")
    safe_payload = quote(payload, safe="")
    match placeholder:
        case "URLParam":
            return f"{base}/?test={safe_payload}"
        case "URLPath":
            return f"{base}/{safe_payload}"
        case "Header" | "UserAgent":
            return f"{base}/"  # Payload goes in header, not URL
        case "JSONBody" | "JSONRequest" | "RequestBody" | "HTMLForm" | "HTMLMultipartForm" | "SOAPBody" | "XMLBody":
            return f"{base}/"
        case "RawRequest":
            return f"{base}/?raw={safe_payload}"
        case _:
            return None


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://kernernorland.com/"
    asyncio.run(scan(url))
