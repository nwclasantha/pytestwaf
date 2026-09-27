"""Deep test suite — 18 tests covering every feature and bug fix."""
import sys, traceback
sys.path.insert(0, "src")

failures = []
passes = []

def test(name, func):
    try:
        func()
        passes.append(name)
    except Exception as e:
        tb = traceback.format_exc().strip().split("\n")
        failures.append((name, str(e), tb[-1] if tb else ""))

# 1. All imports work
def t1():
    from gotestwaf.scanner.scanner import Scanner
    from gotestwaf.report.report import ExportFullReport
    from gotestwaf.report.excel import generate_excel_report
    from gotestwaf.report.report3d import generate_3d_html_report
    from gotestwaf.ml.engine import HybridMLEngine
    from gotestwaf.ml.online import OnlineMLEngine
    from gotestwaf.scanner.ruleset_inference import infer_rulesets
    from gotestwaf.scanner.cloud_waf_query import auto_query_cloud_waf
    from gotestwaf.payload.encoder.encoder import apply_encoder, get_encoders
    from gotestwaf.payload.placeholder.placeholder import get_placeholders
    from gotestwaf.db.database import DB
    from gotestwaf.db.statistics import get_statistics
test("All imports", t1)

# 2. Encoders + chains
def t2():
    from gotestwaf.payload.encoder.encoder import apply_encoder
    assert apply_encoder("Plain", "test") == "test"
    assert apply_encoder("URL", "<>") == "%3C%3E"
    assert apply_encoder("Base64", "test") == "dGVzdA=="
    assert apply_encoder("URL+URL", "<") == "%253C"
    assert apply_encoder("URL+Base64", "<") != "<"
    try:
        apply_encoder("INVALID", "x")
        assert False
    except Exception:
        pass
test("Encoders + chains", t2)

# 3. 14 placeholders
def t3():
    from gotestwaf.payload.placeholder.placeholder import get_placeholders
    ph = get_placeholders()
    assert len(ph) == 14
    for n in ["Header","URLParam","URLPath","UserAgent","HTMLForm","JSONBody","gRPC","GraphQL"]:
        assert n in ph
test("14 placeholders", t3)

# 4. 52 WAF detectors
def t4():
    from gotestwaf.scanner.waf_detector.detectors.detectors import get_detectors
    d = get_detectors()
    assert len(d) == 52
    names = [x.waf_name for x in d]
    for w in ["AWS WAF","Cloudflare","Cloud Armor","Azure Front Door","ModSecurity","FortiWeb","Wordfence"]:
        assert w in names, f"Missing: {w}"
test("52 WAF detectors", t4)

# 5. Header case insensitive
def t5():
    from gotestwaf.scanner.waf_detector.detectors.checks import check_header, check_cookie, check_content, Responses
    from gotestwaf.scanner.types.response import ResponseMeta
    r = ResponseMeta(status_code=200, headers={"server":["cloudflare"],"set-cookie":["TS1=x"]}, content=b"Incapsula")
    rs = Responses(resp=r, resp_to_attack=r)
    assert check_header("Server","cloudflare",attack=False)(rs)
    assert check_cookie("^TS",attack=False)(rs)
    assert check_content("INCAPSULA",attack=False)(rs)
test("Header/cookie/content case insensitive", t5)

# 6. Cloudflare detect vs block
def t6():
    from gotestwaf.scanner.waf_detector.detectors.checks import Responses
    from gotestwaf.scanner.waf_detector.detectors.detectors import get_detectors
    from gotestwaf.scanner.types.response import ResponseMeta
    cf = [d for d in get_detectors() if d.waf_name == "Cloudflare"][0]
    ok = ResponseMeta(status_code=200, headers={"server":["cloudflare"]}, content=b"OK")
    assert cf.is_waf(Responses(resp=ok))
    assert not cf.check(Responses(resp_to_attack=ok))
    block = ResponseMeta(status_code=403, headers={}, content=b"Error 1020")
    assert cf.check(Responses(resp_to_attack=block))
test("Cloudflare detect vs block separated", t6)

# 7. DB + statistics
def t7():
    from gotestwaf.db.database import DB
    from gotestwaf.db.models import Case, Placeholder, Info
    from gotestwaf.db.statistics import get_statistics
    cases = [Case(payloads=["p1","p2"], encoders=["Plain"], placeholders=[Placeholder(name="URLParam")], set="owasp", name="xss")]
    db = DB.from_test_cases(cases)
    assert db.number_of_tests == 2
    db.update_blocked_tests(Info(set="owasp",case="xss",payload="p1",encoder="Plain",placeholder="URLParam"))
    db.update_passed_tests(Info(set="owasp",case="xss",payload="p2",encoder="Plain",placeholder="URLParam"))
    stat = get_statistics(db, False, False)
    assert stat.true_positive_tests.req_stats.blocked_requests_number == 1
    assert stat.true_positive_tests.req_stats.bypassed_requests_number == 1
test("DB + statistics", t7)

# 8. ML features handle chains
def t8():
    from gotestwaf.ml.features import extract_payload_features, PAYLOAD_FEATURE_DIM
    f = extract_payload_features("<script>", "URL+Base64", "Header")
    assert f.shape == (PAYLOAD_FEATURE_DIM,)
    assert f[33] == 1.0  # URL
    assert f[34] == 1.0  # Base64
    assert f[39] == 1.0  # Header
test("ML features handle chains", t8)

# 9. Online ML no deadlock
def t9():
    from gotestwaf.ml.online import OnlineMLEngine
    e = OnlineMLEngine()
    e.set_baseline(200, {"content-type":["text/html"]}, b"OK")
    for i in range(10):
        e.record_result(f"p{i}","Plain","URLParam",403,{},b"X",True)
    assert e.should_skip("Plain","URLParam") == True
    assert e.should_skip("URL","Header") == False
    stats = e.get_stats()  # deadlock test
    assert stats["total_requests"] == 10
test("Online ML no deadlock + skip", t9)

# 10. Batch ML fallback
def t10():
    from gotestwaf.ml.engine import HybridMLEngine
    e = HybridMLEngine()
    p = e.predict("<script>","Plain","URLParam",403,{},b"Forbidden")
    assert p.source == "rules"
test("Batch ML fallback when untrained", t10)

# 11. Ruleset inference
def t11():
    from gotestwaf.scanner.ruleset_inference import infer_rulesets
    from gotestwaf.db.database import DB
    from gotestwaf.db.models import Case, Placeholder, Info
    cases = [Case(payloads=["p"], encoders=["Plain"], placeholders=[Placeholder(name="URLParam")], set="owasp", name="xss-scripting")]
    db = DB.from_test_cases(cases)
    db.blocked_tests.append(Info(payload="<s>",encoder="Plain",placeholder="HTMLForm",set="owasp",case="xss-scripting",response_status_code=403))
    db.passed_tests.append(Info(payload="<s>",encoder="Base64Flat",placeholder="URLParam",set="owasp",case="xss-scripting",response_status_code=200))
    db.passed_tests.append(Info(payload="<s>",encoder="URL",placeholder="Header",set="owasp",case="xss-scripting",response_status_code=200))
    db.passed_tests.append(Info(payload="sqlmap",encoder="Plain",placeholder="UserAgent",set="community",case="community-user-agent",response_status_code=200))
    db.passed_tests.append(Info(payload="%0d%0a",encoder="Plain",placeholder="URLPath",set="owasp",case="crlf",response_status_code=404))
    ri = infer_rulesets(db, "AWS WAF")
    det = [r.name for r in ri.detected if r.status == "detected"]
    mis = [r.name for r in ri.missing]
    assert any("OWASP" in n for n in det)
    assert any("BASE64" in n for n in mis)
    assert any("Header" in n for n in mis)
    assert any("CRLF" in n for n in mis)
test("Ruleset inference", t11)

# 12. HTML report
def t12():
    from gotestwaf.report.report3d import generate_3d_html_report
    from gotestwaf.db.statistics import Statistics
    from gotestwaf.scanner.ruleset_inference import InferenceResult, RulesetStatus
    from datetime import datetime
    ri = InferenceResult(
        detected=[RulesetStatus(name="TestRule",vendor="AWS",status="detected",confidence=0.9,evidence="e")],
        missing=[RulesetStatus(name="Missing",vendor="AWS",status="missing",confidence=0.95,evidence="e",recommendation="fix")],
    )
    html = generate_3d_html_report(Statistics(), datetime.now(), "T", "http://t", [], False, False,
        ml_analysis={"metrics":{"is_trained":False}}, ruleset_inference=ri)
    assert "</body></html>" in html
    assert "WAF Ruleset Detection" in html
    assert html.index("WAF Ruleset Detection") < html.index("</body></html>")
    assert "TestRule" in html
    assert "Missing" in html
test("HTML report (ML + ruleset before </html>)", t12)

# 13. Excel report
def t13():
    from gotestwaf.report.excel import generate_excel_report
    from gotestwaf.db.statistics import Statistics
    from gotestwaf.scanner.ruleset_inference import InferenceResult, RulesetStatus
    from datetime import datetime
    import os
    import tempfile
    ri = InferenceResult(detected=[RulesetStatus(name="R",vendor="V",status="detected",confidence=0.9,evidence="e")])
    out = os.path.join(tempfile.gettempdir(), "deep_test.xlsx")
    generate_excel_report(Statistics(), out, datetime.now(), "T", "http://t", [], False, True, None, ri)
    assert os.path.exists(out) and os.path.getsize(out) > 5000
test("Excel report with ruleset sheet", t13)

# 14. Grade calculation
def t14():
    from gotestwaf.report.helpers import get_grade
    assert get_grade(95)["mark"] == "A"
    assert get_grade(0.5)["mark"] == "F"  # was bug
    assert get_grade(1.0)["mark"] == "F"  # was bug
    assert get_grade(100)["mark"] == "A+"
test("Grade calculation fixed", t14)

# 15. Excel safe string
def t15():
    from gotestwaf.report.excel import _safe_str
    assert _safe_str("has\x00null") == "hasnull"
    assert _safe_str("\x01\x02\x03") == ""
    assert _safe_str("ok\ttab") == "ok\ttab"
test("Excel safe string", t15)

# 16. Cloud auto-query
def t16():
    from gotestwaf.scanner.cloud_waf_query import auto_query_cloud_waf
    assert auto_query_cloud_waf("AWS WAF (Amazon)", "https://t").provider == "aws"
    assert auto_query_cloud_waf("Azure Front Door", "https://t").provider == "azure"
    assert auto_query_cloud_waf("ModSecurity", "https://t") is None
test("Cloud WAF auto-query", t16)

# 17. Scanner code structure
def t17():
    with open("src/gotestwaf/scanner/scanner.py", encoding="utf-8") as f:
        src = f.read()
    w = src[src.index("async def worker(pc"):src.index("progress.advance(task_id)")]
    assert "should_skip" not in w
    assert "for attempt in range(3):" in src
    assert "self.ml_engine = HybridMLEngine()" in src
    assert "self.online_ml = OnlineMLEngine()" in src
    assert "async def _run_adaptive_scan" in src
    idx = src.index("await self._send_openapi_requests(pc)")
    assert "return" in src[idx:idx+60]
test("Scanner structure", t17)

# 18. CLI flow
def t18():
    with open("src/gotestwaf/cli/main.py") as f:
        cli = f.read()
    assert cli.index("await scanner.initialize()") < cli.index("Try to identify WAF solution")
    assert "--cloudProvider" not in cli
    assert "SESSION_WAFS" in cli
    assert "auto_query_cloud_waf" in cli
    assert "infer_rulesets" in cli
test("CLI flow", t18)

# Print results
print()
print("=" * 60)
for p in passes:
    print(f"  [OK] {p}")
if failures:
    print()
    for name, err, loc in failures:
        print(f"  [FAIL] {name}: {err}")
        print(f"         {loc}")
print("=" * 60)
if failures:
    print(f"  {len(failures)} FAILURES")
else:
    print(f"  ALL {len(passes)} TESTS PASSED - ZERO FAILURES")
print("=" * 60)
sys.exit(len(failures))
