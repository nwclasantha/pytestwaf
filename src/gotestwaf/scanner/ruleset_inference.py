"""WAF Ruleset Inference Engine.

Analyzes scan block/bypass patterns to infer which WAF rulesets and
configurations are active vs missing. Works for AWS WAF, Azure WAF,
Cloudflare, ModSecurity, and generic WAFs.

Logic:
- If basic XSS in body blocked but Base64 XSS bypassed -> has XSS rules, missing BASE64_DECODE
- If SQLi in query blocked but SQLi in header bypassed -> has SQLi rules, missing header inspection
- If Log4Shell JNDI bypassed -> missing KnownBadInputs
- If scanner UA bypassed -> missing Bot Control
- If CRLF bypassed but other attacks blocked -> missing CRLF rule
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gotestwaf.db.database import DB


@dataclass
class RulesetStatus:
    """Status of a single ruleset or configuration."""
    name: str = ""
    vendor: str = ""
    status: str = "unknown"  # "detected", "missing", "partial", "cannot_verify"
    confidence: float = 0.0  # 0.0 - 1.0
    evidence: str = ""
    recommendation: str = ""
    category: str = ""  # "ruleset", "transform", "config"


@dataclass
class InferenceResult:
    """Complete ruleset inference result."""
    detected: list[RulesetStatus] = field(default_factory=list)
    missing: list[RulesetStatus] = field(default_factory=list)
    partial: list[RulesetStatus] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    waf_name: str = ""


def infer_rulesets(db: DB, waf_name: str = "") -> InferenceResult:
    """Analyze scan results to infer which WAF rulesets are active.

    Args:
        db: The scan results database.
        waf_name: Detected WAF name (e.g., "AWS WAF", "Cloudflare").

    Returns:
        InferenceResult with detected, missing, and partial rulesets.
    """
    result = InferenceResult(waf_name=waf_name)

    # Build lookup: which test categories were blocked vs bypassed
    blocked_cases: dict[str, set[str]] = {}  # case -> set of encoders that were blocked
    bypassed_cases: dict[str, set[str]] = {}  # case -> set of encoders that bypassed
    blocked_placeholders: dict[str, set[str]] = {}  # case -> set of placeholders blocked
    bypassed_placeholders: dict[str, set[str]] = {}  # case -> set of placeholders bypassed

    for t in db.blocked_tests:
        blocked_cases.setdefault(t.case, set()).add(t.encoder)
        blocked_placeholders.setdefault(t.case, set()).add(t.placeholder)

    for t in db.passed_tests:
        bypassed_cases.setdefault(t.case, set()).add(t.encoder)
        bypassed_placeholders.setdefault(t.case, set()).add(t.placeholder)

    # Also count unresolved as bypassed for inference
    for t in db.na_tests:
        bypassed_cases.setdefault(t.case, set()).add(t.encoder)
        bypassed_placeholders.setdefault(t.case, set()).add(t.placeholder)

    # Helper: check if a category is blocked with some encoder but bypassed with another
    def has_block(case: str) -> bool:
        return case in blocked_cases and len(blocked_cases[case]) > 0

    def has_bypass(case: str) -> bool:
        return case in bypassed_cases and len(bypassed_cases[case]) > 0

    def bypassed_encoders(case: str) -> set[str]:
        return bypassed_cases.get(case, set())

    def bypassed_placements(case: str) -> set[str]:
        return bypassed_placeholders.get(case, set())

    def all_bypassed(case: str) -> bool:
        return has_bypass(case) and not has_block(case)

    def all_blocked(case: str) -> bool:
        return has_block(case) and not has_bypass(case)

    # ═══ INFERENCE RULES ═══

    # 1. XSS/SQLi basic rules (Fortinet OWASP Top 10 or Common Rule Set)
    xss_cases = ["xss-scripting", "community-xss"]
    sqli_cases = ["sql-injection", "community-sqli"]
    any_xss_blocked = any(has_block(c) for c in xss_cases)
    any_sqli_blocked = any(has_block(c) for c in sqli_cases)

    if any_xss_blocked or any_sqli_blocked:
        result.detected.append(RulesetStatus(
            name="OWASP Top 10 Protection (XSS/SQLi)",
            vendor="Fortinet or AWS Common",
            status="detected",
            confidence=0.9,
            evidence=f"Basic XSS {'blocked' if any_xss_blocked else 'not tested'}, "
                     f"basic SQLi {'blocked' if any_sqli_blocked else 'not tested'} in body/query",
            category="ruleset",
        ))
    else:
        result.missing.append(RulesetStatus(
            name="OWASP Top 10 Protection (XSS/SQLi)",
            vendor="Fortinet or AWS Common",
            status="missing",
            confidence=0.85,
            evidence="Neither XSS nor SQLi blocked in any form",
            recommendation="Add AWSManagedRulesCommonRuleSet or Fortinet OWASP Top 10",
            category="ruleset",
        ))

    # 2. BASE64_DECODE transformation
    base64_encoders = {"Base64", "Base64Flat"}
    base64_bypassed = False
    plain_blocked = False
    for case in xss_cases + sqli_cases + ["shell-injection", "nosql-injection"]:
        be = bypassed_encoders(case)
        if be & base64_encoders:
            base64_bypassed = True
        if has_block(case):
            bc = blocked_cases.get(case, set())
            if bc - base64_encoders:  # blocked with non-Base64 encoder
                plain_blocked = True

    if base64_bypassed and plain_blocked:
        result.missing.append(RulesetStatus(
            name="BASE64_DECODE Text Transformation",
            vendor="AWS WAF Configuration",
            status="missing",
            confidence=0.95,
            evidence="Payloads blocked in plain text but bypassed when Base64-encoded",
            recommendation="Enable BASE64_DECODE transformation on all rule groups",
            category="transform",
        ))
    elif not base64_bypassed and plain_blocked:
        result.detected.append(RulesetStatus(
            name="BASE64_DECODE Text Transformation",
            vendor="AWS WAF Configuration",
            status="detected",
            confidence=0.8,
            evidence="Base64-encoded payloads also blocked",
            category="transform",
        ))

    # 3. Header inspection
    header_placements = {"Header", "UserAgent"}
    header_bypassed = False
    body_blocked = False
    for case in xss_cases + sqli_cases + ["rce", "shell-injection"]:
        bp = bypassed_placements(case)
        if bp & header_placements:
            header_bypassed = True
        blp = blocked_placeholders.get(case, set())
        if blp - header_placements:  # blocked in non-header placement
            body_blocked = True

    if header_bypassed and body_blocked:
        result.missing.append(RulesetStatus(
            name="HTTP Header Inspection",
            vendor="AWS WAF Configuration",
            status="missing",
            confidence=0.95,
            evidence="Payloads blocked in body/query but bypassed in custom headers and User-Agent",
            recommendation="Create custom rule to inspect All Headers with attack signatures",
            category="config",
        ))
    elif not header_bypassed:
        result.detected.append(RulesetStatus(
            name="HTTP Header Inspection",
            vendor="AWS WAF Configuration",
            status="detected",
            confidence=0.75,
            evidence="Header-placed payloads also blocked",
            category="config",
        ))

    # 4. Known Bad Inputs (Log4Shell JNDI)
    ua_case = "community-user-agent"
    if all_bypassed(ua_case):
        # Check if any UA payload contains jndi
        jndi_bypassed = False
        for t in db.passed_tests:
            if t.case == ua_case and "jndi" in t.payload.lower():
                jndi_bypassed = True
                break
        for t in db.na_tests:
            if t.case == ua_case and "jndi" in t.payload.lower():
                jndi_bypassed = True
                break

        if jndi_bypassed:
            result.missing.append(RulesetStatus(
                name="AWSManagedRulesKnownBadInputsRuleSet",
                vendor="AWS Managed",
                status="missing",
                confidence=0.9,
                evidence="Log4Shell JNDI payload in User-Agent bypassed (HTTP 200)",
                recommendation="Add AWSManagedRulesKnownBadInputsRuleSet",
                category="ruleset",
            ))

    # 5. Bot Control (scanner UA detection)
    scanner_uas = ["sqlmap", "nuclei", "ffuf", "openvas", "nessus", "burp"]
    scanner_bypassed = False
    for t in list(db.passed_tests) + list(db.na_tests):
        if t.case == ua_case:
            pl = t.payload.lower()
            if any(s in pl for s in scanner_uas):
                scanner_bypassed = True
                break

    if scanner_bypassed:
        result.missing.append(RulesetStatus(
            name="AWSManagedRulesBotControlRuleSet",
            vendor="AWS Managed",
            status="missing",
            confidence=0.9,
            evidence=f"Security scanner User-Agent strings bypassed (sqlmap, nuclei, etc.)",
            recommendation="Add AWSManagedRulesBotControlRuleSet ($10/month)",
            category="ruleset",
        ))

    # 6. CRLF detection
    crlf_case = "crlf"
    if all_bypassed(crlf_case):
        result.missing.append(RulesetStatus(
            name="CRLF Injection Detection",
            vendor="Custom Rule Needed",
            status="missing",
            confidence=0.95,
            evidence="All CRLF injection payloads bypassed (0% block rate)",
            recommendation="Add custom regex rule for %0d%0a patterns",
            category="ruleset",
        ))
    elif all_blocked(crlf_case):
        result.detected.append(RulesetStatus(
            name="CRLF Injection Detection",
            vendor="Active Rule",
            status="detected",
            confidence=0.9,
            evidence="CRLF injection payloads blocked",
            category="ruleset",
        ))

    # 7. Linux/Unix RCE rules
    rce_cases = ["rce", "rce-urlparam", "rce-urlpath", "shell-injection"]
    rce_blocked = any(has_block(c) for c in rce_cases)
    rce_all_blocked = all(all_blocked(c) for c in rce_cases if c in blocked_cases or c in bypassed_cases)

    if rce_blocked and not rce_all_blocked:
        result.partial.append(RulesetStatus(
            name="AWSManagedRulesLinuxRuleSet + UnixRuleSet",
            vendor="AWS Managed",
            status="partial",
            confidence=0.7,
            evidence="Some RCE/shell payloads blocked, some bypassed — partial coverage",
            recommendation="Add AWSManagedRulesLinuxRuleSet and AWSManagedRulesUnixRuleSet for full coverage",
            category="ruleset",
        ))
    elif not rce_blocked:
        result.missing.append(RulesetStatus(
            name="AWSManagedRulesLinuxRuleSet + UnixRuleSet",
            vendor="AWS Managed",
            status="missing",
            confidence=0.8,
            evidence="RCE and shell injection payloads all bypassed",
            recommendation="Add AWSManagedRulesLinuxRuleSet and AWSManagedRulesUnixRuleSet",
            category="ruleset",
        ))

    # 8. SQLi specific rule set
    sqli_advanced_bypassed = False
    for t in list(db.passed_tests) + list(db.na_tests):
        if "sqli" in t.case or "sql" in t.case:
            pl = t.payload.lower()
            if "union" in pl or "select" in pl or "information_schema" in pl:
                sqli_advanced_bypassed = True
                break

    if sqli_advanced_bypassed:
        result.missing.append(RulesetStatus(
            name="AWSManagedRulesSQLiRuleSet",
            vendor="AWS Managed",
            status="missing",
            confidence=0.75,
            evidence="Advanced SQLi patterns (UNION SELECT, information_schema) bypassed",
            recommendation="Add AWSManagedRulesSQLiRuleSet for advanced SQLi detection",
            category="ruleset",
        ))

    # 9. URI path inspection
    urlpath_placement = "URLPath"
    path_bypassed = False
    path_blocked_other = False
    for case in rce_cases + ["path-traversal", "community-lfi"]:
        bp = bypassed_placements(case)
        if urlpath_placement in bp:
            path_bypassed = True
        blp = blocked_placeholders.get(case, set())
        if blp - {urlpath_placement}:
            path_blocked_other = True

    if path_bypassed and path_blocked_other:
        result.missing.append(RulesetStatus(
            name="URI Path Inspection",
            vendor="AWS WAF Configuration",
            status="missing",
            confidence=0.85,
            evidence="Payloads blocked in query/body but bypassed when placed in URL path",
            recommendation="Add custom rule inspecting URI path for attack patterns",
            category="config",
        ))

    # 10. IP Reputation (cannot verify from scan)
    result.detected.append(RulesetStatus(
        name="AWSManagedRulesAmazonIpReputationList",
        vendor="AWS Managed",
        status="cannot_verify",
        confidence=0.0,
        evidence="IP reputation rules cannot be verified from payload scan (they match by source IP, not content)",
        category="ruleset",
    ))
    result.detected.append(RulesetStatus(
        name="AWSManagedRulesAnonymousIpList",
        vendor="AWS Managed",
        status="cannot_verify",
        confidence=0.0,
        evidence="Anonymous IP rules cannot be verified from payload scan (they match by source IP, not content)",
        category="ruleset",
    ))

    # 11. URL_DECODE transformation
    url_encoded_bypass = False
    for case in xss_cases + sqli_cases:
        be = bypassed_encoders(case)
        if "URL" in be and has_block(case):
            # URL-encoded version bypassed but plain version blocked
            bc = blocked_cases.get(case, set())
            if "Plain" in bc or any(e not in ("URL",) for e in bc):
                url_encoded_bypass = True
                break

    if url_encoded_bypass:
        result.partial.append(RulesetStatus(
            name="URL_DECODE Text Transformation",
            vendor="AWS WAF Configuration",
            status="partial",
            confidence=0.7,
            evidence="Some URL-encoded payloads bypassed — URL decode may not be applied to all rules",
            recommendation="Ensure URL_DECODE transformation is set on all rule groups",
            category="transform",
        ))

    # Build recommendations summary
    for rs in result.missing:
        if rs.recommendation:
            result.recommendations.append(f"[MISSING] {rs.name}: {rs.recommendation}")
    for rs in result.partial:
        if rs.recommendation:
            result.recommendations.append(f"[PARTIAL] {rs.name}: {rs.recommendation}")

    return result
