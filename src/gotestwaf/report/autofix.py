"""Auto-fix generation — produces actual WAF configuration to fix bypasses.

Generates ready-to-apply configs for:
- AWS WAF (JSON for aws wafv2 update-web-acl)
- Cloudflare (API JSON)
- ModSecurity (SecRule directives)
- Generic (text recommendations)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gotestwaf.scanner.ruleset_inference import InferenceResult


def generate_autofix(
    waf_name: str,
    inference: InferenceResult | None,
    bypassed_categories: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate auto-fix configurations based on scan results.

    Returns dict with:
        - fixes: list of fix objects with config snippets (primary WAF)
        - multi_cloud: parallel AWS / Azure / GCP recommendations so the
          user can pick the relevant cloud-vendor config regardless of
          which WAF was actually identified during the scan
        - summary: overall fix summary
        - configs: ready-to-apply config files
    """
    waf_lower = waf_name.lower()

    # Always-on multi-cloud companion. Detection identifies a single WAF
    # but real deployments often live behind any of AWS / Azure / GCP, so
    # researchers / SREs need the equivalent recommendation for whichever
    # cloud they actually run on.
    multi_cloud = {
        "aws":   _generate_aws_fixes(inference, bypassed_categories),
        "azure": _generate_azure_fixes(inference, bypassed_categories),
        "gcp":   _generate_gcp_fixes(inference, bypassed_categories),
    }

    if "aws" in waf_lower or "cloudfront" in waf_lower or "amazon" in waf_lower:
        primary = _generate_aws_fixes(inference, bypassed_categories)
        primary["multi_cloud"] = multi_cloud
        return primary
    elif "azure" in waf_lower or "microsoft" in waf_lower or "front door" in waf_lower:
        primary = _generate_azure_fixes(inference, bypassed_categories)
        primary["multi_cloud"] = multi_cloud
        return primary
    elif "cloud armor" in waf_lower or "google" in waf_lower or "gcp" in waf_lower:
        primary = _generate_gcp_fixes(inference, bypassed_categories)
        primary["multi_cloud"] = multi_cloud
        return primary
    elif "cloudflare" in waf_lower:
        primary = _generate_cloudflare_fixes(inference, bypassed_categories)
    elif "f5" in waf_lower or "big-ip" in waf_lower or "bigip" in waf_lower or "trafficshield" in waf_lower or "firepass" in waf_lower:
        primary = _generate_f5_fixes(inference, bypassed_categories)
    elif "fortinet" in waf_lower or "fortiweb" in waf_lower or "fortigate" in waf_lower:
        primary = _generate_fortinet_fixes(inference, bypassed_categories)
    elif "imperva" in waf_lower or "incapsula" in waf_lower or "securesphere" in waf_lower:
        primary = _generate_imperva_fixes(inference, bypassed_categories)
    elif "akamai" in waf_lower or "kona" in waf_lower:
        primary = _generate_akamai_fixes(inference, bypassed_categories)
    elif "barracuda" in waf_lower:
        primary = _generate_barracuda_fixes(inference, bypassed_categories)
    elif "citrix" in waf_lower or "netscaler" in waf_lower:
        primary = _generate_citrix_fixes(inference, bypassed_categories)
    elif "check point" in waf_lower or "cloudguard" in waf_lower:
        primary = _generate_checkpoint_fixes(inference, bypassed_categories)
    elif "palo alto" in waf_lower or "prisma" in waf_lower:
        primary = _generate_paloalto_fixes(inference, bypassed_categories)
    elif "modsecurity" in waf_lower or "modsec" in waf_lower or "naxsi" in waf_lower or "openresty" in waf_lower:
        primary = _generate_modsec_fixes(inference, bypassed_categories)
    elif "sucuri" in waf_lower:
        primary = _generate_sucuri_fixes(inference, bypassed_categories)
    elif "wordfence" in waf_lower or "wp cerber" in waf_lower:
        primary = _generate_wordpress_fixes(inference, bypassed_categories)
    elif "radware" in waf_lower or "appwall" in waf_lower:
        primary = _generate_radware_fixes(inference, bypassed_categories)
    elif "wallarm" in waf_lower:
        primary = _generate_wallarm_fixes(inference, bypassed_categories)
    elif "sophos" in waf_lower:
        primary = _generate_sophos_fixes(inference, bypassed_categories)
    elif "alibaba" in waf_lower:
        primary = _generate_alibaba_fixes(inference, bypassed_categories)
    elif "tencent" in waf_lower:
        primary = _generate_tencent_fixes(inference, bypassed_categories)
    elif "huawei" in waf_lower:
        primary = _generate_huawei_fixes(inference, bypassed_categories)
    else:
        primary = _generate_generic_fixes(inference, bypassed_categories)
    primary["multi_cloud"] = multi_cloud
    return primary


def _generate_aws_fixes(
    inference: InferenceResult | None,
    bypassed_categories: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate AWS WAF v2 JSON configs to fix bypasses."""

    fixes: list[dict[str, Any]] = []
    aws_rules: list[dict[str, Any]] = []

    # 1. Missing managed rule groups
    if inference:
        managed_rules_to_add = []
        for rs in inference.missing:
            if "AWSManaged" in rs.name or rs.vendor == "AWS Managed":
                rule_name = rs.name
                # Extract clean AWS rule group name
                if "KnownBad" in rule_name:
                    aws_name = "AWSManagedRulesKnownBadInputsRuleSet"
                elif "SQLi" in rule_name:
                    aws_name = "AWSManagedRulesSQLiRuleSet"
                elif "Linux" in rule_name:
                    aws_name = "AWSManagedRulesLinuxRuleSet"
                elif "Unix" in rule_name:
                    aws_name = "AWSManagedRulesUnixRuleSet"
                elif "Bot" in rule_name:
                    aws_name = "AWSManagedRulesBotControlRuleSet"
                elif "Common" in rule_name:
                    aws_name = "AWSManagedRulesCommonRuleSet"
                else:
                    continue

                managed_rules_to_add.append(aws_name)
                aws_rule = {
                    "Name": aws_name.replace("AWSManagedRules", "").replace("RuleSet", ""),
                    "Priority": len(aws_rules) + 10,
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": aws_name,
                        }
                    },
                    "OverrideAction": {"None": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": aws_name.replace("AWSManagedRules", ""),
                    },
                }
                aws_rules.append(aws_rule)
                fixes.append({
                    "type": "add_managed_rule",
                    "name": aws_name,
                    "priority": "HIGH",
                    "description": f"Add {aws_name} managed rule group",
                    "evidence": rs.evidence,
                    "config": json.dumps(aws_rule, indent=2),
                })

    # 2. BASE64_DECODE transformation
    if inference:
        for rs in inference.missing:
            if "BASE64" in rs.name:
                transform_config = {
                    "TextTransformations": [
                        {"Priority": 0, "Type": "BASE64_DECODE"},
                        {"Priority": 1, "Type": "URL_DECODE"},
                        {"Priority": 2, "Type": "HTML_ENTITY_DECODE"},
                        {"Priority": 3, "Type": "LOWERCASE"},
                    ]
                }
                fixes.append({
                    "type": "add_transformation",
                    "name": "BASE64_DECODE + URL_DECODE + HTML_ENTITY_DECODE + LOWERCASE",
                    "priority": "CRITICAL",
                    "description": "Add text transformation chain to ALL rule groups. Apply BASE64_DECODE first, then URL_DECODE, then HTML_ENTITY_DECODE, then LOWERCASE.",
                    "evidence": rs.evidence,
                    "config": json.dumps(transform_config, indent=2),
                    "apply_to": "ALL existing rule groups and custom rules",
                })
                break

    # 3. Custom header inspection rule
    if inference:
        for rs in inference.missing:
            if "Header" in rs.name:
                header_rule = {
                    "Name": "InspectAllHeaders",
                    "Priority": 1,
                    "Statement": {
                        "OrStatement": {
                            "Statements": [
                                {
                                    "ByteMatchStatement": {
                                        "FieldToMatch": {"Headers": {"MatchPattern": {"All": {}}, "MatchScope": "VALUE", "OversizeHandling": "MATCH"}},
                                        "PositionalConstraint": "CONTAINS",
                                        "SearchString": pattern,
                                        "TextTransformations": [
                                            {"Priority": 0, "Type": "BASE64_DECODE"},
                                            {"Priority": 1, "Type": "URL_DECODE"},
                                            {"Priority": 2, "Type": "LOWERCASE"},
                                        ],
                                    }
                                }
                                for pattern in ["<script", "alert(", "onerror=", "union select", "/etc/passwd", "${jndi:"]
                            ]
                        }
                    },
                    "Action": {"Block": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "InspectAllHeaders",
                    },
                }
                aws_rules.append(header_rule)
                fixes.append({
                    "type": "add_custom_rule",
                    "name": "Header Inspection Rule",
                    "priority": "CRITICAL",
                    "description": "Create custom rule to inspect ALL HTTP headers for attack patterns",
                    "evidence": rs.evidence,
                    "config": json.dumps(header_rule, indent=2),
                })
                break

    # 4. CRLF custom rule
    if inference:
        for rs in inference.missing:
            if "CRLF" in rs.name:
                crlf_rule = {
                    "Name": "BlockCRLFInjection",
                    "Priority": 2,
                    "Statement": {
                        "OrStatement": {
                            "Statements": [
                                {
                                    "RegexMatchStatement": {
                                        "FieldToMatch": {"UriPath": {}},
                                        "RegexString": "%0[dD]%0[aA]|%0[aA]%0[dD]|%25%30[aAdD]",
                                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                                    }
                                },
                                {
                                    "RegexMatchStatement": {
                                        "FieldToMatch": {"QueryString": {}},
                                        "RegexString": "%0[dD]%0[aA]|%0[aA]%0[dD]|%25%30[aAdD]",
                                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                                    }
                                },
                            ]
                        }
                    },
                    "Action": {"Block": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "BlockCRLFInjection",
                    },
                }
                aws_rules.append(crlf_rule)
                fixes.append({
                    "type": "add_custom_rule",
                    "name": "CRLF Injection Block",
                    "priority": "HIGH",
                    "description": "Create custom regex rule to block CRLF injection",
                    "evidence": rs.evidence,
                    "config": json.dumps(crlf_rule, indent=2),
                })
                break

    return {
        "waf_type": "AWS WAF",
        "fixes": fixes,
        "aws_rules": aws_rules,
        "summary": {
            "total_fixes": len(fixes),
            "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]),
            "high": len([f for f in fixes if f["priority"] == "HIGH"]),
        },
        "full_config": json.dumps({"Rules": aws_rules}, indent=2) if aws_rules else "",
    }


def _generate_cloudflare_fixes(
    inference: InferenceResult | None,
    bypassed_categories: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate Cloudflare WAF API configs."""
    fixes = _common_fixes(inference, "Cloudflare")

    fixes.append({
        "type": "enable_managed_ruleset",
        "name": "Cloudflare OWASP Core Ruleset",
        "priority": "HIGH",
        "description": "Enable Cloudflare Managed Ruleset with sensitivity set to HIGH",
        "config": json.dumps({
            "action": "execute",
            "action_parameters": {"id": "efb7b8c949ac4650a09736fc376e9aee"},
            "description": "Enable Cloudflare OWASP Core Ruleset",
        }, indent=2),
    })

    fixes.append({
        "type": "enable_bot_management",
        "name": "Bot Fight Mode",
        "priority": "MEDIUM",
        "description": "Enable Bot Fight Mode to block scanner tools",
        "config": "Dashboard: Security > Bots > Bot Fight Mode = ON",
    })

    return {"waf_type": "Cloudflare", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    AZURE WAF
# ═══════════════════════════════════════════════════════════════

def _generate_azure_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Azure WAF")
    fixes.append({"type": "enable_ruleset", "name": "Enable OWASP 3.2 Rule Set", "priority": "HIGH",
        "description": "Azure Portal > WAF Policy > Managed Rules > Add Rule Set > OWASP 3.2. Set mode to Prevention (not Detection).",
        "config": json.dumps({"ruleSetType": "OWASP", "ruleSetVersion": "3.2"}, indent=2)})
    fixes.append({"type": "enable_bot_manager", "name": "Enable Bot Manager Rule Set", "priority": "HIGH",
        "description": "WAF Policy > Managed Rules > Add > Microsoft_BotManagerRuleSet v1.0",
        "config": json.dumps({"ruleSetType": "Microsoft_BotManagerRuleSet", "ruleSetVersion": "1.0"}, indent=2)})
    fixes.append({"type": "custom_rule", "name": "Block Base64 Encoded Attacks", "priority": "CRITICAL",
        "description": "WAF Policy > Custom Rules > Add > Match: RequestBody + QueryString, Transform: Base64Decode + UrlDecode + Lowercase, Condition: Contains attack patterns, Action: Block",
        "config": json.dumps({"name": "BlockBase64Attacks", "priority": 1, "ruleType": "MatchRule", "action": "Block",
            "matchConditions": [{"matchVariable": "RequestBody", "operator": "Contains", "matchValue": ["<script", "union select", "/etc/passwd"],
                "transforms": ["Base64Decode", "UrlDecode", "Lowercase"]}]}, indent=2)})
    fixes.append({"type": "policy_setting", "name": "Set WAF Mode to Prevention", "priority": "CRITICAL",
        "description": "WAF Policy > Overview > Mode: Switch from Detection to Prevention. Detection mode only logs, does NOT block.",
        "config": 'az network front-door waf-policy update --name YOUR_POLICY --resource-group YOUR_RG --mode Prevention'})
    return {"waf_type": "Azure WAF", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    GCP CLOUD ARMOR
# ═══════════════════════════════════════════════════════════════

def _generate_gcp_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "GCP Cloud Armor")
    fixes.append({"type": "enable_preconfigured", "name": "Enable Pre-configured WAF Rules", "priority": "HIGH",
        "description": "Cloud Console > Network Security > Cloud Armor > Your Policy > Add Rule > Pre-configured WAF rules > Enable: sqli-v33-stable, xss-v33-stable, lfi-v33-stable, rce-v33-stable, rfi-v33-stable",
        "config": 'gcloud compute security-policies rules create 1000 --security-policy=YOUR_POLICY --expression="evaluatePreconfiguredExpr(\'sqli-v33-stable\',\'xss-v33-stable\',\'lfi-v33-stable\',\'rce-v33-stable\')" --action=deny-403'})
    fixes.append({"type": "enable_adaptive", "name": "Enable Adaptive Protection", "priority": "HIGH",
        "description": "Cloud Armor > Policy > Adaptive Protection > Enable. Detects and mitigates L7 DDoS and application attacks automatically.",
        "config": 'gcloud compute security-policies update YOUR_POLICY --enable-layer7-ddos-defense'})
    fixes.append({"type": "custom_rule", "name": "Block Base64 Encoded Payloads", "priority": "CRITICAL",
        "description": "Add custom rule with CEL expression to detect Base64-encoded attack patterns in request body and headers.",
        "config": 'gcloud compute security-policies rules create 900 --security-policy=YOUR_POLICY --expression="has(request.headers[\'user-agent\']) && request.headers[\'user-agent\'].matches(\'(?i)(sqlmap|nuclei|ffuf|nessus|nikto)\')" --action=deny-403'})
    return {"waf_type": "GCP Cloud Armor", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    F5 BIG-IP
# ═══════════════════════════════════════════════════════════════

def _generate_f5_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "F5 BIG-IP ASM")
    fixes.append({"type": "policy_setting", "name": "Enable Signature Staging → Enforcement", "priority": "CRITICAL",
        "description": "Security > Application Security > Policy > Signatures > Move all staged signatures to Enforcement mode. Staged signatures log but do NOT block.",
        "config": "tmsh modify asm policy /Common/YOUR_POLICY signatures all { enforcement-mode blocking }"})
    fixes.append({"type": "enable_encoding", "name": "Enable Content Decoding (Base64, URL, HTML)", "priority": "CRITICAL",
        "description": "Security > Application Security > Policy > Content Profiles > Add Decoding: Base64, URL, HTML Entity. Apply to all parameters.",
        "config": "tmsh modify asm policy /Common/YOUR_POLICY parameter-extraction { decode-base64 enabled url-decode enabled html-decode enabled }"})
    fixes.append({"type": "enable_header_check", "name": "Enable HTTP Header Inspection", "priority": "HIGH",
        "description": "Security > Application Security > Headers > Enable inspection for all custom headers and User-Agent.",
        "config": "tmsh modify asm policy /Common/YOUR_POLICY header-settings { check-all-headers enabled }"})
    fixes.append({"type": "attack_signatures", "name": "Update Attack Signature Database", "priority": "HIGH",
        "description": "System > Software Management > Attack Signature Update > Download and install latest signatures.",
        "config": "tmsh modify sys provision datasync-global-dg { enabled }"})
    return {"waf_type": "F5 BIG-IP ASM", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    FORTINET FORTIWEB
# ═══════════════════════════════════════════════════════════════

def _generate_fortinet_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Fortinet FortiWeb")
    fixes.append({"type": "policy_setting", "name": "Enable Signature-Based Detection for All Attack Types", "priority": "HIGH",
        "description": "FortiWeb > Web Protection > Signatures > Enable all OWASP Top 10 signature groups. Set action to Alert & Block (not just Alert).",
        "config": "config waf signature\n  set status enable\n  set action alert_deny\n  config main_class_list\n    edit 1\n      set status enable\n    next\n  end\nend"})
    fixes.append({"type": "enable_encoding", "name": "Enable Request Body Decoding (Base64, URL)", "priority": "CRITICAL",
        "description": "FortiWeb > Web Protection > Input Validation > Enable Base64 decode, URL decode, and HTML entity decode for all parameters.",
        "config": "config waf url-access\n  edit 1\n    set decode-base64 enable\n    set decode-url enable\n    set decode-html enable\n  next\nend"})
    fixes.append({"type": "enable_header_check", "name": "Enable HTTP Header Inspection", "priority": "CRITICAL",
        "description": "FortiWeb > Web Protection > Input Validation > HTTP Header Constraints > Enable inspection for custom headers and User-Agent.",
        "config": "config waf http-header-security\n  edit 1\n    set header-name-check enable\n    set header-value-check enable\n  next\nend"})
    fixes.append({"type": "bot_detection", "name": "Enable Bot Detection", "priority": "HIGH",
        "description": "FortiWeb > Bot Mitigation > Known Bots > Enable detection for scanner tools (sqlmap, Nuclei, ffuf).",
        "config": "config waf bot-detection\n  set status enable\n  set action alert_deny\nend"})
    return {"waf_type": "Fortinet FortiWeb", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    IMPERVA (INCAPSULA / SECURESPHERE)
# ═══════════════════════════════════════════════════════════════

def _generate_imperva_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Imperva WAF")
    fixes.append({"type": "policy_setting", "name": "Set Security Rule Action to Block (not Alert)", "priority": "CRITICAL",
        "description": "Imperva Console > Security > WAF Rules > For each rule: Change action from 'Alert Only' to 'Block'. Many rules default to alert-only after deployment.",
        "config": "Imperva API: POST /api/v1/sites/{site_id}/security/waf/rules/{rule_id} {\"action\": \"block\"}"})
    fixes.append({"type": "enable_encoding", "name": "Enable Content Encoding Normalization", "priority": "CRITICAL",
        "description": "Imperva Console > Security > WAF Settings > Advanced > Enable: Base64 Decoding, Double URL Decode, HTML Entity Decode.",
        "config": "Imperva API: POST /api/v1/sites/{site_id}/security/waf/settings {\"decode_base64\": true, \"double_url_decode\": true}"})
    fixes.append({"type": "enable_header_check", "name": "Enable Custom Header Inspection", "priority": "HIGH",
        "description": "Security > WAF > Advanced > Inspected Headers > Add: All custom headers (X-*) and User-Agent.",
        "config": "Imperva API: POST /api/v1/sites/{site_id}/security/waf/settings {\"inspect_custom_headers\": true}"})
    fixes.append({"type": "bot_detection", "name": "Enable Advanced Bot Protection", "priority": "HIGH",
        "description": "Security > Bot Mitigation > Enable Advanced Bot Protection. Block known scanner User-Agents.",
        "config": "Imperva Console: Security > Bot Mitigation > Protection Mode > Block"})
    return {"waf_type": "Imperva WAF", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    AKAMAI KONA
# ═══════════════════════════════════════════════════════════════

def _generate_akamai_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Akamai Kona SiteDefender")
    fixes.append({"type": "policy_setting", "name": "Move WAF Rules from Alert to Deny", "priority": "CRITICAL",
        "description": "Akamai Control Center > Security Configuration > WAF > For each Attack Group: Change from 'Alert' to 'Deny'. Many rules are deployed in alert-only mode.",
        "config": "Akamai API: PUT /appsec/v1/configs/{configId}/versions/{versionId}/security-policies/{policyId}/attack-groups/{group} {\"action\": \"deny\"}"})
    fixes.append({"type": "enable_encoding", "name": "Enable Advanced Request Body Inspection", "priority": "CRITICAL",
        "description": "Security Configuration > Advanced Settings > Request Body Inspection > Enable: Base64 Decode, JSON parse, XML parse.",
        "config": "Akamai Control Center: Security > Advanced > Inspection Settings > Enable All Decoders"})
    fixes.append({"type": "krs_upgrade", "name": "Upgrade to Kona Rule Set (KRS) v2023+", "priority": "HIGH",
        "description": "Ensure latest Kona Rule Set version is active. Older versions miss modern evasion techniques.",
        "config": "Akamai Control Center: Security Configuration > Rule Set > Upgrade to latest KRS version"})
    return {"waf_type": "Akamai Kona SiteDefender", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    BARRACUDA WAF
# ═══════════════════════════════════════════════════════════════

def _generate_barracuda_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Barracuda WAF")
    fixes.append({"type": "policy_setting", "name": "Set WAF Mode to Active (Blocking)", "priority": "CRITICAL",
        "description": "Barracuda Console > SECURITY POLICIES > Policy > Mode: Change from 'Passive' to 'Active'. Passive mode only logs.",
        "config": "Barracuda API: PUT /restapi/v3.2/security-policies/{policy} {\"mode\": \"active\"}"})
    fixes.append({"type": "enable_encoding", "name": "Enable Request Normalization", "priority": "CRITICAL",
        "description": "SECURITY POLICIES > Request Limits > Enable: URL Decoding, Base64 Decoding, Double Encoding Detection.",
        "config": "Barracuda Console: SECURITY POLICIES > Request Limits > Normalization > Enable All"})
    fixes.append({"type": "enable_header_check", "name": "Enable Header Filtering", "priority": "HIGH",
        "description": "SECURITY POLICIES > Cookie and Header Security > Enable header value inspection for all custom headers.",
        "config": "Barracuda Console: SECURITY POLICIES > Cookie and Header Security > Custom Header Filter > Enable"})
    return {"waf_type": "Barracuda WAF", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    CITRIX NETSCALER
# ═══════════════════════════════════════════════════════════════

def _generate_citrix_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Citrix NetScaler AppFirewall")
    fixes.append({"type": "policy_setting", "name": "Enable All Security Checks in Block Mode", "priority": "CRITICAL",
        "description": "NetScaler Console > AppFirewall > Profiles > Your Profile > Security Checks > For each check (SQLi, XSS, etc.): Set to Block (not Log).",
        "config": "set appfw profile YOUR_PROFILE -SQLInjectionAction block\nset appfw profile YOUR_PROFILE -crossSiteScriptingAction block\nset appfw profile YOUR_PROFILE -fieldFormatAction block"})
    fixes.append({"type": "enable_encoding", "name": "Enable Request Body Transformation", "priority": "CRITICAL",
        "description": "AppFirewall > Profile > Settings > Enable: checkRequestHeaders, optimizePartialReqs, streaming",
        "config": "set appfw profile YOUR_PROFILE -checkRequestHeaders ON\nset appfw profile YOUR_PROFILE -urlDecodeRequestCookies ON"})
    fixes.append({"type": "signatures", "name": "Update Signature Database", "priority": "HIGH",
        "description": "System > Signatures > Update > Download latest signatures from Citrix.",
        "config": "update appfw signatures"})
    return {"waf_type": "Citrix NetScaler AppFirewall", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    CHECK POINT CLOUDGUARD
# ═══════════════════════════════════════════════════════════════

def _generate_checkpoint_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Check Point CloudGuard")
    fixes.append({"type": "policy_setting", "name": "Set Web Protection to Prevent Mode", "priority": "CRITICAL",
        "description": "CloudGuard Console > Web Protection > Policy > Mode: Change from 'Detect' to 'Prevent'. Detect mode only logs, does not block.",
        "config": "SmartConsole: Threat Prevention > Web Protection > Mode > Prevent"})
    fixes.append({"type": "ips_update", "name": "Update IPS Signatures and Enable All Web Protections", "priority": "HIGH",
        "description": "SmartConsole > Threat Prevention > IPS > Update > Download latest. Enable all Web Intelligence categories.",
        "config": "SmartConsole: Threat Prevention > IPS Protections > Web Intelligence > Enable All > Action: Prevent"})
    return {"waf_type": "Check Point CloudGuard", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    PALO ALTO PRISMA
# ═══════════════════════════════════════════════════════════════

def _generate_paloalto_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Palo Alto Prisma Cloud WAAS")
    fixes.append({"type": "policy_setting", "name": "Set WAAS Rule Effect to Ban/Prevent", "priority": "CRITICAL",
        "description": "Prisma Console > Compute > Defend > WAAS > Your Rule > For each protection (SQLi, XSS, etc.): Set Effect to 'Prevent' or 'Ban'.",
        "config": "Prisma API: PUT /api/v1/policies/firewall/app/network-list {\"effect\": \"ban\", \"protection\": \"sqlInjection\"}"})
    fixes.append({"type": "enable_encoding", "name": "Enable Advanced Payload Inspection", "priority": "CRITICAL",
        "description": "WAAS > Rule > Advanced Settings > Enable: Body inspection, Header inspection, Base64 decode.",
        "config": "Prisma Console: WAAS > Rule > Advanced > Inspection Depth > Full Body + Headers"})
    fixes.append({"type": "bot_protection", "name": "Enable Bot Protection", "priority": "HIGH",
        "description": "WAAS > Rule > Bot Protection > Enable. Set known bot User-Agents to 'Ban'.",
        "config": "Prisma Console: WAAS > Bot Protection > Known Scanner Tools > Effect: Ban"})
    return {"waf_type": "Palo Alto Prisma WAAS", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    SUCURI WAF
# ═══════════════════════════════════════════════════════════════

def _generate_sucuri_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Sucuri WAF")
    fixes.append({"type": "policy_setting", "name": "Enable All Protection Features", "priority": "HIGH",
        "description": "Sucuri Dashboard > Firewall > Security > Enable: XSS Protection, SQLi Protection, RCE Protection, Directory Traversal Protection.",
        "config": "Sucuri Dashboard: Firewall WAF > Settings > Enable All OWASP Protections"})
    fixes.append({"type": "block_scanners", "name": "Block Security Scanner User-Agents", "priority": "HIGH",
        "description": "Firewall > Access Control > Block User-Agents: sqlmap, Nuclei, ffuf, Nessus, nikto, OpenVAS.",
        "config": "Sucuri Dashboard: Access Control > User-Agent Blocking > Add scanner patterns"})
    return {"waf_type": "Sucuri WAF", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    WORDPRESS (WORDFENCE / WP CERBER)
# ═══════════════════════════════════════════════════════════════

def _generate_wordpress_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "WordPress WAF")
    fixes.append({"type": "policy_setting", "name": "Set Wordfence to Extended Protection Mode", "priority": "HIGH",
        "description": "WordPress Admin > Wordfence > Firewall > Manage Firewall > Protection Level: Set to 'Extended Protection' (auto-prepend).",
        "config": "Wordfence > Firewall > Protection Level > Extended Protection (requires .htaccess or user.ini modification)"})
    fixes.append({"type": "enable_rules", "name": "Enable All Firewall Rules", "priority": "HIGH",
        "description": "Wordfence > Firewall > Rules > Enable all rules, especially: SQLi, XSS, File Upload, Directory Traversal.",
        "config": "Wordfence > Firewall > Manage Rules > Enable All > Status: Enabled and Blocking"})
    fixes.append({"type": "rate_limiting", "name": "Enable Rate Limiting for Scanner Detection", "priority": "MEDIUM",
        "description": "Wordfence > Firewall > Rate Limiting > Set: Anyone who exceeds 240 requests/min is throttled, 960/min is blocked.",
        "config": "Wordfence > Firewall > Rate Limiting > Throttle: 240/min, Block: 960/min"})
    return {"waf_type": "WordPress WAF", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    RADWARE APPWALL
# ═══════════════════════════════════════════════════════════════

def _generate_radware_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Radware AppWall")
    fixes.append({"type": "policy_setting", "name": "Set Security Policy to Active Blocking", "priority": "CRITICAL",
        "description": "AppWall Console > Security Policies > Your Policy > Mode: Change from 'Report Only' to 'Active Blocking'.",
        "config": "AppWall Console: Policies > Mode > Active Blocking"})
    fixes.append({"type": "signatures", "name": "Update and Enable All Signature Profiles", "priority": "HIGH",
        "description": "AppWall > Signatures > Profile > Enable all OWASP categories. Update to latest signature database.",
        "config": "AppWall Console: Signatures > Update DB > Enable All Categories"})
    return {"waf_type": "Radware AppWall", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    WALLARM NGWAF
# ═══════════════════════════════════════════════════════════════

def _generate_wallarm_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Wallarm NGWAF")
    fixes.append({"type": "policy_setting", "name": "Set Filtration Mode to Block", "priority": "CRITICAL",
        "description": "Wallarm Console > Settings > Filtration Mode > Set to 'block' (not 'monitoring' or 'safe_blocking').",
        "config": "wallarm_mode block;  # In nginx.conf or via Wallarm Console > Rules"})
    fixes.append({"type": "enable_parser", "name": "Enable All Request Parsers", "priority": "HIGH",
        "description": "Wallarm Console > Rules > Request Parsers > Enable: base64, json, xml, multipart, htmljs.",
        "config": "Wallarm Console: Rules > Manage Parsers > Enable base64, json, xml, htmljs"})
    return {"waf_type": "Wallarm NGWAF", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    SOPHOS UTM WAF
# ═══════════════════════════════════════════════════════════════

def _generate_sophos_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Sophos UTM WAF")
    fixes.append({"type": "policy_setting", "name": "Enable Web Application Firewall in Block Mode", "priority": "CRITICAL",
        "description": "Sophos Console > Web Protection > WAF > Profiles > Your Profile > Mode: Reject (not Monitor).",
        "config": "Sophos Console: Web Protection > WAF > Mode > Reject"})
    fixes.append({"type": "signatures", "name": "Enable All Attack Pattern Groups", "priority": "HIGH",
        "description": "WAF > Profiles > Filtering > Enable all OWASP attack pattern groups: SQL Injection, XSS, Command Injection, Path Traversal.",
        "config": "Sophos Console: WAF > Profiles > Threats Filter > Enable All Categories"})
    return {"waf_type": "Sophos UTM WAF", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    ALIBABA CLOUD WAF
# ═══════════════════════════════════════════════════════════════

def _generate_alibaba_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Alibaba Cloud WAF")
    fixes.append({"type": "policy_setting", "name": "Enable Web Application Protection", "priority": "HIGH",
        "description": "Alibaba Console > WAF > Protection Settings > Web Application Protection > Mode: Block. Enable: SQL Injection, XSS, Command Injection, File Inclusion.",
        "config": "Alibaba Console: WAF > Web Application Protection > Mode > Block > Enable All Rule Groups"})
    fixes.append({"type": "enable_encoding", "name": "Enable Deep Inspection (Base64 Decode)", "priority": "CRITICAL",
        "description": "WAF > Protection Settings > Advanced > Deep Inspection > Enable Base64 decode, URL decode for request body and headers.",
        "config": "Alibaba Console: WAF > Advanced Settings > Deep Inspection > Enable"})
    return {"waf_type": "Alibaba Cloud WAF", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    TENCENT CLOUD WAF
# ═══════════════════════════════════════════════════════════════

def _generate_tencent_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Tencent Cloud WAF")
    fixes.append({"type": "policy_setting", "name": "Set WAF to Blocking Mode", "priority": "CRITICAL",
        "description": "Tencent Console > WAF > Protection Settings > Mode: Block (not Observe).",
        "config": "Tencent Console: WAF > Domain Settings > Protection Mode > Block"})
    fixes.append({"type": "enable_rules", "name": "Enable All Managed Rule Groups", "priority": "HIGH",
        "description": "WAF > Managed Rules > Enable: OWASP Top 10, Bot Management, API Security rule groups.",
        "config": "Tencent Console: WAF > Managed Rules > Enable All > Action: Block"})
    return {"waf_type": "Tencent Cloud WAF", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    HUAWEI CLOUD WAF
# ═══════════════════════════════════════════════════════════════

def _generate_huawei_fixes(inference: InferenceResult | None, bypassed_categories: list[dict[str, Any]]) -> dict[str, Any]:
    fixes = _common_fixes(inference, "Huawei Cloud WAF")
    fixes.append({"type": "policy_setting", "name": "Set Protection Mode to Block", "priority": "CRITICAL",
        "description": "Huawei Console > WAF > Policies > Your Policy > Mode: Block (not Log Only).",
        "config": "Huawei Console: WAF > Policies > Protection Mode > Block"})
    fixes.append({"type": "enable_rules", "name": "Enable All Built-in Protection Rules", "priority": "HIGH",
        "description": "WAF > Policies > Rule Management > Enable all built-in rules for: XSS, SQLi, Command Injection, Path Traversal, XXE.",
        "config": "Huawei Console: WAF > Rule Management > Enable All Built-in Rules"})
    return {"waf_type": "Huawei Cloud WAF", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


# ═══════════════════════════════════════════════════════════════
#                    COMMON FIXES (shared across all WAFs)
# ═══════════════════════════════════════════════════════════════

def _common_fixes(inference: InferenceResult | None, waf_type: str) -> list[dict[str, Any]]:
    """Generate fixes common to all WAFs based on inference results."""
    fixes: list[dict[str, Any]] = []
    if not inference:
        return fixes

    for rs in inference.missing:
        if "BASE64" in rs.name.upper():
            fixes.append({"type": "enable_encoding", "name": f"Enable Base64 Decoding on {waf_type}",
                "priority": "CRITICAL", "description": f"Enable Base64 decode transformation on all {waf_type} rules. {rs.evidence}",
                "evidence": rs.evidence, "config": f"Enable BASE64_DECODE + URL_DECODE + HTML_ENTITY_DECODE on all rules in {waf_type}"})
        elif "HEADER" in rs.name.upper():
            fixes.append({"type": "enable_header_inspection", "name": f"Enable Header Inspection on {waf_type}",
                "priority": "CRITICAL", "description": f"Enable inspection of ALL HTTP headers including custom X-* headers and User-Agent. {rs.evidence}",
                "evidence": rs.evidence, "config": f"Enable header inspection for all custom headers in {waf_type}"})
        elif "CRLF" in rs.name.upper():
            fixes.append({"type": "add_crlf_rule", "name": f"Add CRLF Injection Rule on {waf_type}",
                "priority": "HIGH", "description": f"Add custom rule to detect %0d%0a CRLF injection patterns in URLs, query strings, and headers. {rs.evidence}",
                "evidence": rs.evidence, "config": f"Add regex rule matching %0[dD]%0[aA] patterns in {waf_type}"})
        elif "BOT" in rs.name.upper() or "SCANNER" in rs.name.upper():
            fixes.append({"type": "enable_bot_detection", "name": f"Enable Bot/Scanner Detection on {waf_type}",
                "priority": "HIGH", "description": f"Block known security scanner User-Agents (sqlmap, Nuclei, ffuf, Nessus). {rs.evidence}",
                "evidence": rs.evidence, "config": f"Enable bot detection/scanner blocking in {waf_type}"})
        elif "URI" in rs.name.upper() or "PATH" in rs.name.upper():
            fixes.append({"type": "enable_path_inspection", "name": f"Enable URI Path Inspection on {waf_type}",
                "priority": "HIGH", "description": f"Enable inspection of URL path component for command injection and traversal. {rs.evidence}",
                "evidence": rs.evidence, "config": f"Add URI path inspection rule in {waf_type}"})

    return fixes


def _generate_modsec_fixes(
    inference: InferenceResult | None,
    bypassed_categories: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate ModSecurity SecRule directives."""
    fixes = _common_fixes(inference, "ModSecurity")

    fixes.append({
        "type": "increase_paranoia",
        "name": "Increase Paranoia Level",
        "priority": "HIGH",
        "description": "Increase CRS paranoia level from 1 to 2 or 3",
        "config": 'SecAction "id:900000, phase:1, pass, t:none, nolog, setvar:tx.paranoia_level=3"',
    })

    fixes.append({
        "type": "enable_base64_decode",
        "name": "Enable Base64 Decoding",
        "priority": "CRITICAL",
        "description": "Add Base64 decode transformation to all rules",
        "config": 'SecRule REQUEST_BODY "@rx ." "id:900100, phase:2, pass, t:base64Decode, t:urlDecodeUni, t:htmlEntityDecode, t:lowercase"',
    })

    return {"waf_type": "ModSecurity", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}


def _generate_generic_fixes(
    inference: InferenceResult | None,
    bypassed_categories: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate generic text recommendations."""
    fixes: list[dict[str, Any]] = []

    if inference:
        for rs in inference.missing:
            fixes.append({
                "type": "recommendation",
                "name": rs.name,
                "priority": "HIGH",
                "description": rs.recommendation,
                "evidence": rs.evidence,
            })

    return {"waf_type": "Generic", "fixes": fixes, "summary": {"total_fixes": len(fixes), "critical": len([f for f in fixes if f["priority"] == "CRITICAL"]), "high": len([f for f in fixes if f["priority"] == "HIGH"])}}
