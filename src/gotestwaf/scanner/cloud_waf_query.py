"""Cloud WAF Configuration Query — reads actual configured rulesets via cloud APIs.

Supports:
- AWS WAF (boto3) — reads Web ACL rules, managed rule groups, custom rules
- Azure WAF (azure SDK) — reads Front Door / Application Gateway WAF policies
- GCP Cloud Armor (google-cloud) — reads security policies
- Cloudflare (REST API) — reads WAF rulesets

Usage:
    result = query_cloud_waf("aws", region="us-east-1", resource_id="web-acl-id")
    for rule in result.rules:
        print(f"{rule.name} ({rule.vendor}) - {rule.action}")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class CloudRule:
    """A single WAF rule or rule group from cloud API."""
    name: str = ""
    vendor: str = ""  # "AWS", "Fortinet", "Custom", etc.
    rule_type: str = ""  # "managed", "custom", "rate_based", "ip_set"
    action: str = ""  # "block", "count", "allow"
    priority: int = 0
    description: str = ""
    arn: str = ""
    # For managed rule groups
    managed_group_name: str = ""
    managed_vendor: str = ""
    # Text transformations configured
    text_transformations: list[str] = field(default_factory=list)
    # Inspection fields
    inspected_fields: list[str] = field(default_factory=list)


@dataclass
class CloudWAFConfig:
    """Complete WAF configuration from cloud API."""
    provider: str = ""  # "aws", "azure", "gcp", "cloudflare"
    waf_name: str = ""
    waf_id: str = ""
    region: str = ""
    rules: list[CloudRule] = field(default_factory=list)
    raw_config: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    @property
    def managed_rules(self) -> list[CloudRule]:
        return [r for r in self.rules if r.rule_type == "managed"]

    @property
    def custom_rules(self) -> list[CloudRule]:
        return [r for r in self.rules if r.rule_type == "custom"]


def auto_query_cloud_waf(waf_name: str, target_url: str) -> CloudWAFConfig | None:
    """Auto-detect cloud provider from WAF name and query config if credentials available.

    No flags needed — detects provider from WAF identification result,
    checks for credentials in environment (AWS_*, AZURE_*, GOOGLE_*, CF_*),
    and queries automatically.
    """
    import os

    waf_lower = waf_name.lower()

    # Auto-detect provider from WAF name
    if any(kw in waf_lower for kw in ("aws", "cloudfront", "amazon")):
        provider = "aws"
    elif any(kw in waf_lower for kw in ("azure", "microsoft", "front door")):
        provider = "azure"
    elif any(kw in waf_lower for kw in ("cloud armor", "google", "gcp")):
        provider = "gcp"
    elif "cloudflare" in waf_lower:
        provider = "cloudflare"
    else:
        return None  # Unknown provider, skip

    # Check if credentials are available in environment
    match provider:
        case "aws":
            has_creds = (
                os.path.exists(os.path.expanduser("~/.aws/credentials"))
                or os.environ.get("AWS_ACCESS_KEY_ID")
                or os.environ.get("AWS_PROFILE")
                or os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")  # ECS
            )
            if not has_creds:
                return CloudWAFConfig(provider="aws", error="No AWS credentials found (no ~/.aws/credentials, no AWS_ACCESS_KEY_ID env var)")

            # Auto-detect region from URL or use common regions
            region = os.environ.get("AWS_DEFAULT_REGION", os.environ.get("AWS_REGION", ""))
            profile = os.environ.get("AWS_PROFILE", "")

            # Try to find the Web ACL automatically
            return _query_aws_waf(region, "", "", profile)

        case "azure":
            has_creds = (
                os.environ.get("AZURE_CLIENT_ID")
                or os.environ.get("AZURE_TENANT_ID")
                or os.path.exists(os.path.expanduser("~/.azure/"))
            )
            if not has_creds:
                return CloudWAFConfig(provider="azure", error="No Azure credentials found")
            return CloudWAFConfig(provider="azure", error="Azure auto-query requires --azureSubscription and --azureResourceGroup")

        case "gcp":
            has_creds = (
                os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
                or os.path.exists(os.path.expanduser("~/.config/gcloud/"))
            )
            if not has_creds:
                return CloudWAFConfig(provider="gcp", error="No GCP credentials found")
            return CloudWAFConfig(provider="gcp", error="GCP auto-query requires --gcpProject and policy name")

        case "cloudflare":
            api_token = os.environ.get("CF_API_TOKEN", os.environ.get("CLOUDFLARE_API_TOKEN", ""))
            zone_id = os.environ.get("CF_ZONE_ID", os.environ.get("CLOUDFLARE_ZONE_ID", ""))
            if api_token and zone_id:
                return _query_cloudflare_waf(api_token, zone_id)
            return CloudWAFConfig(provider="cloudflare", error="Set CF_API_TOKEN and CF_ZONE_ID env vars for auto-query")

    return None


def query_cloud_waf(
    provider: str,
    region: str = "",
    resource_id: str = "",
    resource_name: str = "",
    api_token: str = "",
    zone_id: str = "",
    subscription_id: str = "",
    resource_group: str = "",
    project_id: str = "",
    profile: str = "",
) -> CloudWAFConfig:
    """Query cloud WAF for actual configured rules.

    Args:
        provider: "aws", "azure", "gcp", "cloudflare"
        region: Cloud region (e.g., "us-east-1")
        resource_id: WAF resource ID (Web ACL ID, policy name, etc.)
        resource_name: WAF resource name
        api_token: API token (for Cloudflare)
        zone_id: Cloudflare zone ID
        subscription_id: Azure subscription ID
        resource_group: Azure resource group
        project_id: GCP project ID
        profile: AWS profile name

    Returns:
        CloudWAFConfig with all configured rules.
    """
    match provider.lower():
        case "aws":
            return _query_aws_waf(region, resource_id, resource_name, profile)
        case "azure":
            return _query_azure_waf(subscription_id, resource_group, resource_name)
        case "gcp":
            return _query_gcp_cloud_armor(project_id, resource_name)
        case "cloudflare":
            return _query_cloudflare_waf(api_token, zone_id)
        case _:
            return CloudWAFConfig(provider=provider, error=f"Unsupported provider: {provider}")


# ═══════════════════════════════════════════════════════════════
#                        AWS WAF
# ═══════════════════════════════════════════════════════════════

def _query_aws_waf(region: str, acl_id: str, acl_name: str, profile: str) -> CloudWAFConfig:
    """Query AWS WAF v2 for Web ACL configuration."""
    config = CloudWAFConfig(provider="aws", region=region)

    try:
        import boto3
    except ImportError:
        config.error = "boto3 not installed (add boto3 to Docker for cloud WAF query)"
        return config

    try:
        session_kwargs: dict[str, str] = {}
        if profile:
            session_kwargs["profile_name"] = profile

        # Auto-search regions if not specified
        regions_to_try = [region] if region else []
        if not regions_to_try:
            # Try common regions
            session_tmp = boto3.Session(**session_kwargs)
            try:
                # Try to get region from session config
                default_region = session_tmp.region_name
                if default_region:
                    regions_to_try = [default_region]
            except Exception:
                pass
            if not regions_to_try:
                regions_to_try = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1"]

        web_acls = []
        used_region = ""
        used_scope = "REGIONAL"

        for try_region in regions_to_try:
            try:
                sess = boto3.Session(region_name=try_region, **session_kwargs)
                client = sess.client("wafv2")
                acls = client.list_web_acls(Scope="REGIONAL")
                found = acls.get("WebACLs", [])
                if found:
                    web_acls = found
                    used_region = try_region
                    break
                # Also try CLOUDFRONT (only from us-east-1)
                if try_region == "us-east-1":
                    acls = client.list_web_acls(Scope="CLOUDFRONT")
                    found = acls.get("WebACLs", [])
                    if found:
                        web_acls = found
                        used_region = try_region
                        used_scope = "CLOUDFRONT"
                        break
            except Exception:
                continue

        if not web_acls:
            config.error = f"No Web ACLs found in regions: {regions_to_try}"
            return config

        config.region = used_region
        session_kwargs["region_name"] = used_region
        session = boto3.Session(**session_kwargs)
        client = session.client("wafv2")

        if not acl_id:
            if acl_name:
                matched = [a for a in web_acls if a["Name"] == acl_name]
                if not matched:
                    config.error = f"Web ACL '{acl_name}' not found. Available: {[a['Name'] for a in web_acls]}"
                    return config
                acl_id = matched[0]["Id"]
                acl_name = matched[0]["Name"]
            else:
                # Use first one
                acl_id = web_acls[0]["Id"]
                acl_name = web_acls[0]["Name"]
                logger.info("Auto-selected Web ACL", name=acl_name, id=acl_id)

        # Get full Web ACL config
        try:
            resp = client.get_web_acl(Name=acl_name, Scope=used_scope, Id=acl_id)
        except Exception:
            alt_scope = "CLOUDFRONT" if used_scope == "REGIONAL" else "REGIONAL"
            resp = client.get_web_acl(Name=acl_name, Scope=alt_scope, Id=acl_id)

        acl = resp["WebACL"]
        config.waf_name = acl["Name"]
        config.waf_id = acl["Id"]
        config.raw_config = acl

        # Parse each rule
        for rule in acl.get("Rules", []):
            cr = _parse_aws_rule(rule)
            config.rules.append(cr)

        config.rules.sort(key=lambda r: r.priority)

        logger.info(
            "AWS WAF configuration loaded",
            acl_name=config.waf_name,
            rules=len(config.rules),
            managed=len(config.managed_rules),
            custom=len(config.custom_rules),
        )

    except Exception as e:
        config.error = str(e)
        logger.error("Failed to query AWS WAF", error=str(e))

    return config


def _parse_aws_rule(rule: dict[str, Any]) -> CloudRule:
    """Parse a single AWS WAF rule into CloudRule."""
    cr = CloudRule()
    cr.name = rule.get("Name", "")
    cr.priority = rule.get("Priority", 0)

    # Determine action
    action = rule.get("Action", {})
    override_action = rule.get("OverrideAction", {})
    if "Block" in action:
        cr.action = "block"
    elif "Allow" in action:
        cr.action = "allow"
    elif "Count" in action:
        cr.action = "count"
    elif "None" in override_action:
        cr.action = "block (use rule group action)"
    elif "Count" in override_action:
        cr.action = "count (override)"
    else:
        cr.action = "unknown"

    # Parse statement to find rule type
    stmt = rule.get("Statement", {})
    if "ManagedRuleGroupStatement" in stmt:
        mrg = stmt["ManagedRuleGroupStatement"]
        cr.rule_type = "managed"
        cr.managed_vendor = mrg.get("VendorName", "")
        cr.managed_group_name = mrg.get("Name", "")
        cr.vendor = cr.managed_vendor

        # Build descriptive name
        vendor_display = cr.managed_vendor
        if vendor_display == "AWS":
            vendor_display = "AWS Managed"
        cr.description = f"{vendor_display}: {cr.managed_group_name}"

        # Check for excluded rules
        excluded = mrg.get("ExcludedRules", [])
        if excluded:
            cr.description += f" ({len(excluded)} rules excluded)"

    elif "RateBasedStatement" in stmt:
        cr.rule_type = "rate_based"
        cr.vendor = "Custom"
        rbs = stmt["RateBasedStatement"]
        cr.description = f"Rate limit: {rbs.get('Limit', 0)} requests per 5 min"

    elif "IPSetReferenceStatement" in stmt:
        cr.rule_type = "ip_set"
        cr.vendor = "Custom"
        cr.description = "IP Set match rule"

    else:
        cr.rule_type = "custom"
        cr.vendor = "Custom"
        cr.description = "Custom rule"

    # Extract text transformations from any field-level match
    _extract_transforms(stmt, cr)

    return cr


def _extract_transforms(stmt: dict[str, Any], cr: CloudRule) -> None:
    """Recursively extract text transformations from AWS WAF statement."""
    for key, val in stmt.items():
        if key == "TextTransformations" and isinstance(val, list):
            for t in val:
                tt = t.get("Type", "")
                if tt and tt not in cr.text_transformations:
                    cr.text_transformations.append(tt)
        elif key == "FieldToMatch" and isinstance(val, dict):
            for field_key in val:
                if field_key not in cr.inspected_fields:
                    cr.inspected_fields.append(field_key)
        elif isinstance(val, dict):
            _extract_transforms(val, cr)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    _extract_transforms(item, cr)


# ═══════════════════════════════════════════════════════════════
#                        AZURE WAF
# ═══════════════════════════════════════════════════════════════

def _query_azure_waf(subscription_id: str, resource_group: str, policy_name: str) -> CloudWAFConfig:
    """Query Azure WAF policy configuration."""
    config = CloudWAFConfig(provider="azure")

    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.frontdoor import FrontDoorManagementClient
    except ImportError:
        config.error = "Azure SDK not installed. Run: pip install azure-identity azure-mgmt-frontdoor"
        return config

    try:
        credential = DefaultAzureCredential()
        client = FrontDoorManagementClient(credential, subscription_id)

        policy = client.policies.get(resource_group, policy_name)
        config.waf_name = policy.name
        config.waf_id = policy.id

        # Parse managed rules
        if policy.managed_rules:
            for rule_set in policy.managed_rules.managed_rule_sets:
                cr = CloudRule(
                    name=f"{rule_set.rule_set_type} v{rule_set.rule_set_version}",
                    vendor="Azure/Microsoft",
                    rule_type="managed",
                    managed_group_name=rule_set.rule_set_type,
                    action="block",
                    description=f"Azure managed: {rule_set.rule_set_type}",
                )
                config.rules.append(cr)

        # Parse custom rules
        if policy.custom_rules:
            for rule in policy.custom_rules.rules:
                cr = CloudRule(
                    name=rule.name,
                    vendor="Custom",
                    rule_type="custom",
                    action=rule.action.lower(),
                    priority=rule.priority,
                    description=f"Custom rule: {rule.name}",
                )
                config.rules.append(cr)

        logger.info("Azure WAF configuration loaded", policy=config.waf_name, rules=len(config.rules))

    except Exception as e:
        config.error = str(e)

    return config


# ═══════════════════════════════════════════════════════════════
#                      GCP CLOUD ARMOR
# ═══════════════════════════════════════════════════════════════

def _query_gcp_cloud_armor(project_id: str, policy_name: str) -> CloudWAFConfig:
    """Query GCP Cloud Armor security policy."""
    config = CloudWAFConfig(provider="gcp")

    try:
        from google.cloud import compute_v1
    except ImportError:
        config.error = "Google Cloud SDK not installed. Run: pip install google-cloud-compute"
        return config

    try:
        client = compute_v1.SecurityPoliciesClient()
        policy = client.get(project=project_id, security_policy=policy_name)
        config.waf_name = policy.name
        config.waf_id = str(policy.id)

        for rule in policy.rules:
            cr = CloudRule(
                name=f"Rule {rule.priority}",
                vendor="Google Cloud",
                rule_type="custom" if not rule.match else "managed",
                action=rule.action.lower(),
                priority=rule.priority,
                description=rule.description or f"Priority {rule.priority}",
            )
            if rule.match and rule.match.expr:
                cr.description += f" | Match: {rule.match.expr.expression[:100]}"
            config.rules.append(cr)

        logger.info("GCP Cloud Armor configuration loaded", policy=config.waf_name, rules=len(config.rules))

    except Exception as e:
        config.error = str(e)

    return config


# ═══════════════════════════════════════════════════════════════
#                      CLOUDFLARE WAF
# ═══════════════════════════════════════════════════════════════

def _query_cloudflare_waf(api_token: str, zone_id: str) -> CloudWAFConfig:
    """Query Cloudflare WAF rulesets."""
    config = CloudWAFConfig(provider="cloudflare")

    if not api_token or not zone_id:
        config.error = "Cloudflare requires --api-token and --zone-id"
        return config

    try:
        import httpx

        headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
        base_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"

        with httpx.Client(headers=headers, timeout=30) as client:
            # Get WAF rulesets
            resp = client.get(f"{base_url}/rulesets")
            if resp.status_code != 200:
                config.error = f"Cloudflare API error: {resp.status_code}"
                return config

            data = resp.json()
            rulesets = data.get("result", [])

            for rs in rulesets:
                cr = CloudRule(
                    name=rs.get("name", ""),
                    vendor="Cloudflare",
                    rule_type="managed" if rs.get("kind") == "managed" else "custom",
                    description=rs.get("description", ""),
                    arn=rs.get("id", ""),
                )
                config.rules.append(cr)

            # Get managed WAF configuration
            resp2 = client.get(f"{base_url}/firewall/waf/packages")
            if resp2.status_code == 200:
                packages = resp2.json().get("result", [])
                for pkg in packages:
                    cr = CloudRule(
                        name=pkg.get("name", ""),
                        vendor="Cloudflare",
                        rule_type="managed",
                        action=pkg.get("action_mode", ""),
                        description=f"WAF Package: {pkg.get('description', '')}",
                    )
                    config.rules.append(cr)

        config.waf_name = f"Cloudflare WAF (zone: {zone_id[:8]}...)"
        logger.info("Cloudflare WAF configuration loaded", zone=zone_id, rules=len(config.rules))

    except ImportError:
        config.error = "httpx not installed"
    except Exception as e:
        config.error = str(e)

    return config
