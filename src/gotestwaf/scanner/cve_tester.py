"""Zero-Day CVE simulation — tests WAF against recently published CVEs.

Fetches recent web-related CVEs from NVD API, maps CWE to attack category,
generates test payloads, and checks if the WAF blocks them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CWE → attack type mapping
CWE_TO_ATTACK = {
    "CWE-79": ("XSS", ['<script>alert("CVE")</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>']),
    "CWE-89": ("SQLi", ["' OR 1=1--", "' UNION SELECT NULL--", "1; DROP TABLE users--"]),
    "CWE-78": ("Command Injection", ["; cat /etc/passwd", "| whoami", "$(id)"]),
    "CWE-22": ("Path Traversal", ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam", "/etc/shadow"]),
    "CWE-611": ("XXE", ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>']),
    "CWE-94": ("Code Injection", ["${7*7}", "{{7*7}}", "<%= 7*7 %>"]),
    "CWE-918": ("SSRF", ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80", "http://[::1]/"]),
    "CWE-502": ("Deserialization", ['O:8:"stdClass":0:{}', 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==']),
    "CWE-434": ("File Upload", ["../../shell.php", "shell.php%00.jpg", "shell.phtml"]),
    "CWE-352": ("CSRF", [""]),  # CSRF is hard to test via payloads
    "CWE-287": ("Auth Bypass", ["admin' --", "' OR '1'='1", "admin%00"]),
}


@dataclass(slots=True)
class CVETestResult:
    """Result of testing a single CVE."""
    cve_id: str = ""
    description: str = ""
    severity: str = ""
    published: str = ""
    cwe: str = ""
    attack_type: str = ""
    payloads_tested: int = 0
    blocked: int = 0
    bypassed: int = 0
    status: str = "unknown"  # "protected", "vulnerable", "partial", "not_applicable"

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id, "description": self.description[:200],
            "severity": self.severity, "published": self.published,
            "cwe": self.cwe, "attack_type": self.attack_type,
            "payloads_tested": self.payloads_tested,
            "blocked": self.blocked, "bypassed": self.bypassed,
            "status": self.status,
        }


async def fetch_recent_cves(days: int = 30) -> list[dict[str, Any]]:
    """Fetch recent web-related CVEs from NVD API."""
    from datetime import datetime, timedelta

    from datetime import timezone
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000+00:00"),
        "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.999+00:00"),
        "resultsPerPage": 50,
    }

    cves: list[dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(NVD_API, params=params)
            if resp.status_code != 200:
                logger.warning("NVD API error", status=resp.status_code)
                return []

            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")

                # Get CWE
                cwes = []
                for weakness in cve.get("weaknesses", []):
                    for desc in weakness.get("description", []):
                        cwe_val = desc.get("value", "")
                        if cwe_val.startswith("CWE-"):
                            cwes.append(cwe_val)

                # Filter to web-related CWEs only
                web_cwes = [c for c in cwes if c in CWE_TO_ATTACK]
                if not web_cwes:
                    continue

                # Get severity
                metrics = cve.get("metrics", {})
                severity = "UNKNOWN"
                for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metric_list = metrics.get(metric_key, [])
                    if metric_list:
                        severity = metric_list[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                        break

                # Get description
                descriptions = cve.get("descriptions", [])
                desc_text = ""
                for d in descriptions:
                    if d.get("lang") == "en":
                        desc_text = d.get("value", "")
                        break

                cves.append({
                    "id": cve_id,
                    "description": desc_text,
                    "severity": severity,
                    "published": cve.get("published", ""),
                    "cwes": web_cwes,
                })

        logger.info("Fetched web-related CVEs", count=len(cves), days=days)
    except Exception as e:
        logger.warning("Failed to fetch CVEs from NVD", error=str(e))

    return cves


def generate_cve_payloads(cve: dict[str, Any]) -> list[tuple[str, str]]:
    """Generate test payloads for a CVE based on its CWE classification.

    Returns list of (payload, attack_type) tuples.
    """
    payloads: list[tuple[str, str]] = []
    for cwe in cve.get("cwes", []):
        if cwe in CWE_TO_ATTACK:
            attack_type, attack_payloads = CWE_TO_ATTACK[cwe]
            for p in attack_payloads:
                if p:
                    payloads.append((p, attack_type))
    return payloads
