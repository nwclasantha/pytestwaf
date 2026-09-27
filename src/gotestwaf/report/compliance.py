"""Compliance mapping — maps WAF scan findings to regulatory frameworks.

Supports: PCI-DSS 4.0, SOC 2, ISO 27001, NIST 800-53
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gotestwaf.db.statistics import Statistics


@dataclass(slots=True)
class ComplianceControl:
    """A single compliance control with pass/fail status."""
    control_id: str = ""
    name: str = ""
    description: str = ""
    framework: str = ""
    status: str = "unknown"  # "pass", "fail", "partial", "n/a"
    related_attacks: list[str] = field(default_factory=list)
    block_rate: float = 0.0
    evidence: str = ""


@dataclass
class ComplianceSummary:
    """Summary for one framework."""
    framework: str = ""
    total_controls: int = 0
    passed: int = 0
    failed: int = 0
    partial: int = 0
    compliance_pct: float = 0.0
    controls: list[ComplianceControl] = field(default_factory=list)


# ── Attack category → compliance control mappings ──

PCI_DSS_4 = {
    "6.2.4": ("Software Engineering — Protection Against Common Attacks",
              "Ensure web-facing applications are protected against known attacks (XSS, SQLi, injection)",
              ["xss", "sql", "injection", "rce", "lfi", "path", "xxe", "xml", "ssti", "ssi"]),
    "6.4.1": ("Public-Facing Web Applications — WAF Protection",
              "Web applications must be protected by a WAF that detects and prevents web-based attacks",
              ["xss", "sql", "injection", "rce", "lfi", "shell", "command"]),
    "6.4.2": ("Automated Technical Solution for Public Web Apps",
              "An automated technical solution must continuously detect and prevent web attacks",
              ["xss", "sql", "nosql", "ldap", "mail", "crlf", "ssti"]),
    "11.6.1": ("Unauthorized Changes Detection",
              "Detect unauthorized changes to HTTP headers and payment page content",
              ["crlf", "header", "xss"]),
    "6.3.2": ("Software Vulnerability Management",
              "Track and manage known vulnerabilities in custom and third-party software",
              ["rce", "xxe", "ssti", "path"]),
}

SOC2 = {
    "CC6.1": ("Logical and Physical Access Controls",
              "Restrict logical access to information assets using WAF and access controls",
              ["xss", "sql", "injection", "rce", "lfi", "path", "auth"]),
    "CC6.6": ("Security of Externally-Facing Applications",
              "Manage threats and vulnerabilities for externally-facing applications",
              ["xss", "sql", "nosql", "rce", "shell", "lfi", "xxe", "crlf"]),
    "CC7.1": ("Detection of Unauthorized Activities",
              "Detect and monitor unauthorized activities including injection attacks",
              ["sql", "nosql", "ldap", "command", "shell", "rce"]),
    "CC7.2": ("Monitor System Components for Anomalies",
              "Monitor system components for anomalies indicating malicious acts",
              ["xss", "sql", "rce", "path", "xxe", "ssti"]),
    "CC8.1": ("Change Management Controls",
              "Authorize, design, develop, configure, document, test changes",
              ["crlf", "header"]),
}

ISO_27001 = {
    "A.14.2.5": ("Secure Development — System Security Testing",
              "Security testing of developed systems and applications",
              ["xss", "sql", "injection", "rce", "lfi", "xxe"]),
    "A.14.1.2": ("Securing Application Services on Public Networks",
              "Protect application services from injection, tampering, and information disclosure",
              ["xss", "sql", "nosql", "rce", "shell", "lfi", "path", "crlf"]),
    "A.14.1.3": ("Protecting Application Service Transactions",
              "Protect information in application service transactions from incomplete transmission and unauthorized access",
              ["sql", "xss", "crlf", "header"]),
    "A.12.6.1": ("Management of Technical Vulnerabilities",
              "Timely identification and remediation of technical vulnerabilities",
              ["rce", "xxe", "ssti", "path", "lfi"]),
    "A.13.1.1": ("Network Controls",
              "Networks managed and controlled to protect information in systems and applications",
              ["xss", "sql", "rce", "shell", "command"]),
}

NIST_800_53 = {
    "SI-10": ("Information Input Validation",
              "Check the validity of information inputs to the application",
              ["xss", "sql", "nosql", "ldap", "command", "shell", "rce", "injection"]),
    "SI-11": ("Error Handling",
              "Generate error messages that provide information necessary for corrective actions without revealing exploitation information",
              ["xss", "path", "lfi", "rce"]),
    "SC-18": ("Mobile Code",
              "Define acceptable and unacceptable mobile code and technologies; restrict use of mobile code",
              ["xss", "ssti", "ssi", "xxe"]),
    "SI-3": ("Malicious Code Protection",
              "Implement malicious code protection mechanisms at entry and exit points",
              ["xss", "sql", "rce", "shell", "command", "xxe", "injection"]),
    "SC-5": ("Denial of Service Protection",
              "Protect against denial of service attacks",
              ["rate", "dos"]),
    "AC-4": ("Information Flow Enforcement",
              "Enforce approved authorizations for controlling the flow of information",
              ["crlf", "header", "path", "lfi"]),
    "SI-16": ("Memory Protection",
              "Implement memory protection mechanisms for buffer overflow prevention",
              ["rce", "command", "shell"]),
}

FRAMEWORKS = {
    "pci-dss": ("PCI-DSS 4.0", PCI_DSS_4),
    "soc2": ("SOC 2 Type II", SOC2),
    "iso27001": ("ISO 27001:2022", ISO_27001),
    "nist": ("NIST 800-53 Rev 5", NIST_800_53),
}


def map_findings_to_compliance(
    stat: Statistics,
    frameworks: list[str],
) -> dict[str, ComplianceSummary]:
    """Map scan results to compliance frameworks.

    Args:
        stat: Scan statistics with per-category block rates.
        frameworks: List of framework keys (e.g., ["pci-dss", "soc2"])

    Returns:
        Dict of framework_key -> ComplianceSummary
    """
    # Build attack category → block rate lookup
    category_rates: dict[str, float] = {}
    for row in stat.true_positive_tests.summary_table:
        cat = row.test_case.lower()
        total = row.blocked + row.bypassed
        rate = row.blocked / total if total > 0 else 0.0
        category_rates[cat] = rate

    results: dict[str, ComplianceSummary] = {}

    for fw_key in frameworks:
        if fw_key not in FRAMEWORKS:
            continue

        fw_name, controls_map = FRAMEWORKS[fw_key]
        summary = ComplianceSummary(framework=fw_name)

        for ctrl_id, (name, description, attack_keywords) in controls_map.items():
            # Find matching attack categories
            matching_rates: list[float] = []
            matching_cats: list[str] = []
            for cat_name, rate in category_rates.items():
                if any(kw in cat_name for kw in attack_keywords):
                    matching_rates.append(rate)
                    matching_cats.append(cat_name)

            # Determine status based on block rate
            if not matching_rates:
                status = "n/a"
                avg_rate = 0.0
                evidence = "No matching test categories found"
            else:
                avg_rate = sum(matching_rates) / len(matching_rates)
                if avg_rate >= 0.80:
                    status = "pass"
                elif avg_rate >= 0.30:
                    status = "partial"
                else:
                    status = "fail"
                cat_details = ", ".join(f"{c}({r:.0%})" for c, r in zip(matching_cats[:5], matching_rates[:5]))
                evidence = f"Block rate: {avg_rate:.0%} [{cat_details}]"

            ctrl = ComplianceControl(
                control_id=ctrl_id,
                name=name,
                description=description,
                framework=fw_name,
                status=status,
                related_attacks=matching_cats[:5],
                block_rate=avg_rate,
                evidence=evidence,
            )
            summary.controls.append(ctrl)

        summary.total_controls = len(summary.controls)
        summary.passed = sum(1 for c in summary.controls if c.status == "pass")
        summary.failed = sum(1 for c in summary.controls if c.status == "fail")
        summary.partial = sum(1 for c in summary.controls if c.status == "partial")
        assessed = summary.passed + summary.failed + summary.partial
        # Score: pass=100%, partial=50%, fail=0%, weighted over the FULL set
        # of controls. Excluding "n/a" controls from the denominator inflated
        # the score to 100% whenever only a few categories matched and all
        # of them happened to have ≥80% block rate — even if most controls
        # had no evidence either way. Counting "n/a" as 0% is the honest
        # representation: an unverified control should not improve the
        # score.
        if summary.total_controls > 0:
            score = (summary.passed * 100 + summary.partial * 50) / summary.total_controls
            summary.compliance_pct = round(score, 1)
        elif assessed == 0:
            summary.compliance_pct = -1.0
        else:
            summary.compliance_pct = -1.0

        results[fw_key] = summary

    return results
