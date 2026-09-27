"""Inject IEEE-style numbered citations [N] throughout _build_article.py.

The body content uses Python implicit string concatenation, so each "line"
is a separate string literal. We process the whole file as a single string
and add a citation after the FIRST occurrence of each concept globally.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).parent / "_build_article.py"

# (pattern, citation_to_append) — first occurrence in the file gets cited.
CITES: list[tuple[str, str]] = [
    (r"\bOWASP Top 10\b",                                      " [1]"),
    (r"\bAWS WAF\b",                                           " [2]"),
    (r"\bAzure Front Door WAF\b",                              " [3]"),
    (r"\bAzure Front Door\b",                                  " [3]"),
    (r"\bGoogle Cloud Armor\b",                                " [4]"),
    (r"\bAWSManagedRulesCommonRuleSet\b",                      " [2]"),
    (r"\bGoTestWAF\b",                                         " [5]"),
    (r"\bWAFW00F\b",                                           " [6]"),
    (r"\bNuclei\b",                                            " [7]"),
    (r"\bOWASP Zed Attack Proxy\b|\bOWASP ZAP\b",              " [8]"),
    (r"\bBurp Suite\b",                                        " [9]"),
    (r"\bRandom Forest\b",                                     " [10]"),
    (r"\bGradient Boosting\b",                                 " [11]"),
    (r"\bMulti-Layer Perceptron\b",                            " [18]"),
    (r"\bLogistic Regression\b",                               " [12]"),
    (r"\bscikit-learn\b",                                      " [13]"),
    (r"\bisotonic calibration\b",                              " [14], [15]"),
    (r"\bisotonic probability calibration\b",                  " [14], [15]"),
    (r"\bstacking ensemble\b",                                 " [16]"),
    (r"\bstacked generalisation\b|\bstacked generalization\b", " [16]"),
    (r"\bautoencoder\b",                                       " [17]"),
    (r"\bTerraform\b",                                         " [21]"),
    (r"\bCloudFormation\b",                                    " [22]"),
    (r"\bBicep\b",                                             " [23]"),
    (r"\bgcloud\b",                                            " [24]"),
    (r"\bDocker\b",                                            " [31]"),
    (r"\bhttpx\b",                                             " [33]"),
    (r"\bWazuh\b",                                             " [25]"),
    (r"\bMITRE ATT&amp;CK\b|\bMITRE ATT&CK\b",                 " [26]"),
    (r"\bPCI[- ]DSS\b",                                        " [27]"),
    (r"\bSOC ?2\b",                                            " [28]"),
    (r"\bISO[/ ]?(?:IEC )?27001\b",                            " [29]"),
    (r"\bNIST(?: SP 800-53)?\b",                               " [30]"),
]


def _has_existing_cite_after(text: str, pos: int) -> bool:
    """Check whether the next 14 chars after pos already contain [NN]."""
    after = text[pos: pos + 14]
    return bool(re.match(r"\s*\[\d+\]", after))


def _inject(src: str) -> str:
    # Only operate on the part of the file that contains the body content
    # (between the first content constant and the REFERENCES tape). Avoid
    # touching the REFERENCES list itself.
    refs_anchor = src.index("REFERENCES = [")
    head = src[:refs_anchor]
    tail = src[refs_anchor:]

    n_added = 0
    for pat, cite in CITES:
        # First match in head only
        m = re.search(pat, head)
        if not m:
            continue
        end = m.end()
        if _has_existing_cite_after(head, end):
            continue
        head = head[:end] + cite + head[end:]
        n_added += 1

    return head + tail, n_added


def _patch_table_one(src: str) -> str:
    """Convert author-year cites in TABLE_I to numbered IEEE form."""
    replacements = [
        ("Lasantha et al. (2024)",                "Lasantha et al. [4]*  (template-source paper)"),
        ("Pedregosa et al. (2011)",               "Pedregosa et al. [13]"),
        ("Wolpert (1992)",                        "Wolpert [16]"),
        ("Niculescu-Mizil & Caruana (2005)",      "Niculescu-Mizil and Caruana [15]"),
        ("Breiman (2001)",                        "Breiman [10]"),
        ("Friedman (2001)",                       "Friedman [11]"),
        ("Wallarm, 2023",                         "Wallarm [5]"),
        ("EnableSecurity, 2024",                  "EnableSecurity [6]"),
        ("ProjectDiscovery, 2024",                "ProjectDiscovery [7]"),
        ("OWASP, 2024",                           "OWASP [8]"),
        ("PortSwigger, 2024",                     "PortSwigger [9]"),
    ]
    out = src
    for old, new in replacements:
        out = out.replace(old, new)
    return out


def main():
    src = SRC.read_text(encoding="utf-8")
    src = _patch_table_one(src)
    src, n = _inject(src)
    SRC.write_text(src, encoding="utf-8")
    print(f"Body citations added: {n}")
    refs_used = sorted(set(int(m.group(1))
                           for m in re.finditer(r"\[(\d+)\]", src[:src.index("REFERENCES = [")])))
    print(f"Distinct refs cited in body: {len(refs_used)} -> {refs_used}")


if __name__ == "__main__":
    main()
