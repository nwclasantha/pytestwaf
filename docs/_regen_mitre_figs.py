"""
Regenerate Figs. 27 (MITRE ATT&CK), 28 (kill-chain) and 29 (tactic radar)
at HD using real scan data.

Each attack family is mapped to a MITRE technique ID and a kill-chain
phase based on standard threat-modelling conventions for web attacks.
The mapping is approximate but defensible.
"""
from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

csv.field_size_limit(10_000_000)

ROOT = Path(__file__).resolve().parent
CSV_PATH = ROOT.parent / "reports" / "waf-scan-portal-wazuh-hrclabs-io.csv"
OUT = ROOT / "diagrams"

plt.rcParams.update({
    "font.family":     "DejaVu Sans",
    "font.size":       14,
    "axes.titlesize":  18,
    "axes.titleweight": "bold",
    "axes.labelsize":  16,
    "xtick.labelsize": 14,
    "ytick.labelsize": 14,
    "legend.fontsize": 14,
    "figure.dpi":      600,
    "savefig.dpi":     600,
    "lines.linewidth": 2.5,
    "lines.markersize": 9,
})

C_BLOCK   = "#0072B2"
C_BYPASS  = "#D55E00"
C_RADAR   = "#0072B2"

FW, FH = 10.0, 6.67


# ---------------------------------------------------------------------------
# Mappings
# ---------------------------------------------------------------------------
def categorise(case: str, set_name: str) -> tuple[str, str, str]:
    """Return (mitre_technique_id, mitre_technique_name, kill_chain_phase)."""
    case = case.lower()
    if "xss" in case:
        return ("T1059.007", "Scripting: JavaScript",        "Exploitation")
    if "sql" in case:
        return ("T1190",     "Exploit Public-Facing App.",   "Exploitation")
    if "shell" in case or "rce" in case or "command" in case:
        return ("T1059",     "Command & Scripting Interp.",  "Exploitation")
    if "ldap" in case:
        return ("T1190",     "Exploit Public-Facing App.",   "Exploitation")
    if "lfi" in case or "traversal" in case:
        return ("T1083",     "File & Directory Discovery",   "Discovery")
    if "xxe" in case or "xml" in case:
        return ("T1203",     "Exploitation for Client Exec.", "Exploitation")
    if "nosql" in case:
        return ("T1190",     "Exploit Public-Facing App.",   "Exploitation")
    if "crlf" in case:
        return ("T1556",     "Modify Authentication Process", "Defense Evasion")
    if "mail" in case:
        return ("T1566",     "Phishing: Spearphishing",      "Initial Access")
    if "ssti" in case or "template" in case:
        return ("T1059",     "Command & Scripting Interp.",  "Exploitation")
    if "ssi" in case:
        return ("T1059",     "Command & Scripting Interp.",  "Exploitation")
    if "graphql" in case or "soap" in case:
        return ("T1190",     "Exploit Public-Facing App.",   "Initial Access")
    if "user-agent" in case or "header" in case:
        return ("T1071",     "Application Layer Protocol",   "Command & Control")
    if "false-pos" in set_name.lower():
        return ("BENIGN",    "Benign control traffic",       "Reconnaissance")
    return ("T1190", "Exploit Public-Facing App.", "Exploitation")


# ---------------------------------------------------------------------------
# Fig. 27 — MITRE ATT&CK technique coverage
# ---------------------------------------------------------------------------
def fig27(rows):
    by_tech = defaultdict(lambda: Counter())
    name_of = {}
    for r in rows:
        tid, tname, _ = categorise(r["Case"], r["Set"])
        if tid == "BENIGN":
            continue  # skip benign
        by_tech[tid][r["Check Status"]] += 1
        name_of[tid] = tname

    techs = sorted(by_tech.keys(),
                   key=lambda t: -(by_tech[t].get("blocked", 0) + by_tech[t].get("passed", 0)))
    labels = [f"{t}\n{name_of[t]}" for t in techs]
    blocks = [by_tech[t].get("blocked", 0) for t in techs]
    bypass = [by_tech[t].get("passed",  0) for t in techs]

    y = np.arange(len(techs)); h = 0.4
    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.barh(y - h / 2, blocks, h, color=C_BLOCK,  label="Blocked",  edgecolor="white", linewidth=0.8)
    ax.barh(y + h / 2, bypass, h, color=C_BYPASS, label="Bypassed", edgecolor="white", linewidth=0.8)
    ax.set_yticks(y); ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.legend(loc="lower right", frameon=True)
    ax.set_title("MITRE ATT&CK technique coverage (block vs. bypass)", pad=14)
    ax.set_xlabel("Number of payloads")
    ax.set_ylabel("MITRE technique")
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    ax.grid(True, axis="x", alpha=0.3, linestyle=":")
    fig.tight_layout()
    p = OUT / "waf-mitre-attack.png"
    fig.savefig(p, dpi=600, bbox_inches="tight", pad_inches=0.18)
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# Fig. 28 — Cyber kill-chain phase coverage
# ---------------------------------------------------------------------------
def fig28(rows):
    PHASES = ["Reconnaissance", "Weaponisation", "Delivery", "Exploitation",
              "Installation", "Command & Control", "Actions"]
    by_phase = {p: Counter() for p in PHASES}
    for r in rows:
        _, _, phase = categorise(r["Case"], r["Set"])
        if phase not in by_phase:
            phase = "Exploitation"
        by_phase[phase][r["Check Status"]] += 1

    blocks = [by_phase[p].get("blocked", 0) for p in PHASES]
    bypass = [by_phase[p].get("passed",  0) for p in PHASES]

    x = np.arange(len(PHASES)); w = 0.4
    fig, ax = plt.subplots(figsize=(FW, FH))
    ax.bar(x - w / 2, blocks, w, color=C_BLOCK,  label="Blocked",  edgecolor="white", linewidth=0.8)
    ax.bar(x + w / 2, bypass, w, color=C_BYPASS, label="Bypassed", edgecolor="white", linewidth=0.8)
    ax.set_xticks(x); ax.set_xticklabels(PHASES, rotation=20, ha="right")
    ax.legend(loc="upper right", frameon=True)
    ax.set_title("Cyber kill-chain coverage of blocked and bypassed payloads", pad=14)
    ax.set_xlabel("Kill-chain phase")
    ax.set_ylabel("Number of payloads")
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    ax.grid(True, axis="y", alpha=0.3, linestyle=":")
    fig.tight_layout()
    p = OUT / "waf-kill-chain.png"
    fig.savefig(p, dpi=600, bbox_inches="tight", pad_inches=0.18)
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# Fig. 29 — MITRE tactic-coverage radar
# ---------------------------------------------------------------------------
def fig29(rows):
    """For each MITRE tactic the figure plots the WAF's detection rate
    (block / (block+passed)) %."""
    TACTICS = ["Initial Access", "Execution", "Persistence",
               "Defense Evasion", "Discovery",
               "Command & Control", "Reconnaissance"]

    # Map technique IDs back to tactics (approximate):
    tech_to_tactic = {
        "T1190":    "Initial Access",
        "T1566":    "Initial Access",
        "T1059":    "Execution",
        "T1059.007": "Execution",
        "T1203":    "Execution",
        "T1556":    "Defense Evasion",
        "T1083":    "Discovery",
        "T1071":    "Command & Control",
        "BENIGN":   "Reconnaissance",
    }

    by_tactic = {t: Counter() for t in TACTICS}
    for r in rows:
        tid, _, _ = categorise(r["Case"], r["Set"])
        tactic = tech_to_tactic.get(tid, "Initial Access")
        by_tactic[tactic][r["Check Status"]] += 1

    rates = []
    for t in TACTICS:
        c = by_tactic[t]
        total = c.get("blocked", 0) + c.get("passed", 0)
        rates.append(100.0 * c.get("blocked", 0) / total if total > 0 else 0.0)

    angles = np.linspace(0, 2 * np.pi, len(TACTICS), endpoint=False).tolist()
    rates_loop  = rates + rates[:1]
    angles_loop = angles + angles[:1]

    fig, ax = plt.subplots(figsize=(FW, FH), subplot_kw=dict(polar=True))
    ax.plot(angles_loop, rates_loop, "-o", color=C_RADAR, linewidth=3, markersize=10)
    ax.fill(angles_loop, rates_loop, color=C_RADAR, alpha=0.18)
    ax.set_xticks(angles)
    ax.set_xticklabels(TACTICS, fontsize=14)
    ax.set_ylim(0, 100)
    ax.set_yticks([20, 40, 60, 80, 100])
    ax.set_yticklabels(["20%", "40%", "60%", "80%", "100%"], fontsize=12)
    ax.set_title("MITRE tactic detection rate (% blocked by WAF)", pad=22, fontsize=18, fontweight="bold")
    ax.grid(True, alpha=0.4)

    fig.tight_layout()
    p = OUT / "waf-tactic-radar.png"
    fig.savefig(p, dpi=600, bbox_inches="tight", pad_inches=0.25)
    plt.close(fig)
    return p


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    rows = list(csv.DictReader(open(CSV_PATH, encoding="utf-8")))
    written = []
    written.append(fig27(rows))
    written.append(fig28(rows))
    written.append(fig29(rows))
    print("Regenerated MITRE/kill-chain/radar figures (600 DPI):")
    from PIL import Image
    for p in written:
        img = Image.open(p)
        sz = p.stat().st_size
        print(f"  {p.name:40s}  {img.size[0]:5d}x{img.size[1]:<5d}  {sz/1024:6.1f} KB")


if __name__ == "__main__":
    main()
