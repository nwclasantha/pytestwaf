"""Honest end-to-end audit: verify what landed in the saved file vs what
was asked for across the whole conversation."""
import re
from docx import Document
from docx.oxml.ns import qn

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
d = Document(r'C:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx')

paras = list(d.paragraphs)

# Collect text incl. tables
all_text = "\n".join(p.text for p in paras)
for t in d.tables:
    for r in t.rows:
        for c in r.cells:
            all_text += "\n" + c.text

# Markers (what / where / required by user)
markers = [
    ("Methodology section after Lit Review",          "Methodology"),
    ("Phase 1-2 heading",                              "Phase 1-2: Input Configuration"),
    ("Phase 3 heading",                                "Phase 3: Test Corpus"),
    ("Phase 4 heading",                                "Phase 4: Four-Layer"),
    ("Phase 5 heading",                                "Phase 5: Hybrid ML Engine"),
    ("Phase 6 heading",                                "Phase 6: Adaptive Mutation"),
    ("Phase 7-8-9 heading",                            "Phases 7, 8 and 9"),
    ("Phase 7 narrative (auto-fix)",                   "Phase 7 (Generate Fixes)"),
    ("Phase 8 narrative (report)",                     "Phase 8 (Report)"),
    ("52-dim payload features",                        "fifty-two payload"),
    ("72-dim total features",                          "72-dimensional"),
    ("47 YAML test cases",                             "forty-seven YAML"),
    ("Real ResponseVerdict enum",                      "BLOCKED_BY_WAF"),
    ("Layer 2 Isolation Forest",                       "Isolation Forest"),
    ("Layer 4 KS-test drift",                          "Kolmogorov-Smirnov"),
    ("Layer 4 Population Stability",                   "Population Stability"),
    ("Cloudflare cf_clearance",                        "cf_clearance"),
    ("Stealth init script",                            "navigator.webdriver"),
    ("Pure IEEE citation 'GoTestWAF [5]'",             "GoTestWAF [5]"),
    ("Mixed citation '(Wallarm [5])' removed",         "(Wallarm ["),  # should NOT appear
    ("Cohen kappa labelling",                          "Cohen's kappa"),
    ("ECE Expected Calibration Error",                 "Expected Calibration Error"),
    ("Concept drift retraining triggers",              "Retraining triggers"),
    ("Stacking-vs-bagging analysis",                   "Stacking-versus-bagging"),
    ("Two-phase labelling protocol",                   "two-phase protocol"),
    ("MITRE ATT&CK figure",                            "MITRE ATT&CK coverage"),
    ("Cyber kill-chain figure",                        "Cyber kill-chain"),
    ("Encoder x placement heatmap fig",                "encoder x placeholder bypass"),
]

print(f"{'Status':<8} {'Asked for':<48} {'Marker found?'}")
print("-" * 90)
for label, mk in markers:
    n = all_text.count(mk)
    if "removed" in label:
        ok = n == 0
    else:
        ok = n > 0
    sign = "OK" if ok else "MISS"
    print(f"[{sign:<6}] {label:<48} hits={n}")

# Algorithm pseudocode (was in build script, but stripped from docx)
algo_lines = sum(1 for p in paras if any(r.font.name == "Consolas" for r in p.runs))
print(f"\nAlgorithm pseudocode lines (Consolas) in docx: {algo_lines}")
print("  -> 0 means the 50-line Algorithm 1 + 30-line Algorithm 2 pseudocode")
print("     blocks are NOT in the docx; they live only in build script source.")
print("     User originally asked for these (turn 2-3); they were stripped to")
print("     fix Body Text font pollution. The flowchart in Fig 1 is the only")
print("     remaining algorithm visualisation in the docx output.")

# Figure ordering
cap_re = re.compile(r"^Fig\.\s+(\d+)\.\s")
fig_order = []
for p in paras:
    m = cap_re.match(p.text.strip())
    if m and p.style.name == "figure caption":
        fig_order.append(int(m.group(1)))
print(f"\nFigure document order: {fig_order}")
print("  IEEE convention: figures should appear in numerical order (1, 2, 3, ...)")
print(f"  Sorted = {sorted(fig_order)}")
print(f"  Same order? {'YES' if fig_order == sorted(fig_order) else 'NO -- non-monotonic'}")

# Page-count proxy
print(f"\nFile stats:")
print(f"  Paragraphs: {len(paras)}")
print(f"  Tables: {len(d.tables)}")
print(f"  Sections (sectPr): {sum(1 for _ in d.element.iter(W + 'sectPr'))}")
n_imgs = sum(len(r._element.findall('.//' + W + 'drawing')) for p in paras for r in p.runs)
print(f"  Inline images: {n_imgs}")
chars = sum(len(p.text) for p in paras)
print(f"  Total body chars: {chars:,}")
# Rough proxy: IEEE 2-col page typically holds ~5500 body chars, but with 27
# figures (some full-width and tall) total page count is figures-dominated.
est_pages = max(chars // 4500, 12) + n_imgs // 2
print(f"  ROUGH page estimate: ~{est_pages} pages (open Word for exact count)")

# Section IV order check
h1_order = [p.text.strip() for p in paras if p.style.name == "Heading 1" and p.text.strip()]
print(f"\nH1 section order: {h1_order}")

# Figure 3 location check
print(f"\nFigure 3 (Four-Layer Classifier) location check:")
current_h1 = current_h2 = ""
for p in paras:
    if p.style.name == "Heading 1":
        current_h1 = p.text.strip()
        current_h2 = ""
    elif p.style.name == "Heading 2":
        current_h2 = p.text.strip()
    if cap_re.match(p.text.strip()):
        m = cap_re.match(p.text.strip())
        if int(m.group(1)) == 3:
            print(f"  Fig 3 is in: {current_h1} > {current_h2}")
            print(f"  EXPECTED: Methodology > C. Phase 4: Four-Layer Response Classification Pipeline")
            break
