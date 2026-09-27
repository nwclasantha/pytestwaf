"""Split Table I aggregated rows R14 (9 foundational ML papers) and R15
(5 WAF testing tools) into individual one-per-paper rows.

Approach: clone the existing R14 (or R15) <w:tr> element 8 times (or 4
times) using deepcopy, then rewrite each clone's cell texts with the
per-paper content. The original aggregated row is removed.

Each new row preserves Table I's existing tr/tc XML structure (margins,
borders, etc.) so it inherits the table's visual style automatically.
"""
import os, shutil, zipfile, re, sys
sys.stdout.reconfigure(encoding="utf-8")
from copy import deepcopy
from lxml import etree

CURRENT = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"
BACKUP  = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-split-rows.docx"

if not os.path.exists(BACKUP):
    shutil.copy(CURRENT, BACKUP)
    print(f"Backup: {BACKUP}")

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W = f"{{{W_NS}}}"

try:
    with open(CURRENT, 'a'): pass
except PermissionError:
    print("File locked; close it in Word."); raise SystemExit(1)

with zipfile.ZipFile(CURRENT) as z:
    doc_xml = z.read("word/document.xml")
root = etree.fromstring(doc_xml)
body = root.find(f"{W}body")


def text_of(elem):
    return "".join(t.text or "" for t in elem.iter(f"{W}t"))


# Build refs map from references list
refs = {}
in_refs = False
for p in body.iter(f"{W}p"):
    pStyle = p.find(f"{W}pPr/{W}pStyle")
    style_val = pStyle.get(f"{W}val") if pStyle is not None else ""
    full = text_of(p).strip()
    if full == "References" and style_val.startswith("Heading"):
        in_refs = True; continue
    if in_refs:
        m = re.match(r"\[(\d+)\]\s*(.*)", full)
        if m:
            refs[int(m.group(1))] = m.group(2)
        elif refs and full and not re.match(r"\[\d+\]", full):
            break


def extract_title(bib):
    m = re.search(r'[“"]([^”"]+?)[”"]', bib)
    if m:
        return m.group(1).rstrip(",.;:")
    # books may not have quotes — fallback: text between commas
    m2 = re.match(r"^[^,]+,\s*(.+?)\.", bib)
    if m2:
        return m2.group(1).strip()
    return bib[:80]


# Per-paper content for the 9 split rows of original R14 (Foundational ML)
SPLIT_R14 = [
    # (cite_num, contribution, technology, remarks)
    (46, "Scikit-learn machine learning library for Python",
         "Python; ensemble, calibration, cross-validation utilities",
         "Provides the stacking, calibration, and CV utilities used by the proposed framework"),
    (47, "Original formulation of stacked generalization",
         "Stacked generalization (meta-learning)",
         "Theoretical basis for the stacking ensemble in the proposed framework"),
    (48, "Empirical study of probability calibration methods",
         "Isotonic regression and Platt scaling",
         "Motivates the isotonic calibration wrapper used in this research"),
    (49, "Foundational Random Forest algorithm",
         "Random Forest ensemble",
         "Random Forest is one of the base estimators in the stacking ensemble"),
    (50, "Gradient Boosting Machine formulation",
         "Gradient Boosting (GBM)",
         "Gradient Boosting is one of the base estimators in the stacking ensemble"),
    (51, "Statistical learning textbook (ESL)",
         "Reference for ensemble methods, regularization, and CV",
         "Theoretical reference for ensemble selection and bias-variance trade-offs"),
    (52, "Extremely Randomized Trees (Extra Trees)",
         "Extra Trees ensemble",
         "Alternative ensemble baseline; ERT compared against RF in the stacking design"),
    (53, "Deep Learning textbook",
         "Reference for MLP, autoencoders, and training",
         "Theoretical reference for the MLP base estimator and the autoencoder layer"),
    (54, "Empirical analysis of miscalibration in modern neural networks",
         "Calibration of modern neural networks",
         "Motivates the explicit isotonic calibration of the deep base estimator"),
]

# Per-tool content for the 5 split rows of original R15 (WAF testing tools)
SPLIT_R15 = [
    (55, "Open-source WAF testing tool exercising a fixed YAML payload corpus",
         "Go; YAML payload corpus",
         "Static corpus, no learning loop, no calibrated probability, no multi-cloud IaC"),
    (56, "WAF fingerprinting tool that identifies vendor by response signature",
         "Python; deterministic regex",
         "Vendor identification only; sends no attack payloads and produces no remediation"),
    (57, "YAML-template based vulnerability scanner",
         "Go; signature/YAML templates",
         "Templates fire as written; no adaptive mutation; no remediation generator"),
    (58, "Open-source web application security scanner",
         "Java; active and passive scanning",
         "Operator-scripted scan policies; HTML/XML/JSON report; no calibrated probability"),
    (59, "Commercial intercepting proxy with manual fuzzing capabilities",
         "Java; Intruder fuzzing",
         "Operator interprets findings; no IaC output; no model persistence"),
]

# Locate Table I (first top-level table in the body)
tables = [c for c in body if c.tag == f"{W}tbl"]
table0 = tables[0]
rows = [c for c in table0 if c.tag == f"{W}tr"]
print(f"Table I has {len(rows)} rows")

# We want to find rows by content (more robust than indices, in case rows
# moved). Search for the row whose first cell contains "Pedregosa et al."
r14_idx = None
r15_idx = None
for ri, tr in enumerate(rows):
    txt = text_of(tr)
    if "Pedregosa" in txt and r14_idx is None:
        r14_idx = ri
    elif "GoTestWAF" in txt and r15_idx is None:
        r15_idx = ri

print(f"Identified R14 at index {r14_idx}, R15 at index {r15_idx}")
assert r14_idx is not None and r15_idx is not None


def replace_cell_paragraph(cell_elem, text):
    """Replace the first paragraph in cell with a single run containing text.
    Preserves pPr (paragraph properties)."""
    p = cell_elem.find(f"{W}p")
    if p is None:
        return
    # Keep pPr, drop other children
    pPr = p.find(f"{W}pPr")
    for child in list(p):
        if child is not pPr:
            p.remove(child)
    r = etree.SubElement(p, f"{W}r")
    t = etree.SubElement(r, f"{W}t")
    t.text = text
    t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    # Remove any extra paragraphs
    for extra in cell_elem.findall(f"{W}p")[1:]:
        cell_elem.remove(extra)


def build_split_rows(template_tr, replacements):
    """For each tuple in replacements, clone template_tr and fill its 4 cells.
    replacements: list of (cite, contribution, technology, remarks)."""
    new_trs = []
    for cite, contrib, tech, rem in replacements:
        bib = refs.get(cite, "")
        title = extract_title(bib)
        work_text = f"{title} [{cite}]"
        clone = deepcopy(template_tr)
        cells = [c for c in clone if c.tag == f"{W}tc"]
        if len(cells) < 4:
            print(f"  WARNING: row clone has only {len(cells)} cells")
            continue
        replace_cell_paragraph(cells[0], work_text)
        replace_cell_paragraph(cells[1], contrib)
        replace_cell_paragraph(cells[2], tech)
        replace_cell_paragraph(cells[3], rem)
        new_trs.append(clone)
    return new_trs


# Build replacement rows
new_rows_for_r14 = build_split_rows(rows[r14_idx], SPLIT_R14)
new_rows_for_r15 = build_split_rows(rows[r15_idx], SPLIT_R15)
print(f"Built {len(new_rows_for_r14)} replacement rows for R14, "
      f"{len(new_rows_for_r15)} for R15")

# Insert in document order. Strategy: replace R14's element with the 9 new
# rows, then replace R15's element with the 5 new rows. We must do this
# without breaking citation occurrence positions, and the simplest way is to
# do the replacements in REVERSE document order (R15 first, then R14) so
# that the indices/positions of earlier elements aren't disturbed.

# Replace R15 first (later in document)
parent = table0
old_r15 = rows[r15_idx]
idx_in_parent = list(parent).index(old_r15)
parent.remove(old_r15)
for offset, new_tr in enumerate(new_rows_for_r15):
    parent.insert(idx_in_parent + offset, new_tr)
print(f"Replaced R15 with {len(new_rows_for_r15)} rows")

# Re-fetch rows after R15 changes
rows = [c for c in table0 if c.tag == f"{W}tr"]

# Replace R14
old_r14 = None
for tr in rows:
    if "Pedregosa" in text_of(tr):
        old_r14 = tr; break
assert old_r14 is not None
idx_in_parent = list(parent).index(old_r14)
parent.remove(old_r14)
for offset, new_tr in enumerate(new_rows_for_r14):
    parent.insert(idx_in_parent + offset, new_tr)
print(f"Replaced R14 with {len(new_rows_for_r14)} rows")

# Write back
new_xml = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
TMP = CURRENT + ".tmp"
if os.path.exists(TMP): os.remove(TMP)
with zipfile.ZipFile(CURRENT) as zin:
    with zipfile.ZipFile(TMP, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == "word/document.xml":
                zout.writestr(item, new_xml)
            else:
                zout.writestr(item, zin.read(item.filename))
os.replace(TMP, CURRENT)
print(f"\nSaved: {CURRENT}")

# Verify
from docx import Document
d = Document(CURRENT)
print(f"\nTable I now has {len(d.tables[0].rows)} rows:")
for ri, row in enumerate(d.tables[0].rows):
    print(f"  R{ri}C0: {row.cells[0].text[:100]}")
