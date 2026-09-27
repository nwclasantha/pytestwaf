"""Replace author-name labels in Table I (R1..R13) and Table II (R1..R11)
Work column with the full paper title + citation, matching IEEE / Template.docx
style.

Leaves untouched:
  - Table I R0 (header), R14, R15 (aggregated foundational/tools lists), R16
    ('This research')
  - Table II R0 (header), R12 ('This research')
"""
import os, shutil, zipfile, re, sys
sys.stdout.reconfigure(encoding="utf-8")
from lxml import etree

CURRENT = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"
BACKUP  = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-ieee-titles.docx"

if not os.path.exists(BACKUP):
    shutil.copy(CURRENT, BACKUP)
    print(f"Backup: {BACKUP}")

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W = f"{{{W_NS}}}"

with zipfile.ZipFile(CURRENT) as z:
    doc_xml = z.read("word/document.xml")

root = etree.fromstring(doc_xml)
body = root.find(f"{W}body")


def text_of(elem):
    return "".join(t.text or "" for t in elem.iter(f"{W}t"))


# Build refs: citation number -> bibliographic text
# References are paragraphs in document order with style=references; first
# capture them regardless of style.
def get_refs():
    out = {}
    in_refs = False
    for p in body.iter(f"{W}p"):
        # detect "References" heading
        pStyle = p.find(f"{W}pPr/{W}pStyle")
        style_val = pStyle.get(f"{W}val") if pStyle is not None else ""
        full = text_of(p).strip()
        if full == "References" and style_val.startswith("Heading"):
            in_refs = True; continue
        if in_refs:
            m = re.match(r"\[(\d+)\]\s*(.*)", full)
            if m:
                out[int(m.group(1))] = m.group(2)
            elif full == "":
                continue
            else:
                # stop at first non-reference paragraph encountered after refs
                # Heuristic: if we've collected refs and hit something that
                # doesn't start with [N], we're done.
                if out: break
    return out


refs = get_refs()
print(f"Loaded {len(refs)} reference entries")


def extract_title(bib):
    m = re.search(r'[“"]([^”"]+?)[”"]', bib)
    if m:
        title = m.group(1)
        # strip trailing comma/period that's commonly inside the IEEE quote
        title = title.rstrip(",.;:")
        return title
    return None


# Find all top-level tables
tables = [c for c in body if c.tag == f"{W}tbl"]
print(f"Found {len(tables)} top-level tables")

# Tables to edit:
#   table 0 = Table I (Lit Review): rows 1..13 (last data rows are 14,15,16 we skip)
#   table 1 = Table II (Comparison): rows 1..11 (row 12 = This research, skip)
TARGETS = {
    0: list(range(1, 14)),
    1: list(range(1, 12)),
}


def replace_cell_text(cell_elem, new_text):
    """Replace the cell's first paragraph text with new_text, preserving
    paragraph-level styling. Clears any extra runs/paragraphs in the cell."""
    # Find the first <w:p> in this cell
    p_first = cell_elem.find(f"{W}p")
    if p_first is None:
        return
    # Remove all children of p_first except its pPr
    pPr = p_first.find(f"{W}pPr")
    for child in list(p_first):
        if child is not pPr:
            p_first.remove(child)
    # Append a single run with new_text
    r = etree.SubElement(p_first, f"{W}r")
    t = etree.SubElement(r, f"{W}t")
    t.text = new_text
    t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    # Remove additional paragraphs in the same cell
    for extra_p in cell_elem.findall(f"{W}p")[1:]:
        cell_elem.remove(extra_p)


changes = []
for ti, row_indices in TARGETS.items():
    tbl = tables[ti]
    rows = list(tbl.iter(f"{W}tr"))
    for ri in row_indices:
        if ri >= len(rows): continue
        row = rows[ri]
        cells = [c for c in row if c.tag == f"{W}tc"]
        cell0 = cells[0]
        old_text = text_of(cell0).strip()
        m = re.search(r"\[(\d+)\]", old_text)
        if not m:
            print(f"  T{ti}.R{ri}: no [N] found in {old_text!r}; skipping")
            continue
        n = int(m.group(1))
        bib = refs.get(n)
        if not bib:
            print(f"  T{ti}.R{ri}: ref [{n}] not in bibliography; skipping")
            continue
        title = extract_title(bib)
        if not title:
            print(f"  T{ti}.R{ri}: could not extract title from bib; skipping")
            continue
        new_text = f"{title} [{n}]"
        replace_cell_text(cell0, new_text)
        changes.append((ti, ri, old_text, new_text))
        print(f"  T{ti}.R{ri}: {old_text!r} → {new_text[:60]!r}…")

# Write back
new_xml = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
TMP = CURRENT + ".tmp"
if os.path.exists(TMP):
    os.remove(TMP)
with zipfile.ZipFile(CURRENT) as zin:
    with zipfile.ZipFile(TMP, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == "word/document.xml":
                zout.writestr(item, new_xml)
            else:
                zout.writestr(item, zin.read(item.filename))
os.replace(TMP, CURRENT)

print(f"\nApplied {len(changes)} title replacements")
print(f"Saved: {CURRENT}")

# Verify
from docx import Document
d = Document(CURRENT)
print("\n=== Verification — Table I Work column ===")
for ri in range(min(8, len(d.tables[0].rows))):
    print(f"  R{ri}: {d.tables[0].rows[ri].cells[0].text[:120]}")
print("\n=== Verification — Table II Work column ===")
for ri in range(min(8, len(d.tables[1].rows))):
    print(f"  R{ri}: {d.tables[1].rows[ri].cells[0].text[:120]}")
