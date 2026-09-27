"""Apply Template.docx table border style to all 4 tables in the article.

Template style:
  - top: single, sz=8 (1 pt thick)
  - bottom: single, sz=8 (1 pt thick)
  - insideH: single, sz=4 (0.5 pt — thin separator between rows)
  - left, right, insideV: nil (no vertical lines, no outer side lines)

Bypasses python-docx; edits word/document.xml directly.
"""
import os, shutil, zipfile
from lxml import etree

CURRENT = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"
BACKUP  = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-template-borders.docx"

if not os.path.exists(BACKUP):
    shutil.copy(CURRENT, BACKUP)
    print(f"Backup: {BACKUP}")

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W = f"{{{W_NS}}}"

with zipfile.ZipFile(CURRENT) as z:
    doc_xml = z.read("word/document.xml")

root = etree.fromstring(doc_xml)


def make_border(tag_name, val, sz=None, color="auto"):
    elem = etree.SubElement(parent_dummy, f"{W}{tag_name}")
    elem.set(f"{W}val", val)
    if sz is not None:
        elem.set(f"{W}sz", str(sz))
        elem.set(f"{W}space", "0")
        elem.set(f"{W}color", color)
    return elem


# Find all top-level tables (skip any nested ones)
def iter_top_tables(elem):
    body = elem.find(f"{W}body")
    for child in body.iter(f"{W}tbl"):
        # check it's a top-level table (parent is body)
        if child.getparent().tag == f"{W}body":
            yield child


tables = list(iter_top_tables(root))
print(f"Found {len(tables)} top-level tables")

for ti, tbl in enumerate(tables):
    tblPr = tbl.find(f"{W}tblPr")
    if tblPr is None:
        print(f"Table {ti}: no tblPr, skipping")
        continue

    # Replace tblBorders with template style
    old_borders = tblPr.find(f"{W}tblBorders")
    if old_borders is not None:
        tblPr.remove(old_borders)

    # Build new tblBorders
    new_borders = etree.SubElement(tblPr, f"{W}tblBorders")

    def add_border(parent, tag, val, sz=None):
        e = etree.SubElement(parent, f"{W}{tag}")
        e.set(f"{W}val", val)
        if sz is not None:
            e.set(f"{W}sz", str(sz))
            e.set(f"{W}space", "0")
            e.set(f"{W}color", "auto")

    add_border(new_borders, "top",     "single", 8)
    add_border(new_borders, "left",    "nil")
    add_border(new_borders, "bottom",  "single", 8)
    add_border(new_borders, "right",   "nil")
    add_border(new_borders, "insideH", "single", 4)
    add_border(new_borders, "insideV", "nil")

    # Move tblBorders to the conventional position (after tblStyle / tblW
    # but before tblLook, etc.)
    # Reorder children: tblStyle, tblW, tblLayout, tblBorders, tblLook, ...
    # Simpler: just place it before tblLook if present
    tblLook = tblPr.find(f"{W}tblLook")
    if tblLook is not None and new_borders.getnext() is not tblLook:
        # Move new_borders to be right before tblLook
        tblPr.remove(new_borders)
        tblLook.addprevious(new_borders)

    # Defensive: also clear any cell-level tcBorders that would override
    # the table-level borders (e.g. coming from firstRow conditional style).
    for tc in tbl.iter(f"{W}tc"):
        tcPr = tc.find(f"{W}tcPr")
        if tcPr is not None:
            tcBorders = tcPr.find(f"{W}tcBorders")
            if tcBorders is not None:
                tcPr.remove(tcBorders)

    print(f"Table {ti}: borders rewritten to template style; cell tcBorders cleared")

# Write back
new_xml = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
TMP = CURRENT + ".tmp"
with zipfile.ZipFile(CURRENT) as zin:
    with zipfile.ZipFile(TMP, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == "word/document.xml":
                zout.writestr(item, new_xml)
            else:
                zout.writestr(item, zin.read(item.filename))

shutil.move(TMP, CURRENT)
print(f"\nWrote: {CURRENT}")

# Verify with python-docx (read-only check)
from docx import Document
from docx.oxml.ns import qn
d = Document(CURRENT)
print("\n=== Verification ===")
for ti, table in enumerate(d.tables):
    tblPr = table._element.find(qn('w:tblPr'))
    tblBorders = tblPr.find(qn('w:tblBorders'))
    if tblBorders is not None:
        print(f"Table {ti} borders:")
        for child in tblBorders:
            tag = child.tag.split('}')[1]
            print(f"  {tag}: val={child.get(qn('w:val'))} sz={child.get(qn('w:sz'))}")
    headers = [c.text for c in table.rows[0].cells]
    print(f"  headers: {headers[:4]}")
