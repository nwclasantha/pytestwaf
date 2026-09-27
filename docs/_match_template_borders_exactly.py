"""Match Template.docx tblBorders EXACTLY by omitting (not nil-ing) the
unused border directions.

Template Table 1 tblBorders:
    <w:tblBorders>
      <w:top w:val="single" w:sz="8" .../>
      <w:bottom w:val="single" w:sz="8" .../>
      <w:insideH w:val="single" w:sz="4" .../>
    </w:tblBorders>

Note the absence of <w:left>, <w:right>, <w:insideV> (i.e. they are not
present at all, rather than present with val="nil").

This script also adds explicit per-cell tcBorders matching Template Table 1:
  - Header row cells: top=single sz=8, bottom=single sz=4, left/right=nil
  - Data row cells:  top=single sz=4, bottom=single sz=4, left/right=nil

Both the tblBorders simplification and explicit per-cell tcBorders ensure
Word renders no vertical lines under any inheritance path.
"""
import os, shutil, zipfile, sys
sys.stdout.reconfigure(encoding="utf-8")
from lxml import etree

CURRENT = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"
BACKUP  = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-strict-borders.docx"

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


def add(parent, tag, **attrs):
    e = etree.SubElement(parent, f"{W}{tag}")
    for k, v in attrs.items():
        e.set(f"{W}{k}", v)
    return e


tables = [c for c in body if c.tag == f"{W}tbl"]
print(f"Found {len(tables)} top-level tables")

for ti, tbl in enumerate(tables):
    tblPr = tbl.find(f"{W}tblPr")

    # 1. Replace tblBorders with template-exact (only top, bottom, insideH)
    old = tblPr.find(f"{W}tblBorders")
    if old is not None:
        tblPr.remove(old)
    new_borders = etree.Element(f"{W}tblBorders")
    add(new_borders, "top",     val="single", sz="8", space="0", color="auto")
    add(new_borders, "bottom",  val="single", sz="8", space="0", color="auto")
    add(new_borders, "insideH", val="single", sz="4", space="0", color="auto")
    # Insert in the spec-correct position: after tblLayout / before tblLook
    tblLook = tblPr.find(f"{W}tblLook")
    if tblLook is not None:
        tblLook.addprevious(new_borders)
    else:
        tblPr.append(new_borders)

    # 2. For every cell, set explicit tcBorders that suppress all vertical
    #    lines and define the horizontal line style.
    rows = list(tbl.iter(f"{W}tr"))
    for ri, tr in enumerate(rows):
        is_header = (ri == 0)
        is_last = (ri == len(rows) - 1)
        for tc in tr.iter(f"{W}tc"):
            tcPr = tc.find(f"{W}tcPr")
            if tcPr is None:
                tcPr = etree.Element(f"{W}tcPr")
                tc.insert(0, tcPr)
            # remove existing tcBorders
            old_tcb = tcPr.find(f"{W}tcBorders")
            if old_tcb is not None:
                tcPr.remove(old_tcb)
            tcBorders = etree.Element(f"{W}tcBorders")
            if is_header:
                # Header row: thicker top (sz=8), thinner bottom (sz=4)
                add(tcBorders, "top", val="single", sz="8", space="0", color="auto")
                add(tcBorders, "left", val="nil")
                add(tcBorders, "bottom", val="single", sz="4", space="0", color="auto")
                add(tcBorders, "right", val="nil")
            elif is_last:
                # Last row: thinner top (sz=4), thicker bottom (sz=8)
                add(tcBorders, "top", val="single", sz="4", space="0", color="auto")
                add(tcBorders, "left", val="nil")
                add(tcBorders, "bottom", val="single", sz="8", space="0", color="auto")
                add(tcBorders, "right", val="nil")
            else:
                # Middle data rows: thin (sz=4) top and bottom
                add(tcBorders, "top", val="single", sz="4", space="0", color="auto")
                add(tcBorders, "left", val="nil")
                add(tcBorders, "bottom", val="single", sz="4", space="0", color="auto")
                add(tcBorders, "right", val="nil")
            # Insert tcBorders into tcPr in proper position
            # tcPr child order: cnfStyle, tcW, gridSpan, hMerge, vMerge,
            # tcBorders, shd, noWrap, tcMar, textDirection, ...
            # Find where tcW ends and insert tcBorders right after it
            inserted = False
            for child in tcPr:
                local = child.tag.split('}')[1]
                if local in ("hideMark", "shd", "noWrap", "tcMar", "vAlign"):
                    child.addprevious(tcBorders)
                    inserted = True
                    break
            if not inserted:
                tcPr.append(tcBorders)
    print(f"T{ti}: simplified tblBorders + set per-cell tcBorders on "
          f"{len(rows)} rows")

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
from docx.oxml.ns import qn
d = Document(CURRENT)
print("\n=== Verification ===")
for ti, table in enumerate(d.tables):
    tblBorders = table._element.find(f"{qn('w:tblPr')}/{qn('w:tblBorders')}")
    if tblBorders is not None:
        kinds = [child.tag.split('}')[1] for child in tblBorders]
        print(f"Table {ti} tblBorders directions: {kinds}")
    # sample cell borders
    sample = table.rows[1].cells[0] if len(table.rows) > 1 else None
    if sample is not None:
        tcBorders = sample._element.find(f"{qn('w:tcPr')}/{qn('w:tcBorders')}")
        if tcBorders is not None:
            for child in tcBorders:
                tag = child.tag.split('}')[1]
                print(f"  R1C0.{tag}: val={child.get(qn('w:val'))} sz={child.get(qn('w:sz'))}")
