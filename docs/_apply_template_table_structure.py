"""Bring all 4 article tables into structural alignment with Template.docx.

Changes (applied per top-level table, via direct XML editing):
  1. Remove <w:tblStyle> reference (GridTable1Light) — Template uses no style.
  2. Add <w:jc w:val="center"/> at the table level (tblPr) — center the table.
  3. Set <w:tblLook> to 04A0 with firstRow=1, firstCol=1, lastCol=0, noVBand=1
     (matches Template; harmless because no style is referenced).
  4. Strip <w:cnfStyle> from every <w:tr> and <w:tc> (legacy from the removed
     style; Template has none).
  5. Add <w:hideMark/> to every <w:tcPr> if missing (cosmetic — matches
     Template Table 1; lets row heights collapse around content).
  6. Add an explicit <w:b/> to every run in the header row (row 0). The bold
     was previously coming from the table style's firstRow conditional rPr;
     once the style is gone we must mark bold directly.

NOT changed:
  - Table-level <w:tblBorders> (already set to Template style by previous run:
    top=8, bottom=8, insideH=4, left/right/insideV=nil).
  - Data cell paragraph properties — preserved to avoid breaking existing
    formatting (citations, italics, etc.).
"""
import os, shutil, zipfile
from lxml import etree

CURRENT = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"
BACKUP  = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-template-structure.docx"

if not os.path.exists(BACKUP):
    shutil.copy(CURRENT, BACKUP)
    print(f"Backup: {BACKUP}")

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W = f"{{{W_NS}}}"

# Confirm not locked
try:
    with open(CURRENT, 'a'):
        pass
except PermissionError:
    print("File locked; close it in Word.")
    raise SystemExit(1)

with zipfile.ZipFile(CURRENT) as z:
    doc_xml = z.read("word/document.xml")

root = etree.fromstring(doc_xml)
body = root.find(f"{W}body")


def iter_top_tables(body_elem):
    for child in body_elem:
        if child.tag == f"{W}tbl":
            yield child


def reorder_tblPr_children(tblPr):
    """Word expects a specific order: tblStyle, tblpPr, tblOverlap, bidiVisual,
    tblStyleRowBandSize, tblStyleColBandSize, tblW, jc, tblCellSpacing,
    tblInd, tblBorders, shd, tblLayout, tblCellMar, tblLook, tblCaption,
    tblDescription, tblPrChange. Reordering is defensive — preserves any
    existing children but in spec order."""
    desired = [
        "tblStyle", "tblpPr", "tblOverlap", "bidiVisual",
        "tblStyleRowBandSize", "tblStyleColBandSize", "tblW", "jc",
        "tblCellSpacing", "tblInd", "tblBorders", "shd", "tblLayout",
        "tblCellMar", "tblLook", "tblCaption", "tblDescription",
        "tblPrChange",
    ]
    children = list(tblPr)
    by_name = {}
    for c in children:
        local = c.tag.split('}')[1]
        by_name.setdefault(local, []).append(c)
        tblPr.remove(c)
    for name in desired:
        for el in by_name.pop(name, []):
            tblPr.append(el)
    # append anything left over (unknown elements) at the end
    for name, els in by_name.items():
        for el in els:
            tblPr.append(el)


tables = list(iter_top_tables(body))
print(f"Found {len(tables)} top-level tables")

for ti, tbl in enumerate(tables):
    tblPr = tbl.find(f"{W}tblPr")
    if tblPr is None:
        print(f"Table {ti}: no tblPr"); continue

    # 1. Remove tblStyle reference
    tblStyle = tblPr.find(f"{W}tblStyle")
    if tblStyle is not None:
        tblPr.remove(tblStyle)
        print(f"  T{ti}: removed tblStyle")

    # 2. Ensure jc=center (insert if absent)
    jc = tblPr.find(f"{W}jc")
    if jc is None:
        jc = etree.SubElement(tblPr, f"{W}jc")
        jc.set(f"{W}val", "center")
        print(f"  T{ti}: added jc=center")
    else:
        jc.set(f"{W}val", "center")

    # 3. Set tblLook to Template values
    tblLook = tblPr.find(f"{W}tblLook")
    if tblLook is None:
        tblLook = etree.SubElement(tblPr, f"{W}tblLook")
    tblLook.set(f"{W}val", "04A0")
    tblLook.set(f"{W}firstRow", "1")
    tblLook.set(f"{W}lastRow", "0")
    tblLook.set(f"{W}firstColumn", "1")
    tblLook.set(f"{W}lastColumn", "0")
    tblLook.set(f"{W}noHBand", "0")
    tblLook.set(f"{W}noVBand", "1")

    reorder_tblPr_children(tblPr)

    # 4. Strip cnfStyle from rows and cells
    cnf_count = 0
    for tr in tbl.iter(f"{W}tr"):
        trPr = tr.find(f"{W}trPr")
        if trPr is not None:
            cnf = trPr.find(f"{W}cnfStyle")
            if cnf is not None:
                trPr.remove(cnf); cnf_count += 1
            # If trPr is now empty, remove it (cosmetic)
            if len(list(trPr)) == 0:
                tr.remove(trPr)
    for tc in tbl.iter(f"{W}tc"):
        tcPr = tc.find(f"{W}tcPr")
        if tcPr is not None:
            cnf = tcPr.find(f"{W}cnfStyle")
            if cnf is not None:
                tcPr.remove(cnf); cnf_count += 1
    print(f"  T{ti}: stripped {cnf_count} cnfStyle elements")

    # 5. Add hideMark to every tcPr
    hm_count = 0
    for tc in tbl.iter(f"{W}tc"):
        tcPr = tc.find(f"{W}tcPr")
        if tcPr is None:
            tcPr = etree.Element(f"{W}tcPr")
            tc.insert(0, tcPr)
        if tcPr.find(f"{W}hideMark") is None:
            etree.SubElement(tcPr, f"{W}hideMark")
            hm_count += 1
    print(f"  T{ti}: added hideMark to {hm_count} cells")

    # 6. Add explicit <w:b/> to every run in row 0 (header)
    bold_count = 0
    rows = list(tbl.iter(f"{W}tr"))
    if rows:
        header_row = rows[0]
        for r in header_row.iter(f"{W}r"):
            rPr = r.find(f"{W}rPr")
            if rPr is None:
                rPr = etree.Element(f"{W}rPr")
                r.insert(0, rPr)
            if rPr.find(f"{W}b") is None:
                # Insert <w:b/> as the first child of rPr (XML schema order)
                b = etree.Element(f"{W}b")
                rPr.insert(0, b)
                bold_count += 1
        print(f"  T{ti}: added <w:b/> to {bold_count} header runs")


# Write back
new_xml = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
TMP = CURRENT + ".tmp"
# clean any stale tmp
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
print(f"\nWrote: {CURRENT}")

# Verify
from docx import Document
from docx.oxml.ns import qn
d = Document(CURRENT)
print("\n=== Verification ===")
for ti, table in enumerate(d.tables):
    tblPr = table._element.find(qn('w:tblPr'))
    has_style = tblPr.find(qn('w:tblStyle')) is not None
    has_jc = tblPr.find(qn('w:jc'))
    jc_val = has_jc.get(qn('w:val')) if has_jc is not None else None
    headers = [c.text for c in table.rows[0].cells]
    # Check first header run for bold
    first_run = table.rows[0].cells[0].paragraphs[0].runs[0]
    rPr = first_run._element.find(qn('w:rPr'))
    has_bold = rPr is not None and rPr.find(qn('w:b')) is not None
    print(f"Table {ti}: tblStyle={has_style}, jc={jc_val}, hdrBold={has_bold}, "
          f"hdrs={headers[:4]}")
