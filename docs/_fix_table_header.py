"""Change Table II first-column header from 'Title' to 'Work' to match
Table I and the journal example."""
import os, shutil, zipfile
from lxml import etree

CURRENT = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"
BACKUP  = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-table2-header.docx"

if not os.path.exists(BACKUP):
    shutil.copy(CURRENT, BACKUP)
    print(f"Backup: {BACKUP}")

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W = f"{{{W_NS}}}"

with zipfile.ZipFile(CURRENT) as z:
    doc_xml = z.read("word/document.xml")

root = etree.fromstring(doc_xml)
body = root.find(f"{W}body")

# Find tables in document order
tables = [c for c in body.iter(f"{W}tbl")]
print(f"Found {len(tables)} tables")

# Table index 1 (second table)
target_table = tables[1]
# First row, first cell, find <w:t> with text "Title"
first_row = next(target_table.iterchildren(f"{W}tr"))
first_cell = next(first_row.iterchildren(f"{W}tc"))
t_elements = list(first_cell.iter(f"{W}t"))
changed = False
for t in t_elements:
    if (t.text or "").strip() == "Title":
        print(f"Found 'Title' in cell, changing to 'Work'")
        t.text = "Work"
        changed = True
        break

assert changed, "Did not find 'Title' header text in Table II first cell"

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
print(f"Wrote: {CURRENT}")

# Verify
from docx import Document
d = Document(CURRENT)
for ti, table in enumerate(d.tables):
    headers = [cell.text for cell in table.rows[0].cells]
    print(f"Table {ti} headers: {headers}")
