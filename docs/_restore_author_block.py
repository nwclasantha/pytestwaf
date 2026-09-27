"""Restore P1, P4, P5 (author byline + 3rd affiliation + emails) from the
good backup into the current docx, by editing word/document.xml directly.

Bypasses python-docx round-trip to avoid any further corruption."""
import os, shutil, zipfile, io
from lxml import etree

CURRENT = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"
GOOD    = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-results-cleanup.docx"
BACKUP  = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-author-restore.docx"

if not os.path.exists(BACKUP):
    shutil.copy(CURRENT, BACKUP)
    print(f"Backup written: {BACKUP}")

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W = f"{{{W_NS}}}"


def read_doc_xml(path):
    with zipfile.ZipFile(path) as z:
        return z.read("word/document.xml")


def parse(xml_bytes):
    return etree.fromstring(xml_bytes)


def get_body_paragraphs(root):
    body = root.find(f"{W}body")
    return [child for child in body if child.tag == f"{W}p"]


good_root = parse(read_doc_xml(GOOD))
cur_root  = parse(read_doc_xml(CURRENT))

good_paras = get_body_paragraphs(good_root)
cur_paras  = get_body_paragraphs(cur_root)
print(f"Body paragraph count — GOOD: {len(good_paras)}, CURRENT: {len(cur_paras)}")
assert len(good_paras) == len(cur_paras), "paragraph count mismatch — abort"


def para_text(p):
    return "".join(t.text or "" for t in p.iter(f"{W}t"))


# Replace the corrupted paragraphs (1, 4, 5) with the good ones.
TARGETS = [1, 4, 5]
for i in TARGETS:
    print(f"\n--- P{i} ---")
    print(f"  CURRENT before: {para_text(cur_paras[i])!r}")
    print(f"  GOOD wanted:    {para_text(good_paras[i])!r}")

# Replace each in the cur_root tree
body = cur_root.find(f"{W}body")
# Build child index list (only top-level children; some may be sectPr etc.)
top_children = list(body)
# Map paragraph index (within only <w:p> children) to its position in top_children
p_positions = []
for idx, child in enumerate(top_children):
    if child.tag == f"{W}p":
        p_positions.append(idx)
assert len(p_positions) == len(cur_paras)

for i in TARGETS:
    pos_in_body = p_positions[i]
    old_p = top_children[pos_in_body]
    new_p = etree.fromstring(etree.tostring(good_paras[i]))  # deep copy via serialize/parse
    body.replace(old_p, new_p)
    top_children[pos_in_body] = new_p

# Verify in-memory tree
new_paras = get_body_paragraphs(cur_root)
for i in TARGETS:
    print(f"  P{i} after replacement: {para_text(new_paras[i])!r}")

new_doc_xml = etree.tostring(
    cur_root, xml_declaration=True, encoding="UTF-8", standalone=True
)

# Write back: copy the zip, replacing only word/document.xml
TMP = CURRENT + ".tmp"
with zipfile.ZipFile(CURRENT) as zin:
    with zipfile.ZipFile(TMP, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            if item.filename == "word/document.xml":
                zout.writestr(item, new_doc_xml)
            else:
                zout.writestr(item, zin.read(item.filename))

shutil.move(TMP, CURRENT)
print(f"\nWrote restored XML into: {CURRENT}")

# Re-read and confirm via python-docx
from docx import Document
d = Document(CURRENT)
print("\n=== Re-loaded via python-docx ===")
for i in TARGETS:
    print(f"  P{i}: {d.paragraphs[i].text!r}")
