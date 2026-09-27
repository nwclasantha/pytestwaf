"""Apply P414 result-leak cleanup via direct XML editing.
Bypasses python-docx save to avoid the round-trip bug that previously
truncated P1, P4, P5 author/affiliation paragraphs.

Edits in P414:
  - run[2]: replace "per-class F1 above 0.9 on both the blocked and
            bypassed classes" with "per-class F1 reported in Section VII
            for both the blocked and bypassed classes"
  - run[6]: replace "discovered five novel bypass categories that the
            static base corpus does not exercise" with "discovered novel
            bypass categories (reported in Section VII) that the static
            base corpus does not exercise"
"""
import os, shutil, zipfile
from lxml import etree

CURRENT = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"
BACKUP  = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-p414-fix.docx"

if not os.path.exists(BACKUP):
    shutil.copy(CURRENT, BACKUP)
    print(f"Backup: {BACKUP}")

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W = f"{{{W_NS}}}"

with zipfile.ZipFile(CURRENT) as z:
    doc_xml = z.read("word/document.xml")

root = etree.fromstring(doc_xml)
body = root.find(f"{W}body")
paragraphs = [c for c in body if c.tag == f"{W}p"]
p414 = paragraphs[414]

runs = [r for r in p414 if r.tag == f"{W}r"]
print(f"P414 has {len(runs)} runs")

# Precondition checks (so we fail loudly if structure changed)
def get_text(run):
    t = run.find(f"{W}t")
    return t.text or "" if t is not None else ""


run2 = runs[2]
run6 = runs[6]

old2_phrase = "per-class F1 above 0.9 on both the blocked and bypassed classes"
new2_phrase = "per-class F1 reported in Section VII for both the blocked and bypassed classes"

old6_phrase = "discovered five novel bypass categories that the static base corpus does not exercise"
new6_phrase = "discovered novel bypass categories (reported in Section VII) that the static base corpus does not exercise"

t2 = run2.find(f"{W}t")
t6 = run6.find(f"{W}t")

assert t2 is not None and old2_phrase in (t2.text or ""), \
    f"P414 run[2] does not contain expected phrase. Got: {t2.text[:200]!r}"
assert t6 is not None and old6_phrase in (t6.text or ""), \
    f"P414 run[6] does not contain expected phrase. Got: {t6.text[:200]!r}"

t2.text = t2.text.replace(old2_phrase, new2_phrase)
t6.text = t6.text.replace(old6_phrase, new6_phrase)

# Verify
print("\nrun[2] after edit:")
print(f"  {t2.text}")
print("\nrun[6] after edit:")
print(f"  {t6.text}")

new_xml = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)

# Replace document.xml in zip
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

# Verify with python-docx
from docx import Document
d = Document(CURRENT)
print("\n=== Verification ===")
print(d.paragraphs[414].text)

# Sanity: check that previously preserved P1/P4/P5 are still intact
for i in [1, 4, 5]:
    print(f"\nP{i}: {d.paragraphs[i].text!r}")
