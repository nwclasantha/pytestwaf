"""Assign every citation OCCURRENCE a unique sequential number.

Starting state: pytestwaf-research-article.docx is sequential by
first-appearance (1..34 cited, 35..50 uncited). This script transforms it so
that EACH occurrence of a citation in the body+tables gets a unique new
number (1, 2, 3, ...). The references list is rebuilt so that:
  * For each occurrence k=1..M, references entry [k] reproduces the
    bibliographic text of whatever paper was cited at occurrence k.
  * After M, the 16 uncited references are appended in their current order
    with numbers [M+1], [M+2], ...
"""
from docx import Document
from docx.oxml.ns import qn
from copy import deepcopy
import re
import shutil
import os

src = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"
backup = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-uniqueocc.docx"

if not os.path.exists(backup):
    shutil.copy(src, backup)
    print(f"Backup written: {backup}")
else:
    print(f"Backup already exists: {backup}")

doc = Document(src)
body = doc.element.body
all_paras = doc.paragraphs

# Locate References heading
ref_para_idx = None
for i, p in enumerate(all_paras):
    if p.text.strip() == "References" and p.style.name.startswith("Heading"):
        ref_para_idx = i
        break
ref_heading_el = all_paras[ref_para_idx]._element

# Reference list paragraphs (style 'references')
ref_paragraphs = []
for i in range(ref_para_idx + 1, len(all_paras)):
    p = all_paras[i]
    if p.style.name == "references":
        ref_paragraphs.append(p)
    elif p.text.strip() == "":
        continue
    else:
        break
print(f"Reference list contains {len(ref_paragraphs)} entries")

# Build map from current ref number -> bibliographic text after the [N] prefix
ref_text_by_num = {}
for p in ref_paragraphs:
    m = re.match(r"\[(\d+)\]\s*(.*)", p.text.strip())
    if m:
        ref_text_by_num[int(m.group(1))] = m.group(2)

# Identify cited vs uncited based on the current first-appearance ordering.
# Walk doc to find which numbers actually appear in body/tables.
def iter_paragraphs_in_doc_order(parent_el, stop_at_element):
    def walk(element):
        for child in element.iterchildren():
            if child is stop_at_element:
                yield ("STOP",)
                return
            tag = child.tag
            if tag == qn("w:p"):
                yield ("p", child)
            elif tag == qn("w:tbl"):
                for tr in child.iterchildren(qn("w:tr")):
                    for tc in tr.iterchildren(qn("w:tc")):
                        for sub in walk(tc):
                            if sub[0] == "STOP":
                                yield sub
                                return
                            yield sub

    yield from walk(parent_el)


cited_set = set()
for item in iter_paragraphs_in_doc_order(body, ref_heading_el):
    if item[0] == "STOP":
        break
    p_el = item[1]
    txt = "".join(t.text or "" for t in p_el.iter(qn("w:t")))
    for m in re.finditer(r"\[(\d+)\]", txt):
        cited_set.add(int(m.group(1)))

uncited_numbers_in_order = [
    int(re.match(r"\[(\d+)\]", p.text).group(1))
    for p in ref_paragraphs
    if int(re.match(r"\[(\d+)\]", p.text).group(1)) not in cited_set
]
print(f"Cited refs: {len(cited_set)}; Uncited refs: {len(uncited_numbers_in_order)}")

# Walk body+tables. For each citation occurrence in order, allocate next
# sequential number and remember which bibliographic text it points to.
occurrence_log = []  # list of dicts: {old_num, new_num, where}
counter = [0]


def remap_text(text):
    """Replace each [N] in text with [k] where k is next sequential occurrence
    number. Records (old_num -> new_num) into occurrence_log."""

    def sub(m):
        old_n = int(m.group(1))
        counter[0] += 1
        new_n = counter[0]
        occurrence_log.append((old_n, new_n))
        return f"[{new_n}]"

    return re.sub(r"\[(\d+)\]", sub, text)


# Apply to body+tables (left-to-right within each text node)
paragraphs_updated = 0
for item in iter_paragraphs_in_doc_order(body, ref_heading_el):
    if item[0] == "STOP":
        break
    p_el = item[1]
    changed = False
    for t_el in p_el.iter(qn("w:t")):
        old = t_el.text or ""
        if "[" in old and re.search(r"\[\d+\]", old):
            new = remap_text(old)
            if old != new:
                t_el.text = new
                changed = True
    if changed:
        paragraphs_updated += 1

M = counter[0]
print(f"Total citation occurrences in body+tables: {M}")
print(f"Paragraphs updated: {paragraphs_updated}")

# Now rebuild references list:
# - For occurrence k (1..M), entry [k] = ref_text_by_num[old_num at occurrence k]
# - After M, append uncited refs in their existing order with numbers M+1..

# Use the first reference paragraph as a template (preserve style + run props).
template_el = ref_paragraphs[0]._element
template_clone_source = deepcopy(template_el)


def build_ref_paragraph(number, bib_text):
    """Clone the template paragraph and set its text to '[number] bib_text'."""
    new_el = deepcopy(template_clone_source)
    # collect all w:t nodes; set first one to full text, clear the rest.
    ts = list(new_el.iter(qn("w:t")))
    if not ts:
        # If template had no w:t (shouldn't happen), build a minimal run
        return new_el
    ts[0].text = f"[{number}] {bib_text}"
    # preserve whitespace
    ts[0].set(
        "{http://www.w3.org/XML/1998/namespace}space", "preserve"
    )
    for tt in ts[1:]:
        tt.text = ""
    return new_el


# Build new ref paragraph elements in order
new_ref_elements = []
for k in range(1, M + 1):
    old_num, _ = occurrence_log[k - 1]
    bib = ref_text_by_num.get(old_num)
    if bib is None:
        print(f"  WARNING: occurrence {k} cites [{old_num}] which has no refs entry!")
        bib = f"<missing reference for old number {old_num}>"
    new_ref_elements.append(build_ref_paragraph(k, bib))

# Append uncited refs after M
next_num = M + 1
for old_num in uncited_numbers_in_order:
    bib = ref_text_by_num[old_num]
    new_ref_elements.append(build_ref_paragraph(next_num, bib))
    next_num += 1

print(f"Built {len(new_ref_elements)} new reference paragraphs (cited+uncited)")

# Remove existing reference paragraphs from the document
parent = ref_heading_el.getparent()
for p in ref_paragraphs:
    parent.remove(p._element)

# Insert new ref paragraphs right after the References heading
insert_idx = list(parent).index(ref_heading_el) + 1
for offset, el in enumerate(new_ref_elements):
    parent.insert(insert_idx + offset, el)

doc.save(src)
print(f"\nSaved: {src}")

# ----- Verification -----
print("\n=== Verification ===")
doc2 = Document(src)
ref_seq = []
for p in doc2.paragraphs:
    if p.style.name == "references":
        m = re.match(r"\[(\d+)\]", p.text)
        if m:
            ref_seq.append(int(m.group(1)))
expected_total = M + len(uncited_numbers_in_order)
print(f"Refs list has {len(ref_seq)} entries (expected {expected_total})")
print(f"Sequential 1..{expected_total}? {ref_seq == list(range(1, expected_total + 1))}")

# Body cites
body_cites = []
ref_h2 = None
for p in doc2.paragraphs:
    if p.style.name.startswith("Heading") and p.text.strip() == "References":
        ref_h2 = p._element
        break
for item in iter_paragraphs_in_doc_order(doc2.element.body, ref_h2):
    if item[0] == "STOP":
        break
    txt = "".join(t.text or "" for t in item[1].iter(qn("w:t")))
    for m in re.finditer(r"\[(\d+)\]", txt):
        body_cites.append(int(m.group(1)))
print(f"Body+tables citation occurrences: {len(body_cites)}")
print(f"All distinct? {len(body_cites) == len(set(body_cites))}")
print(f"Sequential 1..{len(body_cites)}? {body_cites == list(range(1, len(body_cites) + 1))}")
