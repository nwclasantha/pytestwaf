"""Renumber [N] citations in pytestwaf-research-article.docx so they appear
sequentially (1, 2, 3, ...) in order of first appearance in body+tables.
References list is reordered and re-prefixed to match the new mapping.
Uncited references are appended at the end of the new ordering.
"""
from docx import Document
from docx.oxml.ns import qn
import re
import shutil
import os

src = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"
backup = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-renumber.docx"

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
assert ref_para_idx is not None, "Could not locate References heading"
ref_heading_el = all_paras[ref_para_idx]._element
print(f"References heading at paragraph index {ref_para_idx}")

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


def iter_paragraphs_in_doc_order(parent_el, stop_at_element):
    """Yield ('p', xml_element) for paragraphs in document order including
    those nested in tables. Stops when encountering stop_at_element."""

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


# Pass 1: collect citations in first-appearance order BEFORE references heading
seen = set()
first_appearance_order = []
for item in iter_paragraphs_in_doc_order(body, ref_heading_el):
    if item[0] == "STOP":
        break
    p_el = item[1]
    text = "".join(t.text or "" for t in p_el.iter(qn("w:t")))
    for m in re.finditer(r"\[(\d+)\]", text):
        n = int(m.group(1))
        if n not in seen:
            seen.add(n)
            first_appearance_order.append(n)

print(f"\nUnique cited refs in body ({len(first_appearance_order)}):")
print(first_appearance_order)

# All reference numbers in current refs list
all_ref_numbers = []
for p in ref_paragraphs:
    m = re.match(r"\s*\[(\d+)\]", p.text)
    if m:
        all_ref_numbers.append(int(m.group(1)))

uncited = [n for n in all_ref_numbers if n not in seen]
print(f"\nUncited references appended at end: {uncited}")

mapping = {}
for new_idx, old in enumerate(first_appearance_order, start=1):
    mapping[old] = new_idx
next_n = len(first_appearance_order) + 1
for old in uncited:
    mapping[old] = next_n
    next_n += 1

print("\nMapping (old -> new):")
for old in sorted(mapping):
    print(f"  [{old:>2}] -> [{mapping[old]:>2}]")


def remap_text(text):
    return re.sub(
        r"\[(\d+)\]",
        lambda m: f"[{mapping.get(int(m.group(1)), m.group(1))}]",
        text,
    )


# Pass 2: rewrite citations in body+tables (run-by-run, no run spans)
paragraphs_updated = 0
runs_updated = 0
for item in iter_paragraphs_in_doc_order(body, ref_heading_el):
    if item[0] == "STOP":
        break
    p_el = item[1]
    changed = False
    for t_el in p_el.iter(qn("w:t")):
        old = t_el.text or ""
        new = remap_text(old)
        if old != new:
            t_el.text = new
            runs_updated += 1
            changed = True
    if changed:
        paragraphs_updated += 1

print(
    f"\nUpdated {runs_updated} text nodes across {paragraphs_updated} body paragraphs"
)

# Pass 3: rewrite [N] prefix in reference paragraphs and reorder them
ref_pairs = []
for p in ref_paragraphs:
    txt = p.text
    m = re.match(r"\[(\d+)\]", txt)
    if not m:
        print(f"WARNING: ref paragraph missing [N] prefix: {txt[:60]!r}")
        continue
    old = int(m.group(1))
    new = mapping.get(old, old)
    new_text = f"[{new}]" + txt[m.end():]
    ts = list(p._element.iter(qn("w:t")))
    if ts:
        ts[0].text = new_text
        for tt in ts[1:]:
            tt.text = ""
    ref_pairs.append((new, p._element))

ref_pairs.sort(key=lambda x: x[0])
new_order_elements = [el for _, el in ref_pairs]
parent = ref_heading_el.getparent()
for el in new_order_elements:
    parent.remove(el)
insert_idx = list(parent).index(ref_heading_el) + 1
for offset, el in enumerate(new_order_elements):
    parent.insert(insert_idx + offset, el)

doc.save(src)
print(f"\nSaved: {src}")

# Verification
print("\n=== Verification ===")
doc2 = Document(src)
ref_seq = []
in_refs = False
ref_idx2 = None
for i, p in enumerate(doc2.paragraphs):
    if p.style.name.startswith("Heading") and p.text.strip() == "References":
        in_refs = True
        ref_idx2 = i
        continue
    if in_refs and p.style.name == "references":
        m = re.match(r"\[(\d+)\]", p.text)
        if m:
            ref_seq.append(int(m.group(1)))
print(f"Reference list new order: {ref_seq}")
print(
    f"Sequential 1..{len(ref_seq)}? {ref_seq == list(range(1, len(ref_seq) + 1))}"
)

# Body first-appearance order should now be 1,2,3,...
ordered_cits = []
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
        ordered_cits.append(int(m.group(1)))

uniq = []
sset = set()
for n in ordered_cits:
    if n not in sset:
        sset.add(n)
        uniq.append(n)
print(f"\nBody first-appearance order: {uniq}")
print(
    f"Sequential 1..{len(uniq)}? {uniq == list(range(1, len(uniq) + 1))}"
)
