"""Final confirmation audit using key-based comparison (robust to row
additions/removals in tables)."""
import sys; sys.stdout.reconfigure(encoding="utf-8")
from docx import Document
from docx.oxml.ns import qn
from collections import Counter
import re, hashlib, zipfile

ORIG = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-renumber.docx"
NEW  = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"

def get_refs(doc):
    out = {}
    in_refs = False
    for p in doc.paragraphs:
        if p.style.name.startswith('Heading') and p.text.strip() == 'References':
            in_refs = True; continue
        if in_refs and p.style.name == 'references':
            m = re.match(r'\[(\d+)\]\s*(.*)', p.text.strip())
            if m: out[int(m.group(1))] = m.group(2)
    return out


def collect_all(doc):
    """Return:
       - body_paras: dict {P_index: text}  for top-level paragraphs (NO tables)
       - table_cells: dict {(t, r, c, p): text} for every table-cell paragraph
       - cite_seq:   list[(paper_text, position_key)] in document order
    """
    refs = get_refs(doc)
    body_paras = {}
    table_cells = {}
    cite_seq = []
    body = doc.element.body
    ref_idx_el = None
    for i, p in enumerate(doc.paragraphs):
        if p.style.name.startswith('Heading') and p.text.strip() == 'References':
            ref_idx_el = p._element; break
    body_p_counter = 0
    tbl_counter = 0
    for child in body.iterchildren():
        if child is ref_idx_el: break
        if child.tag == qn('w:p'):
            txt = "".join(t.text or "" for t in child.iter(qn('w:t')))
            body_paras[body_p_counter] = txt
            for m in re.finditer(r"\[(\d+)\]", txt):
                paper = refs.get(int(m.group(1)), '<missing>')
                cite_seq.append((paper, f"P{body_p_counter}"))
            body_p_counter += 1
        elif child.tag == qn('w:tbl'):
            t_id = tbl_counter; tbl_counter += 1
            for ri, tr in enumerate(child.iterchildren(qn('w:tr'))):
                for ci, tc in enumerate(tr.iterchildren(qn('w:tc'))):
                    for pi, sub in enumerate(tc.iterchildren(qn('w:p'))):
                        txt = "".join(t.text or "" for t in sub.iter(qn('w:t')))
                        table_cells[(t_id, ri, ci, pi)] = txt
                        for m in re.finditer(r"\[(\d+)\]", txt):
                            paper = refs.get(int(m.group(1)), '<missing>')
                            cite_seq.append((paper, f"T{t_id}.R{ri}.C{ci}.P{pi}"))
    return body_paras, table_cells, cite_seq


print("Loading documents...")
d_orig = Document(ORIG)
d_new = Document(NEW)
ob, otc, ocs = collect_all(d_orig)
nb, ntc, ncs = collect_all(d_new)
orig_refs = get_refs(d_orig)
new_refs = get_refs(d_new)

issues = 0

# 1. Reference list sequential
print("\n=== 1. References list ===")
on = sorted(orig_refs); nn = sorted(new_refs)
print(f"  ORIG: {len(on)} entries; NEW: {len(nn)} entries")
seq_orig = on == list(range(1, len(on)+1))
seq_new  = nn == list(range(1, len(nn)+1))
print(f"  ORIG sequential 1..{len(on)}? {seq_orig}")
print(f"  NEW  sequential 1..{len(nn)}? {seq_new}")
if not seq_new: issues += 1

# 2. Citation occurrences identity
print("\n=== 2. Citation occurrences (papers in document order) ===")
print(f"  ORIG: {len(ocs)} occurrences; NEW: {len(ncs)}")
papers_orig = [p for p, _ in ocs]
papers_new  = [p for p, _ in ncs]
same = papers_orig == papers_new
print(f"  Same papers in same order? {same}")
if not same:
    issues += 1
    for i, (po, pn) in enumerate(zip(papers_orig, papers_new)):
        if po != pn:
            print(f"    diff at occurrence {i+1}: orig={po[:60]} | new={pn[:60]}")
            break

# 3. Citation numbers in NEW are 1..N sequential, all distinct
print("\n=== 3. NEW citation numbers ===")
new_nums = []
for paper, pos in ncs:
    pass
# extract numbers from NEW
for kind, container in [('body', nb), ('table', ntc)]:
    pass

import re as _re
new_cite_nums = []
body = d_new.element.body
ref_idx_el = None
for i, p in enumerate(d_new.paragraphs):
    if p.style.name.startswith('Heading') and p.text.strip() == 'References':
        ref_idx_el = p._element; break

def walk(parent):
    for child in parent.iterchildren():
        if child is ref_idx_el: return
        if child.tag == qn('w:p'):
            txt = "".join(t.text or "" for t in child.iter(qn('w:t')))
            for m in _re.finditer(r"\[(\d+)\]", txt):
                new_cite_nums.append(int(m.group(1)))
        elif child.tag == qn('w:tbl'):
            for tr in child.iterchildren(qn('w:tr')):
                for tc in tr.iterchildren(qn('w:tc')):
                    for sub in tc.iterchildren(qn('w:p')):
                        txt = "".join(t.text or "" for t in sub.iter(qn('w:t')))
                        for m in _re.finditer(r"\[(\d+)\]", txt):
                            new_cite_nums.append(int(m.group(1)))
walk(body)
distinct = len(new_cite_nums) == len(set(new_cite_nums))
seq = new_cite_nums == list(range(1, len(new_cite_nums)+1))
print(f"  count: {len(new_cite_nums)}; distinct: {distinct}; sequential 1..N: {seq}")
if not distinct or not seq: issues += 1

# 4. Body paragraphs — same set of body paragraphs in both?
print("\n=== 4. Body paragraphs (top-level, excluding tables) ===")
print(f"  ORIG body paragraphs: {len(ob)}; NEW: {len(nb)}")
same_count = len(ob) == len(nb)
print(f"  Same count? {same_count}")
diffs = []
EXPECTED_BODY_EDITS = {53, 286, 412, 414}
for k in sorted(ob.keys() | nb.keys()):
    o = ob.get(k); n = nb.get(k)
    if _re.sub(r"\[\d+\]", "[#]", o or "") != _re.sub(r"\[\d+\]", "[#]", n or ""):
        diffs.append((k, o, n))
unexpected = [(k, o, n) for k, o, n in diffs if k not in EXPECTED_BODY_EDITS]
print(f"  Body diffs: {len(diffs)}; unexpected: {len(unexpected)}")
for k, o, n in unexpected[:5]:
    print(f"    P{k}: orig={o[:80]!r} | new={n[:80]!r}")
if unexpected: issues += 1

# 5. Table cell content — only intentional edits
print("\n=== 5. Table cell paragraphs ===")
print(f"  ORIG table cells: {len(otc)}; NEW: {len(ntc)}")
EXPECTED_TABLE_EDITS = {
    (0, 16, 3, 0),
    (1, 12, 3, 0),
    (2, 10, 2, 0),
    (1, 0, 0, 0),
}
# Title replacements in T0 R1..R13 and T1 R1..R11 (Work column)
for r in range(1, 14):
    EXPECTED_TABLE_EDITS.add((0, r, 0, 0))
for r in range(1, 12):
    EXPECTED_TABLE_EDITS.add((1, r, 0, 0))

orig_keys = set(otc); new_keys = set(ntc)
only_orig = orig_keys - new_keys
only_new = new_keys - orig_keys
print(f"  cells only in ORIG: {len(only_orig)}")
print(f"  cells only in NEW (added by row split): {len(only_new)}")
# Common cells
unexpected_cell_diffs = []
for k in orig_keys & new_keys:
    o = otc[k]; n = ntc[k]
    if _re.sub(r"\[\d+\]", "[#]", o) != _re.sub(r"\[\d+\]", "[#]", n):
        # The split moved [46]..[59] out of the original aggregate cells.
        # Original cells T0.R14.C0.P0 and T0.R15.C0.P0 are GONE in NEW
        # (they're in only_orig set, not in common set), so they don't
        # appear here.
        if k not in EXPECTED_TABLE_EDITS:
            unexpected_cell_diffs.append((k, o, n))
print(f"  unexpected cell diffs in common cells: {len(unexpected_cell_diffs)}")
for k, o, n in unexpected_cell_diffs[:5]:
    print(f"    {k}: orig={o[:80]!r} | new={n[:80]!r}")
if unexpected_cell_diffs: issues += 1

# Detail of split rows
print("\n  ORIG cells removed (R14/R15 original aggregated):")
for k in sorted(only_orig):
    if otc.get(k):
        print(f"    {k}: {otc[k][:90]}")
print(f"  NEW cells added (split into individual rows):")
new_added_count_by_table = Counter(k[0] for k in only_new)
for t_id, cnt in sorted(new_added_count_by_table.items()):
    print(f"    Table {t_id}: +{cnt} new cell-paragraphs")

# 6. Figures/media
print("\n=== 6. Figures and media ===")
def count_drawings(doc):
    return len(list(doc.element.iter(qn('w:drawing'))))
od = count_drawings(d_orig); nd = count_drawings(d_new)
print(f"  ORIG drawings: {od}; NEW: {nd}; preserved? {od == nd}")
def media_hashes(path):
    out = {}
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.startswith("word/media/"):
                out[n] = hashlib.sha256(z.read(n)).hexdigest()
    return out
om = media_hashes(ORIG); nm = media_hashes(NEW)
mediasame = om == nm
print(f"  ORIG media: {len(om)}; NEW: {len(nm)}; byte-identical? {mediasame}")
if not (od == nd and mediasame): issues += 1

# 7. Bookmarks
print("\n=== 7. Bookmarks ===")
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
starts = sum(1 for _ in d_new.element.iter(f"{W}bookmarkStart"))
ends = sum(1 for _ in d_new.element.iter(f"{W}bookmarkEnd"))
print(f"  bookmarkStart: {starts}; bookmarkEnd: {ends}; matched? {starts == ends}")
if starts != ends: issues += 1

# 8. Author block intact
print("\n=== 8. Author block ===")
for i, expected in [
    (1, "Ruvan Abeysekara"),
    (4, "BCAS Campus, Colombo, Sri Lanka"),
    (5, "ruvan@bcas.lk"),
]:
    got = nb.get(i, "")
    ok = expected in got
    print(f"  P{i}: contains {expected!r}? {ok}")
    if not ok: issues += 1

print("\n" + "=" * 70)
print(f"FINAL VERDICT: {'PASS' if issues == 0 else f'FAIL ({issues} issues)'}")
print("=" * 70)
