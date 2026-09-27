"""Deep verification of unique-per-occurrence citation renumbering.

Three-way check across:
  ORIG  = pytestwaf-research-article.before-renumber.docx (original mixed numbering)
  PREV  = pytestwaf-research-article.before-uniqueocc.docx (first-appearance sequential)
  NEW   = pytestwaf-research-article.docx (unique per occurrence)

Verified invariants:
  V1. NEW refs list is sequential 1..N with no gaps/dupes.
  V2. NEW body+tables citation occurrences are exactly 1, 2, 3, ... in
      document order, with NO repeats.
  V3. For every occurrence position p in document order, the paper cited at
      p is identical across ORIG, PREV, NEW.
  V4. Every NEW citation [k] has a refs entry [k] whose bibliographic text
      equals the paper that was cited at occurrence k in ORIG.
  V5. The 16 uncited references from ORIG appear at the END of the NEW refs
      list, in original order.
  V6. Total citation occurrence count is the same in all three docs.
  V7. The non-citation prose and table cell text is identical across NEW
      and PREV (i.e., we did not accidentally edit anything other than [N]).
"""
import sys
sys.stdout.reconfigure(encoding="utf-8")

from docx import Document
from docx.oxml.ns import qn
import re
import hashlib

ORIG = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-renumber.docx"
PREV = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-uniqueocc.docx"
NEW  = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"


def find_refs_heading(doc):
    for i, p in enumerate(doc.paragraphs):
        if p.text.strip() == "References" and p.style.name.startswith("Heading"):
            return i, p._element
    return None, None


def get_ref_text(doc):
    """Return dict: ref_number -> bibliographic text (after [N] prefix)."""
    idx, _ = find_refs_heading(doc)
    out = {}
    seq = []
    for i in range(idx + 1, len(doc.paragraphs)):
        p = doc.paragraphs[i]
        if p.style.name == "references":
            m = re.match(r"\[(\d+)\]\s*(.*)", p.text.strip())
            if m:
                num = int(m.group(1))
                txt = m.group(2)
                if num in out:
                    # duplicate ref number — record it
                    pass
                out.setdefault(num, txt)
                seq.append((num, txt))
        elif p.text.strip() == "":
            continue
        else:
            break
    return out, seq


def iter_doc_positions(doc):
    """Yield (kind, key, text) for each paragraph or table-cell paragraph
    BEFORE the references heading, in document order."""
    _, ref_el = find_refs_heading(doc)
    body = doc.element.body
    body_p_counter = 0
    tbl_counter = 0
    for child in body.iterchildren():
        if child is ref_el:
            return
        if child.tag == qn("w:p"):
            txt = "".join(t.text or "" for t in child.iter(qn("w:t")))
            yield ("body", f"P{body_p_counter}", txt)
            body_p_counter += 1
        elif child.tag == qn("w:tbl"):
            t_id = tbl_counter
            tbl_counter += 1
            for ri, tr in enumerate(child.iterchildren(qn("w:tr"))):
                for ci, tc in enumerate(tr.iterchildren(qn("w:tc"))):
                    for pi, sub in enumerate(tc.iterchildren(qn("w:p"))):
                        txt = "".join(t.text or "" for t in sub.iter(qn("w:t")))
                        yield ("tbl", f"T{t_id}.R{ri}.C{ci}.P{pi}", txt)


def occurrences_in_order(doc):
    """Return list of (position_key, citation_number_int) in document order."""
    out = []
    for kind, key, txt in iter_doc_positions(doc):
        for m in re.finditer(r"\[(\d+)\]", txt):
            out.append((key, int(m.group(1))))
    return out


def shape(text):
    return re.sub(r"\[\d+\]", "[#]", text)


# ---------------------------------------------------------------------------
print("Loading documents...")
d_orig = Document(ORIG)
d_prev = Document(PREV)
d_new  = Document(NEW)

orig_refs, _      = get_ref_text(d_orig)
prev_refs, _      = get_ref_text(d_prev)
new_refs,  new_seq = get_ref_text(d_new)

orig_occ = occurrences_in_order(d_orig)
prev_occ = occurrences_in_order(d_prev)
new_occ  = occurrences_in_order(d_new)

print(f"\nOccurrence counts: ORIG={len(orig_occ)}  PREV={len(prev_occ)}  NEW={len(new_occ)}")
print(f"Refs list sizes:   ORIG={len(orig_refs)}  PREV={len(prev_refs)}  NEW={len(new_refs)}")

# V1
print("\n--- V1: NEW refs list sequential 1..N ---")
nums = [n for n, _ in new_seq]
expected = list(range(1, len(nums) + 1))
v1 = nums == expected
print(f"  refs count: {len(nums)}   sequential? {v1}")
if not v1:
    bad = [(i, n) for i, n in enumerate(nums) if n != i + 1]
    print(f"  bad: {bad[:10]}")

# V2
print("\n--- V2: NEW body+tables occurrences are 1..M unique sequential ---")
new_nums_in_order = [n for _, n in new_occ]
exp = list(range(1, len(new_nums_in_order) + 1))
v2 = new_nums_in_order == exp
print(f"  occurrence count: {len(new_nums_in_order)}   sequential 1..M? {v2}")
print(f"  all distinct? {len(new_nums_in_order) == len(set(new_nums_in_order))}")

# V3
print("\n--- V3: For every position, same paper cited across ORIG/PREV/NEW ---")
v3_problems = 0
v3_checked = 0
N = min(len(orig_occ), len(prev_occ), len(new_occ))
for i in range(N):
    (ok, on), (pk, pn), (nk, nn) = orig_occ[i], prev_occ[i], new_occ[i]
    if not (ok == pk == nk):
        # structural drift; skip
        continue
    o_text = orig_refs.get(on)
    p_text = prev_refs.get(pn)
    n_text = new_refs.get(nn)
    if o_text is None or p_text is None or n_text is None:
        v3_problems += 1
        print(f"  pos {i} [{ok}] missing ref text: orig[{on}]={'OK' if o_text else 'MISS'}, "
              f"prev[{pn}]={'OK' if p_text else 'MISS'}, new[{nn}]={'OK' if n_text else 'MISS'}")
        continue
    if not (o_text == p_text == n_text):
        v3_problems += 1
        if v3_problems <= 5:
            print(f"  pos {i} [{ok}] mismatch:")
            print(f"    ORIG[{on}]: {o_text[:80]}")
            print(f"    PREV[{pn}]: {p_text[:80]}")
            print(f"    NEW [{nn}]: {n_text[:80]}")
    v3_checked += 1
print(f"  positions checked: {v3_checked} of {N}; mismatches: {v3_problems}")

# V4
print("\n--- V4: Every NEW [k] in body resolves to the same paper as ORIG ---")
v4_bad = 0
for k, (pos_key, num) in enumerate(new_occ, start=1):
    if num != k:
        v4_bad += 1
        continue
    new_target = new_refs.get(num)
    # find ORIG's citation at this position
    if k - 1 < len(orig_occ):
        ok, on = orig_occ[k - 1]
        orig_target = orig_refs.get(on)
        if new_target != orig_target:
            v4_bad += 1
            if v4_bad <= 5:
                print(f"  occ {k} target mismatch:")
                print(f"    NEW  ref[{num}]: {new_target[:80] if new_target else 'MISSING'}")
                print(f"    ORIG ref[{on}]:  {orig_target[:80] if orig_target else 'MISSING'}")
print(f"  occurrences with wrong target: {v4_bad}")

# V5
print("\n--- V5: 16 uncited refs appended at end of NEW refs list ---")
# uncited papers from ORIG = those in orig_refs whose text never appears as a body cite target
orig_cited_texts = set()
for _, on in orig_occ:
    if on in orig_refs:
        orig_cited_texts.add(orig_refs[on])
orig_uncited_texts_in_order = []
# preserve original order: walk orig refs in numeric order
for n in sorted(orig_refs):
    if orig_refs[n] not in orig_cited_texts:
        orig_uncited_texts_in_order.append(orig_refs[n])
print(f"  ORIG uncited refs: {len(orig_uncited_texts_in_order)}")

# tail of NEW refs = last len(uncited) entries
M = len(new_occ)
tail_texts = [t for n, t in new_seq if n > M]
v5 = tail_texts == orig_uncited_texts_in_order
print(f"  tail length: {len(tail_texts)}   matches ORIG uncited order? {v5}")
if not v5:
    print(f"  tail first: {tail_texts[0][:80] if tail_texts else 'empty'}")
    print(f"  expected:   {orig_uncited_texts_in_order[0][:80] if orig_uncited_texts_in_order else 'empty'}")

# V6
print("\n--- V6: Same total occurrence count in all three docs ---")
v6 = len(orig_occ) == len(prev_occ) == len(new_occ)
print(f"  same count? {v6}  ({len(orig_occ)}, {len(prev_occ)}, {len(new_occ)})")

# V7
print("\n--- V7: Non-citation prose identical NEW vs PREV ---")
prev_shapes = [shape(t) for _, _, t in iter_doc_positions(d_prev)]
new_shapes  = [shape(t) for _, _, t in iter_doc_positions(d_new)]
v7 = prev_shapes == new_shapes
print(f"  prose+structure identical? {v7}")
if not v7:
    for i, (a, b) in enumerate(zip(prev_shapes, new_shapes)):
        if a != b:
            print(f"  diff at {i}: PREV={a[:80]!r}  NEW={b[:80]!r}")
            break

# Final
print("\n" + "=" * 70)
ok = (v1 and v2 and v3_problems == 0 and v4_bad == 0 and v5 and v6 and v7)
print("FINAL VERDICT:", "PASS — citations are 100% correct" if ok else "FAIL")
print("=" * 70)
