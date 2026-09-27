"""Deep verification of citation renumbering.

Checks performed:
  1. References list is exactly sequential 1..N with no gaps/duplicates.
  2. Every [N] in body of NEW doc points to a real entry in NEW refs list.
  3. Every [N] in tables of NEW doc points to a real entry in NEW refs list.
  4. POSITIONAL EQUIVALENCE: at every (paragraph or table-cell) text position
     where the OLD doc had citation [old_K], the NEW doc has citation [new_K]
     pointing to the SAME bibliographic entry (matched on the post-prefix text).
  5. No NEW [N] in body/tables refers to an entry beyond the cited range
     (which would mean a body cite was incorrectly assigned to an "uncited"
     reference).
  6. The set of cited refs in NEW doc equals the set in OLD doc.
"""
from docx import Document
from docx.oxml.ns import qn
import re

NEW = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"
OLD = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-renumber.docx"


def find_refs_heading_idx(doc):
    for i, p in enumerate(doc.paragraphs):
        if p.text.strip() == "References" and p.style.name.startswith("Heading"):
            return i
    return None


def get_ref_entries(doc):
    """Return list of (number, body_text_after_prefix) for each ref."""
    idx = find_refs_heading_idx(doc)
    out = []
    for i in range(idx + 1, len(doc.paragraphs)):
        p = doc.paragraphs[i]
        if p.style.name == "references":
            m = re.match(r"\[(\d+)\]\s*(.*)", p.text.strip())
            if m:
                out.append((int(m.group(1)), m.group(2)))
        elif p.text.strip() == "":
            continue
        else:
            break
    return out


def iter_text_positions(doc):
    """Yield (kind, key, text) for each paragraph-equivalent text unit BEFORE
    the references heading. kind is 'body' or 'tbl'.
    key is a stable identifier so we can pair OLD vs NEW entries."""
    body = doc.element.body
    ref_idx = find_refs_heading_idx(doc)
    ref_el = doc.paragraphs[ref_idx]._element

    body_p_counter = 0
    tbl_counter = 0

    def walk(parent, tbl_ctx=None):
        nonlocal body_p_counter, tbl_counter
        for child in parent.iterchildren():
            if child is ref_el:
                return False  # signal stop
            tag = child.tag
            if tag == qn("w:p"):
                txt = "".join(t.text or "" for t in child.iter(qn("w:t")))
                if tbl_ctx is None:
                    yield ("body", f"P{body_p_counter}", txt)
                    body_p_counter += 1
                else:
                    yield ("tbl", tbl_ctx, txt)
            elif tag == qn("w:tbl"):
                t_id = tbl_counter
                tbl_counter += 1
                for ri, tr in enumerate(child.iterchildren(qn("w:tr"))):
                    for ci, tc in enumerate(tr.iterchildren(qn("w:tc"))):
                        for pi, sub in enumerate(tc.iterchildren(qn("w:p"))):
                            txt = "".join(
                                t.text or "" for t in sub.iter(qn("w:t"))
                            )
                            yield ("tbl", f"T{t_id}.R{ri}.C{ci}.P{pi}", txt)
        return True

    # walk top level
    for child in body.iterchildren():
        if child is ref_el:
            return
        tag = child.tag
        if tag == qn("w:p"):
            txt = "".join(t.text or "" for t in child.iter(qn("w:t")))
            yield ("body", f"P{body_p_counter}", txt)
            body_p_counter += 1
        elif tag == qn("w:tbl"):
            t_id = tbl_counter
            tbl_counter += 1
            for ri, tr in enumerate(child.iterchildren(qn("w:tr"))):
                for ci, tc in enumerate(tr.iterchildren(qn("w:tc"))):
                    for pi, sub in enumerate(tc.iterchildren(qn("w:p"))):
                        txt = "".join(t.text or "" for t in sub.iter(qn("w:t")))
                        yield ("tbl", f"T{t_id}.R{ri}.C{ci}.P{pi}", txt)


def signature(text):
    """Stable shape of a text: replace each [N] with [#] so OLD/NEW positions
    can be paired regardless of the renumbering."""
    return re.sub(r"\[\d+\]", "[#]", text)


# ---------------------------------------------------------------------------
old = Document(OLD)
new = Document(NEW)

old_refs = get_ref_entries(old)
new_refs = get_ref_entries(new)

print("=" * 72)
print("Check 1: Sequential references list")
print("=" * 72)
new_nums = [n for n, _ in new_refs]
expected = list(range(1, len(new_nums) + 1))
print(f"  refs count: {len(new_nums)} expected sequential 1..{len(new_nums)}")
print(f"  sequential? {new_nums == expected}")
if new_nums != expected:
    print(f"  ACTUAL: {new_nums}")

# Build lookup new_num -> body_text and old_num -> body_text
new_ref_text = {n: t for n, t in new_refs}
old_ref_text = {n: t for n, t in old_refs}

print()
print("=" * 72)
print("Check 2+3: Every [N] in NEW body/tables resolves to a refs entry")
print("=" * 72)
unresolved = []
for kind, key, txt in iter_text_positions(new):
    for m in re.finditer(r"\[(\d+)\]", txt):
        n = int(m.group(1))
        if n not in new_ref_text:
            unresolved.append((kind, key, n, txt[:80]))
print(f"  unresolved citations in body/tables: {len(unresolved)}")
for u in unresolved[:10]:
    print(f"    {u}")

print()
print("=" * 72)
print("Check 4: Positional equivalence OLD vs NEW")
print("=" * 72)
old_positions = list(iter_text_positions(old))
new_positions = list(iter_text_positions(new))
print(f"  OLD positions: {len(old_positions)}, NEW positions: {len(new_positions)}")

if len(old_positions) != len(new_positions):
    print("  WARNING: position count differs (document structure changed?)")

mismatches = []
positional_pairs_checked = 0
for (ok, okey, otxt), (nk, nkey, ntxt) in zip(old_positions, new_positions):
    if (ok, okey) != (nk, nkey):
        # structure drift; skip strict pairing here
        continue
    # ensure the non-citation text is identical
    if signature(otxt) != signature(ntxt):
        mismatches.append(("text-shape-mismatch", okey, otxt[:80], ntxt[:80]))
        continue
    # extract paired citations in order
    o_cits = [int(x) for x in re.findall(r"\[(\d+)\]", otxt)]
    n_cits = [int(x) for x in re.findall(r"\[(\d+)\]", ntxt)]
    if len(o_cits) != len(n_cits):
        mismatches.append(("count-mismatch", okey, o_cits, n_cits))
        continue
    for o_n, n_n in zip(o_cits, n_cits):
        # The NEW reference text for n_n must equal the OLD reference text
        # for o_n (i.e., they describe the same bibliographic entry).
        if o_n not in old_ref_text:
            mismatches.append(("old-ref-missing", okey, o_n))
            continue
        if n_n not in new_ref_text:
            mismatches.append(("new-ref-missing", okey, n_n))
            continue
        if old_ref_text[o_n] != new_ref_text[n_n]:
            mismatches.append(
                (
                    "wrong-target",
                    okey,
                    f"old [{o_n}] -> {old_ref_text[o_n][:60]}",
                    f"new [{n_n}] -> {new_ref_text[n_n][:60]}",
                )
            )
        positional_pairs_checked += 1

print(f"  citation pairs checked: {positional_pairs_checked}")
print(f"  mismatches: {len(mismatches)}")
for m in mismatches[:20]:
    print(f"    {m}")

print()
print("=" * 72)
print("Check 5: Cited set equality OLD vs NEW (mapped through reference text)")
print("=" * 72)
old_cited_texts = set()
for kind, key, txt in iter_text_positions(old):
    for m in re.finditer(r"\[(\d+)\]", txt):
        n = int(m.group(1))
        if n in old_ref_text:
            old_cited_texts.add(old_ref_text[n])
new_cited_texts = set()
for kind, key, txt in iter_text_positions(new):
    for m in re.finditer(r"\[(\d+)\]", txt):
        n = int(m.group(1))
        if n in new_ref_text:
            new_cited_texts.add(new_ref_text[n])

only_in_old = old_cited_texts - new_cited_texts
only_in_new = new_cited_texts - old_cited_texts
print(f"  OLD cited refs (unique works): {len(old_cited_texts)}")
print(f"  NEW cited refs (unique works): {len(new_cited_texts)}")
print(f"  only in OLD: {len(only_in_old)}")
for t in list(only_in_old)[:5]:
    print(f"    -> {t[:90]}")
print(f"  only in NEW: {len(only_in_new)}")
for t in list(only_in_new)[:5]:
    print(f"    -> {t[:90]}")

print()
print("=" * 72)
print("Check 6: NEW body first-appearance order is sequential")
print("=" * 72)
seen, order = set(), []
for kind, key, txt in iter_text_positions(new):
    for m in re.finditer(r"\[(\d+)\]", txt):
        n = int(m.group(1))
        if n not in seen:
            seen.add(n)
            order.append(n)
expected = list(range(1, len(order) + 1))
print(f"  first-appearance order: {order}")
print(f"  sequential? {order == expected}")

# Final summary
print()
print("=" * 72)
ok = (
    new_nums == list(range(1, len(new_nums) + 1))
    and not unresolved
    and not mismatches
    and not only_in_old
    and not only_in_new
    and order == list(range(1, len(order) + 1))
)
print("DEEP-CHECK RESULT:", "PASS" if ok else "FAIL")
print("=" * 72)
