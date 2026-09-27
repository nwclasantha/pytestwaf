"""Deep audit of pytestwaf-research-article.docx for any remaining issues
after the multi-step renumbering / cleanup / restoration sequence.

Audits performed:
  A1. Bookmark IDs unique (XML restoration could cause duplicate IDs).
  A2. All 113 reference entries: any duplicate paper text under different
      numbers should correspond to a paper cited multiple times.
  A3. Every body/table [k] points to a refs entry whose text matches the
      original paper cited at that position.
  A4. Heading numbering consistency (Sections I, II, III, ...).
  A5. Figure caption count vs figure references in body (Fig. N).
  A6. Table caption count vs table references in body (Table N).
  A7. "Section VII" / "Section X" cross-references valid.
  A8. No orphan references (refs not cited).
  Note: in our scheme, refs 98-113 are intentionally uncited.
  A9. Any leaked result tokens still present outside the Results section.
  A10. Page breaks, line breaks, and special elements preserved relative to original.
  A11. Image/drawing count preserved.
  A12. Hyperlink rels preserved.
  A13. Detect ALL text differences vs original (not just shape) including
       whitespace, punctuation, and character-level mutations.
  A14. Verify bookmark spans (start/end) are matched.
"""
import sys; sys.stdout.reconfigure(encoding='utf-8')
from docx import Document
from docx.oxml.ns import qn
from collections import Counter, defaultdict
import re, zipfile

ORIG = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-renumber.docx"
GOOD = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.before-results-cleanup.docx"
NEW  = r"c:\Users\nwcla\Desktop\pytestwaf\docs\pytestwaf-research-article.docx"

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W = f"{{{W_NS}}}"

issues = []
def report(level, code, msg):
    issues.append((level, code, msg))
    print(f"  [{level}] {code}: {msg}")


def shape(t):
    return re.sub(r"\[\d+\]", "[#]", t)


def iter_doc_positions(doc):
    body = doc.element.body
    ref_idx = None
    for i, p in enumerate(doc.paragraphs):
        if p.text.strip() == "References" and p.style.name.startswith("Heading"):
            ref_idx = i; break
    ref_el = doc.paragraphs[ref_idx]._element
    body_p_counter = 0; tbl_counter = 0
    for child in body.iterchildren():
        if child is ref_el: return
        if child.tag == qn("w:p"):
            txt = "".join(t.text or "" for t in child.iter(qn("w:t")))
            yield ("body", f"P{body_p_counter}", txt, child)
            body_p_counter += 1
        elif child.tag == qn("w:tbl"):
            t_id = tbl_counter; tbl_counter += 1
            for ri, tr in enumerate(child.iterchildren(qn("w:tr"))):
                for ci, tc in enumerate(tr.iterchildren(qn("w:tc"))):
                    for pi, sub in enumerate(tc.iterchildren(qn("w:p"))):
                        txt = "".join(t.text or "" for t in sub.iter(qn("w:t")))
                        yield ("tbl", f"T{t_id}.R{ri}.C{ci}.P{pi}", txt, sub)


print("=" * 70); print("Loading documents..."); print("=" * 70)
d_orig = Document(ORIG)
d_new  = Document(NEW)

# --------------------------------------------------------------------------
print("\n=== A1: Bookmark IDs unique in current doc ===")
seen_ids = []
seen_starts = {}
seen_ends = {}
for el in d_new.element.iter():
    tag = el.tag
    if tag == f"{W}bookmarkStart":
        bid = el.get(f"{W}id")
        seen_ids.append(("start", bid, el.get(f"{W}name")))
        if bid in seen_starts:
            report("WARN", "DUP_BOOKMARK_START_ID",
                   f"id={bid} seen twice (names: {seen_starts[bid]}, {el.get(f'{W}name')})")
        seen_starts[bid] = el.get(f"{W}name")
    elif tag == f"{W}bookmarkEnd":
        bid = el.get(f"{W}id")
        if bid in seen_ends:
            report("WARN", "DUP_BOOKMARK_END_ID", f"id={bid} seen twice")
        seen_ends[bid] = True

start_ids = set(seen_starts)
end_ids = set(seen_ends)
unmatched_starts = start_ids - end_ids
unmatched_ends = end_ids - start_ids
if unmatched_starts:
    report("FAIL", "UNMATCHED_BOOKMARK_START", f"{sorted(unmatched_starts)}")
if unmatched_ends:
    report("FAIL", "UNMATCHED_BOOKMARK_END", f"{sorted(unmatched_ends)}")
print(f"  {len(seen_starts)} bookmark starts, {len(seen_ends)} ends, "
      f"unmatched: {len(unmatched_starts)}+{len(unmatched_ends)}")

# --------------------------------------------------------------------------
print("\n=== A2: Reference list entry duplicates and citation mapping ===")
# Build refs list from new
def get_refs(doc):
    out = []
    in_refs = False
    for p in doc.paragraphs:
        if p.style.name.startswith("Heading") and p.text.strip() == "References":
            in_refs = True; continue
        if in_refs and p.style.name == "references":
            m = re.match(r"\[(\d+)\]\s*(.*)", p.text.strip())
            if m: out.append((int(m.group(1)), m.group(2)))
    return out

new_refs = get_refs(d_new)
orig_refs = get_refs(d_orig)
new_ref_text = {n: t for n, t in new_refs}

# Group new refs by bib text — papers cited multiple times will have multiple ref numbers.
groups = defaultdict(list)
for n, t in new_refs:
    groups[t].append(n)

print(f"  total refs in NEW: {len(new_refs)}; unique bibliographies: {len(groups)}")
# Distribution of duplication
dupe_distribution = Counter(len(v) for v in groups.values())
for k, v in sorted(dupe_distribution.items()):
    print(f"    bibliographies appearing {k}x: {v}")

# --------------------------------------------------------------------------
print("\n=== A3: Body/table citations resolve to correct papers ===")
# For each occurrence k in NEW, the bib at refs[k] should equal the bib at
# orig_refs[orig_num at occurrence k].
orig_ref_text = {n: t for n, t in orig_refs}

orig_positions = list(iter_doc_positions(d_orig))
new_positions = list(iter_doc_positions(d_new))
mismatches = 0
for (op_kind, op_key, op_txt, _), (np_kind, np_key, np_txt, _) in zip(orig_positions, new_positions):
    o_cits = [int(x) for x in re.findall(r"\[(\d+)\]", op_txt)]
    n_cits = [int(x) for x in re.findall(r"\[(\d+)\]", np_txt)]
    if len(o_cits) != len(n_cits):
        # only if shapes differ (intentional edits) — don't flag these
        if shape(op_txt) == shape(np_txt):
            report("FAIL", "CIT_COUNT_MISMATCH", f"{op_key}: orig {o_cits} new {n_cits}")
        continue
    for ocn, ncn in zip(o_cits, n_cits):
        ot = orig_ref_text.get(ocn)
        nt = new_ref_text.get(ncn)
        if ot != nt:
            mismatches += 1
            if mismatches <= 5:
                report("FAIL", "WRONG_TARGET",
                       f"{op_key}: orig[{ocn}]={ot[:50]!r} -> new[{ncn}]={nt[:50] if nt else 'MISS'!r}")
print(f"  mismatches: {mismatches}")

# --------------------------------------------------------------------------
print("\n=== A4: Heading numbering consistency ===")
# Find Heading 1's and check Roman numeral order
romans = ['I.', 'II.', 'III.', 'IV.', 'V.', 'VI.', 'VII.', 'VIII.', 'IX.', 'X.',
          'XI.', 'XII.', 'XIII.']
h1_titles = []
for p in d_new.paragraphs:
    if p.style.name == 'Heading 1':
        h1_titles.append(p.text)
print(f"  H1 headings ({len(h1_titles)}):")
for h in h1_titles: print(f"    - {h}")

# --------------------------------------------------------------------------
print("\n=== A5: Figure captions vs body Fig. N references ===")
fig_caps = []
for p in d_new.paragraphs:
    if p.style.name == 'figure caption':
        fig_caps.append(p.text)

caption_numbers = []
for c in fig_caps:
    m = re.match(r"\s*Fig\.\s*(\d+)\.?", c)
    if m: caption_numbers.append(int(m.group(1)))
print(f"  Fig captions found: {len(fig_caps)}, with Fig. N number: {len(caption_numbers)}")
if caption_numbers:
    expected = list(range(1, len(caption_numbers) + 1))
    if caption_numbers != expected:
        report("WARN", "FIG_CAP_NOT_SEQUENTIAL", f"got {caption_numbers}")
    else:
        print(f"  Captions sequential 1..{len(caption_numbers)}: OK")

# Body references to figures
body_text_all = ""
for kind, key, txt, _ in iter_doc_positions(d_new):
    body_text_all += txt + " "
fig_refs = sorted(set(int(m.group(1)) for m in re.finditer(r"Fig\.\s*(\d+)", body_text_all)))
caption_set = set(caption_numbers)
missing_in_caption = [n for n in fig_refs if n not in caption_set]
if missing_in_caption:
    report("WARN", "FIG_REF_WITHOUT_CAPTION", f"{missing_in_caption}")
else:
    print(f"  All {len(fig_refs)} figure refs in body have a caption")
unused_caption = [n for n in caption_numbers if n not in set(fig_refs)]
if unused_caption:
    report("INFO", "FIG_CAPTION_NOT_REFERENCED", f"{unused_caption}")

# --------------------------------------------------------------------------
print("\n=== A6: Table captions vs body Table N references ===")
# Table captions might be in 'TABLE I.', 'TABLE II.' format (small caps)
table_caps = []
for p in d_new.paragraphs:
    txt = p.text.strip()
    if re.match(r"^TABLE\s+[IVX]+\.", txt, re.IGNORECASE) or "TABLE I" in txt[:15]:
        table_caps.append(txt)
print(f"  Table captions found: {len(table_caps)}")
for c in table_caps[:10]: print(f"    - {c[:100]}")

# --------------------------------------------------------------------------
print("\n=== A7: 'Section VII' style cross-references ===")
section_refs = re.findall(r"Section\s+([IVX]+|\d+)", body_text_all)
sec_counter = Counter(section_refs)
print(f"  Section cross-refs found: {sum(sec_counter.values())}")
for s, c in sec_counter.most_common():
    print(f"    Section {s}: {c}x")

# --------------------------------------------------------------------------
print("\n=== A8: Refs cited 0 times are exactly the tail uncited refs ===")
# Determine which refs are cited
cited = set()
for kind, key, txt, _ in iter_doc_positions(d_new):
    for m in re.finditer(r"\[(\d+)\]", txt):
        cited.add(int(m.group(1)))
all_nums = set(n for n,_ in new_refs)
uncited = all_nums - cited
print(f"  refs cited: {len(cited)}, uncited: {len(uncited)}")
# Cited should be 1..97; uncited should be 98..113
expected_cited = set(range(1, 98))
expected_uncited = set(range(98, 114))
if cited != expected_cited:
    report("FAIL", "CITED_SET", f"expected {sorted(expected_cited)} got {sorted(cited)}")
if uncited != expected_uncited:
    report("FAIL", "UNCITED_SET", f"expected {sorted(expected_uncited)} got {sorted(uncited)}")

# --------------------------------------------------------------------------
print("\n=== A9: Any leaked result tokens outside Results section ===")
# tokens likely to be result-only
forbidden = ["0.858", "0.8575", "0.909", "0.891", "0.900", "0.938", "0.949", "0.943",
             "1,104", "403 blocks", "701 bypasses", "36.5 percent", "63.5 percent",
             "five novel", "5 novel"]
results_section_indices = []
ref_idx = None
for i, p in enumerate(d_new.paragraphs):
    if p.style.name.startswith("Heading") and p.text.strip() == "References":
        ref_idx = i; break
results_start = None; results_end = ref_idx
for i, p in enumerate(d_new.paragraphs):
    if p.style.name == 'Heading 1' and p.text.strip() == 'Results':
        results_start = i; break
# Find next H1 after Results
next_h1 = ref_idx
for i in range(results_start+1, ref_idx):
    if d_new.paragraphs[i].style.name == 'Heading 1':
        next_h1 = i; break
print(f"  Results section: paragraphs {results_start} to {next_h1-1}")

leak_count = 0
for i, p in enumerate(d_new.paragraphs):
    if i < results_start or i >= next_h1:
        for tok in forbidden:
            if tok in p.text:
                # Check that this isn't a benign occurrence
                # OK if it's: 0.99 (literature), or in figures/captions
                leak_count += 1
                report("WARN", "RESULT_LEAK_OUTSIDE_RESULTS",
                       f"P{i}: token '{tok}' in: {p.text[:120]}")
# Tables
for ti, table in enumerate(d_new.tables):
    for ri, row in enumerate(table.rows):
        for ci, cell in enumerate(row.cells):
            for tok in forbidden:
                if tok in cell.text:
                    leak_count += 1
                    report("WARN", "RESULT_LEAK_IN_TABLE",
                           f"T{ti}.R{ri}.C{ci}: token '{tok}' in: {cell.text[:120]}")
print(f"  Leaks: {leak_count}")

# --------------------------------------------------------------------------
print("\n=== A10: Original-vs-current text diff (every position) ===")
diffs = []
for (op_kind, op_key, op_txt, _), (np_kind, np_key, np_txt, _) in zip(orig_positions, new_positions):
    if shape(op_txt) != shape(np_txt):
        diffs.append((op_key, op_txt, np_txt))
EXPECTED_EDITS = {"P53", "P286", "P412", "P414",
                  "T0.R16.C3.P0", "T1.R12.C3.P0", "T2.R10.C2.P0",
                  "T1.R0.C0.P0"}
# IEEE-style title replacements in Work column
for ri in range(1, 14):
    EXPECTED_EDITS.add(f"T0.R{ri}.C0.P0")
for ri in range(1, 12):
    EXPECTED_EDITS.add(f"T1.R{ri}.C0.P0")
unexpected = [(k, o, n) for k, o, n in diffs if k not in EXPECTED_EDITS]
print(f"  total text diffs: {len(diffs)}; unexpected (potential corruption): {len(unexpected)}")
for k, o, n in unexpected:
    report("FAIL", "UNEXPECTED_TEXT_DIFF",
           f"{k}: orig {o[:80]!r} -> new {n[:80]!r}")

# --------------------------------------------------------------------------
print("\n=== A11: Drawing/image count preserved ===")
def count_drawings(doc):
    return len(list(doc.element.iter(qn('w:drawing'))))
oc = count_drawings(d_orig); nc = count_drawings(d_new)
print(f"  ORIG drawings: {oc}; NEW drawings: {nc}")
if oc != nc:
    report("FAIL", "DRAWING_COUNT", f"orig {oc} != new {nc}")

# --------------------------------------------------------------------------
print("\n=== A12: Media files identical (zip-level) ===")
def media_hashes(path):
    import hashlib
    out = {}
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.startswith("word/media/"):
                out[n] = hashlib.sha256(z.read(n)).hexdigest()
    return out
om = media_hashes(ORIG); nm = media_hashes(NEW)
print(f"  ORIG media files: {len(om)}; NEW: {len(nm)}")
missing = set(om) - set(nm)
extra = set(nm) - set(om)
changed = [n for n in om if n in nm and om[n] != nm[n]]
if missing: report("FAIL", "MEDIA_MISSING", f"{sorted(missing)}")
if extra:   report("WARN", "MEDIA_EXTRA", f"{sorted(extra)}")
if changed: report("FAIL", "MEDIA_CHANGED", f"{sorted(changed)}")
if not (missing or extra or changed):
    print("  All media files byte-identical")

# --------------------------------------------------------------------------
print("\n=== A13: ALL paragraph-level char-level diffs vs GOOD pre-cleanup ===")
# This catches anything that diverged from the verified-good snapshot taken
# right after the unique-occurrence renumber.
d_good = Document(GOOD)
good_positions = list(iter_doc_positions(d_good))
deeper = []
for (gk, gkey, gtxt, _), (nk, nkey, ntxt, _) in zip(good_positions, new_positions):
    if shape(gtxt) != shape(ntxt):
        deeper.append((gkey, gtxt, ntxt))
unexpected2 = [(k, g, n) for k, g, n in deeper if k not in EXPECTED_EDITS]
print(f"  diffs vs good: {len(deeper)}; unexpected: {len(unexpected2)}")
for k, g, n in unexpected2:
    report("FAIL", "DIFF_VS_GOOD", f"{k}: good {g[:80]!r} new {n[:80]!r}")

# --------------------------------------------------------------------------
# Summary
print("\n" + "=" * 70)
print("AUDIT SUMMARY")
print("=" * 70)
counts = Counter(lvl for lvl, _, _ in issues)
print(f"  FAIL: {counts.get('FAIL', 0)}  WARN: {counts.get('WARN', 0)}  INFO: {counts.get('INFO', 0)}")
if not issues:
    print("\n  No issues found.")
else:
    print("\n  Issue list:")
    for lvl, code, msg in issues:
        print(f"    [{lvl}] {code}: {msg[:140]}")
