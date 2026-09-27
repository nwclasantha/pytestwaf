"""
Align pytestwaf-research-article.docx alignment, fonts and sizes 100% to
JCM-20514-v5-fixed.docx.

Problems found:
  1. 14 Body-Text paragraphs are wrongly centered (`jc=center`).  They
     should inherit `jc=both` (justified) from the Body Text style.
     Only TABLE I/II/III/IV captions should be centered.
  2. TABLE IV. caption is currently jc=None - needs explicit jc=center to
     match the other table captions.
  3. 25 figure-caption paragraphs lack explicit `jc=center`.  In JCM all
     figure captions are explicitly center-aligned.
  4. Re-embed the regenerated radar (Fig. 29) at native aspect.

Idempotent.  Backup created on first run.
"""
from pathlib import Path
import re
import shutil

from PIL import Image
from docx import Document
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-jcm-alignment.docx")
DIAG = Path("diagrams")


def get_or_create_pPr(p):
    pPr = p._p.find(qn("w:pPr"))
    if pPr is None:
        pPr = OxmlElement("w:pPr")
        p._p.insert(0, pPr)
    return pPr


def remove_jc(p):
    pPr = p._p.find(qn("w:pPr"))
    if pPr is None:
        return False
    jc = pPr.find(qn("w:jc"))
    if jc is None:
        return False
    pPr.remove(jc)
    return True


def set_jc(p, val):
    pPr = get_or_create_pPr(p)
    jc = pPr.find(qn("w:jc"))
    if jc is None:
        jc = OxmlElement("w:jc")
        pPr.append(jc)
    jc.set(qn("w:val"), val)


def main():
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    doc = Document(str(DOC))

    # 1. Identify which Body-Text paragraphs SHOULD remain centered:
    #    only those whose first non-whitespace text starts with TABLE roman.
    keep_centered_pat = re.compile(r"^\s*TABLE\s+[IVX]+", re.IGNORECASE)

    removed = 0
    centered_table = 0
    for p in doc.paragraphs:
        if p.style.name != "Body Text":
            continue
        if not p.text.strip():
            continue
        pPr = p._p.find(qn("w:pPr"))
        jc_val = None
        if pPr is not None:
            jc = pPr.find(qn("w:jc"))
            if jc is not None:
                jc_val = jc.get(qn("w:val"))

        if keep_centered_pat.match(p.text):
            # Should be centered - ensure it is
            if jc_val != "center":
                set_jc(p, "center")
                centered_table += 1
        else:
            # Should not be centered - remove any explicit center
            if jc_val == "center":
                remove_jc(p)
                removed += 1

    print(f"Removed wrong jc=center from {removed} Body-Text paragraphs")
    print(f"Set jc=center on {centered_table} TABLE caption paragraphs that lacked it")

    # 2. All figure captions should be jc=center (JCM convention)
    fig_centered = 0
    for p in doc.paragraphs:
        if p.style.name != "figure caption":
            continue
        if not p.text.strip():
            continue
        pPr = p._p.find(qn("w:pPr"))
        jc_val = None
        if pPr is not None:
            jc = pPr.find(qn("w:jc"))
            if jc is not None:
                jc_val = jc.get(qn("w:val"))
        if jc_val != "center":
            set_jc(p, "center")
            fig_centered += 1
    print(f"Set jc=center on {fig_centered} figure-caption paragraphs")

    # 3. Remove explicit jc=both from Heading 2 paragraphs (style is jc=left;
    #    JCM has 5 such overrides which is OK, ours has 5 too -> match).
    # Already matches per the audit, no action.

    # 4. Re-embed the regenerated radar (Fig. 29) with native aspect.
    rels = doc.part.related_parts
    drawing_qn = qn("w:drawing")
    blip_qn    = qn("a:blip")
    embed_qn   = qn("r:embed")
    extent_qn  = qn("wp:extent")
    ext_a_qn   = qn("a:ext")

    paragraphs = list(doc.paragraphs)
    pending = None
    pending_part = None
    for p in paragraphs:
        for d in p._p.iter(drawing_qn):
            pending = d
            for blip in d.iter(blip_qn):
                rid = blip.get(embed_qn)
                if rid:
                    pending_part = rels[rid]
        if p.style.name == "figure caption":
            m = re.match(r"\s*Fig\.\s*(\d+)", p.text)
            if m:
                fig_n = int(m.group(1))
                if fig_n == 29 and pending is not None and pending_part is not None:
                    src = DIAG / "waf-tactic-radar.png"
                    if src.exists():
                        pending_part._blob = src.read_bytes()
                        img = Image.open(src)
                        ratio = img.size[0] / img.size[1]
                        target_cx = int(6.5 * 914400)
                        new_cy = int(round(target_cx / ratio))
                        ex = next(pending.iter(extent_qn), None)
                        if ex is not None:
                            ex.set("cx", str(target_cx))
                            ex.set("cy", str(new_cy))
                        for ae in pending.iter(ext_a_qn):
                            ae.set("cx", str(target_cx))
                            ae.set("cy", str(new_cy))
                        print(f"Re-embedded Fig. 29 radar: {img.size[0]}x{img.size[1]} "
                              f"-> 6.5x{new_cy/914400:.2f}\"")
                pending = None
                pending_part = None

    doc.save(str(DOC))
    print(f"Saved: {DOC}")


if __name__ == "__main__":
    main()
