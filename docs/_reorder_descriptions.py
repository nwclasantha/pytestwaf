"""
Move figure description paragraphs to BEFORE their images, in line with
academic style (description -> image -> caption -> further discussion).

Three figures have their description appearing AFTER the image:
  Fig. 3  - description "The end-to-end architecture describes one scan
            as a continuous lifecycle..." is at p77, image at p75
  Fig. 12 - description "The prediction architecture has two runtime
            paths..." is at p203, image at p201
  Fig. 13 - description "Fig. 13 illustrates the per-category block..."
            is at p216, image at p214

For each, the description paragraph is moved to be just before the image.

Idempotent: re-running detects each description is already before the
image and exits without changes.
"""
from pathlib import Path
import re
import shutil

from docx import Document
from docx.oxml.ns import qn

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-reorder-descriptions.docx")

# (fig_n, description_anchor_starting_text)
MOVES = [
    (3,  "The end-to-end architecture describes one scan as a continuous lifecycle"),
    (12, "The prediction architecture has two runtime paths"),
    (13, "Fig. 13 illustrates the per-category block and bypass counts"),
]


def main():
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    doc = Document(str(DOC))
    drawing_qn = qn("w:drawing")

    # Find image paragraph index for each Fig. N (the empty paragraph that
    # immediately precedes the figure caption and contains a w:drawing).
    paragraphs = list(doc.paragraphs)

    def caption_index(fig_n):
        for i, p in enumerate(paragraphs):
            if p.style.name == "figure caption":
                m = re.match(r"\s*Fig\.\s*(\d+)", p.text)
                if m and int(m.group(1)) == fig_n:
                    return i
        return None

    def image_para_for(fig_n):
        cap_i = caption_index(fig_n)
        if cap_i is None:
            return None
        # Find the most recent image-bearing paragraph BEFORE the caption
        for i in range(cap_i - 1, -1, -1):
            if any(True for _ in paragraphs[i]._p.iter(drawing_qn)):
                return i
        return None

    moves_applied = 0
    for fig_n, anchor in MOVES:
        # Find the description paragraph (the one starting with the anchor)
        desc_i = None
        for i, p in enumerate(paragraphs):
            if p.text.startswith(anchor):
                desc_i = i
                break
        if desc_i is None:
            print(f"  [skip] Fig. {fig_n}: anchor not found")
            continue

        img_i = image_para_for(fig_n)
        if img_i is None:
            print(f"  [skip] Fig. {fig_n}: image paragraph not found")
            continue

        if desc_i < img_i:
            print(f"  [skip] Fig. {fig_n}: description already before image (desc p{desc_i}, image p{img_i})")
            continue

        # Move desc paragraph to immediately before the image paragraph.
        body = paragraphs[desc_i]._p.getparent()
        body.remove(paragraphs[desc_i]._p)
        # Re-find img element index after removal
        img_el = paragraphs[img_i]._p
        idx = list(body).index(img_el)
        body.insert(idx, paragraphs[desc_i]._p)
        moves_applied += 1
        print(f"  Fig. {fig_n}: moved description paragraph from p{desc_i} to before image p{img_i}")

        # Re-list paragraphs since indices have shifted
        paragraphs = list(doc.paragraphs)

    doc.save(str(DOC))
    print(f"\nReorderings applied: {moves_applied}")
    print(f"Saved: {DOC}")


if __name__ == "__main__":
    main()
