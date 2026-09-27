"""
Resize the regenerated figures (Figs. 13-29) to match JCM template widths.

Cause of the user-reported overflow: I previously set every regenerated
figure to 6.5" display width.  JCM template uses 3.30" for nearly every
data figure (single-column width).  6.5" overflows into the page margin.

Fix: set the regenerated figures' display width to 3.30" with native
aspect ratio (height computed from the source PNG's width:height ratio).
For Figs. 1-12 we leave the widths alone.

Idempotent.  Backup created on first run.
"""
import re
import shutil
from pathlib import Path
from io import BytesIO

from PIL import Image
from docx import Document
from docx.oxml.ns import qn

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-jcm-widths.docx")

# Figs to resize; each gets 3.30" wide, native aspect.
TARGETS = list(range(13, 30))  # 13-29

EMU_PER_INCH = 914400
TARGET_W_IN = 3.30


def main():
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    doc = Document(str(DOC))
    rels = doc.part.related_parts

    drawing_qn = qn("w:drawing")
    blip_qn    = qn("a:blip")
    embed_qn   = qn("r:embed")
    extent_qn  = qn("wp:extent")
    ext_a_qn   = qn("a:ext")

    pending_drawing = None
    pending_part = None
    fig_drawings = []
    for p in doc.paragraphs:
        for dr in p._p.iter(drawing_qn):
            pending_drawing = dr
            for blip in dr.iter(blip_qn):
                rid = blip.get(embed_qn)
                if rid:
                    pending_part = rels[rid]
        if p.style.name == "figure caption":
            m = re.match(r"\s*Fig\.\s*(\d+)", p.text)
            if m:
                fig_n = int(m.group(1))
                if pending_drawing is not None and pending_part is not None:
                    fig_drawings.append((fig_n, pending_drawing, pending_part))
                pending_drawing = None
                pending_part = None

    target_cx = int(TARGET_W_IN * EMU_PER_INCH)

    resized = 0
    for fig_n, drawing, img_part in fig_drawings:
        if fig_n not in TARGETS:
            continue
        # Read native PNG dimensions
        img = Image.open(BytesIO(img_part._blob))
        ratio = img.size[0] / img.size[1]
        new_cy = int(round(target_cx / ratio))

        ext = next(drawing.iter(extent_qn), None)
        if ext is not None:
            ext.set("cx", str(target_cx))
            ext.set("cy", str(new_cy))
        for ae in drawing.iter(ext_a_qn):
            ae.set("cx", str(target_cx))
            ae.set("cy", str(new_cy))

        print(
            f"  Fig. {fig_n:>2}: {img.size[0]}x{img.size[1]} (ratio={ratio:.3f}) "
            f"-> {TARGET_W_IN:.2f}x{new_cy/EMU_PER_INCH:.2f}\""
        )
        resized += 1

    doc.save(str(DOC))
    print(f"\nResized {resized} figures to {TARGET_W_IN}\" wide (matches JCM template default)")


if __name__ == "__main__":
    main()
