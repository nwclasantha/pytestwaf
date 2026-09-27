"""
Fix the display dimensions of the regenerated images in the docx.

When the embedded PNG bytes were swapped, the original drawing extents
(cx,cy in EMU) were left untouched.  Those extents were sized for the
old 4:1 wide images, so the new 3:2 images get squished horizontally
and stretched vertically -> blurred and distorted.

This script reads the actual PNG aspect ratio for each replaced figure,
keeps the existing display width (cx) in the docx, and recomputes the
display height (cy) so the image displays at its native aspect ratio.

Both <wp:extent cx cy /> (drawing extent) and the inner
<a:ext cx cy /> (graphicFrame transform) are updated.

Idempotent.
"""
from pathlib import Path
import re
import shutil

from PIL import Image
from docx import Document
from docx.oxml.ns import qn

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-image-resize.docx")
DIAG = Path("diagrams")

# Same map as the embed-replace script
FIG_TO_FILE = {
    13: "waf-attack-prevention.png",
    14: "waf-accuracy-breakdown.png",
    15: "waf-ml-bypass-cdf.png",
    16: "waf-ml-bypass-distribution.png",
    17: "waf-ml-bypass-scatter.png",
    18: "waf-ml-class-balance.png",
    19: "waf-ml-confidence-distribution.png",
    20: "waf-ml-bypass-by-encoder.png",
    21: "waf-ml-bypass-by-placement.png",
    22: "waf-ml-encoder-placement-heatmap.png",
    23: "waf-ml-attack-type-composition.png",
    24: "waf-ml-top-risk-ranked.png",
    25: "waf-ml-confusion-matrix.png",
    26: "waf-ml-calibration-plot.png",
}


def png_aspect(path: Path) -> float:
    """Return width / height for a PNG."""
    img = Image.open(path)
    return img.size[0] / img.size[1]


def main():
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    doc = Document(str(DOC))

    drawing_qn = qn("w:drawing")
    blip_qn    = qn("a:blip")
    embed_qn   = qn("r:embed")
    extent_w_qn = qn("wp:extent")
    ext_a_qn   = qn("a:ext")

    rels = doc.part.related_parts

    # Map paragraph -> (Fig. N, drawing-element)
    paragraphs = list(doc.paragraphs)
    fig_drawings = []  # list of (fig_n, drawing_element)

    pending_drawing = None
    for p in paragraphs:
        for drawing in p._p.iter(drawing_qn):
            pending_drawing = drawing
        if p.style.name == "figure caption":
            m = re.match(r"\s*Fig\.\s*(\d+)", p.text)
            if m and pending_drawing is not None:
                fig_drawings.append((int(m.group(1)), pending_drawing))
                pending_drawing = None

    print(f"Located {len(fig_drawings)} figures with drawings")

    # For each regenerated figure, recompute cy from cx using the new PNG's
    # aspect ratio.
    EMU_PER_INCH = 914400
    MAX_DISPLAY_WIDTH_INCH = 6.5  # cap any display width at 6.5"

    fixed = 0
    for fig_n, drawing in fig_drawings:
        png_name = FIG_TO_FILE.get(fig_n)
        if not png_name:
            continue
        src = DIAG / png_name
        if not src.exists():
            continue
        ratio = png_aspect(src)  # width / height of the actual PNG

        # Find the wp:extent element (the drawing's display size)
        extent = next(drawing.iter(extent_w_qn), None)
        if extent is None:
            print(f"  [warn] Fig. {fig_n}: no wp:extent found")
            continue

        cx = int(extent.get("cx"))
        cy = int(extent.get("cy"))

        # Cap display width at 6.5 inches
        max_cx = int(MAX_DISPLAY_WIDTH_INCH * EMU_PER_INCH)
        if cx > max_cx:
            cx = max_cx

        # New cy from native aspect
        new_cy = int(round(cx / ratio))

        extent.set("cx", str(cx))
        extent.set("cy", str(new_cy))

        # Also update the inner a:ext (under graphicFrame) so the picture
        # transform matches the drawing extent.
        for a_ext in drawing.iter(ext_a_qn):
            a_ext.set("cx", str(cx))
            a_ext.set("cy", str(new_cy))

        old_in_w = cx / EMU_PER_INCH
        old_in_h = cy / EMU_PER_INCH
        new_in_h = new_cy / EMU_PER_INCH
        print(
            f"  Fig. {fig_n:>2}: png={ratio:.3f}  "
            f"size {old_in_w:.2f}x{old_in_h:.2f}\" -> {old_in_w:.2f}x{new_in_h:.2f}\""
        )
        fixed += 1

    doc.save(str(DOC))
    print(f"\nResized {fixed} figures")
    print(f"Saved: {DOC}")


if __name__ == "__main__":
    main()
