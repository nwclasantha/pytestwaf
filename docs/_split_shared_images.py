"""
Fix the shared-image-part bug.

After the Fig. 25 (confusion matrix) and Fig. 26 (reliability) figures
were inserted, two pairs of figures ended up sharing the same internal
docx image part:

    rId40 / image22.png  <- Fig. 14 AND Fig. 25
    rId41 / image23.png  <- Fig. 15 AND Fig. 26

Replacing the bytes for one figure therefore overwrote the other.  The
visual result was that Fig. 14 displayed the confusion-matrix bytes
(meant for Fig. 25), and Fig. 15 displayed the calibration plot (meant
for Fig. 26).

This script:
  1. Locates every <w:drawing> in document order, paired with its caption.
  2. For figures that should NOT share with a later figure, adds a NEW
     image relationship (and a new image part) so each figure has its
     own dedicated image.
  3. Writes the correct PNG bytes to each figure's dedicated part.

Idempotent.  Backup created on first run.
"""
from pathlib import Path
import re
import shutil

from PIL import Image
from docx import Document
from docx.opc.constants import RELATIONSHIP_TYPE
from docx.oxml.ns import qn
from docx.parts.image import ImagePart
from docx.image.image import Image as DocxImage

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-image-collision-fix.docx")
DIAG = Path("diagrams")

# Definitive Fig. N -> source PNG mapping
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
    27: "waf-mitre-attack.png",
    28: "waf-kill-chain.png",
    29: "waf-tactic-radar.png",
}

EMU_PER_INCH = 914400
TARGET_W_IN = 6.5


def add_image_part_from_file(doc, png_path: Path):
    """Create a NEW image part (no dedup) for png_path and return (part, rId).

    The package-level get_or_add_image_part de-dupes by SHA1, which would
    return the existing colliding part.  We bypass that by calling the
    private _add_image_part API which always creates a fresh part.
    """
    from docx.image.image import Image as DocxImage
    docx_image = DocxImage.from_file(str(png_path))
    image_part = doc.part.package.image_parts._add_image_part(docx_image)
    rid = doc.part.relate_to(image_part, RELATIONSHIP_TYPE.IMAGE)
    return image_part, rid


def main():
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    doc = Document(str(DOC))
    rels = doc.part.related_parts

    # Phase 1: walk document, build (fig_n, drawing_element, blip, current_rid) list
    drawing_qn = qn("w:drawing")
    blip_qn    = qn("a:blip")
    embed_qn   = qn("r:embed")
    extent_qn  = qn("wp:extent")
    ext_a_qn   = qn("a:ext")

    fig_blips = []  # (fig_n, drawing, blip)
    pending = []
    for p in doc.paragraphs:
        for d in p._p.iter(drawing_qn):
            for b in d.iter(blip_qn):
                pending.append((d, b))
        if p.style.name == "figure caption":
            m = re.match(r"\s*Fig\.\s*(\d+)", p.text)
            if m and pending:
                # Use the last drawing/blip seen since caption
                d, b = pending[-1]
                fig_blips.append((int(m.group(1)), d, b))
                pending = []

    # Phase 2: detect shared rIds and split them
    rid_to_figs = {}
    for fig_n, d, b in fig_blips:
        rid = b.get(embed_qn)
        rid_to_figs.setdefault(rid, []).append(fig_n)

    collisions = {rid: figs for rid, figs in rid_to_figs.items() if len(figs) > 1}
    print(f"Detected {len(collisions)} shared rIds:")
    for rid, figs in collisions.items():
        print(f"  {rid} shared by Figs {figs}")

    # For each collision: keep one figure's reference on the original rId,
    # add new image parts for the others.
    fig_to_part = {}  # fig_n -> image_part to write bytes into
    for fig_n, d, b in fig_blips:
        rid = b.get(embed_qn)
        if rid in collisions and fig_n != collisions[rid][0]:
            # This figure must get its own image part
            png = FIG_TO_FILE.get(fig_n)
            if not png:
                continue
            png_path = DIAG / png
            if not png_path.exists():
                continue
            part, new_rid = add_image_part_from_file(doc, png_path)
            b.set(embed_qn, new_rid)
            fig_to_part[fig_n] = part
            print(f"  Fig. {fig_n}: assigned new rId {new_rid}, new image part {part.partname.split('/')[-1]}")

    # Phase 3: write correct bytes to every figure's part (this also re-writes
    # the non-colliding ones so all 17 regenerated figures match their PNG).
    # Re-read the rId now that some have changed.
    for fig_n, d, b in fig_blips:
        png = FIG_TO_FILE.get(fig_n)
        if not png:
            continue
        png_path = DIAG / png
        if not png_path.exists():
            continue
        rid = b.get(embed_qn)
        part = doc.part.related_parts[rid]
        part._blob = png_path.read_bytes()

        # Set display extent to native aspect at 6.5" wide
        img = Image.open(png_path)
        ratio = img.size[0] / img.size[1]
        target_cx = int(TARGET_W_IN * EMU_PER_INCH)
        new_cy = int(round(target_cx / ratio))
        ex = next(d.iter(extent_qn), None)
        if ex is not None:
            ex.set("cx", str(target_cx))
            ex.set("cy", str(new_cy))
        for ae in d.iter(ext_a_qn):
            ae.set("cx", str(target_cx))
            ae.set("cy", str(new_cy))

    doc.save(str(DOC))
    print(f"\nSaved: {DOC}")


if __name__ == "__main__":
    main()
