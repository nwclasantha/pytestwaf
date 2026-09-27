"""
Replace the embedded image bytes inside pytestwaf-research-article.docx
with the regenerated PNGs in docs/diagrams/.

Strategy:
  1. Walk the document body in order.
  2. For each paragraph that contains a <w:drawing>, capture the
     referenced image part by following the r:embed relationship.
  3. The next figure-caption paragraph tells us the Fig. N number.
  4. The Fig. N number maps to a known regenerated PNG.
  5. Replace the bytes of that image part with the new PNG.

Idempotent: re-running just re-replaces with the latest PNG bytes
(no harm; the file content is whatever the regen script most recently
produced).
"""
from pathlib import Path
import re
import shutil

from docx import Document
from docx.oxml.ns import qn

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-image-refresh.docx")
DIAG = Path("diagrams")

# Map Fig. N -> path of the regenerated PNG to embed
FIG_TO_FILE = {
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


def main():
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    doc = Document(str(DOC))
    rels = doc.part.related_parts

    # Walk paragraphs in order, find each <w:drawing> with a:blip r:embed,
    # and pair it with the next figure-caption Fig. N.
    drawing_qn = qn("w:drawing")
    blip_qn = qn("a:blip")  # in DrawingML

    # In python-docx the image-blip embed attr is in r namespace
    embed_attr = qn("r:embed")

    paragraphs = list(doc.paragraphs)
    pending_image_part = None  # image part attached to the most-recently-seen drawing

    image_assignments = []  # list of (fig_n, image_part)

    for p in paragraphs:
        # Does this paragraph contain a drawing?
        for drawing in p._p.iter(drawing_qn):
            for blip in drawing.iter(blip_qn):
                rid = blip.get(embed_attr)
                if rid:
                    img_part = rels[rid]
                    pending_image_part = img_part

        # Is this a figure-caption paragraph?
        if p.style.name == "figure caption":
            m = re.match(r"\s*Fig\.\s*(\d+)", p.text)
            if m and pending_image_part is not None:
                image_assignments.append((int(m.group(1)), pending_image_part))
                pending_image_part = None

    print(f"Located {len(image_assignments)} (figure -> image-part) pairs")
    for fig_n, _ in sorted(image_assignments):
        print(f"  Fig. {fig_n}")

    # Replace bytes for figures we have regenerated
    replaced = 0
    for fig_n, img_part in image_assignments:
        png_name = FIG_TO_FILE.get(fig_n)
        if not png_name:
            continue
        src = DIAG / png_name
        if not src.exists():
            print(f"  [skip] Fig. {fig_n}: {src} not found")
            continue
        new_bytes = src.read_bytes()
        # Replace the image part's blob via its underlying _blob attribute.
        img_part._blob = new_bytes
        replaced += 1
        print(f"  swapped Fig. {fig_n} <- {png_name} ({len(new_bytes)} bytes)")

    doc.save(str(DOC))
    print(f"\nReplaced {replaced} embedded images")
    print(f"Saved: {DOC}")


if __name__ == "__main__":
    main()
