"""Convert all architecture figures (PPTX slides + Mermaid renders) to
publication-style grayscale to match the IEEE academic look-and-feel.

Source figures:
  - docs/pptx_extracted/slide01.png .. slide10.png  (PPTX architecture)
  - docs/diagrams/00-overview.png, 09-full-architecture.png, 02-training.png,
    03-prediction.png  (Mermaid diagrams used in the article)

Output: <name>_gs.png next to each source. The article builder is updated
to point Fig 1-6, 14-19 at the *_gs.png variants.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageEnhance

DOCS = Path(__file__).parent
PPTX = DOCS / "pptx_extracted"
DIAG = DOCS / "diagrams"

SOURCES = [
    PPTX / "slide01.png",
    PPTX / "slide02.png",
    PPTX / "slide03.png",
    PPTX / "slide04.png",
    PPTX / "slide05.png",
    PPTX / "slide06.png",
    PPTX / "slide07.png",
    PPTX / "slide08.png",
    PPTX / "slide09.png",
    PPTX / "slide10.png",
    DIAG / "00-overview.png",
    DIAG / "02-training.png",
    DIAG / "03-prediction.png",
    DIAG / "09-full-architecture.png",
]


def convert(src: Path) -> Path:
    img = Image.open(src).convert("RGB")

    # Convert to grayscale via luminance, then back to RGB so PNG stays
    # color-mode-compatible with all renderers.
    gray = img.convert("L")

    # Slightly desaturate-but-keep-structure: increase contrast a little so
    # text stays sharp after downsampling, then convert back to RGB.
    enhanced = ImageEnhance.Contrast(gray).enhance(1.15)
    rgb = enhanced.convert("RGB")

    out = src.with_name(src.stem + "_gs.png")
    rgb.save(out, optimize=True)
    return out


def main():
    for src in SOURCES:
        if not src.exists():
            print(f"  MISSING: {src}")
            continue
        out = convert(src)
        size_kb = out.stat().st_size // 1024
        print(f"  {src.name} -> {out.name}  ({size_kb} KB)")
    print("\nDone.")


if __name__ == "__main__":
    main()
