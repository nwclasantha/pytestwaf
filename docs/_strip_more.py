"""Final polish on _build_article.py source:
- Strip [N] citations from ABSTRACT, KEYWORDS, INTRO, BACKGROUND
  (keep cites only in Literature Review).
- Replace em-dashes (—) and en-dashes (–) with comma+space or colon
  for cleaner science-journal punctuation.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).parent / "_build_article.py"

# Constants whose contents must have all [N] removed
NO_CITE_CONSTANTS = ["ABSTRACT", "KEYWORDS", "INTRO", "BACKGROUND"]

CITE_RE = re.compile(r"(?:\s*\[\d+\])+")


def strip_constant(src: str, name: str) -> tuple[str, int]:
    """Strip [N] from inside `NAME = ...` block (literal or list)."""
    # Match either `NAME = (` (tuple/string concat) or `NAME = [` (list)
    pattern = re.compile(
        rf"({name}\s*=\s*[\(\[])(.*?)(\n[\)\]])", re.DOTALL
    )
    m = pattern.search(src)
    if not m:
        return src, 0
    pre, body, post = m.group(1), m.group(2), m.group(3)
    new_body, n = CITE_RE.subn("", body)
    src = src[:m.start()] + pre + new_body + post + src[m.end():]
    return src, n


def replace_dashes(src: str) -> int:
    """Replace em-dashes (U+2014) and en-dashes (U+2013) with cleaner
    punctuation in the body content portion of the file. Skip:
    - The REFERENCES list (en-dashes are legitimate page-range separators).
    - Tables (table content kept as-is).
    """
    # Process only the section before the REFERENCES = [ marker
    cut = src.index("REFERENCES = [")
    head = src[:cut]
    tail = src[cut:]

    n = 0
    # Em-dash → comma space (most common journalistic substitute)
    em = "—"
    n += head.count(em)
    head = head.replace(em, ", ")

    # En-dash inside number ranges 0–1 etc → keep as hyphen
    # Otherwise en-dash → space hyphen space
    en = "–"
    # Replace number-en-dash-number with number-hyphen-number
    head = re.sub(r"(\d)" + en + r"(\d)", r"\1-\2", head)
    n += head.count(en)
    head = head.replace(en, ", ")

    return head + tail, n


def main():
    src = SRC.read_text(encoding="utf-8")

    total_cites = 0
    for name in NO_CITE_CONSTANTS:
        src, n = strip_constant(src, name)
        if n:
            print(f"  stripped {n} [N] from {name}")
            total_cites += n

    src, n_dashes = replace_dashes(src)
    print(f"\nDashes replaced: {n_dashes}")
    print(f"Total cite markers stripped: {total_cites}")

    SRC.write_text(src, encoding="utf-8")


if __name__ == "__main__":
    main()
