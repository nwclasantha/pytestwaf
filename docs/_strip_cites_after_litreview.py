"""Strip IEEE [N] citations from body content of sections IV onward.

User policy: keep cites only in Introduction / Background / Literature
Review. After the Methodology section onward (Limitations, Proposed Solution,
Experimental Design, Results, Discussion, Ethics, Conclusions), the body
should be cite-free. Tables remain unchanged.
"""
from __future__ import annotations

import re
from pathlib import Path

SRC = Path(__file__).parent / "_build_article.py"

# Constant names whose contents must have all [N] removed.
SECTIONS_TO_STRIP = [
    "LIMITATIONS_INTRO", "LIMITATIONS_A",
    "PROPOSED_INTRO", "PROPOSED_ALGO", "PROPOSED_HYBRID",
    "PROPOSED_CORPUS", "PROPOSED_CLASSIFY", "PROPOSED_ENGINE",
    "PROPOSED_MUTATION", "PROPOSED_PERSIST",
    "EXP_INTRO", "EXP_REALTIME", "EXP_CONTINUOUS", "EXP_HYBRID",
    "EXP_AUTOFIX", "EXP_TRAINING", "EXP_DATASET", "EXP_TRAINARCH",
    "RES_INTRO", "RES_OVERALL", "RES_COMPARE", "RES_LEARN",
    "RES_ADAPT", "RES_METRICS",
    "DISCUSSION", "ETHICS", "CONCLUSIONS",
]

# Match a single [N] or [N], [M] (groups). We strip just [N], leaving the
# surrounding text intact (and clean up trailing punctuation/whitespace).
CITE_RE = re.compile(r"(?:\s*\[\d+\])+")


def strip_constant(src: str, name: str) -> tuple[str, int]:
    """Strip [N] from inside `NAME = [ ... ]` block."""
    pattern = re.compile(rf"({name}\s*=\s*\[)(.*?)(\n\])", re.DOTALL)
    m = pattern.search(src)
    if not m:
        return src, 0
    pre, body, post = m.group(1), m.group(2), m.group(3)
    new_body, n = CITE_RE.subn("", body)
    src = src[:m.start()] + pre + new_body + post + src[m.end():]
    return src, n


def main():
    src = SRC.read_text(encoding="utf-8")
    total = 0
    for name in SECTIONS_TO_STRIP:
        src, n = strip_constant(src, name)
        if n:
            print(f"  stripped {n} [N] markers from {name}")
            total += n
    SRC.write_text(src, encoding="utf-8")
    print(f"\nTotal citation markers removed: {total}")


if __name__ == "__main__":
    main()
