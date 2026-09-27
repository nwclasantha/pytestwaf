"""
Replace every em-dash (U+2014, "—") in pytestwaf-research-article.docx with
a plain comma + space.  Covers body paragraphs, headings, figure captions,
and table cells.

Idempotent (re-running is a no-op once em-dashes are gone).  Backup created
on first run.
"""
from pathlib import Path
import shutil

from docx import Document

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-em-dash-removal.docx")

EM = "—"  # em-dash
REPL = ", "


def fix_runs(p) -> int:
    """Replace em-dashes in every run of paragraph p. Returns number of em-dashes removed."""
    n = 0
    for r in p.runs:
        if r.text and EM in r.text:
            n += r.text.count(EM)
            r.text = r.text.replace(EM, REPL)
    return n


def main():
    if not DOC.exists():
        raise SystemExit(f"Cannot find {DOC.resolve()}")
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    doc = Document(str(DOC))
    total = 0

    # All top-level paragraphs (body, headings, captions, references, etc.)
    for p in doc.paragraphs:
        total += fix_runs(p)

    # All table cells
    for t in doc.tables:
        for row in t.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    total += fix_runs(p)

    # Tidy up the few cases where the replacement creates an obvious
    # double-punctuation artefact.  We do this by scanning paragraph text
    # again and applying targeted string replaces.
    cleanups = [
        (",  ,", ","),   # ", X—" + ",..." -> ",  ,..."
        (", , ", ", "),  # rare cascade
        (", .", "."),    # trailing-em-dash before period
        (",.", "."),
        (", ;", ";"),
        (",;", ";"),
    ]
    for p in doc.paragraphs:
        if not p.runs:
            continue
        joined = "".join(r.text for r in p.runs)
        new = joined
        for a, b in cleanups:
            new = new.replace(a, b)
        if new != joined:
            # Push the cleaned text back into the first run; clear the rest.
            p.runs[0].text = new
            for r in p.runs[1:]:
                r.text = ""

    doc.save(str(DOC))
    print(f"Em-dashes replaced: {total}")
    print(f"Saved: {DOC}")


if __name__ == "__main__":
    main()
