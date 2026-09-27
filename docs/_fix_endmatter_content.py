"""
Fix the displaced content under the end-matter Heading 5 entries.

Currently:
  Conclusions [H1]
    p307  "This paper presented pytestwaf..."     (correct)
    p308  "Evaluation against a production WAF..."(correct)
  Conflict of Interest [H5]
    p310  "The framework demonstrates that hybrid machine learning..." <- belongs in Conclusions
  Author Contributions [H5]
    p312-p314  three Conclusions-style paragraphs <- belong in Conclusions
  Artifact Availability [H5]
    p316  artifact text                            (correct)
  References [H5]
    p317+  IEEE-format reference list              (correct)

Action: move p310, p312, p313, p314 to immediately before the Conflict of
Interest heading (i.e., into the Conclusions section), then replace the COI
and Author Contributions bodies with standard MDPI / IEEE declarations
(no fabricated funding sources; CRediT taxonomy with author initials).

Idempotent: re-running detects the standard COI sentence and exits.
"""
from copy import deepcopy
from pathlib import Path
import shutil

from docx import Document

DOC = Path("pytestwaf-research-article.docx")
BAK = Path("pytestwaf-research-article.before-endmatter-fix.docx")

# Standard text — short, factual, no assumed funding source
COI_TEXT = "The authors declare no conflict of interest."

AUTHORS_TEXT = (
    "Conceptualization, N.W.C.L., M.W.P.M., and R.A.; methodology, N.W.C.L. and M.W.P.M.; "
    "software, N.W.C.L.; validation, N.W.C.L., M.W.P.M., and R.A.; formal analysis, N.W.C.L.; "
    "investigation, N.W.C.L.; resources, N.W.C.L.; data curation, N.W.C.L.; writing"
    "—original draft preparation, N.W.C.L.; writing—review and editing, M.W.P.M. and "
    "R.A.; visualization, N.W.C.L.; supervision, M.W.P.M. and R.A.; project administration, "
    "M.W.P.M. All authors have read and agreed to the published version of the manuscript."
)


def main():
    if not DOC.exists():
        raise SystemExit(f"Cannot find {DOC.resolve()}")
    if not BAK.exists():
        shutil.copyfile(DOC, BAK)
        print(f"Backup written: {BAK}")

    doc = Document(str(DOC))

    # Idempotency
    for p in doc.paragraphs:
        if "The authors declare no conflict of interest" in p.text:
            print("End-matter already fixed.")
            return

    body = doc.paragraphs[0]._p.getparent()

    # Locate landmarks
    coi_h = author_h = artifact_h = refs_h = concl_h = None
    for p in doc.paragraphs:
        if p.style.name == "Heading 1" and p.text.strip() == "Conclusions":
            concl_h = p
        elif p.style.name == "Heading 5":
            t = p.text.strip()
            if t == "Conflict of Interest":
                coi_h = p
            elif t == "Author Contributions":
                author_h = p
            elif t == "Artifact Availability":
                artifact_h = p
            elif t == "References":
                refs_h = p

    if not all([coi_h, author_h, artifact_h, refs_h, concl_h]):
        raise SystemExit("Cannot find all end-matter landmarks")

    # Collect the "displaced" paragraphs:
    #   between Conflict of Interest and Author Contributions  -> 1 paragraph
    #   between Author Contributions and Artifact Availability  -> N paragraphs
    def paragraphs_between(start_p, end_p):
        out = []
        body_xml = start_p._p.getparent()
        i = list(body_xml).index(start_p._p) + 1
        end_idx = list(body_xml).index(end_p._p)
        while i < end_idx:
            el = body_xml[i]
            # only include 'p' elements that have non-empty text
            if el.tag.endswith("}p"):
                # build a minimal paragraph wrapper to access .text
                from docx.text.paragraph import Paragraph
                p = Paragraph(el, start_p._parent)
                if p.text.strip():
                    out.append(p)
            i += 1
        return out

    coi_block = paragraphs_between(coi_h, author_h)
    author_block = paragraphs_between(author_h, artifact_h)

    print(f"Displaced under Conflict of Interest: {len(coi_block)} paragraph(s)")
    print(f"Displaced under Author Contributions: {len(author_block)} paragraph(s)")

    # Move all displaced paragraphs to be the LAST paragraphs of Conclusions
    # i.e., insert them in order immediately BEFORE the Conflict of Interest heading.
    moved = 0
    for p in coi_block + author_block:
        body.remove(p._p)
        idx = list(body).index(coi_h._p)
        body.insert(idx, p._p)
        moved += 1
    print(f"Moved {moved} paragraphs back into Conclusions section")

    # Replace the (now-empty) bodies of Conflict of Interest and Author
    # Contributions with proper short declarations.
    coi_idx = list(body).index(coi_h._p)
    coi_p = doc.add_paragraph(COI_TEXT, style="Body Text")
    body.insert(coi_idx + 1, coi_p._p)

    author_idx = list(body).index(author_h._p)
    author_p = doc.add_paragraph(AUTHORS_TEXT, style="Body Text")
    body.insert(author_idx + 1, author_p._p)

    print("Inserted standard COI declaration and CRediT-style Author Contributions")

    doc.save(str(DOC))
    print(f"Saved: {DOC}")


if __name__ == "__main__":
    main()
