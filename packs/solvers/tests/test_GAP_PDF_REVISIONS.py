#!/usr/bin/env python3
"""GAP-PDF-REVISIONS: the PDF incremental-revision splitter (solvers/toolkits/pdf_revisions.py).

Offline, no Game Master request, no token. Proves the structural readers (classic xref AND xref
stream, the /Prev chain, prior-state recovery) and the never-wrong boundary of solve_set:
  - a deterministic count is PLAIN only when the whole chain resolves and the noun pins the number;
  - an author-named SELECTION is labels.candidates -- UNSURE, never plain;
  - a broken/ambiguous chain, a foreign-lane id and an unrelated question are None;
  - everything is bounded and fail-closed (garbage and a truncated /Prev never crash).

  .venv/bin/python tests/test_GAP_PDF_REVISIONS.py
"""
import re
import sys
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.dont_write_bytecode = True

import labels          # noqa: E402
import pdf_revisions as P   # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + label + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(label)


def _xref_stream_pdf() -> bytes:
    """A single-revision PDF whose cross-reference is an xref STREAM (PDF 1.5+), FlateDecode,
    W=[1 3 1]. Proves pdf_revisions handles the stream form as well as the classic table."""
    out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    off = {}

    def add(n, body):
        off[n] = len(out)
        out.extend(b"%d 0 obj\n" % n + body + b"\nendobj\n")

    add(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    add(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    add(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>")
    content = b"BT /F1 24 Tf 20 100 Td (SECRET) Tj ET"       # /Length is its true length: object_at ends a stream by it
    add(4, b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")

    xref_off = len(out)
    # rows for objects 0..5, width 1+3+1 = 5: [type][offset:3][gen:1]
    rows = bytearray()
    rows += bytes([0, 0, 0, 0, 255])                       # obj 0: free
    for n in (1, 2, 3, 4):
        rows += bytes([1]) + off[n].to_bytes(3, "big") + bytes([0])
    rows += bytes([1]) + xref_off.to_bytes(3, "big") + bytes([0])   # obj 5: the xref stream itself
    body = zlib.compress(bytes(rows))
    out.extend(b"5 0 obj\n<< /Type /XRef /Size 6 /W [1 3 1] /Root 1 0 R "
               b"/Filter /FlateDecode /Length %d >>\nstream\n" % len(body))
    out.extend(body)
    out.extend(b"\nendstream\nendobj\n")
    out.extend(b"startxref\n%d\n" % xref_off + b"%%EOF\n")
    return bytes(out)


def _q(qid, question, kind="exact_text", syntax="", member="", artifact=""):
    return {"qid": qid, "answer_id": qid, "question": question,
            "answer_format": {"kind": kind, "syntax": syntax}, "member": member, "artifact": artifact}


def _solve(questions, files):
    return P.solve_set(questions, files, {})


def test_module_selftest():
    check("the module's in-file selftest passes (classic xref, /Prev chain, fail-closed)",
          P._selftest() == 0)


def test_structural_readers_classic():
    pdf = P._build_incremental_pdf()
    check("revision_count counts the 3 %%EOF boundaries", P.revision_count(pdf) == 3)
    revs = P.revisions(pdf)
    check("revisions() yields 3 records oldest-first with valid trailers",
          [r["index"] for r in revs] == [1, 2, 3] and all(r["valid"] for r in revs))
    check("each reconstructed revision is a standalone slice ending at its %%EOF",
          all(P.reconstruct(pdf, i).endswith(b"%%EOF\n") for i in (1, 2, 3)))
    o4 = P.object_at(pdf, 4, 1)
    check("prior-state recovery: object 4 at revision 1 still holds SECRET", o4 and b"SECRET" in o4)
    check("object 5 (redaction overlay) absent at rev 1, present at rev 2",
          P.object_at(pdf, 5, 1) is None and P.object_at(pdf, 5, 2) is not None)


def test_structural_readers_xref_stream():
    pdf = _xref_stream_pdf()
    check("an xref-STREAM PDF: revision_count == 1", P.revision_count(pdf) == 1)
    o4 = P.object_at(pdf, 4, 1)
    check("an xref-STREAM PDF: object_at resolves obj 4 to SECRET", o4 and b"SECRET" in o4)
    check("an xref-STREAM PDF: chain resolves", P.chain_resolves(pdf) is True)


def test_plain_only_when_proven_and_judged_shape():
    pdf = P._build_incremental_pdf()
    files = {"report.pdf": pdf}
    # PLAIN: a revision count, integer answer kind, chain fully resolves, noun pins the number
    r = _solve([_q("rev-count", "How many incremental revisions does report.pdf contain?",
                   kind="integer")], files)
    check("PLAIN: 'how many revisions' (integer, resolved chain) -> plain int 3",
          r["rev-count"] == 3 and not labels.is_unsure(r["rev-count"]))
    # PLAIN: incremental UPDATES = revisions - 1 (distinct deterministic reading)
    r = _solve([_q("upd-count", "How many incremental updates were applied to report.pdf?",
                   kind="integer")], files)
    check("PLAIN: 'how many incremental updates' -> plain int 2 (revisions - 1)",
          r["upd-count"] == 2)


def test_unsure_for_author_named_selection():
    pdf = P._build_incremental_pdf()
    files = {"report.pdf": pdf}
    r = _solve([_q("which-orig", "Which revision is the original document before the redaction?")], files)
    v = r["which-orig"]
    check("UNSURE: an author-named selection is a labels.candidates pick, never plain",
          labels.is_candidate(v) and isinstance(v, str) and v.startswith("??"))
    # the hypotheses are named, their values are DIFFERENT revision indices (never plain before judged)
    if labels.is_candidate(v):
        _key, opts = labels.parse(v)
        names = [n for n, _ in opts]
        check("the selection pick names hypotheses (earliest / latest_before_final), not values",
              "earliest" in names and all(isinstance(n, str) for n, _ in opts))


def test_ambiguous_count_noun_is_unsure_or_none_never_plain():
    """GAP (wrong-PLAIN): a count noun that names a quantity DIFFERENT from revisions/updates must
    never be a plain integer. 'saves' is ambiguous (total saves = 3 vs incremental saves = 2); the
    module used to conflate it with 'incremental updates' and return a plain n-1. It now yields
    labels.candidates of the distinct readings. A PDF object 'generation' count is a quantity we do
    not prove -> None. The genuine revision / incremental-update counts stay PLAIN (no false None)."""
    pdf = P._build_incremental_pdf()        # a clean 3-revision / 3-save PDF
    files = {"report.pdf": pdf}
    for qid, text in (("saves", "How many incremental saves does report.pdf contain?"),
                      ("prior-saves", "How many prior saves does report.pdf have?")):
        v = _solve([_q(qid, text, kind="integer")], files)[qid]
        check(f"UNSURE: an ambiguous 'saves' count ({qid}) is labels.candidates, never a plain int",
              labels.is_candidate(v) and isinstance(v, str) and v.startswith("??"), v)
        if labels.is_candidate(v):
            key, opts = labels.parse(v)
            check(f"the 'saves' candidate ({qid}) offers the DISTINCT readings 3 and 2, not one guess",
                  {val for _n, val in opts} == {"3", "2"}, opts)
            check(f"the ambiguous count ({qid}) is keyed APART from the author-named selection pick",
                  "pdf_count_interpretation" in key and "pdf_original_revision" not in key, key)
    v = _solve([_q("gens", "How many generations of report.pdf are stored?", kind="integer")], files)["gens"]
    check("NONE: a 'generations' count (a distinct, unproven quantity) is None, never plain", v is None, v)
    r = _solve([_q("rev", "How many incremental revisions does report.pdf contain?", kind="integer"),
                _q("upd", "How many incremental updates were applied to report.pdf?", kind="integer")], files)
    check("PLAIN preserved: revisions -> plain 3, incremental updates -> plain 2 (no false None)",
          r["rev"] == 3 and not labels.is_unsure(r["rev"])
          and r["upd"] == 2 and not labels.is_unsure(r["upd"]), r)


def test_none_when_chain_broken_or_foreign_or_unrelated():
    pdf = P._build_incremental_pdf()
    # a broken /Prev chain: a count question must be None, never a partial guess
    broken = bytearray(pdf)
    last_prev = broken.rfind(b"/Prev ")
    m = re.compile(rb"/Prev (\d+)").search(bytes(broken), last_prev)
    broken[m.start(1):m.end(1)] = b"9" * (m.end(1) - m.start(1))
    r = _solve([_q("rev-count", "How many revisions does it contain?", kind="integer")],
               {"report.pdf": bytes(broken)})
    check("NONE: a count over a broken /Prev chain is None (never a partial guess)",
          r["rev-count"] is None)

    files = {"report.pdf": pdf}
    # a foreign lane owns these ids / phrasings -> None (pdf_revisions does not poach)
    r = _solve([_q("d23_magic", "What is the magic at the last revision?", kind="integer"),
                _q("ANS-1", "Decode the revision", kind="exact_text"),
                _q("x-role", "the revision role", kind="exact_text"),
                _q("det", "Determine the revision count for report.pdf", kind="integer")], files)
    check("NONE: foreign-lane ids and 'Determine X for Y' phrasing are declined",
          all(r[k] is None for k in ("d23_magic", "ANS-1", "x-role", "det")))

    # an unrelated question (no revision vocabulary) -> None even on a multi-revision PDF
    r = _solve([_q("author", "What is the author of the document?")], files)
    check("NONE: a question with no revision vocabulary is None", r["author"] is None)

    # ambiguous noun (neither 'revision' nor 'update' pins the number) -> None
    r = _solve([_q("amb", "How many incremental things are there?", kind="integer")], files)
    check("NONE: an ambiguous count noun is None", r["amb"] is None)


def test_signals():
    pdf3 = P._build_incremental_pdf()
    one = pdf3[:pdf3.find(b"%%EOF") + len(b"%%EOF") + 1]
    revq = [_q("q", "How many incremental revisions are present?", kind="integer")]
    check("signals > 0.5 on a multi-revision PDF with revision vocabulary",
          P.signals(revq, {"report.pdf": pdf3}) > 0.5)
    check("signals == 0 on a single-revision PDF", P.signals(revq, {"report.pdf": one}) == 0.0)
    check("signals == 0 on a non-PDF delivery", P.signals(revq, {"a.bin": bytes(64)}) == 0.0)


def test_bounded_and_failclosed():
    check("garbage bytes: no crash, empty / 0 / None",
          P.revisions(b"\x00\xff not pdf") == [] and P.revision_count(b"x") == 0
          and P.object_at(b"x", 1, 1) is None and P.reconstruct(b"x", 1) is None)
    storm = b"%PDF-1.4\n" + P._EOF * (P.MAX_REVISIONS + 1000)
    check("bounded: a %%EOF storm is capped at MAX_REVISIONS", P.revision_count(storm) <= P.MAX_REVISIONS)
    check("solve_set never raises on a malformed delivery",
          _solve([_q("q", "how many revisions", kind="integer")], {"x.pdf": b"%PDF-\nbroken"})["q"] is None)


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print()
    if FAILED:
        print(f"FAILED {len(FAILED)}: " + "; ".join(FAILED))
        return 1
    print("all GAP-PDF-REVISIONS checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
