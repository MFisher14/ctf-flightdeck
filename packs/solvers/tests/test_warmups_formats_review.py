#!/usr/bin/env python3
"""Offline tests of the review fixes to the Day 9 round-2 Warmups formats (solvers/warmups/esolangs.py).

  .venv/bin/python tests/test_warmups_formats_review.py

No network, no token, no saved attempt: the label ledger is an empty tempfile.mkdtemp() folder, removed
at the end. A few seconds. Prints one line per check and a last line
`TEST warmups formats review: <passed>/<checks> ...`; exits 1 when a check failed.

What is checked:

  cow        a COW loop still runs as the language says (a counting loop prints its count); a program
             whose every pass skips 240 000 instructions ends at its deadline, not seconds after it (it
             took 7.9 s against a 0.1 s deadline before the jumps were remembered and their looking
             counted against the clock); so does a nest of 120 000 loops, each looked for once.
  whitespace a megabyte of instructions is parsed inside the deadline too.
  blob       crib_decode.solve_blob on the same COW program as a blob keeps to its budget.
  base2048   the OTHER base2048 (the Rust crate and PyPI's base2048 0.1.3, not qntm's; step b2048r): the
             package's own encodings (tests/fixtures/warmups_formats/base2048_rust.json) are read back, an
             encoder written from the description writes the same strings, a mangled text is refused, and
             the sentence in it is answered plain as the whole blob and as record 09 behind Days 1 to 8.

The limits are generous (the deadline plus one second) because this machine is often under load when
the suite runs; the defect they pin was seconds to hours.
"""
import contextlib
import base64
import codecs
import io
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_warmups_formats_review_"))
os.environ["CTF_WORKDIR"] = str(TMP)          # an empty ledger, and nothing is written elsewhere
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
for _p in (REPO / "tools", REPO / "solvers" / "common", REPO / "solvers" / "warmups"):
    sys.path.insert(0, str(_p))
import crib_decode as C   # noqa: E402
import esolangs as E      # noqa: E402
import formats_more as M  # noqa: E402
import formats_tables as T  # noqa: E402

SLACK = 1.0
checks = []


def check(ok, name, detail=""):
    checks.append(bool(ok))
    print("%s %s%s" % ("PASS" if ok else "FAIL", name, (": " + str(detail)[:400]) if detail and not ok else ""))


def timed(fn, *args, **kw):
    t0 = time.perf_counter()
    out = fn(*args, **kw)
    return out, time.perf_counter() - t0


def scan_loop(n: int) -> str:
    """An endless COW loop whose every pass skips a loop of n instructions and comes back over it; the
    print behind it is never reached (a program without one is refused before it runs)."""
    return " ".join(["MoO", "MOO", "moO", "MOO"] + ["OOO"] * n + ["moo", "mOo", "moo", "Moo"])


def b2048r(data: bytes) -> str:
    """The Rust crate's encoder, from its description: eleven bits a character; a last group of one to
    three bits is a tail character, of four to ten bits a table character with the bits right-aligned."""
    out, acc, nbits = [], 0, 0
    for b in data:
        acc, nbits = (acc << 8) | b, nbits + 8
        if nbits >= 11:
            nbits -= 11
            out.append(T.BASE2048R[acc >> nbits])
            acc &= (1 << nbits) - 1
    if nbits:
        out.append((T.BASE2048R_TAIL if nbits <= 3 else T.BASE2048R)[acc])
    return "".join(out)


def records9(sentence: str, enc) -> bytes:
    days = [base64.b64encode, lambda b: codecs.encode(b.decode(), "rot13").encode(), lambda b: b.hex().encode(),
            lambda b: " ".join(f"{x:08b}" for x in b).encode(), lambda b: " ".join(str(x) for x in b).encode(),
            lambda b: " ".join(f"{x:03o}" for x in b).encode(), lambda b: "".join(f"%{x:02x}" for x in b).encode(),
            lambda b: "".join(f"&#{x};" for x in b).encode(), enc]
    idx = [i * len(sentence) // 9 for i in range(10)]
    return b"\n".join(f"{i + 1:02d}\t".encode() + days[i](sentence[idx[i]:idx[i + 1]].encode()) for i in range(9))


def base2048_rust():
    ref = json.loads((REPO / "tests" / "fixtures" / "warmups_formats" / "base2048_rust.json").read_text(encoding="utf-8"))
    rows = [(bytes.fromhex(r["hex"]), r["b2048r"]) for r in ref["rows"]]
    bad = [d.hex() for d, e in rows if M.d_b2048r(e) != d]
    check(len(rows) >= 40 and not bad, "base2048 (Rust, PyPI): %d encodings of the package are read back" % len(rows), bad[:3])
    bad = [d.hex() for d, e in rows if b2048r(d) != e]
    check(not bad, "base2048 (Rust, PyPI): the encoder written from the description writes the same strings", bad[:3])
    text = b2048r(b"calm-cloud-fern-42")
    tail = T.BASE2048R_TAIL[0]
    refused = [M.d_b2048r(text[:3] + tail + text[3:]), M.d_b2048r(text + tail + tail), M.d_b2048r(text[:-1] + T.BASE2048R[2047]),
               M.d_b2048r(text + "A"), M.d_b2048(text), M.d_b2048r(M.qntm_encode(b"calm-cloud-fern-42", T.BASE2048_PAIRS,
                                                                                    T.BASE2048_LAST_PAIRS, 11))]
    check(all(x is None for x in refused), "base2048 (Rust, PyPI): a tail character inside the text, a last character too big"
          " for its bits, a foreign character and qntm's base2048 are refused, and qntm's reader refuses this one", refused)
    wrong = []
    for slug in ("calm-cloud-fern-42", "groovy-quilt-waterfall-71", "tidy-valley-tulip-07"):
        for name, blob in (("whole", b2048r((C.CRIB + slug).encode()).encode()),
                           ("record 09", records9(C.CRIB + slug, lambda b: b2048r(b).encode()))):
            with contextlib.redirect_stderr(io.StringIO()):
                hit = C.solve_blob(blob, 2.0)
            if not hit or hit[0] != slug or "b2048r" not in [s for chain in hit[1] for s in chain]:
                wrong.append((name, slug, hit and hit[0], C.LAST.get("note")))
    check(not wrong, "base2048 (Rust, PyPI): the sentence is answered plain by the step b2048r, as the whole blob and as record 09", wrong[:2])


def main() -> int:
    try:
        base2048_rust()
        # c0 = 3; while c0: c0 -= 1, c1 += 1; print c1 as a number
        out = E.cow("MoO MoO MoO MOO MOo moO MoO mOo moo moO OOM")
        check(out == b"3", "cow: a counting loop prints its count", out)
        text = E.cow_encode(b"Nice work decoding this warmup!")
        check(E.cow(text) == b"Nice work decoding this warmup!" and E.cow(text.replace(" ", "")) == b"Nice work decoding this warmup!",
              "cow: a program without loops prints its text, spaced and packed")

        prog = scan_loop(240_000)
        out, took = timed(lambda: E.cow(prog, deadline=time.perf_counter() + 0.1))
        check(out is None and took < 0.1 + SLACK,
              "cow: a loop that skips 240 000 instructions on every pass ends at its deadline (%.2f s for 0.1 s)" % took, out)
        out, took = timed(lambda: E.cow(prog, deadline=None))
        check(out is None and took < 5, "cow: the same program without a deadline ends at its step cap (%.2f s)" % took, out)

        nest = " ".join(["MOO"] * 120_000 + ["Moo"] + ["moo"] * 120_000)
        out, took = timed(lambda: E.cow(nest, deadline=time.perf_counter() + 0.1))
        check(out is None and took < 0.1 + SLACK, "cow: a nest of 120 000 loops ends at its deadline (%.2f s for 0.1 s)" % took, out)

        ws = "   \t\n" * 200_000 + "\t\n  \n\n\n"
        out, took = timed(lambda: E.whitespace(ws, deadline=time.perf_counter() + 0.05))
        check(out is None and took < 0.05 + SLACK, "whitespace: a megabyte of pushes is not parsed past the deadline (%.2f s for 0.05 s)" % took, out)
        check(E.whitespace(E.whitespace_encode(b"calm-cloud-fern-42")) == b"calm-cloud-fern-42", "whitespace: a short program still prints its text")

        with contextlib.redirect_stderr(io.StringIO()):
            hit, took = timed(C.solve_blob, prog.encode(), 0.15, retry=0)
        check(hit is None and took < 0.15 + SLACK, "blob: the COW program as a blob keeps to its 0.15 s budget (%.2f s)" % took, hit)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("TEST warmups formats review: %d/%d checks passed" % (sum(checks), len(checks)))
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
