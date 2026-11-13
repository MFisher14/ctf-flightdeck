#!/usr/bin/env python3
"""Never-wrong hardening, Mobile (wave12): the two remaining decoy WRONG-plain holes of the long side-field
window scan, closed by the dense every-offset scan (codec_search._long_dense / window_codes / long_field_unscanned).

  .venv/bin/python tests/test_nw_mobile_decoy.py

A judged codec's `data` holds a DECOY code; the real code is hidden, encoded under the document's own codec, in a
top-level side field longer than 256 characters. window_codes reads windows of len(data) along a run of the class
`data` is written in, but it STEPS by the class stride (2 for hex, 4 for base64/url): it never reads a phase-shifted
offset, and its strided reading is capped at LONG_WINDOWS+ANCHORS windows. The committed long_field_unscanned used
`n - L + 1 <= LONG_WINDOWS + ANCHORS` to call a run "fully scanned" -- ignoring the stride -- so a code at an offset
the stride skips, inside a run that measure calls short, stood unread and the decoy in `data` was answered PLAIN
(WRONG; the all-or-nothing batch is then lost).

  Hole 1  the real code in a LONG (>256) side field at a stride-aligned offset past the LONG_WINDOWS cap.
  Hole 2  the real code in a long PAD-LESS, FILLER-LESS field (hex/reverse) at an offset the strided scan skips.

In both the solver must NEVER answer the decoy plain: it either FINDS the real code (offered as a second code, the
decoy demoted to an unsure pick) where the dense scan can afford every offset, or FAILS CLOSED to an unsure
candidate pick where it cannot. Checked here against the real codec_search.solve_set.

  [1] hex, short runs in a >256 field, every offset (incl. the stride-skipped odd ones): never the decoy plain
  [2] reverse (a pad-less, filler-less class), short runs, non-stride offsets: never the decoy plain
  [3] base64 and base32 (the other strided classes): never the decoy plain
  [4] a single >256 run, the code at a stride-aligned offset past the LONG_WINDOWS cap (Hole 1): never the decoy plain
  [5] FOUND: a single run the dense budget can afford -> the real code is offered as field:@...:window, decoy demoted
  [6] FAIL-CLOSED: runs past the dense budget -> an unsure candidate pick of the lone reading, never the decoy plain
  [7] no regression: a pure repeated-character filler field, and a legit short side field, stay plain; same under a
      five-delivery Mastery's budget
  [T] seconds: a 4096-character strided side field is answered in well under 100 ms
"""
import base64
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mobile_codec_env as T  # noqa: E402  (a private ledger, no token, no network)

C, labels = T.C, T.labels
code_for, decoy_for, b64, doc, apk, solve, options, fresh = (
    T.code_for, T.decoy_for, T.b64, T.doc, T.apk, T.solve, T.options, T.fresh)

check = T.check   # one tally (mobile_codec_env.PASSED / FAILED) for script and pytest mode


def enc(codec, code):
    if codec == "base64":
        return b64(code.encode())
    if codec == "hex":
        return code.encode().hex()
    if codec == "reverse":
        return code[::-1]
    if codec == "base32":
        return base64.b32encode(code.encode()).decode()
    raise ValueError(codec)


CLASSCHARS = {
    "hex": "0123456789abcdef",
    "base64": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "reverse": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",   # the reversed code's class is url-safe (holds '-')
    "base32": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
}


def classify(blob, real, decoy):
    """(kind, decoy_plain, real_offered, out) for one solve."""
    fresh()
    out, _, _ = solve(blob)
    k, opts = options(out)
    offered = [v for _, v in opts]
    if out is None:
        kind = "None"
    elif isinstance(out, str) and labels.is_unsure(out):
        kind = "UNSURE"
    else:
        kind = "PLAIN"
    return kind, (kind == "PLAIN" and out == decoy), (real in offered), out


def side_field(codec, hidden, off, runlen, nruns):
    """A side field of `nruns` class-runs of `runlen` characters separated by spaces (so each is its own run),
    the middle run holding `hidden` at offset `off`. Deterministic filler, no repeated-character runs."""
    fc = CLASSCHARS[codec]
    def frun(k, seed):
        return "".join(fc[(seed * 7 + i * 13) % len(fc)] for i in range(k))
    target = frun(off, 1) + hidden + frun(max(0, runlen - off - len(hidden)), 2)
    runs = [frun(runlen, i + 3) for i in range(nruns)]
    runs[nruns // 2] = target
    return " ".join(runs)


# ------------------------------------------------------------------- [1][2][3] never the decoy plain, every offset
def never_decoy_plain(codec, offsets, runlens=(45, 60, 80)):
    bad, found, closed = [], 0, 0
    for runlen in runlens:
        for off in offsets:
            real, decoy = code_for("r%s%d%d" % (codec, off, runlen)), decoy_for("d%s%d%d" % (codec, off, runlen))
            data, hidden = enc(codec, decoy), enc(codec, real)
            side = side_field(codec, hidden, off, runlen, nruns=11)
            if len(side) <= C.MAX_PIECE or hidden not in side:
                continue
            blob = apk(doc(codec, data, audit_log=side))
            kind, decoy_plain, real_offered, out = classify(blob, real, decoy)
            if decoy_plain:
                bad.append((off, runlen, out))
            elif real_offered:
                found += 1
            else:
                closed += 1
    check("[%s] a decoy in data, the real code in a >256 side field: never the decoy plain (found=%d, closed=%d)"
          % (codec, found, closed), not bad, bad)


# ------------------------------------------------------------------- [4] Hole 1: single long run past the cap
def hole1_single_long_run():
    bad = []
    for runlen in (300, 600, 1200, 2000):
        for off in (64, 100, 200, 400, 900):   # stride-aligned (even) offsets, many past LONG_WINDOWS*2
            if off + 40 >= runlen:
                continue
            real, decoy = code_for("h1%d%d" % (off, runlen)), decoy_for("h1%d%d" % (off, runlen))
            data, hidden = enc("hex", decoy), enc("hex", real)
            fc = CLASSCHARS["hex"]
            body = "".join(fc[(i * 13 + 5) % 16] for i in range(runlen))
            side = body[:off] + hidden + body[off + len(hidden):]   # one long hex run, varied content
            side = side[:runlen]
            if len(side) <= C.MAX_PIECE or hidden not in side:
                continue
            blob = apk(doc("hex", data, audit_log=side))
            kind, decoy_plain, real_offered, out = classify(blob, real, decoy)
            if decoy_plain:
                bad.append((off, runlen, out))
    check("[4] Hole 1: a single >256 run, the code at a stride-aligned offset past the LONG_WINDOWS cap: never the "
          "decoy plain", not bad, bad)


# ------------------------------------------------------------------- [5] FOUND where the budget can afford it
def found_when_affordable():
    real, decoy = code_for("found"), decoy_for("found")
    data, hidden = enc("hex", decoy), enc("hex", real)   # L=40
    fc = CLASSCHARS["hex"]
    runA = "".join(fc[(i * 11 + 1) % 16] for i in range(7)) + hidden + "".join(fc[(i * 11 + 2) % 16] for i in range(20))
    side = runA + " " + "".join(fc[(i * 7 + 3) % 16] for i in range(220))   # one short run (code) + a filler run; >256
    assert hidden in side and len(side) > C.MAX_PIECE
    blob = apk(doc("hex", data, blob=side))
    kind, decoy_plain, real_offered, out = classify(blob, real, decoy)
    k, opts = options(out)
    where = [n for n, v in opts if v == real]
    check("[5] FOUND: a short run the dense scan affords -> real code offered as a second code, decoy demoted",
          kind == "UNSURE" and real_offered and not decoy_plain and any("window" in n for n in where),
          "%s %s" % (k, opts))
    short, _, _ = solve(blob, deliveries=5)
    check("[5] ... the same answer under a five-delivery Mastery's budget", short == out, short)


# ------------------------------------------------------------------- [6] FAIL-CLOSED beyond the budget
def fail_closed_beyond_budget():
    real, decoy = code_for("closed"), decoy_for("closed")
    data, hidden = enc("hex", decoy), enc("hex", real)
    side = side_field("hex", hidden, 3, 60, nruns=14)   # 14 runs > the dense budget can cover
    assert hidden in side and len(side) > C.MAX_PIECE
    blob = apk(doc("hex", data, blob=side))
    kind, decoy_plain, real_offered, out = classify(blob, real, decoy)
    k, _ = options(out)
    check("[6] FAIL-CLOSED: runs past the dense budget -> an unsure candidate pick, never the decoy plain",
          kind == "UNSURE" and not decoy_plain and labels.is_candidate(out), "%s %s" % (kind, k))
    short, _, _ = solve(blob, deliveries=5)
    check("[6] ... the same answer under a five-delivery Mastery's budget", short == out, short)


# ------------------------------------------------------------------- [7] no regression on safe shapes
def no_regression_safe_shapes():
    real = code_for("legit")
    # a pure repeated-character long field (Day 20 look-ahead [L]): stays plain
    blob = apk(doc("base64", enc("base64", real), note="x" * 400))
    k1, dp1, ro1, out1 = classify(blob, real, decoy_for("x"))
    check("[7] a pure repeated-character >256 field stays plain (the real code)", out1 == real, out1)
    short, _, _ = solve(blob, deliveries=5)
    check("[7] ... the same under a five-delivery Mastery's budget", short == out1, short)
    # a legit short side field (<= MAX_PIECE) that holds no code: the base reads `data` plain
    blob2 = apk(doc("base64", enc("base64", real), hint="build 1.0.0, release channel stable"))
    k2, dp2, ro2, out2 = classify(blob2, real, decoy_for("y"))
    check("[7] a legit short side field with no code stays plain (the real code)", out2 == real, out2)


# ------------------------------------------------------------------- [T] timing
def timing():
    real, decoy = code_for("time"), decoy_for("time")
    data, hidden = enc("hex", decoy), enc("hex", real)
    side = side_field("hex", hidden, 3, 60, nruns=66)[:C.LONG_FIELD]   # a full 4096-char strided side field
    blob = apk(doc("hex", data, audit_log=side))
    fresh()
    t0 = time.perf_counter()
    solve(blob)
    dt = (time.perf_counter() - t0) * 1000
    check("[T] a 4096-character strided side field answered in under 100 ms (%.1f ms)" % dt, dt < 100, dt)


def hex_offsets():
    never_decoy_plain("hex", offsets=(1, 2, 3, 5, 7, 9, 11, 13, 0, 4, 8))


def reverse_offsets():
    never_decoy_plain("reverse", offsets=(1, 2, 3, 5, 7, 11, 0, 4))


def base64_offsets():
    never_decoy_plain("base64", offsets=(1, 2, 3, 5, 7, 0, 4, 8))


def base32_offsets():
    never_decoy_plain("base32", offsets=(1, 2, 3, 4, 5, 7, 0))


PARTS = (hex_offsets, reverse_offsets, base64_offsets, base32_offsets, hole1_single_long_run, found_when_affordable,
         fail_closed_beyond_budget, no_regression_safe_shapes, timing)


@pytest.mark.parametrize("part", PARTS, ids=lambda f: f.__name__)
def test_nw_mobile_decoy(part):
    T.run_part(part)


def main():
    return T.run_parts(PARTS)


if __name__ == "__main__":
    sys.exit(main())
