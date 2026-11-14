#!/usr/bin/env python
"""wave17, Mobile: the never-wrong sweep's SUB-256 side-field wrong-plain.

A judged codec's `data` holds a decoy while a SUB-256 side field (16..MAX_PIECE characters, an all-hex or
all-base64 field) carries the REAL code embedded at an offset the whole-field transform search (field_codes)
cannot isolate -- behind a filler run of its own class, or where the whole-field decode misaligns the code.
The window scan (window_codes) reached only fields OVER MAX_PIECE, so such a field fell to field_codes alone and
the decoy stood PLAIN and WRONG (it sinks the all-or-nothing batch).

The fix extends window_codes to also scan the sub-256 side fields, under the document's own codec, in windows of
len(data), after every long field (so long-field behaviour is byte-identical). A window is kept only when it
decodes to an EXACT answer (read() returns only a strict code), so the look can only demote a plain answer to
`<key>:second-code`, never make a wrong one plain, and never a false match.

  [B->A] the base64 repro: decoy PLAIN (before) -> the real code surfaced, the answer unsure (after)
  [H]     the same for an all-hex field, with the whole-field decode misaligned
  [A]     once the window name is accepted, the real code answers plain
  [N]     fail-closed: a random all-hex / all-base64 side field fabricates no code (no false match)
  [F]     fallback byte-identical: a benign side field that embeds no code leaves the answer exactly as before
  [W]     window_codes alone finds the embedded strict code, and nothing in a field with no code
  [T]     seconds: the sub-256 window scan stays fast
"""
import base64
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mobile_codec_env as T  # noqa: E402  (its environment: a private ledger, no token, no network)

C, labels = T.C, T.labels
b64, doc, apk, solve, options, check, fresh = T.b64, T.doc, T.apk, T.solve, T.options, T.check, T.fresh

DECOY = "ANS-0123456789ABCDEF"
REAL = "ANS-FEDCBA9876543210"
DECOY2 = "ANS-AAAA1111BBBB2222"
REAL2 = "ANS-CCCC3333DDDD4444"


def learn(key, name):
    labels.learn(key, name, "accepted", attempt_id="t", answer_ids=["answer"])


def b64_text(s):
    return base64.b64encode(s.encode()).decode()


def base64_specimen(decoy, real):
    """codec base64; data decodes to the decoy; a sub-256 all-base64 side field carries base64(real) behind a
    5-char filler run (so the whole-field base64 decode never yields the literal code)."""
    data = b64_text(decoy)                       # len(data) == 28 == L
    vault = "AAAAA" + b64_text(real) + "ZZZZZ"   # the code at offset 5, after a filler run of 5
    return doc("base64", data, vault=vault), vault


def hex_specimen(decoy, real):
    """codec hex; data hex-decodes to the decoy; a sub-256 all-hex side field carries hex(real) behind a 5-char
    filler run (odd prefix, so the whole-field hex decode misaligns and yields no literal code)."""
    data = decoy.encode().hex()                  # 40 hex chars == L
    vault = "fffff" + real.encode().hex() + "ddddd"
    return doc("hex", data, vault=vault), vault


def before_shape():
    # The bug's precondition: neither the whole-field transform search nor a long-field window scan can see it.
    _, vault = base64_specimen(DECOY, REAL)
    whole = C.base.t_base64(vault.encode(), {})
    check("[B] the whole-field base64 decode holds no literal code (field_codes cannot isolate it)",
          not C.answers_in(whole or b""), C.answers_in(whole or b""))
    check("[B] the vault is a SUB-256 side field the long-field window scan never reached",
          16 <= len(vault) <= C.MAX_PIECE < 257, len(vault))


def surfaced(label, build, decoy, real, key):
    fresh()
    document, _ = build(decoy, real)
    out, _, last = solve(apk(document))
    check("%s: the decoy is no longer PLAIN" % label, out != decoy, out)
    k, opts = options(out)
    vals = [v for _, v in opts]
    check("%s: the answer is unsure under the second-code key" % label,
          labels.is_unsure(out) and k == key, "%s %s" % (k, opts))
    check("%s: the decoy reading is offered first" % label, vals[:1] == [decoy], opts)
    check("%s: the REAL embedded code is an option, read from the side field by the window scan" % label,
          real in vals and any(n.startswith("field:@") and n.endswith(":window") for n, v in opts if v == real),
          opts)
    short, _, _ = solve(apk(document), deliveries=5)
    check("%s: the same answer under a five-delivery Mastery's budget" % label, short == out, short)
    # once the judge accepts the window name for this code, it answers plain (correct, never the decoy)
    name = next(n for n, v in opts if v == real)
    learn(k, name)
    again, _, _ = solve(apk(document))
    check("%s: plain and CORRECT once the window name is accepted" % label, again == real, again)
    fresh()


def no_false_match():
    # A random all-base64 and an all-hex side field beside a legit code in `data`: nothing decodes to an exact
    # code, so the window scan adds no option and never fabricates one. The real code in `data` stays plain.
    fresh()
    noise64 = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"   # 36 base64 chars, decodes to no code
    out64, _, _ = solve(apk(doc("base64", b64_text(REAL), vault=noise64)))
    check("[N] a random all-base64 side field fabricates no code: the real `data` code stays plain",
          out64 == REAL, out64)
    noisehex = "deadbeef" * 6                            # 48 hex chars, decodes to no code
    outhex, _, _ = solve(apk(doc("hex", REAL.encode().hex(), vault=noisehex)))
    check("[N] a random all-hex side field fabricates no code: the real `data` code stays plain",
          outhex == REAL, outhex)
    fresh()


def fallback_identical():
    # Fallback byte-identical: a document whose side field embeds no code answers exactly as the same document
    # with that side field removed. The new window-scan phase is inert when it reads nothing.
    fresh()
    benign = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"          # 32 'A' (decodes to zero bytes, no code)
    with_field, _, _ = solve(apk(doc("base64", b64_text(DECOY2), vault=benign)))
    without_field, _, _ = solve(apk(doc("base64", b64_text(DECOY2))))
    check("[F] a benign side field leaves the answer identical to the field-free document (fallback = today)",
          with_field == without_field == DECOY2, "%r vs %r" % (with_field, without_field))
    fresh()


def window_codes_unit():
    # window_codes directly: it reads the embedded strict code from a sub-256 field, and nothing from a field
    # that carries no code.
    document, _ = base64_specimen(DECOY, REAL)
    own = C.own_codec(document)
    got = C.window_codes(document, DECOY, own)
    codes = [c for _, c, _ in got]
    check("[W] window_codes reads the embedded code from the sub-256 field", codes == [REAL], got)
    blank = C.window_codes(doc("base64", b64_text(DECOY), vault="AAAAAAAAAAAAAAAAAAAAAAAA"), DECOY,
                           C.own_codec(doc("base64", b64_text(DECOY))))
    check("[W] window_codes reads nothing from a sub-256 field with no code", blank == [], blank)


def timing():
    document, _ = hex_specimen(DECOY2, REAL2)
    blob = apk(document)
    fresh()
    t0 = time.perf_counter()
    for _ in range(20):
        solve(blob)
    dt = (time.perf_counter() - t0) / 20
    check("[T] a sub-256 window-scan solve stays fast (< 50 ms)", dt < 0.050, "%.4f s" % dt)
    fresh()


def base64_surfaced():
    surfaced("[B->A base64]", base64_specimen, DECOY, REAL, "mobile.codec/base64:second-code")


def hex_surfaced():
    surfaced("[H all-hex]", hex_specimen, DECOY, REAL, "mobile.codec/hex:second-code")


PARTS = (before_shape, base64_surfaced, hex_surfaced, no_false_match, fallback_identical, window_codes_unit, timing)


@pytest.mark.parametrize("part", PARTS, ids=lambda f: f.__name__)
def test_wave17_mobile_sub256(part):
    T.run_part(part)


def main():
    return T.run_parts(PARTS)


if __name__ == "__main__":
    sys.exit(main())
