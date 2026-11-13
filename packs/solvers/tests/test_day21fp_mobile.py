#!/usr/bin/env python3
"""Day 21 final prep, Mobile: a side field's decoy member, Hermes string tables, codes cut in pieces, data by basename.

  .venv/bin/python -I -B tests/test_day21fp_mobile.py

No network and no token; a private ledger (the seed's judged names only). The packages are built by the encoders of
tests/mobile_codec_env.py (hermes, dotnet, axml, rn_bundle, carried from the Huntress Day 21 harnesses) on a
synthetic Day 20-shaped template (never a saved challenge APK), so every truth is known by construction.

  [S] a decoy dex a side field names beside a judged codec's `data`: unsure under <codec>:second-code, the
      document's code first (it was WRONG plain on ac5c24e); tests/test_day21_mobile_fold.py [S] has the repro cases
  [H] Hermes bytecode: the string table (header count, 32-bit small entries, overflow entries) is read string by
      string; a code glued to its neighbours, to a word of hex letters, in a UTF-16 string or past 255 characters
      is read; a code cut in two strings is apk-pieces:named-strings:hermes; two heads, or a whole code beside
      another code in pieces, are None; a file whose table does not add up is read with the ANS boundary regex only
  [N] .NET #US and [A] AXML: a code cut over two strings; two heads None; a bare `ANS-` head is never completed
  [J] a JS bundle: "ANS-"+"..."+"..." in one expression; two expressions with two codes None; an expression with a
      variable or call in it is not read
  [B] `data` names a member only by its basename or stem (X7, X8): read before the search, `...named-by-basename`,
      unsure; two members that match, a text with a `/`, classes.dex: nothing by basename
  [U] the readers alone: by_basename, pieces, js_concat_codes
  [T] every answering path above in under 5 ms; a document that names nothing costs what it did

(The Huntress [M] check of tools/day_review_markers.json and .claude/rules is dropped: neither exists in master.)
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mobile_codec_env as T  # noqa: E402  (a private ledger, no token, no network)

C, labels = T.C, T.labels
import dynamic_members as D  # noqa: E402  (on the path mobile_codec_env set)

TMPL = T.template21()
check = T.check


def run(document, members, deliveries=1):
    """(answer, CPU seconds of the solve, C.LAST, stderr). The [T] bounds are on this thread's CPU time:
    a full-suite run on a loaded machine stretched the wall time of a 1 ms solve past 5 ms (SH-08)."""
    import contextlib
    import io
    blob = T.package(TMPL, document, members)
    err = io.StringIO()
    attempt = {"artifacts": [{} for _ in range(deliveries)]}
    t0 = time.thread_time()
    with contextlib.redirect_stderr(err):
        out = C.solve_set([dict(T.QUESTION)], {}, {"set": 1, "delivery": blob, "delivery_name": "d.apk",
                                                   "attempt": attempt, "partial": {}})
    return out.get("answer"), time.thread_time() - t0, dict(C.LAST), err.getvalue()


def best_secs(document, members, first, n=3):
    """The least CPU time of `first` and n - 1 more solves of the same package."""
    return min([first] + [run(document, members)[1] for _ in range(n - 1)])


def opts(ans):
    u = labels.parse(ans) if isinstance(ans, str) and labels.is_unsure(ans) else None
    return (u.key, [tuple(o) for o in u.options]) if u else (None, [])


def one_option(label, document, members, truth, route_part, limit=0.005):
    ans, secs, last, err = run(document, members)
    secs = best_secs(document, members, secs)
    k, o = opts(ans)
    check("%s: a one-option pick of the truth (%s), %.2f ms" % (label, last.get("route"), secs * 1000),
          o == [(o[0][0], truth)] if o else False, (ans, last.get("route")))
    check("%s ... route %s" % (label, route_part), route_part in (last.get("route") or ""), last.get("route"))
    check("%s ... answered in under %.0f ms of CPU (best of 3)" % (label, limit * 1000), secs < limit, secs)
    return err


def none(label, document, members, *wrong):
    ans, secs, last, err = run(document, members)
    k, o = opts(ans)
    check("%s: None (never a guess)" % label, ans is None, (ans, last.get("route")))
    return err


def never_plain(label, document, members):
    """None, or an unsure pick the judge must accept first: never a plain answer. On the synthetic template the Day 27
    `:beside-analysis` rule (codec_search._beside_analysis) offers the package look's lone whole code as an unsure
    pick where the Huntress run on the saved Day 20 APK gave None; both are never-wrong."""
    ans, secs, last, err = run(document, members)
    check("%s: None or unsure (never a plain guess)" % label, ans is None or labels.is_unsure(ans),
          (ans, last.get("route")))
    return err


c, d = T.code21, T.decoy21
BUNDLE = "assets/index.android.bundle"
DLL = "assemblies/Huntress.Arena.dll"


def side():
    real, fake = c("fpS1"), d("fpS1")
    ans, _, last, err = run(T.doc21(codec="base64", data=T.b64(real.encode()), legacy_module="assets/old.dex"),
                            {"assets/old.dex": T.dex("Lcom/x/Old;", fake)})
    k, o = opts(ans)
    check("[S] judged base64 data + a side field's decoy dex: unsure under mobile.codec/base64:second-code",
          k == "mobile.codec/base64" + C.SECOND, (ans, k))
    check("[S] ... the document's code first, the member's after", [v for _, v in o][:2] == [real, fake], o)
    check("[S] ... NOTE mobile side member", "NOTE mobile side member:" in err, err[-300:])


def hermes():
    n = c("fpH1")
    err = one_option("[H] strings back to back", T.doc21(data=BUNDLE),
                     {BUNDLE: T.hermes(["answerCode", "DAY21-BRIDGE:hermes", n, "getAnswer"])}, n, "apk-string:hermes:named")
    check("[H] ... NOTE mobile dynamic_members names the route", "apk-string:hermes:named gives " + n in err, err[-300:])
    n = c("fpH2")
    one_option("[H] the code glued to 'Error' (a hex letter after it)", T.doc21(data=BUNDLE),
               {BUNDLE: T.hermes(["answerCode", n, "Error", "DEADBEEF"])}, n, "apk-string:hermes:named")
    n = c("fpH3")
    one_option("[H] the code a UTF-16 string", T.doc21(data=BUNDLE),
               {BUNDLE: T.hermes(["answerCode", (n, True), "getAnswer"])}, n, "apk-string:hermes:named")
    n = c("fpH4")
    long_text = "x" * 300 + " answer " + n + " " + "y" * 20
    one_option("[H] the code inside a string past 255 characters (an overflow entry)", T.doc21(data=BUNDLE),
               {BUNDLE: T.hermes(["answerCode", long_text, "getAnswer"])}, n, "apk-string:hermes:named")
    check("[U] the overflow entry is read back whole",
          D.hermes_strings(T.hermes(["a1", long_text, "b2"])) == ["a1", long_text, "b2"],
          D.hermes_strings(T.hermes(["a1", long_text, "b2"])))
    n = c("fpH5")
    one_option("[H] a code cut in two strings", T.doc21(data=BUNDLE),
               {BUNDLE: T.hermes(["answerCode", n[:9], "getAnswer", n[9:]])}, n, "apk-pieces:named-strings:hermes")
    n = c("fpH6")
    none("[H] two strings start a code", T.doc21(data=BUNDLE),
         {BUNDLE: T.hermes(["answerCode", n[:9], d("fpH6")[:9], n[9:]])})
    never_plain("[H] a whole code and another code in pieces", T.doc21(data=BUNDLE),
                {BUNDLE: T.hermes(["answerCode", d("fpH7"), n[:9], n[9:]])})
    # no table: the stage's glued shape (magic, zeros, the strings glued): never a looser regex
    glued = b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f" + bytes([94, 0, 0, 0]) + b"\0" * 120
    none("[H] no string table, the code glued to letters: not cut out of the glue", T.doc21(data=BUNDLE),
         {BUNDLE: glued + b"answerCode\0" + n.encode() + b"getAnswer" + b"\0" * 64})
    none("[H] no string table, the code glued to hex letters", T.doc21(data=BUNDLE),
         {BUNDLE: glued + b"answerCode\0" + n.encode() + b"Error" + b"\0" * 64})
    ans, _, last, _ = run(T.doc21(data=BUNDLE), {BUNDLE: glued + b"answerCode\0" + n.encode() + b"\0getAnswer" + b"\0" * 64})
    k, o = opts(ans)
    check("[H] no string table, the code between NULs: read with the boundary regex as before", o and o[0][1] == n,
          (ans, last.get("route")))


def dotnet_axml():
    n = c("fpN1")
    one_option("[N] a code cut over two #US strings", T.doc21(codec="xamarin", data=DLL),
               {DLL: T.dotnet(["ANSWER", n[:10], n[10:]])}, n, "apk-pieces:named-strings:dotnet")
    none("[N] two #US strings start a code", T.doc21(codec="xamarin", data=DLL),
         {DLL: T.dotnet(["ANSWER", n[:10], d("fpN1")[:10], n[10:]])})
    none("[N] a bare ANS- head beside 16 hex digits: not completed (a head is ANS- and 1 to 15 hex)",
         T.doc21(codec="xamarin", data=DLL), {DLL: T.dotnet(["ANSWER", n[:4], n[4:]])})
    ans, _, last, _ = run(T.doc21(codec="xamarin", data=DLL), {DLL: T.dotnet(["ANSWER", n])})
    k, o = opts(ans)
    check("[N] a whole code in #US keeps its route (apk-string:dotnet:utf16)", o == [("apk-string:dotnet:utf16", n)],
          (ans, last.get("route")))
    n = c("fpA1")
    one_option("[A] a code cut over two AXML pool strings", T.doc21(data="res/xml/arena_config.xml"),
               {"res/xml/arena_config.xml": T.axml("config", n[:6], "answer", n[6:])}, n, "apk-pieces:named-strings:axml")
    none("[A] two AXML strings start a code", T.doc21(data="res/xml/arena_config.xml"),
         {"res/xml/arena_config.xml": T.axml("config", n[:6], d("fpA1")[:6], n[6:])})


def js():
    n = c("fpJ1")
    one_option('[J] "ANS-"+"..."+"..." in one expression', T.doc21(codec="hybrid", data=BUNDLE),
               {BUNDLE: T.rn_bundle('"%s"+"%s"+"%s"' % (n[:4], n[4:12], n[12:]))}, n, "apk-pieces:named-strings:js-concat")
    one_option("[J] single quotes and spaces", T.doc21(codec="hybrid", data=BUNDLE),
               {BUNDLE: T.rn_bundle("'%s' + '%s'" % (n[:10], n[10:]))}, n, "js-concat")
    none("[J] two expressions join to two codes", T.doc21(codec="hybrid", data=BUNDLE),
         {BUNDLE: T.rn_bundle('"%s"+"%s"' % (n[:8], n[8:]), '"%s"+"%s"' % (d("fpJ1")[:8], d("fpJ1")[8:]))})
    none("[J] a variable in the expression: not read", T.doc21(codec="hybrid", data=BUNDLE),
         {BUNDLE: T.rn_bundle('t+"%s"+"%s"' % (n[:8], n[8:]))})
    none("[J] a call after the expression: not read", T.doc21(codec="hybrid", data=BUNDLE),
         {BUNDLE: T.rn_bundle('"%s"+"%s"+g(1)' % (n[:8], n[8:]))})
    never_plain("[J] a whole decoy code beside a joined one", T.doc21(codec="hybrid", data=BUNDLE),
                {BUNDLE: T.rn_bundle('"%s"' % d("fpJ2"), '"%s"+"%s"' % (n[:8], n[8:]))})


def basename():
    n = c("fpB1")
    err = one_option("[B] X7: data 'index.android.bundle' names assets/index.android.bundle",
                     T.doc21(codec="hybrid", data="index.android.bundle"), {BUNDLE: T.rn_bundle('"%s"' % n)}, n,
                     "named-by-basename")
    n = c("fpB2")
    err = one_option("[B] X8: data 'Huntress.Arena' names assemblies/Huntress.Arena.dll",
                     T.doc21(codec="xamarin", data="Huntress.Arena"), {DLL: T.dotnet(["ANSWER", n])}, n,
                     "apk-string:dotnet:utf16:named-by-basename")
    check("[B] ... NOTE mobile named member", "NOTE mobile named member: data \"Huntress.Arena\" names " + DLL in err,
          err[-300:])
    n = c("fpB3")
    one_option("[B] case folded, a .NET 8 lib_<name>.dll.so", T.doc21(codec="xamarin", data="HUNTRESS.ARENA"),
               {"lib/arm64-v8a/lib_Huntress.Arena.dll.so": T.dotnet(["ANSWER", n])}, n, "named-by-basename")
    n = c("fpB4")
    one_option("[B] a basename that names a dex: never the judged apk-string:dex", T.doc21(codec="loader", data="module.dex"),
               {"assets/module.dex": T.dex("ANSWER", n)}, n, "apk-string:dex:named-by-basename")
    members = {"assets/a/Huntress.Arena.dll": T.dotnet(["ANSWER", n]), "assets/b/Huntress.Arena.dll": T.dotnet(["X", d("fpB4")])}
    check("[U] two members match the stem: nothing by basename", D.by_basename("Huntress.Arena", members) is None)
    check("[U] a text with a / is no basename", D.by_basename("x/Huntress.Arena", {DLL: b""}) is None)
    check("[U] classes.dex, the manifest and the document are never named by stem",
          D.by_basename("classes", {"classes.dex": b""}) is None
          and D.by_basename("AndroidManifest", {"AndroidManifest.xml": b""}) is None
          and D.by_basename("huntress_puzzle", {T.PZ: b""}) is None)
    check("[U] stem and basename", D.by_basename("index.android", {BUNDLE: b""}) == BUNDLE
          and D.by_basename("INDEX.ANDROID.BUNDLE", {BUNDLE: b""}) == BUNDLE)
    # a judged codec whose data happens to be a member's stem: the document's own reading leads
    real = c("fpB5")
    hexdata = real.encode().hex()
    ans, _, last, _ = run(T.doc21(codec="hex", data=hexdata), {"assets/%s.bin" % hexdata: ("x " + d("fpB5")).encode()})
    k, o = opts(ans)
    check("[B] a judged codec's data that is also a member's stem: never the member's code plain, the document's first",
          ans != d("fpB5") and (ans == real or (o and o[0][1] == real)), (ans, k, o))


def units():
    n = c("fpU1")
    check("[U] pieces: one head, one tail", D.pieces("hermes", T.hermes(["a", n[:7], n[7:], "b"])) == (n, "hermes"))
    check("[U] pieces: two tails is nothing", D.pieces("hermes", T.hermes([n[:7], n[7:], d("fpU1")[7:]]))[0] is None)
    check("[U] js: the + rule reads only literals", D.js_concat_codes(('x="%s"+"%s";' % (n[:5], n[5:])).encode()) == {n})
    check("[U] js: a + before the first literal is not read",
          D.js_concat_codes(('x=a+"%s"+"%s";' % (n[:5], n[5:])).encode()) == set())


def timing():
    plain = T.doc21(codec="base64", data=T.b64(c("fpT1").encode()))
    best = min(run(plain, {})[1] for _ in range(5))
    check("[T] a judged document that names nothing: %.2f ms of CPU (best of 5)" % (best * 1000), best < 0.01, best)


PARTS = (side, hermes, dotnet_axml, js, basename, units, timing)


@pytest.mark.parametrize("part", PARTS, ids=lambda f: f.__name__)
def test_day21fp_mobile(part):
    T.run_part(part)


def main():
    return T.run_parts(PARTS)


if __name__ == "__main__":
    sys.exit(main())
