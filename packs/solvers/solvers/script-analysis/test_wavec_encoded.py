#!/usr/bin/env python3
"""Offline test of row 77: Microsoft Script Encoder files (screnc.py and its dispatch in analyze.py).

Usage:
  PYTHONDONTWRITEBYTECODE=1 .venv/bin/python solvers/script-analysis/test_wavec_encoded.py [-v]

No Game Master request and no token. It reads the saved Script Analysis attempts of Days 2 to 4
(the JScript and VBScript specimens, every saved variant) through gm.CHALLENGES and writes
nothing but a scratch label ledger under tempfile.mkdtemp(), and the fixture files under
/private/tmp/claude-501/wave-c-encoded/fixtures when that folder can be made.

What it proves:

  tables      each column of the substitution is one-to-one over the 123 substituted characters
  wine        Wine's own test vectors (dlls/jscript/tests/run.c, from real screnc output): the
              three good blocks decode, the five bad ones (length field, checksum, closing mark)
              give no decode; this encoder writes the three good blocks byte for byte
  round trip  every saved Day 2-4 JScript and VBScript specimen, and random text, encodes and
              decodes back to itself
  .vbe/.jse   each specimen encoded and renamed .vbe/.jse answers exactly as the plain specimen:
              the same answers as the plain run (plain, unsure and None alike), and every key.json
              answer of the plain specimen equal
  hosts       an encoded block in a .vbe/.jse after a plain line, inside a .wsf (VBScript.Encode,
              CDATA and XML-escaped), an .hta and an .sct (JScript.Encode): the answers of the same
              container holding the plain script
  scope       only where the host decodes: a block in a plain .vbs/.js, or in a <script> whose
              language is not *.Encode, is left byte for byte (the same files object, no decode
              line); a decoy comment holding a block with another plan, appended to a .vbs, changes
              no answer; a bare #@~^ planted in a comment of every Day 7 base specimen (.ps1, .py,
              .vbs, .js, .cmd, ...) and of every Day 2-4 specimen changes no answer; a bare marker
              outside the Encode element of a .wsf is ignored, inside it the file is no reading
  corrupt     one changed character (checksum), a cut block, a wrong length field, a missing
              closing mark, a bad escape: every question of that specimen unanswered, the other
              specimens of the set unchanged, and covers() names the file
  speed       a Day 4 Mastery set with every JScript and VBScript specimen encoded

Last line: `TEST_WAVEC_ENCODED passed=<n> failed=<n>`. Exit 0 when nothing failed, 1 otherwise,
2 when the saved attempts are not there.
"""
import contextlib
import io
import json
import os
import random
import re
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SCRATCH = Path(tempfile.mkdtemp(prefix="test_wavec_encoded_"))
os.environ["CTF_STATE_DIR"] = str(SCRATCH / "state")
for _name in ("ONLY", "CTF_HIDE", "CTF_LEDGER_MASK", "CTF_PLATFORM_URL"):
    os.environ.pop(_name, None)
os.environ["CTF_TESTING"] = "1"
for _p in (HERE.parent.parent / "tools", HERE.parent / "common", HERE):
    sys.path.insert(0, str(_p))

import gm    # noqa: E402 - resolves the real challenges folder
import run   # noqa: E402 - load_offline and split_sets: the runner's own reading of an attempt

os.environ["CTF_WORKDIR"] = str(SCRATCH / "challenges")    # the label ledger: an empty scratch folder

import analyze      # noqa: E402
import plan_codec   # noqa: E402
import screnc       # noqa: E402

VERBOSE = "-v" in sys.argv[1:]
DAYS = ("day-02", "day-03", "day-04")
FIXTURES = Path("/private/tmp/claude-501/wave-c-encoded/fixtures")
ENCODED_EXT = {".vbs": ".vbe", ".js": ".jse"}
results = []

# Wine's dlls/jscript/tests/run.c, test_script_encoding(): (block, decoded text or None).
WINE = [
    ("#@~^EAAAAA==.\x7fwGMYUEm1+kd`*iAQYAAA==^#~@", "reportSuccess();"),
    ("report#@~^BwAAAA==j!m^\x7f/k2QIAAA==^#~@();", "reportSuccess();"),
    ("#@~^GQAAAA==@#@&d.\x7fwKDYUE1^+k/c#p@#@&OAYAAA==^#~@", "\r\n\treportSuccess();\r\n"),
    ("#@~^EAA*AA==.\x7fwGMYUEm1+kd`*iAQYAAA==^#~@", None),
    ("#@~^EAAAAAAA==.\x7fwGMYUEm1+kd`*iAQYAAA==^#~@", None),
    ("#@~^EAAAAA^=.\x7fwGMYUEm1+kd`*iAQYAAA==^#~@", None),
    ("#@~^EAAAAA==.\x7fwGMYUEm1ekd`*iAQYAAA==^#~@", None),
    ("#@~^EAAAAA==.\x7fwGMYUEm1+kd`*iAQYAAA==^~#@", None),
]


def check(name: str, ok: bool, detail: str = ""):
    results.append((name, bool(ok)))
    print(f"{'ok  ' if ok else 'FAIL'} {name}" + (f": {detail}" if detail and (VERBOSE or not ok) else ""))


def solve(qs, files):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = analyze.solve_set(qs, files, {"set": 1})
    return out, err.getvalue()


def load_variants():
    out = []
    for day in DAYS:
        for base in sorted((gm.CHALLENGES / day).glob("script-analysis-*")):
            dirs = [base, base / "time_trial"] + sorted((base / "time_trial" / "history").glob("*")) + \
                [base / "mastery"] + sorted((base / "mastery" / "history").glob("*"))
            for d in dirs:
                if not (d / "attempt.json").exists():
                    continue
                try:
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                        attempt, blobs, _ = run.load_offline("", str(d))
                        sets = run.split_sets(attempt, blobs)
                except SystemExit:
                    continue
                key = json.loads((d / "key.json").read_text()) if (d / "key.json").exists() else None
                for n, qs, files, _ in sets:
                    out.append({"name": f"{d.relative_to(gm.CHALLENGES)}#{n}", "qs": qs, "files": files,
                                "key": {q["qid"]: key["answers"].get(q["answer_id"]) for q in qs} if key else None})
    return out


def specimens(v):
    by = {}
    for q in v["qs"]:
        by.setdefault(q["member"], []).append(q)
    return by


def renamed(q, old, new):
    q = dict(q, member=new)
    if isinstance(q.get("artifact"), str):
        q["artifact"] = q["artifact"].replace(old, new)
    return q


def encoded_variant(v, rename=True, wrap=None):
    """(questions, files, {old member: new member}) of a set with every JScript and VBScript
    specimen encoded; `wrap(text, ext)` builds the file around the block, else the block alone."""
    qs, files, names = [], dict(v["files"]), {}
    for member, mqs in specimens(v).items():
        ext = Path(member).suffix.lower()
        if ext not in ENCODED_EXT:
            qs += mqs
            continue
        text = plan_codec.text_of(v["files"][member])
        block = screnc.encode(text)
        body = wrap(block, ext) if wrap else block
        new = member[: -len(ext)] + ENCODED_EXT[ext] if rename else member
        files.pop(member, None)
        files[new] = body.encode("utf-8")
        names[member] = new
        qs += [renamed(q, member, new) for q in mqs]
    return qs, files, names


# ---------------------------------------------------------------- the codec itself

def test_tables():
    ok = all(len({screnc.DICTIONARY[e][p] for e in range(128) if chr(e) not in "<>@\r\n"}) == 123 for p in range(3))
    check("tables: each of the three columns is one-to-one over the 123 substituted characters",
          ok and len(screnc.PICK) == 64 and len(screnc.DICTIONARY) == 128)


def test_wine():
    good = bad = 0
    detail = []
    for block, want in WINE:
        got, info = screnc.decode(block)
        if want is None:
            bad += got is None
            if got is not None:
                detail.append(f"decoded a bad block: {block!r}")
        else:
            good += got == want and info == 1
            if got != want:
                detail.append(f"{block!r}: {got!r} ({info})")
    check(f"wine: {good}/3 good blocks decode and {bad}/5 bad blocks give no decode", good == 3 and bad == 5,
          "; ".join(detail))
    same = [screnc.encode(t) == b[b.index("#@~^"):b.index("^#~@") + 4] for b, t in
            (("#@~^EAAAAA==.\x7fwGMYUEm1+kd`*iAQYAAA==^#~@", "reportSuccess();"),
             ("report#@~^BwAAAA==j!m^\x7f/k2QIAAA==^#~@();", "Success"),
             ("#@~^GQAAAA==@#@&d.\x7fwKDYUE1^+k/c#p@#@&OAYAAA==^#~@", "\r\n\treportSuccess();\r\n"))]
    check("wine: this encoder writes the three good blocks byte for byte", all(same), str(same))


def test_round_trip(corpus):
    n, bad = 0, []
    seen = set()
    for v in corpus:
        for member in specimens(v):
            if Path(member).suffix.lower() not in ENCODED_EXT:
                continue
            text = plan_codec.text_of(v["files"][member])
            if text in seen:
                continue
            seen.add(text)
            n += 1
            got, info = screnc.decode(screnc.encode(text))
            if got != text or info != 1:
                bad.append(f"{v['name']} {member}")
    rng = random.Random(77)
    alphabet = "".join(chr(c) for c in range(128))
    for _ in range(500):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 300)))
        n += 1
        if screnc.decode(screnc.encode(text)) != (text, 1):
            bad.append(repr(text[:40]))
    check(f"round trip: {n - len(bad)}/{n} texts ({len(seen)} distinct saved specimens, 500 random) decode back to "
          f"themselves", not bad and len(seen) >= 18, "; ".join(bad[:5]))


def test_high_chars():
    """A character above 127 inside a block: a decode only when exactly one reading matches the checksum."""
    plain = 'MsgBox "café ok"'
    # Kept as it is, taking no position and no share of the checksum (decode-vbe.py's reading).
    data, total, j = [], 0, 0
    for c in plain:
        if ord(c) >= 128:
            data.append(c)
            continue
        e = screnc.encode(c * (j + 1))      # the encoded form of c at position j
        data.append(e[12:-12][-1] if c not in screnc.ESCAPED else screnc.ESCAPED[c])
        total += ord(c)
        j += 1
    body = "".join(data)
    block = screnc.OPEN + screnc.dword_field(len(body)) + body + screnc.dword_field(total) + screnc.CLOSE
    got, info = screnc.decode(block)
    wrong = screnc.OPEN + screnc.dword_field(len(body)) + body + screnc.dword_field(total + 1) + screnc.CLOSE
    check("high characters: a kept character above 127 decodes when one reading matches the checksum, and not otherwise",
          got == plain and info == 1 and screnc.decode(wrong)[0] is None, f"{got!r} {info}")
    try:
        screnc.encode(plain)
        refused = False
    except ValueError:
        refused = True
    check("high characters: the encoder refuses one (its handling is not in the public tables)", refused)


# ---------------------------------------------------------------- through analyze.py

def test_vbe_jse(corpus):
    """Each Day 2-4 set with its JScript and VBScript specimens encoded and renamed .vbe/.jse."""
    sets = encoded = same = keyed = keyed_ok = wrong = 0
    plain_n = unsure_n = none_n = 0
    bad = []
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for v in corpus:
        qs, files, names = encoded_variant(v)
        if not names:
            continue
        sets += 1
        encoded += len(names)
        base, _ = solve(v["qs"], v["files"])
        got, err = solve(qs, files)
        if sets == 1 or (v["name"].startswith("day-04") and not any(FIXTURES.glob("[!c]*.vbe"))):
            for old, new in names.items():
                (FIXTURES / Path(new).name).write_bytes(files[new])
        back = {q["qid"]: q for q in qs}
        for q in v["qs"]:
            if Path(q["member"]).suffix.lower() not in ENCODED_EXT:
                continue
            a, b = got.get(q["qid"]), base.get(q["qid"])
            assert q["qid"] in back
            if a == b:
                same += 1
            else:
                bad.append(f"{v['name']} {q['qid']}: encoded {a!r} plain {b!r}")
            if a is None:
                none_n += 1
            elif analyze.plain(a):
                plain_n += 1
            else:
                unsure_n += 1
            if v["key"] is not None and v["key"].get(q["qid"]) is not None and analyze.plain(b):
                keyed += 1
                if a == v["key"][q["qid"]]:
                    keyed_ok += 1
                elif analyze.plain(a):
                    wrong += 1
        if "Script Encoder block" not in err:
            bad.append(f"{v['name']}: no decode line on stderr")
    total = plain_n + unsure_n + none_n
    check(f"vbe/jse: {sets} sets, {encoded} encoded specimens: {same}/{total} answers the same as the plain specimen "
          f"({plain_n} plain, {unsure_n} unsure, {none_n} None)", sets >= 16 and same == total and total > 0,
          "; ".join(bad[:5]))
    check(f"vbe/jse: {keyed_ok}/{keyed} key.json answers equal, {wrong} plain answer wrong",
          keyed > 0 and keyed_ok == keyed and wrong == 0)


def test_any_file(corpus):
    v = next(v for v in corpus if v["name"].startswith("day-04") and v["key"] is not None)
    base, _ = solve(v["qs"], v["files"])
    mine = [q["qid"] for q in v["qs"] if Path(q["member"]).suffix.lower() in ENCODED_EXT]
    # A block between plain lines of a .vbe/.jse: the host decodes the whole file, the plain lines stay.
    qs, files, _ = encoded_variant(v, wrap=lambda b, ext: ("' head\r\n" if ext == ".vbs" else "// head\r\n") + b + "\r\n")
    got, _ = solve(qs, files)
    check("hosts: a block between plain lines of a .vbe/.jse answers as the plain file plus those lines",
          all(got.get(i) == base.get(i) for i in mine), str([(i, got.get(i), base.get(i)) for i in mine
                                                             if got.get(i) != base.get(i)][:3]))
    # Wrapped: the same container around the plain script is the reference.
    forms = {
        "wsf-cdata": (".wsf", lambda body, enc: '<?xml version="1.0"?>\n<job id="fixture">\n<script language="VBScript'
                      + (".Encode" if enc else "") + '"><![CDATA[\n' + body + "\n]]></script>\n</job>\n"),
        "wsf-escaped": (".wsf", lambda body, enc: '<?xml version="1.0"?>\n<job id="fixture">\n<script language="VBScript'
                        + (".Encode" if enc else "") + '">\n' + body.replace("&", "&amp;").replace("<", "&lt;")
                        .replace(">", "&gt;") + "\n</script>\n</job>\n"),
        "hta": (".hta", lambda body, enc: '<html><head><hta:application id="fixture"/>\n<script language="JScript'
                + (".Encode" if enc else "") + '">\n' + body + "\n</script></head><body></body></html>\n"),
        "sct-cdata": (".sct", lambda body, enc: '<?XML version="1.0"?>\n<scriptlet>\n<script language="JScript'
                      + (".Encode" if enc else "") + '"><![CDATA[\n' + body + "\n]]></script>\n</scriptlet>\n"),
    }
    for form, (ext, build) in forms.items():
        want_lang = "jscript" if form in ("hta", "sct-cdata") else "vbscript"
        src_ext = ".js" if want_lang == "jscript" else ".vbs"
        member, mqs = next((m, q) for m, q in specimens(v).items() if Path(m).suffix.lower() == src_ext)
        text = plan_codec.text_of(v["files"][member])
        new = member[: -len(src_ext)] + ext
        prefix = ext.lstrip(".")
        nqs = [dict(renamed(q, member, new), qid=prefix + q["qid"][len(want_lang):]) for q in mqs]
        ref, _ = solve(nqs, {new: build(text, False).encode()})
        got, err = solve(nqs, {new: build(screnc.encode(text), True).encode()})
        plain_ref = sum(analyze.plain(x) for x in ref.values())
        check(f"hosts: {form}: the encoded block answers as the plain script in the same container "
              f"({len(got)} answers, {plain_ref} plain)", got == ref and plain_ref > 0 and "decoded" in err,
              f"{[(k, got.get(k), ref.get(k)) for k in set(got) | set(ref) if got.get(k) != ref.get(k)][:3]}")
        if form == "wsf-escaped":
            (FIXTURES / Path(new).name).write_bytes(build(screnc.encode(text), True).encode())


def test_scope(corpus):
    """Blocks and markers where the host does not decode are inert text: nothing changes."""
    v = next(v for v in corpus if v["name"].startswith("day-04") and v["key"] is not None)
    base, _ = solve(v["qs"], v["files"])
    # 1. A whole encoded file under the plain extension: left as it is, not decoded.
    qs, files, names = encoded_variant(v, rename=False)
    same = all(analyze.encoded_view(m, files)[0] is files and analyze.encoded_view(m, files)[1] is None for m in names)
    _, err = solve(qs, files)
    check(f"scope: {len(names)} plain .vbs/.js files holding only an encoded block are left byte for byte "
          f"(the same files, no problem, no decode line)", same and names and "Script Encoder" not in err)
    # 2. A block in a <script> whose language is not *.Encode (.wsf, .hta, .sct, .wsc): left as it is.
    block = screnc.encode("WScript.Echo 1\r\n")
    left = []
    for ext, lang in ((".wsf", "VBScript"), (".hta", "JScript"), (".sct", "JScript"), (".wsc", "VBScript"),
                      (".wsf", "VBScript.Encoder"), (".hta", "text/vbscript.encode")):
        files = {"x" + ext: f'<job><script language="{lang}">\n{block}\n</script></job>\n'.encode()}
        seen, problem = analyze.encoded_view("x" + ext, files)
        left.append(seen is files and problem is None)
    check(f"scope: a block in a <script> of another language is left as it is ({sum(left)}/{len(left)})", all(left))
    # 3. The reviewer's decoy: a comment line holding a block with another plan, appended to a .vbs.
    member = next(m for m in specimens(v) if Path(m).suffix.lower() == ".vbs")
    data = v["files"][member]
    text = plan_codec.text_of(data)
    m = re.search(r'(\w+) = "((?:[0-9a-f]{2}:)+[0-9a-f]{2})"', text)
    changed = None
    if m:
        hexs = m.group(2).split(":")
        plain = bytes(int(h, 16) ^ 0x2b for h in hexs).decode("latin-1")
        decoy = re.sub(r"campaign_id=[^|]+", "campaign_id=campaign-decoy00001", plain)
        dhex = ":".join(f"{b ^ 0x2b:02x}" for b in decoy.encode("latin-1"))
        line = "' note " + screnc.encode('\r\nConst ' + m.group(1) + ' = "' + dhex + '"\r\n\'')
        files = {k: ((text + "\n" + line).encode("latin-1") if val is data else val) for k, val in v["files"].items()}
        got, _ = solve(v["qs"], files)
        changed = [k for k in base if got.get(k) != base[k]]
    check(f"scope: a decoy comment with an encoded block holding another plan, appended to {member}, changes "
          f"{len(changed) if changed is not None else '?'} answers",
          changed == [] and "decoy" in (decoy if m else "") and decoy != plain, str(changed)[:200])
    # 4. A bare #@~^ in a comment of every specimen: no answer changes (Day 7 base set 1 and every Day 2-4 set).
    sets = list(corpus)
    d7 = gm.CHALLENGES / "day-07" / "script-analysis-day-07-node-operation-graphs"
    if (d7 / "attempt.json").exists():
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            attempt, blobs, _ = run.load_offline("", str(d7))
            d7sets = run.split_sets(attempt, blobs)
        sets = [{"name": "day-07 base#1", "qs": d7sets[0][1], "files": d7sets[0][2]}] + sets[:6]
    comment = {".ps1": b"\n# #@~^ marker\n", ".py": b"\n# #@~^ marker\n", ".vbs": b"\n' #@~^ marker\n",
               ".js": b"\n// #@~^ marker\n", ".cmd": b"\nREM #@~^ marker\n", ".bat": b"\nREM #@~^ marker\n"}
    n = moved = answered = 0
    exts, bad = set(), []
    for s in sets:
        ref, _ = solve(s["qs"], s["files"])
        for member, mqs in specimens(s).items():
            ext = Path(member).suffix.lower()
            orig = analyze.generic.find(s["files"], member)
            if not isinstance(orig, (bytes, bytearray)):
                continue
            plant = comment.get(ext, b"\n#@~^ marker\n")
            files = {k: (val + plant if val is orig else val) for k, val in s["files"].items()}
            got, _ = solve(mqs, files)
            n += 1
            exts.add(ext)
            ids = [q["qid"] for q in mqs]
            answered += sum(ref.get(i) is not None for i in ids)
            if any(got.get(i) != ref.get(i) for i in ids):
                moved += 1
                bad.append(f"{s['name']} {member}")
    check(f"scope: a bare #@~^ planted in {n} specimens ({', '.join(sorted(exts))}) of {len(sets)} sets: "
          f"{moved} change an answer ({answered} answers were given)", n >= 60 and moved == 0 and answered > 0,
          "; ".join(bad[:5]))
    # 5. Inside a .wsf: a bare marker outside the Encode element is ignored; inside it, no reading.
    src = next(m for m in specimens(v) if Path(m).suffix.lower() == ".vbs")
    body = plan_codec.text_of(v["files"][src])
    good = ('<?xml version="1.0"?>\n<job id="f">\n<!-- see #@~^ docs -->\n<script language="VBScript">\' #@~^\n'
            '</script>\n<script language="VBScript.Encode"><![CDATA[\n' + screnc.encode(body) + '\n]]></script>\n</job>\n')
    seen, problem = analyze.encoded_view("f.wsf", {"f.wsf": good.encode()})
    inner = good.replace("<![CDATA[\n", "<![CDATA[\n' #@~^ x\n")
    _, problem2 = analyze.encoded_view("f.wsf", {"f.wsf": inner.encode()})
    check("scope: a .wsf: markers outside the Encode element are ignored and its block decodes; a bad marker "
          "inside the Encode element is no reading",
          problem is None and body in plan_codec.text_of(seen["f.wsf"]) and "' #@~^\n" in plan_codec.text_of(seen["f.wsf"])
          and problem2 is not None, f"{problem} {problem2}")


def test_new_component(corpus):
    """A .vbe/.jse of a component the modules were not built on (another id prefix) goes to the
    general path on the decoded text: the same answers as that path on the plain text, 0 wrong."""
    v = next(v for v in corpus if v["name"].startswith("day-04") and v["key"] is not None)
    same = total = plain_n = wrong = 0
    bad = []
    for member, mqs in specimens(v).items():
        ext = Path(member).suffix.lower()
        if ext not in ENCODED_EXT:
            continue
        lang = analyze.LANGUAGE[ext]
        new = member[: -len(ext)] + ENCODED_EXT[ext]
        word = ENCODED_EXT[ext].lstrip(".")
        nqs = [dict(renamed(q, member, new), qid=word + q["qid"][len(lang):]) for q in mqs]
        text = plan_codec.text_of(v["files"][member])
        ref, _ = solve(nqs, {new: text.encode("utf-8")})
        got, err = solve(nqs, {new: screnc.encode(text).encode()})
        for q, nq in zip(mqs, nqs):
            a = got.get(nq["qid"])
            total += 1
            same += a == ref.get(nq["qid"])
            if analyze.plain(a):
                plain_n += 1
                wrong += a != v["key"][q["qid"]]
                if a != v["key"][q["qid"]]:
                    bad.append(f"{nq['qid']}: {a!r} key {v['key'][q['qid']]!r}")
        if "general path" not in err:
            bad.append(f"{new}: not sent to the general path")
    check(f"new component: {same}/{total} answers of encoded .vbe/.jse specimens with new ids equal the general path "
          f"on the plain text; {plain_n} plain, {wrong} wrong", same == total and total > 0 and wrong == 0,
          "; ".join(bad[:5]))


def corruptions(block: str) -> dict:
    """Ways a block is not one: {name: the bad text}."""
    data = block[12:-12]
    i = next(k for k, c in enumerate(data) if c not in "@#&!*$" and k > 10)
    flipped = data[:i] + ("a" if data[i] != "a" else "b") + data[i + 1:]
    return {
        "a changed character (checksum)": block[:12] + flipped + block[-12:],
        "a cut block": block[: len(block) // 2],
        "a wrong length field": block[:4] + screnc.dword_field(len(data) - 1) + block[12:],
        "no closing mark": block[:-4] + "^#~#",
        "a bad escape": block[:12] + data[:i] + "@x" + data[i + 2:] + block[-12:],
        "a length field that is no number": block[:4] + "AA*AAA==" + block[12:],
    }


def test_corrupt(corpus):
    v = next(v for v in corpus if v["name"].startswith("day-04") and v["key"] is not None)
    base, _ = solve(v["qs"], v["files"])
    by = specimens(v)
    target = next(m for m in by if Path(m).suffix.lower() == ".vbs")
    others = [q["qid"] for m, qs in by.items() if m != target for q in qs]
    new = target[:-4] + ".vbe"
    block = screnc.encode(plan_codec.text_of(v["files"][target]))
    for name, bad in corruptions(block).items():
        files = {k: val for k, val in v["files"].items() if k != target}
        files[new] = bad.encode()
        qs = [renamed(q, target, new) if q["member"] == target else q for q in v["qs"]]
        got, err = solve(qs, files)
        left = [q["qid"] for q in by[target] if q["qid"] in got]
        kept = all(got.get(i) == base.get(i) for i in others)
        problems = analyze.covers([q for q in qs if q["member"] == new], files)
        check(f"corrupt: {name}: {len(by[target])} questions of {Path(new).name} unanswered, the other "
              f"{len(others)} answers unchanged, covers() names it",
              not left and kept and len(problems) == len(by[target]) and "does not decode" in err,
              f"answered {left[:3]} kept={kept} problems={problems[:1]}")
        if name.startswith("a changed"):
            (FIXTURES / ("corrupt-" + Path(new).name)).write_bytes(bad.encode())
    # A good .vbe passes covers() with its files.
    files = {k: val for k, val in v["files"].items() if k != target}
    files[new] = block.encode()
    qs = [renamed(q, target, new) for q in by[target]]
    check("corrupt: a good .vbe has no problem in covers()", analyze.covers(qs, files) == [])


def test_partial(corpus):
    v = next(v for v in corpus if v["name"].startswith("day-04") and v["key"] is not None)
    qs, files, _ = encoded_variant(v)
    ctx = {"set": 1, "partial": {}}
    with contextlib.redirect_stderr(io.StringIO()):
        out = analyze.solve_set(qs, files, ctx)
    check("partial: ctx['partial'] holds every answer of the encoded set", ctx["partial"] == out and len(out) > 0)


def test_speed(corpus):
    sets = [v for v in corpus if v["name"].startswith("day-04") and "/mastery" in v["name"]][:2]
    prepared = [encoded_variant(v) for v in sets]
    plain_best = enc_best = None
    for _ in range(3):
        t = time.perf_counter()
        for v in sets:
            solve(v["qs"], v["files"])
        dt = time.perf_counter() - t
        plain_best = dt if plain_best is None else min(plain_best, dt)
        t = time.perf_counter()
        for qs, files, _ in prepared:
            solve(qs, files)
        dt = time.perf_counter() - t
        enc_best = dt if enc_best is None else min(enc_best, dt)
    check(f"speed: {len(sets)} Day 4 Mastery sets: plain {plain_best:.3f} s, every JScript and VBScript specimen "
          f"encoded {enc_best:.3f} s (limit plain + 0.1 s)", bool(sets) and enc_best <= plain_best + 0.1)


def main() -> int:
    if not gm.CHALLENGES.is_dir():
        print(f"test_wavec_encoded: no saved attempts under {gm.CHALLENGES}", file=sys.stderr)
        return 2
    corpus = load_variants()
    if len(corpus) < 16:
        print(f"test_wavec_encoded: expected at least 16 saved sets of Days 2 to 4, found {len(corpus)}", file=sys.stderr)
        return 2
    print(f"corpus: {len(corpus)} sets of Days 2 to 4 under {gm.CHALLENGES}")
    test_tables()
    test_wine()
    test_round_trip(corpus)
    test_high_chars()
    test_vbe_jse(corpus)
    test_any_file(corpus)
    test_scope(corpus)
    test_new_component(corpus)
    test_corrupt(corpus)
    test_partial(corpus)
    test_speed(corpus)
    failed = [name for name, ok in results if not ok]
    print(f"TEST_WAVEC_ENCODED passed={len(results) - len(failed)} failed={len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
