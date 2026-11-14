#!/usr/bin/env python3
"""Row 92 (wave C2, group deflate): raw (headerless) deflate in the Script lane's general path, offline.

Every specimen here is synthetic and made by this file's own encoders (nothing is read from a saved
attempt, the Day 7 timing check aside, which only replays one): a plan, raw-deflated as PowerShell's
[IO.Compression.DeflateStream], PHP's gzdeflate and .NET's DeflateStream write it, in base64 or as a byte
list, stored under a `Codec_<id>` label (every spelling row 92 names, and labels the module does not know:
the every-reading fallback) and with no label at all (plan_codec's unlabelled reading). Also stacked with
XOR and add in either order, the adler32 trailer that zlib.compress(..)[2:] leaves, and what must stay no
plan: a stream cut short, one with bytes after its end, two plans, random bytes, a bomb. The specimens are
also written to FIXTURES for review. Nothing here is run: the specimens are only read as text.

    .venv/bin/python solvers/script-analysis/test_wavec2_deflate.py [-v]

Last line: TEST_WAVEC2_DEFLATE passed=N failed=M
"""
import base64
import contextlib
import io
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import generic      # noqa: E402
import label_plan   # noqa: E402
import plan_codec   # noqa: E402

VERBOSE = "-v" in sys.argv[1:]
# A fresh temporary folder per run (no machine-specific path, no environment switch); printed at the end.
FIXTURES = Path(tempfile.mkdtemp(prefix="wave-c2-deflate-"))
results = []

PLAN = ("v=1|steps=acquire_remote,dispatch_memory|adapter=Lab.Adapter|stage_count=2|campaign_id=campaign-4242424242|"
        "url=https://lab.invalid/stage-4242424242.bin")
PLAN2 = ("v=2|steps=decode_embedded,write_file|adapter=Lab.Other|stage_count=2|campaign_id=campaign-1313131313|"
         "path=C:\\lab\\drop-1313131313.bin")
ADV = "v=1|feature=indirect_expansion|primitive=pointer|campaign_id=campaign-7777777777|stage_count=1|steps=recognize_syntax,reconstruct_intent"
JPLAN = json.dumps({"v": 1, "steps": ["locate_local", "dispatch_process"], "adapter": "Lab.Json",
                    "campaign_id": "campaign-5555555555", "stage_count": 2}, separators=(",", ":"))
PLANS = {"plan": PLAN, "advanced": ADV, "json": JPLAN}


def check(name: str, ok: bool, detail: str = ""):
    results.append((name, bool(ok)))
    print(f"{'ok  ' if ok else 'FAIL'} {name}" + (f": {detail}" if detail and (VERBOSE or not ok) else ""))


# ---------------------------------------------------------------- this file's own encoders

def deflate(data: bytes, level: int = 9) -> bytes:
    """Raw deflate, as DeflateStream and gzdeflate write it (no header, no trailer)."""
    c = zlib.compressobj(level, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def deflate_adler(data: bytes) -> bytes:
    """zlib.compress(..)[2:]: the header cut off, the adler32 trailer kept."""
    return zlib.compress(data)[2:]


def xor(k: int, data: bytes) -> bytes:
    return bytes(b ^ k for b in data)


def add(k: int, data: bytes) -> bytes:
    return bytes((b + k) % 256 for b in data)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def ps1(material: str, label=None, ident="5a17c0de") -> str:
    """PowerShell: base64 material opened by [IO.Compression.DeflateStream]."""
    lines = ["# Huntress Script Triage -- inert static-analysis fixture",
             f"$Material_{ident} = '{material}'"]
    if label is not None:
        lines.append(f"$Codec_{ident} = '{label}'")
    lines += [f"$ms = New-Object IO.MemoryStream(,[Convert]::FromBase64String($Material_{ident}))",
              "$ds = New-Object IO.Compression.DeflateStream($ms, [IO.Compression.CompressionMode]::Decompress)",
              "$plan = (New-Object IO.StreamReader($ds)).ReadToEnd()", "Write-Output $plan.Length", ""]
    return "\n".join(lines)


def php(material: str, label=None, ident="5a17c0de") -> str:
    """PHP: gzinflate(base64_decode(..))."""
    lines = ["<?php", "// Huntress Script Triage -- inert static-analysis fixture",
             f"$Material_{ident} = '{material}';"]
    if label is not None:
        lines.append(f"$Codec_{ident} = '{label}';")
    lines += [f"$plan = gzinflate(base64_decode($Material_{ident}));", "echo strlen($plan);", ""]
    return "\n".join(lines)


def cs(data: bytes, label=None, ident="5a17c0de") -> str:
    """C# (.NET): the DeflateStream bytes as a byte array."""
    arr = ", ".join(f"0x{b:02x}" for b in data)
    lines = ["// Huntress Script Triage -- inert static-analysis fixture", "using System.IO.Compression;",
             f"static byte[] Material_{ident} = new byte[] {{ {arr} }};"]
    if label is not None:
        lines.append(f"static string Codec_{ident} = \"{label}\";")
    lines += [f"var ds = new DeflateStream(new MemoryStream(Material_{ident}), CompressionMode.Decompress);",
              "Console.WriteLine(new StreamReader(ds).ReadToEnd().Length);", ""]
    return "\n".join(lines)


def node(material: str, label=None, ident="5a17c0de") -> str:
    lines = ["// Huntress Script Triage -- inert static-analysis fixture", f"const Material_{ident} = \"{material}\";"]
    if label is not None:
        lines.append(f"const Codec_{ident} = \"{label}\";")
    lines += [f"const plan = zlib.inflateRawSync(Buffer.from(Material_{ident}, 'base64')).toString();", ""]
    return "\n".join(lines)


def quiet(f, *a):
    with contextlib.redirect_stderr(io.StringIO()):
        return f(*a)


def labelled(text):
    return quiet(label_plan.read_text, text)


def unlabelled(text, ext):
    got = quiet(plan_codec.decode, text, ext)
    return got[0] if got else None


_written = set()


def save(name: str, text: str):
    """Write a specimen to FIXTURES for review (best effort; the tests do not read it back)."""
    if name in _written:
        return
    _written.add(name)
    try:
        FIXTURES.mkdir(parents=True, exist_ok=True)
        (FIXTURES / name).write_text(text)
    except OSError:
        pass


# Every spelling row 92 names for raw deflate, as a transform; and as part of a representation.
NAMES = ("deflate", "raw_deflate", "inflate", "deflate_raw", "compress_deflate", "gzinflate", "deflatestream",
         "deflate_stream", "raw_inflate", "gzdeflate", "Raw_Deflate", "DeflateStream")
REP_LABELS = ("deflate_base64|identity|", "base64_raw_deflate|none|", "gzinflate_base64||", "raw_deflate_base64|plain|")
UNKNOWN = ("mystery|q", "deflated_payload|", "base64-deflate|", "b64>inflate|")


# ---------------------------------------------------------------- the three writers, labelled and not

def test_forms():
    n_lab = n_fb = n_un = bad_lab = bad_fb = bad_un = 0
    for pname, plan in PLANS.items():
        z = deflate(plan.encode())
        for wname, write, ext, material in (("ps1", ps1, ".ps1", b64(z)), ("php", php, ".php", b64(z)),
                                             ("cs", cs, ".cs", z), ("mjs", node, ".mjs", b64(z))):
            for name in NAMES:
                text = write(material, f"base64|{name}|" if wname != "cs" else f"byte_array|{name}|")
                save(f"{pname}-{wname}-{name}{ext}", text)
                n_lab += 1
                got = labelled(text)
                if got != plan:
                    bad_lab += 1
                    check(f"labelled: {pname} {wname} under {name}", False, str(got)[:60])
            if wname != "cs":
                for lab in REP_LABELS:
                    n_lab += 1
                    got = labelled(write(material, lab))
                    if got != plan:
                        bad_lab += 1
                        check(f"labelled: {pname} {wname} as representation {lab}", False, str(got)[:60])
            for lab in UNKNOWN:
                n_fb += 1
                text = write(material, lab)
                save(f"{pname}-{wname}-fallback{ext}", text)
                got = labelled(text)
                if got != plan:
                    bad_fb += 1
                    check(f"fallback: {pname} {wname} under {lab}", False, str(got)[:60])
            # Unlabelled, plan_codec reads what it reads of the same plan written plainly (it has no reading of
            # an advanced `feature=` plan, raw-deflated or not): the same answer.
            want = plan if pname != "advanced" else unlabelled(write(plan.encode() if wname == "cs" else b64(plan.encode())), ext)
            n_un += 1
            text = write(material)
            save(f"{pname}-{wname}-unlabelled{ext}", text)
            got = unlabelled(text, ext)
            if got != want:
                bad_un += 1
                check(f"unlabelled: {pname} {wname}", False, str(got)[:60])
            # The adler32 trailer of zlib.compress(..)[2:], unlabelled and under a label.
            za = deflate_adler(plan.encode())
            mat = za if wname == "cs" else b64(za)
            n_un += 1
            got = unlabelled(write(mat), ext)
            if got != want:
                bad_un += 1
                check(f"unlabelled: {pname} {wname} with the adler32 trailer", False, str(got)[:60])
            n_lab += 1
            got = labelled(write(mat, "base64|deflate|" if wname != "cs" else "bytes|raw_deflate|"))
            if got != plan:
                bad_lab += 1
                check(f"labelled: {pname} {wname} with the adler32 trailer", False, str(got)[:60])
    check(f"forms: labelled {n_lab - bad_lab}/{n_lab}", bad_lab == 0)
    check(f"forms: fallback (labels the module does not know) {n_fb - bad_fb}/{n_fb}", bad_fb == 0)
    check(f"forms: unlabelled (plan_codec) {n_un - bad_un}/{n_un}", bad_un == 0)
    # Every compression level, short and long plans: one writer, labelled, fallback and unlabelled.
    misses = []
    for level in (0, 1, 6, 9):
        for plan in (PLAN, PLAN + "|pad=" + "ab" * 2000):
            mat = b64(deflate(plan.encode(), level))
            for how, got in (("label", labelled(php(mat, "base64|gzinflate|"))), ("fallback", labelled(php(mat, "q|"))),
                             ("unlabelled", unlabelled(php(mat), ".php"))):
                if got != plan:
                    misses.append((level, len(plan), how))
    check("forms: levels 0 (stored), 1, 6, 9 and a 4 KB plan (dynamic blocks) read three ways", not misses, str(misses))
    return n_lab, bad_lab, n_fb, bad_fb, n_un, bad_un


# ---------------------------------------------------------------- stacked with XOR and add

def test_stacked():
    plan = PLAN.encode()
    cases = []    # (description, material bytes, labels that name it, read unlabelled?)
    for k, f, kn in ((0x5A, xor, "xor"), (0x13, add, "add")):
        spelled = f"{k:02x}"
        cases.append((f"{kn} then deflate", deflate(f(k, plan)),
                      [f"base64|{kn}_then_deflate|{spelled}", f"base64|{kn}_then_raw_deflate|{spelled}",
                       f"base64|{kn}+gzdeflate|{spelled}", f"base64|raw_deflate_{kn}|{spelled}"], True))
        cases.append((f"deflate then {kn}", f(k, deflate(plan)),
                      [f"base64|deflate_then_{kn}|{spelled}", f"base64|raw_deflate_then_{kn}|{spelled}",
                       f"base64|deflate>{kn}|{spelled}", f"base64|{kn}_raw_deflate|{spelled}"], False))
    n_lab = n_fb = n_un = bad = 0
    not_built = []
    for desc, data, labs, unl in cases:
        mat = b64(data)
        for lab in labs:
            n_lab += 1
            text = ps1(mat, lab)
            save(f"stacked-{lab.split('|')[1].replace('>', '-').replace('+', '-')}.ps1", text)
            got = labelled(text)
            if got != PLAN:
                bad += 1
                check(f"stacked labelled: {desc} under {lab}", False, str(got)[:60])
        key = labs[0].split("|")[2]
        for lab in (f"mystery|{key}", f"x|{key}|other"):
            n_fb += 1
            got = labelled(ps1(mat, lab))
            if got != PLAN:
                bad += 1
                check(f"stacked fallback: {desc} under {lab}", False, str(got)[:60])
        got = unlabelled(ps1(mat), ".ps1")
        if unl:
            n_un += 1
            if got != PLAN:
                bad += 1
                check(f"stacked unlabelled: {desc}", False, str(got)[:60])
        else:
            # Not built: plan_codec has no key to undo before a stream it cannot see. No plan, never a wrong one.
            not_built.append(desc)
            if got not in (None, PLAN):
                check(f"stacked unlabelled: {desc} gives no wrong plan", False, str(got)[:60])
    check(f"stacked: labelled {n_lab}, fallback {n_fb}, unlabelled {n_un}; all read", bad == 0)
    return n_lab, n_fb, n_un, bad, not_built


# ---------------------------------------------------------------- what must stay no plan

def test_never():
    plan = PLAN.encode()
    z = deflate(plan)
    bad = []

    def none_three(desc, mat_bytes, lab="base64|deflate|"):
        mat = b64(mat_bytes)
        for how, got in (("label", labelled(php(mat, lab))), ("fallback", labelled(php(mat, "q|"))),
                         ("unlabelled", unlabelled(php(mat), ".php"))):
            if got is not None and got != PLAN:
                bad.append((desc, how, got[:50]))
            elif got == PLAN:
                bad.append((desc, how, "a plan"))
    # A stream cut short: no plan at all (its last value would be cut).
    for cut in (1, 4, len(z) // 2):
        none_three(f"cut by {cut}", z[:-cut])
    # Bytes after its end that are no adler32: no plan unlabelled; under a label only when few and a plan.
    none_three("16 bytes after its end", z + bytes(range(16)))
    got = unlabelled(php(b64(z + b"\x00\x01\x02")), ".php")
    if got is not None:
        bad.append(("3 bytes after its end", "unlabelled", got[:50]))
    got = labelled(php(b64(z + b"\x00\x01\x02"), "base64|deflate|"))
    check("never: a raw stream with 3 bytes after its end is a plan under its label only (plan grammar)", got == PLAN, str(got)[:50])
    # A wrong adler32: four bytes after the end that are not its checksum. Unlabelled, no plan; under a label
    # (and in the fallback) the stream reached its own end and gives a whole plan, which the grammar takes.
    za = bytearray(deflate_adler(plan))
    za[-1] ^= 1
    got = unlabelled(php(b64(bytes(za))), ".php")
    if got is not None:
        bad.append(("a wrong adler32 trailer", "unlabelled", got[:50]))
    # Not a plan: deflated prose.
    none_three("deflated prose", deflate(b"The quick brown fox jumps over the lazy dog. " * 20))
    # A plan with its steps garbled under the fallback's strictness: v= and k=v but no steps field.
    none_three("deflated k=v text without steps", deflate(b"v=1|adapter=Lab.Adapter|campaign_id=campaign-1|stage_count=2"))
    check("never: cut, trailed, wrong-checksum, prose and stepless streams give no plan (label, fallback, unlabelled)",
          not bad, str(bad[:4]))
    # Two different plans, both raw-deflated, in two materials: no plan.
    two = (php(b64(deflate(PLAN.encode())), "base64|deflate|", "aa11") +
           php(b64(deflate(PLAN2.encode())), "base64|deflate|", "bb22"))
    got_l = labelled(two)
    got_u = unlabelled(php(b64(deflate(PLAN.encode())), None, "aa11") + php(b64(deflate(PLAN2.encode())), None, "bb22"), ".php")
    check("never: two different raw-deflated plans are no plan (labelled and unlabelled)", got_l is None and got_u is None,
          f"{str(got_l)[:40]} / {str(got_u)[:40]}")
    # A raw-deflated plan beside the same plan in plain base64: what the same plan zlib-compressed beside it gives.
    got = unlabelled(php(b64(deflate(PLAN.encode())), None, "aa11") + php(b64(PLAN.encode()), None, "bb22"), ".php")
    ref = unlabelled(php(b64(zlib.compress(PLAN.encode())), None, "aa11") + php(b64(PLAN.encode()), None, "bb22"), ".php")
    check("never: the same plan raw-deflated and plain reads as it does zlib-compressed and plain", got == ref and got,
          f"{str(got)[:40]} / {str(ref)[:40]}")
    # A bomb: 64 MB of zeros raw-deflated is about 64 KB; it is bounded by MAX_INFLATE, not read.
    # Timed in this thread's CPU time, which a process waiting for a core does not accrue (SH-08).
    bomb = deflate(b"\0" * (64 << 20))
    t0 = time.thread_time()
    out = plan_codec.raw_inflate(bomb)
    got_l = labelled(php(b64(bomb), "base64|deflate|"))
    got_u = unlabelled(php(b64(bomb)), ".php")
    dt = time.thread_time() - t0
    check(f"never: a 64 MB bomb in {len(bomb) // 1024} KB is no stream and no plan ({dt:.2f} s CPU, limit 1 s)",
          out is None and got_l is None and got_u is None and dt < 1.0)
    # The output bound: MAX_INFLATE bytes is a stream, one more is not. The ratio bound (RAW_RATIO, above
    # deflate's own 1032 to 1, so a belt only) checked with the ratio lowered to 100.
    edge = deflate(b"\0" * plan_codec.MAX_INFLATE)
    over = deflate(b"\0" * (plan_codec.MAX_INFLATE + 1))
    at, past = plan_codec.raw_inflate(edge), plan_codec.raw_inflate(over)
    saved = plan_codec.RAW_RATIO
    plan_codec.RAW_RATIO = 100
    plan_codec._RAW.clear()
    try:
        ratio = plan_codec.raw_inflate(edge)
    finally:
        plan_codec.RAW_RATIO = saved
        plan_codec._RAW.clear()
    check(f"never: {plan_codec.MAX_INFLATE} bytes out is a stream, one more is not; over a ratio of 100 it is not",
          at is not None and len(at) == plan_codec.MAX_INFLATE and past is None and ratio is None)


def test_unchanged():
    """The streams with a header read as before, under the names that read them before."""
    plan = PLAN.encode()
    bad = []
    for name, data in (("zlib", zlib.compress(plan)), ("deflate", zlib.compress(plan)), ("zlib_deflate", zlib.compress(plan))):
        got = labelled(node(b64(data), f"base64|{name}|"))
        if got != PLAN:
            bad.append((name, got))
    got = unlabelled(node(b64(zlib.compress(plan))), ".mjs")
    if got != PLAN:
        bad.append(("unlabelled zlib", got))
    check("unchanged: zlib under zlib/deflate/zlib_deflate and unlabelled still read", not bad, str(bad)[:80])
    # A header stream is opened by its header and named so (never as raw deflate).
    how = quiet(plan_codec.decode, node(b64(zlib.compress(plan))), ".mjs")
    check("unchanged: an unlabelled zlib stream is still named base64+zlib", how and "raw_deflate" not in how[1], str(how)[:80])


# ---------------------------------------------------------------- the general path, end to end

def test_generic_path():
    out_all = {}
    for member, write, mat in (("remote-stage.php", php, b64(deflate(PLAN.encode()))),
                               ("remote-stage.cs", cs, deflate(PLAN.encode()))):
        stem = member.split(".")[1]

        def question(qid, text, member=member):
            return {"qid": qid, "id": qid, "answer_id": qid, "member": member, "artifact": f"evidence.zip -> {member}",
                    "question": text, "answer_format": {"type": "exact_text"}}
        qs = [question(f"{stem}-stager-campaign", "Recover the exact synthetic campaign identifier."),
              question(f"{stem}-stager-adapter", "Recover the exact adapter named by the reconstructed plan."),
              question(f"{stem}-stager-url", "Recover the exact url indicator."),
              question(f"{stem}-stager-role", f"Classify {member} by its ordered behavior graph.")]
        want = {f"{stem}-stager-campaign": "campaign-4242424242", f"{stem}-stager-adapter": "Lab.Adapter",
                f"{stem}-stager-url": "https://lab.invalid/stage-4242424242.bin", f"{stem}-stager-role": "stager"}
        for how, body in (("labelled", write(mat, "base64|gzinflate|" if stem == "php" else "bytes|deflatestream|")),
                          ("unlabelled", write(mat))):
            out = quiet(generic.answers, qs, {member: body.encode()}, {})
            out_all[f"{stem} {how}"] = out
            check(f"generic: {member} {how}, raw deflate: the plan's answers", out == want, str(out))


# ---------------------------------------------------------------- bounded and fast

ROW92_LIMIT = 0.05      # CPU seconds row 92 may add to one reading of a random 100 KB blob
# Row 92's whole code path: switched off (each returning None), no raw stream is read anywhere.
ROW92_ENTRIES = ((plan_codec, "raw_inflate"), (label_plan, "_inflate_raw"), (label_plan, "_raw_search"))


def _row92_cost(f, n=3, clock=time.thread_time):
    """(best of `n` calls of f: the CPU seconds spent inside row 92's entry points, whether any of them
    gave something). Row 92's cost was once measured as f's wall time with row 92 on minus with it off,
    the difference of two ~0.45 s readings that a busy machine moves by more than the 0.05 s limit (SH-08).
    Its entry points, switched off, return None; so while every outermost call of them gives None (and
    _raw_search finds nothing), everything outside them runs exactly as with row 92 off, and the time
    inside them is the whole of what row 92 adds. That time is counted directly, in this thread's CPU
    time, which a process waiting for a core does not accrue. `gave` True means the argument does not
    hold for f (a stream or a plan came out of row 92), and the caller fails on it."""
    spent, gave, depth = [0.0], [False], [0]

    def wrap(real, search):
        def timed(*a, **k):
            if depth[0]:
                return real(*a, **k)
            found = (a[2] if len(a) > 2 else k["found"]) if search else None
            before = len(found) if search else 0
            depth[0] += 1
            t0 = clock()
            try:
                r = real(*a, **k)
            finally:
                spent[0] += clock() - t0
                depth[0] -= 1
            if r is not None or (search and len(found) != before):
                gave[0] = True
            return r
        return timed

    saved = [(mod, name, getattr(mod, name)) for mod, name in ROW92_ENTRIES]
    best = None
    try:
        for mod, name, real in saved:
            setattr(mod, name, wrap(real, name == "_raw_search"))
        for _ in range(n):
            plan_codec._RAW.clear()
            label_plan._UNPACKED.clear()
            spent[0] = 0.0
            f()
            best = spent[0] if best is None else min(best, spent[0])
    finally:
        for mod, name, real in saved:
            setattr(mod, name, real)
    return best, gave[0]


def bounded_forms(rng):
    """{(blob, how): f}: the nine random-blob readings test_bounded times (each must give no plan)."""
    blobs = {"base64": b64(rng.randbytes(100_000)), "hex": rng.randbytes(50_000).hex(),
             "base64 of 75 KB": b64(rng.randbytes(75_000))}
    out = {}
    for name, m in blobs.items():
        out[(name, "fallback")] = lambda m=m: labelled(php(m, "mystery|5a,13|huntress"))
        out[(name, "labelled")] = lambda m=m: labelled(php(m, "base64|xor_then_deflate|5a"))
        out[(name, "unlabelled")] = lambda m=m: unlabelled(php(m), ".php")
    return out


def test_bounded():
    rng = random.Random(92)
    worst, where, wrong, gave = 0.0, "", [], []
    for (name, how), f in bounded_forms(rng).items():
        if f() is not None:
            wrong.append((name, how))
        cost, g = _row92_cost(f)
        if g:
            gave.append((name, how))
        if cost > worst:
            worst, where = cost, f"{name} {how}"
    check("bounded: random 100 KB blobs are no plan", not wrong, str(wrong))
    check("bounded: row 92 gives no stream on random 100 KB blobs, so its in-call time is its whole cost",
          not gave, str(gave))
    check(f"bounded: row 92's cost on random 100 KB blobs: worst +{worst:.3f} s CPU ({where}, best of 3); "
          f"limit +{ROW92_LIMIT} s", worst <= ROW92_LIMIT)
    # How often raw inflate takes random input at all (it must not reach a plan): short inputs.
    took = 0
    n = 20_000
    for i in range(n):
        if plan_codec.raw_inflate(rng.randbytes(8 + i % 57)) is not None:
            took += 1
    check(f"bounded: raw inflate took {took} of {n} random inputs of 8 to 64 bytes as whole streams "
          f"({100 * took / n:.2f} %); none is a plan (above)", took / n < 0.01)


def test_day7_replay():
    """The Day 7 Script Mastery replay (read only) must stay within 0.1 s of its 0.48 s before row 92."""
    repo = HERE.parent.parent
    if str(repo) not in sys.path:
        sys.path.append(str(repo))      # the ctf package
    from ctf import paths
    challenges = paths.saved_challenges_root()   # $CTF_REAL_CHALLENGES (read-only); None when unset
    if challenges is None:
        print("SKIP day 7: not run: CTF_REAL_CHALLENGES is not set (the saved past-event attempts)")
        return None
    mastery = challenges / "day-07" / "script-analysis-day-07-node-operation-graphs" / "mastery"
    if not mastery.is_dir():
        print(f"SKIP day 7: not run: no saved Mastery at {mastery}")
        return None
    times, equal = [], True
    for _ in range(3):
        p = subprocess.run([sys.executable, str(repo / "tools" / "preflight.py"), "--replay", str(mastery)],
                           capture_output=True, text=True, cwd=repo, timeout=300,
                           env={**os.environ, "CTF_WORKDIR": str(challenges)})
        try:
            d = json.loads(p.stdout)
        except ValueError:
            check("day 7: the replay printed its JSON", False, p.stderr[-200:])
            return None
        times.append(d.get("seconds", 99))
        equal = equal and bool(d.get("equals_key"))
    best = min(times)
    check(f"day 7: Script Mastery replay equals its key in {best:.3f} s (best of 3; limit 0.48 + 0.1 s)",
          equal and best <= 0.58)
    return best


def main() -> int:
    t0 = time.perf_counter()
    n_lab, bad_lab, n_fb, bad_fb, n_un, bad_un = test_forms()
    s_lab, s_fb, s_un, s_bad, not_built = test_stacked()
    test_never()
    test_unchanged()
    test_generic_path()
    test_bounded()
    day7 = test_day7_replay()
    print(f"coverage: forms labelled {n_lab - bad_lab}/{n_lab}, fallback {n_fb - bad_fb}/{n_fb}, unlabelled "
          f"{n_un - bad_un}/{n_un}; stacked labelled {s_lab}, fallback {s_fb}, unlabelled {s_un} "
          f"({s_bad} missed; not built unlabelled: {', '.join(not_built)}); day 7 replay "
          f"{'n/a' if day7 is None else f'{day7:.3f} s'}; {time.perf_counter() - t0:.1f} s")
    failed = sum(1 for _, ok in results if not ok)
    print(f"specimens written to {FIXTURES}")
    print(f"TEST_WAVEC2_DEFLATE passed={len(results) - failed} failed={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
