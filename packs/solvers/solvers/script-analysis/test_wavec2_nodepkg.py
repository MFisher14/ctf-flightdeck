#!/usr/bin/env python3
"""Offline test of row 94: Node.js packagings (nodepkg.py and node_view in analyze.py).

Usage:
  PYTHONDONTWRITEBYTECODE=1 .venv/bin/python solvers/script-analysis/test_wavec2_nodepkg.py [-v]

No Game Master request and no token. It reads the saved Day 7 Script Analysis attempts (the eight
Node.js .mjs specimens of the base, the Time Trial, the Mastery and their saved variants) through
gm.CHALLENGES, writes a scratch label ledger under tempfile.mkdtemp(), and the fixtures under
/private/tmp/claude-501/wave-c2-nodepkg/fixtures. Nothing it builds is run: a specimen is wrapped
in the container's bytes by hand; where `node` is on the PATH it is used only to compile a V8 code
cache (vm.Script(...).createCachedData(), as bytenode and pkg do; the script is compiled, never
called) and to write a SEA preparation blob (--experimental-sea-config). Without node, those
fixtures are skipped and say so.

What it proves:

  containers  every Day 7 Node specimen wrapped as pkg (content store, gzip, V8 blob store), nexe
              (content and resource), a Node SEA blob in an ELF, PE and Mach-O and alone (node's
              own blob, and a Node 20 style blob), Bun (module table, and text runs), Deno
              (trailer, and section), and bytenode .jsc: no plain answer differs from key.json,
              every unsure answer holds the judged answer among its options, and the counts of
              plain, unsure and None answers per container are printed
  keys        every answer is held under the container's own label keys (an unsure answer's
              key names the kind), never the .mjs keys
  fallback    a recognised container whose script gives no plan (Brotli pkg, a nexe trailer
              with bad sizes, a Bun trailer without a payload) is read as it is: the same
              answers as before row 94, which here are the raw file's own
  ambiguous   a pkg holding two modules with two different plans answers no plan question
  scope       a text specimen with every marker in a comment (.mjs, .py, .sh, .ps1, ...) is
              answered exactly as before; a native executable with no packaging is not a view
  bounds      a gzip bomb is refused by the ratio bound; an input over MAX_INPUT is not looked
              at; a reading over its time budget gives no text
  covers      covers(questions, files) passes a packaged specimen and names one with no plan
  speed       one Day 7 Mastery set with every Node specimen packaged as pkg

Last line: `TEST_WAVEC2_NODEPKG passed=<n> failed=<n> skipped=<n>`. Exit 0 when nothing failed,
1 otherwise, 2 when the saved attempts are not there.
"""
import contextlib
import gzip
import hashlib
import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SCRATCH = Path(tempfile.mkdtemp(prefix="test_wavec2_nodepkg_"))
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
import labels       # noqa: E402
import nodepkg      # noqa: E402

VERBOSE = "-v" in sys.argv[1:]
FIXTURES = Path("/private/tmp/claude-501/wave-c2-nodepkg/fixtures")
NODE = shutil.which("node")
results, skipped = [], []


def check(name: str, ok: bool, detail: str = ""):
    results.append((name, bool(ok)))
    print(f"{'ok  ' if ok else 'FAIL'} {name}" + (f": {detail}" if detail and (VERBOSE or not ok) else ""))


def skip(name: str, why: str):
    skipped.append(name)
    print(f"skip {name}: {why}")


def solve(qs, files):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        out = analyze.solve_set(qs, files, {"set": 1})
    return out, err.getvalue()


def load_variants():
    out = []
    for base in sorted((gm.CHALLENGES / "day-07").glob("script-analysis-*")):
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


def node_specimens(corpus):
    """[(variant, member, questions, text bytes)] for every .mjs specimen of every saved variant."""
    out = []
    for v in corpus:
        by = {}
        for q in v["qs"]:
            by.setdefault(q["member"], []).append(q)
        for member, qs in by.items():
            if member.endswith(".mjs"):
                out.append((v, member, qs, v["files"][member]))
    return out


def unsure(value) -> bool:
    return isinstance(value, str) and value.startswith("??")


# ---------------------------------------------------------------- building the containers

RNG = random.Random(94)
RUNTIME = bytes(RNG.getrandbits(8) for _ in range(6000))
# The runtime's own code holds every marker as a constant (Bun's trailer, Deno's magic, the SEA
# resource name, the SEA magic as an immediate): a reader must not take those for a payload.
RUNTIME += b"\x00---- Bun! ----\x00d3n0l4nd\x00NODE_SEA_BLOB\x00NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2:0\x00"
RUNTIME += b"\xb8\x20\xda\x43\x01\xc3" + bytes(RNG.getrandbits(8) for _ in range(2000))


def elf():
    return b"\x7fELF\x02\x01\x01" + bytes(57) + RUNTIME


def pe():
    head = bytearray(0x80)
    head[:2] = b"MZ"
    struct.pack_into("<I", head, 0x3c, 0x80)
    return bytes(head) + b"PE\x00\x00" + bytes(20) + RUNTIME


def macho():
    return b"\xcf\xfa\xed\xfe" + bytes(28) + RUNTIME


def script_of(text: bytes) -> str:
    """The specimen as a CommonJS script body (what a packager bundles); its top-level await is
    kept inside an async function so the text compiles. Nothing is ever run."""
    src = text.decode("utf-8").replace("export ", "")
    return "(async () => {\n" + src + "\n})();\n"


def node_ok():
    return bool(NODE)


def v8_cache(text: bytes, tag: str):
    """A V8 code cache of the specimen (bytenode's .jsc, pkg's blob store), compiled by node with
    --no-lazy as bytenode does; cached under FIXTURES. None without node."""
    out = FIXTURES / "v8" / f"{tag}.jsc"
    if out.exists():
        return out.read_bytes()
    if not NODE:
        return None
    out.parent.mkdir(parents=True, exist_ok=True)
    src = out.with_suffix(".src.js")
    src.write_text(script_of(text))
    prog = ("const fs=require('fs'),vm=require('vm'),v8=require('v8'),M=require('module');"
            "v8.setFlagsFromString('--no-lazy');"
            "const s=new vm.Script(M.wrap(fs.readFileSync(process.argv[1],'utf8')),{produceCachedData:true});"
            "fs.writeFileSync(process.argv[2],s.createCachedData());")
    subprocess.run([NODE, "-e", prog, str(src), str(out)], check=True, capture_output=True, timeout=60)
    return out.read_bytes()


def sea_blob_node(text: bytes, tag: str, assets=False):
    """node's own SEA preparation blob for the specimen (main script, and an asset when asked)."""
    out = FIXTURES / "sea" / f"{tag}{'-assets' if assets else ''}.blob"
    if out.exists():
        return out.read_bytes()
    if not NODE:
        return None
    out.parent.mkdir(parents=True, exist_ok=True)
    main = out.with_suffix(".main.js")
    main.write_text(script_of(text) if not assets else "module.exports = 1;\n")
    asset = out.with_suffix(".asset.js")
    asset.write_text(script_of(text))
    cfg = {"main": str(main), "output": str(out), "disableExperimentalSEAWarning": True}
    if assets:
        cfg["assets"] = {"payload.js": str(asset)}
    conf = out.with_suffix(".json")
    conf.write_text(json.dumps(cfg))
    subprocess.run([NODE, "--experimental-sea-config", str(conf)], check=True, capture_output=True, timeout=60,
                   cwd=str(out.parent))
    return out.read_bytes()


def sea_blob_v20(text: bytes):
    """A Node 20 style blob, written by hand: magic, flags, the main script (no code path)."""
    code = script_of(text).encode()
    return nodepkg.SEA_MAGIC + struct.pack("<I", 1) + struct.pack("<Q", len(code)) + code


def nexe(text: bytes, as_resource=False):
    code = script_of(text).encode()
    if as_resource:
        res = b'{"note":"config"}' + code
        index = {"./config.json": [0, 17], "./app.js": [17, len(code)]}
        content = ("!(function () {process.__nexe = " + json.dumps({"resources": index}) +
                   ";})();\nrequire('./app.js');\n").encode()
    else:
        res = b""
        content = b"!(function () {process.__nexe = {\"resources\":{}};})();\n" + code
    return pe() + content + res + nodepkg.NEXE_SENTINEL + struct.pack("<dd", len(content), len(res))


def pkg(modules, compress=0, entry="/snapshot/app/index.js", store="content", gap=0):
    """pkg's layout: the runtime, the payload stripes, the prelude with the virtual file system.
    modules: [(path, text bytes)]; store 'content' (1) holds the text, 'blob' (0) its V8 cache."""
    payload, vfs = bytearray(), {}

    def put(raw):
        if compress == 1:
            raw = gzip.compress(raw, mtime=0)
        elif compress == 2:
            raw = b"\x8b" + bytes(RNG.getrandbits(8) for _ in range(len(raw) // 3 + 5))   # stands in for Brotli
        at = len(payload)
        payload.extend(raw)
        return [at, len(raw)]

    for i, (path, text) in enumerate(modules):
        stores = {}
        if store == "blob":
            cache = v8_cache(text, f"pkg-{i}-{hashlib.sha256(text).hexdigest()[:12]}")
            if cache is None:
                return None
            stores["0"] = put(cache)
        else:
            stores["1"] = put(script_of(text).encode())
        stores["3"] = put(json.dumps({"mode": 33188, "size": len(text), "isFileValue": True}).encode())
        vfs[path] = stores
    vfs["/snapshot/app"] = {"3": put(b'{"mode":16877,"size":0,"isDirectoryValue":true}')}
    prelude = ("return (function (REQUIRE_COMMON, VIRTUAL_FILESYSTEM, DEFAULT_ENTRYPOINT, SYMLINKS, DICT, DOCOMPRESS) {\n"
               "  // bootstrap\n})(function (exports) {\n  // common\n},\n" + json.dumps(vfs) + "\n,\n" +
               json.dumps(entry) + "\n,\n{}\n,\n{}\n,\n" + str(compress) + "\n);")
    return elf() + bytes(payload) + bytes(gap) + prelude.encode()


def bun(text: bytes, table=True):
    code = script_of(text).encode()
    name = b"/$bunfs/root/app.js"
    payload = bytearray(b"\x00" * 8)
    co = len(payload)
    payload += code + b"\x00"
    no = len(payload)
    payload += name + b"\x00"
    while len(payload) % 4:
        payload += b"\x00"
    mo = len(payload)
    rec = struct.pack("<IIIIIIII", no, len(name), co, len(code), 0, 0, 0, 0) + bytes([0, 1, 0, 0])
    if not table:
        rec = bytes(len(rec))
    payload += rec
    offsets = struct.pack("<QIII", len(payload), mo, len(rec), 0) + bytes(12)     # 32 bytes
    return elf() + bytes(payload) + offsets + nodepkg.BUN_TRAILER + struct.pack("<Q", len(payload) + 48)


def deno(text: bytes, section=False):
    code = script_of(text).encode()
    eszip = b"ESZIP2.3" + bytes(16) + b"file:///app/main.ts\x00" + struct.pack(">I", len(code)) + code + bytes(32)
    meta = json.dumps({"argv": [], "entrypoint": "file:///app/main.ts"}).encode()
    if section:
        return macho() + nodepkg.DENO_MAGIC + bytes(8) + eszip + meta
    body = elf()
    at = len(body)
    return body + eszip + meta + nodepkg.DENO_MAGIC + struct.pack(">QQ", at, at + len(eszip))


def builders():
    """[(container name, file suffix, build(text bytes, tag) -> bytes or None)]."""
    return [
        ("pkg content", ".exe", lambda t, g: pkg([("/snapshot/app/index.js", t)])),
        ("pkg gap", ".exe", lambda t, g: pkg([("/snapshot/app/index.js", t)], gap=13)),
        ("pkg gzip", ".exe", lambda t, g: pkg([("/snapshot/app/index.js", t)], compress=1)),
        ("pkg blob", ".exe", lambda t, g: pkg([("/snapshot/app/index.js", t)], store="blob") if node_ok() else None),
        ("nexe content", ".exe", lambda t, g: nexe(t)),
        ("nexe resource", ".exe", lambda t, g: nexe(t, as_resource=True)),
        ("sea elf", "", lambda t, g: (lambda b: b and elf() + b + bytes(16))(sea_blob_node(t, g))),
        ("sea pe", ".exe", lambda t, g: (lambda b: b and pe() + b + bytes(16))(sea_blob_node(t, g))),
        ("sea macho", "", lambda t, g: (lambda b: b and macho() + b)(sea_blob_node(t, g))),
        ("sea blob alone", ".blob", lambda t, g: sea_blob_node(t, g)),
        ("sea asset", "", lambda t, g: (lambda b: b and elf() + b)(sea_blob_node(t, g, assets=True))),
        ("sea node20", ".exe", lambda t, g: pe() + sea_blob_v20(t) + bytes(8)),
        ("bun table", "", lambda t, g: bun(t)),
        ("bun runs", "", lambda t, g: bun(t, table=False)),
        ("deno trailer", "", lambda t, g: deno(t)),
        ("deno section", "", lambda t, g: deno(t, section=True)),
        ("bytenode", ".jsc", lambda t, g: v8_cache(t, g)),
    ]


# ---------------------------------------------------------------- the tests

def packaged(spec, suffix, raw, tag):
    v, member, qs, _ = spec
    new = member.replace(".mjs", f"-{tag}{suffix}")
    files = {k: val for k, val in v["files"].items() if k != member}
    files[new] = raw
    return [dict(q, member=new, artifact=str(q.get("artifact", "")).replace(member, new)) for q in qs], files, new


def test_containers(specs):
    totals = {}
    for cname, suffix, build in builders():
        plain = uns = none = wrong = n = missed = 0
        bad, keys_ok, missing = [], True, 0
        for i, spec in enumerate(specs):
            v, member, qs, text = spec
            tag = f"{Path(member).stem}-{hashlib.sha256(text).hexdigest()[:12]}"
            raw = build(text, tag)
            if raw is None:
                missing += 1
                continue
            FIXTURES.mkdir(parents=True, exist_ok=True)
            fq, files, new = packaged(spec, suffix, raw, cname.replace(" ", "_"))
            if i < 8:
                (FIXTURES / new).write_bytes(raw)
            got, err = solve(fq, files)
            kind = (nodepkg.view(new, raw) or [None])[0]
            for q in fq:
                n += 1
                a, want = got.get(q["qid"]), (v["key"] or {}).get(q["qid"])
                if a is None:
                    none += 1
                elif unsure(a):
                    uns += 1
                    p = labels.parse(a)
                    k = p.key if p else ""
                    if kind and f"/{kind}" not in k:
                        keys_ok = False
                        bad.append(f"{q['qid']} key {k}")
                    if want is not None and want not in [val for _, val in p.options]:
                        missed += 1
                        bad.append(f"{q['qid']}: {want!r} not among the options of {k}")
                else:
                    plain += 1
                    if want is not None and a != want:
                        wrong += 1
                        bad.append(f"{q['qid']}={a!r} key {want!r}")
        if missing and not n:
            skip(f"containers: {cname}", "node is not on the PATH (V8 cache / SEA blob fixtures)")
            continue
        totals[cname] = (plain, uns, none, n)
        check(f"containers: {cname}: {plain}/{n} plain (none differs from key.json), {uns} unsure (each holds "
              f"the judged answer among its options), {none} None",
              wrong == 0 and missed == 0 and keys_ok and plain > 0, "; ".join(bad[:6]))
    return totals


def test_fallback(specs):
    v, member, qs, text = specs[0]
    cases = [
        ("pkg brotli", ".exe", pkg([("/snapshot/app/index.js", text)], compress=2)),
        ("nexe bad sizes", ".exe", nexe(text)[:-16] + struct.pack("<dd", 1e12, 3.5)),
        ("bun no payload", "", elf() + b"\x00" * 64 + nodepkg.BUN_TRAILER + struct.pack("<Q", 99)),
    ]
    for name, suffix, raw in cases:
        fq, files, new = packaged(specs[0], suffix, raw, name.replace(" ", "_"))
        got, err = solve(fq, files)
        before = dict(files)
        # what the file gives read as it is (the general path on the raw bytes, as before row 94)
        saved = analyze.node_view
        analyze.node_view = lambda m, q, f: (m, q, f)
        try:
            raw_got, _ = solve(fq, before)
        finally:
            analyze.node_view = saved
        check(f"fallback: {name}: read as it is (same answers as without row 94)",
              got == raw_got and "gives no plan; read as it is" in err, f"{got} vs {raw_got}; {err[-300:]}")


def test_ambiguous(specs):
    a, b = specs[0][3], specs[1][3]
    raw = pkg([("/snapshot/app/index.js", a), ("/snapshot/app/lib.js", b)])
    fq, files, new = packaged(specs[0], ".exe", raw, "two_plans")
    got, err = solve(fq, files)
    plan_ids = [q["qid"] for q in fq if q["qid"].rsplit("-", 1)[-1] in ("adapter", "campaign", "steps", "count")]
    check("ambiguous: a pkg with two modules holding two plans answers no plan question",
          plan_ids and all(got.get(i) is None for i in plan_ids), f"{[(i, got.get(i)) for i in plan_ids]}")


def test_scope(corpus):
    v = next(x for x in corpus if "mastery" not in x["name"] and "time_trial" not in x["name"])
    marks = (b"\n// ---- Bun! ----  d3n0l4nd  <nexe~~sentinel> (function (REQUIRE_COMMON, VIRTUAL_FILESYSTEM) "
             b"NODE_SEA_BLOB \x20\xda\x43\x01\n")
    files = {}
    for k, val in v["files"].items():
        files[k] = val + marks if isinstance(val, (bytes, bytearray)) and "->" not in k and not k.endswith(".zip") else val
    with contextlib.redirect_stderr(io.StringIO()):
        before = analyze.solve_set(v["qs"], v["files"], {"set": 1})
        after_view = {m: analyze.node_view(m, [], files)[0] for m in {q["member"] for q in v["qs"]}}
    changed = [m for m, n in after_view.items() if n != m]
    check(f"scope: no text specimen of the Day 7 base ({len(after_view)} files, every marker appended) is a "
          f"Node packaging", not changed, str(changed[:5]))
    got, _ = solve(v["qs"], dict(v["files"]))
    check("scope: the Day 7 base answers as before (no view taken)", got == before)
    plain = b"\x7fELF\x02\x01\x01" + bytes(57) + bytes(RNG.getrandbits(8) for _ in range(6000))
    check("scope: a native executable with no packaging is not a view",
          nodepkg.view("tool", plain + b"plain native code, no packaging" * 10) is None)
    check("scope: a SEA magic as an immediate in code is no blob",
          nodepkg.view("node", plain + b"\xb8\x20\xda\x43\x01\xc3" + bytes(64)) is None)
    fq, files, new = packaged(next(iter(test_scope.specs)), "", elf(), "runtime_only")
    with contextlib.redirect_stderr(io.StringIO()):
        seen = analyze.node_view(new, fq, files)
    check("scope: a runtime holding every marker as a constant (and no script) is read as it is",
          seen[0] == new and seen[2] is files)


def test_bounds(specs):
    bomb = gzip.compress(b"\x00" * (8 << 20))
    b = nodepkg.Budget()
    check("bounds: a gzip stream over the ratio bound is refused", nodepkg.inflate(bomb, b) is None,
          f"{len(bomb)} bytes")
    ok = gzip.compress(b"v=1|steps=a" * 100)
    check("bounds: an ordinary gzip stream inflates", nodepkg.inflate(ok, nodepkg.Budget()) == b"v=1|steps=a" * 100)
    old = nodepkg.MAX_INPUT
    raw = pkg([("/snapshot/app/index.js", specs[0][3])])
    nodepkg.MAX_INPUT = len(raw) - 1
    try:
        check("bounds: an input over MAX_INPUT is not looked at", nodepkg.view("big.exe", raw) is None)
    finally:
        nodepkg.MAX_INPUT = old
    got = nodepkg.view("slow.exe", raw, budget_seconds=-1)
    check("bounds: a reading over its time budget gives no text", got is not None and got[1] == "", str(got and got[2]))
    t = time.monotonic()
    big = elf() + bytes(RNG.getrandbits(8) for _ in range(1 << 20)) * 8 + nodepkg.BUN_TRAILER + struct.pack("<Q", 0)
    nodepkg.view("bun.exe", big)
    check(f"bounds: an 8 MB Bun file with a bad trailer reads in {time.monotonic() - t:.2f} s (< 2 s)",
          time.monotonic() - t < 2)


def test_covers(specs):
    v, member, qs, text = specs[0]
    fq, files, new = packaged(specs[0], ".exe", pkg([("/snapshot/app/index.js", text)]), "covers")
    with contextlib.redirect_stderr(io.StringIO()):
        good = analyze.covers(fq, files)
    check("covers: a packaged specimen whose script gives a plan is covered", not good, str(good[:3]))
    fq, files, new = packaged(specs[0], ".exe", pkg([("/snapshot/app/index.js", text)], compress=2), "covers_no")
    with contextlib.redirect_stderr(io.StringIO()):
        bad = analyze.covers(fq, files)
    check("covers: a packaged specimen with no plan is named", len(bad) == len(fq), str(bad[:2]))


def test_speed(corpus):
    v = next((x for x in corpus if "mastery" in x["name"]), None)
    if v is None:
        skip("speed", "no saved Day 7 Mastery")
        return
    qs, files = list(v["qs"]), dict(v["files"])
    by = {}
    for q in qs:
        by.setdefault(q["member"], []).append(q)
    out_qs = []
    for member, mqs in by.items():
        if not member.endswith(".mjs"):
            out_qs += mqs
            continue
        new = member.replace(".mjs", ".exe")
        files.pop(member, None)
        files[new] = pkg([("/snapshot/app/index.js", v["files"][member])])
        out_qs += [dict(q, member=new) for q in mqs]
    t = time.monotonic()
    solve(v["qs"], v["files"])
    plain_t = time.monotonic() - t
    t = time.monotonic()
    solve(out_qs, files)
    pkg_t = time.monotonic() - t
    check(f"speed: Day 7 Mastery set {v['name']}: {plain_t:.2f} s as .mjs, {pkg_t:.2f} s with every Node "
          f"specimen packaged as pkg (< plain + 0.5 s)", pkg_t < plain_t + 0.5)


def main():
    if not (gm.CHALLENGES / "day-07").exists():
        print("TEST_WAVEC2_NODEPKG passed=0 failed=0 skipped=0 (no saved Day 7 attempts)")
        return 2
    corpus = load_variants()
    specs = node_specimens(corpus)
    seen, uniq = set(), []
    for s in specs:
        if s[3] not in seen:
            seen.add(s[3])
            uniq.append(s)
    print(f"{len(corpus)} saved Day 7 sets, {len(specs)} Node specimens ({len(uniq)} distinct)")
    totals = test_containers(uniq)
    test_fallback(uniq)
    test_ambiguous(uniq)
    test_scope.specs = uniq
    test_scope(corpus)
    test_bounds(uniq)
    test_covers(uniq)
    test_speed(corpus)
    if totals:
        print("coverage (plain/unsure/None of n): " +
              "; ".join(f"{k} {p}/{u}/{z} of {n}" for k, (p, u, z, n) in totals.items()))
    failed = sum(1 for _, ok in results if not ok)
    print(f"TEST_WAVEC2_NODEPKG passed={len(results) - failed} failed={failed} skipped={len(skipped)}")
    shutil.rmtree(SCRATCH, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
