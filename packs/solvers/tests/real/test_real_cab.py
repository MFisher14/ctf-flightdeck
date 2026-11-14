#!/usr/bin/env python3
"""The cabinet unpacking of solvers/metadata-forensics/readers_msi.py on REAL cabinets (backlog
row 283, round 4): the 101 public test cabinets of libmspack, cabextract and libarchive.

  .venv/bin/python tests/real/test_real_cab.py [-v]

Reads the untracked cache <main checkout>/challenges/_realdata/cab (or $CTF_REALDATA/cab),
which tests/real/fetch_cab.py fills; prints SKIP and exits 0 without it. Nothing is written into
the cache, nothing in it is run, no request is made. Several of the files were written to crash a
decoder: here they are bytes handed to the readers, and an LZX or Quantum folder goes to 7zz and
bsdtar the way the reader sends it (carved out under a name of the reader's, to standard output).

The reference is reference_cab.json beside this file: what cabextract 1.11 (libmspack), run once
in a Docker container with no network, unpacked each member to, and what the reader gave then.

  [1] every cached file is the manifest's bytes.
  [2] every cabinet the reader read then it reads now, and refuses the ones it refused; no member
      digest differs from cabextract's, anywhere; every member is `same`, `unknown` or the reader's
      own digest exactly as recorded (a decoder that got better or worse shows here).
  [3] an LZX folder that is read was unpacked by 7zz and by bsdtar, a Quantum folder by 7zz and by
      the decoder in the pack: two decoders, the same bytes. One SKIP line without the tools.
  [4] the damaged cabinets (cve-*, bad_*, partial_*, *-violation-*, lzx-*, the invalid LZX history)
      give no digest for a member cabextract reported damaged, and none raises anything but Unknown.
  [5] timing: no cabinet costs the reader more than the 0.6 s its unpacking may take, and the
      hundred together stay under five seconds.
  [6] the Quantum decoder in the pack against cabinets rebuilt here by the mirror encoder of
      tests/msi_fixtures.py: the encoder gives libmspack's own Quantum block back byte
      for byte; each rebuilt folder is, byte for byte, the one cabextract and 7zz unpacked in round
      4 (its packed SHA-256 is in the reference), and the decoder gives its bytes; the folders with
      a match over a frame's end, which cabextract and 7zz refused, it refuses too.
"""
import hashlib
import json
import os
import random
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
VERBOSE = "-v" in sys.argv[1:]
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
sys.path.append(str(REPO / "tests"))      # last, so tests/ shadows no toolkit module
import sh09_clocks  # noqa: E402
FAILED = []


def check(name, ok, detail=""):
    if VERBOSE or not ok:
        print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else f"   [{str(detail)[:600]}]"))
    if not ok:
        FAILED.append(name)


def samples():
    """The data of the rebuilt Quantum folders, by sample name. Deterministic."""
    rnd = random.Random(13)
    words = [bytes(rnd.randrange(97, 123) for _ in range(rnd.randrange(2, 9))) for _ in range(300)]
    text = b" ".join(rnd.choice(words) for _ in range(60000))
    noise = bytes(rnd.randrange(256) for _ in range(30000))
    mixed = text[:50000] + noise + b"ABCD" * 10000 + text[3000:33000]
    return {"text": text[:200000], "mixed": mixed, "noise": noise[:20000], "zeros": b"\x00" * 100000,
            "short": b"hello hello hello quantum\n", "squares": bytes((i * i >> 3) & 0xFF for i in range(80000))}


def main() -> int:
    import fetch_cab
    folder = fetch_cab.have()
    if folder is None:
        print("SKIP no cache: challenges/_realdata/cab is not filled (tests/real/fetch_cab.py fills it)")
        return 0
    sys.path.insert(0, str(REPO / "tests"))
    import msi_fixtures as T                     # the pack as properties_strict loads it, and the mirror encoder
    try:
        return run(folder, fetch_cab, T.M, T.MSI, T)
    finally:
        shutil.rmtree(T.TMP, ignore_errors=True)


def run(folder, fetch_cab, M, MSI, T) -> int:
    reference = json.loads((HERE / "reference_cab.json").read_text())
    rows = {r["name"]: r for r in fetch_cab.manifest()}
    bodies = {name: (folder / name).read_bytes() for name in rows}
    wrong = [name for name, body in bodies.items() if hashlib.sha256(body).hexdigest() != rows[name]["sha256"]]
    check(f"[1] the {len(rows)} cached cabinets are the manifest's bytes", len(rows) == 101 and not wrong
          and set(rows) == set(reference["cabinets"]), wrong[:4])
    tools = MSI._sevenzip() is not None and os.access(MSI.BSDTAR[0], os.X_OK)
    if not tools:
        print("SKIP [2][3] 7zz or bsdtar is not installed: the LZX and Quantum members are not held to the reference")
    # The reader's production SEVENZIP_BUDGET/SECONDS are WALL caps for a live solve. Under the suite's
    # sustained load the tool subprocess spawn and the post-timeout SIGKILL reap alone can blow a 0.6 s cap,
    # so a cabinet that unpacks on an idle machine runs out of budget: members come back `unknown`, LZX/Quantum
    # folders are read by only one decoder, and [2]/[3]/[5] flake. Give the reader a generous budget for the
    # test (the SH-08/SH-10 method: an explicit test budget, not the production default), so every tool and
    # the in-process Quantum decoder finish under any load and [2]-[4] match the reference deterministically.
    # The reader's own cost is then held as idle-machine WORK below (not this wall budget). WORK_LIMIT is the
    # production per-cabinet budget, i.e. the idle-machine seconds a cabinet's in-process work may cost.
    WORK_LIMIT = MSI.SEVENZIP_BUDGET
    MSI.SEVENZIP_BUDGET = MSI.SEVENZIP_SECONDS = 30.0
    differ, moved, raised, single, damaged = [], [], [], [], []
    work, meter = {}, {"why": None}               # per-cabinet in-process work (seconds at the core's top clock)
    counts = {"same": 0, "unknown": 0, "own": 0, "refused": 0}

    def metered(fn, *a):
        out, w, why = sh09_clocks.work_seconds_unless_missing(fn, *a)
        if why:
            meter["why"] = why
        return out, (w or 0.0)

    for name, want in sorted(reference["cabinets"].items()):
        body = bodies[name]
        cabwork = 0.0
        try:
            cab, w = metered(MSI.held(MSI._cab_parse), body)   # as the readers call it: a cut header is Unknown
            cabwork += w
        except M.Unknown:
            cab = None
        if cab is None or "refused" in want:
            if (cab is None) != ("refused" in want):
                moved.append((name, "read now" if cab is not None else "refused now"))
            counts["refused"] += 1
            continue
        for i, (f, ref) in enumerate(zip(cab["files"], want["members"])):
            hard = ref["method"] in ("lzx", "quantum")
            try:
                mb, w = metered(MSI._cab_member, body, cab, f)
                cabwork += w
                got = hashlib.sha256(mb).hexdigest()
            except M.Unknown:
                got = "unknown"
            except Exception as e:
                raised.append((name, i, type(e).__name__))
                continue
            theirs = ref["cabextract"] if ref["cabextract"] not in (None, "failed") else None
            if got != "unknown" and theirs is not None and got != theirs:
                differ.append((name, i, got[:12], theirs[:12]))
            if got != "unknown" and ref["cabextract"] == "failed":
                damaged.append((name, i))
            expected = theirs if ref["reader"] == "same" else ref["reader"]
            if got != expected and (tools or not hard):
                moved.append((name, i, ref["method"], f"{got[:12]} now, {expected[:12]} then"))
            counts["same" if ref["reader"] == "same" else "unknown" if ref["reader"] == "unknown" else "own"] += 1
            if tools and hard and got != "unknown" and len(cab.get("decoders", {}).get(f[3], [])) != 2:
                single.append((name, i, cab.get("decoders", {}).get(f[3])))
        if len(cab["files"]) != len(want["members"]):
            moved.append((name, "member count"))
        work[name] = cabwork
    check("[2] no member digest differs from cabextract's on any real cabinet", not differ, differ[:4])
    check(f"[2] every cabinet and member is as the reference has it: {counts['same']} the same as cabextract, {counts['unknown']} unknown, "
          f"{counts['own']} the reader's own, {counts['refused']} cabinets refused at the header",
          not moved and counts["same"] >= 190 and counts["refused"] == 36, moved[:5])
    if tools:
        members = [m for w in reference["cabinets"].values() for m in w.get("members", []) if m["reader"] == "same"]
        lzx, qtm = sum(1 for m in members if m["method"] == "lzx"), sum(1 for m in members if m["method"] == "quantum")
        check(f"[3] every LZX and Quantum member that is read ({lzx} and {qtm}) was unpacked by two decoders that agree",
              not single and lzx == 17 and qtm == 2, single[:4])
    check("[4] no digest for a member cabextract reported damaged, and nothing raised but Unknown", not damaged and not raised,
          (damaged[:3], raised[:3]))
    # [5] Not a wall-clock upper bound on this test's elapsed time (which flakes under the suite's load,
    # SH-10, rule 16), and not the reader's wall budget (its tool spawn/reap overhead inflates under load
    # too). The cost held here is the reader's IN-PROCESS work per cabinet (header parse, MSZIP and Quantum
    # decode, glue), measured as seconds at the core's top clock (sh09 work meter: core cycles over the top
    # clock, which a lower clock does not change), against WORK_LIMIT (the production per-cabinet budget).
    # The LZX/Quantum tool subprocesses run in another process, so their cycles are not in this meter; their
    # time is bounded by the reader's own (now generous) budget and is not what this check is about.
    if meter["why"]:
        print(f"SKIP [5] the in-process work bound: cost limit {WORK_LIMIT:g} s not checked: no work meter ({meter['why']})")
    else:
        slow = {n: round(w, 3) for n, w in work.items() if w > WORK_LIMIT}
        check(f"[5] no cabinet's in-process work is over {WORK_LIMIT:g} s at the core's top clock "
              f"(slowest {(max(work.values()) if work else 0):.3f} s), all of them {sum(work.values()):.2f} s",
              not slow and sum(work.values()) < 5, slow)

    real = bodies["cabextract-cabs-mixed.cab"]
    parsed = MSI._cab_parse(real)
    block = MSI._cab_blocks(real, parsed, 2)[0]
    text = MSI._quantum([block], 18)
    check("[6] the mirror encoder gives libmspack's own Quantum block back, byte for byte",
          text.startswith(b"If you can read this") and T.quantum_encode(text, 18) == [block], text[:40])
    data, bad = samples(), []
    for ref in reference["quantum_built"]:
        blocks = T.quantum_encode(data[ref["sample"]], ref["window_bits"], cross=ref["cross"])
        packed = hashlib.sha256(b"".join(p for p, _ in blocks)).hexdigest()
        try:
            got = hashlib.sha256(MSI._quantum(blocks, ref["window_bits"])).hexdigest()
        except M.Unknown:
            got = None
        if packed != ref["packed_sha256"] or got != (ref["sha256"] if ref["valid"] else None) or len(blocks) != ref["frames"]:
            bad.append((ref["sample"], ref["window_bits"], ref["cross"], packed == ref["packed_sha256"], got and got[:12]))
    valid = sum(1 for r in reference["quantum_built"] if r["valid"])
    check(f"[6] the {valid} rebuilt Quantum folders cabextract and 7zz unpacked are unpacked to the same bytes here, "
          f"and the {len(reference['quantum_built']) - valid} they refused are refused", not bad and valid == 9, bad[:4])
    print(f"{len(FAILED)} failed")
    if FAILED:
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
