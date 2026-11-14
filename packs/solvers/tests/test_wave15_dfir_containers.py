#!/usr/bin/env python3
"""wave15 coverage: readers_dfir_more.py (WIM, VHDX, EWF/E01, classic EVT headers).

  .venv/bin/python tests/test_wave15_dfir_containers.py

Offline; no request, no token. What is held here:

  1. the pack loads and registers nothing confirmed (every answer of it goes through labels.pick), and
     readers_forensic.py is still LAST in MORE_FILES (this pack is inserted before it);
  2. on tool-built samples each reader returns the structural fact UNSURE with the truth as the first option,
     dispatching by the TRUE leading magic / fixed header, not the extension: a WIM, a VHDX, an EWF and an
     EVT are never read as one another, and random / foreign bytes are read as none of them;
  3. damaged, cut and ambiguous inputs are never plain (None or an unsure value, never a wrong fact);
  4. fuzz: truncated and bit-flipped copies of every sample raise nothing inside solve_set, answer in well
     under a second, and nothing is ever plain.
"""
import io
import os
import random
import struct
import sys
import time
import uuid
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "metadata-forensics"))
os.environ.setdefault("CTF_TESTING", "1")
import labels  # noqa: E402
import properties_strict as M  # noqa: E402

FORMATS = {
    "int": {"kind": "integer", "syntax": "base-10 integer with no units, separators, or explanatory text"},
    "text": {"kind": "exact_text", "syntax": "exact ordered artifact-derived text"},
    "value": {"kind": "exact_text", "syntax": "exact artifact-derived value only; use the literal none only when the requested field is absent"},
    "list": {"kind": "json", "syntax": "compact valid JSON array with exact values and order"},
}
FAILED = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  [{str(detail)[:600]}]"))
    if not ok:
        FAILED.append(name)


def ask(prop, member, data, kind="value"):
    ns = prop.split(".")[0]
    qid = f"w15-{ns}-001-" + prop.replace(".", "-").replace("_", "-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr(zipfile.ZipInfo(member, (2026, 1, 1, 0, 0, 0)), data)
    blob = buf.getvalue()
    q = {"id": qid, "qid": qid, "answer_id": qid, "question": f"Determine {prop} for {member}.",
         "artifact": f"evidence.zip -> {member}", "member": member, "answer_format": dict(FORMATS[kind])}
    err, old = io.StringIO(), sys.stderr
    sys.stderr = err
    t = time.perf_counter()
    try:
        out = M.solve_set([q], {"evidence.zip": blob, member: data},
                          {"set": 1, "delivery_name": "evidence.zip", "delivery": blob, "attempt": {}})
    finally:
        sys.stderr = old
    return out[qid], err.getvalue(), time.perf_counter() - t


def options(answer):
    u = labels.parse(answer) if isinstance(answer, str) else None
    return None if u is None else [v for _, v in u.options]


def is_plain(answer):
    return isinstance(answer, str) and not labels.is_unsure(answer)


def first(answer):
    o = options(answer)
    return o[0] if o else None


# ------------------------------------------------------------------ sample builders

def wim(image_count=2, version=0x00010D00, flags=0x00000002, chunk=0x8000, part=1, total=1, boot=1,
        guid_bytes=None):
    d = bytearray(0xD0)
    d[:8] = b"MSWIM\x00\x00\x00"
    struct.pack_into("<IIII", d, 8, 0xD0, version, flags, chunk)
    d[0x18:0x28] = guid_bytes if guid_bytes is not None else bytes(range(16))
    struct.pack_into("<HH", d, 0x28, part, total)
    struct.pack_into("<I", d, 0x2C, image_count)
    struct.pack_into("<I", d, 0x78, boot)
    return bytes(d)


def vhdx(creator="Microsoft Windows 10.0", seqs=(3, 7), version=1, log_version=0, log_len=0x100000,
         log_off=0x100000, fwg=None, dwg=None, lg=None):
    """A VHDX whose two 'head' regions carry sequence numbers `seqs`; the greater one is current."""
    d = bytearray(0x30000)
    d[:8] = b"vhdxfile"
    cb = creator.encode("utf-16-le")
    d[8:8 + len(cb)] = cb
    fwg = fwg if fwg is not None else bytes(range(16))
    dwg = dwg if dwg is not None else bytes(range(16, 32))
    lg = lg if lg is not None else bytes(16)
    for base, seq in zip((0x10000, 0x20000), seqs):
        d[base:base + 4] = b"head"
        struct.pack_into("<Q", d, base + 8, seq)
        d[base + 0x10:base + 0x20] = fwg
        d[base + 0x20:base + 0x30] = dwg
        d[base + 0x30:base + 0x40] = lg
        struct.pack_into("<HH", d, base + 0x40, log_version, version)
        struct.pack_into("<I", d, base + 0x44, log_len)
        struct.pack_into("<Q", d, base + 0x48, log_off)
    return bytes(d)


def ewf(family="EVF", segment=1, sections=("header", "volume", "sectors", "table", "done")):
    magic = {"EVF": b"EVF\x09\x0d\x0a\xff\x00", "LVF": b"LVF\x09\x0d\x0a\xff\x00"}[family]
    # lay out fixed-stride 76-byte section descriptors, each `next` pointing to the following one
    body = bytearray()
    at0 = 13
    offsets = [at0 + i * 76 for i in range(len(sections))]
    for i, t in enumerate(sections):
        desc = bytearray(76)
        desc[:len(t)] = t.encode("ascii")
        terminal = t in ("done", "next") or i == len(sections) - 1
        nxt = offsets[i] if terminal else offsets[i + 1]
        struct.pack_into("<QQ", desc, 16, nxt, 76)
        body += desc
    head = magic + bytes([1]) + struct.pack("<H", segment) + b"\x00\x00"
    return head + bytes(body)


def ewf2(family="EVF2"):
    return {"EVF2": b"EVF2\x0d\x0a\x81\x00", "LEF2": b"LEF2\x0d\x0a\x81\x00"}[family] + b"\x00" * 64


def evt(major=1, minor=1, start=0x30, end=0x1000, cur=42, old=1, maxsize=0x80000, flags=0x08, ret=0):
    d = bytearray(0x30)
    struct.pack_into("<I4sIIIIIIIIII", d, 0, 0x30, b"LfLe", major, minor, start, end, cur, old, maxsize,
                     flags, ret, 0x30)
    return bytes(d) + b"\x00" * 0x100


# ------------------------------------------------------------------ tests

def test_loads():
    loaded = M.MORE_LOADED.get("readers_dfir_more.py")
    check("readers_dfir_more.py is loaded and registers names", bool(loaded) and loaded[0] > 20, loaded)
    check("readers_dfir_more.py is in MORE_FILES before readers_forensic.py", "readers_dfir_more.py" in M.MORE_FILES
          and M.MORE_FILES.index("readers_dfir_more.py") < M.MORE_FILES.index("readers_forensic.py"), M.MORE_FILES[-3:])
    # readers_forensic.py was LAST when this pack was cut; HEAD since appended the Day-24 look-ahead
    # readers_polyglot.py (new namespaces only, no ewf.* name), so forensic is no longer the final entry.
    # What this pack actually needs is that its own EWF2-capable readers win the shared ewf.* names,
    # which the first-registration guard (free()) gives because this pack loads before readers_forensic.py.
    check("this pack's EWF2-capable ewf.* readers win the shared names (loads before readers_forensic.py)",
          all(getattr(M.REG.get("ewf_" + nm), "fn", None).__module__ == "metadata_readers_dfir_more"
              for nm in ("format", "segment_number", "first_section_type", "section_count", "section_types")),
          {nm: getattr(getattr(M.REG.get("ewf_" + nm), "fn", None), "__module__", None)
           for nm in ("format", "segment_number", "first_section_type")})
    pack = M.MORE_MODULES["readers_dfir_more.py"]
    confirmed = sorted(p.name for p in M.REG.values() if p.confirmed and p.fn in set(pack.NEW_FNS))
    check("nothing the pack registers is confirmed: every answer goes through labels.pick", not confirmed, confirmed)


def test_wim():
    g = uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00")
    w = wim(image_count=3, version=0x00010D00, flags=0x00000002, chunk=0x8000, part=1, total=1, boot=2,
            guid_bytes=g.bytes_le)
    cases = {
        "wim.image_count": ("int", "3"),
        "wim.header_size": ("int", "208"),
        "wim.chunk_size": ("int", "32768"),
        "wim.boot_index": ("int", "2"),
    }
    bad = [f"{p}: {ask(p, 'install.wim', w, k)[0]!r}" for p, (k, want) in cases.items()
           if is_plain(ask(p, "install.wim", w, k)[0]) or first(ask(p, "install.wim", w, k)[0]) != want]
    check("WIM header: counts and sizes read UNSURE with the truth first", not bad, bad)
    ver, _, _ = ask("wim.version", "install.wim", w, "value")
    check("wim.version is an unsure number, 0x10d00 first", not is_plain(ver) and first(ver) == "0x10d00", ver)
    gid, _, _ = ask("wim.guid", "install.wim", w, "value")
    check("wim.guid is unsure, the GUID (hyphen-lower) first", not is_plain(gid) and first(gid) == str(g), gid)
    cut = ask("wim.image_count", "x.wim", w[:0x40], "int")[0]
    check("a cut WIM header is never plain", not is_plain(cut), cut)


def test_vhdx():
    fwg = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    v = vhdx(creator="QEMU 8.1", seqs=(3, 9), version=1, log_len=0x100000, log_off=0x100000, fwg=fwg.bytes_le)
    cr, _, _ = ask("vhdx.creator", "disk.vhdx", v, "text")
    seq, _, _ = ask("vhdx.sequence_number", "disk.vhdx", v, "int")
    ver, _, _ = ask("vhdx.format_version", "disk.vhdx", v, "value")
    fwgid, _, _ = ask("vhdx.file_write_guid", "disk.vhdx", v, "value")
    ll, _, _ = ask("vhdx.log_length", "disk.vhdx", v, "int")
    check("VHDX: creator, current (max-seq) sequence number, version, write GUID and log length read UNSURE, truth first",
          first(cr) == "QEMU 8.1" and first(seq) == "9" and first(ver) == "0x1" and first(fwgid) == str(fwg)
          and first(ll) == "1048576" and not any(is_plain(x) for x in (cr, seq, ver, fwgid, ll)),
          (cr, seq, ver, fwgid, ll))
    # header fields come from the region with the GREATER sequence number
    v2 = vhdx(seqs=(50, 2))
    seq2, _, _ = ask("vhdx.sequence_number", "disk.vhdx", v2, "int")
    check("VHDX current header is the greater sequence number regardless of region order", first(seq2) == "50", seq2)
    # a VHDX with only the file-type identifier (no header regions) still reads the creator, header fields None
    short = vhdx()[:0x9000]
    crs, _, _ = ask("vhdx.creator", "disk.vhdx", short, "text")
    seqs_none = ask("vhdx.sequence_number", "disk.vhdx", short, "int")[0]
    check("VHDX with no header region: creator still read (unsure), header fields None",
          not is_plain(crs) and first(crs) and seqs_none is None, (crs, seqs_none))


def test_ewf():
    e = ewf(family="EVF", segment=1, sections=("header", "volume", "sectors", "table", "table2", "digest", "done"))
    fam, _, _ = ask("ewf.format", "image.E01", e, "text")
    seg, _, _ = ask("ewf.segment_number", "image.E01", e, "int")
    fs, _, _ = ask("ewf.first_section_type", "image.E01", e, "text")
    sc, _, _ = ask("ewf.section_count", "image.E01", e, "int")
    st, _, _ = ask("ewf.section_types", "image.E01", e, "list")
    check("EWF1 (E01): family, segment, first section, count and type list read UNSURE, truth first",
          first(fam) == "EVF" and first(seg) == "1" and first(fs) == "header" and first(sc) == "7"
          and first(st) == '["header","volume","sectors","table","table2","digest","done"]'
          and not any(is_plain(x) for x in (fam, seg, fs, sc, st)), (fam, seg, fs, sc, st))
    lvf = ewf(family="LVF", segment=3, sections=("header", "done"))
    lf, _, _ = ask("ewf.format", "logical.L01", lvf, "text")
    ls, _, _ = ask("ewf.segment_number", "logical.L01", lvf, "int")
    check("EWF1 logical (LVF/L01): family LVF and segment read", first(lf) == "LVF" and first(ls) == "3", (lf, ls))
    e2 = ewf2("EVF2")
    f2, _, _ = ask("ewf.format", "image.Ex01", e2, "text")
    s2 = ask("ewf.segment_number", "image.Ex01", e2, "int")[0]
    check("EWF2 (Ex01): only the family is read (EVF2); segment/sections None (layout differs)",
          first(f2) == "EVF2" and not is_plain(f2) and s2 is None, (f2, s2))
    # a damaged EWF1 (fields-start byte not 0x01) is Unknown for segment/sections, never plain, but the magic
    # family still reads
    bad = bytearray(e)
    bad[8] = 0x55
    dseg = ask("ewf.segment_number", "x.E01", bytes(bad), "int")[0]
    dfam, _, _ = ask("ewf.format", "x.E01", bytes(bad), "text")
    check("EWF1 with a bad fields-start byte: segment None, family still EVF, never plain",
          dseg is None and first(dfam) == "EVF", (dseg, dfam))
    # a looping / off-file section next offset -> Unknown, never plain
    loop = bytearray(ewf(sections=("header", "sectors", "done")))
    struct.pack_into("<Q", loop, 13 + 16, 13 + 76 * 999)   # header.next points past the file
    lc = ask("ewf.section_count", "x.E01", bytes(loop), "int")[0]
    check("EWF1 with a section 'next' past the file: count None (Unknown), never plain", not is_plain(lc), lc)


def test_evt():
    e = evt(major=1, minor=1, cur=42, old=1, maxsize=0x80000, flags=0x08)
    cases = {
        "evt.header_size": ("int", "48"),
        "evt.major_version": ("int", "1"),
        "evt.current_record_number": ("int", "42"),
        "evt.oldest_record_number": ("int", "1"),
        "evt.max_size": ("int", "524288"),
    }
    bad = [f"{p}: {ask(p, 'AppEvent.Evt', e, k)[0]!r}" for p, (k, want) in cases.items()
           if is_plain(ask(p, "AppEvent.Evt", e, k)[0]) or first(ask(p, "AppEvent.Evt", e, k)[0]) != want]
    check("classic EVT header: fields read UNSURE with the truth first", not bad, bad)
    fl, _, _ = ask("evt.flags", "AppEvent.Evt", e, "value")
    check("evt.flags is an unsure number, 0x8 first", not is_plain(fl) and first(fl) == "0x8", fl)
    bad_size = bytearray(e)
    struct.pack_into("<I", bad_size, 0, 0x40)   # a header-size field that is not 0x30
    bs = ask("evt.header_size", "x.evt", bytes(bad_size), "int")[0]
    check("EVT with a header size that is not 0x30 is Unknown, never plain", not is_plain(bs), bs)


def test_dispatch_cross():
    samples = {"wim": wim(), "vhdx": vhdx(), "ewf": ewf(), "evt": evt()}
    probes = {"wim": ("wim.image_count", "int"), "vhdx": ("vhdx.sequence_number", "int"),
              "ewf": ("ewf.segment_number", "int"), "evt": ("evt.header_size", "int")}
    wrong = []
    for sname, data in samples.items():
        for pname, (prop, kind) in probes.items():
            got = ask(prop, "x.bin", data, kind)[0]
            if pname != sname and got is not None:
                wrong.append(f"{pname} reader read a {sname} sample: {got!r}")
    check("cross-dispatch: each reader reads only its own magic; a foreign container is None", not wrong, wrong)
    decoy = [("random", os.urandom(0x400)), ("zeros", b"\x00" * 0x400), ("jpeg", b"\xff\xd8\xff\xe0" + b"\x00" * 0x200),
             ("text", b"not a container at all " * 40), ("MSWIM-prefix-only", b"MSWIM\x00\x00\x00" + b"\x00" * 4)]
    none_bad = []
    for lab, d in decoy:
        for prop, kind in probes.values():
            if ask(prop, "x.bin", d, kind)[0] is not None and lab != "MSWIM-prefix-only":
                none_bad.append(f"{lab}: {prop}")
    # the MSWIM-prefix-only buffer is a cut WIM header: it must be Unknown (unsure/None), never plain
    cut = ask("wim.image_count", "x.bin", b"MSWIM\x00\x00\x00" + b"\x00" * 4, "int")[0]
    check("decoys (random/zeros/jpeg/text) are read as no container", not none_bad, none_bad)
    check("a bare WIM magic with a cut header is never plain", not is_plain(cut), cut)


def test_never_wrong_and_fast():
    samples = {"wim": wim(), "vhdx": vhdx(), "ewf": ewf(sections=("header", "volume", "sectors", "done")),
               "evt": evt()}
    props = ["wim.image_count", "wim.version", "wim.guid", "vhdx.creator", "vhdx.sequence_number",
             "vhdx.file_write_guid", "ewf.format", "ewf.segment_number", "ewf.section_types",
             "ewf.section_count", "evt.header_size", "evt.flags", "evt.current_record_number"]
    rnd = random.Random(20261024)
    plain, raised, slow, n = [], [], [], 0
    for base, data in samples.items():
        variants = [("whole", data)]
        for _ in range(16):
            if len(data) < 16:
                continue
            b = bytearray(data)
            cut = rnd.randrange(8, len(b))
            variants.append(("truncated", bytes(b[:cut])))
            b2 = bytearray(data)
            i = rnd.randrange(len(b2))
            b2[i] ^= 1 << rnd.randrange(8)
            variants.append(("bitflip", bytes(b2)))
        for label, d in variants:
            for prop in props:
                n += 1
                try:
                    got, _, secs = ask(prop, "x.bin", d, "value")
                except Exception as e:
                    raised.append(f"{base}/{label} {prop}: {type(e).__name__}: {e}")
                    continue
                if is_plain(got):
                    plain.append(f"{base}/{label} {prop}: {got!r}")
                if secs > 0.3:
                    slow.append(f"{base}/{label} {prop}: {secs:.2f}s")
    check(f"fuzz ({n} asks): no exception leaves solve_set", not raised, raised[:5])
    check("fuzz: no answer is ever plain (never-wrong)", not plain, plain[:5])
    check("fuzz: every ask returns in under 0.3 s", not slow, slow[:5])


def main():
    test_loads()
    test_wim()
    test_vhdx()
    test_ewf()
    test_evt()
    test_dispatch_cross()
    test_never_wrong_and_fast()
    print()
    if FAILED:
        print(f"FAILED {len(FAILED)}:")
        for f in FAILED:
            print("  - " + f)
        sys.exit(1)
    print("all wave15 dfir-container checks passed")


if __name__ == "__main__":
    main()
