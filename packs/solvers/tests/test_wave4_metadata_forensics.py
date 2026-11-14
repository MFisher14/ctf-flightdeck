#!/usr/bin/env python3
"""wave4, Metadata Forensics ticket T7: readers_forensic.py (the USN $J change journal, the regf root key's
value list, the prefetch volume information block).

  .venv/bin/python tests/test_wave4_metadata_forensics.py

Offline; no request, no token. What is held here:

  1. the pack loads with the solver LAST in MORE_FILES and registers nothing confirmed (every answer of it
     goes through labels.pick);
  2. on tool-built samples each reader returns the structural fact UNSURE with the truth read as the first
     option, dispatching by the TRUE structure, not the extension: a prefetch, a hive and random bytes are
     not read as a USN journal, and a USN journal is not read as a hive or a prefetch;
  3. damaged, ambiguous and no-sample inputs are never plain (None or an unsure value, never a wrong fact):
     a cut record, a bad name offset, a later garbage record, a compressed (MAM) prefetch, an unknown
     prefetch version, a hive with an unnamed default value;
  4. fuzz: truncated and bit-flipped copies of every sample raise nothing inside solve_set and answer in
     well under a second, and nothing is ever plain.
"""
import io
import os
import random
import struct
import sys
import time
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
    """(answer, stderr, seconds) for one question asked as tools/run.py asks it."""
    ns = prop.split(".")[0]
    qid = f"w4-{ns}-001-" + prop.replace(".", "-").replace("_", "-")
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

def usn_record(name, usn=0x100, frn=0x1234, parent=0x5, ts=133000000000000000, reason=0x102, source=0,
               sec=0x201, attrs=0x20, major=2):
    """One USN_RECORD_V2 (major 2) or V3 (major 3), 8-byte aligned."""
    refw = 8 if major == 2 else 16
    hdr = 60 if major == 2 else 76
    nb = name.encode("utf-16-le")
    rl = (hdr + len(nb) + 7) & ~7
    b = bytearray(rl)
    struct.pack_into("<IHH", b, 0, rl, major, 0)
    b[8:8 + refw] = frn.to_bytes(refw, "little")
    b[8 + refw:8 + 2 * refw] = parent.to_bytes(refw, "little")
    p = 8 + 2 * refw
    struct.pack_into("<QqIIII", b, p, usn, ts, reason, source, sec, attrs)
    struct.pack_into("<HH", b, hdr - 4, len(nb), hdr)
    b[hdr:hdr + len(nb)] = nb
    return bytes(b)


def journal(records, pad=4096):
    return b"\x00" * pad + b"".join(records) + b"\x00" * 64


def hive(values, nsub=0, last_written=0x01D4A1B2C3D40000, class_name=None, default_value=False):
    """A registry hive whose root nk (cell 0x20) carries a value list at 0x200 with vk cells at 0x600+.
    `values`: [(name, ascii_flag)]. `default_value`: give one value an empty (default) name."""
    d = bytearray(0x1000 + 0x8000)
    d[:4] = b"regf"
    d[36:40] = (0x20).to_bytes(4, "little")
    at = 0x1000 + 0x20 + 4
    d[at:at + 2] = b"nk"
    d[at + 2:at + 4] = (0x20).to_bytes(2, "little")   # flags: 0x20 = ASCII key name
    d[at + 4:at + 12] = last_written.to_bytes(8, "little")
    d[at + 0x14:at + 0x18] = nsub.to_bytes(4, "little")
    d[at + 0x1C:at + 0x20] = (0x100).to_bytes(4, "little")
    d[at + 0x24:at + 0x28] = len(values).to_bytes(4, "little")
    d[at + 0x28:at + 0x2C] = (0x200).to_bytes(4, "little")
    if class_name:
        cb = class_name.encode("utf-16-le")
        d[at + 0x30:at + 0x34] = (0x400).to_bytes(4, "little")
        d[at + 0x4A:at + 0x4C] = len(cb).to_bytes(2, "little")
        d[0x1000 + 0x400 + 4:0x1000 + 0x400 + 4 + len(cb)] = cb
    else:
        d[at + 0x30:at + 0x34] = (0xFFFFFFFF).to_bytes(4, "little")
    d[at + 0x48:at + 0x4A] = (4).to_bytes(2, "little")
    d[at + 0x4C:at + 0x50] = b"ROOT"
    la = 0x1000 + 0x200 + 4
    for i, (name, af) in enumerate(values):
        voff = 0x600 + i * 0x40
        d[la + 4 * i:la + 4 * i + 4] = voff.to_bytes(4, "little")
        vk = 0x1000 + voff + 4
        d[vk:vk + 2] = b"vk"
        if default_value and i == 0:
            name, nb = "", b""
        else:
            nb = name.encode("latin-1") if af else name.encode("utf-16-le")
        d[vk + 2:vk + 4] = len(nb).to_bytes(2, "little")
        d[vk + 0x10:vk + 0x12] = (1 if af else 0).to_bytes(2, "little")
        d[vk + 0x14:vk + 0x14 + len(nb)] = nb
    return bytes(d)


def prefetch(version=30, exe="CMD.EXE", vol_path="\\DEVICE\\HARDDISKVOLUME1", serial=0x1234ABCD,
             created=0x01D4A1B2C3D40000, vol_count=1):
    d = bytearray(0x8000)
    struct.pack_into("<I", d, 0, version)
    d[4:8] = b"SCCA"
    struct.pack_into("<I", d, 12, len(d))
    eb = exe.encode("utf-16-le")
    d[16:16 + len(eb)] = eb
    struct.pack_into("<I", d, 76, 0xDEADBEEF)   # name hash
    struct.pack_into("<III", d, 0x6C, 0x1000, vol_count, 0x200)   # volume info offset, count, size
    struct.pack_into("<I", d, 0xD0, 3)          # a v26/v30 run count (not this pack's field)
    if vol_count:
        vo, db = 0x1000, vol_path.encode("utf-16-le")
        struct.pack_into("<I", d, vo + 0, 0x20)              # device path offset (relative to the entry)
        struct.pack_into("<I", d, vo + 4, len(vol_path))     # device path length in characters
        struct.pack_into("<Q", d, vo + 8, created)
        struct.pack_into("<I", d, vo + 0x10, serial)
        d[vo + 0x20:vo + 0x20 + len(db)] = db
    return bytes(d)


# ------------------------------------------------------------------ tests

def test_loads():
    loaded = M.MORE_LOADED.get("readers_forensic.py")
    check("readers_forensic.py is loaded and registers names", bool(loaded) and loaded[0] > 50, loaded)
    # This pack was last when wave4 was cut; HEAD since appended look-ahead packs after it (Day-24
    # readers_polyglot.py, wave15 readers_dfir_more.py loads before it). It registers ONLY free names
    # via free(), so its position no longer needs to be last: what matters is that nothing it registered
    # was taken from it, i.e. every name it owns still resolves to this pack's module.
    pack0 = M.MORE_MODULES["readers_forensic.py"]
    owned = {k for k, p in M.REG.items() if p.fn in set(pack0.NEW_FNS)}
    check("readers_forensic.py registers only free names, and keeps every one it registered",
          bool(owned) and all(M.REG[k].fn.__module__ == "metadata_readers_forensic" for k in owned),
          M.MORE_FILES[M.MORE_FILES.index("readers_forensic.py"):])
    pack = M.MORE_MODULES["readers_forensic.py"]
    confirmed = sorted(p.name for p in M.REG.values() if p.confirmed and p.fn in set(pack.NEW_FNS))
    check("nothing the pack registers is confirmed: every answer goes through labels.pick", not confirmed, confirmed)


def test_usn():
    j = journal([usn_record("report.txt", usn=0x100, frn=0x1234, parent=0x5, reason=0x102, sec=0x201, attrs=0x20),
                 usn_record("notes.log", usn=0x200), usn_record("a", usn=0x300)])
    cases = {
        "usn.record_count": ("int", "3"),
        "usn.first_record_usn": ("int", "256"),
        "usn.first_record_file_reference_number": ("int", "4660"),
        "usn.first_record_parent_file_reference_number": ("int", "5"),
        "usn.first_record_file_name": ("text", "report.txt"),
        "usn.first_record_file_name_length": ("int", "20"),
        "usn.first_record_major_version": ("int", "2"),
        "usn.first_record_minor_version": ("int", "0"),
        "usn.first_record_security_id": ("int", "513"),
    }
    bad = []
    for prop, (kind, want) in cases.items():
        got, _, _ = ask(prop, "UsnJrnl-J.bin", j, kind)
        if is_plain(got) or first(got) != want:
            bad.append(f"{prop}: {got!r}")
    check("USN V2 journal: count and first-record fields read UNSURE with the truth first", not bad, bad)

    reason, _, _ = ask("usn.first_record_reason", "UsnJrnl-J.bin", j, "value")
    check("usn.first_record_reason is an unsure number, 0x102 first", not is_plain(reason) and first(reason) == "0x102", reason)
    ts, _, _ = ask("usn.first_record_timestamp", "UsnJrnl-J.bin", j, "value")
    check("usn.first_record_timestamp is unsure, the raw FILETIME first", not is_plain(ts) and first(ts) == "133000000000000000", ts)

    j3 = journal([usn_record("v3file.dat", usn=0x50, frn=0xABCD, parent=0x5, major=3)])
    name3, _, _ = ask("usn.first_record_file_name", "UsnJrnl-J.bin", j3, "text")
    frn3, _, _ = ask("usn.first_record_file_reference_number", "UsnJrnl-J.bin", j3, "int")
    maj3, _, _ = ask("usn.first_record_major_version", "UsnJrnl-J.bin", j3, "int")
    check("USN V3 journal (128-bit references): name, reference and version 3 read", first(name3) == "v3file.dat" and first(frn3) == "43981" and first(maj3) == "3", (name3, frn3, maj3))

    # dispatch by structure, not extension: not-a-journal is None
    decoy = [("random bytes", os.urandom(2048)), ("a JPEG header", b"\xff\xd8\xff\xe0" + b"\x00" * 512),
             ("a prefetch", prefetch()), ("a hive", hive([("X", 1)])), ("ascii text", b"hello this is not a journal " * 40)]
    none_bad = [lab for lab, d in decoy if ask("usn.record_count", "x.bin", d, "int")[0] is not None]
    check("USN dispatch by structure: a prefetch, a hive, a JPEG, random and text bytes are not read as a journal (None)", not none_bad, none_bad)

    # damaged / ambiguous -> never plain
    cut = journal([usn_record("report.txt")[:40]])            # first record cut
    badoff = bytearray(journal([usn_record("report.txt")]))   # corrupt the first record's name offset
    s = len(cut) and 4096
    badoff[s + 58:s + 60] = (999).to_bytes(2, "little")
    garbage = journal([usn_record("report.txt")]) [:-64] + b"\x11" * 32 + b"\x00" * 32  # a non-zero garbage second record
    dmg = {"first record cut": ask("usn.record_count", "x.bin", cut, "int")[0],
           "bad name offset": ask("usn.first_record_file_name", "x.bin", bytes(badoff), "text")[0],
           "garbage second record (count not established)": ask("usn.record_count", "x.bin", garbage, "int")[0]}
    check("USN damaged inputs are never plain (None or unsure)", not any(is_plain(v) for v in dmg.values()), dmg)
    check("USN a cut first record is None (not a readable journal)", dmg["first record cut"] is None, dmg)


def test_regf():
    h = hive([("Version", 1), ("InstallDate", 1), ("Owner", 0)], nsub=2, last_written=0x01D4A1B2C3D40000, class_name="CsiTool")
    count, _, _ = ask("regf.root_key_value_count", "NTUSER-001.DAT", h, "int")
    names, _, _ = ask("regf.root_key_value_names", "NTUSER-001.DAT", h, "list")
    lw, _, _ = ask("regf.root_key_last_written", "NTUSER-001.DAT", h, "value")
    cls, _, _ = ask("regf.root_key_class_name", "NTUSER-001.DAT", h, "text")
    check("regf root key value count, names, class and last-written read UNSURE with the truth first",
          first(count) == "3" and first(names) == '["Version","InstallDate","Owner"]' and first(cls) == "CsiTool"
          and first(lw) == "131908078262288384" and not any(is_plain(x) for x in (count, names, lw, cls)),
          (count, names, lw, cls))

    empty = hive([], nsub=1)
    ec, _, _ = ask("regf.root_key_value_count", "NTUSER-001.DAT", empty, "int")
    en, _, _ = ask("regf.root_key_value_names", "NTUSER-001.DAT", empty, "list")
    check("a hive with no values: count 0 (unsure), names empty/absent and never plain",
          first(ec) == "0" and not is_plain(ec) and not is_plain(en) and (en is None or first(en) in ("[]", "null", "none")), (ec, en))

    dv = hive([("", 0), ("Real", 1)], default_value=True)   # one unnamed default value
    dn, _, _ = ask("regf.root_key_value_names", "NTUSER-001.DAT", dv, "list")
    check("an unnamed default value makes the name list ambiguous: never plain", not is_plain(dn), dn)

    not_hive = ask("regf.root_key_value_count", "x.bin", b"notaregf" + b"\x00" * 0x2000, "int")[0]
    check("regf dispatch: a file whose magic is not 'regf' is None", not_hive is None, not_hive)


def test_prefetch():
    for ver in (17, 23, 26, 30):
        p = prefetch(version=ver, vol_path="\\DEVICE\\HARDDISKVOLUME2", serial=0xCAFED00D, created=0x01D4A1B2C3D40000)
        vc, _, _ = ask("prefetch.volume_count", "CMD.EXE-001.pf", p, "int")
        vp, _, _ = ask("prefetch.volume_device_path", "CMD.EXE-001.pf", p, "text")
        vs, _, _ = ask("prefetch.volume_serial_number", "CMD.EXE-001.pf", p, "value")
        vt, _, _ = ask("prefetch.volume_creation_time", "CMD.EXE-001.pf", p, "value")
        ok = (first(vc) == "1" and first(vp) == "\\DEVICE\\HARDDISKVOLUME2" and first(vs) == "0xcafed00d"
              and first(vt) == "131908078262288384" and not any(is_plain(x) for x in (vc, vp, vs, vt)))
        check(f"prefetch v{ver} volume block: count, device path, serial and creation time read UNSURE, truth first", ok, (ver, vc, vp, vs, vt))

    mam, _, _ = ask("prefetch.volume_count", "C.pf", b"MAM\x04" + b"\x00" * 512, "int")
    check("a compressed (MAM) prefetch is not read: never plain, None", mam is None and not is_plain(mam), mam)
    unk, _, _ = ask("prefetch.volume_count", "C.pf", prefetch(version=15), "int")
    check("an unknown prefetch version is never plain", not is_plain(unk), unk)
    zero, _, _ = ask("prefetch.volume_count", "C.pf", prefetch(vol_count=0), "int")
    zp, _, _ = ask("prefetch.volume_device_path", "C.pf", prefetch(vol_count=0), "text")
    check("a prefetch with zero volumes: count 0 (unsure), device path absent and never plain",
          first(zero) == "0" and not is_plain(zp) and (zp is None or first(zp) == "none"), (zero, zp))
    not_pf = ask("prefetch.volume_count", "x.bin", b"\x1e\x00\x00\x00NOPE" + b"\x00" * 512, "int")[0]
    check("prefetch dispatch: no 'SCCA' signature is None", not_pf is None, not_pf)


def test_never_wrong_and_fast():
    samples = {
        "usn-v2": journal([usn_record("report.txt"), usn_record("b.log", usn=0x200)]),
        "usn-v3": journal([usn_record("v3.dat", major=3)]),
        "hive": hive([("Version", 1), ("Owner", 0)], nsub=2, class_name="Cls"),
        "prefetch": prefetch(),
    }
    props = ["usn.record_count", "usn.first_record_usn", "usn.first_record_file_name", "usn.first_record_timestamp",
             "regf.root_key_value_count", "regf.root_key_value_names", "regf.root_key_last_written",
             "prefetch.volume_count", "prefetch.volume_device_path", "prefetch.volume_serial_number"]
    rnd = random.Random(20261023)
    plain, raised, slow, n = [], [], [], 0
    for base, data in samples.items():
        variants = [("whole", data)]
        for _ in range(12):
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
    test_usn()
    test_regf()
    test_prefetch()
    test_never_wrong_and_fast()
    print()
    if FAILED:
        print(f"FAILED {len(FAILED)}:")
        for f in FAILED:
            print("  - " + f)
        sys.exit(1)
    print("all wave4 metadata-forensics checks passed")


if __name__ == "__main__":
    main()
