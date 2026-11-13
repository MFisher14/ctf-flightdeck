#!/usr/bin/env python3
"""Focused tests for readers_lookahead22.py (the Day 22 Metadata look-ahead pack).

Lives beside the pack (the build's area is solvers/metadata-forensics/ only). Run it with:
    .venv/bin/python -I solvers/metadata-forensics/test_lookahead22.py
It uses no network and no Game Master. It proves, through the REAL solver (properties_strict.solve_set),
that:
  1. the pack is wired into MORE_FILES and loads (MORE_LOADED lists it; 18 names, no clash on them);
  2. each new name on its RIGHT container is UNSURE (labels.pick), with the truth among the options, and
     is never a plain answer;
  3. each new name on a WRONG container is None (M.Unknown), never a wrong-type 'none';
  4. a genuinely-absent field in the right container is the unsure `none` (not plain, not a crash);
  5. the pack changes NOTHING a reader already answered: with the pack renamed aside (baseline), every
     new name was None on every specimen, and a battery of existing names answers identically with and
     without the pack. So every change is None -> unsure, for the new names only.
"""
import contextlib
import importlib.util
import io
import json
import os
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "solvers" / "common"))
import labels  # noqa: E402

PACK = HERE / "readers_lookahead22.py"
DELIVERY = "metadata-day-22-evidence.zip"
TEXT = {"kind": "exact_text", "syntax": "exact artifact-derived value only; use the literal none only "
        "when the requested field is absent"}
INT = {"kind": "integer", "syntax": "base-10 integer with no units or explanatory text"}
HEX = {"kind": "pattern", "syntax": "lowercase hexadecimal with no explanatory text"}
JSON = {"kind": "json", "syntax": "compact valid JSON array with exact values and order"}

FAIL = []


def check(ok, msg):
    print(("PASS " if ok else "FAIL ") + msg)
    if not ok:
        FAIL.append(msg)


# ------------------------------------------------------------------ driving one question through the solver

def load_solver():
    """A fresh properties_strict module instance (its import runs _load_more, so the pack is loaded or
    not depending on whether its file is present)."""
    spec = importlib.util.spec_from_file_location("ps_t22_" + str(id(object())), HERE / "properties_strict.py")
    mod = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stderr(io.StringIO()):
        spec.loader.exec_module(mod)
    return mod


def ask(solver, name, member, data, fmt=TEXT, aid=None):
    """The solver's answer for a `Determine <name> for <member>.` question whose delivery holds member."""
    aid = aid or ("d22-" + name.replace(".", "-").replace("_", "-"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(member, data)
    blob = buf.getvalue()
    q = {"id": aid, "qid": aid, "answer_id": aid, "question": f"Determine {name} for {member}.",
         "artifact": f"{DELIVERY} -> {member}", "answer_format": fmt, "normalization": "trim"}
    ctx = {"set": 1, "delivery_name": DELIVERY, "delivery": blob, "attempt": {}, "partial": {}}
    with contextlib.redirect_stderr(io.StringIO()):
        return solver.solve_set([q], {DELIVERY: blob, member: data}, ctx)[aid]


def is_plain(v):
    return v is not None and not labels.is_unsure(v)


def unsure_has(v, truth):
    if not labels.is_unsure(v):
        return False
    u = labels.parse(v)
    if u is None:
        return False
    want = {str(truth)}
    if isinstance(truth, (list, tuple)):   # a JSON list is offered as compact JSON text ("[4,3]")
        want.add(json.dumps(truth, separators=(",", ":")))
    return bool(want & {str(val) for _, val in u.options})


# ------------------------------------------------------------------ specimens

def msg_cfb(streams):
    """A version-3 compound file (.msg) whose top-level streams are [(name, bytes)] (a trimmed copy of
    the builder in tests/test_day13_metadata_msi.py; CLSID is arbitrary for a .msg)."""
    END, FREE, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF
    ss, ms, cutoff = 512, 64, 4096
    sec = lambda n, size: -(-n // size)   # noqa: E731
    mini_fat, mini, where = [], b"", []
    for _, body in streams:
        if len(body) < cutoff:
            n = sec(len(body), ms)
            where.append(len(mini_fat) if n else END)
            mini_fat += list(range(len(mini_fat) + 1, len(mini_fat) + n)) + [END] if n else []
            mini += body.ljust(n * ms, b"\x00")
        else:
            where.append(None)
    dir_sectors = sec(len(streams) + 1, 4)
    mini_fat_sectors = sec(len(mini_fat) * 4, ss)
    mini_sectors = sec(len(mini), ss)
    fat = list(range(1, dir_sectors)) + [END]
    at = dir_sectors
    first_mini_fat = at if mini_fat_sectors else END
    fat += list(range(at + 1, at + mini_fat_sectors)) + [END] if mini_fat_sectors else []
    at += mini_fat_sectors
    first_mini = at if mini_sectors else END
    fat += list(range(at + 1, at + mini_sectors)) + [END] if mini_sectors else []
    at += mini_sectors
    large = b""
    for i, (_, body) in enumerate(streams):
        if where[i] is None:
            n = sec(len(body), ss)
            where[i] = at
            fat += list(range(at + 1, at + n)) + [END]
            at += n
            large += body.ljust(n * ss, b"\x00")
    fat_sectors = 1
    while fat_sectors * (ss // 4) < at + fat_sectors:
        fat_sectors += 1
    fat += [FATSECT] * fat_sectors + [FREE] * (fat_sectors * (ss // 4) - len(fat) - fat_sectors)

    def entry(name, kind, right, child, start, size, cls=b"\x00" * 16):
        raw = (name + "\x00").encode("utf-16-le")
        return (raw.ljust(64, b"\x00") + struct.pack("<HBBIII", len(raw), kind, 1, NOSTREAM, right, child) + cls
                + struct.pack("<I8s8sIII", 0, b"", b"", start, size, 0))
    directory = entry("Root Entry", 5, NOSTREAM, 1 if streams else NOSTREAM, first_mini, len(mini))
    for i, (name, body) in enumerate(streams):
        directory += entry(name, 2, i + 2 if i + 1 < len(streams) else NOSTREAM, NOSTREAM, where[i], len(body))
    directory = directory.ljust(dir_sectors * ss, b"\x00")
    header = (bytes.fromhex("d0cf11e0a1b11ae1") + b"\x00" * 16 + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\x00" * 6
              + struct.pack("<IIIIIIIII", 0, fat_sectors, 0, 0, cutoff, first_mini_fat, mini_fat_sectors, END, 0)
              + struct.pack("<109I", *([at + i for i in range(fat_sectors)] + [FREE] * (109 - fat_sectors))))
    mini_fat_bytes = struct.pack(f"<{len(mini_fat)}I", *mini_fat).ljust(mini_fat_sectors * ss, b"\xff")
    return header + directory + mini_fat_bytes + mini.ljust(mini_sectors * ss, b"\x00") + large + struct.pack(f"<{len(fat)}I", *fat)


def make_pe(subsystem=2):
    """A minimal PE32 image whose IMAGE_OPTIONAL_HEADER.Subsystem is `subsystem` (offset 68)."""
    opt = bytearray(96)
    struct.pack_into("<H", opt, 0, 0x10B)   # PE32 magic
    struct.pack_into("<H", opt, 68, subsystem)
    coff = struct.pack("<HHIIIHH", 0x14C, 0, 0, 0, 0, len(opt), 0x0102)   # i386, SizeOfOptionalHeader, exe
    pe = b"PE\x00\x00" + coff + bytes(opt)
    head = bytearray(0x80)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x80)
    return bytes(head) + pe


def make_go():
    inner = b"path\tgithub.com/acme/tool\nmod\tgithub.com/acme/tool\tv1.4.2\th1:abc=\n"
    mod = b"\x00" * 16 + inner + b"\x00" * 16   # mod[len-17] is inner's last byte '\n', so the strip triggers
    vers = b"go1.21.3"

    def leb(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)
    blob = b"\xff Go buildinf:" + b"\x08\x02" + b"\x00" * 16 + leb(len(vers)) + vers + leb(len(mod)) + mod
    return b"\x7fELF" + b"\x00" * 60 + blob + b"\x00" * 16


def make_rar4():
    marker = b"Rar!\x1a\x07\x00"
    main = struct.pack("<HBHH", 0xCF90, 0x73, 0, 13) + b"\x00" * 6   # CRC=0xcf90, type MAIN, flags, size
    return marker + main


def make_rar5():
    return b"Rar!\x1a\x07\x01\x00" + struct.pack("<I", 0x12345678) + b"\x0b" + b"\x00" * 16


def make_ar():
    def hdr(name, mtime, uid, gid, mode_octal, size):
        return (name.ljust(16).encode() + str(mtime).ljust(12).encode() + str(uid).ljust(6).encode()
                + str(gid).ljust(6).encode() + mode_octal.ljust(8).encode() + str(size).ljust(10).encode() + b"`\n")
    m1 = hdr("foo.o/", 1700000000, 1000, 1000, "100644", 4) + b"ABCD"
    m2 = hdr("bar.txt/", 1700000001, 0, 0, "100755", 3) + b"xyz" + b"\n"   # odd size -> 1 pad byte
    return b"!<arch>\n" + m1 + m2


def make_ttcf():
    return b"ttcf" + struct.pack(">HHI", 1, 0, 2) + struct.pack(">II", 100, 200)


NOT_A_CONTAINER = b"this is just some plain text, not any binary container at all.\n" * 4
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 13 + b"\x00\x00\x00\x00"


def main():
    # 1. wiring
    s = load_solver()
    loaded = s.MORE_LOADED.get("readers_lookahead22.py")
    check(loaded == (18, 0), f"pack is in MORE_LOADED with (18,0); got {loaded}")
    mine = [k for k in s.REG if s.REG[k].fn.__module__ and "lookahead22" in str(getattr(s.REG[k].fn, "__module__", ""))]
    # a reader's __module__ is the dynamic name; fall back to checking the 18 names by hand
    new_names = [
        "mbox.message_count", "msg.subject", "msg.message_id", "msg.sender_email", "msg.message_class",
        "pe.subsystem_name", "go.build_version", "go.main_module_path", "go.main_module_version",
        "rar.main_header_crc", "rar.archive_header_crc", "ar.member_sizes_bytes", "ar.member_uids",
        "ar.member_gids", "ar.member_modes", "ttc.font_count", "ttc.major_version", "ttc.minor_version"]
    check(all(s.canon(n) in s.REG and not s.REG[s.canon(n)].confirmed for n in new_names),
          "all 18 new names are registered and unconfirmed (never plain)")
    check(not any(c in new_names for c in s.MORE_CLASHES), "no new name clashed with an existing reader")
    # new namespaces do not collide with an existing registered name's prefix
    for ns in ("mbox", "msg", "go", "ttc"):
        pre = ns + "_"
        # only this pack's names may start with the prefix
        owners = [k for k in s.REG if k.startswith(pre)]
        check(all(s.dotted(k) in new_names for k in owners),
              f"namespace {ns}: only new names use the prefix ({[s.dotted(k) for k in owners]})")

    # 2 + 3 + 4: each reader on right / wrong container / absent field
    pe, go, rar4, rar5, ar, ttc = make_pe(2), make_go(), make_rar4(), make_rar5(), make_ar(), make_ttcf()
    mbox = (b"From a@x Sat Oct 17 08:01:00 2026\r\nSubject: one\r\n\r\nhi\r\n"
            b"From b@y Sat Oct 17 08:02:00 2026\r\nSubject: two\r\n\r\nyo\r\n")
    msg = msg_cfb([("__substg1.0_0037001F", "Quarterly report".encode("utf-16-le")),
                   ("__substg1.0_1035001F", "<abc123@acme.example>".encode("utf-16-le")),
                   ("__substg1.0_0C1F001F", "sender@acme.example".encode("utf-16-le")),
                   ("__substg1.0_001A001F", "IPM.Note".encode("utf-16-le"))])
    msg_no_subject = msg_cfb([("__substg1.0_001A001F", "IPM.Note".encode("utf-16-le"))])

    right = [
        ("mbox.message_count", "mail.mbox", mbox, INT, 2),
        ("msg.subject", "mail.msg", msg, TEXT, "Quarterly report"),
        ("msg.message_id", "mail.msg", msg, TEXT, "<abc123@acme.example>"),
        ("msg.sender_email", "mail.msg", msg, TEXT, "sender@acme.example"),
        ("msg.message_class", "mail.msg", msg, TEXT, "IPM.Note"),
        ("pe.subsystem_name", "app.exe", pe, TEXT, "WINDOWS_GUI"),
        ("go.build_version", "tool.bin", go, TEXT, "go1.21.3"),
        ("go.main_module_path", "tool.bin", go, TEXT, "github.com/acme/tool"),
        ("go.main_module_version", "tool.bin", go, TEXT, "v1.4.2"),
        ("rar.main_header_crc_hex", "arc.rar", rar4, HEX, "cf90"),
        ("rar.main_header_crc_hex", "arc5.rar", rar5, HEX, "12345678"),
        ("ar.member_sizes_bytes", "lib.a", ar, JSON, [4, 3]),
        ("ar.member_uids", "lib.a", ar, JSON, [1000, 0]),
        ("ar.member_gids", "lib.a", ar, JSON, [1000, 0]),
        ("ar.member_modes", "lib.a", ar, JSON, [0o100644, 0o100755]),
        ("ttc.font_count", "fonts.ttc", ttc, INT, 2),
        ("ttc.major_version", "fonts.ttc", ttc, INT, 1),
        ("ttc.minor_version", "fonts.ttc", ttc, INT, 0),
    ]
    for name, member, data, fmt, truth in right:
        v = ask(s, name, member, data, fmt)
        check(not is_plain(v), f"{name} on its container is NEVER plain (got {v!r})")
        check(unsure_has(v, truth), f"{name} on its container is unsure with truth {truth!r} offered (got {v!r})")

    # wrong container -> None (M.Unknown), never a wrong-type 'none'
    wrong = [
        ("mbox.message_count", "x.bin", NOT_A_CONTAINER, INT),
        ("msg.subject", "x.png", PNG, TEXT),
        ("pe.subsystem_name", "x.txt", NOT_A_CONTAINER, TEXT),
        ("go.build_version", "x.txt", NOT_A_CONTAINER, TEXT),
        ("rar.main_header_crc_hex", "x.bin", pe, HEX),
        ("ar.member_sizes_bytes", "x.bin", NOT_A_CONTAINER, JSON),
        ("ttc.font_count", "x.ttf", b"\x00\x01\x00\x00" + b"\x00" * 40, INT),
    ]
    for name, member, data, fmt in wrong:
        v = ask(s, name, member, data, fmt)
        check(v is None, f"{name} on a WRONG container is None, not a wrong-type 'none' (got {v!r})")

    # absent field in the right container -> the unsure `none` (not plain, not a crash)
    v = ask(s, "msg.subject", "mail.msg", msg_no_subject, TEXT)
    check(not is_plain(v) and v is not None and labels.is_unsure(v),
          f"msg.subject absent in a real .msg is the unsure `none` (got {v!r})")

    # 5. baseline: without the pack, every new name was None on every specimen; existing names unchanged.
    specimens = {"mail.mbox": mbox, "mail.msg": msg, "app.exe": pe, "tool.bin": go, "arc.rar": rar4,
                 "lib.a": ar, "fonts.ttc": ttc, "x.png": PNG, "x.txt": NOT_A_CONTAINER}
    probe_new = [(n, m, (JSON if n.startswith("ar.") else TEXT)) for n in new_names for m in specimens]
    # a battery of existing names that must answer identically with and without the pack
    existing = ["pe.subsystem", "pe.coff_machine_u16_hex", "pe.machine", "elf.e_machine_u16_hex", "elf.class",
                "png.ihdr_dimensions_pixels", "png.text_chunk_count", "ar.member_names", "ar.member_count",
                "zip.central_directory_member_names", "file.size_bytes", "magic.prefix_hex_8", "rar.file_count",
                "ole.header_major_version", "tiff.image_width"]
    probe_existing = [(n, m, TEXT) for n in existing for m in specimens]

    with_pack = {(n, m): ask(s, n, m, specimens[m], f) for n, m, f in probe_new + probe_existing}

    off = PACK.with_suffix(".py.off")
    PACK.rename(off)
    try:
        base = load_solver()
        check(base.MORE_LOADED.get("readers_lookahead22.py") is None, "baseline solver loads WITHOUT the pack")
        without = {(n, m): ask(base, n, m, specimens[m], f) for n, m, f in probe_new + probe_existing}
    finally:
        off.rename(PACK)

    for n, m, _f in probe_new:
        check(without[(n, m)] is None, f"baseline (no pack): {n} on {m} was None (change is only None->unsure)")
    changed = [(n, m, without[(n, m)], with_pack[(n, m)]) for n, m, _f in probe_existing
               if without[(n, m)] != with_pack[(n, m)]]
    check(not changed, f"existing names answer identically with and without the pack ({changed[:4]})")

    print()
    if FAIL:
        print(f"FAILED: {len(FAIL)} check(s)")
        for m in FAIL:
            print("  - " + m)
        sys.exit(1)
    print("ALL PASS")


if __name__ == "__main__":
    main()
