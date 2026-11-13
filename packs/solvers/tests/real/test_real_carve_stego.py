#!/usr/bin/env python3
"""The carve_stego toolkit on real artifacts: zsteg's sample pictures with zsteg's own expected output,
zbar's barcode examples with zbar's recorded output, dfvfs's small disk images against a 7-Zip listing,
rust-minidump's test dumps against its stackwalk snapshot, and two Huntress challenges (2025 'QRception',
2024 'Unbelievable').

  .venv/bin/python tests/real/test_real_carve_stego.py     the real-file groups SKIP when challenges/_realdata/carve_stego is absent

Offline; the cache is filled by tests/real/fetch_c.py. The truth of each file is in the manifest's `what`.
"""
import hashlib
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realdata_c as R  # noqa: E402

cs, ROOT = R.start("carve_stego")
check, q = R.check, R.q
FLAG_QR = "flag{e1487f138f885bfef64f07cdeac96908}"
PASSWORDS = b"place,user,password\nbank,joesmith,superrich\nalarm system,-,1234\ntreasure chest,-,1111\nuber secret laire,admin,admin\n"
A_FILE = b"This is a text file.\n\nWe should be able to parse it.\n"


# solve_set reads a set's files inside a wall-clock budget (cs.BUDGET, 1 s): a reading cut short by it
# leaves the answer None (unproven). On a loaded machine (the suite beside other jobs) the wall clock
# runs out before the work does, so a check of an answer must not depend on it (R-15: QRception was
# answered plain alone and None in the full run). The answers here are read with a budget load cannot
# use up, and the budget itself is checked as CPU time: one set's reading must fit in cs.BUDGET CPU
# seconds, which is what the deadline gives it on an idle machine. A reading that grows past it fails
# that check whatever the load.
UNLOADED_BUDGET = 120.0

# CPU time was not enough (SH-09): under the suite's sustained load this machine runs its cores at about
# half their top clock, so the same reading takes about twice the CPU seconds it takes on an idle machine
# (stg300.png's solve_set: 1.08 to 1.34 s of CPU against its 1 s, about 0.55 s of work). The limits are
# what the readings may cost on an idle machine, so they are checked as work at the core's top clock
# (tests/sh09_clocks.work_seconds: core cycles over the top clock), which a lower clock does not change.
sys.path.append(str(Path(__file__).resolve().parents[1]))       # last: tests/ shadows no toolkit module
import sh09_clocks  # noqa: E402


def timed(label, fn, *args, limit=R.LIMIT, **kw):
    """fn(*args) and a check that its work stayed under the limit, in seconds at the core's top clock.
    Without the work meter fn still runs (the group's answer checks still run), and the cost limit alone is
    reported as a SKIP line naming the missing meter (a SKIP fails the realdata run), never passed."""
    out, work, no_meter = sh09_clocks.work_seconds_unless_missing(fn, *args, **kw)
    if no_meter:
        print(f"SKIP {label}: cost limit {limit:g} s not checked: no work meter ({no_meter})")
        R.SKIPPED.append(f"{label} (cost limit: no work meter)")
        return out
    if work > limit:
        R.SLOW.append((label, round(work, 2)))
    check(f"{label}: {work:.2f} s of work (limit {limit:g} s)", work <= limit)
    return out


def solve(label, qs, files):
    return timed(f"solve_set on {label}", cs.solve_set, qs, files, {"carve_stego_budget": UNLOADED_BUDGET},
                 limit=cs.BUDGET)


def scan(rel, name=None):
    d = R.data(ROOT, rel)
    name = name or rel.rsplit("/", 1)[-1]
    return d, timed(f"scan of {rel} ({len(d)} bytes)", cs.scan, name, d)


def texts(found, channel=None):
    return [f["text"] for f in found if f["text"] and (channel is None or f["channel"] == channel)]


def png(w, h, raw, extra_in_idat=b"", ctype=2):
    def chunk(t, body):
        return struct.pack(">I", len(body)) + t + body + struct.pack(">I", zlib.crc32(t + body))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, ctype, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw) + extra_in_idat) + chunk(b"IEND", b""))


def bmp(w, h, rows):
    stride = (w * 3 + 3) & ~3
    body = b"".join(r.ljust(stride, b"\x00") for r in rows)
    return b"BM" + struct.pack("<IHHI", 54 + len(body), 0, 0, 54) + struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(body), 2835, 2835, 0, 0) + body


def built_in_memory():
    """What the real files changed, on pictures and disks built here: these run with no cache."""
    rows = b"".join(b"\x00" + bytes([40, 80, 120]) * 4 for _ in range(4))
    found = cs.scan("a.png", png(4, 4, rows + b"after-rows-secret", b"after-zlib-secret"))
    got = {f["method"].split(" bytes ")[-1]: f["text"] for f in found if f["channel"] == "png_chunk"}
    check("a PNG's IDAT: bytes after the last scanline and after the zlib stream are findings",
          got == {"after the last scanline": "after-rows-secret", "after the zlib stream": "after-zlib-secret"}, got)
    check("a clean PNG has no such finding", not [f for f in cs.scan("b.png", png(4, 4, rows)) if f["channel"] == "png_chunk"])
    text = b"Look, the pixel bytes are words: key=swordfish!!"
    found = cs.scan("t.bmp", bmp(4, 4, [text[i:i + 12] for i in range(0, 48, 12)]))
    check("a BMP whose pixel bytes are text", text.decode() in texts(found, "lsb"), texts(found))
    # bit 1 of every stored byte, the two padding bytes of each 10-byte row included (w=3: 9 bytes + 1... use w=2: 6 + 2)
    msg = b"padding-carries-bits-too\x00"
    bits = "".join(f"{c:08b}"[::-1] for c in msg)
    flat = bytearray(b"\x80" * (8 * ((len(bits) + 7) // 8)))
    for i, b in enumerate(bits):
        flat[i] = 0x80 | (int(b) << 1)
    rows_ = [bytes(flat[i:i + 8]) for i in range(0, len(flat), 8)]
    w, h = 2, len(rows_)
    body = b"".join(rows_)
    pic = b"BM" + struct.pack("<IHHI", 54 + len(body), 0, 0, 54) + struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(body), 2835, 2835, 0, 0) + body
    found = cs.scan("p.bmp", pic)
    check("LSB text that runs through a BMP's row padding is read whole", "padding-carries-bits-too" in texts(found, "lsb"), texts(found))
    try:
        import qrcode
        import io
        img = qrcode.make("line one\nline two\x1b[0m end", box_size=4)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        got = cs.decode_codes(buf.getvalue())
        check("a QR payload with a line break and an escape comes back as written, not as '<LF>' and '<ESC>'",
              [g["text"] for g in got] == ["line one\nline two\x1b[0m end"], got)
        code = qrcode.QRCode(border=2)
        code.add_data("half-block-payload")
        code.make()
        m = code.get_matrix()
        if len(m) % 2:
            m.append([False] * len(m[0]))
        # white on black, as `qrencode -t ANSIUTF8` prints it: a full block is a LIGHT module
        glyph = {(False, False): "█", (True, True): " ", (False, True): "▀", (True, False): "▄"}
        ansi = "\n".join("\x1b[40;37;1m" + "".join(glyph[(m[y][x], m[y + 1][x])] for x in range(len(m[0]))) + "\x1b[0m" for y in range(0, len(m), 2))
        got = cs.decode_grid(ansi)
        check("a QR printed in half blocks under one ANSI colour pair is read (two rows a line, either colour dark)",
              [g["text"] for g in got] == ["half-block-payload"], got)
        sig = cs.signals([q("f", "What is the flag?")], {"picture.png": buf.getvalue()})
        check("a picture that is a QR code signals 0.5 with no channel word in the question", sig >= 0.5, sig)
    except ImportError:
        print("SKIP the QR checks built here: qrcode is not installed")
    check("a PNG named .mp3 signals 0.3 (a disguise), a PNG named .png 0.1",
          cs.signals([q("f", "What is the flag?")], {"song.mp3": png(4, 4, rows)}) == 0.3
          and cs.signals([q("f", "What is the flag?")], {"song.png": png(4, 4, rows)}) == 0.1)
    disk = bytearray(4096)
    disk[446:462] = struct.pack("<BBBBBBBBII", 0, 0, 2, 0, 0x83, 0, 0, 0, 2, 4)
    disk[462:478] = struct.pack("<BBBBBBBBII", 0, 0, 0, 0, 0x0C, 0, 0, 0, 6, 2)
    disk[510:512] = b"\x55\xaa"
    table = cs.fs.partitions(bytes(disk))
    check("an MBR table: two partitions with their types, offsets and sizes",
          table == {"scheme": "mbr", "parts": [{"index": 1, "type": 0x83, "type_name": "linux", "start": 1024, "size": 2048, "name": None},
                                               {"index": 2, "type": 0x0C, "type_name": "fat32", "start": 3072, "size": 1024, "name": None}]}, table)
    check("a FAT boot sector and plain text ending 55 AA are no partition table",
          cs.fs.partitions(b"\xeb\x3c\x90" + b"x" * 507 + b"\x55\xaa" + bytes(512)) is None)


def qrception():
    d, found = scan("huntress/qrception.png")
    codes = [f for f in found if f["channel"] == "code"]
    check("QRception: the QR in the QR (drawn in ANSI half blocks) is followed to the write-up's flag",
          [c["text"].strip() for c in codes] == [FLAG_QR], [c["text"][:60] for c in codes])
    qs = [q("qr", "What does the QR code say?"), q("flag", "What is the hidden flag?", pattern=r"^flag\{[0-9a-f]{32}\}$"), q("n", "What is the flag?")]
    got = solve("qrception.png", qs, {"qrception.png": d})
    check("QRception: 'what does the QR code say' and a flag with a pattern are answered plain", got["qr"] == FLAG_QR and got["flag"] == FLAG_QR, got)
    check("QRception: a question with no channel word and no pattern is not answered", got["n"] is None, got["n"])
    dr = R.drill({"qrception.png": d}, [q("flag", "What is the flag?")])
    check("QRception, end to end: the triage map ranks carve_stego first for the bare picture", dr["winner"] == "carve_stego", dr["rank"])


def unbelievable():
    d, found = scan("huntress/Half-Life_3_OST.mp3")
    check("Unbelievable: the .mp3 is read as the PNG it is (800x200)", cs.sniff(d) == "png" and struct.unpack(">II", d[16:24]) == (800, 200))
    check("Unbelievable: nothing is hidden in its structure (the flag is drawn text: OCR is agent work)", found == [], found[:2])
    check("Unbelievable: the disguise raises the signal to 0.3, under the match threshold", cs.signals([q("f", "What is the flag?")], {"Half-Life_3_OST.mp3": d}) == 0.3)


def zsteg_pictures():
    d, found = scan("zsteg/extradata.png")
    got = sorted(t for t in texts(found) if t.startswith("foobar"))
    check("extradata.png: foobar1, foobar2 and foobar3", got == ["foobar1", "foobar2", "foobar3"], [(f["channel"], f["method"], f["text"]) for f in found])
    d, found = scan("zsteg/Code.png")
    check("Code.png: the iTXt comment", "QkJCQjIAAACR2PFtcCA6q2eaC8SR+8dmD/zNzLQC+td3tFQ4qx8O447TDeuZw5P+0SsbEcYR\n78jKLw==" in texts(found, "png_text"), texts(found))
    got = solve("Code.png", [q("c", "What is the comment in the PNG's text chunk?")], {"Code.png": d})
    check("Code.png: 'the comment' is answered (the base64 as written; a line break inside makes it unsure or None, never a cut value)",
          got["c"] is None or R.offers(got["c"], "QkJCQjIAAACR2PFtcCA6q2eaC8SR+8dmD/zNzLQC+td3tFQ4qx8O447TDeuZw5P+0SsbEcYR\n78jKLw=="), got)
    d, found = scan("zsteg/stg300.png")
    check("stg300.png: Congrats and the flag in the LSB text", any("Congrats" in t and "4E34B38257200616FB75CD869B8C3CF0" in t for t in texts(found, "lsb")), texts(found)[:2])
    got = solve("stg300.png", [q("f", "What is the flag hidden in the least significant bits?", pattern="^[0-9A-F]{32}$")], {"stg300.png": d})
    check("stg300.png: the flag by its pattern", got["f"] == "4E34B38257200616FB75CD869B8C3CF0", got)
    d, found = scan("zsteg/06_enc.png")
    check("06_enc.png: Lorem ipsum in the LSBs", any(t.startswith("Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod") for t in texts(found, "lsb")))
    d, found = scan("zsteg/cats.png")
    allt = "\n".join(texts(found))
    check("cats.png: the four texts zsteg finds",
          all(s in allt for s in ("Second cat is Marussia", "Hello, third kitten is Bessy", "Fourth and last cat is Luke", "Good, but look a bit deeper...")),
          [t[:60] for t in texts(found)])
    d, found = scan("zsteg/square.bmp")
    check("square.bmp: thesecretpasswordis:jedimaster, whole, and not also its cut first row", texts(found, "lsb") == ["thesecretpasswordis:jedimaster"], texts(found))
    d, found = scan("zsteg/crypt.bmp")
    check("crypt.bmp: 111Hello", any(t.startswith("111Hello") for t in texts(found, "lsb")), texts(found))
    d, found = scan("zsteg/stegano1.bmp")
    check("stegano1.bmp: the pixel bytes are the text", texts(found, "lsb") == ["Look what the hex-edit revealed: passwd:steganoI"], texts(found))
    d, found = scan("zsteg/plte1.png")
    zips = [f for f in found if f["channel"] == "carved" and f["kind"] == "zip"]
    plte = [c["data"] for c in cs.png_chunks(d) if c["type"] == "PLTE"]
    check("plte1.png: the PLTE chunk is zsteg's zip (md5 e125f0f3...), carved as a zip by its own end record, its one member read",
          len(zips) == 1 and hashlib.md5(plte[0]).hexdigest() == "e125f0f322fd1e99050dba688968385c" and plte[0].startswith(zips[0]["data"])
          and [f["text"] for f in found if f["channel"] == "member"] == ["<?php $_GET['a']($_GET['b']);?>\r\n"],
          [(f["channel"], f["method"], f["text"]) for f in found])
    d, found = scan("zsteg/flower_rgb1.png")
    check("flower_rgb1.png: SuperSecretMessage", "SuperSecretMessage" in texts(found, "lsb"), texts(found))
    got = solve("flower_rgb1.png", [q("m", "What is the hidden message in the image?")], {"flower_rgb1.png": d})
    check("flower_rgb1.png: a hidden message with no pattern is unsure, the text offered", not R.plain(got["m"]) and R.offers(got["m"], "SuperSecretMessage"), got)
    d, found = scan("zsteg/flower_rgb2.png")
    check("flower_rgb2.png: the same message at two bits a sample", "SuperSecretMessage" in texts(found, "lsb"), texts(found))
    d, found = scan("zsteg/flower_rgb3.png")
    check("flower_rgb3.png: three bits a sample is not read, and nothing is made up", texts(found, "lsb") == [], texts(found))
    d, found = scan("zsteg/flower.png")
    check("flower.png (the cover): no finding", found == [], [(f["channel"], f["method"]) for f in found])
    got = solve("flower.png", [q("m", "What is the hidden message in the image?")], {"flower.png": d})
    check("flower.png: nothing hidden, nothing answered", got == {"m": None}, got)


def zbar_codes():
    for rel, kind, sym, want in (("zbar/code-128.png", "code128", "CODE-128", "cc53bf34878f769fc3611020c11e572f2853bd2a"),
                                 ("zbar/code-39.png", "code39", "CODE-39", "7537d593ea42393a43bc0eda0a896c0e31017dd8"),
                                 ("zbar/ean-13.png", "ean13", "EAN-13", "53429fc04dfcf674349e2db6cfbaf73e301fc3dc"),
                                 ("zbar/ean-8.png", "ean8", "EAN-8", "4095418b74efbb026dd730543558fefdda46f5b9"),
                                 ("zbar/i2-5.png", "itf", "I2/5", "5501245dbba21c153f690787fc97ab50c973b846"),
                                 ("zbar/databar.png", "databaromni", "DataBar", "aebbdbed0b32d7fd72f1245e3fb384822d492062"),
                                 ("zbar/qr-code.png", "qrcode", "QR-Code", "b350ca7efad7a50c5ac082d5c683a8e8d8d380a7")):
        d, found = scan(rel)
        codes = [f for f in found if f["channel"] == "code"]
        line = f"{sym}:{codes[0]['text']}\n" if len(codes) == 1 else ""
        check(f"{rel}: one {kind} whose text gives zbar's recorded sha1", len(codes) == 1 and hashlib.sha1(line.encode()).hexdigest() == want,
              [(c["kind"], c["text"]) for c in codes])
    d, found = scan("zbar/qr-code-inverted.png")
    check("qr-code-inverted.png: the light-on-dark QR reads the same", [f["text"] for f in found if f["channel"] == "code"] == ["https://github.com/mchehab/zbar"])
    got = solve("qr-code.png", [q("u", "What URL does the QR code hold?"), q("t", "What type of barcode is in the image?")], {"qr-code.png": R.data(ROOT, "zbar/qr-code.png")})
    check("qr-code.png: the URL plain, the type a label (unsure)", got["u"] == "https://github.com/mchehab/zbar" and not R.plain(got["t"]), got)


def disks():
    for rel, kind in (("dfvfs/fat12.raw", "fat12"), ("dfvfs/ext2.raw", "ext"), ("dfvfs/ext4.raw", "ext"), ("dfvfs/iso9660.raw", "iso9660")):
        d, found = scan(rel)
        files = {f["name"].lower(): f["data"] for f in found if f["channel"] == "fs" and not f.get("is_dir")}
        check(f"{rel}: the three files of the 7-Zip listing, byte for byte",
              files.get("passwords.txt") == PASSWORDS and files.get("a_directory/a_file") == A_FILE and files.get("a_directory/another_file") == b"This is another file.\n",
              sorted(files))
        got = solve(rel, [q("h", "What is the SHA-256 of passwords.txt on the disk image?"),
                          q("m", "What is the MD5 of a_file in the file system?"),
                          q("x", "What is the SHA-256 of secrets.txt on the disk image?")], {"disk.img": d})
        check(f"{rel}: the hash of a file the question names is plain; a name the image does not hold is None",
              got["h"] == hashlib.sha256(PASSWORDS).hexdigest() and got["m"] == hashlib.md5(A_FILE).hexdigest() and got["x"] is None, got)
    d, found = scan("dfvfs/mbr.raw")
    parts = [(f["name"], f["offset"], f["size"], f["kind"]) for f in found if f.get("partition")]
    check("mbr.raw: the primary and the logical partition 7-Zip lists (66048 bytes each), both ext, and the extended container",
          parts == [("partition1", 0x200, 66048, "ext"), ("partition2", 0x10400, 4127744, None), ("partition5", 0x10600, 66048, "ext")], parts)
    inner = [f for f in found if f["channel"] == "fs" and f["name"] == "passwords.txt"]
    check("mbr.raw: passwords.txt is read out of both partitions", len(inner) == 2 and all(f["data"] == PASSWORDS for f in inner), len(inner))
    got = solve("mbr.raw", [q("h", "What is the SHA-256 of passwords.txt on the disk image?")], {"disk.raw": d})
    check("mbr.raw: the two copies are the same bytes, so its hash is one fact", got["h"] == hashlib.sha256(PASSWORDS).hexdigest(), got)
    d, found = scan("dfvfs/ntfs.raw")
    check("ntfs.raw: named as NTFS and NOT READ, with the sandbox command; no entry is invented",
          len(found) == 1 and found[0]["kind"] == "ntfs" and "NOT READ" in found[0]["method"] and "sandbox.py" in found[0]["method"], found)
    got = solve("ntfs.raw", [q("n", "How many files are on the disk image?"), q("h", "What is the SHA-256 of passwords.txt on the disk image?")], {"disk.raw": d})
    check("ntfs.raw: a volume that was not read answers nothing", got == {"n": None, "h": None}, got)
    for rel in ("dfvfs/syslog.newc.cpio", "dfvfs/syslog.bin.cpio"):
        d, found = scan(rel)
        files = [(f["name"], len(f["data"])) for f in found if f["channel"] == "fs" and not f.get("is_dir")]
        check(f"{rel}: one member, syslog, 1247 bytes", files == [("syslog", 1247)], files)


def minidumps():
    d, found = scan("minidump/test.dmp")
    info = [f for f in found if f["channel"] == "dump"][0]["info"]
    names = [str(m.get("name") or "") for m in info.get("modules", [])]
    check("test.dmp: 13 modules and 2 threads, the first module test_app.exe (the stackwalk snapshot)",
          len(names) == 13 and len(info.get("threads", [])) == 2 and names[0].lower().endswith("test_app.exe"), (len(names), names[:2]))
    got = solve("test.dmp", [q("m", "How many modules does the minidump list?"), q("t", "How many threads are in the minidump?")], {"crash.dmp": d})
    check("test.dmp: both counts plain", got == {"m": "13", "t": "2"}, got)
    d, found = scan("minidump/linux-mini.dmp")
    check("linux-mini.dmp: read as a minidump", [f["kind"] for f in found if f["channel"] == "dump"] == ["minidump"], [(f["channel"], f["method"]) for f in found])


if __name__ == "__main__":      # run as a script (tests/real/conftest.py); tests/sh09_drivers.py imports it
    for fn in (built_in_memory, qrception, unbelievable, zsteg_pictures, zbar_codes, disks, minidumps):
        R.section(fn)
    sys.exit(R.finish("test_real_carve_stego"))
