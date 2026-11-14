#!/usr/bin/env python3
"""Script lane, round 2 (2026-10-08): binary carriers read as containers (solvers/script-analysis/carriers.py).

    .venv/bin/python tests/test_script_carriers.py        (offline, about 5 s; exit 0 = every check passes)

Every fixture is built here, from the formats' own layouts; nothing is downloaded and nothing is run.

  chm       an ITSF file whose script is stored (section 0), and one whose script is in the MSCompressed
            section: as an uncompressed LZX block over three frames and two resets, and as a verbatim block
            (pretree, main tree, literals and matches written by the small encoder below)
  one       a OneNote section with two FileDataStoreObjects (a picture and an .hta), padded as OneNote pads
  lnk       a shell link whose command-line arguments hold the script, counted UTF-16
  au3       a compiled AutoIt script: an EA06 container around tokens assembled here (the package's own
            keystream; autoit-ripper is pinned in requirements.in, so its absence fails)
  the lane  each of them through analyze.solve_set: every field of the plan plain, the last one too (as the
            strings of the same file it is left out); two inner scripts with two plans answer nothing
  bounds    a damaged container, an LZX stream that does not decode and a deadline in the past give no
            reading and raise nothing
  corpus    when $SCRIPT_B_CORPUS names a folder of real .chm files with a 7-Zip extraction beside each
            (<name>.chm and <name>.chm.out/), every file this reader gives is byte for byte 7-Zip's.
            Without it, pytest reports test_corpus as skipped (not run).
            (2026-10-08: Apache Tika's testChm.chm, testChm2.chm, testChm3.chm: 72, 198 and 199 files.)

The decoder was checked against 7-Zip on real help files (the corpus line); the encoder here is this
file's own and only keeps the decoder's reading of its blocks from changing.
"""
import base64
import contextlib
import io
import os
import shutil
import struct
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "script-analysis"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
import analyze  # noqa: E402
import carriers  # noqa: E402

# ---------------------------------------------------------------------------- the scratch environment
# Carried from tests/test_script_review.py (archived with the Huntress day data): an empty challenges
# folder with a ledger under a tempdir, a platform URL that refuses, and no rehearsal knobs. It is set
# around each test (pytest) or around main() (a direct run) and restored after, so nothing leaks into
# other tests in the same process and nothing is written to a real challenges folder.
_SCRATCH_SET = ("CTF_WORKDIR", "CTF_WORKDIR", "CTF_PLATFORM_URL")
_SCRATCH_POP = ("ONLY", "CTF_TESTING", "CTF_LEDGER_MASK", "CTF_HIDE", "CTF_TESTING", "CTF_LEDGER_MASK")


@contextlib.contextmanager
def scratch_env():
    tmp = Path(tempfile.mkdtemp(prefix="test_script_carriers_"))
    (tmp / "challenges" / "_ledger").mkdir(parents=True)
    saved = {k: os.environ.get(k) for k in _SCRATCH_SET + _SCRATCH_POP}
    os.environ["CTF_WORKDIR"] = str(tmp / "challenges")
    os.environ["CTF_WORKDIR"] = str(tmp / "challenges")    # still read by proposer_* in solvers/common
    os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"          # nothing here makes a request; this makes sure
    for k in _SCRATCH_POP:
        os.environ.pop(k, None)
    try:
        yield tmp
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(tmp, ignore_errors=True)


try:
    import pytest
except ImportError:  # a direct run needs no pytest
    pytest = None
else:
    @pytest.fixture(autouse=True)
    def _scratch():
        with scratch_env() as tmp:
            yield tmp


# ---------------------------------------------------------------------------- the plan and its questions
# Carried from tests/test_script_review.py: the version-3 plan, the twelve questions asked of a member, and
# the plan's own answers.
V3 = ("v=3|language=php|role=downloader|verdict=suspicious|attack=T1105|adapter=http_client|host_profile=standalone|"
      "obfuscation_profile=base64|stage_profile=two_stage_download_execute|next_language=python|stage_count=2|"
      "steps=acquire_remote,write_file|campaign_id=PHP-0a1b2c3d|url=https://php-0a1b2c3d4e.example.invalid/stage|"
      "file_path=/tmp/huntress-php/.0a1b2c3d4e5f6071.stage")
FIELDS = [("role", "enum"), ("attack", "mitre_attack_id"), ("adapter", "exact_text"), ("campaign", "exact_text"),
          ("url", "exact_text"), ("file-path", "exact_text"), ("stage-count", "integer"), ("steps", "ordered_tokens"),
          ("host-profile", "exact_text"), ("obfuscation", "exact_text"), ("stage-profile", "exact_text"),
          ("next-language", "exact_text")]
ROLES = ["benign_utility", "downloader", "dropper", "impact", "launcher", "persistence_descriptor", "relay",
         "staged_chain", "stager", "uploader", "advanced_syntax"]
PREFIX = "polyglot-php-downloader"


def questions(member):
    out = []
    for f, kind in FIELDS:
        fmt, text = {"kind": kind}, f"Recover the {f} of the specimen."
        if f == "role":
            fmt["accepted_values"], text = list(ROLES), "Classify the inert source role."
        elif f == "attack":
            text = "Recover the primary ATT&CK technique ID, or none."
        elif f == "steps":
            fmt["syntax"], text = "exact tokens joined by > with no surrounding spaces or explanatory text", \
                "Recover the ordered behavior graph using > separators."
        qid = f"{PREFIX}-{f}"
        out.append({"id": qid, "qid": qid, "answer_id": qid, "question": text, "artifact": f"evidence.zip -> {member}",
                    "member": member, "answer_format": fmt})
    return out


def want_of(plan):
    p = dict(x.split("=", 1) for x in plan.split("|"))
    w = {"role": p.get("role"), "attack": p.get("attack"), "adapter": p.get("adapter"), "campaign": p.get("campaign_id"),
         "url": p.get("url"), "file-path": p.get("file_path"), "stage-count": p.get("stage_count"),
         "steps": ">".join(p["steps"].split(",")), "host-profile": p.get("host_profile"),
         "obfuscation": p.get("obfuscation_profile"), "stage-profile": p.get("stage_profile"),
         "next-language": p.get("next_language")}
    return {f"{PREFIX}-{k}": v for k, v in w.items()}


def plain(v):
    return isinstance(v, str) and not v.startswith("??")


def wrong(got, plan):
    """The plain answers that differ from the plan's own values (a field the plan does not hold is not compared)."""
    want = want_of(plan)
    return {k: v for k, v in got.items() if plain(v) and want.get(k) is not None and v != want[k]}


FAILED = []
PLAN = V3
B64 = base64.b64encode(PLAN.encode()).decode()
HTA = (f"<html><head><hta:application id=\"x\"/><script language=\"JScript\">\n"
       f"// HUNTRESS_ANALYSIS_V1:B64-{B64}\nvar descriptor_aa11bb22 = \"{B64}\";\n</script></head></html>\n").encode()
HTA_ONE_COPY = (f"<html><head><hta:application id=\"x\"/><script language=\"JScript\">\n"
                f"var m = \"{B64}\";\n</script></head></html>\n").encode()


def check(label, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + label + ("" if ok or not detail else f"  [{str(detail)[:900]}]"))
    if not ok:
        FAILED.append(label)
        if os.environ.get("PYTEST_CURRENT_TEST"):     # under pytest a failed check fails the test it is in
            raise AssertionError(label + ("" if not detail else f"  [{str(detail)[:900]}]"))


# ---------------------------------------------------------------------------- CHM fixtures

def encint(n):
    out = [n & 0x7F]
    n >>= 7
    while n:
        out.append(0x80 | (n & 0x7F))
        n >>= 7
    return bytes(reversed(out))


class BitWriter:
    """LZX's bit order: most significant bit first, in 16-bit little-endian words."""

    def __init__(self):
        self.out, self.acc, self.n = bytearray(), 0, 0

    def put(self, value, bits):
        for i in reversed(range(bits)):
            self.acc = (self.acc << 1) | ((value >> i) & 1)
            self.n += 1
            if self.n == 16:
                self.out += struct.pack("<H", self.acc)
                self.acc, self.n = 0, 0

    def align(self):
        if self.n:
            self.put(0, 16 - self.n)

    def raw(self, data):
        assert self.n == 0
        self.out += data


def canonical(lengths):
    codes, code = {}, 0
    for n in range(1, max(lengths) + 1):
        for sym, ln in enumerate(lengths):
            if ln == n:
                codes[sym] = (code, n)
                code += 1
        code <<= 1
    return codes


def lzx_uncompressed(data, reset_frames=2):
    """An LZX stream of uncompressed blocks, one a frame, with a reset every `reset_frames` frames."""
    w, frame = BitWriter(), 0
    for at in range(0, len(data), carriers.LZX_FRAME):
        chunk = data[at:at + carriers.LZX_FRAME]
        if frame % reset_frames == 0:
            w.put(0, 1)                          # no x86 translation
        w.put(3, 3)
        w.put(len(chunk) >> 8, 16)
        w.put(len(chunk) & 0xFF, 8)
        if w.n == 0:
            w.put(0, 16)                         # 1 to 16 bits of padding: a whole word when already aligned
        w.align()
        w.raw(struct.pack("<III", 1, 1, 1) + chunk + (b"\0" if len(chunk) & 1 else b""))
        frame += 1
    return bytes(w.out)


def lzx_verbatim(data, window_bits=16):
    """One verbatim block (data shorter than a frame): every literal nine bits, and a match of offset slot 4
    to 7 wherever the same four bytes stood shortly before."""
    assert len(data) <= carriers.LZX_FRAME
    slots = carriers._SLOTS[window_bits]
    main_n = 256 + slots * 8
    lengths = [9] * 256 + [0] * (main_n - 256)
    matches = [(slot << 3) | 2 for slot in range(4, 8)] + [(slot << 3) | 6 for slot in range(4, 8)]   # lengths 4 and 8
    for m in matches:
        lengths[256 + m] = 4
    codes = canonical(lengths)
    pre = canonical([5] * 17 + [0] * 3)
    w = BitWriter()
    w.put(0, 1)
    w.put(1, 3)
    w.put(len(data) >> 8, 16)
    w.put(len(data) & 0xFF, 8)

    def table(part):
        for _ in range(20):
            w.put(5 if _ < 17 else 0, 4)
        for ln in part:
            w.put(*pre[(0 - ln) % 17])
    table(lengths[:256])
    table(lengths[256:])
    table([0] * 249)
    at = matched = 0
    while at < len(data):
        done = False
        for n, head in ((8, 6), (4, 2)):
            if at + n > len(data):
                continue
            for off in range(2, 14):
                if at - off >= 0 and data[at - off:at - off + n] == data[at:at + n] and off >= n:
                    slot = next(s for s in range(4, 8) if carriers._BASE[s] - 2 <= off < carriers._BASE[s + 1] - 2)
                    w.put(*codes[256 + ((slot << 3) | head)])
                    w.put(off - (carriers._BASE[slot] - 2), carriers._EXTRA[slot])
                    at += n
                    matched += 1
                    done = True
                    break
            if done:
                break
        if not done:
            w.put(*codes[data[at]])
            at += 1
    w.align()
    return bytes(w.out), matched


def chm(files, compressed=None, stream=None, reset=2, window=2):
    """An ITSF file. `files` {name: bytes} go to section 0; `compressed` {name: bytes} to the MSCompressed
    section, whose LZX stream is `stream` (default: uncompressed blocks)."""
    compressed = compressed or {}
    body1 = b"".join(compressed.values())
    system = {}
    if compressed:
        stream = lzx_uncompressed(body1, reset) if stream is None else stream
        system["::DataSpace/Storage/MSCompressed/ControlData"] = struct.pack("<I4sIIIII", 6, b"LZXC", 2, reset, window, 0, 0)
        frames = (len(body1) + carriers.LZX_FRAME - 1) // carriers.LZX_FRAME
        system["::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable"] = \
            struct.pack("<IIIIQQQ", 2, frames, 8, 0x28, len(body1), len(stream), carriers.LZX_FRAME) + b"\0" * 8 * frames
        system["::DataSpace/Storage/MSCompressed/Content"] = stream
    content, entries = b"", []
    for name, blob in list(files.items()) + list(system.items()):
        entries.append((name, 0, len(content), len(blob)))
        content += blob
    at = 0
    for name, blob in compressed.items():
        entries.append((name, 1, at, len(blob)))
        at += len(blob)
    listing = b"".join(encint(len(n.encode())) + n.encode() + encint(s) + encint(o) + encint(ln)
                       for n, s, o, ln in sorted(entries))
    chunk = 0x1000
    assert len(listing) < chunk - 0x14
    pmgl = b"PMGL" + struct.pack("<IIii", chunk - 0x14 - len(listing), 0, -1, -1) + listing
    pmgl += b"\0" * (chunk - len(pmgl))
    itsp = b"ITSP" + struct.pack("<IIIIIIiiiiI", 1, 0x54, 0x0A, chunk, 2, 1, -1, 0, 0, -1, 1)
    itsp += struct.pack("<I", 0x409) + b"\0" * 16 + struct.pack("<Iiii", 0x54, -1, -1, -1)
    assert len(itsp) == 0x54
    directory = itsp + pmgl
    head = b"ITSF" + struct.pack("<IIIII", 3, 0x60, 1, 0, 0x409) + b"\0" * 32
    section0 = struct.pack("<IIQQ", 0x1FE, 0, 0, 0)[:0x18]
    dir_off = 0x60 + len(section0)
    head += struct.pack("<QQQQQ", 0x60, len(section0), dir_off, len(directory), dir_off + len(directory))
    assert len(head) == 0x60
    return head + section0 + directory + content


# ---------------------------------------------------------------------------- the other fixtures

def onenote(blobs):
    out = carriers.ONE_HEAD + b"\0" * 1008
    for blob in blobs:
        obj = carriers.FDSO_HEAD + struct.pack("<QIQ", len(blob), 0, 0) + blob
        obj += b"\0" * ((8 - len(obj) % 8) % 8) + carriers.FDSO_FOOT
        out += obj + b"\0" * 24
    return out


def lnk(arguments, name="update", wide=True):
    flags = 0x04 | 0x20 | (0x80 if wide else 0)
    head = struct.pack("<I", 0x4C) + carriers.LNK_CLSID + struct.pack("<II", flags, 0x20) + b"\0" * (0x4C - 28)

    def counted(s):
        return struct.pack("<H", len(s)) + (s.encode("utf-16-le") if wide else s.encode("cp1252"))
    return head + counted(name) + counted(arguments) + struct.pack("<I", 0)


def ahk_exe(script: bytes, name=">AUTOHOTKEY SCRIPT<"):
    """A PE image whose resource directory holds RT_RCDATA / `name` / 0x409 -> the script, as Ahk2Exe stores it."""
    wide = name.encode("utf-16-le")
    d1 = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 10, 0x80000000 | 0x18)
    d2 = struct.pack("<IIHHHH", 0, 0, 0, 0, 1, 0) + struct.pack("<II", 0x80000000 | 0x58, 0x80000000 | 0x30)
    d3 = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 0x409, 0x48)
    string_at = 0x58
    data_at = string_at + 2 + len(wide)
    data_at += (4 - data_at % 4) % 4
    entry = struct.pack("<IIII", 0x1000 + data_at, len(script), 0, 0)
    rsrc = (d1 + d2 + d3 + entry).ljust(string_at, b"\0") + struct.pack("<H", len(name)) + wide
    rsrc = rsrc.ljust(data_at, b"\0") + script
    assert len(d1 + d2 + d3) == 0x48
    nt = 0x80
    head = b"MZ" + b"\0" * 0x3A + struct.pack("<I", nt) + b"\0" * (nt - 0x40)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray((struct.pack("<HBB", 0x20B, 14, 0) + b"\0" * 104 + struct.pack("<I", 16)).ljust(240, b"\0"))
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)                       # section and file alignment
    struct.pack_into("<II", opt, 56, 0x3000, 0x400)                       # size of image, of headers
    struct.pack_into("<II", opt, 112 + 8 * 2, 0x1000, len(rsrc))          # data directory 2: the resources
    raw = rsrc.ljust((len(rsrc) + 0x1FF) & ~0x1FF, b"\0")
    table = b".rsrc\0\0\0" + struct.pack("<IIII", len(rsrc), 0x1000, len(raw), 0x400) + b"\0" * 12 + struct.pack("<I", 0x40000040)
    return (head + coff + bytes(opt) + table).ljust(0x400, b"\0") + raw


def au3_tokens(lines):
    """A tokenized AutoIt script: `$name = "text"` lines."""
    def xored(s):
        n = len(s)
        return struct.pack("<I", n) + b"".join(struct.pack("<H", ord(c) ^ n) for c in s)
    out = struct.pack("<I", len(lines))
    for name, text in lines:
        out += b"\x33" + xored(name) + b"\x41" + b"\x36" + xored(text) + b"\x7f"
    return out


def a3x(script_tokens):
    from autoit_ripper.utils import EA06Decryptor, crc_data
    d = EA06Decryptor()

    def string(s, keys):
        raw = s.encode("utf-16-le")
        return struct.pack("<I", len(s) ^ keys[0]) + d.decrypt(raw, len(s) + keys[1])
    body = d.decrypt(script_tokens, d.au3_ResContent)
    out = carriers.AU3_MAGIC + b"AU3!" + b"EA06" + b"\0" * 16
    out += d.decrypt(b"FILE", d.au3_ResType) + string(">>>AUTOIT SCRIPT<<<", d.au3_ResSubType)
    out += string("C:\\build\\x.au3", d.au3_ResName) + b"\0"
    out += struct.pack("<III", len(script_tokens) ^ d.au3_ResSize, len(script_tokens) ^ d.au3_ResSize,
                       crc_data(script_tokens) ^ d.au3_ResCrcCompressed) + b"\0" * 16 + body
    return out + b"AU3!EA06"


# ---------------------------------------------------------------------------- the tests

def solve(member, data):
    qs = questions(member)
    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
        got = analyze.solve_set(qs, {member: data}, {"set": 0, "partial": {}})
    return {q["qid"]: got.get(q["qid"]) for q in qs}


def test_readers():
    filler = bytes((i * 7 + 3) % 251 for i in range(70000))
    box = chm({"/index.hhc": b"<ul></ul>"}, {"/pad.bin": filler, "/run.hta": HTA})
    got = dict(carriers.chm_files(box))
    check("chm: files of the MSCompressed section through uncompressed LZX blocks, three frames and a reset",
          got.get("pad.bin") == filler and got.get("run.hta") == HTA and got.get("index.hhc") == b"<ul></ul>",
          {k: len(v) for k, v in got.items()})
    text = (b"descriptor descriptor descriptor " + HTA + b" abcdabcdabcdabcd 0123456701234567 ") * 3
    stream, matched = lzx_verbatim(text)
    check(f"lzx: a verbatim block (pretree, main tree, literals, {matched} matches with extra bits) decodes to its text",
          carriers.lzx_decode(stream, 16, 2, len(text)) == text and matched >= 12, (len(stream), matched))
    box = chm({}, {"/run.hta": text}, stream=stream)
    check("chm: and the same block as the section of a help file", dict(carriers.chm_files(box)).get("run.hta") == text)
    one = onenote([b"\x89PNG\r\n\x1a\n" + b"\0" * 37, HTA])
    found = carriers.onenote_files(one)
    check("one: both FileDataStoreObjects, each by its length and footer; the .hta named for what it is",
          [n for n, _ in found] == ["embedded-0.png", "embedded-1.hta"] and found[1][1] == HTA, [n for n, _ in found])
    link = lnk("/c mshta \"javascript:var m='" + B64 + "';close()\"")
    strings = dict(carriers.lnk_strings(link))
    check("lnk: the counted strings of StringData", strings.get("name") == "update" and B64 in strings.get("arguments", ""),
          strings)
    check("kind_of: each by its own mark, a text file by none",
          [carriers.kind_of(x) for x in (box, one, link, b"<?php echo 1;", b"L\0\0\0" + b"\x01" * 80)]
          == ["chm", "one", "lnk", None, None])


def test_lane():
    whole = want_of(PLAN)
    for what, member, data in (
            ("a .chm, the script stored", "help.chm", chm({"/run.hta": HTA_ONE_COPY})),
            ("a .chm, the script in the compressed section", "help.chm", chm({}, {"/run.hta": HTA_ONE_COPY})),
            ("a .one with an embedded .hta", "notes.one", onenote([b"\x89PNG\r\n\x1a\n" + b"\0" * 20, HTA_ONE_COPY])),
            ("a .lnk, the script in its arguments", "update.lnk", lnk("/c wscript //e:jscript run.js & rem var m = '" + B64 + "';")),
    ):
        got = solve(member, data)
        check(f"lane: {what}: every field of the plan plain, the last one too", got == whole,
              {k: (got[k], whole[k]) for k in whole if got[k] != whole[k]})
    got = solve("update.lnk", lnk("/c mshta \"javascript:var m='" + B64 + "';close()\""))
    check("lane: a .lnk whose script is quoted inside a quoted argument: a piece of that literal, so every field "
          "but the last", not wrong(got, PLAN) and got["polyglot-php-downloader-url"] == whole["polyglot-php-downloader-url"]
          and got["polyglot-php-downloader-file-path"] is None, got)
    try:
        import autoit_ripper  # noqa: F401
    except Exception as e:  # noqa: BLE001
        # autoit-ripper is pinned in requirements.in: its absence is a broken environment, not a skip
        check("au3: autoit-ripper (pinned in requirements.in) imports", False, f"{type(e).__name__}: {e}")
    else:
        compiled = a3x(au3_tokens([("m", B64), ("n", "done")]))
        files = carriers.autoit_files(compiled)
        check("au3: the EA06 container decrypted and its tokens written out as source",
              len(files) == 1 and f'$m = "{B64}"' in files[0][1].decode(), files[:1])
        got = solve("update.a3x", compiled)
        check("lane: a compiled AutoIt script: every field of the plan plain", got == whole,
              {k: (got[k], whole[k]) for k in whole if got[k] != whole[k]})
    script = f"#NoEnv\r\n; an inert fixture\r\nm := \"{B64}\"\r\nreturn\r\n".encode()
    exe = ahk_exe(script)
    check("ahk: the script resource of a compiled AutoHotkey executable, by its name in the resource directory",
          carriers.kind_of(exe) == "ahk" and carriers.ahk_script(exe) == script, carriers.kind_of(exe))
    got = solve("update.exe", exe)
    check("lane: a compiled AutoHotkey executable: every field of the plan plain", got == whole,
          {k: (got[k], whole[k]) for k in whole if got[k] != whole[k]})
    other = V3.replace("PHP-0a1b2c3d", "PHP-ffffffff")
    two = chm({"/a.hta": HTA_ONE_COPY, "/b.hta": HTA_ONE_COPY.replace(B64.encode(), base64.b64encode(other.encode()))})
    got = solve("help.chm", two)
    check("lane: two inner scripts with two plans: no plain answer from either",
          not any(plain(v) for k, v in got.items() if k.endswith(("campaign", "url", "file-path", "adapter"))), got)
    many = {f"/p{i:03d}.htm": b"<html><body>page %03d of the help file</body></html>" % i for i in range(60)}
    packed = dict(many, **{"/run.hta": HTA_ONE_COPY})
    box = chm({}, packed, stream=lzx_verbatim(b"".join(packed.values()))[0])      # Huffman-coded: not in the strings
    old = analyze.INNER_FILES
    try:
        analyze.INNER_FILES = 40
        capped = solve("help.chm", box)
    finally:
        analyze.INNER_FILES = old
    full = solve("help.chm", box)
    check("lane: a container that holds more files than are read is not read as one script (no plan is called the "
          "only one), and within the bound it is", full == whole and not any(capped.values()), capped)
    same = chm({"/a.hta": HTA_ONE_COPY, "/b.hta": HTA_ONE_COPY})
    check("lane: two inner scripts with the same plan are one reading", solve("help.chm", same) == whole)


def test_bounds():
    box = chm({}, {"/run.hta": HTA})
    bad = []
    for label, data in (("cut in the directory", box[:0x90]), ("cut in the content", box[:-40]),
                        ("a directory offset past the end", box[:0x48] + struct.pack("<Q", 1 << 40) + box[0x50:]),
                        ("an ENCINT that never ends", box.replace(b"/run.hta", b"\xff\xff\xff\xff\xff\xff\xff\xff")),
                        ("a OneNote length past the end", carriers.ONE_HEAD + carriers.FDSO_HEAD + struct.pack("<Q", 1 << 50)),
                        ("a link cut in its strings", lnk("x" * 400)[:-200]),
                        ("an AutoIt mark and nothing behind it", carriers.AU3_MAGIC + b"AU3!EA06" + b"\x01" * 40)):
        try:
            got = carriers.inner("x.bin", data)
            if got is not None and any(B64.encode() in blob for _, blob in got[1]) and "cut" not in label:
                bad.append((label, "gave the script"))
        except Exception as e:  # noqa: BLE001
            bad.append((label, type(e).__name__))
        try:
            solve("x.chm", data)
        except Exception as e:  # noqa: BLE001
            bad.append((label, "solve_set raised " + type(e).__name__))
    check("bounds: seven damaged containers give no reading and raise nothing", not bad, bad)
    try:
        carriers.lzx_decode(b"\xff" * 4000, 16, 2, 5000)
        raised = False
    except ValueError:
        raised = True
    check("bounds: an LZX stream that does not decode is a ValueError (inner() turns it into no files)", raised)
    big = chm({}, {"/pad.bin": bytes(200000), "/run.hta": HTA})
    got = carriers.inner("x.chm", big, budget=-1.0)
    check("bounds: past its deadline the LZX decoder stops and inner() gives the kind with no files",
          got is not None and got[0] == "chm" and got[1] == [] and "not read" in got[2][0], got)
    t0 = time.perf_counter()
    carriers.inner("x.chm", chm({}, {"/pad.bin": bytes(range(256)) * 4000, "/run.hta": HTA}))
    check("bounds: a megabyte of uncompressed blocks is read in under a second", time.perf_counter() - t0 < 1.0,
          time.perf_counter() - t0)


def test_corpus():
    root = os.environ.get("SCRIPT_B_CORPUS")
    if not root or not Path(root).is_dir():
        why = "set SCRIPT_B_CORPUS to a folder of <name>.chm and <name>.chm.out/ (a 7-Zip extraction)"
        if os.environ.get("PYTEST_CURRENT_TEST") and pytest is not None:
            pytest.skip("corpus not run: " + why)          # reported as not run, never green
        print("skip corpus: " + why)
        return
    compared = 0
    for f in sorted(Path(root).glob("*.chm")):
        ref = Path(str(f) + ".out")
        if not ref.is_dir():
            continue
        compared += 1
        files = carriers.chm_files(f.read_bytes(), time.perf_counter() + 60)
        differ = [n for n, b in files if not (ref / n).is_file() or (ref / n).read_bytes() != b]
        check(f"corpus: {f.name}: {len(files)} files, each byte for byte 7-Zip's", files and not differ, differ[:3])
    check(f"corpus: {root} holds at least one <name>.chm with its <name>.chm.out/ beside it", compared > 0)


def main():
    with scratch_env():
        for test in (test_readers, test_lane, test_bounds, test_corpus):
            test()
    if FAILED:
        print(f"FAILED {len(FAILED)}: " + "; ".join(FAILED))
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
