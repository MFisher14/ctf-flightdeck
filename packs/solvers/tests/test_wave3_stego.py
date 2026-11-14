#!/usr/bin/env python3
"""Offline tests of the wave-3 never-wrong stego readers (tickets #9, #10, C6, C8):

    solvers/toolkits/stego_containers.py   #9 headered self-validating LSB container + C6 steghide
    solvers/toolkits/jpeg_stego.py         #10 jsteg DCT-coefficient LSB extraction
    solvers/toolkits/audio_stego.py        C8 the audio-manipulation axis (unsure-only)

  .venv/bin/python tests/test_wave3_stego.py

No network and no token. Every fixture is synthetic and made here, in memory. The one invariant under
test is the never-wrong contract: a value is PLAIN only when a stored length/CRC/checksum (or a
complete file structure) self-validates it; a random carrier, a corrupt CRC, an unproven decode -> None
or an unsure candidate. The flag is never used or submitted. Prints one line per check and `ok` at the
end; exits 1 when a check fails. This test builds its own jsteg carrier with a tiny baseline-JPEG
encoder (standard luminance Huffman tables), so it needs neither the jsteg binary nor the sandbox.
"""
import io
import os
import struct
import sys
import tempfile
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_wave3_stego_"))
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
sys.path.insert(0, str(REPO / "tests"))

import stego_fixtures as fx         # noqa: E402
import carve_stego as cs            # noqa: E402
import stego_containers as sc       # noqa: E402
import jpeg_stego as js             # noqa: E402
import audio_stego as au            # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


def crc(b):
    return zlib.crc32(b) & 0xFFFFFFFF


def container_be(payload):
    return struct.pack(">I", len(payload)) + struct.pack(">I", crc(payload)) + payload


def container_le(payload):
    return struct.pack("<I", len(payload)) + struct.pack("<I", crc(payload)) + payload


def container_trailing(payload):
    return struct.pack(">I", len(payload)) + payload + struct.pack(">I", crc(payload))


def noise_png(w=96, h=64, seed=1):
    import random
    from PIL import Image
    rnd = random.Random(seed)
    raw = bytes(rnd.randrange(256) for _ in range(w * h * 3))
    out = io.BytesIO()
    Image.frombytes("RGB", (w, h), raw).save(out, "PNG")
    return out.getvalue()


# ---- #9 and the shared container test --------------------------------------------------------------

def test_containers():
    pl = b"a self-validating payload, proven by crc"
    f = sc.validate_container(container_be(pl))
    check("#9 validate: len+crc (be) -> plain", f.plain == pl and f.validated and "len+crc" in f.method, f)
    f = sc.validate_container(container_le(pl))
    check("#9 validate: len+crc (le) -> plain", f.plain == pl and f.validated, f)
    f = sc.validate_container(container_trailing(pl))
    check("#9 validate: len+payload+crc -> plain", f.plain == pl and f.validated, f)
    # a complete file structure of a CHECKSUM kind (gzip inflates + CRC) is self-proving too
    gz = __import__("gzip").compress(b"hello wave3 file-magic channel")
    f = sc.validate_container(gz + b"\x00" * 64)
    check("#9 validate: a complete gzip structure -> plain (file magic, checksum kind)",
          f.plain is not None and f.method.startswith("magic:") and f.kind == "gzip", f)
    # H12: a structure-only match of a kind whose sizer carries NO payload checksum (riff/pdf/png/...)
    # is a forgeable walk -- a bare/garbage/decoy magic must be UNSURE, never a self-validated plain.
    forged_riff = b"RIFF" + struct.pack("<I", 44) + b"WAVE" + b"\x00" * 40
    f = sc.validate_container(forged_riff)
    check("#9 H12: a forged RIFF/WAVE (self-declared length, no checksum) -> unsure, not plain",
          f.plain is None and not f.validated and bool(f.candidates) and f.candidates[0][0] == "carved_file", f)
    garbage_pdf = b"%PDF-1.4\nARBITRARY GARBAGE\n%%EOF"
    f = sc.validate_container(garbage_pdf)
    check("#9 H12: a garbage %PDF...%%EOF (rfind of a marker, no checksum) -> unsure, not plain",
          f.plain is None and not f.validated and bool(f.candidates), f)

    def _png_all_bad_crc():
        sig = b"\x89PNG\r\n\x1a\n"

        def ch(typ, body, c):
            return struct.pack(">I", len(body)) + typ + body + struct.pack(">I", c)
        return (sig + ch(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0), 0xDEADBEEF)
                + ch(b"IDAT", b"\x00\x00\x00\x00", 0x11111111) + ch(b"IEND", b"", 0x22222222))
    f = sc.validate_container(_png_all_bad_crc())
    check("#9 H12: an all-bad-CRC PNG walked to IEND (chunk CRCs unchecked) -> unsure, not plain",
          f.plain is None and not f.validated and bool(f.candidates), f)
    # and the forged RIFF must not sneak back in through the LSB reader either
    r = sc.read_image(fx.lsb_png(forged_riff, w=96, h=64))
    check("#9 H12: a forged RIFF carried in the LSBs -> no plain (structure-only, no checksum)",
          r["plain"] is None, r)
    # corrupt CRC -> None
    bad = bytearray(container_be(pl))
    bad[7] ^= 0x01
    check("#9 validate: a corrupt CRC -> None (not plain)", sc.validate_container(bytes(bad)).plain is None)
    # random bytes -> None
    import random
    rnd = random.Random(7)
    rand = bytes(rnd.randrange(256) for _ in range(4096))
    check("#9 validate: random bytes -> None", sc.validate_container(rand).plain is None)
    # a declared length that overruns the blob -> None
    over = struct.pack(">I", 1 << 20) + struct.pack(">I", 0) + b"short"
    check("#9 validate: a length past the blob -> None", sc.validate_container(over).plain is None)
    # printable text with no length/CRC -> unsure, never plain
    f = sc.validate_container(b"plain words with spaces but no checksum to prove them\x00")
    check("#9 validate: a NUL-ended printable start -> unsure candidate, not plain",
          f.plain is None and bool(f.candidates), f)


def test_lsb_reader_9():
    pl = b"PROVEN_BY_CRC_payload_0123456789"
    r = sc.read_image(fx.lsb_png(container_be(pl), w=96, h=64))
    check("#9 read_image: a CRC-headed LSB payload round-trips to plain", r["plain"] == pl, r)
    r = sc.read_image(fx.lsb_png(container_le(pl), w=96, h=64))
    check("#9 read_image: a little-endian CRC container also -> plain", r["plain"] == pl, r)
    # a complete file magic embedded in the LSBs -> plain
    gz = __import__("gzip").compress(b"embedded gzip through the lsb channel")
    r = sc.read_image(fx.lsb_png(gz, w=96, h=64))
    check("#9 read_image: an embedded gzip file -> plain (file magic)",
          r["plain"] is not None and cs.sniff(r["plain"]) == "gzip", r)
    # a random image -> None
    r = sc.read_image(noise_png())
    check("#9 read_image: a random image -> None (no plain)", r["plain"] is None, r)
    # a corrupt CRC -> None
    bad = bytearray(container_be(pl))
    bad[7] ^= 0x01
    r = sc.read_image(fx.lsb_png(bytes(bad), w=96, h=64))
    check("#9 read_image: a corrupt CRC -> None (no plain)", r["plain"] is None, r)
    # not an image this reader pulls pixels from -> None, with a note
    r = sc.read_image(b"not an image at all")
    check("#9 read_image: a non-image -> None with a note", r["plain"] is None and r["notes"], r)


# ---- #10 jsteg: a tiny baseline-JPEG encoder so we need no jsteg binary ----------------------------

_BITS_DC = [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
_VALS_DC = list(range(12))
_BITS_AC = [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d]
_VALS_AC = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xa1, 0x08, 0x23, 0x42, 0xb1, 0xc1, 0x15, 0x52, 0xd1, 0xf0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0a, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6a, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5,
    0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xe1, 0xe2,
    0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
    0xf9, 0xfa]


def _enc_map(bits, vals):
    m, code, vi = {}, 0, 0
    for length in range(1, 17):
        for _ in range(bits[length - 1]):
            m[vals[vi]] = (code, length)
            vi += 1
            code += 1
        code <<= 1
    return m


_DC = _enc_map(_BITS_DC, _VALS_DC)
_AC = _enc_map(_BITS_AC, _VALS_AC)


class _BitWriter:
    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, code, length):
        for i in range(length - 1, -1, -1):
            self.acc = (self.acc << 1) | ((code >> i) & 1)
            self.n += 1
            if self.n == 8:
                self.out.append(self.acc)
                if self.acc == 0xFF:
                    self.out.append(0x00)
                self.acc, self.n = 0, 0

    def flush(self):
        if self.n:
            self.acc = (self.acc << (8 - self.n)) | ((1 << (8 - self.n)) - 1)
            self.out.append(self.acc)
            if self.acc == 0xFF:
                self.out.append(0x00)
            self.acc, self.n = 0, 0


def _size_of(v):
    v, s = abs(v), 0
    while v:
        s += 1
        v >>= 1
    return s


def _mant(v, s):
    return v if v >= 0 else v + (1 << s) - 1


def _seg(marker, body):
    return bytes([0xFF, marker]) + struct.pack(">H", len(body) + 2) + body


def jsteg_encode(container, W=32, H=24, K=16):
    """A minimal grayscale baseline JPEG (standard luminance Huffman tables, quant table all ones)
    whose DCT-coefficient LSBs, in decode order, spell `container` -- i.e. a jsteg carrier. DC and
    AC carriers hold magnitudes 2/3 (LSB = the message bit; never 0 or 1, so jsteg never skips a
    carrier). Trailing carriers are padded with 0, which a length/CRC container ignores."""
    assert W % 8 == 0 and H % 8 == 0
    nb = (W // 8) * (H // 8)
    bits = [(byte >> (7 - i)) & 1 for byte in container for i in range(8)]
    slots = nb * (1 + K)
    assert slots >= len(bits), (slots, len(bits))
    bits = bits + [0] * (slots - len(bits))
    bw = _BitWriter()
    pred = 0
    bi = 0
    for _ in range(nb):
        dcv = 2 | bits[bi]
        bi += 1
        diff = dcv - pred
        pred = dcv
        s = _size_of(diff)
        code, length = _DC[s]
        bw.put(code, length)
        if s:
            bw.put(_mant(diff, s), s)
        for _k in range(K):
            acv = 2 | bits[bi]
            bi += 1
            code, length = _AC[0x02]        # run 0, size 2
            bw.put(code, length)
            bw.put(_mant(acv, 2), 2)
        code, length = _AC[0x00]            # end of block
        bw.put(code, length)
    bw.flush()
    out = bytearray(b"\xFF\xD8")
    out += _seg(0xDB, bytes([0]) + bytes([1] * 64))
    out += _seg(0xC0, struct.pack(">BHHB", 8, H, W, 1) + struct.pack(">BBB", 1, 0x11, 0))
    out += _seg(0xC4, bytes([0x00]) + bytes(_BITS_DC) + bytes(_VALS_DC))
    out += _seg(0xC4, bytes([0x10]) + bytes(_BITS_AC) + bytes(_VALS_AC))
    out += _seg(0xDA, bytes([1]) + struct.pack(">BB", 1, 0x00) + bytes([0, 63, 0]))
    out += bw.out
    out += b"\xFF\xD9"
    return bytes(out)


def test_jsteg_10():
    pl = b"wave3-jsteg-OK!!"
    jpg = jsteg_encode(container_be(pl))
    raw = js.extract_jsteg(jpg)
    check("#10 extract_jsteg: the carrier yields the embedded container at the front",
          raw is not None and raw[:len(container_be(pl))] == container_be(pl), raw[:40] if raw else None)
    r = js.read(jpg)
    check("#10 read: a jsteg carrier with a CRC container -> plain == payload", r["plain"] == pl, r)
    # a bigger payload across many blocks
    big = bytes((i * 37 + 11) & 0xFF for i in range(60))
    r = js.read(jsteg_encode(container_be(big), W=48, H=48))
    check("#10 read: a larger multi-block jsteg payload -> plain", r["plain"] == big, r.get("method"))
    # corrupt CRC -> None
    bad = bytearray(container_be(pl))
    bad[7] ^= 0x01
    r = js.read(jsteg_encode(bytes(bad)))
    check("#10 read: a corrupt CRC jsteg carrier -> None (no plain)", r["plain"] is None, r)
    # a clean Pillow JPEG -> None
    from PIL import Image
    import random
    rnd = random.Random(3)
    im = Image.new("RGB", (64, 48))
    px = im.load()
    for y in range(48):
        for x in range(64):
            px[x, y] = (rnd.randrange(256), rnd.randrange(256), rnd.randrange(256))
    bb = io.BytesIO()
    im.save(bb, "JPEG", quality=85)
    r = js.read(bb.getvalue())
    check("#10 read: a clean (noise) JPEG -> None", r["plain"] is None, r)
    # a progressive JPEG is declined (jsteg is baseline only)
    bb = io.BytesIO()
    im.save(bb, "JPEG", quality=85, progressive=True)
    r = js.read(bb.getvalue())
    check("#10 read: a progressive JPEG -> None (declined, baseline only)",
          r["plain"] is None and js.extract_jsteg(bb.getvalue()) is None, r)
    # not a JPEG at all -> None
    check("#10 extract_jsteg: a non-JPEG -> None", js.extract_jsteg(b"PK\x03\x04not a jpeg") is None)


# ---- C6 steghide / stegseek CRC-validated channel --------------------------------------------------

class _FakeRec:
    def __init__(self, ok=False, data=None, note="", files=None):
        self.ok, self.data, self.note, self.files = ok, data, note, dict(files or {})


def test_steghide_c6():
    # the pure never-wrong decision
    f = sc.classify_steghide(True, b"secret bytes", "", in_wordlist=True)
    check("C6 classify: a CRC-validated extract under the empty passphrase -> plain",
          f.plain == b"secret bytes" and f.validated, f)
    f = sc.classify_steghide(True, b"secret", "hunter2", in_wordlist=True)
    check("C6 classify: a CRC-validated extract under a question-supplied word -> plain",
          f.plain == b"secret", f)
    f = sc.classify_steghide(True, b"secret", "random-guess", in_wordlist=False)
    check("C6 classify: an extract under a passphrase NOT from the question's list -> unsure, not plain",
          f.plain is None and f.candidates, f)
    f = sc.classify_steghide(False, None, "", in_wordlist=True)
    check("C6 classify: nothing extracted -> no plain, no candidate", f.plain is None and not f.candidates, f)

    # end to end with a fake sandbox (no steghide needed)
    class _FakeST:
        @staticmethod
        def steghide_info(data, p=""):
            if p == "":
                return _FakeRec(ok=True, data={"embedded": "secret.txt", "capacity": "2.0 KB"},
                                note="steghide: embedded file 'secret.txt'")
            return _FakeRec(ok=True, data={"embedded": None}, note="nothing")

        @staticmethod
        def steghide_extract(data, p=""):
            if p == "":
                return _FakeRec(ok=True, data=b"the embedded payload", note="18 bytes")
            return _FakeRec(ok=False, data=None, note="nothing")

        @staticmethod
        def stegseek(data, words):
            return _FakeRec(ok=False, data=None, note="none of the words", files={})

    saved = sys.modules.get("stego_tools")
    try:
        sys.modules["stego_tools"] = _FakeST
        f = sc.steghide_channel(b"\xff\xd8\xffcoverjpeg")
        check("C6 channel: the empty passphrase opens a CRC-validated payload -> plain",
              f.plain == b"the embedded payload" and f.validated, f)

        class _Locked(_FakeST):
            @staticmethod
            def steghide_info(data, p=""):
                return _FakeRec(ok=True, data={"embedded": None, "capacity": "2.0 KB"}, note="read")

            @staticmethod
            def steghide_extract(data, p=""):
                return _FakeRec(ok=False, data=None, note="could not extract any data")
        sys.modules["stego_tools"] = _Locked
        f = sc.steghide_channel(b"\xff\xd8\xffcoverjpeg", words=["one", "two", "three"])
        check("C6 channel: a supplied word list, none opens it -> ARCHIVE PASSWORD NEEDED (need_password)",
              f.need_password and f.plain is None, f)
        f = sc.steghide_channel(b"\xff\xd8\xffcoverjpeg")
        check("C6 channel: no word list and nothing opens -> neutral note, no plain, no STOP",
              f.plain is None and not f.need_password, f)

        class _Down(_FakeST):
            @staticmethod
            def steghide_info(data, p=""):
                return _FakeRec(ok=False, data=None, note="sandbox down: not read")
        sys.modules["stego_tools"] = _Down
        f = sc.steghide_channel(b"\xff\xd8\xffcoverjpeg")
        check("C6 channel: a down sandbox -> a not-read note, no plain", f.plain is None and "sandbox down" in f.note, f)
    finally:
        if saved is not None:
            sys.modules["stego_tools"] = saved
        else:
            sys.modules.pop("stego_tools", None)


# ---- C8 the audio-manipulation axis (unsure only) --------------------------------------------------

def test_audio_c8():
    w = fx.dtmf_wav("5309", rate=8000)
    fwd = cs.dtmf(w)
    rev = cs.dtmf(au.reverse_wav(w))
    check("C8 reverse_wav: the reversed recording decodes to the reversed digits",
          fwd == "5309" and rev == fwd[::-1], (fwd, rev))
    a = au.analyze(w)
    names = dict(a["candidates"])
    check("C8 analyze: the reversed DTMF is offered as a CANDIDATE (unsure), never plain",
          names.get("dtmf_reversed") == "9035" and names.get("dtmf_forward") == "5309", a["candidates"])
    check("C8 reverse_wav: reversing twice round-trips the exact bytes (self-check)",
          au.reverse_wav(au.reverse_wav(w)) == w)
    # half speed doubles the sample count
    got = au.wav_channels(w)
    slow = au.wav_channels(au.half_speed(w))
    check("C8 half_speed: each sample is duplicated", slow is not None and len(slow[1][0]) == 2 * len(got[1][0]))
    # stereo difference of a 2-channel recording where L==R cancels to silence
    mono = got[1][0]
    stereo = au.build_wav(8000, 16, [mono, mono])
    diff = au.stereo_difference(stereo)
    dch = au.wav_channels(diff)
    check("C8 stereo_difference: identical L and R cancel to a silent difference channel",
          dch is not None and len(dch[1]) == 1 and max(abs(v) for v in dch[1][0]) == 0, dch and dch[1][0][:4])
    check("C8 stereo_difference: a mono recording has no difference channel -> None", au.stereo_difference(w) is None)
    # AIFF (non-WAV) path: build a tiny AIFF and read its samples back
    aiff = _make_aiff([100, -200, 300, -400, 500], rate=8000, bits=16)
    got = au.aiff_samples(aiff)
    check("C8 aiff_samples: an AIFF PCM recording is decoded (non-WAV LSB axis)",
          got is not None and got[2][0] == [100, -200, 300, -400, 500], got)
    # a noise recording offers no deterministic DTMF reading
    import math
    noise = au.build_wav(8000, 16, [[int(3000 * math.sin(i * 0.9) + (i * 97 % 400 - 200)) for i in range(4000)]])
    a = au.analyze(noise)
    check("C8 analyze: a noise recording yields no DTMF candidate",
          not any(n.startswith("dtmf") for n, _ in a["candidates"]), a["candidates"])


def _make_aiff(samples, rate=8000, bits=16):
    width = bits // 8
    data = b"".join(int(v).to_bytes(width, "big", signed=True) for v in samples)
    ssnd = struct.pack(">II", 0, 0) + data
    # 80-bit extended for the sample rate
    import math
    exp = 16383 + int(math.floor(math.log2(rate)))
    mant = int(rate * 2.0 ** (63 - (exp - 16383))) & ((1 << 64) - 1)
    ext = struct.pack(">H", exp) + struct.pack(">Q", mant)
    comm = struct.pack(">HIH", 1, len(samples), bits) + ext
    body = b"COMM" + struct.pack(">I", len(comm)) + comm + b"SSND" + struct.pack(">I", len(ssnd)) + ssnd
    return b"FORM" + struct.pack(">I", 4 + len(body)) + b"AIFF" + body


def main():
    import shutil
    try:
        for t in (test_containers, test_lsb_reader_9, test_jsteg_10, test_steghide_c6, test_audio_c8):
            try:
                t()
            except Exception as e:
                import traceback
                check(f"{t.__name__} ran", False, f"{type(e).__name__}: {e} | {traceback.format_exc()[-500:]}")
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED[:8]))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
