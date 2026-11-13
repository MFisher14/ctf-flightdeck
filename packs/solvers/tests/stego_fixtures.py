"""Fixtures of tests/test_stego_tools.py: small samples made here, in memory, by plain Python, numpy,
Pillow and qrcode (the venv). Nothing is downloaded and nothing here is run by anyone: a cover
picture, an LSB PNG, a picture of text, QR codes, a PDF with a line of text, recordings (DTMF keys,
an AX.25 packet as AFSK 1200, a POCSAG 1200 page, Morse, Bell 202 text, text drawn in the spectrum), an
OOK PWM transmission as an IQ file, a blob to carve, a FAT12 image with a deleted file, and a tiny
x86-64 ELF. The stego payloads themselves (steghide, outguess, snow) and the SSTV recording are
made by the same programs inside the sandbox, in the test.
"""
import io
import math
import random
import struct
import wave
import zlib


# ---- pictures ----------------------------------------------------------------------------------

def cover_jpeg(w=480, h=360, seed=11, comment=None) -> bytes:
    """A noisy photograph-like JPEG (enough coefficients to hide a short file in)."""
    from PIL import Image
    rnd = random.Random(seed)
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        for x in range(w):
            base = int(120 + 80 * math.sin(x / 23.0) * math.cos(y / 17.0))
            px[x, y] = tuple(max(0, min(255, base + rnd.randint(-40, 40) + d)) for d in (0, 12, -9))
    out = io.BytesIO()
    kw = {}
    if comment is not None:
        exif = Image.Exif()
        exif[0x010E] = comment                 # ImageDescription
        exif[0x013B] = "huntress-fixture"      # Artist
        kw["exif"] = exif
    img.save(out, "JPEG", quality=90, **kw)
    return out.getvalue()


def lsb_png(payload: bytes, w=96, h=64, seed=5) -> bytes:
    """An RGB PNG whose least significant bits, row by row, R then G then B, most significant bit of
    each byte first, spell the payload (what zsteg calls b1,rgb,lsb,xy)."""
    from PIL import Image
    rnd = random.Random(seed)
    raw = bytearray(rnd.randrange(256) for _ in range(w * h * 3))
    bits = [(b >> (7 - i)) & 1 for b in payload for i in range(8)]
    assert len(bits) <= len(raw)
    for i, bit in enumerate(bits):
        raw[i] = (raw[i] & 0xFE) | bit
    out = io.BytesIO()
    Image.frombytes("RGB", (w, h), bytes(raw)).save(out, "PNG")
    return out.getvalue()


def text_png(lines, size=44, pad=24, invert=False) -> bytes:
    """Black text on white (Pillow's built-in font at `size`), one line per item."""
    from PIL import Image, ImageDraw, ImageFont
    font = ImageFont.load_default(size=size)
    w = max(int(font.getlength(t)) for t in lines) + 2 * pad
    h = len(lines) * int(size * 1.5) + 2 * pad
    img = Image.new("L", (w, h), 0 if invert else 255)
    d = ImageDraw.Draw(img)
    for i, t in enumerate(lines):
        d.text((pad, pad + i * int(size * 1.5)), t, fill=255 if invert else 0, font=font)
    out = io.BytesIO()
    img.save(out, "PNG")
    return out.getvalue()


def qr_png(text: str, box=6, border=4, size=None) -> bytes:
    import qrcode
    from PIL import Image
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=box, border=border)
    q.add_data(text)
    q.make(fit=True)
    img = q.make_image(fill_color="black", back_color="white").convert("RGB")
    if size:
        canvas = Image.new("RGB", size, "white")
        side = min(size) - 8
        img = img.resize((side, side), Image.NEAREST)
        canvas.paste(img, ((size[0] - side) // 2, (size[1] - side) // 2))
        img = canvas
    out = io.BytesIO()
    img.save(out, "PNG")
    return out.getvalue()


# ---- a PDF -------------------------------------------------------------------------------------

def pdf(text: str, attachment=None) -> bytes:
    """A one-page PDF with one line of Helvetica text; attachment: (name, bytes) embedded with pypdf."""
    stream = f"BT /F1 18 Tf 72 720 Td ({text}) Tj ET".encode()
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out = bytearray(b"%PDF-1.4\n")
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for o in offs:
        out += b"%010d 00000 n \n" % o
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    if attachment is None:
        return bytes(out)
    from pypdf import PdfReader, PdfWriter
    w = PdfWriter()
    w.append(PdfReader(io.BytesIO(bytes(out))))
    w.add_attachment(attachment[0], attachment[1])
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


# ---- recordings --------------------------------------------------------------------------------

def wav(samples, rate: int) -> bytes:
    """Mono 16-bit PCM from floats in -1..1."""
    out = io.BytesIO()
    with wave.open(out, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(b"".join(struct.pack("<h", max(-32767, min(32767, int(s * 32767)))) for s in samples))
    return out.getvalue()


DTMF = {"1": (697, 1209), "2": (697, 1336), "3": (697, 1477), "A": (697, 1633),
        "4": (770, 1209), "5": (770, 1336), "6": (770, 1477), "B": (770, 1633),
        "7": (852, 1209), "8": (852, 1336), "9": (852, 1477), "C": (852, 1633),
        "*": (941, 1209), "0": (941, 1336), "#": (941, 1477), "D": (941, 1633)}


def dtmf_wav(keys: str, rate=22050, tone=0.12, gap=0.08) -> bytes:
    s = [0.0] * int(rate * 0.2)
    for k in keys:
        lo, hi = DTMF[k]
        s += [0.4 * math.sin(2 * math.pi * lo * i / rate) + 0.4 * math.sin(2 * math.pi * hi * i / rate) for i in range(int(rate * tone))]
        s += [0.0] * int(rate * gap)
    return wav(s + [0.0] * int(rate * 0.2), rate)


MORSE = {"A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
         "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
         "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
         "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----."}


def morse_wav(text: str, wpm=20, freq=700, rate=22050) -> bytes:
    """Morse code as a keyed tone: a dot is 1.2/wpm seconds, a dash three dots, one dot between
    marks, three between letters, seven between words."""
    dot = int(rate * 1.2 / wpm)
    s = [0.0] * (dot * 10)

    def tone(n):
        return [0.6 * math.sin(2 * math.pi * freq * i / rate) * min(1.0, i / 60, (n - i) / 60) for i in range(n)]

    for word in text.upper().split():
        for ch in word:
            for mark in MORSE[ch]:
                s += tone(dot if mark == "." else 3 * dot) + [0.0] * dot
            s += [0.0] * (2 * dot)
        s += [0.0] * (4 * dot)
    return wav(s + [0.0] * (dot * 10), rate)


def _fsk(bits, rate, baud, f_one, f_zero, amp=0.6, lead=0.2, nrzi=False):
    """Continuous-phase FSK of a bit list. nrzi: a 0 changes the tone, a 1 keeps it (AX.25)."""
    s = [0.0] * int(rate * lead)
    phase, t, tone_one = 0.0, 0.0, True
    n = 0
    for b in bits:
        if nrzi:
            if not b:
                tone_one = not tone_one
        else:
            tone_one = bool(b)
        f = f_one if tone_one else f_zero
        t += rate / baud
        while n < t:
            phase += 2 * math.pi * f / rate
            s.append(amp * math.sin(phase))
            n += 1
    return s + [0.0] * int(rate * lead)


def _crc_x25(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def ax25_frame(dest: str, src: str, info: bytes) -> bytes:
    def addr(call, last):
        return bytes((ord(c) << 1) for c in call.ljust(6)[:6]) + bytes([0x60 | (1 if last else 0)])
    body = addr(dest, False) + addr(src, True) + b"\x03\xf0" + info
    fcs = _crc_x25(body)
    return body + bytes([fcs & 0xFF, fcs >> 8])


def afsk1200_wav(dest="APRS", src="N0CALL", info=b"hello", rate=22050) -> bytes:
    """One AX.25 UI frame as Bell 202 AFSK (1200 Hz mark, 2200 Hz space, NRZI, bit stuffing)."""
    flag = [0, 1, 1, 1, 1, 1, 1, 0]
    bits = flag * 40
    ones = 0
    for byte in ax25_frame(dest, src, info):
        for i in range(8):
            b = (byte >> i) & 1
            bits.append(b)
            ones = ones + 1 if b else 0
            if ones == 5:
                bits.append(0)
                ones = 0
    bits += flag * 8
    return wav(_fsk(bits, rate, 1200, 1200, 2200, nrzi=True), rate)


def bell202_wav(text: str, rate=48000) -> bytes:
    """Asynchronous 8N1 text as Bell 202 FSK at 1200 baud (what `minimodem --rx 1200` reads)."""
    bits = [1] * 600
    for byte in text.encode("ascii"):
        bits += [0] + [(byte >> i) & 1 for i in range(8)] + [1]
    bits += [1] * 600
    return wav(_fsk(bits, rate, 1200, 1200, 2200), rate)


def _pocsag_cw(data21: int) -> int:
    cw = data21 << 10
    r = cw
    for i in range(21):
        if r & (1 << (30 - i)):
            r ^= 0x769 << (20 - i)
    cw |= r & 0x3FF
    return (cw << 1) | (bin(cw).count("1") & 1)


def pocsag_bits(address: int, text: str, function=3) -> list:
    """One POCSAG transmission: preamble, then batches holding the address codeword in its frame
    and the alphanumeric message (7-bit characters, least significant bit first)."""
    idle, sync = 0x7A89C197, 0x7CD215D8
    stream = [(ord(c) >> i) & 1 for c in text for i in range(7)]
    while len(stream) % 20:
        stream.append(0)
    msgs = []
    for i in range(0, len(stream), 20):
        v = 0
        for b in stream[i:i + 20]:
            v = (v << 1) | b
        msgs.append(_pocsag_cw((1 << 20) | v))
    words = [idle] * (2 * (address & 7)) + [_pocsag_cw(((address >> 3) << 2) | function)] + msgs + [idle]
    while len(words) % 16:
        words.append(idle)
    bits = [1, 0] * 288
    for i in range(0, len(words), 16):
        for w in [sync] + words[i:i + 16]:
            bits += [(w >> (31 - k)) & 1 for k in range(32)]
    return bits


def pocsag_wav(address: int, text: str, rate=22050, baud=1200, invert=False) -> bytes:
    """The page as the discriminator's sound: one level per bit."""
    s = [0.0] * int(rate * 0.2)
    t, n = 0.0, 0
    for b in pocsag_bits(address, text):
        level = (-0.6 if b else 0.6) * (-1 if invert else 1)
        t += rate / baud
        while n < t:
            s.append(level)
            n += 1
    return wav(s + [0.0] * int(rate * 0.2), rate)


def spectrum_text_wav(text: str, rate=16000, f_lo=1000.0, f_hi=7000.0, col=0.035, size=64) -> bytes:
    """A recording whose spectrogram shows the text: every lit pixel of the rendered line is a
    sine at its row's frequency for its column's time."""
    import numpy as np
    from PIL import Image, ImageDraw, ImageFont
    font = ImageFont.load_default(size=size)
    w = int(font.getlength(text)) + 16
    h = int(size * 1.3)
    img = Image.new("L", (w, h), 0)
    ImageDraw.Draw(img).text((8, 4), text, fill=255, font=font)
    a = np.asarray(img) > 128                                  # rows top (high frequency) to bottom
    n = int(rate * col)
    tt = np.arange(n) / rate
    freqs = f_hi - (f_hi - f_lo) * np.arange(h) / (h - 1)
    table = np.sin(2 * np.pi * freqs[:, None] * tt[None, :])   # h x n
    cols = []
    for x in range(w):
        lit = a[:, x]
        cols.append(table[lit].sum(axis=0) if lit.any() else np.zeros(n))
    sig = np.concatenate([np.zeros(n * 4)] + cols + [np.zeros(n * 4)])
    sig = sig / (np.abs(sig).max() or 1.0) * 0.8
    out = io.BytesIO()
    with wave.open(out, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(rate)
        wf.writeframes((sig * 32767).astype("<i2").tobytes())
    return out.getvalue()


def ook_pwm_cu8(payload: bytes, rate=250000, short=400e-6, long=1200e-6, gap=800e-6, repeats=3, pause=12e-3) -> bytes:
    """An OOK pulse-width transmission as rtl_sdr's unsigned 8-bit IQ: a short pulse is a 1, a long
    pulse a 0 (rtl_433's OOK_PWM), a fixed gap between pulses, the packet sent `repeats` times."""
    import numpy as np
    rnd = np.random.default_rng(3)
    env = [np.zeros(int(rate * 0.03))]
    for _ in range(repeats):
        for byte in payload:
            for i in range(8):
                bit = (byte >> (7 - i)) & 1
                env.append(np.ones(int(rate * (short if bit else long))))
                env.append(np.zeros(int(rate * gap)))
        env.append(np.zeros(int(rate * pause)))
    env.append(np.zeros(int(rate * 0.05)))
    e = np.concatenate(env)
    ph = 2 * np.pi * 25000.0 * np.arange(len(e)) / rate
    i = 127.5 + 100 * e * np.cos(ph) + rnd.normal(0, 1.0, len(e))
    q = 127.5 + 100 * e * np.sin(ph) + rnd.normal(0, 1.0, len(e))
    iq = np.empty(2 * len(e), dtype=np.uint8)
    iq[0::2] = np.clip(i, 0, 255).astype(np.uint8)
    iq[1::2] = np.clip(q, 0, 255).astype(np.uint8)
    return iq.tobytes()


# ---- bytes to carve, a disk, a program ---------------------------------------------------------

def carve_blob(members: list, seed=9, gap=3000) -> bytes:
    """Random bytes with the members between them, each at a 512-byte boundary."""
    rnd = random.Random(seed)
    out = bytearray(rnd.randbytes(gap))
    for m in members:
        out += b"\0" * (-len(out) % 512)
        out += m
        out += rnd.randbytes(gap)
    return bytes(out)


def fat12(live: dict, deleted: dict) -> bytes:
    """A 1.44 MB FAT12 floppy image: `live` files in the root folder, and `deleted` files whose
    entries are marked deleted (first name byte 0xE5) and whose clusters are freed, data in place.
    Names are 8.3, upper case."""
    spc, reserved, nfat, root_ents, spf, total = 1, 1, 2, 224, 9, 2880
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHBHHBHHHII", boot, 11, 512, spc, reserved, nfat, root_ents, total, 0xF0, spf, 18, 2, 0, 0)
    boot[36:39] = b"\x00\x00\x29"
    boot[39:43] = b"\x12\x34\x56\x78"
    boot[43:54] = b"HUNTRESS   "
    boot[54:62] = b"FAT12   "
    boot[510:512] = b"\x55\xaa"
    fat = [0xFF0, 0xFFF] + [0] * 2847
    root = bytearray(root_ents * 32)
    data_start = (reserved + nfat * spf) * 512 + root_ents * 32
    img = bytearray(total * 512)
    cluster, slot = 2, 0
    for files, gone in ((live, False), (deleted, True)):
        for name, body in files.items():
            stem, _, ext = name.partition(".")
            short = stem.upper().ljust(8)[:8].encode() + ext.upper().ljust(3)[:3].encode()
            n = max(1, -(-len(body) // 512))
            first = cluster
            for k in range(n):
                if not gone:
                    fat[cluster] = 0xFFF if k == n - 1 else cluster + 1
                off = data_start + (cluster - 2) * 512
                img[off:off + 512] = body[k * 512:(k + 1) * 512].ljust(512, b"\0")
                cluster += 1
            ent = bytearray(32)
            ent[0:11] = short
            if gone:
                ent[0] = 0xE5
            ent[11] = 0x20
            struct.pack_into("<HH", ent, 22, 0x6000, 0x5B48)      # 12:00:00, 2025-10-08
            struct.pack_into("<HI", ent, 26, first, len(body))
            root[slot * 32:(slot + 1) * 32] = ent
            slot += 1
    packed = bytearray()
    for i in range(0, len(fat) - 1, 2):
        a, b = fat[i], fat[i + 1]
        packed += bytes([a & 0xFF, ((a >> 8) & 0x0F) | ((b & 0x0F) << 4), (b >> 4) & 0xFF])
    packed = bytes(packed).ljust(spf * 512, b"\0")[:spf * 512]
    img[0:512] = boot
    for k in range(nfat):
        off = (reserved + k * spf) * 512
        img[off:off + spf * 512] = packed
    off = (reserved + nfat * spf) * 512
    img[off:off + len(root)] = root
    return bytes(img)


def tiny_elf(code: bytes, rodata: bytes = b"") -> bytes:
    """A static x86-64 ELF executable: one loadable segment, the entry point at `code`, `rodata`
    after it. It is only ever disassembled."""
    base = 0x400000
    body = code + rodata
    ehdr_size, phdr_size = 64, 56
    entry = base + ehdr_size + phdr_size
    total = ehdr_size + phdr_size + len(body)
    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8 + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, entry, ehdr_size, 0, 0,
                                                                         ehdr_size, phdr_size, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, total, total, 0x1000)
    return ehdr + phdr + body


def crc32(b: bytes) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF
