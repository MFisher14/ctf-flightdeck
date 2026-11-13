#!/usr/bin/env python3
"""Malware config extraction beyond HCFG, key recovery and ransomware sets (toolkit `malconfig`).

  .venv/bin/python solvers/common/malconfig.py <file> [...]      (the triage is solvers/toolkits/malconfig.py)

Offline, no Game Master request. This is the reader library; solvers/toolkits/malconfig.py is the
runner contract (signals, solve_set) and the command. Nothing here names an answer: every reader
returns facts read from the bytes, and a reading counts only when it VALIDATES (a CRC, a JSON
object that parses, a declared magic whose structure parses, a checksum of an address).

1. The container scanner, whole file, never by section name
   scan(data)      every validated config reading of a file, each once
   config(data)    the one reading, or None when none or more than one validates
   solvers/binary/hcfg.py is asked first and never copied. Then, over the file and over what its
   wrappers hold (base64, hex, UTF-16LE text, zlib and gzip streams, three levels deep):
     - single-byte XOR (key 0 is the plain object), found for all 256 keys in one pass;
     - repeating XOR of 2 to 8 bytes, key-free in a small block (the opening brace and quote give
       two key bytes, the JSON alphabet the others), by crib in a large one;
     - XOR, RC4 and AES (ECB, CBC) under a key found in the file: a printable or quoted literal, a
       hex or base64 literal, a 16/24/32-byte piece between NULs, the head or tail of the file,
       MD5/SHA-256 of a short literal; the IV is zero, the 16 bytes before the block, or a literal.
   A large file (over FULL bytes) is searched by needle only (the encoded HCFG magic and the
   encoded opening of an object) plus its first and last WINDOW bytes, so 67 MB cost under a second.

2. Family readers (every answer they lead to is unsure until a base confirms it)
   cobalt_strike(data)  beacon settings: the TLV block under any single-byte XOR
   us_strings(data)     the .NET #US heap, found by the BSJB magic; dotnet(data) adds the
                        resources through dnfile; xor_b64_pairs() reads Redline-style pairs
   netsupport(text)     client32.ini / NSM.LIC fields
   autoit(data)         the compiled-script marker, its subtype and offset (no extraction: see the doc)
   lua_constants(data)  Lua 5.1, 5.3 and 5.4 bytecode constant strings
   quarantine(data)     AV quarantine wrappers undone, kept only when a clean payload shows
   xor_pe(data)         an embedded PE under a repeating XOR of 1 to 8 bytes (DOS stub crib)

3. Pair helpers
   xor_key_from_pair(plain, cipher), keystream_from_magic(cipher, kind), footer_diff(blobs),
   decrypt_set(files): an encrypted set with a key in a footer, a key file, the note or a known magic

4. The ransom note
   note(text): onion v3 (checksum), wallets (base58check, bech32/bech32m, EIP-55, Monero), tox
   ids (checksum), victim id, appended extension, e-mail addresses

proof(plain) is what makes a decrypt a fact: a clean magic AND a parse of the structure behind it.
"""
import base64
import binascii
import hashlib
import importlib.util
import io
import json
import re
import struct
import sys
import time
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent

FULL = 4 * 1024 * 1024        # a view up to this size is searched whole
HUGE = 16 * 1024 * 1024       # above it only the encoded HCFG magic is looked for in the middle
WINDOW = 1 * 1024 * 1024      # of a larger one: this much of its head and of its tail
SMALL = 64 * 1024             # key-free multi-byte XOR, whole-view key trials
OBJECT = 64 * 1024            # the longest config read from one place
INFLATE = 1 << 20             # bytes one compressed stream may decode to
MAX_VIEWS = 400               # decoded wrappers of one file
MAX_KEYS = 4096               # key candidates of one file
MAX_TRIES = 600               # full validations of one search in one view
DEPTH = 3
ARROW = " -> "


def _load_hcfg():
    """solvers/binary/hcfg.py under a private name: its folder is not put on sys.path, where its
    generic.py and facts.py would shadow another lane's."""
    name = "_malconfig_hcfg"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, HERE.parent / "binary" / "hcfg.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    sys.modules[name] = mod
    return mod


hcfg = _load_hcfg()

try:                                    # pycryptodomex; pycryptodome as the other spelling
    from Cryptodome.Cipher import AES, ARC4
    from Cryptodome.Hash import keccak as _keccak
except ImportError:                     # pragma: no cover
    try:
        from Crypto.Cipher import AES, ARC4
        from Crypto.Hash import keccak as _keccak
    except ImportError:
        AES = ARC4 = _keccak = None


# ---- bytes ---------------------------------------------------------------------------------------------

def xor(blob: bytes, key: bytes) -> bytes:
    """`blob` XOR-ed with `key` repeated from the blob's first byte."""
    n = len(blob)
    if not n or not key:
        return bytes(blob)
    stream = (bytes(key) * (n // len(key) + 1))[:n]
    return (int.from_bytes(blob, "little") ^ int.from_bytes(stream, "little")).to_bytes(n, "little")


def delta(data: bytes, n: int = 1) -> bytes:
    """data[i] ^ data[i+n] for every i: a repeating XOR key of n bytes (or of a divisor) is gone.
    The last n bytes of the result are not differences; callers stop n short."""
    whole = int.from_bytes(data, "little")
    return (whole ^ (whole >> (8 * n))).to_bytes(len(data), "little")


def rc4(key: bytes, blob: bytes) -> bytes:
    if ARC4 is not None and 1 <= len(key) <= 256:
        try:
            return ARC4.new(bytes(key)).decrypt(bytes(blob))
        except ValueError:
            pass
    s, j, out = list(range(256)), 0, bytearray()
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i], s[j] = s[j], s[i]
    i = j = 0
    for c in blob:
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) & 255])
    return bytes(out)


def unpad(plain: bytes):
    """PKCS#7 removed, or None when the padding is not PKCS#7."""
    if not plain:
        return None
    n = plain[-1]
    if 1 <= n <= 16 and plain.endswith(bytes([n]) * n):
        return plain[:-n]
    return None


def aes_cbc(key: bytes, iv: bytes, blob: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).decrypt(blob[:len(blob) // 16 * 16])


def aes_ecb(key: bytes, blob: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(blob[:len(blob) // 16 * 16])


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---- proof: a clean magic and a parse -------------------------------------------------------------------

def _png(d):
    if d[:8] != b"\x89PNG\r\n\x1a\n":
        return False
    o, seen = 8, 0
    while o + 12 <= len(d):
        n, kind = struct.unpack_from(">I4s", d, o)
        if o + 12 + n > len(d) or zlib.crc32(d[o + 4:o + 8 + n]) & 0xFFFFFFFF != struct.unpack_from(">I", d, o + 8 + n)[0]:
            return False
        seen += 1
        o += 12 + n
        if kind == b"IEND":
            return o == len(d) and seen >= 2
    return False


def _pe_size(d):
    """Bytes of the PE image on disk by its section table, or 0 when `d` is not a PE that parses."""
    try:
        if d[:2] != b"MZ":
            return 0
        off = struct.unpack_from("<I", d, 0x3C)[0]
        if off > len(d) - 24 or d[off:off + 4] != b"PE\x00\x00":
            return 0
        nsec, opt = struct.unpack_from("<H", d, off + 6)[0], struct.unpack_from("<H", d, off + 20)[0]
        if not 1 <= nsec <= 96 or struct.unpack_from("<H", d, off + 24)[0] not in (0x10B, 0x20B):
            return 0
        table, end = off + 24 + opt, 0
        for i in range(nsec):
            size, ptr = struct.unpack_from("<II", d, table + 40 * i + 16)
            end = max(end, ptr + size if ptr else 0)
        end = max(end, table + 40 * nsec)
        return end if end <= len(d) else 0
    except (struct.error, IndexError):
        return 0


def _elf(d):
    try:
        if d[:4] != b"\x7fELF" or d[4] not in (1, 2) or d[5] not in (1, 2) or d[6] != 1:
            return False
        e = "<" if d[5] == 1 else ">"
        etype, machine, version = struct.unpack_from(e + "HHI", d, 16)
        if version != 1 or etype not in (1, 2, 3, 4):
            return False
        if d[4] == 2:
            phoff, shoff = struct.unpack_from(e + "QQ", d, 32)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", d, 54)
        else:
            phoff, shoff = struct.unpack_from(e + "II", d, 28)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", d, 42)
        if not (phoff + phentsize * phnum <= len(d) and shoff + shentsize * shnum <= len(d) and (phnum or shnum)):
            return False
        return "exact" if shnum and shoff + shentsize * shnum == len(d) else "loose"
    except (struct.error, IndexError):
        return False


def _zip(d):
    if d[:4] != b"PK\x03\x04":
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(d)) as z:
            infos = z.infolist()
            if not infos:
                return False
            eocd = d.rfind(b"PK\x05\x06")
            if eocd < 0 or eocd + 22 + struct.unpack_from("<H", d, eocd + 20)[0] != len(d):
                return False                # the end-of-directory record must end the file
            if any(i.flag_bits & 1 for i in infos):
                return True                 # encrypted members: the directory parsed, the CRCs cannot be read
            return sum(i.file_size for i in infos) > 64 * 1024 * 1024 or z.testzip() is None
    except Exception:
        return False


def _jpeg(d):
    if d[:3] != b"\xff\xd8\xff" or d[-2:] != b"\xff\xd9":
        return False
    o = 2
    try:
        while o + 4 <= len(d) and d[o] == 0xFF:
            m, n = d[o + 1], struct.unpack_from(">H", d, o + 2)[0]
            if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
                # the frame header: its length is 8 + 3 per component, a sample precision, a size
                if o + 2 + n > len(d) or n < 11:
                    return False
                prec, height, width, comps = struct.unpack_from(">BHHB", d, o + 4)
                return n == 8 + 3 * comps and prec in (8, 12, 16) and width > 0 and 1 <= comps <= 4
            if m == 0xDA or n < 2:
                return False
            o += 2 + n
    except (struct.error, IndexError):
        pass
    return False


def _gif(d):
    """True when `d` is a GIF whose blocks walk from the header to a trailer that is the file's
    last byte, with one image or more. (The magic and a last ';' alone are met by one wrong
    decrypt in 256: the six bytes of the magic give a six-byte XOR key away for any file.)"""
    if d[:6] not in (b"GIF87a", b"GIF89a") or len(d) < 14:
        return False
    try:
        flags = d[10]
        o = 13 + (3 << ((flags & 7) + 1) if flags & 0x80 else 0)
        images = 0

        def sub(o):
            while True:
                n = d[o]
                o += 1 + n
                if n == 0:
                    return o

        while True:
            b = d[o]
            if b == 0x3B:
                return o + 1 == len(d) and images >= 1
            if b == 0x21:
                o = sub(o + 2)
            elif b == 0x2C:
                w, h, f = struct.unpack_from("<HHB", d, o + 5)
                if not (w and h):
                    return False
                o += 10 + (3 << ((f & 7) + 1) if f & 0x80 else 0)
                if not 2 <= d[o] <= 11:         # the LZW minimum code size
                    return False
                o = sub(o + 1)
                images += 1
            else:
                return False
    except (IndexError, struct.error):
        return False


def _pdf(d):
    return d[:5] == b"%PDF-" and d.rstrip(b"\r\n \t").endswith(b"%%EOF") and len(d) - len(d.rstrip(b"\r\n \t")) <= 2 \
        and (b"startxref" in d[-2048:] or b"/Root" in d)


def _text(d):
    if len(d) < 16 or b"\x00" in d:
        return False
    try:
        t = d.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(c.isprintable() or c in "\r\n\t" for c in t) and sum(c.isalnum() or c == " " for c in t) >= 0.6 * len(t)


def _json(d):
    try:
        obj = json.loads(d.decode("utf-8"))
    except Exception:
        return None
    return obj if isinstance(obj, (dict, list)) and obj else None


def proof(plain: bytes):
    """The kind of file `plain` is when its magic is clean and its structure parses, else None.
    The kinds in STRONG are exact about the file's last byte as well, so a decrypt cut at the
    wrong place does not pass: png (every chunk CRC, IEND last), zip (every member's CRC, the
    end-of-directory record last), pdf (%%EOF last), jpeg (a frame header, FFD9 last), gif, pe
    and elf (the section table ends the file), gzip and zlib (the stream inflates to its end),
    sqlite (page size times page count), json. The others are weak: pe_loose, elf_loose,
    sqlite_loose, gzip_loose and zlib_loose (NULs follow the stream), ole_loose (the structure parses but does not say where the file ends) and
    text (strict UTF-8, all printable, 16 bytes or more)."""
    d = bytes(plain)
    if _png(d):
        return "png"
    if _zip(d):
        return "zip"
    if _pdf(d):
        return "pdf"
    if _jpeg(d):
        return "jpeg"
    if _gif(d):
        return "gif"
    size = _pe_size(d)
    if size:
        return "pe" if size == len(d) else "pe_loose"
    elf = _elf(d)
    if elf:
        return "elf" if elf == "exact" else "elf_loose"
    if d[:3] == b"\x1f\x8b\x08" or (d[:1] == b"\x78" and d[1:2] in (b"\x01", b"\x5e", b"\x9c", b"\xda")):
        try:
            o = zlib.decompressobj(47)
            o.decompress(d, 64 * INFLATE)
            if o.eof and not o.unused_data.strip(b"\x00"):
                # NULs after the stream (a zero-padded block cipher) are not the file: weak
                return ("gzip" if d[0] == 0x1F else "zlib") + ("_loose" if o.unused_data else "")
        except zlib.error:
            pass
    if d[:16] == b"SQLite format 3\x00" and len(d) >= 100:
        page = struct.unpack_from(">H", d, 16)[0]
        page = 65536 if page == 1 else page
        if page in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536) and len(d) % page == 0:
            return "sqlite" if struct.unpack_from(">I", d, 28)[0] * page == len(d) else "sqlite_loose"
    if d[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and len(d) >= 512 and struct.unpack_from("<H", d, 30)[0] in (9, 12):
        return "ole_loose"
    if d[:1] in (b"{", b"[") and _json(d.strip()) is not None:
        return "json"
    if _text(d):
        return "text"
    return None


STRONG = ("png", "zip", "pdf", "jpeg", "gif", "pe", "elf", "gzip", "zlib", "sqlite", "json")

# What the start of a file of a kind is known to be (the keystream a known magic gives away).
MAGIC = {
    "png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "pdf": b"%PDF-1.", "zip": b"PK\x03\x04", "gif": b"GIF89a",
    "jpeg": b"\xff\xd8\xff", "pe": b"MZ", "elf": b"\x7fELF", "gzip": b"\x1f\x8b\x08",
    "sqlite": b"SQLite format 3\x00", "ole": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "rtf": b"{\\rtf1", "xml": b"<?xml ",
    "7z": b"7z\xbc\xaf\x27\x1c", "bmp": b"BM",
}
EXT_KIND = {"png": "png", "pdf": "pdf", "zip": "zip", "docx": "zip", "xlsx": "zip", "pptx": "zip", "jar": "zip",
            "apk": "zip", "odt": "zip", "gif": "gif", "jpg": "jpeg", "jpeg": "jpeg", "exe": "pe", "dll": "pe",
            "elf": "elf", "gz": "gzip", "db": "sqlite", "sqlite": "sqlite", "doc": "ole", "xls": "ole", "ppt": "ole",
            "msi": "ole", "rtf": "rtf", "xml": "xml", "7z": "7z", "bmp": "bmp"}


# ---- validation of a config reading -----------------------------------------------------------------------

_INI_LINE = re.compile(r"^\s*([A-Za-z_][\w .-]{0,48}?)\s*[=:]\s*(.*?)\s*$")


def ini(text: str) -> dict:
    """{'section.key' or 'key': value} of key=value lines ([section] headers kept); {} when under
    three such lines or when other lines outnumber them."""
    out, section, other = {}, "", 0
    for line in text.splitlines():
        s = line.strip()
        if not s or s[:1] in ";#":
            continue
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1].strip()
            continue
        m = _INI_LINE.match(line) if "=" in line else None
        if not m:
            other += 1
            continue
        out[(section + "." if section else "") + m.group(1).strip()] = m.group(2)
    return out if len(out) >= 3 and other * 4 <= len(out) else {}


_DECODER = json.JSONDecoder()


def _object(plain: bytes):
    """(object, bytes used) of the JSON object that opens `plain`, or None. Read by the json
    module's own scanner (a byte loop cost 3 ms per 64 KB), then strictly as UTF-8."""
    try:
        _, end = _DECODER.raw_decode(plain[:OBJECT].decode("latin-1"))      # one character per byte: `end` is in bytes
        obj = json.loads(plain[:end].decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    return (obj, end) if isinstance(obj, dict) and obj else None


def settle(plain: bytes, bounded: bool = False, depth: int = 0):
    """What a decoded block holds, read from its first byte: (kind, object, bytes used) or None.
    kind is `json` (a non-empty object; the bytes after it are ignored unless `bounded`, where
    only padding or white space may follow), or `ini` (bounded only: key=value text). A zlib or
    gzip stream and a base64 or UTF-16LE text of such a block are opened first, two levels."""
    if not plain:
        return None
    head = plain[:1]
    if head == b"{" and plain[1:2] != b"\x00":
        got = _object(plain)
        if got:
            rest = plain[got[1]:]
            if not bounded or not rest.strip(b" \t\r\n\x00") or (len(rest) <= 16 and rest == rest[-1:] * rest[-1]):
                return "json", got[0], got[1]
        return None
    if depth >= 2:
        return None
    if plain[:3] == b"\x1f\x8b\x08" or (head == b"\x78" and plain[1:2] in (b"\x01", b"\x5e", b"\x9c", b"\xda")):
        try:
            inner = zlib.decompressobj(47).decompress(plain[:OBJECT], INFLATE)
        except zlib.error:
            return None
        got = settle(inner, True, depth + 1)
        return (got[0], got[1], len(plain)) if got else None
    if plain[:3] in (b"eyJ", b"eyI", b"ewo", b"ew0", b"eyA"):
        run = re.match(rb"[A-Za-z0-9+/]+={0,2}", plain[:2 * OBJECT]).group()
        inner = _b64(run)
        got = settle(inner, True, depth + 1) if inner else None
        return (got[0], got[1], len(run)) if got else None
    if plain[:2] == b"{\x00" and len(plain) >= 8:
        try:
            m = re.match(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00)+", plain[:OBJECT * 2])
            inner = m.group().decode("utf-16-le").encode("utf-8")
        except (UnicodeError, AttributeError):
            return None
        got = settle(inner, bounded, depth + 1)
        return (got[0], got[1], got[2] * 2) if got else None
    if bounded:
        body = unpad(plain) or plain.rstrip(b"\x00")
        if _text(body):
            pairs = ini(body.decode("utf-8"))
            if pairs:
                return "ini", pairs, len(plain)
    return None


# Plaintext openings a keyed search looks for: an object, its base64, a compressed stream.
STARTS = (b'{"', b"{\n", b"{\r", b"{ ", b"eyJ", b"ewo", b"\x1f\x8b\x08", b"x\x9c", b"x\xda")


# ---- wrappers: the views of a file ------------------------------------------------------------------------

_B64 = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
_B64URL = re.compile(rb"[A-Za-z0-9_-]{24,}={0,2}")
_HEX = re.compile(rb"(?:[0-9a-fA-F]{2}){12,}")
_WIDE = re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){12,}")
_ZMAGIC = re.compile(rb"\x1f\x8b\x08|\x78[\x01\x5e\x9c\xda]")
def _stable(word: bytes) -> tuple:
    """The base64 spellings of `word` at the three phases of a base64 text: the characters that
    are the same whatever stands before and after it."""
    out = []
    for phase in range(3):
        encs = [base64.b64encode(bytes([x]) * phase + word + bytes([y]) * 3) for x in (0, 0xFF, 0x55) for y in (0, 0xFF, 0xAA)]
        same = bytes(c[0] if len(set(c)) == 1 else 0 for c in zip(*encs))
        out.append(max(same.split(b"\x00"), key=len))
    return tuple(o for o in out if len(o) >= 3)


# Needles of a large file: the encoded HCFG magic and the encoded opening of an object.
# In each tuple the HCFG seeds come first: _HCFG_ONLY of them are all a file over HUGE is searched for.
_B64_SEEDS = _stable(b"HCFG") + (b"eyJ", b"eyI", b"ewo")
_HEX_SEEDS = (b"48434647", b"7b22", b"7B22", b"7b0a", b"7B0A")
_WIDE_SEEDS = (b"H\x00C\x00F\x00G\x00",) + tuple(bytes(x for c in sd for x in (c, 0)) for sd in _stable(b"HCFG")) + \
    (b"{\x00\"\x00", b"e\x00y\x00J\x00")
_HCFG_ONLY = {id(_B64_SEEDS): len(_stable(b"HCFG")), id(_HEX_SEEDS): 1, id(_WIDE_SEEDS): 1}
_B64SET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
_HEXSET = frozenset(b"0123456789abcdefABCDEF")
_WIDESET = frozenset(range(0x20, 0x7F)) | frozenset(b"\t\r\n")


def _b64(run: bytes):
    run = run.rstrip(b"=")
    run = run[:len(run) - (1 if len(run) % 4 == 1 else 0)]
    try:
        return base64.b64decode(run + b"=" * (-len(run) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _around(data: bytes, seeds, cls, step: int, rx):
    """The runs of a large file that hold one of the seeds: each seed is a find, and the run is
    read back from the hit to where its alphabet began."""
    seen = set()
    if len(data) > HUGE:
        seeds = seeds[:_HCFG_ONLY[id(seeds)]]
    for seed in seeds:
        at, n = data.find(seed), 0
        while at >= 0 and n < 32:
            n += 1
            s, lim = at, max(0, at - 2 * OBJECT)
            if step == 1:
                while s > lim and data[s - 1] in cls:
                    s -= 1
            else:
                while s - 2 >= lim and data[s - 2] in cls and data[s - 1] == 0:
                    s -= 2
            m = rx.match(data, s, min(len(data), s + 8 * OBJECT))
            nxt = at + 1
            if m is not None and m.end() > at:
                nxt = m.end()
                if s not in seen:
                    seen.add(s)
                    yield m
            at = data.find(seed, nxt)


def _runs(data: bytes, large: bool):
    """(how, offset, decoded bytes) of every wrapper standing in `data`, one level."""
    for m in (_around(data, _WIDE_SEEDS, _WIDESET, 2, _WIDE) if large else _WIDE.finditer(data)):
        yield "utf16le", m.start(), m.group()[::2]
    for m in (_around(data, _HEX_SEEDS, _HEXSET, 1, _HEX) if large else _HEX.finditer(data)):
        try:
            yield "hex", m.start(), binascii.unhexlify(m.group())
        except binascii.Error:
            pass
    for m in (_around(data, _B64_SEEDS, _B64SET, 1, _B64) if large else _B64.finditer(data)):
        run = m.group()
        if _HEX.fullmatch(run):
            continue
        for shift in (range(4) if large else (0,)):     # a literal glued to a character before it
            got = _b64(run[shift:])
            if got and len(got) >= 12:
                yield "base64", m.start() + shift, got
    if not large:
        for m in _B64URL.finditer(data):
            run = m.group()
            if b"-" in run or b"_" in run:
                got = _b64(run.replace(b"-", b"+").replace(b"_", b"/"))
                if got and len(got) >= 12:
                    yield "base64url", m.start(), got
        n = 0
        for m in _ZMAGIC.finditer(data):
            if n >= 64:
                break
            try:
                o = zlib.decompressobj(47)
                got = o.decompress(data[m.start():m.start() + 4 * OBJECT], INFLATE)
            except zlib.error:
                continue
            if len(got) >= 12 and (o.eof or len(got) >= 64):
                n += 1
                yield ("gzip" if m.group()[0] == 0x1F else "zlib"), m.start(), got


def views(data: bytes, deadline=None):
    """[(how, offset in the file of the outermost wrapper, bytes, bounded)]: the file itself first
    (how ''), then what its wrappers decode to, breadth first, DEPTH levels, each block once."""
    out = [("", 0, data, len(data) <= SMALL)]
    seen = {hash(data)}
    i = 0
    while i < len(out) and len(out) < MAX_VIEWS:
        how, off, blob, _ = out[i]
        i += 1
        if how.count(">") + (1 if how else 0) >= DEPTH or (deadline and time.monotonic() > deadline):
            continue
        for kind, at, inner in _runs(blob, len(blob) > FULL):
            h = hash(inner)
            if h in seen:
                continue
            seen.add(h)
            out.append((f"{how}>{kind}" if how else kind, off if how else at, inner, True))
            if len(out) >= MAX_VIEWS:
                break
    return out


# ---- XOR without a key ---------------------------------------------------------------------------------------

_IDENT = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-. $@/")
_SPACE = frozenset(b" \t\r\n")
_COMMON = frozenset(b'abcdefghijklmnopqrstuvwxyz0123456789":,_.- ')
_JSONCH = frozenset(range(0x20, 0x7F)) | _SPACE
_OPEN1 = re.compile(b"[" + b"".join(re.escape(bytes([0x7B ^ c])) for c in b'" \t\r\n') + b"]")


def _spans(data: bytes):
    """The parts of a view that are searched byte by byte: all of it, or its head and its tail."""
    if len(data) <= FULL:
        return [(0, len(data))]
    return [(0, WINDOW), (len(data) - WINDOW, len(data))]


def xor1_objects(data: bytes, tries: int = MAX_TRIES):
    """(offset, key, kind, object, used) for every object that stands under a single-byte XOR
    (key 0: in the clear). One pass for all keys: in data[i]^data[i+1] the key is gone, and an
    object opens with a brace followed by a quote or white space."""
    out, done = [], {}
    for lo, hi in _spans(data):
        part = data[lo:hi]
        d = delta(part)
        n = len(part)
        for m in _OPEN1.finditer(d, 0, max(0, n - 4)):
            o = m.start()
            k = part[o] ^ 0x7B
            if done.get(k, -1) > lo + o:
                continue
            j = o + 1
            while j < n and j - o < 12 and part[j] ^ k in _SPACE:
                j += 1
            if j + 2 >= n or part[j] ^ k != 0x22 or part[j + 1] ^ k not in _IDENT:
                continue
            j += 1
            e = j
            while e < n and e - j < 64 and part[e] ^ k in _IDENT:
                e += 1
            if e >= n or part[e] ^ k != 0x22:
                continue
            e += 1
            while e < n and part[e] ^ k in _SPACE:
                e += 1
            if e >= n or part[e] ^ k != 0x3A:
                continue
            if tries <= 0:
                return out
            tries -= 1
            got = settle(hcfg._xor(part[o:o + OBJECT], k))
            if got:
                out.append((lo + o, k, got[0], got[1], got[2]))
                done[k] = lo + o + got[2]
    return out


CRIBS = tuple(b'{"' + w for w in (
    b'campaign":"', b'campaign"', b'c2"', b'c2_', b'config"', b'host"', b'server"', b'version"', b'id"', b'name"',
    b'mutex"', b'key"', b'url"', b'family"', b'build"', b'bot', b'sleep"', b'cnc"', b'domain"', b'ip"', b'port"',
    b'type"', b'target"', b'payload"', b'schema"', b'magic"', b'v":', b'cfg"', b'botnet"', b'group"', b'tag"'))


def xorn_cribs(data: bytes, sizes=(2, 3, 4), tries: int = MAX_TRIES):
    """(offset, key bytes, kind, object, used): objects under a repeating XOR of 2 to 4 bytes that
    open with one of CRIBS. In data[i]^data[i+n] an n-byte key is gone, so each crib is one find."""
    out, seen = [], set()
    for lo, hi in _spans(data):
        part = data[lo:hi]
        for n in sizes:
            d = delta(part, n)
            for crib in CRIBS:
                if len(crib) < n + 3:
                    continue
                needle = bytes(a ^ b for a, b in zip(crib, crib[n:]))
                at = d.find(needle, 0, len(part) - n)
                while at >= 0 and tries > 0:
                    if (lo + at, n) not in seen:
                        seen.add((lo + at, n))
                        key = bytes(a ^ b for a, b in zip(part[at:at + n], crib))
                        if len(set(key)) > 1 or n == 1:
                            tries -= 1
                            got = settle(xor(part[at:at + OBJECT], key))
                            if got:
                                out.append((lo + at, key, got[0], got[1], got[2]))
                    at = d.find(needle, at + 1, len(part) - n)
    return out


def _class(xored: int) -> bytes:
    return b"[" + b"".join(re.escape(bytes([c ^ xored])) for c in sorted(_JSONCH)) + b"]"


_FREE_RX = {second: re.compile(_class(0x7B) + _class(second)) for second in (0x22, 0x0A, 0x20, 0x0D)}


def xorn_free(data: bytes, sizes=(2, 3, 4, 5, 6, 7, 8), tries: int = 200):
    """(offset, key bytes, kind, object, used): objects under a repeating XOR of 2 to 8 bytes in a
    small block (SMALL bytes for 2 to 4, a quarter of it for longer keys), with no crib. The
    opening brace and quote give two key bytes; a key byte in another place is one that turns
    every byte of its place into JSON text; the object must then parse."""
    out, n_data, seen = [], len(data), set()
    for n in sizes:
        if n_data > (SMALL if n <= 4 else SMALL // 4) or n_data < 2 * n + 8:
            continue
        d = delta(data, n)
        left = tries                    # per key length: a 4-byte key's text fills the 2-byte search with near misses
        for second in (0x22, 0x0A, 0x20, 0x0D):
            rx = _FREE_RX[second]
            pos = 0
            while left > 0:
                m = rx.search(d, pos, n_data - n)
                if not m:
                    break
                o = m.start()
                pos = o + 1
                k0, k1 = data[o] ^ 0x7B, data[o + 1] ^ second
                rows, most = 1, min(64, (n_data - o - 2) // n)
                while rows < most and data[o + rows * n] ^ k0 in _JSONCH and data[o + rows * n + 1] ^ k1 in _JSONCH:
                    rows += 1                   # how far the two known key bytes give JSON text
                if rows < 5:
                    continue
                slots = [[k0], [k1]]
                for s in range(2, n):
                    # The last row counted may be cut short by the end of the object, or be chance.
                    col = data[o + s:o + (rows - 1) * n:n]
                    # XOR with a small difference keeps most text printable, so some thirty bytes
                    # would pass a printable test; the right one turns the column into the
                    # commonest JSON characters. The parse below is what decides.
                    ks = sorted(range(256), key=lambda k: -sum(1 for c in col if c ^ k in _COMMON))
                    slots.append(ks[:3 if n <= 5 else 2])
                keys = [b""]
                for ks in slots:
                    keys = [p + bytes([k]) for p in keys for k in ks]
                for key in keys:
                    if len(set(key)) == 1 or (n % 2 == 0 and key[:n // 2] == key[n // 2:]) or (o, key) in seen:
                        continue                # a shorter key: found under its own length
                    if n == 6 and (key[:2] * 3 == key or key[:3] * 2 == key) or n == 8 and key[:2] * 4 == key:
                        continue
                    seen.add((o, key))
                    left -= 1
                    got = settle(xor(data[o:o + OBJECT], key))
                    if got:
                        out.append((o, key, got[0], got[1], got[2]))
    return out


# ---- keys found in the file ------------------------------------------------------------------------------------

_STR = re.compile(rb"[\x21-\x7e][\x20-\x7e]{4,62}[\x21-\x7e]|(?<=\x00)[\x21-\x7e]{4,5}(?=\x00)")
_QUOTED = re.compile(rb"\"([^\"\\\r\n]{4,64})\"|'([^'\\\r\n]{4,64})'")
_WSTR = re.compile(rb"(?:[\x21-\x7e]\x00)(?:[\x20-\x7e]\x00){2,62}(?:[\x21-\x7e]\x00)")
_PIECE = re.compile(rb"(?:(?<=\x00)|\A)[^\x00]{16,32}(?=\x00|\Z)")
_HEXKEY = re.compile(rb"(?:[0-9a-fA-F]{2}){4,64}")
_HEXRUN = re.compile(rb"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,64}(?![0-9a-fA-F])")
_B64RUN = re.compile(rb"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{22}==|[A-Za-z0-9+/]{32}|[A-Za-z0-9+/]{43}=)(?![A-Za-z0-9+/=])")


def key_candidates(data: bytes, limit: int = MAX_KEYS) -> list:
    """[(key bytes, offset, kind)] of what in the file could be a key, in file order, each once:
    quoted and printable literals (4 to 64 characters; also as UTF-16LE), what a hex literal or a
    base64 literal of 16/24/32 bytes decodes to, pieces of exactly 16, 24 or 32 bytes between
    NULs, and the first and last 16 and 32 bytes of the file."""
    out, seen = [], set()
    gather = 8 * limit

    def add(key, at, kind):
        key = bytes(key)
        if 1 <= len(key) <= 256 and key not in seen and len(set(key)) > 1:
            seen.add(key)
            out.append((key, at, kind))

    for n in (16, 32):
        if len(data) > 2 * n:
            add(data[:n], 0, "head")
            add(data[-n:], len(data) - n, "tail")
    for lo, hi in _spans(data):
        part = data[lo:hi]
        found = [(m.start(1) if m.group(1) is not None else m.start(2), m.group(1) or m.group(2), "quoted")
                 for m in _QUOTED.finditer(part)]
        found += [(m.start(), m.group(), "string") for m in _STR.finditer(part)]
        found += [(m.start(), m.group()[::2], "wide") for m in _WSTR.finditer(part)]
        found.sort(key=lambda t: t[0])
        for at, s, kind in found:
            if len(out) >= gather:
                break
            add(s, lo + at, kind)
            if _HEXKEY.fullmatch(s):
                add(binascii.unhexlify(s), lo + at, "hex")
            if len(s) in (24, 32, 44) and re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", s):
                got = _b64(s)
                if got and len(got) in (16, 24, 32):
                    add(got, lo + at, "base64")
        for m in _PIECE.finditer(part):
            if len(out) >= gather:
                break
            if len(m.group()) in (16, 24, 32) and len(set(m.group())) >= 8:
                add(m.group(), lo + m.start(), "piece")
        for m in _HEXRUN.finditer(part):                # a hex or base64 literal inside a longer line (key=0a1b...)
            if len(out) >= gather:
                break
            add(binascii.unhexlify(m.group()), lo + m.start(), "hex")
        for m in _B64RUN.finditer(part):
            if len(out) >= gather:
                break
            got = _b64(m.group())
            if got and len(got) in (16, 24, 32) and len(set(got)) >= 8:
                add(got, lo + m.start(), "base64")
    # When a file has more than `limit`: what was written as a key (a quoted, hex or base64
    # literal, a 16/24/32-byte piece) stands before the plain strings; file order within each.
    rank = {"quoted": 0, "hex": 0, "base64": 0, "piece": 0, "head": 0, "tail": 0, "wide": 1, "string": 2}
    out.sort(key=lambda t: rank.get(t[2], 3))
    return out[:limit]


NEAR = ("quoted", "hex", "base64", "piece", "head", "tail", "given")     # kinds written as a key


def _aes_keys(keys: list, limit: int = 48) -> list:
    """[(key, offset, kind)] of 16, 24 and 32 bytes: the candidates of that length, then MD5 and
    SHA-256 of the short literals."""
    out = [(k, at, kind) for k, at, kind in keys if len(k) in (16, 24, 32)][:limit]
    for k, at, kind in keys:
        if len(out) >= limit:
            break
        if kind in ("quoted", "string", "wide") and 4 <= len(k) <= 40 and len(k) not in (16, 24, 32):
            out.append((hashlib.sha256(k).digest(), at, "sha256(" + kind + ")"))
            out.append((hashlib.md5(k).digest(), at, "md5(" + kind + ")"))
    return out[:limit]


class KeySet:
    """The key candidates of one file, with the first keystream bytes of each worked out once."""

    def __init__(self, cands: list):
        self.cands = list(cands)
        self.items = []
        for key, at, kind in self.cands:
            streams = {}
            if len(key) >= 2:
                streams["xor"] = (key * (8 // len(key) + 1))[:8]
            if ARC4 is not None:
                streams["rc4"] = rc4(key, bytes(8))
            self.items.append((key, at, kind, streams))
        self.aes = _aes_keys(self.cands) if AES is not None else []
        self.ivs = [k for k, _, _ in self.cands if len(k) == 16][:6]


_FIRST = re.compile(b"[" + b"".join(sorted({re.escape(s[:1]) for s in STARTS})) + b"]")
_PRINT3 = frozenset(range(0x20, 0x7F)) | frozenset(b"\t\r\n")
_ALIGNED = 16 * (OBJECT // 16)


def keyed(blob: bytes, keys: KeySet, mode: str, deadline=None) -> list:
    """Config readings of `blob` under the key candidates:
    [(offset, cipher, key, iv, kind, object, plain)].

    XOR with the literal, RC4, AES-ECB and AES-CBC (IV zero, the 16 bytes before the block, a
    16-byte candidate, the key's first 16 bytes). `mode`:
      'literal'  the blob is what a wrapper decoded: it is read from its first byte only (after a
                 16-byte IV as well), and key=value text counts as well as an object;
      'small'    a file up to SMALL bytes: as 'literal', and an object is looked for near the key;
      'file'     a larger file: an object is looked for near the key.
    Near is 32 KB either side for what was written as a key (a quoted, hex or base64 literal, a
    16/24/32-byte piece between NULs, the head or tail of the file), 1 KB for any other string,
    4 KB for AES; a blob up to 8 KB is searched whole.
    Each key costs one keystream prefix or one block decryption, searched for the openings in
    STARTS; only a hit is decoded in full, and it must settle."""
    out, n = [], len(blob)
    if n < 8:
        return out
    whole_first = mode in ("literal", "small")
    head = blob[:3]
    for key, at, kind, streams in keys.items:
        if deadline and time.monotonic() > deadline:
            return out
        reach = 32768 if kind in NEAR else 1024
        lo, hi = (0, n) if n <= 8192 else (max(0, at - reach), min(n, at + reach))
        for cipher, ks in streams.items():
            dec = (lambda part: xor(part, key)) if cipher == "xor" else (lambda part: rc4(key, part))
            if whole_first:
                x = bytes(a ^ b for a, b in zip(head, ks))
                if x.startswith(STARTS) or all(c in _PRINT3 for c in x):
                    plain = dec(blob[:OBJECT])
                    got = settle(plain, True)
                    if got:
                        out.append((0, cipher, key, None, got[0], got[1], plain[:got[2]]))
            if mode == "literal":
                continue
            for start in STARTS:
                needle = bytes(a ^ b for a, b in zip(start, ks))
                o = blob.find(needle, max(lo, 1 if whole_first else 0), hi)
                hits = 0
                while o >= 0 and hits < 8:
                    hits += 1
                    plain = dec(blob[o:o + OBJECT])
                    got = settle(plain)
                    if got:
                        out.append((o, cipher, key, None, got[0], got[1], plain[:got[2]]))
                    o = blob.find(needle, o + 1, hi)
    zero = bytes(16)
    for key, at, _ in keys.aes:
        if deadline and time.monotonic() > deadline:
            return out
        ecb = AES.new(key, AES.MODE_ECB)
        if whole_first and n % 16 == 0 and n >= 16:
            part = blob[:_ALIGNED]
            dec = ecb.decrypt(part)
            trials = [("aes_ecb", None, 0, dec)]
            for iv in dict.fromkeys([zero, key[:16]] + keys.ivs):
                trials.append(("aes_cbc", iv, 0, xor(dec, iv + part[:-16])))
            if len(part) >= 32:
                trials.append(("aes_cbc", part[:16], 16, xor(dec[16:], part[:-16])))
            for cipher, iv, o, plain in trials:
                got = settle(plain, True)
                if got:
                    out.append((o, cipher, key, iv, got[0], got[1], plain[:got[2]]))
        if mode == "literal":
            continue
        lo, hi = (0, n) if n <= 8192 else (max(0, at - 4096), min(n, at + 4096))
        for a in range(16):
            part = blob[lo + a:hi]
            part = part[:len(part) // 16 * 16]
            m = len(part)
            if m < 16:
                continue
            dec = ecb.decrypt(part)
            modes = [("aes_ecb", None, 0, dec), ("aes_cbc", zero, 0, None)]
            if m >= 32:
                modes.append(("aes_cbc", "prefix", 16, xor(dec[16:], part[:-16])))
            if mode == "small":
                for iv in dict.fromkeys([key[:16]] + keys.ivs):
                    modes.append(("aes_cbc", iv, 0, xor(dec, iv)))
            for cipher, iv, base, plain in modes:
                if plain is None:
                    plain = dec                   # CBC under a zero IV opens as ECB does
                firsts = plain[0::16]
                for hit in _FIRST.finditer(firsts):
                    o = 16 * hit.start()
                    if plain.startswith(STARTS, o):
                        c0 = lo + a + base + o
                        if not (whole_first and c0 == 0 and n % 16 == 0):
                            body = blob[c0:c0 + _ALIGNED]
                            body = body[:len(body) // 16 * 16]
                            if cipher == "aes_ecb":
                                used_iv, full = None, ecb.decrypt(body)
                            else:
                                used_iv = blob[c0 - 16:c0] if iv == "prefix" else iv
                                full = aes_cbc(key, used_iv, body)
                            got = settle(full)
                            if got:
                                out.append((c0, cipher, key, used_iv, got[0], got[1], full[:got[2]]))
    return out


# ---- the scanner -------------------------------------------------------------------------------------------------

def _hit(how, offset, cipher, key, iv, kind, obj, plain, valid, **more):
    h = {"how": how, "offset": offset, "cipher": cipher, "key": key, "iv": iv, "kind": kind, "config": obj,
         "plain": plain, "valid": valid, "also": []}
    h.update(more)
    return h


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _weighty(obj, used: int, keylen: int) -> bool:
    """An object read under an XOR key says something only when it is much longer than the key
    that was fitted to it ('{"":6}' under five chosen bytes is no config) and names a field."""
    return used >= max(12 if keylen == 1 else 24, 4 * keylen) and isinstance(obj, dict) and \
        any(len(str(k)) >= 2 for k in obj)


def _printable_share(blob: bytes) -> float:
    sample = blob[:4096]
    return sum(1 for c in sample if c in _PRINT3) / len(sample) if sample else 0.0


def scan(data: bytes, budget: float = None, keys: list = None) -> list:
    """Every validated config reading of a file, each config once:

      {"how": the wrappers and the cipher ('base64>xor'), "offset", "cipher": None|'xor'|'rc4'|
       'aes_cbc'|'aes_ecb', "key": bytes or None, "iv", "kind": 'json'|'ini', "config": dict,
       "plain": the decoded bytes, "valid": 'crc32'|'json'|'ini', "also": [(cipher, key, iv)] of
       other ways that gave the same config, and for an HCFG container "container": 'hcfg',
       "version", "crc32", "header_key"}

    The same config reached two ways is listed under the way that says most (a CRC before a
    parse, a cipher before none, fewer wrappers); a different cipher or key that gives the same
    config is kept under "also", and such a config's key and cipher are then not one fact.
    `budget` (seconds) stops the keyed search early: scan.partial is True afterwards when the
    search did not finish. `keys` adds key candidates from elsewhere (another file of the set)."""
    data = bytes(data)
    deadline = time.monotonic() + budget if budget else None
    found, order = {}, []
    scan.partial = False

    def add(h):
        ident = _canon(h["config"])
        rank = (h["valid"] == "crc32", h["cipher"] is not None, -h["how"].count(">"))
        old = found.get(ident)
        if old is None:
            order.append(ident)
            found[ident] = (rank, h)
            return
        way, old_way = (h["cipher"], h["key"], h["iv"]), (old[1]["cipher"], old[1]["key"], old[1]["iv"])
        if rank > old[0]:
            if way != old_way and old[1]["cipher"] is not None:
                h["also"] = old[1]["also"] + [old_way]
            found[ident] = (rank, h)
        elif way != old_way and h["cipher"] is not None and way not in old[1]["also"]:
            old[1]["also"].append(way)

    vs = views(data, deadline)
    for how, off, blob, bounded in vs:
        pre = how + ">" if how else ""
        for c in hcfg.containers(blob, others=True):
            key = c.get("key_bytes") or bytes([c["key"]])
            add(_hit(pre + "hcfg:" + c["how"], off if how else c["offset"], "xor", key, None, "json", c["json"], c["plain"],
                     "crc32" if c["crc_ok"] else "json", container="hcfg", version=c["version"], crc32=c["crc32"],
                     header_key=c["key"]))
        for o, k, kind, obj, used in xor1_objects(blob):
            if k and not _weighty(obj, used, 1):
                continue
            plain = hcfg._xor(blob[o:o + used], k)
            add(_hit(pre + ("xor" if k else "plain"), off if how else o, "xor" if k else None, bytes([k]) if k else None,
                     None, kind, obj, plain, kind))
        multi = []
        if len(blob) <= SMALL and _printable_share(blob) < 0.9:
            multi = xorn_free(blob)
        if len(blob) > SMALL // 4:
            multi += xorn_cribs(blob)
        for o, key, kind, obj, used in multi:
            if not _weighty(obj, used, len(key)):
                continue
            add(_hit(pre + "xor", off if how else o, "xor", key, None, kind, obj, xor(blob[o:o + used], key), kind))
    cands = key_candidates(data)
    if keys:
        cands = [(bytes(k), 0, "given") for k in keys] + cands
    keyset = KeySet(cands)
    for how, off, blob, bounded in vs:
        if deadline and time.monotonic() > deadline:
            break
        pre = how + ">" if how else ""
        mode = "literal" if how else "small" if len(blob) <= SMALL else "file"
        if not how and _printable_share(blob) > 0.97 and b"\x00" not in blob[:4096]:
            continue        # a text file: ciphertext stands in it as a literal (a view), never raw
        for o, cipher, key, iv, kind, obj, plain in keyed(blob, keyset, mode, deadline):
            body = blob[o:o + max(16, len(plain))]
            if plain.startswith(key[:8]) or len(set(body)) < 6 or (not how and _printable_share(body) > 0.75):
                continue    # not ciphertext: zeros give the key back, and text XOR text is no proof
            if cipher == "xor" and not _weighty(obj, len(plain), len(key)):
                continue
            add(_hit(pre + cipher, off if how else o, cipher, key, iv, kind, obj, plain, kind))
    if deadline and time.monotonic() > deadline:
        scan.partial = True
    return [found[i][1] for i in order]


scan.partial = False


def config(data: bytes, budget: float = None):
    """The file's one config, or None: exactly one reading must validate. A reading whose CRC-32
    checks stands before readings that only parse (when exactly one has a CRC)."""
    hits = scan(data, budget)
    crc = [h for h in hits if h["valid"] == "crc32"]
    if len(crc) == 1:
        return crc[0]
    return hits[0] if len(hits) == 1 else None


def as_hcfg(hit: dict) -> dict:
    """A scan hit in the shape solvers/binary/hcfg.py's find() returns, so the Binary lane's
    hcfg.answer(field, cfg) reads a config that is not in an HCFG container the way it reads one
    that is: 'key' is the XOR byte when the key is one byte (else None, with 'key_bytes'), and
    'crc32' is the stored one for a container, else the CRC-32 of the decoded bytes ('crc_ok'
    False: nothing in the file vouches for it)."""
    key = hit.get("key") or b""
    out = {"offset": hit["offset"], "version": hit.get("version"), "key": key[0] if len(key) == 1 else hit.get("header_key"),
           "crc32": hit["crc32"] if "crc32" in hit else zlib.crc32(hit["plain"]) & 0xFFFFFFFF,
           "crc_ok": hit["valid"] == "crc32", "json": hit["config"], "plain": hit["plain"], "how": hit["how"]}
    if len(key) > 1:
        out["key_bytes"] = key
    return out


def flatten(obj, prefix: str = "") -> dict:
    """{dotted key: scalar or list of scalars} of a config object."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            name = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.update(flatten(v, name))
            elif isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                for i, x in enumerate(v):
                    out.update(flatten(x, f"{name}.{i}"))
            else:
                out[name] = v
    return out


# ---- Cobalt Strike -----------------------------------------------------------------------------------------------------

CS_SETTINGS = {
    1: "beacon_type", 2: "port", 3: "sleeptime", 4: "max_get_size", 5: "jitter", 6: "max_dns", 7: "public_key",
    8: "c2_server", 9: "user_agent", 10: "http_post_uri", 11: "malleable_c2_instructions", 12: "http_get_header",
    13: "http_post_header", 14: "spawn_to", 15: "pipe_name", 19: "dns_idle", 20: "dns_sleep", 26: "http_get_verb",
    27: "http_post_verb", 28: "http_post_chunk", 29: "spawnto_x86", 30: "spawnto_x64", 31: "crypto_scheme",
    32: "proxy_config", 33: "proxy_user", 34: "proxy_password", 35: "proxy_behavior", 37: "watermark",
    38: "stage_cleanup", 39: "cfg_caution", 40: "kill_date", 50: "cookie_beacon", 54: "host_header",
}
CS_BEACON_TYPES = {0: "http", 1: "hybrid_http_dns", 2: "smb", 4: "tcp", 8: "https", 10: "tcp_bind", 16: "tcp_bind", 32: "dns_over_https"}
_CS_OPEN = b"\x00\x01\x00\x01\x00\x02"
_CS_DELTA = bytes(a ^ b for a, b in zip(_CS_OPEN, _CS_OPEN[1:]))


def _cs_parse(plain: bytes):
    out, o, last = {}, 0, 0
    while o + 6 <= len(plain):
        sid, typ, length = struct.unpack_from(">HHH", plain, o)
        if sid == 0:
            break
        if sid <= last or sid > 255 or typ not in (1, 2, 3) or (typ == 1 and length != 2) or (typ == 2 and length != 4) \
                or o + 6 + length > len(plain):
            return None
        raw = plain[o + 6:o + 6 + length]
        value = struct.unpack(">H", raw)[0] if typ == 1 else struct.unpack(">I", raw)[0] if typ == 2 else raw
        if typ == 3:
            stripped = raw.rstrip(b"\x00")
            if stripped and all(0x20 <= c < 0x7F for c in stripped):
                value = stripped.decode("ascii")
        out[sid] = value
        last = sid
        o += 6 + length
    return out if len(out) >= 5 and 1 in out and 2 in out else None


def cobalt_strike(data: bytes):
    """[{"offset", "key": the XOR byte, "settings": {id: value}, "named": {name: value}}] for every
    beacon settings block (id u16, type u16, length u16, value; big-endian) under any single-byte
    XOR (0x69 in version 3, 0x2e in version 4, 0 unpacked). A block is kept only when at least
    five settings parse in ascending id order and settings 1 and 2 are there."""
    out = []
    for lo, hi in _spans(data):
        part = data[lo:hi]
        d = delta(part)
        at = d.find(_CS_DELTA, 0, len(part) - 1)
        while at >= 0 and len(out) < 8:
            k = part[at]
            settings = _cs_parse(hcfg._xor(part[at:at + 8192], k))
            if settings:
                named = {CS_SETTINGS.get(i, f"setting_{i}"): v for i, v in settings.items()}
                if isinstance(named.get("beacon_type"), int):
                    named["beacon_type_name"] = CS_BEACON_TYPES.get(named["beacon_type"])
                c2 = named.get("c2_server")
                if isinstance(c2, str) and "," in c2:
                    parts = c2.split(",")
                    named["c2_hosts"] = parts[0::2]
                    named["c2_uris"] = parts[1::2]
                out.append({"offset": lo + at, "key": k, "settings": settings, "named": named})
            at = d.find(_CS_DELTA, at + 1, len(part) - 1)
    return out


# ---- .NET ----------------------------------------------------------------------------------------------------------------

def us_strings(data: bytes, limit: int = 20000) -> list:
    """The strings of the .NET #US heap, in heap order. The metadata root is found by its BSJB
    magic anywhere in the file (never by a section); [] when there is none or it does not parse."""
    at = data.find(b"BSJB")
    while at >= 0:
        try:
            vlen = struct.unpack_from("<I", data, at + 12)[0]
            if vlen > 255:
                raise ValueError
            o = at + 16 + vlen
            streams = struct.unpack_from("<H", data, o + 2)[0]
            o += 4
            for _ in range(min(streams, 16)):
                off, size = struct.unpack_from("<II", data, o)
                end = data.index(b"\x00", o + 8)
                name = data[o + 8:end]
                o = (end + 4) & ~3
                if name == b"#US":
                    return _us_heap(data[at + off:at + off + size], limit)
        except (struct.error, ValueError, IndexError):
            pass
        at = data.find(b"BSJB", at + 1)
    return []


def _us_heap(heap: bytes, limit: int) -> list:
    out, o = [], 1
    while o < len(heap) and len(out) < limit:
        b = heap[o]
        if b & 0x80 == 0:
            n, o = b, o + 1
        elif b & 0xC0 == 0x80:
            if o + 2 > len(heap):
                break
            n, o = ((b & 0x3F) << 8) | heap[o + 1], o + 2
        else:
            if o + 4 > len(heap):
                break
            n, o = ((b & 0x1F) << 24) | (heap[o + 1] << 16) | (heap[o + 2] << 8) | heap[o + 3], o + 4
        if n == 0:
            continue
        raw = heap[o:o + n - 1]
        o += n
        try:
            s = raw.decode("utf-16-le")
        except UnicodeDecodeError:
            continue
        if s:
            out.append(s)
    return out


def dotnet(data: bytes) -> dict:
    """{"strings": the #US heap, "resources": {name: bytes}} of a .NET assembly; the resources
    through dnfile ({} when it cannot read the file)."""
    out = {"strings": us_strings(data), "resources": {}}
    try:
        import dnfile
        pe = dnfile.dnPE(data=data)
        for r in getattr(pe.net, "resources", None) or []:
            body = getattr(r, "data", None)
            if isinstance(body, (bytes, bytearray)):
                out["resources"][str(getattr(r, "name", len(out["resources"])))] = bytes(body)
    except Exception:
        pass
    return out


_B64TEXT = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")


def xor_b64_pairs(strings: list, limit: int = 40000) -> list:
    """Redline-style pairs among literals: value = base64(xor(base64(text), key)). Returns
    [{"value": the literal, "key": the key literal, "text": the decoded text}] for every (value,
    key) where both base64 layers decode strictly and the text is printable. A value that reads
    under more than one key is left out: exactly one key must fit."""
    values = [s for s in dict.fromkeys(strings) if len(s) % 4 == 0 and _B64TEXT.fullmatch(s)]
    keys = [s for s in dict.fromkeys(strings) if 2 <= len(s) <= 64]
    out, tried = [], 0
    for v in values:
        try:
            raw = base64.b64decode(v, validate=True)
        except (binascii.Error, ValueError):
            continue
        got = []
        for k in keys:
            if k == v:
                continue
            tried += 1
            if tried > limit:
                return out
            try:
                inner = xor(raw, k.encode("utf-8"))
                if len(inner) % 4 or not re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", inner):
                    continue
                text = base64.b64decode(inner, validate=True).decode("utf-8")
            except (binascii.Error, ValueError, UnicodeError):
                continue
            if len(text) >= 3 and text.isprintable():
                got.append((k, text))
        if len({t for _, t in got}) == 1 and len(got) == 1:
            out.append({"value": v, "key": got[0][0], "text": got[0][1]})
    return out


# ---- NetSupport, AutoIt, Lua -------------------------------------------------------------------------------------------------

def decode_text(data: bytes):
    """The text of a text file (BOMs and UTF-16 read), or None."""
    try:
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return data.decode("utf-16")
        if len(data) >= 8 and data[1:2] == b"\x00" and data[3:4] == b"\x00" and data[0] and data[2]:
            return data.decode("utf-16-le")
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def netsupport(text: str):
    """The fields of a NetSupport client32.ini (or NSM.LIC), or None when the text is neither:
    {"gateway_address", "gateway_host", "gateway_port", "secondary_gateway", "secondary_port", "gsk",
     "licensee", "serial_no", "fields": every 'section.key'}."""
    if not re.search(r"(?im)^\s*(?:GatewayAddress|GSK|SecondaryGateway|licensee|serial_no)\s*=", text):
        return None
    pairs = ini(text)
    if not pairs:
        return None
    low = {k.lower(): v for k, v in pairs.items()}

    def get(*names):
        vals = {v for k, v in low.items() if k.rsplit(".", 1)[-1] in names and v != ""}
        return next(iter(vals)) if len(vals) == 1 else None

    out = {"fields": pairs, "gateway_address": get("gatewayaddress"), "secondary_gateway": get("secondarygateway"),
           "gsk": get("gsk"), "licensee": get("licensee"), "serial_no": get("serial_no"), "port": get("port"),
           "secondary_port": get("secondaryport")}
    addr = out["gateway_address"]
    if addr:
        m = re.fullmatch(r"(.+?):(\d{1,5})", addr)
        out["gateway_host"] = m.group(1) if m else addr
        out["gateway_port"] = m.group(2) if m else out["port"]
    return {k: v for k, v in out.items() if v is not None}


AU3_MARK = bytes.fromhex("a3484bbe986c4aa9994c530a86d6487d")


def autoit(data: bytes):
    """{"offset", "subtype": 'EA06'|'EA05'|..., "standalone": the marker opens the file (.a3x),
    "after_pe": the marker stands behind the PE image (an overlay)} for a compiled AutoIt script,
    or None. Nothing is extracted: the script body is encrypted and LZSS-packed (see the doc)."""
    at = data.find(AU3_MARK)
    if at < 0:
        return None
    tag = data[at + 16:at + 24]
    if tag[:4] != b"AU3!":
        return None
    size = _pe_size(data[:1 << 20]) if data[:2] == b"MZ" and len(data) <= 1 << 20 else 0
    return {"offset": at, "subtype": tag[4:8].decode("latin-1"), "standalone": at == 0,
            "after_pe": bool(size) and at >= size}


class _R:
    def __init__(self, d, o=0):
        self.d, self.o = d, o

    def take(self, n):
        if n < 0 or self.o + n > len(self.d):
            raise ValueError("short")
        b = self.d[self.o:self.o + n]
        self.o += n
        return b

    def u8(self):
        return self.take(1)[0]


def lua_constants(data: bytes):
    """{"version": '5.1'|'5.3'|'5.4', "strings": [...], "numbers": [...], "source": name} of Lua
    bytecode: every string and number constant of every function, in file order. None for
    another version, LuaJIT, or a file that does not parse to its end."""
    if data[:4] != b"\x1bLua" or len(data) < 12:
        return None
    ver = data[4]
    r = _R(data, 6)
    strings, numbers, source = [], [], [None]
    try:
        if ver == 0x51:
            little, isz, ssz, insz, nsz, integral = data[6] == 1, data[7], data[8], data[9], data[10], data[11]
            r.o = 12
            e = "<" if little else ">"

            def integer():
                return int.from_bytes(r.take(isz), "little" if little else "big")

            def string():
                n = int.from_bytes(r.take(ssz), "little" if little else "big")
                return r.take(n)[:-1].decode("utf-8", "replace") if n else None

            def func():
                s = string()
                source[0] = source[0] or s
                integer(), integer()
                r.take(4)
                r.take(integer() * insz)
                for _ in range(integer()):
                    t = r.u8()
                    if t == 1:
                        r.u8()
                    elif t == 3:
                        raw = r.take(nsz)
                        numbers.append(int.from_bytes(raw, "little" if little else "big", signed=True) if integral
                                       else struct.unpack(e + ("d" if nsz == 8 else "f"), raw)[0])
                    elif t == 4:
                        strings.append(string())
                    elif t != 0:
                        raise ValueError("constant type")
                for _ in range(integer()):
                    func()
                r.take(integer() * isz)
                for _ in range(integer()):
                    string(), integer(), integer()
                for _ in range(integer()):
                    string()
            func()
        elif ver == 0x53:
            if data[6:12] != b"\x19\x93\r\n\x1a\n":
                return None
            isz, ssz, insz, lisz, nsz = data[12:17]
            r.o = 17 + lisz + nsz + 1
            little = data[17:17 + lisz] == (0x5678).to_bytes(lisz, "little")
            order = "little" if little else "big"

            def integer():
                return int.from_bytes(r.take(isz), order)

            def string():
                n = r.u8()
                if n == 0xFF:
                    n = int.from_bytes(r.take(ssz), order)
                return r.take(n - 1).decode("utf-8", "replace") if n else None

            def func():
                s = string()
                source[0] = source[0] or s
                integer(), integer()
                r.take(3)
                r.take(integer() * insz)
                for _ in range(integer()):
                    t = r.u8()
                    if t == 1:
                        r.u8()
                    elif t == 3:
                        numbers.append(struct.unpack(("<" if little else ">") + "d", r.take(nsz))[0] if nsz == 8 else r.take(nsz))
                    elif t == 0x13:
                        numbers.append(int.from_bytes(r.take(lisz), order, signed=True))
                    elif t in (4, 0x14):
                        strings.append(string())
                    elif t != 0:
                        raise ValueError("constant type")
                r.take(integer() * 2)
                for _ in range(integer()):
                    func()
                r.take(integer() * isz)
                for _ in range(integer()):
                    string(), integer(), integer()
                for _ in range(integer()):
                    string()
            func()
        elif ver == 0x54:
            if data[6:12] != b"\x19\x93\r\n\x1a\n":
                return None
            insz, lisz, nsz = data[12:15]
            little = data[15:15 + lisz] == (0x5678).to_bytes(lisz, "little")
            order = "little" if little else "big"
            r.o = 15 + lisz + nsz + 1

            def size():
                x = 0
                while True:
                    b = r.u8()
                    x = (x << 7) | (b & 0x7F)
                    if b & 0x80:
                        return x

            def string():
                n = size()
                return r.take(n - 1).decode("utf-8", "replace") if n else None

            def func():
                s = string()
                source[0] = source[0] or s
                size(), size()
                r.take(3)
                r.take(size() * insz)
                for _ in range(size()):
                    t = r.u8()
                    if t == 0x13:
                        numbers.append(struct.unpack(("<" if little else ">") + "d", r.take(nsz))[0] if nsz == 8 else r.take(nsz))
                    elif t == 0x03:
                        numbers.append(int.from_bytes(r.take(lisz), order, signed=True))
                    elif t in (0x04, 0x14):
                        strings.append(string())
                    elif t not in (0x00, 0x01, 0x11):
                        raise ValueError("constant type")
                r.take(size() * 3)
                for _ in range(size()):
                    func()
                r.take(size())
                for _ in range(size()):
                    size(), size()
                for _ in range(size()):
                    string(), size(), size()
                for _ in range(size()):
                    string()
            func()
        else:
            return None
    except (ValueError, struct.error, IndexError, RecursionError):
        return None
    if r.o != len(data):
        return None
    return {"version": {0x51: "5.1", 0x53: "5.3", 0x54: "5.4"}[ver], "strings": [s for s in strings if s is not None],
            "numbers": numbers, "source": source[0]}


# ---- embedded payloads and quarantine wrappers ---------------------------------------------------------------------------------

DOS_STUB = b"This program cannot be run in DOS mode"
XOR_PE_STUBS = 64           # stub texts looked at per key length


def _pe_head(d) -> bool:
    """The MZ and PE signatures and an optional-header magic in the first bytes of `d`."""
    try:
        if d[:2] != b"MZ":
            return False
        off = struct.unpack_from("<I", d, 0x3C)[0]
        if off > len(d) - 26:
            return len(d) >= 4096 and off < FULL        # the PE header lies beyond this window: not decided here
        return d[off:off + 4] == b"PE\x00\x00" and struct.unpack_from("<H", d, off + 24)[0] in (0x10B, 0x20B)
    except (struct.error, IndexError):
        return False


def xor_pe(data: bytes, sizes=range(1, 9)) -> list:
    """[{"offset", "key", "size", "plain", "sha256"}] for every PE that stands in `data` under a
    repeating XOR of 1 to 8 bytes (not in the clear), found by the DOS stub text and kept only
    when the decoded image's headers and section table parse inside the file."""
    out, seen = [], set()
    data = data[:FULL] if len(data) > FULL else data
    work = 4 * FULL         # bytes decoded in all: a file of thousands of stub texts is not read a thousand times
    for n in sizes:
        d = delta(data, n)
        needle = bytes(a ^ b for a, b in zip(DOS_STUB, DOS_STUB[n:]))
        at = d.find(needle, 0, len(data) - n)
        stubs = 0
        while at >= 0 and stubs < XOR_PE_STUBS and work > 0:
            stubs += 1
            key_at = bytes(a ^ b for a, b in zip(data[at:at + n], DOS_STUB))
            if any(key_at):
                lo = max(0, at - 1024)
                key_lo = bytes(key_at[(lo - at + i) % n] for i in range(n))
                head = xor(data[lo:at], key_lo)
                mz = head.rfind(b"MZ")
                while mz >= 0:
                    start = lo + mz
                    key = bytes(key_at[(start - at + i) % n] for i in range(n))
                    if start not in seen and work > 0:
                        # the headers first (4 KB); the whole image only when they parse
                        if not _pe_head(xor(data[start:start + 4096], key)):
                            mz = head.rfind(b"MZ", 0, mz)
                            continue
                        work -= len(data) - start
                        plain = xor(data[start:], key)
                        size = _pe_size(plain)
                        if size:
                            seen.add(start)
                            short = next((key[:p] for p in range(1, n) if n % p == 0 and key[:p] * (n // p) == key), key)
                            out.append({"offset": start, "key": short, "size": size, "plain": plain[:size],
                                        "sha256": sha256(plain[:size]), "to_end": start + size == len(data)})
                            break
                    mz = head.rfind(b"MZ", 0, mz)
            at = d.find(needle, at + 1, len(data) - n)
    return out


_NQF = bytes(((b - 84) & 0xFF) ^ 0xA5 for b in range(256))
_KLQ = bytes.fromhex("e24548ec690e5cac")
_QUARANTINE = (
    ("mcafee_bup", lambda d: hcfg._xor(d, 0x6A)), ("symantec_vbn", lambda d: hcfg._xor(d, 0x5A)),
    ("symantec_vbn_a5", lambda d: hcfg._xor(d, 0xA5)), ("trendmicro_vsbx", lambda d: hcfg._xor(d, 0xFF)),
    ("avira_qua", lambda d: hcfg._xor(d, 0xAA)), ("eset_nqf", lambda d: d.translate(_NQF)),
)
_PAYLOAD_MAGIC = (b"MZ", b"\x7fELF", b"PK\x03\x04", b"%PDF-", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"\x89PNG\r\n\x1a\n")


def quarantine(data: bytes) -> list:
    """[{"wrapper", "offset", "kind", "plain", "sha256", "exact": the payload ends where the file
    does}] for a quarantine file whose known transform (McAfee BUP 0x6A, Symantec VBN 0x5A/0xA5,
    Trend Micro VSBX 0xFF, Avira QUA 0xAA, ESET NQF, Kaspersky KLQ) gives a payload with a clean
    magic whose structure parses. The payload's offset is found, not assumed. A wrapper is named
    by the transform that worked; a file already clean under none of them gives []."""
    out, seen = [], set()
    if proof(data) in STRONG:
        return out
    trials = [(name, fn(data[:FULL])) for name, fn in _QUARANTINE]
    for phase in range(8):
        trials.append(("kaspersky_klq", xor(data[:FULL], _KLQ[phase:] + _KLQ[:phase])))
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        try:
            import olefile
            ole = olefile.OleFileIO(io.BytesIO(data))
            for entry in ole.listdir():
                trials.append(("mcafee_bup:" + "/".join(entry), hcfg._xor(ole.openstream(entry).read(), 0x6A)))
        except Exception:
            pass
    for name, plain in trials:
        for magic in _PAYLOAD_MAGIC:
            at = plain.find(magic, 0, 65536)
            n = 0
            while at >= 0 and n < 16:
                n += 1
                body = plain[at:]
                kind = proof(body)
                size = len(body)
                if kind == "pe_loose":
                    size, kind = _pe_size(body), "pe"       # the image by its section table; what follows is not it
                if kind in STRONG:
                    digest = sha256(body[:size])
                    if digest not in seen:
                        seen.add(digest)
                        out.append({"wrapper": name, "offset": at, "kind": kind, "plain": body[:size], "sha256": digest,
                                    "exact": at + size == len(plain)})
                    break
                at = plain.find(magic, at + 1, 65536)
    return out


# ---- pair helpers ------------------------------------------------------------------------------------------------------------------

def shortest_period(stream: bytes, proven: bool = True):
    """The shortest p with stream[i] == stream[i % p] for all i; with `proven`, only when the
    stream shows the key twice (2p <= len). None otherwise."""
    n = len(stream)
    for p in range(1, n + 1):
        if proven and 2 * p > n:
            return None
        if stream[p:] == stream[:n - p]:
            return p
    return None


def xor_key_from_pair(plain: bytes, cipher: bytes) -> dict:
    """{"keystream": plain^cipher over their common length, "key": the repeating key when the
    keystream shows it at least twice (else None), "period"}."""
    n = min(len(plain), len(cipher))
    stream = xor(cipher[:n], plain[:n]) if n else b""
    p = shortest_period(stream) if n else None
    return {"keystream": stream, "key": stream[:p] if p else None, "period": p}


def keystream_from_magic(cipher: bytes, kind: str) -> bytes:
    """The keystream a file's known opening gives away: cipher ^ MAGIC[kind] (b'' for an unknown kind)."""
    magic = MAGIC.get(kind, b"")
    return xor(cipher[:len(magic)], magic) if magic and len(cipher) >= len(magic) else b""


def footer_diff(blobs: list) -> dict:
    """What the files of an encrypted set share at their end: {"common_suffix": the bytes every
    file ends with, "marker": the printable run in it (or b''), "same_tail_len": n}. A footer
    that differs per file shows as an empty common suffix; decrypt_set tries fixed lengths then."""
    blobs = [b for b in blobs if b]
    if len(blobs) < 2:
        return {"common_suffix": b"", "marker": b"", "same_tail_len": 0}
    n, limit = 0, min(min(len(b) for b in blobs), 4096)
    while n < limit and len({b[-1 - n] for b in blobs}) == 1:
        n += 1
    suffix = blobs[0][len(blobs[0]) - n:] if n else b""
    m = max(re.findall(rb"[\x20-\x7e]{4,}", suffix), key=len, default=b"")
    return {"common_suffix": suffix, "marker": m, "same_tail_len": n}


_FOOTERS = (0, 4, 8, 12, 16, 20, 24, 32, 36, 40, 48, 64, 128, 256)


def _footer_keys(footer: bytes, marker: bytes) -> list:
    out = [footer]
    if marker and marker in footer and marker != footer:
        i = footer.find(marker)
        out += [footer[:i], footer[i + len(marker):]]
    for n in (32, 24, 16, 8, 4):
        if len(footer) > n:
            out += [footer[:n], footer[-n:]]
    return [k for k in dict.fromkeys(out) if len(k) >= 1 and len(set(k)) > 1 or len(k) == 1]


def _try_file(body: bytes, key: bytes, ivs: list, want: str):
    """[(cipher, iv, plain, proof kind)] of `body` under `key`: every cipher whose result is proven."""
    out = []
    trials = [("xor", None, lambda: xor(body, key)), ("rc4", None, lambda: rc4(key, body))]
    if AES is not None and len(key) in (16, 24, 32) and len(body) >= 16:
        if len(body) % 16 == 0:
            trials.append(("aes_ecb", None, lambda: unpad(aes_ecb(key, body)) or aes_ecb(key, body)))
            for iv in ivs:
                trials.append(("aes_cbc", iv, lambda iv=iv: unpad(aes_cbc(key, iv, body)) or aes_cbc(key, iv, body)))
            if len(body) >= 32:
                trials.append(("aes_cbc", body[:16], lambda: unpad(aes_cbc(key, body[:16], body[16:])) or b""))
        for iv in ivs + ([body[:16]] if len(body) > 16 else []):
            if len(iv) == 16:
                def ctr(iv=iv, pre=iv is body[:16] or iv == body[:16]):
                    c = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
                    return c.decrypt(body[16:] if pre else body)
                trials.append(("aes_ctr", iv, ctr))
    for cipher, iv, fn in trials:
        try:
            plain = fn()
        except Exception:
            continue
        if not plain:
            continue
        kind = proof(plain)
        if kind and (kind in STRONG or want is None or want == "text" or kind.startswith(want)):
            out.append((cipher, iv, plain, kind))
    return out


def decrypt_set(files: dict, extra_keys=(), budget: float = 2.0) -> dict:
    """Decrypt an encrypted set. `files` is {name: bytes} of the encrypted files only; `extra_keys`
    are key candidates from elsewhere (a key file, literals of the note).

    Key candidates: slices of the footer the files share (footer_diff) and of a fixed-length
    footer per file; the keystream a file's known magic gives away (the kind is read from the
    name under its appended extension), as a repeating XOR key; `extra_keys`. Ciphers: repeating
    XOR, RC4, AES-ECB/CBC/CTR (IV zero, the body's first block, the other part of the footer).

    Returns {name: {"plain", "sha256", "proof": kind, "strong": bool, "cipher", "key", "iv",
    "footer_len"}} for every file with EXACTLY one proven plaintext; a file with none, or with
    two different ones, is left out. A decrypt is proven by proof(): a clean magic and a parse."""
    deadline = time.monotonic() + budget
    names = sorted(files)
    blobs = [files[n] for n in names]
    fd = footer_diff(blobs)
    shared = fd["common_suffix"]
    out, schemes = {}, []
    for name in names:
        data = files[name]
        stems = name.split(ARROW)[-1].rsplit("/", 1)[-1].split(".")
        want = next((EXT_KIND[s.lower()] for s in reversed(stems[1:]) if s.lower() in EXT_KIND), None)
        if want is None and any(s.lower() in ("txt", "csv", "log", "md", "json", "ini", "cfg") for s in stems[1:]):
            want = "text"
        results = {}

        def attempt(flen, key, ivs):
            body = data[:len(data) - flen] if flen else data
            if len(body) < 4:
                return
            for cipher, iv, plain, kind in _try_file(body, key, ivs, want):
                results.setdefault(plain, {"plain": plain, "sha256": sha256(plain), "proof": kind, "strong": kind in STRONG,
                                           "cipher": cipher, "key": key, "iv": iv, "footer_len": flen})
                schemes.append((flen, cipher))

        lens = [len(shared)] if shared else []
        lens += [f for f in _FOOTERS if f not in lens and f < len(data) - 4]
        worked = {s[0] for s in schemes}
        lens = [f for f in lens if f in worked] + [f for f in lens if f not in worked]
        for flen in lens:
            if time.monotonic() > deadline:
                break
            footer = data[len(data) - flen:] if flen else b""
            keys = _footer_keys(footer, fd["marker"]) if footer else []
            body = data[:len(data) - flen] if flen else data
            if want in MAGIC:
                ks = keystream_from_magic(body, want)
                for p in range(1, len(ks) + 1):
                    if ks[p:] == ks[:len(ks) - p]:
                        keys.append(ks[:p])
            keys += [bytes(k) for k in extra_keys]
            zero = [bytes(16)]
            for key in dict.fromkeys(keys):
                ivs = zero + [k for k in keys if len(k) == 16 and k != key][:4] + ([key[:16]] if len(key) >= 16 else [])
                attempt(flen, key, list(dict.fromkeys(ivs)))
            if results and shared and flen == len(shared):
                break               # the footer every file shares gave a proven decrypt: that is the footer
        if len(results) == 1:
            out[name] = next(iter(results.values()))
        elif len(results) > 1:
            strong = [r for r in results.values() if r["strong"]]
            if len(strong) == 1:
                out[name] = strong[0]
    return out


# ---- addresses -------------------------------------------------------------------------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58MAP = {c: i for i, c in enumerate(_B58)}
B58_VERSIONS = {0x00: "btc_p2pkh", 0x05: "btc_p2sh", 0x30: "ltc_p2pkh", 0x32: "ltc_p2sh", 0x1E: "doge_p2pkh",
                0x16: "doge_p2sh", 0x41: "tron", 0x4C: "dash_p2pkh", 0x10: "dash_p2sh", 0x6F: "btc_testnet_p2pkh",
                0xC4: "btc_testnet_p2sh", 0x1C: "zcash_t"}


def base58check(addr: str):
    """(version byte, payload) when `addr` is base58 with a valid double-SHA-256 checksum, else None."""
    try:
        n = 0
        for c in addr:
            n = n * 58 + _B58MAP[c]
    except KeyError:
        return None
    pad = len(addr) - len(addr.lstrip("1"))
    raw = b"\x00" * pad + n.to_bytes((n.bit_length() + 7) // 8, "big")
    if len(raw) < 5 or hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        return None
    return raw[0], raw[1:-4]


_BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32(addr: str):
    """(hrp, 'bech32'|'bech32m') when the checksum of `addr` is valid (BIP 173 / BIP 350), else None."""
    if addr.lower() != addr and addr.upper() != addr:
        return None
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return None
    hrp, data = addr[:pos], addr[pos + 1:]
    if any(c not in _BECH for c in data):
        return None
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + [_BECH.index(c) for c in data]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i, g in enumerate((0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)):
            if (b >> i) & 1:
                chk ^= g
    return (hrp, "bech32") if chk == 1 else (hrp, "bech32m") if chk == 0x2BC830A3 else None


def _keccak256(data: bytes):
    if _keccak is None:
        return None
    return _keccak.new(digest_bits=256, data=data).digest()


def eip55(addr: str):
    """True for a mixed-case Ethereum address whose EIP-55 checksum is right, False when it is
    wrong, None for an address in one case (no checksum to check) or when Keccak is missing."""
    body = addr[2:]
    if body.lower() == body or body.upper() == body:
        return None
    digest = _keccak256(body.lower().encode())
    if digest is None:
        return None
    h = digest.hex()
    return all((c.isdigit()) or (c.isupper() == (int(h[i], 16) >= 8)) for i, c in enumerate(body))


_XMR_SIZES = {0: 0, 2: 1, 3: 2, 5: 3, 6: 4, 7: 5, 9: 6, 10: 7, 11: 8}


def monero(addr: str) -> bool:
    """A Monero address (95 or 106 characters) whose Keccak-256 checksum is right."""
    if len(addr) not in (95, 106) or _keccak is None:
        return False
    raw = b""
    try:
        for i in range(0, len(addr), 11):
            block = addr[i:i + 11]
            n = 0
            for c in block:
                n = n * 58 + _B58MAP[c]
            raw += n.to_bytes(_XMR_SIZES[len(block)], "big")
    except (KeyError, OverflowError):
        return False
    return _keccak256(raw[:-4])[:4] == raw[-4:]


def onion_v3(host: str) -> bool:
    """A 56-character .onion name whose version byte is 3 and whose SHA3-256 checksum is right."""
    label = host.lower().removesuffix(".onion")
    if len(label) != 56:
        return False
    try:
        raw = base64.b32decode(label.upper())
    except (binascii.Error, ValueError):
        return False
    pub, chk, ver = raw[:32], raw[32:34], raw[34:]
    return ver == b"\x03" and hashlib.sha3_256(b".onion checksum" + pub + ver).digest()[:2] == chk


def tox_id(value: str) -> bool:
    """A 76-hex-digit Tox id whose two checksum bytes are the XOR of the 18 byte pairs before them."""
    if not re.fullmatch(r"[0-9A-Fa-f]{76}", value):
        return False
    raw = bytes.fromhex(value)
    a = b = 0
    for i in range(0, 36, 2):
        a ^= raw[i]
        b ^= raw[i + 1]
    return raw[36] == a and raw[37] == b


# ---- the ransom note -----------------------------------------------------------------------------------------------------------------------

_ONION = re.compile(r"(?<![a-z2-7])([a-z2-7]{56}|[a-z2-7]{16})\.onion\b", re.I)
_B58ADDR = re.compile(r"(?<![A-Za-z0-9])[1-9A-HJ-NP-Za-km-z]{25,36}(?![A-Za-z0-9])")
_BECHADDR = re.compile(r"(?<![A-Za-z0-9])(?:bc|tb|ltc|bcrt)1[02-9ac-hj-np-z]{11,87}(?![A-Za-z0-9])", re.I)
_ETH = re.compile(r"(?<![A-Za-z0-9])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")
_XMR = re.compile(r"(?<![A-Za-z0-9])[48][1-9A-HJ-NP-Za-km-z]{94}(?:[1-9A-HJ-NP-Za-km-z]{11})?(?![A-Za-z0-9])")
_TOX = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{76}(?![0-9A-Fa-f])")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,200}\.[A-Za-z]{2,24}\b")
_VICTIM = re.compile(r"(?im)^[ \t>*#-]*(?:your\s+)?(?:(?:personal|unique|victim|client|decryption|decrypt|user|system|machine|company)\s+){0,2}"
                     r"(?:id|identifier|key|code|token)\s*(?:is|[:=])\s*[`'\"\[<]?([A-Za-z0-9+/=_-]{6,200})[`'\"\]>]?[ \t.]*$")
_VICTIM_NEXT = re.compile(r"(?im)^[ \t>*#-]*(?:your\s+)?(?:(?:personal|unique|victim|client|decryption|decrypt|user|system|machine)\s+){0,2}"
                          r"(?:id|identifier|key|code)\s*:?[ \t]*\r?\n[ \t]*[`'\"\[<]?([A-Za-z0-9+/=_-]{8,200})[`'\"\]>]?[ \t]*$")
_EXT_A = re.compile(r"(?i)\b(?:extension|suffix)\b[^\n.]{0,40}?[\"'`(\[]?(\.[A-Za-z0-9_-]{2,16})\b")
_EXT_B = re.compile(r"(?i)[\"'`(\[]?(?:\*)?(\.[A-Za-z0-9_-]{2,16})[\"'`)\]]?\s+(?:file\s+)?(?:extension|suffix)\b")
NOTE_WORDS = re.compile(r"(?i)\b(?:your (?:files|data|network|documents) (?:have been|has been|are|were|is) (?:encrypted|locked|stolen)|"
                        r"decrypt(?:or|ion)? (?:key|tool|software)|ransom|\.onion|tor browser|bitcoin|monero|restore your files|"
                        r"do not rename|all your files)\b")


def note(text: str) -> dict:
    """What a ransom note states, every address checked:

      {"onion": [v3 names whose checksum is right], "onion_unchecked": [v2 names and v3 names
       whose checksum is wrong], "wallets": [{"address", "coin", "check"}] (base58check, bech32,
       bech32m, eip55, monero), "wallets_unchecked": [address shaped strings with no valid
       checksum; an Ethereum address in one case is listed with check 'none'], "tox": [...],
       "emails": [...], "victim_id": [...], "extension": [...]}"""
    out = {"onion": [], "onion_unchecked": [], "wallets": [], "wallets_unchecked": [], "tox": [], "emails": [],
           "victim_id": [], "extension": []}

    def add(key, v):
        if v not in out[key]:
            out[key].append(v)

    for m in _ONION.finditer(text):
        host = m.group(1).lower() + ".onion"
        add("onion" if onion_v3(host) else "onion_unchecked", host)
    taken = set()
    for m in _XMR.finditer(text):
        if monero(m.group()):
            add("wallets", {"address": m.group(), "coin": "xmr", "check": "monero"})
            taken.add(m.group())
        else:
            add("wallets_unchecked", {"address": m.group(), "coin": "xmr", "check": "invalid"})
    for m in _BECHADDR.finditer(text):
        got = bech32(m.group())
        coin = {"bc": "btc", "tb": "btc_testnet", "ltc": "ltc", "bcrt": "btc_regtest"}.get(m.group().lower().split("1")[0], "?")
        if got:
            add("wallets", {"address": m.group(), "coin": coin, "check": got[1]})
        else:
            add("wallets_unchecked", {"address": m.group(), "coin": coin, "check": "invalid"})
    for m in _B58ADDR.finditer(text):
        if any(m.group() in t for t in taken):
            continue
        got = base58check(m.group())
        if got and len(got[1]) == 20:
            add("wallets", {"address": m.group(), "coin": B58_VERSIONS.get(got[0], f"version_0x{got[0]:02x}"), "check": "base58check"})
        elif m.group()[0] in "13LMDTX" and 26 <= len(m.group()) <= 35 and re.search(r"\d", m.group()) and re.search(r"[A-Z]", m.group()) \
                and re.search(r"[a-z]", m.group()):
            add("wallets_unchecked", {"address": m.group(), "coin": "?", "check": "invalid"})
    for m in _ETH.finditer(text):
        ok = eip55(m.group())
        if ok:
            add("wallets", {"address": m.group(), "coin": "eth", "check": "eip55"})
        else:
            add("wallets_unchecked", {"address": m.group(), "coin": "eth", "check": "none" if ok is None else "invalid"})
    for m in _TOX.finditer(text):
        if tox_id(m.group()):
            add("tox", m.group())
    for m in _EMAIL.finditer(text):
        add("emails", m.group())
    for rx in (_VICTIM, _VICTIM_NEXT):
        for m in rx.finditer(text):
            v = m.group(1)
            if not any(v in (w["address"]) for w in out["wallets"] + out["wallets_unchecked"]) and v not in out["tox"] \
                    and not v.lower().endswith("onion"):
                add("victim_id", v)
    for rx in (_EXT_A, _EXT_B):
        for m in rx.finditer(text):
            add("extension", m.group(1))
    return out


def appended_extension(names: list):
    """The extension a set of file names shares behind their own ('report.pdf.locked' and
    'notes.txt.locked' give '.locked'), or None: at least two names must carry it behind another
    extension and no name of that form may carry a different one."""
    last = {}
    for n in names:
        base = n.split(ARROW)[-1].rsplit("/", 1)[-1]
        parts = base.split(".")
        if len(parts) >= 3 and parts[-1] and parts[-2]:
            last.setdefault("." + parts[-1], []).append(base)
    if len(last) == 1:
        ext, group = next(iter(last.items()))
        if len(group) >= 2:
            return ext
    return None


if __name__ == "__main__":
    import runpy
    runpy.run_path(str(HERE.parent / "toolkits" / "malconfig.py"), run_name="__main__")
