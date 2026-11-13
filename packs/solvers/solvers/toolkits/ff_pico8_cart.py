"""Bounded, static PICO-8 .p8/.p8.png cartridge inspection; never runs Lua.

Layout references: PICO-8 manual; dansanderson/picotool's p8, p8png,
gfx, sfx and music readers; Lexaloffle's published p8_compress.c and
pxa_compress_snippets.c (github.com/dansanderson/lexaloffle).
All public parsing functions raise only P8CartError on malformed input.
Pillow is needed only for PNG pixel decoding.
"""

import argparse
from functools import wraps
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
import zlib


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = 4 * 1024 * 1024
MAX_LUA = 1024 * 1024
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
P8_HEADER = b"pico-8 cartridge // http://www.pico-8.com"
REGIONS = {"gfx": (0, 0x2000), "map": (0x2000, 0x3000),
           "gff": (0x3000, 0x3100), "music": (0x3100, 0x3200),
           "sfx": (0x3200, 0x4300)}
_LITERALS = b"^\n 0123456789abcdefghijklmnopqrstuvwxyz!#%(){}[]<>+=/*:;.,~_"


class P8CartError(ValueError):
    """Invalid, unsupported, or over-limit cartridge input."""


def _closed(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except P8CartError:
            raise
        except Exception as exc:
            raise P8CartError(f"{function.__name__}: invalid input ({type(exc).__name__})") from None
    return guarded


def _bytes(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise P8CartError("input must be bytes")
    if (data.nbytes if isinstance(data, memoryview) else len(data)) > MAX_INPUT:
        raise P8CartError("input exceeds 4 MiB limit")
    return bytes(data)


def _blob(data):
    return {"byte_size": len(data), "data_hex": data.hex(),
            "sha256": hashlib.sha256(data).hexdigest()}


def _flags(data):
    return sorted({m.decode("ascii") for m in flagfmt.BYTES.findall(data)})


def _lua(data, encoding):
    result = _blob(data)
    result.update(text=data.decode(encoding, errors="replace"), text_encoding=encoding,
                  line_count=len(data.splitlines()), flags=_flags(data))
    return result


def _music(data):
    return [{"channels": [c & 127 for c in data[i:i + 4]],
             "begin_loop": bool(data[i] & 128),
             "end_loop": bool(data[i + 1] & 128),
             "stop": bool(data[i + 2] & 128)} for i in range(0, len(data), 4)]


def _sfx(data):
    records = []
    for start in range(0, len(data), 68):
        row = data[start:start + 68]
        notes = []
        for i in range(0, 64, 2):
            word = row[i] | (row[i + 1] << 8)
            notes.append({"pitch": word & 63,
                          "waveform": ((word >> 6) & 7) | ((word >> 12) & 8),
                          "volume": (word >> 9) & 7, "effect": (word >> 12) & 7})
        records.append({"editor_mode": row[64], "speed": row[65],
                        "loop_start": row[66], "loop_end": row[67], "notes": notes})
    return records


def _section(name, data):
    result = _blob(data)
    if name == "sfx":
        result["records"] = _sfx(data)
    if name == "music":
        result["records"] = _music(data)
    return result


def _text_section(name, raw):
    rows = [line for line in raw.splitlines() if line]
    limits = {"gfx": (128, 128), "label": (128, 128), "map": (256, 32),
              "gff": (256, 2), "sfx": (168, 64), "music": (11, 64)}
    width, maximum = limits[name]
    if len(rows) > maximum:
        raise P8CartError(f"too many {name} rows")
    output = bytearray()
    for row in rows:
        if len(row) != width:
            raise P8CartError(f"{name} row must have {width} characters")
        if name == "music":
            if not re.fullmatch(rb"[0-9a-fA-F]{2} [0-9a-fA-F]{8}", row):
                raise P8CartError("invalid music row")
            flags = int(row[:2], 16)
            channels = bytes.fromhex(row[3:].decode("ascii"))
            if flags > 7 or any(c > 127 for c in channels):
                raise P8CartError("invalid music flags or channels")
            output.extend(c | (((flags >> i) & 1) << 7) if i < 3 else c
                          for i, c in enumerate(channels))
        else:
            if not re.fullmatch(rb"[0-9a-fA-F]+", row):
                raise P8CartError(f"non-hexadecimal {name} row")
            if name == "sfx":
                for i in range(8, 168, 5):
                    pitch = int(row[i:i + 2], 16)
                    waveform, volume, effect = (int(chr(c), 16) for c in row[i + 2:i + 5])
                    if pitch > 63 or volume > 7 or effect > 7:
                        raise P8CartError("out-of-range sound note")
                    word = pitch | ((waveform & 7) << 6) | (volume << 9) | (effect << 12) | ((waveform & 8) << 12)
                    output.extend(word.to_bytes(2, "little"))
                output.extend(bytes.fromhex(row[:8].decode("ascii")))
            else:
                decoded = bytes.fromhex(row.decode("ascii"))
                if name in ("gfx", "label"):
                    decoded = bytes((c >> 4) | ((c & 15) << 4) for c in decoded)
                output.extend(decoded)
    result = _section(name, bytes(output))
    result.update(text_byte_size=len(raw), row_count=len(rows))
    return result


@_closed
def parse_p8(data):
    """Decode text sections, preserving Lua without executing/resolving includes.

    Text .p8 has no EOF sentinel; every byte after the last section marker is
    section content, so there is no unambiguous external trailer to separate.
    """
    data = _bytes(data)
    if data.count(b"\n") > 65536 or data.count(b"\r") > 65536:
        raise P8CartError("text cartridge exceeds 65536 lines")
    lines = data.splitlines(keepends=True)
    if len(lines) < 2 or lines[0].rstrip(b"\r\n") != P8_HEADER:
        raise P8CartError("missing PICO-8 text header")
    match = re.fullmatch(rb"version ([0-9]{1,3})", lines[1].rstrip(b"\r\n"))
    if not match or int(match[1]) > 255:
        raise P8CartError("invalid cartridge version")
    bodies = {}
    current = None
    for line in lines[2:]:
        value = line.rstrip(b"\r\n")
        marker = re.fullmatch(rb"__([a-zA-Z0-9_]+)__", value)
        if marker:
            current = marker[1].decode("ascii")
            if current not in ("lua", "gfx", "map", "gff", "sfx", "music", "label"):
                raise P8CartError("unsupported section: " + current)
            if current in bodies:
                raise P8CartError("duplicate section: " + current)
            bodies[current] = bytearray()
        elif current is None:
            if value:
                raise P8CartError("data before first section")
        else:
            bodies[current].extend(line)
    if not bodies:
        raise P8CartError("no cartridge sections")
    sections = {}
    for name, body in bodies.items():
        raw = bytes(body)
        if name == "lua":
            if len(raw) > MAX_LUA:
                raise P8CartError("Lua source exceeds 1 MiB limit")
            sections[name] = _lua(raw, "utf-8")
        else:
            sections[name] = _text_section(name, raw)
    return {"format": "p8", "version": int(match[1]), "file_size": len(data),
            "sections": sections, "flags": _flags(data), "trailing": _blob(b""),
            "notes": ["Text .p8 has no EOF sentinel; the final section consumes remaining bytes.",
                      "Lua and #include directives are preserved, never executed or resolved.",
                      "Decoded asset bytes cover provided rows; omitted rows are not synthesized."]}


class _Bits:
    def __init__(self, data):
        self.data = data
        self.position = 0

    def read(self, count):
        if self.position + count > len(self.data) * 8:
            raise P8CartError("truncated PXA bitstream")
        value = 0
        for bit in range(count):
            value |= ((self.data[self.position // 8] >> (self.position % 8)) & 1) << bit
            self.position += 1
        return value


def _copy(output, distance, length, limit):
    if distance < 1 or distance > len(output) or len(output) + length > limit:
        raise P8CartError("invalid compressed-code back-reference")
    for _ in range(length):
        output.append(output[-distance])


def _decode_code(data):
    if not data.startswith((b":c:\0", b"\0pxa")):
        end = data.find(b"\0")
        end = len(data) if end == -1 else end
        return data[:end], "uncompressed", min(end + 1, len(data))
    if len(data) < 8:
        raise P8CartError("truncated compressed-code header")
    raw_size = int.from_bytes(data[4:6], "big")
    output = bytearray()
    if data.startswith(b":c:\0"):
        if data[6:8] != b"\0\0":
            raise P8CartError("invalid legacy compression reserved bytes")
        pos = 8
        while len(output) < raw_size:
            if pos >= len(data):
                raise P8CartError("truncated legacy code")
            token = data[pos]
            pos += 1
            if token == 0 or token >= 60:
                if pos >= len(data):
                    raise P8CartError("truncated legacy code token")
                following = data[pos]
                pos += 1
                if token == 0:
                    output.append(following)
                else:
                    _copy(output, (token - 60) * 16 + (following & 15),
                          (following >> 4) + 2, raw_size)
            else:
                output.append(_LITERALS[token])
        return bytes(output), "legacy :c:", pos
    compressed_size = int.from_bytes(data[6:8], "big")
    if not 8 <= compressed_size <= len(data):
        raise P8CartError("invalid PXA compressed size")
    bits = _Bits(data[8:compressed_size])
    alphabet = list(range(256))
    while len(output) < raw_size:
        if bits.read(1):
            width, base = 4, 0
            while bits.read(1):
                base += 1 << width
                width += 1
                if base > 255:
                    raise P8CartError("invalid PXA literal index")
            index = base + bits.read(width)
            if index > 255:
                raise P8CartError("invalid PXA literal index")
            value = alphabet.pop(index)
            output.append(value)
            alphabet.insert(0, value)
        else:
            if bits.read(1) == 0:
                width = 15
            else:
                width = 5 if bits.read(1) else 10
            offset = bits.read(width)
            if width == 10 and offset == 0:
                while True:
                    value = bits.read(8)
                    if value == 0:
                        break
                    if len(output) == raw_size:
                        raise P8CartError("PXA raw block exceeds declared size")
                    output.append(value)
            else:
                length = 3
                while True:
                    part = bits.read(3)
                    length += part
                    if length > raw_size - len(output):
                        raise P8CartError("PXA block exceeds declared size")
                    if part < 7:
                        break
                _copy(output, offset + 1, length, raw_size)
    if (bits.position + 7) // 8 != compressed_size - 8:
        raise P8CartError("PXA declared size does not match consumed stream")
    return bytes(output), "pxa", compressed_size


def _png_end(data):
    if not data.startswith(PNG_MAGIC):
        raise P8CartError("missing PNG signature")
    pos, count, idat = 8, 0, False
    while pos < len(data):
        if len(data) - pos < 12:
            raise P8CartError("truncated PNG chunk")
        size = int.from_bytes(data[pos:pos + 4], "big")
        kind = data[pos + 4:pos + 8]
        end = pos + size + 12
        if end > len(data):
            raise P8CartError("PNG chunk exceeds input")
        if not re.fullmatch(rb"[A-Za-z]{4}", kind):
            raise P8CartError("invalid PNG chunk type")
        if zlib.crc32(data[pos + 4:end - 4]) != int.from_bytes(data[end - 4:end], "big"):
            raise P8CartError("PNG chunk checksum mismatch")
        if count == 0:
            if kind != b"IHDR" or size != 13:
                raise P8CartError("missing PNG IHDR")
            width, height, depth, color, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", data[pos + 8:end - 4])
            if (width, height) != (160, 205) or depth != 8 or color != 6:
                raise P8CartError("PICO-8 PNG requires 160x205, 8-bit RGBA")
            if compression or filtering or interlace not in (0, 1):
                raise P8CartError("unsupported PNG encoding")
        elif kind == b"IHDR":
            raise P8CartError("duplicate PNG IHDR")
        if kind in (b"acTL", b"fcTL", b"fdAT"):
            raise P8CartError("animated PNG is not a cartridge image")
        if kind[:1].isupper() and kind not in (b"IHDR", b"PLTE", b"IDAT", b"IEND"):
            raise P8CartError("unknown critical PNG chunk")
        if kind == b"IDAT":
            idat = True
        if kind == b"IEND":
            if size or not idat:
                raise P8CartError("invalid PNG end")
            return end
        pos = end
        count += 1
        if count > 4096:
            raise P8CartError("too many PNG chunks")
    raise P8CartError("missing PNG IEND")


@_closed
def parse_p8_png(data):
    """Decode low-two-bit RGBA payload, assets, and bounded legacy/PXA Lua."""
    data = _bytes(data)
    end = _png_end(data)
    try:
        from PIL import Image
    except ImportError:
        raise P8CartError("Pillow is required for PNG cartridges") from None
    with Image.open(io.BytesIO(data[:end])) as image:
        if image.size != (160, 205) or image.mode != "RGBA":
            raise P8CartError("unsupported cartridge pixels")
        pixels = image.tobytes()
    payload = bytes(((pixels[i + 3] & 3) << 6) | ((pixels[i] & 3) << 4) |
                    ((pixels[i + 1] & 3) << 2) | (pixels[i + 2] & 3)
                    for i in range(0, len(pixels), 4))
    sections = {name: _section(name, payload[a:b]) for name, (a, b) in REGIONS.items()}
    raw_code = payload[0x4300:0x8000]
    code, compression, consumed = _decode_code(raw_code)
    sections["lua"] = _lua(code, "latin-1")
    sections["lua"].update(compression=compression, stored_byte_size=consumed,
                           storage_capacity=len(raw_code),
                           unused_storage=_blob(raw_code[consumed:]))
    return {"format": "p8.png", "version": payload[0x8000], "file_size": len(data),
            "width": 160, "height": 205, "payload": _blob(payload), "sections": sections,
            "extra_payload": _blob(payload[0x8001:]), "trailing": _blob(data[end:]),
            "flags": sorted(set(_flags(payload) + _flags(code) + _flags(data[end:]))),
            "notes": ["Lua text is a Latin-1 byte view; P8SCII glyphs are preserved in data_hex.",
                      "Sprite memory 0x1000:0x2000 also supplies map rows 32:64.",
                      "Lua is preserved without execution or compatibility-code removal."]}


@_closed
def inspect_cart(data, format="auto"):
    """Inspect bytes with explicit 'p8'/'png' or signature-based 'auto'."""
    data = _bytes(data)
    if format not in ("auto", "p8", "png"):
        raise P8CartError("unsupported format")
    return parse_p8_png(data) if format == "png" or (format == "auto" and data.startswith(PNG_MAGIC)) else parse_p8(data)


@_closed
def inspect_file(path, format="auto"):
    """Read at most MAX_INPUT+1 bytes from a local cartridge file."""
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_INPUT + 1)
    return inspect_cart(data, format)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="local .p8 or .p8.png cartridge")
    parser.add_argument("--format", choices=("auto", "p8", "png"), default="auto")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        print(json.dumps(inspect_file(args.file, args.format), indent=2))
        return 0
    except P8CartError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
