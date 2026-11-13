"""Synthetic fixtures for the B-117 visual stego suite: QR matrices, SWF movies, GIF animations.

Everything is built from bytes here (qrcode and Pillow from the venv, imported inside the function
that needs them so a test file collects without them and its `needs_tool` marker reports it as not
run). Nothing from a challenge is read and nothing is executed.
"""
from __future__ import annotations

import datetime as dt
import io
import lzma
import struct
import zlib

IDENTITY = {"inverted": False, "mirrored": False, "rotation": 0}


def profile(prefixes=("CSCTF",), slug="b117-test", scope=()):
    """A manual-mode event profile with the given flag prefixes. `scope` is its
    rules.live_service_scope: empty (the default) means no live service may be contacted."""
    from ctf import event
    return event.parse({
        "slug": slug, "name": "visual stego test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "manual"},
        "flag": {"prefixes": list(prefixes)},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": list(scope)},
    }, src="<test>")


# ---- QR ---------------------------------------------------------------------------------------------

def qr_modules(payload: str, version: int = 3, ecl: str = "M") -> list[list[bool]]:
    """The module matrix (True = dark, no quiet zone) of a QR of exactly `version`."""
    import qrcode
    level = {"L": qrcode.constants.ERROR_CORRECT_L, "M": qrcode.constants.ERROR_CORRECT_M,
             "Q": qrcode.constants.ERROR_CORRECT_Q, "H": qrcode.constants.ERROR_CORRECT_H}[ecl]
    code = qrcode.QRCode(version=version, error_correction=level, box_size=1, border=0)
    code.add_data(payload)
    code.make(fit=False)
    return [[bool(cell) for cell in row] for row in code.get_matrix()]


FINDER_CENTRES = {"top-left": lambda n: (3, 3), "top-right": lambda n: (n - 4, 3),
                  "bottom-left": lambda n: (3, n - 4)}


def blank_finders(matrix, corners=("top-left", "top-right", "bottom-left"), value=False):
    """A copy with the named 7x7 finder patterns painted one colour (removed)."""
    out = [row[:] for row in matrix]
    size = len(out)
    for corner in corners:
        cx, cy = FINDER_CENTRES[corner](size)
        for dy in range(-3, 4):
            for dx in range(-3, 4):
                out[cy + dy][cx + dx] = value
    return out


def wreck_format(matrix):
    """A copy with both format strings painted dark (no format code within BCH reach)."""
    out = [row[:] for row in matrix]
    size = len(out)
    for i in range(9):
        if i != 6:
            out[8][i] = True
            out[i][8] = True
    for i in range(8):
        out[8][size - 1 - i] = True
    for i in range(7):
        out[size - 1 - i][8] = True
    return out


def rotate(matrix):
    return [list(row) for row in zip(*matrix[::-1])]


def invert(matrix):
    return [[not cell for cell in row] for row in matrix]


def transpose(matrix):
    return [list(row) for row in zip(*matrix)]


def matrix_png(matrix, scale: int = 4, border: int = 4) -> bytes:
    """Our own renderer (not the engine's): PNG bytes of a module matrix."""
    from PIL import Image
    height, width = len(matrix), len(matrix[0])
    image = Image.new("L", ((width + 2 * border) * scale, (height + 2 * border) * scale), 255)
    for y, row in enumerate(matrix):
        for x, cell in enumerate(row):
            if cell:
                for yy in range(scale):
                    for xx in range(scale):
                        image.putpixel(((x + border) * scale + xx, (y + border) * scale + yy), 0)
    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()


def png_modules(png: bytes, scale: int = 8, border: int = 4) -> list[list[bool]]:
    """The module matrix of a picture drawn `scale` pixels a module inside a `border` of modules,
    read at each module's centre pixel (our own reader, not the engine's sampler)."""
    from PIL import Image
    image = Image.open(io.BytesIO(png)).convert("L")
    assert image.width % scale == 0 and image.height % scale == 0, image.size
    width, height = image.width // scale - 2 * border, image.height // scale - 2 * border
    return [[image.getpixel(((x + border) * scale + scale // 2, (y + border) * scale + scale // 2)) < 128
             for x in range(width)] for y in range(height)]


# ---- SWF --------------------------------------------------------------------------------------------

def swf_tag(code: int, body: bytes, long: bool = False) -> bytes:
    if len(body) < 0x3F and not long:
        return struct.pack("<H", (code << 6) | len(body)) + body
    return struct.pack("<H", (code << 6) | 0x3F) + struct.pack("<I", len(body)) + body


def swf_rect(x_max: int = 11000, y_max: int = 8000) -> bytes:
    """A RECT (twips) with x_min = y_min = 0, 15 bits a field."""
    bits = f"{15:05b}" + "".join(f"{value:015b}" for value in (0, x_max, 0, y_max))
    bits += "0" * (-len(bits) % 8)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def swf_body(tags: bytes, frame_count: int = 1, frame_rate: float = 24.0) -> bytes:
    return swf_rect() + struct.pack("<H", int(frame_rate * 256)) + struct.pack("<H", frame_count) + tags


def swf_fws(body: bytes, version: int = 8) -> bytes:
    return b"FWS" + bytes([version]) + struct.pack("<I", 8 + len(body)) + body


def swf_cws(body: bytes, version: int = 8) -> bytes:
    return b"CWS" + bytes([version]) + struct.pack("<I", 8 + len(body)) + zlib.compress(body, 9)


def swf_zws(body: bytes, version: int = 13) -> bytes:
    alone = lzma.compress(body, format=lzma.FORMAT_ALONE)
    props, stream = alone[:5], alone[13:]                    # drop the 8-byte size field
    return (b"ZWS" + bytes([version]) + struct.pack("<I", 8 + len(body))
            + struct.pack("<I", len(stream)) + props + stream)


def avm1(code: int, payload: bytes = b"") -> bytes:
    """One AVM1 action record: a bare byte under 0x80, else code + u16 length + payload."""
    return bytes([code]) if code < 0x80 else bytes([code]) + struct.pack("<H", len(payload)) + payload


def avm1_push(*values) -> bytes:
    """ActionPush of strings, ints, floats (double), bools, None and ("const", i) / ("reg", i)."""
    out = bytearray()
    for value in values:
        if isinstance(value, tuple) and value[0] == "const":
            out += (b"\x08" + bytes([value[1]])) if value[1] < 256 else (b"\x09" + struct.pack("<H", value[1]))
        elif isinstance(value, tuple) and value[0] == "reg":
            out += b"\x04" + bytes([value[1]])
        elif value is None:
            out += b"\x02"
        elif isinstance(value, bool):
            out += b"\x05" + bytes([int(value)])
        elif isinstance(value, int):
            out += b"\x07" + struct.pack("<i", value)
        elif isinstance(value, float):
            raw = struct.pack("<d", value)
            out += b"\x06" + raw[4:] + raw[:4]               # SWF stores the high dword first
        else:
            out += b"\x00" + str(value).encode("utf-8") + b"\x00"
    return avm1(0x96, bytes(out))


def avm1_pool(*strings) -> bytes:
    return avm1(0x88, struct.pack("<H", len(strings)) + b"".join(s.encode("utf-8") + b"\x00" for s in strings))


def lossless_tag_body(char_id: int, matrix, *, scale: int = 1, alpha: bool = False, fmt: int = 5) -> bytes:
    """A DefineBitsLossless(2) body drawing a module matrix: format 5 (32 bits a pixel) or format 3
    (a two-colour palette, rows padded to four bytes)."""
    height, width = len(matrix) * scale, len(matrix[0]) * scale
    raw = bytearray()
    if fmt == 5:
        for y in range(height):
            for x in range(width):
                shade = 0 if matrix[y // scale][x // scale] else 255
                raw += bytes((255, shade, shade, shade))
        return struct.pack("<HBHH", char_id, 5, width, height) + zlib.compress(bytes(raw), 9)
    entry = (lambda r, g, b: bytes((r, g, b, 255))) if alpha else (lambda r, g, b: bytes((r, g, b)))
    raw += entry(255, 255, 255) + entry(0, 0, 0)
    for y in range(height):
        row = bytes(1 if matrix[y // scale][x // scale] else 0 for x in range(width))
        raw += row + bytes(-width % 4)
    return struct.pack("<HBHHB", char_id, 3, width, height, 1) + zlib.compress(bytes(raw), 9)


# ---- GIF --------------------------------------------------------------------------------------------

def text_image(text: str, size=(360, 80), font_size: int = 36, at=(10, 18)):
    """A white picture with black text in a real font when one is found (OCR needs one)."""
    from PIL import Image, ImageDraw, ImageFont
    image = Image.new("L", size, 255)
    font = None
    for name in ("DejaVuSans.ttf", "Arial.ttf", "Helvetica.ttc", "/System/Library/Fonts/Helvetica.ttc",
                 "/Library/Fonts/Arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"):
        try:
            font = ImageFont.truetype(name, font_size)
            break
        except OSError:
            continue
    if font is None:
        font = ImageFont.load_default(size=font_size)
    ImageDraw.Draw(image).text(at, text, fill=0, font=font)
    return image


def gif_bytes(frames, durations=100, loop: int | None = 0, comment: bytes | None = None) -> bytes:
    """An animated GIF of PIL frames; `durations` is one number or one per frame (milliseconds, in
    tens); `loop` None writes no loop extension. Pillow merges equal neighbouring frames, so give
    it frames that differ."""
    out = io.BytesIO()
    frames = [frame.convert("P") for frame in frames]
    extra = {"comment": comment} if comment is not None else {}
    if loop is not None:
        extra["loop"] = loop
    frames[0].save(out, format="GIF", save_all=True, append_images=frames[1:], duration=durations,
                   disposal=1, optimize=False, **extra)
    return out.getvalue()


def bar_frame(k: int, size=(48, 24)):
    """A white frame whose top two rows carry a black bar k + 1 pixels wide from the left edge:
    a frame a test's stand-in OCR can tell from every other."""
    from PIL import Image
    image = Image.new("L", size, 255)
    for x in range(k + 1):
        for y in range(2):
            image.putpixel((x, y), 0)
    return image


def bar_of(png: bytes) -> tuple:
    """(first dark x, dark pixel count) of the top row of a picture made of bar frames."""
    from PIL import Image
    image = Image.open(io.BytesIO(png)).convert("L")
    dark = [x for x in range(image.width) if image.getpixel((x, 0)) < 128]
    return (dark[0], len(dark)) if dark else (None, 0)
