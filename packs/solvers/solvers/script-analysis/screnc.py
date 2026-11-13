#!/usr/bin/env python3
"""Microsoft Script Encoder (screnc.exe) blocks: decode, verify, and (for fixtures) encode.

A .vbe or .jse file, or a <script language="VBScript.Encode"> / "JScript.Encode" block of a
.wsf, .hta or .sct, holds the script as one or more blocks

    #@~^LLLLLL==<encoded text>CCCCCC==^#~@

LLLLLL== is the base64 of the encoded text's length (a 32-bit little-endian number, counted in
characters of the encoded text, an escape pair counting two), CCCCCC== the base64 of the
checksum: the sum of the decoded characters, modulo 2**32. The encoded text is a substitution
by position: the j-th decoded character of the block (j from 0) is DICTIONARY[e][PICK[j % 64]]
for the encoded character e. Five characters are never substituted but escaped, and each
escape pair is one decoded character (it advances j and counts in the checksum):

    @#  CR    @&  LF    @!  <    @*  >    @$  @

The tables are the public ones: Wine's dlls/jscript/decode.c (the interpreter's own decoder,
which verifies the checksum the same way), cross-checked against Didier Stevens' decode-vbe.py
on every (character, position) pair; each column of DICTIONARY is a one-to-one map over the 123
characters the encoder substitutes. Wine's own test vectors are in test_wavec_encoded.py.

Fail closed. A block is decoded only when its header, its length, its checksum and its closing
mark all agree; anything else is no decode (decode() returns None with the reason), never a
best effort. A character above 127 inside a block is not in the tables: Wine refuses the block.
The pass-through readings other decoders use for it (the character kept as it is, with or
without a position and a share of the checksum) are tried, and a decode is given only when
exactly one of them matches the checksum.

Only where the script host decodes. The host runs the decoder only for the VBScript.Encode
and JScript.Encode engines: on the whole of a .vbe or .jse, and on the body of a <script>
element whose language attribute is VBScript.Encode or JScript.Encode in a .wsf, .hta, .sct or
.wsc. Anywhere else (a .vbs, .js, .ps1, .py, a <script language="VBScript">, the text around
the elements) a #@~^ is inert text, a comment or a string, and decode_hosted() leaves it byte
for byte as it is: a block there is never decoded, and a marker there is never a bad block.

Pure Python, no external tool; nothing is run. Usage: screnc.py FILE... prints the decoded text
of each file as the host would read it (by its extension).
"""
import base64
import binascii
import html
import re
import struct
import sys

PICK = (1, 2, 0, 1, 2, 0, 2, 0, 0, 2, 0, 2, 1, 0, 2, 0, 1, 0, 2, 0, 1, 1, 2, 0, 0, 2, 1, 0, 2, 0, 0, 2,
        1, 1, 0, 2, 0, 2, 0, 1, 0, 1, 1, 2, 0, 1, 0, 2, 1, 0, 2, 0, 1, 1, 2, 0, 0, 1, 1, 2, 0, 1, 0, 2)

DICTIONARY = (
    "\x00\x00\x00", "\x01\x01\x01", "\x02\x02\x02", "\x03\x03\x03",
    "\x04\x04\x04", "\x05\x05\x05", "\x06\x06\x06", "\x07\x07\x07",
    "\x08\x08\x08", "\x7b\x57\x6e", "\x0a\x0a\x0a", "\x0b\x0b\x0b",
    "\x0c\x0c\x0c", "\x0d\x0d\x0d", "\x0e\x0e\x0e", "\x0f\x0f\x0f",
    "\x10\x10\x10", "\x11\x11\x11", "\x12\x12\x12", "\x13\x13\x13",
    "\x14\x14\x14", "\x15\x15\x15", "\x16\x16\x16", "\x17\x17\x17",
    "\x18\x18\x18", "\x19\x19\x19", "\x1a\x1a\x1a", "\x1b\x1b\x1b",
    "\x1c\x1c\x1c", "\x1d\x1d\x1d", "\x1e\x1e\x1e", "\x1f\x1f\x1f",
    "\x32\x2e\x2d", "\x30\x47\x75", "\x21\x7a\x52", "\x29\x56\x60",
    "\x5b\x42\x71", "\x38\x6a\x5e", "\x33\x2f\x49", "\x3d\x26\x5c",
    "\x58\x49\x62", "\x3a\x41\x7d", "\x35\x34\x29", "\x65\x32\x36",
    "\x39\x5b\x20", "\x5c\x76\x7c", "\x56\x72\x7a", "\x73\x43\x7f",
    "\x66\x38\x6b", "\x4e\x39\x63", "\x45\x70\x33", "\x6b\x45\x2b",
    "\x62\x68\x68", "\x59\x71\x51", "\x78\x4f\x66", "\x5e\x09\x76",
    "\x7d\x62\x31", "\x4a\x44\x64", "\x6d\x23\x54", "\x71\x75\x43",
    "\x00\x00\x00", "\x60\x7e\x3a", "\x00\x00\x00", "\x53\x5e\x7e",
    "\x00\x00\x00", "\x42\x77\x45", "\x27\x4a\x2c", "\x48\x61\x2a",
    "\x72\x5d\x74", "\x75\x22\x27", "\x31\x4b\x37", "\x37\x6f\x44",
    "\x4d\x4e\x79", "\x52\x3b\x59", "\x22\x4c\x2f", "\x54\x50\x6f",
    "\x6a\x67\x26", "\x47\x2a\x72", "\x64\x7d\x6a", "\x2d\x74\x39",
    "\x20\x54\x7b", "\x7f\x2b\x3f", "\x2e\x2d\x38", "\x4c\x2c\x77",
    "\x5d\x30\x67", "\x7e\x6e\x53", "\x6c\x6b\x47", "\x6f\x66\x34",
    "\x79\x35\x78", "\x74\x25\x5d", "\x43\x21\x30", "\x26\x64\x23",
    "\x76\x4d\x5a", "\x25\x52\x5b", "\x24\x63\x6c", "\x2b\x3f\x48",
    "\x28\x7b\x55", "\x23\x78\x70", "\x41\x29\x69", "\x34\x28\x2e",
    "\x09\x73\x4c", "\x2a\x59\x21", "\x44\x33\x24", "\x3f\x7f\x4e",
    "\x77\x6d\x50", "\x3b\x55\x09", "\x55\x53\x56", "\x69\x7c\x73",
    "\x61\x3a\x35", "\x63\x5f\x61", "\x50\x65\x4b", "\x67\x46\x58",
    "\x51\x58\x3b", "\x49\x31\x57", "\x4f\x69\x22", "\x46\x6c\x6d",
    "\x68\x5a\x4d", "\x7c\x48\x25", "\x36\x27\x28", "\x70\x5c\x46",
    "\x6e\x3d\x4a", "\x7a\x24\x32", "\x2f\x79\x41", "\x5f\x37\x3d",
    "\x4b\x60\x5f", "\x5a\x51\x4f", "\x2c\x20\x42", "\x57\x36\x65",
)

ESCAPES = {"#": "\r", "&": "\n", "!": "<", "*": ">", "$": "@"}
ESCAPED = {v: "@" + k for k, v in ESCAPES.items()}
OPEN, CLOSE = "#@~^", "^#~@"
DWORD = r"[A-Za-z0-9+/]{6}=="
HEADER = re.compile(r"#@~\^(" + DWORD + ")")
# The marker alone: the cheap test that decides whether a file is looked at at all.
MARK_BYTES = (b"#@~^", "#@~^".encode("utf-16-le"), "#@~^".encode("utf-16-be"))
# The character each column turns an encoded character into, reversed: (plain char -> encoded char).
_INVERSE = tuple({DICTIONARY[e][p]: chr(e) for e in range(128) if chr(e) not in "<>@\r\n"} for p in range(3))
MAX_BLOCK = 1 << 24      # characters; the length field of a block longer than this is not believed


class BadBlock(ValueError):
    """A block whose header, length, checksum or closing mark does not agree."""


def dword(field: str):
    """The number in an 8-character `XXXXXX==` field (base64 of 4 bytes, little-endian); None if it is not one."""
    if not re.fullmatch(DWORD, field or ""):
        return None
    try:
        return struct.unpack("<I", base64.b64decode(field))[0]
    except (binascii.Error, struct.error, ValueError):
        return None


def dword_field(n: int) -> str:
    return base64.b64encode(struct.pack("<I", n & 0xFFFFFFFF)).decode("ascii")


def _decode_data(data: str, high: str):
    """(decoded text, checksum) of a block's encoded text. `high` is the reading of a character
    above 127: 'refuse' (Wine), or 'keep+N', 'keep+S', 'keep+NS', 'keep' (kept as it is; N: it
    takes a position, S: it counts in the checksum)."""
    out, j, total, i, n = [], 0, 0, 0, len(data)
    while i < n:
        c = data[i]
        if c == "@":
            if i + 1 >= n or data[i + 1] not in ESCAPES:
                raise BadBlock(f"unknown escape @{data[i + 1:i + 2]!r} at {i}")
            d = ESCAPES[data[i + 1]]
            i += 2
        else:
            o = ord(c)
            i += 1
            if o >= 128:
                if high == "refuse":
                    raise BadBlock(f"character {o:#x} above 127 at {i - 1}")
                out.append(c)
                if "S" in high:
                    total += o
                if "N" in high:
                    j += 1
                continue
            d = DICTIONARY[o][PICK[j % 64]]
        out.append(d)
        total += ord(d)
        j += 1
    return "".join(out), total & 0xFFFFFFFF


def decode_block(text: str, at: int):
    """(decoded text, end index) of the block whose `#@~^` is at text[at]; raises BadBlock."""
    if not text.startswith(OPEN, at):
        raise BadBlock("no #@~^ here")
    length = dword(text[at + 4:at + 12])
    if length is None:
        raise BadBlock("the length field is not XXXXXX==")
    if length > MAX_BLOCK:
        raise BadBlock(f"length {length} is not believed")
    start = at + 12
    data = text[start:start + length]
    if len(data) != length:
        raise BadBlock(f"the text ends before the block's {length} characters")
    tail = start + length
    checksum = dword(text[tail:tail + 8])
    if checksum is None:
        raise BadBlock("the checksum field is not XXXXXX== where the length says it is")
    if not text.startswith(CLOSE, tail + 8):
        raise BadBlock("no ^#~@ after the checksum")
    if any(ord(c) >= 128 for c in data):
        readings = set()
        for high in ("keep", "keep+N", "keep+S", "keep+NS"):
            try:
                plain, total = _decode_data(data, high)
            except BadBlock:
                continue
            if total == checksum:
                readings.add(plain)
        if len(readings) != 1:
            raise BadBlock(f"characters above 127: {len(readings)} readings match the checksum")
        return readings.pop(), tail + 12
    plain, total = _decode_data(data, "refuse")
    if total != checksum:
        raise BadBlock(f"checksum {total:#x} is not the block's {checksum:#x}")
    return plain, tail + 12


def has_marker(data) -> bool:
    """Whether the bytes (or text) hold a `#@~^` at all: the cheap test before anything else."""
    if isinstance(data, str):
        return OPEN in data
    return any(m in data for m in MARK_BYTES)


def in_cdata(text: str, at: int) -> bool:
    """Whether text[at] lies inside an XML CDATA section."""
    opened = text.rfind("<![CDATA[", 0, at)
    return opened >= 0 and text.rfind("]]>", opened, at) < 0


def _escaped_block(text: str, at: int, header_end: int):
    """(decoded text, end) of a block written with XML entities (&amp; for an encoded &): the
    block as the XML parser hands it to the script host. Each later ^#~@ is tried as its end;
    the first whose unescaped text is exactly one well-formed block is taken."""
    close, tries = header_end, 0
    while tries < 8:
        close = text.find(CLOSE, close)
        if close < 0:
            break
        seg = html.unescape(text[at:close + 4])
        try:
            plain, end = decode_block(seg, 0)
            if end == len(seg):
                return plain, close + 4
        except BadBlock:
            pass
        close, tries = close + 1, tries + 1
    raise BadBlock("no reading of the block, as written or with its XML entities undone, agrees")


def decode(text: str, xml: bool = False):
    """(decoded text, number of blocks) with every block replaced by its decoded text, or
    (None, reason) when a block does not decode. As in the script host (Wine's decode_source),
    every `#@~^` starts a block: one whose length field is not XXXXXX== is a bad block too.

    xml=True is for a .wsf or .sct: a block that does not decode as written is tried with its
    XML entities undone, and a decoded text outside a CDATA section is put back with &, < and >
    escaped, so that the file stays the XML that holds this script."""
    out, at, count = [], 0, 0
    while True:
        start = text.find(OPEN, at)
        if start < 0:
            out.append(text[at:])
            return "".join(out), count
        out.append(text[at:start])
        try:
            try:
                plain, end = decode_block(text, start)
            except BadBlock:
                if not xml or not HEADER.match(text, start):
                    raise
                plain, end = _escaped_block(text, start, start + 12)
        except BadBlock as e:
            return None, f"block {count + 1} at offset {start}: {e}"
        if xml and not in_cdata(text, start):
            plain = html.escape(plain, quote=False)
        out.append(plain)
        at, count = end, count + 1


# The files whose bytes the host decodes, whole or inside an Encode script element.
WHOLE = (".vbe", ".jse")
HOSTS = (".wsf", ".hta", ".sct", ".wsc")
SCRIPT_OPEN = re.compile(r"(?i)<script\b([^<>]*)>")
SCRIPT_CLOSE = re.compile(r"(?i)</script\s*>")
LANGUAGE_ATTR = re.compile(r"""(?i)\blanguage\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>/]+))""")
ENCODE_ENGINES = ("vbscript.encode", "jscript.encode")


def encode_element(attrs: str) -> bool:
    """Whether a <script> tag's attributes name an Encode engine (VBScript.Encode or JScript.Encode)."""
    m = LANGUAGE_ATTR.search(attrs or "")
    if not m:
        return False
    return next(g for g in m.groups() if g is not None).strip().lower() in ENCODE_ENGINES


def hosted(ext: str) -> bool:
    """Whether a file with this extension can hold a block the host decodes."""
    return (ext or "").lower() in WHOLE + HOSTS


def decode_hosted(text: str, ext: str):
    """(text as the host reads it, number of blocks decoded), or (None, reason) when a block
    the host would decode does not decode.

    .vbe/.jse: the whole file (decode()). .wsf/.hta/.sct/.wsc: the body of every <script>
    element whose language is VBScript.Encode or JScript.Encode, with XML entities handled for
    the XML containers (not the .hta); the rest of the file is kept as written. Any other
    extension, and every byte outside those places: (text, 0), the text unchanged."""
    ext = (ext or "").lower()
    if ext in WHOLE:
        return decode(text)
    if ext not in HOSTS or OPEN not in text:
        return text, 0
    xml = ext != ".hta"
    out, at, pos, count = [], 0, 0, 0
    while True:
        m = SCRIPT_OPEN.search(text, pos)
        if not m:
            break
        if m.group(1).rstrip().endswith("/"):
            pos = m.end()
            continue
        close = SCRIPT_CLOSE.search(text, m.end())
        if not close:
            break
        pos = close.end()
        if not encode_element(m.group(1)):
            continue
        body = text[m.end():close.start()]
        if OPEN not in body:
            continue
        got, info = decode(body, xml=xml)
        if got is None:
            return None, f"<script> at offset {m.start()}: {info}"
        out.append(text[at:m.end()])
        out.append(got)
        at, count = close.start(), count + info
    out.append(text[at:])
    return "".join(out), count


def encode(plain: str) -> str:
    """One block holding `plain`, as screnc writes it. Raises ValueError on a character above
    127 (the encoder's own handling of those is not part of the public tables)."""
    out, total = [], 0
    for j, c in enumerate(plain):
        if ord(c) >= 128:
            raise ValueError(f"character {ord(c):#x} above 127 at {j}")
        total += ord(c)
        out.append(ESCAPED.get(c) or _INVERSE[PICK[j % 64]][c])
    data = "".join(out)
    return OPEN + dword_field(len(data)) + data + dword_field(total) + CLOSE


def main(argv) -> int:
    from pathlib import Path
    if argv and argv[0] in ("-h", "--help"):
        print("usage: screnc.py <encoded-script> [...]")
        return 0
    if not argv:
        print("screnc.py: expected at least one encoded script", file=sys.stderr)
        return 2
    rc = 0
    try:
        for arg in argv:
            raw = Path(arg).read_bytes()
            text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("latin-1")
            got, info = decode_hosted(text, Path(arg).suffix)
            if got is None:
                print(f"{arg}: no decode ({info})", file=sys.stderr)
                rc = 1
            else:
                sys.stdout.write(got)
    except Exception as exc:
        print(f"screnc.py: {exc}", file=sys.stderr)
        return 2
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
