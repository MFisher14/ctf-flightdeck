"""Synthetic PDFs for the B-073 opener tests (tests/test_b073_pdf_opener.py).

Every file is written here byte by byte, with offsets taken as the bytes are laid down: a classic
cross-reference table per revision, incremental updates appended with /Prev, and one PDF 1.5 file whose
cross-reference is a stream and whose dictionaries live in an object stream. Nothing here comes from a
challenge.
"""
from __future__ import annotations

import base64
import re
import zlib

from Cryptodome.Cipher import AES

FLAG = "spooky{b073_synthetic_under_the_bars}"
KEY = b"sixteen byte key"                     # 16 bytes: an AES-128 key that reads as a phrase
MESSAGE = b"report follows\nthe ship was found adrift and empty.\n\n" + FLAG.encode() + b"\n"


def pad(plain: bytes) -> bytes:
    n = 16 - len(plain) % 16
    return plain + bytes([n]) * n


def ecb(key: bytes, plain: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(plain)


def cbc(key: bytes, iv: bytes, plain: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(plain)


def wrap(text: str, width: int = 44) -> list:
    return [text[i:i + width] for i in range(0, len(text), width)]


def stm(content: bytes, extra: bytes = b"") -> bytes:
    """A stream object body with its true /Length."""
    return b"<< /Length %d %s>>\nstream\n" % (len(content), extra) + content + b"\nendstream"


def _revision(out: bytearray, objects: dict, size: int, root: int, info, prev, encrypt) -> None:
    offsets = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"
    xref = len(out)
    nums = sorted(offsets) if prev is not None else [0] + sorted(offsets)
    out += b"xref\n"
    i = 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        out += b"%d %d\n" % (nums[i], j - i + 1)
        for n in nums[i:j + 1]:
            out += b"0000000000 65535 f \n" if n == 0 else b"%010d 00000 n \n" % offsets[n]
        i = j + 1
    out += b"trailer\n<< /Size %d /Root %d 0 R" % (size, root)
    if info is not None:
        out += b" /Info %d 0 R" % info
    if prev is not None:
        out += b" /Prev %d" % prev
    if encrypt is not None:
        out += b" /Encrypt %d 0 R" % encrypt
    out += b" >>\nstartxref\n%d\n%%%%EOF\n" % xref


def make_pdf(objects: dict, *, root: int = 1, info=None, encrypt=None) -> bytes:
    """One revision: objects {number: body bytes}, a classic xref table, a trailer."""
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    _revision(out, objects, max(objects) + 1, root, info, None, encrypt)
    return bytes(out)


def update_pdf(base: bytes, objects: dict, *, root: int = 1, info=None) -> bytes:
    """`base` with an incremental update appended: new or replaced objects, /Prev to the last xref."""
    out = bytearray(base)
    prev = int(re.findall(rb"startxref\s+(\d+)", base)[-1])
    size = max(max(objects) + 1, int(re.findall(rb"/Size (\d+)", base)[-1]))
    _revision(out, objects, size, root, info, prev, None)
    return bytes(out)


def page_objects(content: bytes, *, fonts: bytes = b"", resources: bytes = b"", page: bytes = b"") -> dict:
    """Catalog 1, page tree 2, page 3, content stream 4."""
    return {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << " + fonts
           + b" >> " + resources + b" >> /Contents 4 0 R " + page + b">>",
        4: stm(content),
    }


def page_pdf(content: bytes, *, extra: dict | None = None, info=None, **kw) -> bytes:
    objects = page_objects(content, **kw)
    objects.update(extra or {})
    return make_pdf(objects, info=info)


class CidFont:
    """A composite (Type0, Identity-H) font whose character codes are scattered two-byte numbers:
    its strings read as text only through the ToUnicode map."""

    def __init__(self, alphabet: str, first: int = 0x0131, step: int = 7):
        self.cids = {ch: first + step * i for i, ch in enumerate(dict.fromkeys(alphabet))}

    def show(self, text: str) -> bytes:
        return b"<" + b"".join(b"%04X" % self.cids[ch] for ch in text) + b">"

    def cmap(self) -> bytes:
        rows = b"".join(b"<%04X> <%04X>\n" % (cid, ord(ch)) for ch, cid in self.cids.items())
        return (b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n"
                b"1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n"
                b"%d beginbfchar\n" % len(self.cids) + rows + b"endbfchar\nendcmap end end\n")

    def objects(self, font: int, descendant: int, cmap: int, *, tounicode: bool = True) -> dict:
        out = {
            font: b"<< /Type /Font /Subtype /Type0 /BaseFont /Synth /Encoding /Identity-H "
                  b"/DescendantFonts [%d 0 R]" % descendant
                  + (b" /ToUnicode %d 0 R" % cmap if tounicode else b"") + b" >>",
            descendant: b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /Synth >>",
        }
        if tounicode:
            out[cmap] = stm(zlib.compress(self.cmap()), b"/Filter /FlateDecode ")
        return out


B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

XMP = (b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
       b'<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Synthetic XMP Core 1.0">\n'
       b' <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
       b'  <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"\n'
       b'    xmlns:pdf="http://ns.adobe.com/pdf/1.3/" pdf:Producer="Synth &amp; Sons">\n'
       b'   <dc:description><rdf:Alt><rdf:li xml:lang="x-default">%s</rdf:li></rdf:Alt></dc:description>\n'
       b'   <!-- <dc:ghost>not a field</dc:ghost> -->\n'
       b'   <dc:title><rdf:Alt><rdf:li xml:lang="x-default">Report &lt;draft&gt;</rdf:li></rdf:Alt></dc:title>\n'
       b'  </rdf:Description>\n </rdf:RDF>\n</x:xmpmeta>\n<?xpacket end="w"?>')


def redacted_pdf(*, key: bytes = KEY, message: bytes = MESSAGE, subject: bytes | None = None,
                 text_colour: bytes = b"0 0 0 rg", bars: bool = True, xmp: bool = True) -> bytes:
    """The shape this item exists for: a heading, then base64 of an AES-128-ECB ciphertext drawn in
    black on black bars through a composite font, and the key as the Info /Subject (and the XMP
    dc:description). `subject` writes another /Subject than the key that encrypted the text."""
    font = CidFont(B64 + "Tel ")
    lines = wrap(base64.b64encode(ecb(key, pad(message))).decode())
    content = [b"1 1 1 rg 0 0 612 792 re f", b"0 0 0 rg"]             # a white page, then the bars
    for i in range(len(lines) if bars else 0):
        content.append(b"72 %d 400 14 re f" % (690 - 20 * i))
    content.append(b"BT /F1 18 Tf 0 0 0 rg 72 740 Td " + font.show("Tell") + b" Tj ET")
    for i, line in enumerate(lines):
        content.append(b"BT /F1 10 Tf " + text_colour + b" 1 0 0 1 72 %d Tm " % (693 - 20 * i)
                       + font.show(line) + b" Tj ET")
    subject = key if subject is None else subject
    objects = page_objects(b"\n".join(content), fonts=b"/F1 5 0 R")
    objects.update(font.objects(5, 6, 7))
    objects[8] = b"<< /Title (Report) /Subject (" + subject + b") /Producer (Synth PDF m1) >>"
    if xmp:
        objects[1] = b"<< /Type /Catalog /Pages 2 0 R /Metadata 9 0 R >>"
        objects[9] = stm(XMP % subject, b"/Type /Metadata /Subtype /XML ")
    return make_pdf(objects, info=8)


def objstm_pdf(content: bytes, info: bytes) -> bytes:
    """A PDF 1.5 file: the cross-reference is a stream (FlateDecode, PNG "up" predictor) and the
    catalog, page tree, page, font and Info dictionaries are compressed into one object stream."""
    members = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> "
           b"/Contents 4 0 R >>",
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        6: info,
    }
    head, body = b"", b""
    for num, value in members.items():
        head += b"%d %d " % (num, len(body))
        body += value + b"\n"
    out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets = {4: len(out)}
    out += b"4 0 obj\n" + stm(zlib.compress(content), b"/Filter /FlateDecode ") + b"\nendobj\n"
    offsets[7] = len(out)
    packed = zlib.compress(head + body)
    out += b"7 0 obj\n" + stm(packed, b"/Type /ObjStm /N %d /First %d /Filter /FlateDecode " % (len(members), len(head))) \
        + b"\nendobj\n"
    xref = len(out)
    rows = []
    order = list(members)
    for num in range(9):
        if num == 0:
            rows.append(bytes([0, 0, 0, 0, 255]))
        elif num in members:
            rows.append(bytes([2]) + (7).to_bytes(3, "big") + bytes([order.index(num)]))
        else:
            rows.append(bytes([1]) + {4: offsets[4], 7: offsets[7], 8: xref}[num].to_bytes(3, "big") + bytes([0]))
    predicted, previous = b"", bytes(5)
    for row in rows:                          # PNG predictor 12: every row is "up" (tag 2)
        predicted += bytes([2]) + bytes((a - b) & 255 for a, b in zip(row, previous))
        previous = row
    table = zlib.compress(predicted)
    out += b"8 0 obj\n" + stm(table, b"/Type /XRef /Size 9 /W [1 3 1] /Root 1 0 R /Info 6 0 R /Filter /FlateDecode "
                              b"/DecodeParms << /Predictor 12 /Columns 5 >> ") + b"\nendobj\n"
    out += b"startxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)
