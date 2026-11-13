"""B-013: ctf/fragjoin.py reads image metadata fields in file order and joins split flag fragments.

Fixtures are hand-built PNG / JPEG / GIF / TIFF byte strings (the formats' own layouts), no image library.
"""
import struct
import zlib

import pytest

from ctf import event, flagfmt
from ctf import fragjoin as fj


def chunk(typ: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + typ + body + struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF)


def tiff(entries) -> bytes:
    """A little-endian TIFF with one IFD of ASCII entries [(tag, text)]; values stored after the IFD."""
    n = len(entries)
    ifd_end = 8 + 2 + 12 * n + 4
    head, data = b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", n), b""
    for tag, text in entries:
        raw = text.encode() + b"\x00"
        if len(raw) <= 4:
            head += struct.pack("<HHI", tag, 2, len(raw)) + raw.ljust(4, b"\x00")
        else:
            head += struct.pack("<HHII", tag, 2, len(raw), ifd_end + len(data))
            data += raw
    return head + struct.pack("<I", 0) + data


def xmp(description: str) -> str:
    return ('<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">'
            f'<dc:description><rdf:Alt><rdf:li xml:lang="x-default">{description}</rdf:li></rdf:Alt>'
            '</dc:description></rdf:Description></rdf:RDF></x:xmpmeta>')


def png(*chunks) -> bytes:
    ihdr = chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
    idat = chunk(b"IDAT", zlib.compress(b"\x00\x00"))
    return fj.PNG_SIG + ihdr + b"".join(chunks) + idat + chunk(b"IEND", b"")


def itxt(keyword: bytes, text: str, compressed=False) -> bytes:
    body = text.encode()
    if compressed:
        body = zlib.compress(body)
    return chunk(b"iTXt", keyword + b"\x00" + (b"\x01" if compressed else b"\x00") + b"\x00" + b"\x00" + b"\x00" + body)


@pytest.fixture
def spooky():
    return flagfmt.for_profile(event.load("spooky"))


def tanny_png(decoy=True):
    """The Tormented-Tanny shape: tEXt, XMP in iTXt and eXIf each hold one third of the flag."""
    parts = [chunk(b"tEXt", b"Comment\x00spooky{split_")]
    if decoy:
        parts.append(chunk(b"tEXt", b"Software\x00GIMP 2.10"))
    parts.append(itxt(b"XML:com.adobe.xmp", xmp("across_three_")))
    parts.append(chunk(b"eXIf", tiff([(0x010E, "containers}")])))
    return png(*parts)


def test_png_fields_in_file_order_from_every_container():
    f = fj.fields(tanny_png())
    texts = [(x.container, x.text) for x in f]
    assert texts == [("png:tEXt", "spooky{split_"), ("png:tEXt", "GIMP 2.10"),
                     ("png:iTXt/xmp", "across_three_"), ("png:eXIf", "containers}")]
    assert f[-1].name == "ImageDescription"


def test_join_recovers_the_tanny_flag_first_despite_a_decoy_field(spooky):
    joins = fj.join(fj.fields(tanny_png()), spooky)
    assert joins[0].flag == "spooky{split_across_three_containers}"
    assert [p.container for p in joins[0].parts] == ["png:tEXt", "png:iTXt/xmp", "png:eXIf"]
    # The variant with the decoy in it is a valid flag shape too; it ranks below.
    assert "spooky{split_GIMP 2.10across_three_containers}" in [j.flag for j in joins[1:]]


def test_no_join_without_a_closing_fragment(spooky):
    data = png(chunk(b"tEXt", b"Comment\x00spooky{split_"), chunk(b"tEXt", b"Author\x00no close here"))
    assert fj.join(fj.fields(data), spooky) == []


def test_opening_needs_the_events_prefix(spooky):
    data = png(chunk(b"tEXt", b"Comment\x00other{abc_"), chunk(b"tEXt", b"Title\x00def}"))
    assert fj.join(fj.fields(data), spooky) == []
    csctf = flagfmt.for_profile(event.load("csctf"))
    data = png(chunk(b"tEXt", b"Comment\x00csctf{abc_"), chunk(b"tEXt", b"Title\x00def}"))
    assert [j.flag for j in fj.join(fj.fields(data), csctf)] == ["csctf{abc_def}"]   # prefix-insensitive


def test_compressed_itxt_and_ztxt_are_inflated():
    data = png(itxt(b"Description", "zipped text", compressed=True),
               chunk(b"zTXt", b"Comment\x00\x00" + zlib.compress(b"deflated comment")))
    assert [x.text for x in fj.fields(data)] == ["zipped text", "deflated comment"]


def test_jpeg_exif_xmp_and_comment():
    def seg(marker, body):
        return b"\xff" + bytes([marker]) + struct.pack(">H", len(body) + 2) + body
    data = (b"\xff\xd8" + seg(0xE1, b"Exif\x00\x00" + tiff([(0x013B, "artist-part")]))
            + seg(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + xmp("xmp-part").encode())
            + seg(0xFE, b"comment-part") + b"\xff\xda" + b"\x00" * 8 + b"\xff\xd9")
    assert [(x.container, x.text) for x in fj.fields(data)] == [
        ("jpeg:exif", "artist-part"), ("jpeg:xmp", "xmp-part"), ("jpeg:COM", "comment-part")]


def test_gif_comment_extension():
    data = (b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x00\x00\x00"
            + b"\x21\xfe" + bytes([5]) + b"hello" + bytes([3]) + b" go" + b"\x00"
            + b"\x2c" + struct.pack("<HHHH", 0, 0, 1, 1) + b"\x00" + b"\x02" + b"\x02\x44\x01" + b"\x00" + b"\x3b")
    assert [x.text for x in fj.fields(data)] == ["hello go"]


def test_tiff_with_short_inline_value_and_big_endian():
    assert [x.text for x in fj.fields(tiff([(0x010F, "abc")]))] == ["abc"]
    be = b"MM\x00*" + struct.pack(">I", 8) + struct.pack(">H", 1) + struct.pack(">HHI", 0x0131, 2, 4) + b"xyz\x00" \
        + struct.pack(">I", 0)
    assert [(x.name, x.text) for x in fj.fields(be)] == [("Software", "xyz")]


def test_damaged_or_foreign_bytes_give_no_fields():
    assert fj.fields(b"not an image at all") == []
    assert fj.fields(fj.PNG_SIG + b"\x00\x00\x00\xffIHDR") == []
    assert fj.fields(b"II*\x00" + struct.pack("<I", 9999)) == []
