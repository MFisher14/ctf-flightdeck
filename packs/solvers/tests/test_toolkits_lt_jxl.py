"""B-251: the JPEG XL reader (solvers/toolkits/lt_jxl.py).

The codestream header parser is held to the first bytes of real files written by the libjxl encoder
(cjxl v0.11.1, from random PPM, PGM, PFM, PNG, APNG and JPEG images of the stated kinds; the bytes are
recorded here so the check always runs; what libjxl's own jxlinfo says of each file is in its comment).
The fields no encoder run produced are assembled here bit by bit from the layout ISO/IEC 18181-1 gives,
and were read back by libjxl (recorded; asked again where jxlinfo is installed). Containers are
assembled here box by box. Where cjxl and djxl are installed, a lossless round trip is checked pixel
for pixel; without them that test reports as not run.
"""
import random
import shutil
import struct
import subprocess
import sys

import brotli
import pytest

import lt_jxl
from _lt_common import FormatError, NeedsTool
from ctf import flagfmt

H = bytes.fromhex
SRGB = {"colour_space": "RGB", "white_point": "D65", "primaries": "sRGB", "transfer_function": "sRGB",
        "rendering_intent": "relative"}
INT8 = {"float_samples": False, "bits_per_sample": 8, "modular_16bit_buffers": True}
# (first bytes of the codestream cjxl wrote, width, height, the rest of the header facts)
REAL = [
    ("ff0a410600130801006c02671328010050a132ca", 8, 8, {"all_default": True}),
    ("ff0a4f0600130801004947671328010050a132ca", 64, 64, {"all_default": True}),
    ("ff0a7f060013080100724504671328010050a132", 256, 256, {"all_default": True}),
    ("ff0a88f1010013080100556a671328010050a132", 100, 50, {"all_default": True}),            # ratio 2:1
    ("ff0afb06001308010068d186813f36bc03f22300", 320, 240, {"all_default": True}),            # ratio 4:3
    ("ff0aba211d00130801007ca59c31c03b860c04a2", 1920, 1080, {"all_default": True}),          # ratio 16:9, 13-bit height
    ("ff0a58990100130801008851114240f20d04e9e3", 300, 300, {"all_default": True}),
    ("ff0a308000c40013080100ec40279c9482118441", 513, 7, {"all_default": True}),              # explicit width
    ("ff0a7a3ee87c0c001308010048253d2f003ff60e", 1000, 2000, {"all_default": True}),
    ("ff0a3c19014018001308014a28c28da967c32188", 17, 9000, {"all_default": True}),
    ("ff0ae830100908020100a5464b189b9c71840338", 40, 30, {"all_default": False, **INT8, "xyb_encoded": False, **SRGB}),
    # jxlinfo: "JPEG XL animation, 24x16, lossy, 8-bit RGB", four frames of 40, 80, 120, 160 ms (from an APNG)
    ("ff0a030503c809001310455000e800b59f200000152aa38c1bbc9ceb", 24, 16, {
        "all_default": False, "orientation": 1, "have_intrinsic_size": False, "have_preview": False, "have_animation": True,
        "ticks_per_second_numerator": 1000, "ticks_per_second_denominator": 1, "loop_count": 0, "have_timecodes": False,
        **INT8, "xyb_encoded": True, **SRGB}),
    # jxlinfo: "16x8, lossy, 32-bit float (8 exponent bits) RGB" (from a PFM)
    ("ff0ac1c965020025880200a003b59f200000152aa38c1bbc9cebf9f2", 16, 8, {
        "all_default": False, "float_samples": True, "bits_per_sample": 32, "exponent_bits": 8, "modular_16bit_buffers": True,
        "xyb_encoded": True, **SRGB}),
    # jxlinfo: "9x9, lossy, 16-bit Grayscale", "Grayscale, D65, sRGB transfer function, rendering intent: Relative"
    ("ff0a4010fc24c58d00138802005002b59f200000152aa38c1bbc9ceb", 9, 9, {
        "all_default": False, "float_samples": False, "bits_per_sample": 16, "modular_16bit_buffers": True, "xyb_encoded": True,
        "want_icc": False, "colour_space": "grey", "white_point": "D65", "transfer_function": "sRGB",
        "rendering_intent": "relative"}),
    # jxlinfo: "19x11, (possibly) lossless, 8-bit RGB+Alpha" (from an RGBA PNG)
    ("ff0a5050b0120810100060004b188b1500d413638c3331ce019c4159", 19, 11, {
        "all_default": False, **INT8, "extra_channels": [{"type": "alpha"}], "xyb_encoded": False, **SRGB}),
    # jxlinfo: "30x20, lossy, 8-bit RGB", "Orientation: 6 (90 degrees clockwise)", "rendering intent: Perceptual"
    # (from a JPEG with an Exif orientation, re-encoded; the codestream of its jxlp boxes)
    ("ff0a98400b241497040013880200f800b59f200000152aa38c1bbc9c", 30, 20, {
        "all_default": False, "orientation": 6, "have_intrinsic_size": False, "have_preview": False, "have_animation": False,
        **INT8, "xyb_encoded": True, "want_icc": False, **{**SRGB, "rendering_intent": "perceptual"}}),
]
STREAM = H(REAL[3][0]) + bytes(40)             # a real header, then filler: only the header is read


@pytest.mark.parametrize("prefix,width,height,rest", REAL)
def test_codestream_header_matches_real_encoder_output(prefix, width, height, rest):
    assert lt_jxl.read_codestream_header(H(prefix)) == {"width": width, "height": height, **rest}


def box(kind, body):
    return struct.pack(">I4s", 8 + len(body), kind) + body


def container(*more, stream=None, trailing=b""):
    stream = box(b"jxlc", STREAM) if stream is None else stream
    return lt_jxl.CONTAINER + box(b"ftyp", b"jxl \x00\x00\x00\x00jxl ") + b"".join(more) + stream + trailing


def test_container_boxes_metadata_and_hidden_payloads():
    exif = b"\x00\x00\x00\x00II*\x00" + b"camera: synthetic"
    xmp = b"<x:xmpmeta><dc:title>corpus picture</dc:title></x:xmpmeta>"
    packed, tail = brotli.compress(b"<second>compressed packet</second>"), b"\x01\x02 bytes after the last box"
    data = container(box(b"jxll", b"\x0a"), box(b"Exif", exif), box(b"xml ", xmp), box(b"brob", b"xml " + packed),
                     box(b"note", b"a box no specification defines"), trailing=tail)
    blobs = []
    got = lt_jxl.read_jxl(data, blobs)
    assert [b["type"] for b in got["boxes"]] == ["JXL ", "ftyp", "jxll", "Exif", "xml ", "brob", "note", "jxlc"]
    assert (got["container"], got["brand"], got["level"]) == (True, "jxl ", 10)
    assert (got["width"], got["height"], got["codestream_bytes"]) == (100, 50, len(STREAM))
    assert got["xmp"] == [xmp.decode()] and got["exif"] == ["hex:" + exif[4:].hex()]
    assert got["brob"] == [{"type": "xml ", "compressed_bytes": len(packed), "bytes": 34,
                            "content": "<second>compressed packet</second>"}]
    assert got["unknown_boxes"] == [{"type": "note", "size": 30, "content": "a box no specification defines"}]
    assert got["trailing_bytes"] == len(tail) and got["trailing"] == "hex:" + tail.hex()
    labels = dict(blobs)
    assert labels["brob xml "] == b"<second>compressed packet</second>" and labels["box note"] == b"a box no specification defines"
    assert labels["trailing"] == tail and labels["Exif"] == exif


def test_partial_codestream_boxes_are_joined_in_order():
    a, b = STREAM[:7], STREAM[7:]
    parts = box(b"jxlp", struct.pack(">I", 0) + a) + box(b"Exif", b"\x00\x00\x00\x00x") + box(b"jxlp", struct.pack(">I", 0x80000001) + b)
    got = lt_jxl.read_jxl(container(stream=parts))
    assert (got["codestream_parts"], got["codestream_bytes"], got["width"], got["height"]) == (2, len(STREAM), 100, 50)
    wrong = box(b"jxlp", struct.pack(">I", 1) + a) + box(b"jxlp", struct.pack(">I", 0x80000000) + b)
    with pytest.raises(FormatError, match=r"numbered \[1, 0\]"):
        lt_jxl.read_jxl(container(stream=wrong))
    with pytest.raises(FormatError, match="not marked as the last"):
        lt_jxl.read_jxl(container(stream=box(b"jxlp", struct.pack(">I", 0) + STREAM)))


def test_large_and_to_the_end_box_sizes():
    large = struct.pack(">I4sQ", 1, b"jxlc", 16 + len(STREAM)) + STREAM
    assert lt_jxl.read_jxl(container(stream=large))["width"] == 100
    to_end = struct.pack(">I4s", 0, b"jxlc") + STREAM
    got = lt_jxl.read_jxl(container(stream=to_end))
    assert got["codestream_bytes"] == len(STREAM) and "trailing_bytes" not in got


def test_refusals():
    with pytest.raises(FormatError, match="neither a JPEG XL codestream"):
        lt_jxl.read_jxl(b"\x89PNG\r\n\x1a\n" + bytes(20))
    with pytest.raises(FormatError, match="no codestream box"):
        lt_jxl.read_jxl(container(stream=b""))
    with pytest.raises(FormatError, match="no codestream box"):          # a box that states more than the file holds
        lt_jxl.read_jxl(container(stream=struct.pack(">I4s", 4096, b"jxlc") + STREAM))
    cut = lt_jxl.read_jxl(container(trailing=struct.pack(">I4s", 4096, b"Exif") + b"lost"))
    assert cut["trailing_bytes"] == 12 and [b["type"] for b in cut["boxes"]][-1] == "jxlc"
    with pytest.raises(FormatError, match="brob box at offset .* does not decompress"):
        lt_jxl.read_jxl(container(box(b"brob", b"Exif" + b"\xff" * 12)))
    with pytest.raises(FormatError, match="ends inside its header"):
        lt_jxl.read_jxl(H("ff0a30"))
    assert not lt_jxl.detect(b"\xff\xd8\xff\xe0" + bytes(20)) and not lt_jxl.detect(b"\xff\x0a")
    assert lt_jxl.detect(H(REAL[0][0])) and lt_jxl.detect(container()[:64])


def test_pixel_decode_names_the_missing_decoder(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(NeedsTool, match="needs_tool djxl") as e:
        lt_jxl.decode_pixels(STREAM)
    assert e.value.tool == "djxl"


@pytest.mark.needs_tool("cjxl", "djxl", "py:PIL")
def test_lossless_round_trip_through_the_reference_tools(tmp_path):
    from PIL import Image
    import io
    width, height = 37, 21
    pixels = bytes((x * 7 + y * 13 + c * 101) & 0xFF for y in range(height) for x in range(width) for c in range(3))
    src = tmp_path / "in.ppm"
    src.write_bytes(b"P6\n%d %d\n255\n" % (width, height) + pixels)
    out = tmp_path / "out.jxl"
    subprocess.run([shutil.which("cjxl"), str(src), str(out), "-d", "0", "--quiet"], check=True, timeout=300)
    data = out.read_bytes()
    got = lt_jxl.read_jxl(data)
    assert (got["width"], got["height"], got["bits_per_sample"]) == (width, height, 8)
    image = Image.open(io.BytesIO(lt_jxl.decode_pixels(data))).convert("RGB")
    assert image.size == (width, height) and image.tobytes() == pixels
    with pytest.raises(FormatError, match="djxl refused the file"):
        lt_jxl.decode_pixels(data[:len(data) // 3])


def test_solve_scans_boxes_compressed_metadata_and_trailing_bytes(tmp_path):
    lead = flagfmt.cribs()[0]
    a, b, c = lead + "jxl_unknown_box}", lead + "jxl_brotli_exif}", lead + "jxl_after_last_box}"
    (tmp_path / "pic.jxl").write_bytes(container(box(b"flag", b"\x00\x01" + a.encode() + b"\xff")))
    r = lt_jxl.solve(tmp_path)
    assert (r.status, r.flags) == ("solved", (a,))
    (tmp_path / "pic.jxl").write_bytes(container(box(b"brob", b"Exif" + brotli.compress(b"\x00\x00\x00\x00" + b.encode()))))
    assert lt_jxl.solve(tmp_path).flags == (b,)
    (tmp_path / "pic.jxl").write_bytes(container(trailing=b"\xfe\xfe" + c.encode()))
    assert lt_jxl.solve(tmp_path).flags == (c,)
    (tmp_path / "pic.jxl").write_bytes(STREAM)
    r = lt_jxl.solve(tmp_path, decode="1")              # solve never starts the decoder
    assert r.status == "unsure" and "width=100, height=50" in r.evidence[0].detail
    (tmp_path / "pic.jxl").unlink()
    assert lt_jxl.solve(tmp_path).status == "none"


# ------------------------------------------------------------------ round 1: the whole image header

def bits(*fields) -> bytes:
    """Pack (value, width) fields as the codestream does: least significant bit first, zero padded to a byte."""
    acc = n = 0
    for value, width in fields:
        acc |= value << n
        n += width
    return acc.to_bytes((n + 7) // 8, "little")


def enum(v):
    """An enumeration value as the format packs it (two selector bits; 0, 1, 2 + 4 bits, 18 + 6 bits)."""
    return [(0, 2)] if v == 0 else [(1, 2)] if v == 1 else [(2, 2), (v - 2, 4)] if v < 18 else [(3, 2), (v - 18, 6)]


def f16(x):
    return (struct.unpack("<H", struct.pack("<e", x))[0], 16)


def header(*fields) -> bytes:
    return b"\xff\x0a" + bits(*fields)


SIZE_5000X300 = [(0, 1), (0, 2), (300 - 1, 9), (0, 3), (1, 2), (5000 - 1, 13)]     # not small; height; ratio 0; width
SIZE_24X16 = [(1, 1), (16 // 8 - 1, 5), (4, 3)]                                    # small; height / 8 - 1; ratio 3:2
DEPTH_CHANNEL = [(0, 1), *enum(1), (0, 1), (3, 2), (16 - 1, 6), (1, 2),            # depth, integer, 16 bits, dim_shift 3
                 (1, 2), (5, 4), *[(c, 8) for c in b"depth"]]                      # a five-letter name
COLOUR = [(0, 1), (0, 1), *enum(0),                                                # not default, no ICC, RGB
          *enum(2), (0, 2), (312700, 19), (0, 2), (329000, 19),                    # a custom white point
          *enum(11), (1, 1), (4545455, 24), *enum(3)]                              # P3; a gamma; absolute
TONE = [(0, 1), f16(8.0), f16(0.0), (1, 1), f16(0.0)]                              # intensity, min nits, relative, linear below
# Every field a header can carry before the preview flag, then with and without a preview. libjxl's jxlinfo
# 0.11.1 read these same bytes (followed by another image's frames) as: 5000x300, 12-bit RGB+Alpha+Depth,
# extra channel 1 Depth 16 bits dim_shift 3 name depth, intensity_target 8 nits, relative_to_max_display 1,
# Preview image 42x32 (in RICH), Intrinsic dimensions 96x80, Orientation 3, white_point(x=0.156350,y=0.164500),
# P3 primaries, gamma(0.454545), rendering intent Absolute. test_libjxl_reads_the_same_headers asks it again.
RICH_TAIL = [(0, 1),                                                               # no animation
             (0, 1), (2, 2), (0, 1),                                               # integer samples, 12 bits; no 16-bit buffers
             (2, 2), (0, 4), (1, 1), *DEPTH_CHANNEL,                               # two extra channels: a default alpha, the depth
             (0, 1), *COLOUR, *TONE, (0, 2), (1, 1)]                               # not xyb; colour; tone mapping; no extensions; default_m
RICH_HEAD = SIZE_5000X300 + [(0, 1), (1, 1), (2, 3), (1, 1), (1, 1), (10 - 1, 5), (2, 3)]    # extra fields; orientation 3; intrinsic 96x80
RICH = header(*RICH_HEAD, (1, 1), (1, 1), (2, 2), (4 - 1, 5), (3, 3), *RICH_TAIL)   # a preview of 8 * 4 rows, 4:3
NO_PREVIEW = header(*RICH_HEAD, (0, 1), *RICH_TAIL)
RICH_FACTS = {
    "width": 5000, "height": 300, "all_default": False, "orientation": 3, "have_intrinsic_size": True,
    "intrinsic_width": 96, "intrinsic_height": 80, "have_preview": False, "have_animation": False, "float_samples": False,
    "bits_per_sample": 12, "modular_16bit_buffers": False,
    "extra_channels": [{"type": "alpha"}, {"type": "depth", "float_samples": False, "bits_per_sample": 16, "dim_shift": 3,
                                           "name": "depth"}],
    "xyb_encoded": False, "want_icc": False, "colour_space": "RGB", "white_point": "custom", "white_point_xy": [0.15635, 0.1645],
    "primaries": "P3", "gamma": 0.4545455, "rendering_intent": "absolute", "intensity_target": 8.0, "min_nits": 0.0,
    "relative_to_max_display": True, "linear_below": 0.0}
# grey, 16-bit float samples with 5 exponent bits, white point E, linear, saturation (jxlinfo: "16-bit float
# (5 exponent bits) Grayscale", "Grayscale, E, Linear transfer function, rendering intent: Saturation")
GREY_FLOAT = header(*SIZE_5000X300, (0, 1), (0, 1), (1, 1), (1, 2), (5 - 1, 4), (1, 1), (0, 2), (0, 1),
                    (0, 1), (0, 1), *enum(1), *enum(10), (0, 1), *enum(8), *enum(2), (0, 2), (1, 1))
# An animation header as cjxl writes it (24x16, extra fields, 8 bits, xyb, sRGB), up to the tone mapping flag.
ANIMATION = SIZE_24X16 + [(0, 1), (1, 1), (4, 3), (0, 1), (0, 1), (1, 1)]          # orientation 5; an animation follows
AFTER_TICKS = [(0, 1), (0, 1), (0, 2), (1, 1), (0, 2), (1, 1), (1, 1), (1, 1)]     # no timecodes .. tone mapping default


def test_bit_packing_helper_matches_the_bytes_libjxl_wrote():
    # the first header bytes of a real cjxl animation (REAL: ff0a030503c809...), assembled field by field
    real = header(*SIZE_24X16, (0, 1), (1, 1), (0, 3), (0, 1), (0, 1), (1, 1), (1, 2), (0, 2), (0, 2), *AFTER_TICKS, (0, 2), (1, 1))
    assert real == H("ff0a030503c809")


@pytest.mark.parametrize("ticks,numerator,denominator,loops", [
    # selector 2: 10 bits + 1, 8 bits + 1, 16 bits. jxlinfo: frames of 40, 80 ... ticks last 3200, 6400 ... ms
    ([(2, 2), (25 - 1, 10), (2, 2), (2 - 1, 8), (2, 2), (300, 16)], 25, 2, 300),
    # selector 3 / 1 / 1: 30 bits + 1, the constant 1001, 3 bits. jxlinfo: 444.9, 889.8 ... ms
    ([(3, 2), (90000 - 1, 30), (1, 2), (1, 2), (7, 3)], 90000, 1001, 7),
    ([(0, 2), (0, 2), (0, 2)], 100, 1, 0),
    ([(1, 2), (3, 2), (1001 - 1, 10), (3, 2), (0xDEADBEEF, 32)], 1000, 1001, 0xDEADBEEF),
])
def test_animation_timing_and_orientation_are_read_from_their_own_fields(ticks, numerator, denominator, loops):
    got = lt_jxl.read_codestream_header(header(*ANIMATION, *ticks, *AFTER_TICKS, (0, 2), (1, 1)))
    assert (got["width"], got["height"], got["orientation"], got["have_animation"]) == (24, 16, 5, True)
    assert (got["ticks_per_second_numerator"], got["ticks_per_second_denominator"], got["loop_count"]) == (numerator, denominator, loops)
    assert (got["have_timecodes"], got["bits_per_sample"], got["xyb_encoded"], got["colour_space"]) == (False, 8, True, "RGB")


def test_every_branch_of_the_image_header():
    assert lt_jxl.read_codestream_header(NO_PREVIEW) == RICH_FACTS
    # with a preview the frames do not follow the header: the reading stops, saying where
    assert lt_jxl.read_codestream_header(RICH) == {**RICH_FACTS, "have_preview": True, "preview_width": 42, "preview_height": 32,
                                                   "header_read_to": "the preview frame"}
    assert lt_jxl.read_codestream_header(GREY_FLOAT) == {
        "width": 5000, "height": 300, "all_default": False, "float_samples": True, "bits_per_sample": 16, "exponent_bits": 5,
        "modular_16bit_buffers": True, "xyb_encoded": False, "want_icc": False, "colour_space": "grey", "white_point": "E",
        "transfer_function": "linear", "rendering_intent": "saturation"}
    # an embedded ICC profile: nothing past the colour space is read
    icc = lt_jxl.read_codestream_header(header(*SIZE_24X16, (0, 1), (0, 1), (0, 1), (0, 2), (1, 1), (0, 2), (1, 1),
                                               (0, 1), (1, 1), *enum(0), (0, 2), (1, 1)))
    assert (icc["want_icc"], icc["colour_space"], icc["header_read_to"]) == (True, "RGB", "the ICC profile") and "white_point" not in icc
    # spot colour and CFA channels carry their own fields
    more = lt_jxl.read_codestream_header(header(
        *SIZE_24X16, (0, 1), (0, 1), (0, 1), (0, 2), (1, 1), (2, 2), (0, 4),
        (0, 1), *enum(2), (0, 1), (0, 2), (0, 2), (0, 2), f16(1.0), f16(0.5), f16(0.25), f16(0.75),
        (0, 1), *enum(5), (0, 1), (0, 2), (0, 2), (0, 2), (2, 2), (9 - 3, 4),
        (1, 1), (1, 1), (0, 2), (1, 1)))
    assert more["extra_channels"] == [
        {"type": "spot colour", "float_samples": False, "bits_per_sample": 8, "dim_shift": 0, "spot_colour": [1.0, 0.5, 0.25, 0.75]},
        {"type": "CFA", "float_samples": False, "bits_per_sample": 8, "dim_shift": 0, "cfa_channel": 9}]


# The header of a real cjxl animation rebuilt with header extensions (bits 0 and 2: 40 and 24 bits of payload),
# with custom 2x upsampling weights, and with a custom opsin inverse matrix. Each was put before that file's
# real frames and jxlinfo 0.11.1 listed its four frames (40, 80, 120, 160 ms): the header ends where it is read to.
REAL_ANIMATION = SIZE_24X16 + [(0, 1), (1, 1), (0, 3), (0, 1), (0, 1), (1, 1), (1, 2), (0, 2), (0, 2)] + AFTER_TICKS
OPSIN = (11.03, -9.87, -0.16, -3.25, 4.42, -0.16, -3.59, 2.72, 1.87, -0.0038, -0.0038, -0.0038, 0.94, 0.94, 0.94, 0.145)


@pytest.mark.parametrize("tail,facts,recorded", [
    ([(1, 2), (5 - 1, 4), (2, 2), (40 - 17, 8), (2, 2), (24 - 17, 8), (0xABCDEF0123, 40), (0x777777, 24), (1, 1)],
     {"extensions": 5}, "ff0a030503c8232f3c1809786f5ebdbbbb0b"),
    ([(0, 2), (0, 1), (1, 1), (1, 3)] + [f16(0.01 * i) for i in range(15)], {"custom_transform": True},
     "ff0a030503c83100001f211f25ae271f29662aae2b7b2c1f2dc32d662e0a2fae2f29307b30"),
    ([(0, 2), (0, 1), (0, 1)] + [f16(v) for v in OPSIN] + [(0, 3)], {"custom_transform": True},
     "ff0a030503c88130e91df9231650988de823d665382e68ef077913791379b370a770a770871406"),
])
def test_extensions_and_custom_transform_data_are_read_through_to_the_padding(tail, facts, recorded):
    head = header(*REAL_ANIMATION, *tail)
    assert head == H(recorded)
    got = lt_jxl.read_codestream_header(head)
    assert {k: got[k] for k in facts} == facts and "header_read_to" not in got
    assert (got["ticks_per_second_numerator"], got["rendering_intent"]) == (1000, "relative")
    # the padding after it is checked: the same header with a padding bit set is not a header
    spare = -sum(w for _, w in REAL_ANIMATION + tail) % 8
    if spare:
        with pytest.raises(FormatError, match="padding bits after the image header are not zero"):
            lt_jxl.read_codestream_header(header(*REAL_ANIMATION, *tail, (1, spare)))
    with pytest.raises(FormatError, match="ends inside its header"):        # every bit of it is read: two bytes
        lt_jxl.read_codestream_header(head[:-2])                            # fewer and it is no header


@pytest.mark.parametrize("fields,message", [
    ([(0, 64)], "the white point 0 is not a value the format defines"),                       # zeros after FF 0A
    (SIZE_24X16 + [(0, 1), (0, 1), (1, 1), (0, 2), (16 - 1, 4)], "a float sample of 32 bits with 16 exponent bits"),
    (SIZE_24X16 + [(0, 1), (0, 1), (1, 1), (3, 2), (10 - 1, 6), (8 - 1, 4)], "a float sample of 10 bits with 8 exponent bits"),
    (SIZE_24X16 + [(0, 1), (0, 1), (0, 1), (3, 2), (40 - 1, 6)], "an integer sample of 40 bits"),
    (SIZE_24X16 + [(0, 1), (0, 1), (0, 1), (0, 2), (1, 1), (0, 2), (1, 1), (0, 1), (0, 1), *enum(7)], "the colour space 7 is not"),
    (SIZE_24X16 + [(0, 1), (0, 1), (0, 1), (0, 2), (1, 1), (0, 2), (1, 1), (0, 1), (0, 1), *enum(0), *enum(1), *enum(3)],
     "the primaries 3 is not"),
    (SIZE_24X16 + [(0, 1), (0, 1), (0, 1), (0, 2), (1, 1), (0, 2), (1, 1), (0, 1), (0, 1), *enum(0), *enum(1), *enum(1), (0, 1),
                   *enum(40)], "the transfer function 40 is not"),
    (SIZE_24X16 + [(0, 1), (0, 1), (0, 1), (0, 2), (1, 1), (0, 2), (1, 1), (0, 1), (0, 1), *enum(0), *enum(1), *enum(1), (1, 1),
                   (1000, 24)], "a gamma of 0.0001 is outside the range"),
    (SIZE_24X16 + [(0, 1), (0, 1), (0, 1), (0, 2), (1, 1), (0, 2), (1, 1), (0, 1), (0, 1), *enum(0), *enum(1), *enum(1), (0, 1),
                   *enum(13), *enum(9)], "the rendering intent 9 is not"),
    (SIZE_24X16 + [(0, 1), (0, 1), (0, 1), (0, 2), (1, 1), (1, 2), (0, 1), *enum(9)], "the extra channel type 9 is not"),
    (SIZE_24X16 + [(0, 1), (0, 1), (0, 1), (0, 2), (1, 1), (1, 2), (0, 1), *enum(1), (0, 1), (0, 2), (3, 2), (8 - 1, 3)],
     "an extra channel's dim_shift of 8"),
    (SIZE_24X16 + [(0, 1), (1, 1), (0, 3), (0, 1), (0, 1), (0, 1), (0, 1), (0, 2), (1, 1), (0, 2), (1, 1), (1, 1), (0, 1),
                   (0x7C00, 16)], "a half float of the header is an infinity or a NaN"),
    (SIZE_24X16 + [(1, 1), (1, 1), (1, 1)], "padding bits after the image header are not zero"),
    ([(0, 1), (3, 2), ((1 << 30) - 1, 30), (7, 3), (1, 1), (1, 1)], "larger than any level of the format allows"),
])
def test_a_header_the_format_does_not_allow_is_refused(fields, message):
    with pytest.raises(FormatError, match=message):
        lt_jxl.read_codestream_header(header(*fields))
    assert not lt_jxl.detect(header(*fields))


@pytest.mark.needs_tool("jxlinfo")
def test_libjxl_reads_the_same_headers(tmp_path):
    """The reference decoder's own reading of the hand-assembled headers (it prints the image header, then
    fails on the frames, which are not there)."""
    def info(head):
        (tmp_path / "h.jxl").write_bytes(head + bytes(64))
        run = subprocess.run([shutil.which("jxlinfo"), "-v", str(tmp_path / "h.jxl")], capture_output=True, text=True, timeout=120)
        return run.stdout + run.stderr

    rich = info(RICH)
    for line in ("JPEG XL image, 5000x300", "12-bit RGB+Alpha+Depth", "bits_per_sample: 16", "dim_shift: 3", "name: depth",
                 "intensity_target: 8.000000 nits", "relative_to_max_display: 1", "Preview image: 42x32",
                 "Intrinsic dimensions: 96x80", "Orientation: 3", "white_point(x=0.156350,y=0.164500)", "P3 primaries",
                 "gamma(0.454545)", "rendering intent: Absolute"):
        assert line in rich, (line, rich)
    assert "have_preview: 0" in info(NO_PREVIEW)
    grey = info(GREY_FLOAT)
    assert "16-bit float (5 exponent bits) Grayscale" in grey and "Grayscale, E, Linear transfer function, rendering intent: Saturation" in grey
    moving = info(header(*ANIMATION, (2, 2), (25 - 1, 10), (2, 2), (2 - 1, 8), (2, 2), (300, 16), *AFTER_TICKS, (0, 2), (1, 1)))
    assert "JPEG XL animation, 24x16" in moving and "Orientation: 5" in moving


# ------------------------------------------------------------------ round 1: FF 0A alone is not a JPEG XL image

NOT_PICTURES = [b"Hello, world", b"The quick brown fox jumps over the lazy dog", b"\xff\xd8\xff\xe0JFIF", b"flag{not_a_picture}",
                b"PK\x03\x04", b"\r\n\r\n", b"#!/bin/sh\n", b"\x7fELF", b"GIF89a", b"<?xml version='1.0'?>", b'{"a": 1}',
                b"MZ\x90\x00", b"%PDF-1.7", bytes(40), b"\xff" * 40, bytes(range(64))]


@pytest.mark.parametrize("rest", NOT_PICTURES)
def test_a_file_that_only_starts_with_ff_0a_is_not_a_jpeg_xl_image(rest, tmp_path):
    blob = b"\xff\x0a" + rest + b" and some more text to follow it" * 3
    assert not lt_jxl.detect(blob)
    with pytest.raises(FormatError):
        lt_jxl.read_jxl(blob)
    (tmp_path / "notes.jxl").write_bytes(blob)                  # the name does not make it one
    r = lt_jxl.solve(tmp_path)
    assert (r.status, r.notes) == ("none", "no JPEG XL image file in the handout")


def test_the_share_of_random_continuations_that_pass_is_small_and_known():
    # The image header has no checksum, so the test is necessary and not sufficient. This holds the measured
    # share (0.04 to 0.05 with this seed: about one in twenty) so that a weaker test cannot slip in unnoticed.
    rnd = random.Random(251)
    passed = sum(lt_jxl.detect(b"\xff\x0a" + rnd.randbytes(1022)) for _ in range(4000))
    assert 0 < passed < 0.08 * 4000, passed
    text = bytes(range(32, 127)) + b"\n"
    passed = sum(lt_jxl.detect(b"\xff\x0a" + bytes(rnd.choice(text) for _ in range(400))) for _ in range(2000))
    assert passed < 0.08 * 2000, passed
    for prefix, *_ in REAL:                                      # and every real header passes
        assert lt_jxl.detect(H(prefix))


# ------------------------------------------------------------------ round 1: brob boxes

def test_a_brob_box_without_brotli_is_named_in_the_facts_and_in_the_result(monkeypatch, tmp_path):
    lead = flagfmt.cribs()[0]
    inside = (lead + "inside_the_brob_box}").encode()
    packed = brotli.compress(b"<x>" + inside + b"</x>" + b" the quick brown fox jumps over the lazy dog" * 40)
    assert inside not in packed                                  # the compressed bytes do not show it
    monkeypatch.setitem(sys.modules, "brotli", None)             # the import fails as on a host without it
    blobs = []
    got = lt_jxl.read_jxl(container(box(b"brob", b"xml " + packed)), blobs)
    why = "py:brotli: the brob box at offset 32 ('xml ') is brotli-compressed"
    assert got["needs_tool"] == [why]
    assert got["brob"] == [{"type": "xml ", "compressed_bytes": len(packed), "undecoded": "needs_tool " + why}]
    assert not [label for label, _ in blobs if label.startswith("brob")]      # undecoded bytes are not scanned
    assert (got["width"], got["height"]) == (100, 50)

    (tmp_path / "pic.jxl").write_bytes(container(box(b"brob", b"xml " + packed)))
    r = lt_jxl.solve(tmp_path)                                   # nothing else to read: blocked, not "no flag"
    assert (r.status, r.flags) == ("blocked", ()) and r.notes == "pic.jxl: JPEG XL image: needs_tool " + why
    here = lead + "in_a_box_beside_it}"
    (tmp_path / "pic.jxl").write_bytes(container(box(b"brob", b"xml " + packed), box(b"note", here.encode())))
    r = lt_jxl.solve(tmp_path)                                   # what can be read is read, and the tool is still named
    assert (r.status, r.flags) == ("solved", (here,)) and "needs_tool py:brotli" in r.notes
    monkeypatch.undo()
    assert lt_jxl.solve(tmp_path).status == "candidate"          # with the decoder both flags are there


def test_a_brob_box_is_never_inflated_past_its_limit(monkeypatch):
    raw = b"<x:xmpmeta>" + b"A" * 5000 + b"</x:xmpmeta>"
    data = container(box(b"brob", b"xml " + brotli.compress(raw)))
    assert lt_jxl.read_jxl(data)["brob"][0]["bytes"] == len(raw)
    monkeypatch.setattr(lt_jxl, "MAX_BROB_BYTES", len(raw))
    assert lt_jxl.read_jxl(data)["brob"][0]["bytes"] == len(raw)
    monkeypatch.setattr(lt_jxl, "MAX_BROB_BYTES", len(raw) - 1)
    with pytest.raises(FormatError, match=f"the brob box at offset 32 decompresses to more than {len(raw) - 1} bytes"):
        lt_jxl.read_jxl(data)
    monkeypatch.undo()
    bomb = container(box(b"brob", b"xml " + brotli.compress(bytes(40 << 20))))           # 40 MiB of zeros in a few bytes
    assert len(bomb) < 400 and lt_jxl.MAX_BROB_BYTES == 16 << 20
    with pytest.raises(FormatError, match="decompresses to more than 16777216 bytes: not inflated further"):
        lt_jxl.read_jxl(bomb)


# ------------------------------------------------------------------ round 2: one brob budget per file

def test_the_brob_boxes_of_a_file_share_one_decompression_budget(monkeypatch, tmp_path):
    lead = flagfmt.cribs()[0]
    after = lead + "in_a_box_after_the_cut}"
    one = brotli.compress(bytes(1000))                       # 1000 zeros in a few bytes
    boxes = [box(b"brob", b"xml " + one) for _ in range(5)]
    data = container(*boxes, box(b"note", after.encode()))
    monkeypatch.setattr(lt_jxl, "MAX_BROB_TOTAL", 2500)
    blobs = []
    got = lt_jxl.read_jxl(data, blobs)
    rows = got["brob"]
    assert [r.get("bytes") for r in rows] == [1000, 1000, None, None, None]
    assert [r.get("undecoded") for r in rows] == [None, None] + ["over the file's brob limit"] * 3
    offset = 32 + 2 * len(boxes[0])                          # the third box: past the ftyp box and two brob boxes
    assert got["brob_stopped"] == (f"the brob boxes before offset {offset} decompressed to 2000 bytes: it and the brob "
                                   "boxes after it would pass the file's 2500-byte limit and are not decoded")
    assert sum(len(b) for label, b in blobs if label.startswith("brob")) == 2000
    assert (got["width"], got["height"]) == (100, 50)       # the rest of the file is still read
    (tmp_path / "pic.jxl").write_bytes(data)
    assert lt_jxl.solve(tmp_path).flags == (after,)
    # a budget the boxes fit exactly is not a cut
    monkeypatch.setattr(lt_jxl, "MAX_BROB_TOTAL", 5000)
    got = lt_jxl.read_jxl(data)
    assert [r["bytes"] for r in got["brob"]] == [1000] * 5 and "brob_stopped" not in got


def test_many_small_brob_bombs_cost_the_files_budget_not_their_number():
    # each box is under 40 bytes and inflates to 16 MiB, the limit of one box: without one budget per
    # file, eight of them would hold 128 MiB of decoded bytes in memory at once
    bomb = brotli.compress(bytes(lt_jxl.MAX_BROB_BYTES))
    assert len(bomb) < 40 and lt_jxl.MAX_BROB_TOTAL == 64 << 20
    blobs = []
    got = lt_jxl.read_jxl(container(*[box(b"brob", b"xml " + bomb)] * 8), blobs)
    assert [r.get("bytes") for r in got["brob"]] == [16 << 20] * 4 + [None] * 4
    assert sum(len(b) for label, b in blobs if label.startswith("brob")) == lt_jxl.MAX_BROB_TOTAL
    assert "brob_stopped" in got


def test_mutated_jpeg_xl_files_raise_only_the_declared_errors():
    from lt_mutations import bit_flips, mutations, only_declared_errors
    full = container(box(b"jxll", b"\x0a"), box(b"Exif", b"\x00\x00\x00\x00II*\x00x"), box(b"xml ", b"<x/>"),
                     box(b"brob", b"xml " + brotli.compress(b"<y>compressed</y>")), box(b"note", b"n"),
                     stream=box(b"jxlp", struct.pack(">I", 0) + STREAM[:9]) + box(b"jxlp", struct.pack(">I", 0x80000001) + STREAM[9:]),
                     trailing=b"tail")
    read, refused = only_declared_errors(lt_jxl.inspect, mutations(full, 2000, seed=251))
    assert read + refused == 2000 and refused > 200 and read > 200
    for prefix, *_ in REAL:                                   # every bit of the real encoder headers
        read, refused = only_declared_errors(lt_jxl.inspect, bit_flips(H(prefix)))
        assert read + refused == 8 * len(H(prefix)) and refused > 0
