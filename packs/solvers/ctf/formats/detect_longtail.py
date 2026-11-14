"""Structural tests of the long-tail formats (B-251), added to ctf.formats.DETECTORS.

Like the tests in ctf/formats/__init__.py they are this package's own, small and bounded (no reader
under solvers/ is imported), they read at most HEAD bytes from the start and four from the end of the
buffer (bytes or an mmap), and on hostile bytes they answer False: every index is checked before it is
used, so none of them raises.

A detector's True is reported as a sure match (formats.identify), so a format with a short or no
magic is held to more than its first bytes:

  jxl      the 12-byte container signature, or FF 0A followed by an image header that parses to its
           end: `jxl_header` reads the SizeHeader, the whole ImageMetadata and the transform data bit
           by bit and refuses an enumeration value, a bit depth, a half float or a size the format
           does not allow, and padding bits that are not zero. That is a necessary test, not a proof:
           the header has no checksum, and a share of the random continuations of FF 0A still pass it
           (tests/test_toolkits_lt_jxl.py holds the measured rate). FF 0A alone, the format's whole
           signature, passes for nothing.
  coreml   a protobuf `Model` whose description holds only ModelDescription fields AND shows what only
           a model has: a feature that is a FeatureDescription (a name and a FeatureType), directly or
           inside a function, or a model-type field (200 and up) after the description.
  thrift   the strict binary protocol's message envelope: version 80 01, a message type, a short
           identifier as the method name, a sequence id and a first field header of a known type.

The toolkit readers (solvers/toolkits/lt_jxl.py, lt_model_meta.py, lt_thrift_parquet.py) use these same
tests and `jxl_header`, so the catalog and the readers cannot disagree about what a file is.
"""
from __future__ import annotations

import struct

HEAD = 8192
JXL_CONTAINER = bytes.fromhex("0000000c4a584c200d0a870a")
JXL_HEADER_BYTES = 1024                                  # the image header is read from this many bytes at most
# ModelDescription: input 1, output 10, predictedFeatureName 11, predictedProbabilitiesName 12, state 13,
# functions 20, defaultFunctionName 21, trainingInput 50, metadata 100. All are length-delimited.
COREML_DESCRIPTION_FIELDS = {1, 10, 11, 12, 13, 20, 21, 50, 100}
COREML_FEATURE_LISTS = {1, 10, 13, 50}                   # repeated FeatureDescription
COREML_FUNCTION_FEATURE_LISTS = {2, 3, 6}                # FunctionDescription: input, output, state
COREML_FEATURE_TYPES = set(range(1, 9))                  # the FeatureType oneof (int64 .. state); 1000 isOptional
THRIFT_MESSAGE_TYPES = (1, 2, 3, 4)                      # call, reply, exception, oneway
THRIFT_BINARY_TYPES = (0, 2, 3, 4, 6, 8, 10, 11, 12, 13, 14, 15, 16)      # a field header's type, or 0: stop


def _is_avro(d) -> bool:
    return d[:4] == b"Obj\x01"


def _is_parquet(d) -> bool:
    return len(d) >= 12 and d[:4] == b"PAR1" and d[len(d) - 4:len(d)] in (b"PAR1", b"PARE")


def _is_tnef(d) -> bool:
    return d[:4] == b"\x78\x9f\x3e\x22" and len(d) >= 6


def _is_tflite(d) -> bool:
    return len(d) >= 16 and (d[4:8] == b"TFL3" or d[8:12] == b"TFL3")


# ------------------------------------------------------------------ JPEG XL codestream header

JXL_RATIOS = {1: (1, 1), 2: (12, 10), 3: (4, 3), 4: (3, 2), 5: (16, 9), 6: (5, 4), 7: (2, 1)}
JXL_COLOUR_SPACES = {0: "RGB", 1: "grey", 2: "XYB", 3: "unknown"}
JXL_WHITE_POINTS = {1: "D65", 2: "custom", 10: "E", 11: "DCI"}
JXL_PRIMARIES = {1: "sRGB", 2: "custom", 9: "BT.2100", 11: "P3"}
JXL_TRANSFER = {1: "BT.709", 2: "unknown", 8: "linear", 13: "sRGB", 16: "PQ", 17: "DCI", 18: "HLG"}
JXL_INTENTS = {0: "perceptual", 1: "relative", 2: "saturation", 3: "absolute"}
JXL_EXTRA_CHANNELS = {0: "alpha", 1: "depth", 2: "spot colour", 3: "selection mask", 4: "black", 5: "CFA",
                      6: "thermal", 15: "non-optional", 16: "optional"}


class _Bits:
    """The codestream's bit order: least significant bit of each byte first."""

    def __init__(self, data: bytes):
        self.d, self.at = data, 0

    def u(self, n: int) -> int:
        if self.at + n > 8 * len(self.d):
            raise ValueError("the codestream ends inside its header")
        v = 0
        for i in range(n):
            v |= (self.d[(self.at + i) >> 3] >> ((self.at + i) & 7) & 1) << i
        self.at += n
        return v

    def flag(self) -> bool:
        return bool(self.u(1))

    def u32(self, *dist):
        """A U32 field: a 2-bit selector, then that distribution: an int is a constant, (bits, offset)
        reads `bits` bits and adds `offset`."""
        d = dist[self.u(2)]
        return d if isinstance(d, int) else self.u(d[0]) + d[1]

    def enum(self, table: dict, what: str):
        v = self.u32(0, 1, (4, 2), (6, 18))
        if v not in table:
            raise ValueError(f"the {what} {v} is not a value the format defines")
        return table[v]

    def u64(self) -> int:
        sel = self.u(2)
        if sel == 0:
            return 0
        if sel == 1:
            return self.u(4) + 1
        if sel == 2:
            return self.u(8) + 17
        v, shift = self.u(12), 12
        while self.flag():
            if shift == 60:
                return v | self.u(4) << shift
            v |= self.u(8) << shift
            shift += 8
        return v

    def f16(self) -> float:
        """A half float. The format has no infinity or NaN: an all-ones exponent is refused."""
        raw = self.u(16)
        if raw >> 10 & 31 == 31:
            raise ValueError("a half float of the header is an infinity or a NaN, which the format does not allow")
        return struct.unpack("<e", raw.to_bytes(2, "little"))[0]


def _jxl_size(b: _Bits):
    small = b.u(1)
    height = (b.u(5) + 1) * 8 if small else b.u32((9, 1), (13, 1), (18, 1), (30, 1))
    ratio = b.u(3)
    if ratio:
        num, den = JXL_RATIOS[ratio]
        return height * num // den, height
    return ((b.u(5) + 1) * 8 if small else b.u32((9, 1), (13, 1), (18, 1), (30, 1))), height


def _jxl_preview(b: _Bits):
    div8 = b.u(1)
    height = 8 * b.u32(16, 32, (5, 1), (9, 33)) if div8 else b.u32((6, 1), (8, 65), (10, 321), (12, 1345))
    ratio = b.u(3)
    if ratio:
        num, den = JXL_RATIOS[ratio]
        return height * num // den, height
    return (8 * b.u32(16, 32, (5, 1), (9, 33)) if div8 else b.u32((6, 1), (8, 65), (10, 321), (12, 1345))), height


def _jxl_depth(b: _Bits, out: dict):
    out["float_samples"] = b.flag()
    if out["float_samples"]:
        bits = out["bits_per_sample"] = b.u32(32, 16, 24, (6, 1))
        exponent = out["exponent_bits"] = b.u(4) + 1
        if not 2 <= exponent <= 8 or not 2 <= bits - exponent - 1 <= 23:
            raise ValueError(f"a float sample of {bits} bits with {exponent} exponent bits is not one the format allows")
    else:
        out["bits_per_sample"] = b.u32(8, 10, 12, (6, 1))
        if out["bits_per_sample"] > 31:
            raise ValueError(f"an integer sample of {out['bits_per_sample']} bits is not one the format allows")


def _jxl_xy(b: _Bits):
    """A CIE xy pair: each coordinate a signed value (its sign in the lowest bit) in millionths."""
    out = []
    for _ in range(2):
        v = b.u32((19, 0), (19, 524288), (20, 1048576), (21, 2097152))
        out.append(((v >> 1) ^ -(v & 1)) / 1_000_000)
    return out


def _jxl_colour(b: _Bits, out: dict):
    if b.flag():                                              # all_default: sRGB
        out.update(colour_space="RGB", white_point="D65", primaries="sRGB", transfer_function="sRGB",
                   rendering_intent="relative")
        return
    out["want_icc"] = b.flag()
    space = out["colour_space"] = b.enum(JXL_COLOUR_SPACES, "colour space")
    if out["want_icc"]:
        return
    if space != "XYB":
        out["white_point"] = b.enum(JXL_WHITE_POINTS, "white point")
        if out["white_point"] == "custom":
            out["white_point_xy"] = _jxl_xy(b)
    if space not in ("XYB", "grey"):
        out["primaries"] = b.enum(JXL_PRIMARIES, "primaries")
        if out["primaries"] == "custom":
            out["primaries_xy"] = [_jxl_xy(b) for _ in range(3)]
    if space != "XYB":                                        # XYB implies its transfer function
        if b.flag():
            gamma = out["gamma"] = b.u(24) / 10_000_000
            if not 1 / 8192 <= gamma <= 1:
                raise ValueError(f"a gamma of {gamma} is outside the range the format allows")
        else:
            out["transfer_function"] = b.enum(JXL_TRANSFER, "transfer function")
    out["rendering_intent"] = b.enum(JXL_INTENTS, "rendering intent")


def jxl_header(cs: bytes) -> dict:
    """The image header of a JPEG XL codestream (FF 0A, SizeHeader, ImageMetadata, the transform
    data's default flag), read bit by bit as ISO/IEC 18181-1 packs it, from the first JXL_HEADER_BYTES
    bytes. ValueError when the bytes are not one: an enumeration value, bit depth or size the format
    does not allow, a half float that is an infinity or a NaN, padding bits that are not zero, or a
    header that runs past the bytes. Header extensions (none is defined) are skipped by the size they
    state and custom transform data is read through. Two things end the reading before the padding,
    each named in `header_read_to`: an embedded ICC profile and a preview frame (what follows the
    header then is entropy coded and is not read)."""
    cs = bytes(cs[:JXL_HEADER_BYTES])
    if cs[:2] != b"\xff\x0a":
        raise ValueError("the codestream does not start with FF 0A")
    b = _Bits(cs[2:])
    width, height = _jxl_size(b)
    if width > 1 << 30 or height > 1 << 30 or width * height > 1 << 40:
        raise ValueError(f"an image of {width}x{height} is larger than any level of the format allows")
    out = {"width": width, "height": height, "all_default": b.flag()}
    extra = False
    if not out["all_default"]:
        extra = b.flag()
        if extra:
            out["orientation"] = b.u(3) + 1
            out["have_intrinsic_size"] = b.flag()
            if out["have_intrinsic_size"]:
                out["intrinsic_width"], out["intrinsic_height"] = _jxl_size(b)
            out["have_preview"] = b.flag()
            if out["have_preview"]:
                out["preview_width"], out["preview_height"] = _jxl_preview(b)
            out["have_animation"] = b.flag()
            if out["have_animation"]:
                out["ticks_per_second_numerator"] = b.u32(100, 1000, (10, 1), (30, 1))
                out["ticks_per_second_denominator"] = b.u32(1, 1001, (8, 1), (10, 1))
                out["loop_count"] = b.u32(0, (3, 0), (16, 0), (32, 0))
                out["have_timecodes"] = b.flag()
        _jxl_depth(b, out)
        out["modular_16bit_buffers"] = b.flag()
        channels = []
        for _ in range(b.u32(0, 1, (4, 2), (12, 1))):
            ch = {"type": "alpha"}
            if not b.flag():                                  # not the default (an 8-bit alpha channel)
                ch["type"] = b.enum(JXL_EXTRA_CHANNELS, "extra channel type")
                _jxl_depth(b, ch)
                ch["dim_shift"] = b.u32(0, 3, 4, (3, 1))
                if ch["dim_shift"] > 3:
                    raise ValueError(f"an extra channel's dim_shift of {ch['dim_shift']} is not one the format allows")
                name = bytes(b.u(8) for _ in range(b.u32(0, (4, 0), (5, 16), (10, 48))))
                if name:
                    ch["name"] = name.decode("utf-8", "replace")
                if ch["type"] == "alpha":
                    ch["alpha_associated"] = b.flag()
                elif ch["type"] == "spot colour":
                    ch["spot_colour"] = [b.f16() for _ in range(4)]      # red, green, blue, solidity
                elif ch["type"] == "CFA":
                    ch["cfa_channel"] = b.u32(1, (2, 0), (4, 3), (8, 19))
            channels.append(ch)
        if channels:
            out["extra_channels"] = channels
        out["xyb_encoded"] = b.flag()
        _jxl_colour(b, out)
        if extra and not b.flag():                            # tone mapping, when it is not all default
            out["intensity_target"], out["min_nits"] = b.f16(), b.f16()
            out["relative_to_max_display"], out["linear_below"] = b.flag(), b.f16()
        extensions = b.u64()
        if extensions:                                        # none is defined: each states its size in bits
            out["extensions"] = extensions
            b.u(sum(b.u64() for i in range(64) if extensions >> i & 1))
    if not b.flag():                                          # custom transform data (default_m is off)
        out["custom_transform"] = True
        if out.get("xyb_encoded", True) and not b.flag():     # the opsin inverse matrix, when it is not default
            for _ in range(16):                               # 9 matrix cells, 3 opsin biases, 4 quantisation biases
                b.f16()
        weights = b.u(3)                                      # which of the 2x, 4x, 8x upsampling weights follow
        for _ in range(15 * (weights & 1) + 55 * (weights >> 1 & 1) + 210 * (weights >> 2 & 1)):
            b.f16()
    if out.get("want_icc") or out.get("have_preview"):
        out["header_read_to"] = "the ICC profile" if out.get("want_icc") else "the preview frame"
        return out
    if b.at % 8 and b.u(8 - b.at % 8):                        # the frames start on a byte: the padding is zero
        raise ValueError("the padding bits after the image header are not zero")
    return out


def _is_jxl(d) -> bool:
    if d[:12] == JXL_CONTAINER:
        return True
    if d[:2] != b"\xff\x0a":
        return False
    try:
        jxl_header(d[:JXL_HEADER_BYTES])
    except ValueError:
        return False
    return True


# ------------------------------------------------------------------ protobuf, read without raising

def _varint(d: bytes, o: int, end: int):
    """(value, next offset), or (None, o) when the varint is cut off or longer than ten bytes."""
    v = shift = 0
    while o < end and shift < 70:
        b = d[o]
        o += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, o
        shift += 7
    return None, o


def _pb_fields(d: bytes, o: int, end: int, limit: int | None = None):
    """([(field, wire type, (start, stop) of a length-delimited value | None)], cut) of the message at
    d[o:end], or None when the bytes are not protobuf wire format. `limit` is how far the buffer goes
    when that is short of `end` (the head of a longer message): a value the limit cuts ends the list
    with cut=True (a length-delimited field cut that way is listed with no span)."""
    limit = end if limit is None else min(limit, end)
    short, out = limit < end, []
    while o < limit:
        key, o = _varint(d, o, limit)
        if key is None:
            return (out, True) if short and o >= limit else None
        field, wire = key >> 3, key & 7
        if field == 0:
            return None
        if wire == 0:
            v, o = _varint(d, o, limit)
            if v is None:
                return (out, True) if short and o >= limit else None
            out.append((field, wire, None))
        elif wire == 2:
            n, o = _varint(d, o, limit)
            if n is None:
                return (out, True) if short and o >= limit else None
            if o + n > end:
                return None                                   # it runs past its own message
            if o + n > limit:
                return out + [(field, wire, None)], True
            out.append((field, wire, (o, o + n)))
            o += n
        elif wire in (1, 5):
            o += 8 if wire == 1 else 4
            if o > end:
                return None
            if o > limit:
                return out, True
            out.append((field, wire, None))
        else:
            return None                                       # groups: no Core ML message has one
    return out, short


def _text(d: bytes, span) -> bool:
    """The span is a non-empty UTF-8 string with no control characters."""
    try:
        s = bytes(d[span[0]:span[1]]).decode("utf-8")
    except UnicodeDecodeError:
        return False
    return bool(s) and all(c >= " " for c in s)


def coreml_feature(d: bytes, start: int, stop: int) -> bool:
    """d[start:stop] is a Core ML FeatureDescription: only name (1), shortDescription (2) and type (3),
    all length-delimited, with a name and a FeatureType that names one of the feature types."""
    got = _pb_fields(d, start, stop)
    if got is None or any(f not in (1, 2, 3) or w != 2 for f, w, _ in got[0]):
        return False
    name = next((v for f, _, v in got[0] if f == 1), None)
    kind = next((v for f, _, v in got[0] if f == 3), None)
    if name is None or kind is None or not _text(d, name):
        return False
    inner = _pb_fields(d, *kind)
    if inner is None:
        return False
    numbers = {f for f, _, _ in inner[0]}
    return bool(numbers & COREML_FEATURE_TYPES) and numbers <= COREML_FEATURE_TYPES | {1000}


def coreml_function(d: bytes, start: int, stop: int) -> bool:
    """d[start:stop] is a FunctionDescription that holds a feature (input 2, output 3, state 6)."""
    got = _pb_fields(d, start, stop)
    return got is not None and any(f in COREML_FUNCTION_FEATURE_LISTS and w == 2 and coreml_feature(d, *v)
                                   for f, w, v in got[0])


def _is_coreml(d) -> bool:
    """A protobuf `Model`: field 1 a small specificationVersion, then field 2 a ModelDescription whose
    fields (as far as the head shows them) are all a description's, and one sign that it is a model: a
    feature that is a FeatureDescription (directly or inside a function), or, when the description ends
    inside the head, a model-type field (200 and up) after it. A description longer than the head is
    read up to the head's end."""
    head = bytes(d[:HEAD])
    if len(head) < 6 or head[0] != 0x08 or not 1 <= head[1] <= 64 or head[2] != 0x12:
        return False
    size, o = _varint(head, 3, len(head))
    if size is None:
        return False
    end = o + size
    got = _pb_fields(head, o, end, len(head))
    if got is None:
        return False
    fields, cut = got
    if not fields or any(f not in COREML_DESCRIPTION_FIELDS or w != 2 for f, w, _ in fields):
        return False
    for f, _, span in fields:
        if span and ((f in COREML_FEATURE_LISTS and coreml_feature(head, *span))
                     or (f == 20 and coreml_function(head, *span))):
            return True
    if cut:
        return False
    rest = _pb_fields(head, end, 1 << 62, len(head))          # the model's own message may run past the head
    return rest is not None and any(f >= 200 and w == 2 for f, w, _ in rest[0])


# ------------------------------------------------------------------ Thrift (strict binary envelope)

def _is_thrift(d) -> bool:
    """`80 01 00 <type>`, a 4-byte big-endian name length, the method name (1 to 255 identifier
    characters), a 4-byte sequence id, then a field header of a binary-protocol type or the stop byte."""
    if len(d) < 13 or d[:3] != b"\x80\x01\x00" or d[3] not in THRIFT_MESSAGE_TYPES:
        return False
    n = int.from_bytes(d[4:8], "big")
    if not 0 < n <= 255 or len(d) < 13 + n:
        return False
    name = bytes(d[8:8 + n])
    return name.isascii() and name.replace(b"_", b"a").isalnum() and d[12 + n] in THRIFT_BINARY_TYPES


DETECTORS = {"avro": _is_avro, "parquet": _is_parquet, "tnef": _is_tnef, "jxl": _is_jxl, "tflite": _is_tflite,
             "coreml": _is_coreml, "thrift": _is_thrift}
