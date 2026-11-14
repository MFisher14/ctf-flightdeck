"""Bounded, checksum-aware offline decompression and entropy-code readers.

Container codecs are accepted only after their decoder consumes a complete stream.  Formats
with checksums (gzip, bzip2, xz, framed LZ4/Zstandard/Snappy) get those checks from their
reference libraries.  Signatureless Brotli and raw Snappy are explicit-only readers.  Raw
LZO1X is available when a caller supplies the expected size; ``R5LZO1`` adds size and CRC for
recursive routing.

Arithmetic and range coding have no universal interchange format or model.  This module
therefore provides a documented adaptive order-0 frame (``R5AC1`` / ``R5RC1``) with bit length,
uncompressed length and CRC32.  The underlying finite-precision decoder is real and generic;
the framing prevents a random bit stream from becoming an unverified candidate.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import struct
import zlib
from dataclasses import dataclass
from typing import Callable, Iterable


MAX_INPUT = 64 * 1024 * 1024
MAX_OUTPUT = 128 * 1024 * 1024


@dataclass(frozen=True)
class Candidate:
    codec: str
    payload: bytes
    checked_by: str


def _raw(value: object) -> bytes | None:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return None
    try:
        data = bytes(value)
    except (ValueError, TypeError):      # e.g. a released memoryview
        return None
    return data if 0 < len(data) <= MAX_INPUT else None


def _finish(payload: bytes, limit: int) -> bytes | None:
    return payload if 0 < len(payload) <= limit else None


def _zlib_stream(data: bytes, wbits: int, limit: int) -> bytes | None:
    try:
        obj = zlib.decompressobj(wbits)
        out = obj.decompress(data, limit + 1)
        if len(out) > limit or obj.unconsumed_tail:
            return None
        out += obj.flush(limit + 1 - len(out))
        if not obj.eof or obj.unused_data or len(out) > limit:
            return None
        return _finish(out, limit)
    except (zlib.error, ValueError, TypeError):
        return None


def decode_gzip(data: object, *, max_output: int = MAX_OUTPUT) -> bytes | None:
    raw = _raw(data)
    if raw is None or not raw.startswith(b"\x1f\x8b\x08"):
        return None
    return _zlib_stream(raw, 16 + zlib.MAX_WBITS, max_output)


def decode_zlib(data: object, *, max_output: int = MAX_OUTPUT) -> bytes | None:
    raw = _raw(data)
    if raw is None or len(raw) < 6:
        return None
    cmf, flg = raw[0], raw[1]
    if cmf & 0x0F != 8 or cmf >> 4 > 7 or (cmf << 8 | flg) % 31:
        return None
    return _zlib_stream(raw, zlib.MAX_WBITS, max_output)


def _incremental(decompressor: object, data: bytes, limit: int) -> bytes | None:
    out = bytearray()
    try:
        for pos in range(0, len(data), 65536):
            chunk = data[pos:pos + 65536]
            while chunk:
                room = limit + 1 - len(out)
                if room <= 0:
                    return None
                part = decompressor.decompress(chunk, max_length=room)
                out.extend(part)
                chunk = getattr(decompressor, "unconsumed_tail", b"")
                if not chunk:
                    break
            if len(out) > limit:
                return None
        if not getattr(decompressor, "eof", False) or getattr(decompressor, "unused_data", b""):
            return None
    except (OSError, EOFError, ValueError, lzma.LZMAError):
        return None
    return _finish(bytes(out), limit)


def decode_bzip2(data: object, *, max_output: int = MAX_OUTPUT) -> bytes | None:
    raw = _raw(data)
    if raw is None or len(raw) < 10 or not re_bzip_header(raw):
        return None
    return _incremental(bz2.BZ2Decompressor(), raw, max_output)


def re_bzip_header(data: bytes) -> bool:
    return data[:3] == b"BZh" and data[3:4] in b"123456789" and data[4:10] == b"1AY&SY"


def decode_lzma(data: object, *, max_output: int = MAX_OUTPUT) -> bytes | None:
    """Decode XZ or legacy .lzma streams, both of which carry an end marker."""

    raw = _raw(data)
    if raw is None:
        return None
    is_xz = raw.startswith(b"\xfd7zXZ\x00")
    # LZMA-alone: valid property byte <= 224 and plausible dictionary size.  FORMAT_AUTO will
    # still validate the stream; this check merely prevents trying it on arbitrary data.
    is_alone = len(raw) >= 13 and raw[0] <= 224 and 4096 <= int.from_bytes(raw[1:5], "little") <= (1 << 31)
    if not (is_xz or is_alone):
        return None
    try:
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_AUTO, memlimit=max(64 << 20, max_output * 2))
    except (lzma.LZMAError, OverflowError, TypeError):
        return None
    return _incremental(dec, raw, max_output)


def decode_brotli(data: object, *, max_output: int = MAX_OUTPUT) -> bytes | None:
    """Explicit raw Brotli reader; full-stream completion is its structural check."""

    raw = _raw(data)
    if raw is None:
        return None
    try:
        import brotli
        dec = brotli.Decompressor()
        out = bytearray()
        for pos in range(0, len(raw), 65536):
            out.extend(dec.process(raw[pos:pos + 65536]))
            if len(out) > max_output:
                return None
        if not dec.is_finished():
            return None
        return _finish(bytes(out), max_output)
    except Exception:
        return None


def decode_lz4(data: object, *, max_output: int = MAX_OUTPUT) -> bytes | None:
    raw = _raw(data)
    if raw is None or raw[:4] not in (b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18"):
        return None
    try:
        import lz4.frame
        dec = lz4.frame.LZ4FrameDecompressor()
        out = bytearray()
        chunk = raw
        while chunk:
            out.extend(dec.decompress(chunk, max_length=max_output + 1 - len(out)))
            if len(out) > max_output:
                return None
            chunk = dec.unused_data
            if chunk:  # concatenated/trailing data is deliberately not a single candidate
                return None
            break
        if not dec.eof:
            return None
        return _finish(bytes(out), max_output)
    except Exception:
        return None


def decode_zstd(data: object, *, max_output: int = MAX_OUTPUT) -> bytes | None:
    raw = _raw(data)
    if raw is None or raw[:4] != b"\x28\xb5\x2f\xfd":
        return None
    try:
        import zstandard
        parameters = zstandard.get_frame_parameters(raw)
        if parameters.content_size not in (zstandard.CONTENTSIZE_UNKNOWN, zstandard.CONTENTSIZE_ERROR):
            if parameters.content_size > max_output:
                return None
        out = zstandard.ZstdDecompressor().decompress(
            raw, max_output_size=max_output, allow_extra_data=False, read_across_frames=False
        )
        if len(out) > max_output:
            return None
        return _finish(out, max_output)
    except Exception:
        return None


def _varint(data: bytes) -> tuple[int, int] | None:
    value = shift = 0
    for index, byte in enumerate(data[:10]):
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, index + 1
        shift += 7
    return None


def decode_snappy_raw(data: object, *, max_output: int = MAX_OUTPUT) -> bytes | None:
    raw = _raw(data)
    size = _varint(raw) if raw is not None else None
    if raw is None or size is None or not 0 < size[0] <= max_output:
        return None
    try:
        import snappy
        out = snappy.uncompress(raw)
        return out if len(out) == size[0] else None
    except Exception:
        return None


def decode_snappy_framed(data: object, *, max_output: int = MAX_OUTPUT) -> bytes | None:
    raw = _raw(data)
    if raw is None or not raw.startswith(b"\xff\x06\x00\x00sNaPpY"):
        return None
    # Preflight every chunk before asking the library to allocate output.  Compressed data
    # chunks contain an ordinary Snappy block after their four-byte CRC32C.
    pos, declared = 0, 0
    while pos < len(raw):
        if pos + 4 > len(raw):
            return None
        kind = raw[pos]
        size = int.from_bytes(raw[pos + 1:pos + 4], "little")
        pos += 4
        if pos + size > len(raw):
            return None
        chunk = raw[pos:pos + size]
        pos += size
        if kind == 0xFF:
            if chunk != b"sNaPpY":
                return None
            continue
        if kind == 0x00:
            got = _varint(chunk[4:]) if size >= 5 else None
            if got is None:
                return None
            declared += got[0]
        elif kind == 0x01:
            if size < 4:
                return None
            declared += size - 4
        elif 0x80 <= kind <= 0xFE:  # skippable extension chunk
            continue
        else:  # reserved unskippable chunk
            return None
        if declared > max_output:
            return None
    try:
        import snappy
        dec = snappy.StreamDecompressor()
        out = dec.decompress(raw)
        if dec.remains:
            return None
        out += dec.flush()
        return out if len(out) == declared and _finish(out, max_output) is not None else None
    except Exception:
        return None


# -- LZO1X --------------------------------------------------------------------

class _LZOError(ValueError):
    pass


def _copy_literals(source: bytes, ip: int, out: bytearray, count: int, limit: int) -> int:
    if count < 0 or ip + count > len(source) or len(out) + count > limit:
        raise _LZOError("literal bounds")
    out.extend(source[ip:ip + count])
    return ip + count


def _copy_match(out: bytearray, position: int, count: int, limit: int) -> None:
    if position < 0 or position >= len(out) or count < 2 or len(out) + count > limit:
        raise _LZOError("match bounds")
    for _ in range(count):
        out.append(out[position])
        position += 1


def _extended_length(source: bytes, ip: int, base: int) -> tuple[int, int]:
    length = 0
    while True:
        if ip >= len(source):
            raise _LZOError("truncated length")
        value = source[ip]
        ip += 1
        if value:
            return length + base + value, ip
        length += 255


def decode_lzo1x(data: object, *, expected_size: int | None = None, max_output: int = MAX_OUTPUT) -> bytes | None:
    """Safe LZO1X decompressor for a raw stream ending in the standard 0x11,0,0 marker."""

    source = _raw(data)
    if source is None or len(source) < 4 or expected_size is not None and not 0 < expected_size <= max_output:
        return None
    ip, out = 0, bytearray()
    state = "top"
    try:
        control = source[ip]
        ip += 1
        if control > 17:
            count = control - 17
            if count < 4:
                control = count
                state = "match_next"
            else:
                ip = _copy_literals(source, ip, out, count, max_output)
                state = "first_literal"
        else:
            ip -= 1

        while True:
            if state == "top":
                if ip >= len(source):
                    raise _LZOError("missing end marker")
                control = source[ip]
                ip += 1
                if control >= 16:
                    state = "match"
                    continue
                if control == 0:
                    control, ip = _extended_length(source, ip, 15)
                count = control + 3
                ip = _copy_literals(source, ip, out, count, max_output)
                state = "first_literal"
                continue

            if state == "first_literal":
                if ip >= len(source):
                    raise _LZOError("missing match")
                control = source[ip]
                ip += 1
                if control >= 16:
                    state = "match"
                    continue
                if ip >= len(source):
                    raise _LZOError("truncated M2 offset")
                position = len(out) - (1 + 0x800) - (control >> 2) - (source[ip] << 2)
                ip += 1
                _copy_match(out, position, 3, max_output)
                state = "match_done"
                continue

            if state == "match_next":
                ip = _copy_literals(source, ip, out, control & 3, max_output)
                if ip >= len(source):
                    raise _LZOError("truncated match")
                control = source[ip]
                ip += 1
                state = "match"
                continue

            if state == "match":
                if control >= 64:
                    if ip >= len(source):
                        raise _LZOError("truncated M2 match")
                    position = len(out) - 1 - ((control >> 2) & 7) - (source[ip] << 3)
                    ip += 1
                    count = (control >> 5) + 1
                elif control >= 32:
                    count = control & 31
                    if count == 0:
                        count, ip = _extended_length(source, ip, 31)
                    if ip + 2 > len(source):
                        raise _LZOError("truncated M3 match")
                    offset = (source[ip] | source[ip + 1] << 8) >> 2
                    ip += 2
                    position = len(out) - 1 - offset
                    count += 2
                elif control >= 16:
                    position = len(out) - ((control & 8) << 11)
                    count = control & 7
                    if count == 0:
                        count, ip = _extended_length(source, ip, 7)
                    if ip + 2 > len(source):
                        raise _LZOError("truncated M4 match")
                    offset = (source[ip] | source[ip + 1] << 8) >> 2
                    ip += 2
                    position -= offset
                    if position == len(out):
                        if ip != len(source):
                            raise _LZOError("trailing bytes")
                        result = bytes(out)
                        if expected_size is not None and len(result) != expected_size:
                            return None
                        return _finish(result, max_output)
                    position -= 0x4000
                    count += 2
                else:
                    if ip >= len(source):
                        raise _LZOError("truncated short match")
                    position = len(out) - 1 - (control >> 2) - (source[ip] << 2)
                    ip += 1
                    count = 2
                _copy_match(out, position, count, max_output)
                state = "match_done"
                continue

            if state == "match_done":
                if ip < 2:
                    raise _LZOError("invalid match state")
                count = source[ip - 2] & 3
                if count == 0:
                    state = "top"
                else:
                    control = count
                    state = "match_next"
                continue
    except (_LZOError, IndexError, OverflowError):
        return None


_LZO_FRAME = struct.Struct(">6sII")


def encode_lzo_literal_frame(data: bytes) -> bytes:
    """Create a standards-compliant literal-only LZO1X stream in the checked R5 frame."""

    if not 4 <= len(data) <= 238:
        raise ValueError("literal helper supports 4..238 bytes")
    stream = bytes((17 + len(data),)) + data + b"\x11\x00\x00"
    return _LZO_FRAME.pack(b"R5LZO1", len(data), zlib.crc32(data)) + stream


def decode_lzo_frame(data: object, *, max_output: int = MAX_OUTPUT) -> bytes | None:
    raw = _raw(data)
    if raw is None or len(raw) <= _LZO_FRAME.size:
        return None
    magic, size, checksum = _LZO_FRAME.unpack_from(raw)
    if magic != b"R5LZO1" or not 0 < size <= max_output:
        return None
    out = decode_lzo1x(raw[_LZO_FRAME.size:], expected_size=size, max_output=max_output)
    return out if out is not None and zlib.crc32(out) == checksum else None


# -- Adaptive arithmetic / range frames --------------------------------------

class _Model:
    def __init__(self, symbols: int = 256):
        self.freq = [1] * symbols
        self.tree = [0] * (symbols + 1)
        self.total = 0
        self._rebuild()

    def _rebuild(self) -> None:
        self.tree[:] = [0] * len(self.tree)
        self.total = 0
        for symbol, frequency in enumerate(self.freq):
            self.total += frequency
            index = symbol + 1
            while index < len(self.tree):
                self.tree[index] += frequency
                index += index & -index

    def prefix(self, symbol: int) -> int:
        total, index = 0, symbol
        while index:
            total += self.tree[index]
            index -= index & -index
        return total

    def interval(self, symbol: int) -> tuple[int, int, int]:
        low = self.prefix(symbol)
        return low, low + self.freq[symbol], self.total

    def find(self, value: int) -> int:
        if not 0 <= value < self.total:
            raise ValueError("model value")
        index = 0
        bit = 1 << (len(self.freq).bit_length() - 1)
        while bit:
            nxt = index + bit
            if nxt < len(self.tree) and self.tree[nxt] <= value:
                index = nxt
                value -= self.tree[nxt]
            bit >>= 1
        if index >= len(self.freq):
            raise ValueError("model symbol")
        return index

    def update(self, symbol: int) -> None:
        self.freq[symbol] += 1
        self.total += 1
        index = symbol + 1
        while index < len(self.tree):
            self.tree[index] += 1
            index += index & -index
        if self.total >= 32768:
            self.freq = [(value + 1) // 2 for value in self.freq]
            self._rebuild()


class _BitWriter:
    def __init__(self):
        self.bits: list[int] = []

    def put(self, bit: int) -> None:
        self.bits.append(bit & 1)

    def bytes(self) -> tuple[bytes, int]:
        count = len(self.bits)
        padded = self.bits + [0] * ((-count) % 8)
        return bytes(sum(padded[i + j] << (7 - j) for j in range(8))
                     for i in range(0, len(padded), 8)), count


class _BitReader:
    def __init__(self, data: bytes, count: int):
        self.data, self.count, self.pos = data, count, 0

    def get(self) -> int:
        if self.pos >= self.count:
            self.pos += 1
            return 0
        bit = (self.data[self.pos // 8] >> (7 - self.pos % 8)) & 1
        self.pos += 1
        return bit


def _arith_encode(data: bytes, state_bits: int) -> tuple[bytes, int]:
    full, half, quarter = 1 << state_bits, 1 << (state_bits - 1), 1 << (state_bits - 2)
    mask, low, high, pending = full - 1, 0, full - 1, 0
    writer, model = _BitWriter(), _Model()

    def emit(bit: int) -> None:
        nonlocal pending
        writer.put(bit)
        for _ in range(pending):
            writer.put(1 - bit)
        pending = 0

    for symbol in data:
        cum_low, cum_high, total = model.interval(symbol)
        span = high - low + 1
        high = low + span * cum_high // total - 1
        low = low + span * cum_low // total
        while True:
            if high < half:
                emit(0)
            elif low >= half:
                emit(1)
                low -= half
                high -= half
            elif low >= quarter and high < 3 * quarter:
                pending += 1
                low -= quarter
                high -= quarter
            else:
                break
            low = low << 1 & mask
            high = (high << 1 & mask) | 1
        model.update(symbol)
    pending += 1
    emit(0 if low < quarter else 1)
    return writer.bytes()


def _arith_decode(data: bytes, bit_count: int, size: int, state_bits: int) -> bytes | None:
    if bit_count < 2 or bit_count > len(data) * 8 or any(data[bit_count // 8 + 1:]):
        return None
    if bit_count % 8 and data[-1] & ((1 << (8 - bit_count % 8)) - 1):
        return None
    full, half, quarter = 1 << state_bits, 1 << (state_bits - 1), 1 << (state_bits - 2)
    mask, low, high = full - 1, 0, full - 1
    reader, model = _BitReader(data, bit_count), _Model()
    code = 0
    for _ in range(state_bits):
        code = (code << 1) | reader.get()
    out = bytearray()
    try:
        for _ in range(size):
            span = high - low + 1
            value = ((code - low + 1) * model.total - 1) // span
            symbol = model.find(value)
            cum_low, cum_high, total = model.interval(symbol)
            high = low + span * cum_high // total - 1
            low = low + span * cum_low // total
            while True:
                if high < half:
                    pass
                elif low >= half:
                    low -= half
                    high -= half
                    code -= half
                elif low >= quarter and high < 3 * quarter:
                    low -= quarter
                    high -= quarter
                    code -= quarter
                else:
                    break
                low = low << 1 & mask
                high = (high << 1 & mask) | 1
                code = (code << 1 & mask) | reader.get()
            out.append(symbol)
            model.update(symbol)
    except (ValueError, OverflowError):
        return None
    return bytes(out)


_ENTROPY_HEADER = struct.Struct(">5sIII")


def _encode_entropy(data: bytes, magic: bytes, state_bits: int) -> bytes:
    if not data or len(data) > MAX_OUTPUT:
        raise ValueError("invalid payload size")
    coded, bit_count = _arith_encode(data, state_bits)
    return _ENTROPY_HEADER.pack(magic, len(data), zlib.crc32(data), bit_count) + coded


def _decode_entropy(data: object, magic: bytes, state_bits: int, max_output: int) -> bytes | None:
    raw = _raw(data)
    if raw is None or len(raw) < _ENTROPY_HEADER.size + 1:
        return None
    got_magic, size, checksum, bit_count = _ENTROPY_HEADER.unpack_from(raw)
    body = raw[_ENTROPY_HEADER.size:]
    if got_magic != magic or not 0 < size <= max_output or len(body) != (bit_count + 7) // 8:
        return None
    out = _arith_decode(body, bit_count, size, state_bits)
    return out if out is not None and zlib.crc32(out) == checksum else None


def encode_arithmetic_frame(data: bytes) -> bytes:
    return _encode_entropy(bytes(data), b"R5AC1", 32)


def decode_arithmetic(data: object, *, max_output: int = MAX_OUTPUT) -> bytes | None:
    return _decode_entropy(data, b"R5AC1", 32, max_output)


def encode_range_frame(data: bytes) -> bytes:
    return _encode_entropy(bytes(data), b"R5RC1", 48)


def decode_range(data: object, *, max_output: int = MAX_OUTPUT) -> bytes | None:
    return _decode_entropy(data, b"R5RC1", 48, max_output)


DECODERS: dict[str, Callable[..., bytes | None]] = {
    "gzip": decode_gzip,
    "zlib": decode_zlib,
    "bzip2": decode_bzip2,
    "lzma": decode_lzma,
    "brotli": decode_brotli,
    "lz4": decode_lz4,
    "zstd": decode_zstd,
    "snappy": decode_snappy_raw,
    "snappy-framed": decode_snappy_framed,
    "lzo": decode_lzo_frame,
    "arithmetic": decode_arithmetic,
    "range": decode_range,
}

_STRONG_PREFIXES = {
    "gzip": (b"\x1f\x8b\x08",),
    "bzip2": (b"BZh",),
    "lzma": (b"\xfd7zXZ\x00",),
    "lz4": (b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18"),
    "zstd": (b"\x28\xb5\x2f\xfd",),
    "snappy-framed": (b"\xff\x06\x00\x00sNaPpY",),
    "lzo": (b"R5LZO1",),
    "arithmetic": (b"R5AC1",),
    "range": (b"R5RC1",),
}


def decode_one(data: object, name: str, *, max_output: int = MAX_OUTPUT) -> Candidate | None:
    if not isinstance(name, str):
        return None
    decoder = DECODERS.get(name)
    if decoder is None:
        return None
    payload = decoder(data, max_output=max_output)
    if payload is None:
        return None
    checks = {
        "gzip": "gzip CRC32 and ISIZE", "zlib": "Adler-32 and complete stream",
        "bzip2": "block and stream CRC", "lzma": "complete LZMA/XZ stream and XZ check when present",
        "brotli": "Brotli full-stream completion", "lz4": "LZ4 frame completion/checksum",
        "zstd": "Zstandard frame completion/checksum", "snappy": "raw block length and tag bounds",
        "snappy-framed": "framing CRC32C", "lzo": "LZO end marker, declared size and CRC32",
        "arithmetic": "declared bit length, size and CRC32", "range": "declared bit length, size and CRC32",
    }
    return Candidate(name, payload, checks[name])


def decode_compression(
    data: object,
    names: Iterable[str] | None = None,
    *,
    max_output: int = MAX_OUTPUT,
) -> list[Candidate]:
    """Return all verified candidates.

    Automatic mode tries only formats with a signature (plus zlib's checkable two-byte header).
    Pass explicit ``names`` for signatureless Brotli, raw Snappy, or legacy LZMA-alone.
    """

    raw = _raw(data)
    if raw is None:
        return []
    if names is None:
        selected = [name for name, prefixes in _STRONG_PREFIXES.items() if raw.startswith(prefixes)]
        if len(raw) >= 2 and raw[0] & 0x0F == 8 and (raw[0] << 8 | raw[1]) % 31 == 0:
            selected.append("zlib")
        # LZMA-alone has a bounded, recognizable 13-byte header but no magic.
        if len(raw) >= 13 and raw[0] <= 224 and 4096 <= int.from_bytes(raw[1:5], "little") <= (1 << 31):
            selected.append("lzma")
    else:
        selected = list(dict.fromkeys(names))
    out = []
    for name in selected:
        candidate = decode_one(raw, name, max_output=max_output)
        if candidate is not None:
            out.append(candidate)
    return out


def steps(data: object) -> list[tuple[str, bytes]]:
    return [(item.codec, item.payload) for item in decode_compression(data)]


def step_fn(name: str) -> Callable[[object], bytes | None] | None:
    if name not in DECODERS:
        return None

    def read(data: object) -> bytes | None:
        candidate = decode_one(data, name)
        return candidate.payload if candidate else None

    return read


__all__ = [
    "Candidate", "DECODERS", "decode_arithmetic", "decode_brotli", "decode_bzip2",
    "decode_compression", "decode_gzip", "decode_lz4", "decode_lzma", "decode_lzo1x",
    "decode_lzo_frame", "decode_one", "decode_range", "decode_snappy_framed",
    "decode_snappy_raw", "decode_zlib", "decode_zstd", "encode_arithmetic_frame",
    "encode_lzo_literal_frame", "encode_range_frame", "step_fn", "steps",
]
