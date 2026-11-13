#!/usr/bin/env python3
"""Static video-steganography planning and extracted-frame analysis.

The engine itself never invokes ffmpeg or opens media codecs.  ``sandbox_plan`` emits reviewable
``tools/sandbox.py`` commands for extracting PNG/keyframes with network disabled.  The remaining
APIs consume those PNGs (or caller-supplied pixel buffers) and perform per-frame LSB, inter-frame
differences, and 8x8 keyframe DCT-parity scans.  MP4/MOV boxes, Matroska codec strings, and supplied
ffprobe JSON are inspected for subtitle, attachment, metadata, timecode, and data tracks.

All dimensions, decompression, frame count, DCT blocks, and candidate output are bounded.  Results
are ranked byte candidates for a human, never a judge probe.
"""
from __future__ import annotations

import argparse
import binascii
import itertools
import json
import math
import re
import shlex
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

PNG_SIG = b"\x89PNG\r\n\x1a\n"
MAX_INPUT = 256 << 20
MAX_FRAME_BYTES = 64 << 20
MAX_PIXELS = 16_000_000
MAX_FRAMES = 4096
MAX_CANDIDATES = 512
MAX_DCT_BLOCKS = 1_000_000
_FLAG = flagfmt.BYTES
_PRINT = re.compile(rb"[\x20-\x7e]{8,1024}")


class VideoStegoError(ValueError):
    pass


def _bounded_frames(frames, minimum: int) -> list:
    try:
        rows = list(itertools.islice(iter(frames), MAX_FRAMES + 1))
    except (TypeError, MemoryError) as exc:
        raise VideoStegoError("frames must be a bounded iterable") from exc
    if not minimum <= len(rows) <= MAX_FRAMES:
        raise VideoStegoError(f"frame count must be in {minimum}..{MAX_FRAMES}")
    return rows


@dataclass(frozen=True)
class Frame:
    width: int
    height: int
    channels: int
    pixels: bytes
    name: str = "frame"

    def __post_init__(self):
        if not (0 < self.width * self.height <= MAX_PIXELS and self.channels in (1, 2, 3, 4)
                and len(self.pixels) == self.width * self.height * self.channels):
            raise VideoStegoError("frame dimensions/pixel length are inconsistent or exceed cap")


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    return a if pa <= pb and pa <= pc else b if pb <= pc else c


def read_png_frame(data: bytes, name: str = "frame.png") -> Frame:
    """Decode the standard 8-bit, non-interlaced PNGs emitted by ffmpeg."""
    if not isinstance(data, bytes) or len(data) > MAX_FRAME_BYTES or not data.startswith(PNG_SIG):
        raise VideoStegoError("not a bounded PNG frame")
    pos, ihdr, compressed, seen_iend = 8, None, bytearray(), False
    while pos + 12 <= len(data):
        length = struct.unpack_from(">I", data, pos)[0]
        if length > MAX_FRAME_BYTES or pos + 12 + length > len(data):
            raise VideoStegoError("truncated PNG chunk")
        kind, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + length]
        stored = struct.unpack_from(">I", data, pos + 8 + length)[0]
        if binascii.crc32(kind + body) & 0xFFFFFFFF != stored:
            raise VideoStegoError("PNG chunk CRC mismatch")
        if kind == b"IHDR":
            if ihdr is not None:
                raise VideoStegoError("duplicate PNG IHDR")
            ihdr = body
        elif kind == b"IDAT":
            compressed += body
            if len(compressed) > MAX_FRAME_BYTES:
                raise VideoStegoError("PNG compressed data exceeds cap")
        elif kind == b"IEND":
            seen_iend = True
            pos += 12 + length
            break
        pos += 12 + length
    if not seen_iend or pos != len(data) or ihdr is None or len(ihdr) != 13:
        raise VideoStegoError("PNG structure is incomplete")
    width, height, depth, color, comp, filt, interlace = struct.unpack(">IIBBBBB", ihdr)
    channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color)
    if channels is None or depth != 8 or comp or filt or interlace:
        raise VideoStegoError("frame PNG must be 8-bit grayscale/RGB(A), non-interlaced")
    if not 0 < width * height <= MAX_PIXELS:
        raise VideoStegoError("PNG pixel count exceeds cap")
    stride = width * channels
    expected = height * (stride + 1)
    decoder = zlib.decompressobj()
    raw = decoder.decompress(bytes(compressed), expected + 1)
    raw += decoder.flush(expected + 1 - len(raw))
    if len(raw) != expected or not decoder.eof or decoder.unused_data:
        raise VideoStegoError("PNG scanline stream did not decode exactly")
    pixels, previous, at = bytearray(), bytearray(stride), 0
    for _row in range(height):
        method, encoded = raw[at], raw[at + 1:at + 1 + stride]
        at += stride + 1
        if method > 4:
            raise VideoStegoError("invalid PNG scanline filter")
        decoded = bytearray(stride)
        for index, value in enumerate(encoded):
            left = decoded[index - channels] if index >= channels else 0
            above = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            predictor = (0 if method == 0 else left if method == 1 else above if method == 2
                         else (left + above) // 2 if method == 3 else _paeth(left, above, upper_left))
            decoded[index] = (value + predictor) & 0xFF
        pixels += decoded
        previous = decoded
    return Frame(width, height, channels, bytes(pixels), name)


def _pack_bit_iter(bits, bit_count: int, msb_first=True) -> bytes:
    length = bit_count // 8
    out = bytearray(length)
    iterator = iter(bits)
    for index in range(length):
        value = 0
        if msb_first:
            for _ in range(8):
                bit = next(iterator)
                value = (value << 1) | bit
        else:
            for offset in range(8):
                bit = next(iterator)
                value |= bit << offset
        out[index] = value
    return bytes(out)


def _pack_bits(bits, msb_first=True) -> bytes:
    return _pack_bit_iter(bits, len(bits), msb_first)


def _byte_candidates(data: bytes, provenance: dict) -> list[dict]:
    out = []
    for match in _FLAG.finditer(data):
        out.append({"score": 100, "kind": "flag-shaped", "offset": match.start(),
                    "value": match.group().decode("ascii"), **provenance})
    signatures = ((b"\x89PNG\r\n\x1a\n", "png"), (b"PK\x03\x04", "zip"),
                  (b"%PDF-", "pdf"), (b"\x1f\x8b", "gzip"))
    for magic, kind in signatures:
        offset = data.find(magic)
        if offset >= 0:
            out.append({"score": 90, "kind": kind, "offset": offset,
                        "value_hex": data[offset:offset + min(256, len(data) - offset)].hex(), **provenance})
    for match in list(_PRINT.finditer(data))[:16]:
        out.append({"score": 60, "kind": "printable", "offset": match.start(),
                    "value": match.group().decode("ascii"), **provenance})
    return out


def frame_lsb_candidates(frames, *, bit: int = 0, channels=None) -> list[dict]:
    rows = _bounded_frames(frames, 1)
    if bit not in range(8):
        raise VideoStegoError("frame count/bit outside bounds")
    output = []
    for frame_index, frame in enumerate(rows):
        if not isinstance(frame, Frame):
            raise VideoStegoError("frames must be Frame objects")
        selected = list(range(frame.channels)) if channels is None else list(channels)
        if not selected or len(selected) > 4 or any(not isinstance(c, int) or not 0 <= c < frame.channels for c in selected):
            raise VideoStegoError("invalid channel selection")
        bit_count = frame.width * frame.height * len(selected)
        for msb in (True, False):
            bits = (((frame.pixels[pixel * frame.channels + channel] >> bit) & 1)
                    for pixel in range(frame.width * frame.height) for channel in selected)
            packed = _pack_bit_iter(bits, bit_count, msb)
            output.extend(_byte_candidates(packed, {"frame": frame_index, "frame_name": frame.name,
                                                    "method": f"lsb-bit{bit}-{'msb' if msb else 'lsb'}",
                                                    "channels": selected}))
    return sorted(output[:MAX_CANDIDATES], key=lambda item: (-item["score"], item["frame"], item["offset"]))


def interframe_candidates(frames) -> list[dict]:
    rows = _bounded_frames(frames, 2)
    output = []
    for index, (left, right) in enumerate(zip(rows, rows[1:])):
        if not isinstance(left, Frame) or not isinstance(right, Frame) or (
                left.width, left.height, left.channels) != (right.width, right.height, right.channels):
            raise VideoStegoError("adjacent frame geometry differs")
        pixel_count = left.width * left.height

        def changed_bits():
            for pixel in range(pixel_count):
                start = pixel * left.channels
                yield int(left.pixels[start:start + left.channels] != right.pixels[start:start + right.channels])

        def xor_bits():
            for pixel in range(pixel_count):
                start = pixel * left.channels
                yield (left.pixels[start] ^ right.pixels[start]) & 1

        for label, bit_factory in (("changed-pixel-mask", changed_bits), ("red-xor-lsb", xor_bits)):
            for msb in (True, False):
                output.extend(_byte_candidates(_pack_bit_iter(bit_factory(), pixel_count, msb),
                                               {"frame_pair": [index, index + 1],
                                                "method": f"{label}-{'msb' if msb else 'lsb'}"}))
    return sorted(output[:MAX_CANDIDATES], key=lambda item: (-item["score"], item["frame_pair"], item["offset"]))


def keyframe_dct_candidates(frames, *, coefficient=(1, 2)) -> list[dict]:
    """Scan parity of a mid-frequency 8x8 luminance DCT coefficient in extracted keyframes."""
    rows = _bounded_frames(frames, 1)
    u, v = coefficient
    if not (0 <= u < 8 and 0 <= v < 8 and (u or v)):
        raise VideoStegoError("DCT coefficient must be a non-DC 8x8 coordinate")
    cosx = [[math.cos((2 * x + 1) * u * math.pi / 16) for x in range(8)] for u in range(8)]
    output, block_count = [], 0
    for frame_index, frame in enumerate(rows):
        bits = []
        for y0 in range(0, frame.height - 7, 8):
            for x0 in range(0, frame.width - 7, 8):
                block_count += 1
                if block_count > MAX_DCT_BLOCKS:
                    raise VideoStegoError("DCT block cap exceeded")
                total = 0.0
                for y in range(8):
                    for x in range(8):
                        start = ((y0 + y) * frame.width + x0 + x) * frame.channels
                        px = frame.pixels[start:start + frame.channels]
                        luminance = px[0] if frame.channels < 3 else (77 * px[0] + 150 * px[1] + 29 * px[2]) / 256
                        total += (luminance - 128) * cosx[u][x] * cosx[v][y]
                bits.append(abs(round(total / 4)) & 1)
        for msb in (True, False):
            output.extend(_byte_candidates(_pack_bits(bits, msb),
                                           {"frame": frame_index, "frame_name": frame.name,
                                            "method": f"pixel-dct-{u}-{v}-parity-{'msb' if msb else 'lsb'}"}))
    return sorted(output[:MAX_CANDIDATES], key=lambda item: (-item["score"], item["frame"], item["offset"]))


def _mp4_boxes(data: bytes, start=0, end=None, depth=0):
    if end is None:
        end = len(data)
    if depth > 12:
        return
    pos = start
    containers = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"udta", b"meta", b"ilst"}
    count = 0
    while pos + 8 <= end and count < 100000:
        size, kind = struct.unpack_from(">I4s", data, pos)
        header = 8
        if size == 1:
            if pos + 16 > end:
                return
            size, header = struct.unpack_from(">Q", data, pos + 8)[0], 16
        elif size == 0:
            size = end - pos
        if size < header or pos + size > end:
            return
        yield {"kind": kind, "offset": pos, "size": size, "body": data[pos + header:pos + size], "depth": depth}
        child_start = pos + header + (4 if kind == b"meta" else 0)
        if kind in containers and child_start <= pos + size:
            yield from _mp4_boxes(data, child_start, pos + size, depth + 1)
        pos += size
        count += 1


def hidden_tracks(data: bytes, ffprobe=None) -> list[dict]:
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        raise VideoStegoError("video input exceeds cap")
    findings = []
    if len(data) >= 12 and data[4:8] == b"ftyp":
        for box in _mp4_boxes(data):
            if box["kind"] == b"hdlr" and len(box["body"]) >= 12:
                handler = box["body"][8:12].decode("latin-1")
                if handler not in ("vide", "soun"):
                    findings.append({"score": 90, "kind": "mp4-track", "handler": handler,
                                     "offset": box["offset"], "reason": "non-audio/video handler"})
            elif box["kind"] in (b"uuid", b"meta"):
                findings.append({"score": 60, "kind": "mp4-box", "box": box["kind"].decode(),
                                 "offset": box["offset"], "reason": "metadata/private box"})
    if data.startswith(b"\x1aE\xdf\xa3"):
        text = data.decode("latin-1", "ignore")
        for match in re.finditer(r"(?:S_(?:TEXT|HDMV|VOBSUB)/[A-Z0-9_]+|application/(?:octet-stream|x-truetype-font))", text):
            findings.append({"score": 90, "kind": "matroska-track-or-attachment", "codec": match.group(),
                             "offset": match.start(), "reason": "subtitle/data/attachment codec"})
    if ffprobe is not None:
        if not isinstance(ffprobe, dict):
            raise VideoStegoError("ffprobe report must be an object")
        streams = ffprobe.get("streams", [])
        if not isinstance(streams, list) or len(streams) > 4096:
            raise VideoStegoError("ffprobe stream count exceeds cap")
        for stream in streams:
            if not isinstance(stream, dict):
                continue
            codec_type = stream.get("codec_type")
            attached = bool((stream.get("disposition") or {}).get("attached_pic")) if isinstance(stream.get("disposition"), dict) else False
            if codec_type not in ("video", "audio") or attached:
                findings.append({"score": 95 if codec_type in ("subtitle", "data", "attachment") else 75,
                                 "kind": "ffprobe-stream", "index": stream.get("index"),
                                 "codec_type": codec_type, "codec_name": stream.get("codec_name"),
                                 "tags": stream.get("tags", {}), "reason": "non-primary/attached stream"})
    return sorted(findings[:MAX_CANDIDATES], key=lambda row: (-row["score"], row.get("offset", 0)))


def sandbox_plan(input_name: str = "video") -> list[dict]:
    safe = shlex.quote(Path(input_name).name or "video")
    return [
        {"purpose": "stream inventory", "command": f"python tools/sandbox.py run --in {safe} ffprobe -v error -show_streams -show_format -of json {{in}}"},
        {"purpose": "all frames as PNG", "command": f"python tools/sandbox.py run --in {safe} ffmpeg -v error -i {{in}} -vsync 0 /out/frame-%06d.png"},
        {"purpose": "keyframes as PNG", "command": f"python tools/sandbox.py run --in {safe} ffmpeg -v error -skip_frame nokey -i {{in}} -vsync 0 /out/key-%06d.png"},
        {"purpose": "attachments", "command": f"python tools/sandbox.py run --in {safe} ffmpeg -v error -dump_attachment:t '' -i {{in}}"},
    ]


def _read(path: str, cap=MAX_INPUT) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        raise VideoStegoError("input exceeds size cap")
    return data


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="video_stego.py")
    sub = parser.add_subparsers(dest="operation", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("input")
    tracks = sub.add_parser("tracks")
    tracks.add_argument("input")
    tracks.add_argument("--ffprobe-json")
    frames = sub.add_parser("frames")
    frames.add_argument("inputs", nargs="+")
    frames.add_argument("--bit", type=int, default=0)
    parser.add_argument("--json", action="store_true")
    for command in (plan, tracks, frames):
        command.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    try:
        args = parser.parse_args(argv)
        if args.operation == "plan":
            result = {"candidates": sandbox_plan(args.input)}
        elif args.operation == "tracks":
            report = json.loads(_read(args.ffprobe_json, 8 << 20).decode("utf-8")) if args.ffprobe_json else None
            result = {"candidates": hidden_tracks(_read(args.input), report)}
        else:
            if len(args.inputs) > MAX_FRAMES:
                raise VideoStegoError("frame count exceeds cap")
            decoded = [read_png_frame(_read(path, MAX_FRAME_BYTES), Path(path).name) for path in args.inputs]
            result = {"lsb": frame_lsb_candidates(decoded, bit=args.bit),
                      "interframe": interframe_candidates(decoded) if len(decoded) > 1 else [],
                      "dct": keyframe_dct_candidates(decoded)}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, OverflowError, UnicodeError, json.JSONDecodeError,
            struct.error, zlib.error, RecursionError, MemoryError) as exc:
        print(f"video_stego: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
