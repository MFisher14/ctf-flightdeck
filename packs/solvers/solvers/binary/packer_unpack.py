"""Bounded static unpack helpers and source-only Docker unpack plans.

No function in this module opens a file, launches a process, imports an
artifact, or executes a packed program.  Recognized compression streams may be
decoded in memory with strict input/output caps.  UPX and custom-stub workflows
are returned as inert argv/script plans that must be run in the repository's
networkless Docker sandbox.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import bz2
import lzma
import re
import struct
import zlib
from typing import Iterable


MAX_INPUT = 32 << 20
MAX_OUTPUT = 64 << 20
MAX_CANDIDATES = 64
MAX_DUMP_SPAN = 64 << 20


class UnpackError(ValueError):
    """A malformed, truncated, or cap-exceeding packed stream."""


@dataclass(frozen=True)
class UnpackResult:
    format: str
    data: bytes
    consumed: int
    verified: bool
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class CarvedStream:
    offset: int
    format: str
    confidence: int
    evidence: str


@dataclass(frozen=True)
class PackerLead:
    name: str
    confidence: int
    evidence: tuple[str, ...]
    offsets: tuple[int, ...]


@dataclass(frozen=True)
class DockerUnpackPlan:
    engine: str
    image: str
    argv: tuple[str, ...]
    generated_files: tuple[tuple[str, str], ...]
    network: str = "none"
    read_only_root: bool = True
    drop_capabilities: tuple[str, ...] = ("ALL",)
    artifact_execution_expected: bool = False
    timeout_seconds: int = 120

    def to_dict(self) -> dict:
        return asdict(self)


class _AplibReader:
    def __init__(self, data: bytes):
        self.data = data
        self.position = 0
        self.tag = 0
        self.bits_left = 0

    def byte(self) -> int:
        if self.position >= len(self.data):
            raise UnpackError("truncated aPLib stream")
        value = self.data[self.position]
        self.position += 1
        return value

    def bit(self) -> int:
        if self.bits_left == 0:
            self.tag = self.byte()
            self.bits_left = 8
        value = 1 if self.tag & 0x80 else 0
        self.tag = (self.tag << 1) & 0xFF
        self.bits_left -= 1
        return value

    def gamma(self, ceiling: int) -> int:
        value = 1
        for _ in range(64):
            value = (value << 1) | self.bit()
            if value > ceiling:
                raise UnpackError("aPLib gamma value exceeds the output cap")
            if self.bit() == 0:
                return value
        raise UnpackError("aPLib gamma code is unreasonably long")


def _bounded_bytes(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("packed input must be immutable bytes")
    if not data:
        raise UnpackError("packed input is empty")
    if len(data) > MAX_INPUT:
        raise UnpackError("packed input exceeds the 32 MiB cap")
    return data


def _output_cap(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_OUTPUT:
        raise ValueError("max_output must be in 1..64 MiB")
    return value


def decompress_aplib(data: bytes, *, max_output: int = MAX_OUTPUT) -> UnpackResult:
    """Decode one raw aPLib stream without calling native code.

    aPLib has no raw-stream magic, so callers must select this decoder from
    independent evidence or an AP32 wrapper.  A terminating short-match marker
    is mandatory; reaching EOF is treated as truncation.
    """
    data = _bounded_bytes(data)
    max_output = _output_cap(max_output)
    reader = _AplibReader(data)
    output = bytearray((reader.byte(),))
    last_offset = -1
    last_was_match = False
    operations = 0

    def append(value: int) -> None:
        if len(output) >= max_output:
            raise UnpackError("aPLib output exceeds the configured cap")
        output.append(value)

    def copy(offset: int, length: int) -> None:
        if offset <= 0 or offset > len(output):
            raise UnpackError("aPLib back-reference is outside produced output")
        if length < 0 or length > max_output - len(output):
            raise UnpackError("aPLib copy exceeds the configured cap")
        for _ in range(length):
            output.append(output[-offset])

    while True:
        operations += 1
        if operations > len(data) * 16 + 16:
            raise UnpackError("aPLib operation cap exceeded")
        if reader.bit() == 0:
            append(reader.byte())
            last_was_match = False
            continue
        if reader.bit() == 0:
            offset = reader.gamma(max_output)
            if not last_was_match and offset == 2:
                if last_offset <= 0:
                    raise UnpackError("aPLib repeats an unavailable offset")
                offset = last_offset
                length = reader.gamma(max_output)
            else:
                offset -= 2 if last_was_match else 3
                if offset < 0:
                    raise UnpackError("aPLib encoded a negative offset prefix")
                offset = (offset << 8) + reader.byte()
                length = reader.gamma(max_output)
                if offset >= 32000:
                    length += 1
                if offset >= 1280:
                    length += 1
                if offset < 128:
                    length += 2
                last_offset = offset
            copy(offset, length)
            last_was_match = True
            continue
        if reader.bit() == 0:
            packed_offset = reader.byte()
            length = 2 + (packed_offset & 1)
            offset = packed_offset >> 1
            if offset == 0:
                return UnpackResult("aplib", bytes(output), reader.position, True,
                                    ("terminating short-match marker present",))
            copy(offset, length)
            last_offset = offset
            last_was_match = True
            continue
        offset = 0
        for _ in range(4):
            offset = (offset << 1) | reader.bit()
        append(output[-offset] if offset else 0)
        last_was_match = False


def parse_ap32(data: bytes, *, max_output: int = MAX_OUTPUT) -> UnpackResult:
    """Validate an ``AP32`` safe wrapper and decode its aPLib payload."""
    data = _bounded_bytes(data)
    max_output = _output_cap(max_output)
    if len(data) < 24 or data[:4] != b"AP32":
        raise UnpackError("not an AP32 wrapper")
    header_size, packed_size, packed_crc, original_size, original_crc = struct.unpack_from("<IIIII", data, 4)
    if not 24 <= header_size <= len(data):
        raise UnpackError("invalid AP32 header size")
    if packed_size == 0 or packed_size > MAX_INPUT or header_size + packed_size > len(data):
        raise UnpackError("invalid or truncated AP32 packed size")
    if original_size == 0 or original_size > max_output:
        raise UnpackError("AP32 original size exceeds the output cap")
    payload = data[header_size:header_size + packed_size]
    if zlib.crc32(payload) & 0xFFFFFFFF != packed_crc:
        raise UnpackError("AP32 packed CRC mismatch")
    decoded = decompress_aplib(payload, max_output=original_size)
    if decoded.consumed != packed_size:
        raise UnpackError("AP32 payload contains bytes after the aPLib terminator")
    if len(decoded.data) != original_size:
        raise UnpackError("AP32 decoded size mismatch")
    if zlib.crc32(decoded.data) & 0xFFFFFFFF != original_crc:
        raise UnpackError("AP32 original CRC mismatch")
    return UnpackResult("ap32", decoded.data, header_size + decoded.consumed, True,
                        ("packed and original CRC32 verified",))


_MAGICS: tuple[tuple[str, bytes, int, str], ...] = (
    ("ap32", b"AP32", 100, "AP32 safe-wrapper magic"),
    ("gzip", b"\x1f\x8b\x08", 98, "gzip deflate header"),
    ("xz", b"\xfd7zXZ\x00", 100, "XZ stream header"),
    ("bzip2", b"BZh", 96, "bzip2 stream header"),
    ("zlib", b"\x78\x01", 88, "zlib no/fast-compression header"),
    ("zlib", b"\x78\x5e", 88, "zlib fast-compression header"),
    ("zlib", b"\x78\x9c", 90, "zlib default-compression header"),
    ("zlib", b"\x78\xda", 90, "zlib best-compression header"),
)


def carve_streams(data: bytes, *, max_candidates: int = MAX_CANDIDATES) -> tuple[CarvedStream, ...]:
    """Locate structured embedded streams in a custom unpacking stub."""
    data = _bounded_bytes(data)
    if not isinstance(max_candidates, int) or isinstance(max_candidates, bool) or not 1 <= max_candidates <= MAX_CANDIDATES:
        raise ValueError("max_candidates must be in 1..64")
    rows = []
    for format_name, magic, confidence, evidence in _MAGICS:
        start = 0
        found_for_magic = 0
        while found_for_magic < max_candidates:
            offset = data.find(magic, start)
            if offset < 0:
                break
            rows.append(CarvedStream(offset, format_name, confidence, evidence))
            found_for_magic += 1
            start = offset + 1
    unique = {(row.offset, row.format): row for row in rows}
    return tuple(sorted(unique.values(), key=lambda row: (row.offset, row.format)))[:max_candidates]


def _zlib_stream(tail: bytes, *, wbits: int, max_output: int, name: str) -> UnpackResult:
    decoder = zlib.decompressobj(wbits)
    try:
        output = decoder.decompress(tail, max_output + 1)
    except zlib.error as exc:
        raise UnpackError(f"invalid {name} stream") from exc
    if len(output) > max_output or decoder.unconsumed_tail:
        raise UnpackError(f"{name} output exceeds the configured cap")
    if not decoder.eof:
        raise UnpackError(f"truncated {name} stream")
    consumed = len(tail) - len(decoder.unused_data)
    return UnpackResult(name, output, consumed, True, ("container checksum verified by decoder",))


def decompress_carved(
    data: bytes, candidate: CarvedStream, *, max_output: int = MAX_OUTPUT
) -> UnpackResult:
    """Decode one previously carved stream; trailing stub bytes are ignored."""
    data = _bounded_bytes(data)
    max_output = _output_cap(max_output)
    if not isinstance(candidate, CarvedStream):
        raise TypeError("candidate must be CarvedStream")
    if not 0 <= candidate.offset < len(data):
        raise UnpackError("carved stream offset is outside the input")
    tail = data[candidate.offset:]
    if candidate.format == "ap32":
        return parse_ap32(tail, max_output=max_output)
    if candidate.format == "gzip":
        return _zlib_stream(tail, wbits=16 + zlib.MAX_WBITS, max_output=max_output, name="gzip")
    if candidate.format == "zlib":
        return _zlib_stream(tail, wbits=zlib.MAX_WBITS, max_output=max_output, name="zlib")
    if candidate.format == "bzip2":
        decoder = bz2.BZ2Decompressor()
        try:
            output = decoder.decompress(tail, max_length=max_output + 1)
        except (OSError, EOFError) as exc:
            raise UnpackError("invalid bzip2 stream") from exc
        if len(output) > max_output or not decoder.eof:
            raise UnpackError("truncated or over-cap bzip2 stream")
        return UnpackResult("bzip2", output, len(tail) - len(decoder.unused_data), True,
                            ("bzip2 end marker verified",))
    if candidate.format == "xz":
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=MAX_OUTPUT)
        try:
            output = decoder.decompress(tail, max_length=max_output + 1)
        except lzma.LZMAError as exc:
            raise UnpackError("invalid XZ stream") from exc
        if len(output) > max_output or not decoder.eof:
            raise UnpackError("truncated or over-cap XZ stream")
        return UnpackResult("xz", output, len(tail) - len(decoder.unused_data), True,
                            ("XZ integrity check verified",))
    raise UnpackError(f"unsupported carved format: {candidate.format}")


def detect_packer_leads(data: bytes) -> tuple[PackerLead, ...]:
    """Return conservative string/section leads without attempting unpacking."""
    data = _bounded_bytes(data)
    definitions: Iterable[tuple[str, tuple[bytes, ...], int]] = (
        ("UPX", (b"UPX!", b"UPX0", b"UPX1"), 96),
        ("aPLib", (b"AP32", b"aPLib"), 90),
        ("Themida", (b".themida", b"Oreans Technologies"), 88),
        ("VMProtect", (b".vmp0", b"VMProtect"), 88),
    )
    leads = []
    executable = _executable_kind(data)
    for name, markers, confidence in definitions:
        found = [(marker.decode("ascii"), data.find(marker)) for marker in markers if data.find(marker) >= 0]
        required = 1 if name == "aPLib" and any(item[0] == "AP32" for item in found) else 2
        context_ok = name == "aPLib" or executable is not None
        if name in {"Themida", "VMProtect"}:
            context_ok = executable == "pe"
        if context_ok and len(found) >= required:
            leads.append(PackerLead(name, confidence, tuple(item[0] for item in found),
                                    tuple(sorted(item[1] for item in found))))
    order = {"UPX": 0, "aPLib": 1, "Themida": 2, "VMProtect": 3}
    return tuple(sorted(leads, key=lambda row: (order[row.name], -row.confidence)))


def _executable_kind(data: bytes) -> str | None:
    if len(data) >= 52 and data[:4] == b"\x7fELF" and data[4] in {1, 2} and data[5] in {1, 2}:
        return "elf"
    if len(data) >= 0x40 and data[:2] == b"MZ":
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if 0x40 <= pe <= len(data) - 24 and data[pe:pe + 4] == b"PE\0\0":
            return "pe"
    if data[:4] in {
        b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    }:
        return "macho"
    return None


_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def _name(value: str, field: str) -> str:
    if not isinstance(value, str) or not _SAFE_NAME.fullmatch(value) or value in {".", ".."} or ".." in value:
        raise ValueError(f"unsafe {field} basename")
    return value


def build_upx_docker_plan(input_name: str, output_name: str = "unpacked.bin") -> DockerUnpackPlan:
    """Return argv for UPX inside Docker; this function does not invoke it."""
    source, output = _name(input_name, "input"), _name(output_name, "output")
    return DockerUnpackPlan(
        engine="upx",
        image="docker/pwn",
        argv=("upx", "-d", "-f", "-o", f"/out/{output}", f"/work/{source}"),
        generated_files=(),
        artifact_execution_expected=False,
        timeout_seconds=120,
    )


def _address(value: int, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < (1 << 64):
        raise ValueError(f"{field} must be an unsigned 64-bit integer")
    return value


def build_custom_stub_dump_plan(
    input_name: str,
    *,
    oep: int,
    dump_start: int,
    dump_end: int,
    architecture: str = "amd64",
    output_name: str = "unpacked-memory.bin",
) -> DockerUnpackPlan:
    """Emit a batch-GDB memory-dump plan for deliberate Docker detonation."""
    source, output = _name(input_name, "input"), _name(output_name, "output")
    if architecture not in {"x86", "amd64", "arm", "aarch64", "mips"}:
        raise ValueError("unsupported architecture")
    oep = _address(oep, "oep")
    dump_start = _address(dump_start, "dump_start")
    dump_end = _address(dump_end, "dump_end")
    if not dump_start < dump_end or dump_end - dump_start > MAX_DUMP_SPAN:
        raise ValueError("dump span must be positive and at most 64 MiB")
    gdb_arch = {
        "x86": "i386", "amd64": "i386:x86-64", "arm": "arm",
        "aarch64": "aarch64", "mips": "mips",
    }[architecture]
    script = "\n".join((
        "set pagination off",
        "set confirm off",
        "set breakpoint pending on",
        f"set architecture {gdb_arch}",
        f"break *{oep:#x}",
        "run",
        f"dump binary memory /out/{output} {dump_start:#x} {dump_end:#x}",
        "info registers",
        "quit",
        "",
    ))
    return DockerUnpackPlan(
        engine="gdb-custom-stub",
        image="docker/pwn",
        argv=("gdb-multiarch", "--batch", "-x", "/plan/r5d_unpack.gdb", f"/work/{source}"),
        generated_files=(("r5d_unpack.gdb", script),),
        artifact_execution_expected=True,
        timeout_seconds=180,
    )


__all__ = [
    "UnpackError", "UnpackResult", "CarvedStream", "PackerLead", "DockerUnpackPlan",
    "decompress_aplib", "parse_ap32", "carve_streams", "decompress_carved",
    "detect_packer_leads", "build_upx_docker_plan", "build_custom_stub_dump_plan",
]
