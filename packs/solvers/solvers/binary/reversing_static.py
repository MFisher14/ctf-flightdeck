"""Bounded, offline reversing leads for native and managed artifacts.

The functions in this module inspect caller-supplied bytes or disassembly text.
They never import, deserialize, load, or execute the artifact.  Results are
evidence leads rather than authoritative identifications: a family is reported
only after a structural header or multiple independent markers reduce the
usual string-only false positives.

The VM helpers operate on *saved disassembly text*.  They group handlers by
normalized instruction semantics so that a reverse engineer can prioritize
representative handlers without running the virtual machine.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
import struct
from typing import Iterable, Mapping, Sequence


MAX_ARTIFACT_BYTES = 64 << 20
MAX_DISASSEMBLY_CHARS = 8 << 20
MAX_VM_HANDLERS = 512
MAX_VM_LABELS = 4096
MAX_HANDLER_LINES = 4096


@dataclass(frozen=True)
class BinaryMetadata:
    """Small amount of header-derived metadata; ``None`` means unsupported."""

    format: str
    architecture: str | None = None
    bits: int | None = None
    entrypoint: int | None = None
    image_base: int | None = None
    managed: bool = False


@dataclass(frozen=True)
class Lead:
    """One ranked language/protector lead and its reproducible evidence."""

    name: str
    confidence: int
    evidence: tuple[str, ...]
    offsets: tuple[int, ...] = ()


@dataclass(frozen=True)
class StaticReport:
    """Deterministic report returned by :func:`analyze_static`."""

    scanned_size: int
    metadata: BinaryMetadata
    language_leads: tuple[Lead, ...]
    protector_leads: tuple[Lead, ...]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class VMHandler:
    name: str
    address: int | None
    instruction_count: int
    features: tuple[str, ...]
    opcodes: tuple[str, ...]


@dataclass(frozen=True)
class VMCluster:
    cluster_id: int
    members: tuple[str, ...]
    shared_features: tuple[str, ...]
    representative: str


@dataclass(frozen=True)
class VMObfuscationReport:
    score: int
    indicators: tuple[str, ...]
    handlers: tuple[VMHandler, ...]
    clusters: tuple[VMCluster, ...]

    def to_dict(self) -> dict:
        return asdict(self)


def _require_bytes(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("artifact must be bytes")
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("artifact exceeds the 64 MiB static scan cap")
    return data


def _u16(data: bytes, offset: int, endian: str) -> int | None:
    if offset < 0 or offset + 2 > len(data):
        return None
    return struct.unpack_from(endian + "H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return struct.unpack_from(endian + "I", data, offset)[0]


def _u64(data: bytes, offset: int, endian: str) -> int | None:
    if offset < 0 or offset + 8 > len(data):
        return None
    return struct.unpack_from(endian + "Q", data, offset)[0]


def _pe_header(data: bytes) -> tuple[int, int, int] | None:
    """Return ``(PE offset, section count, optional-header size)`` if sane."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe = _u32(data, 0x3C, "<")
    if pe is None or pe < 0x40 or pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        return None
    sections = _u16(data, pe + 6, "<")
    optional_size = _u16(data, pe + 20, "<")
    if sections is None or optional_size is None or not 0 <= sections <= 96:
        return None
    section_table = pe + 24 + optional_size
    if section_table > len(data) or section_table + sections * 40 > len(data):
        return None
    return pe, sections, optional_size


def _pe_sections(data: bytes) -> tuple[tuple[str, int], ...]:
    header = _pe_header(data)
    if header is None:
        return ()
    pe, count, optional_size = header
    start = pe + 24 + optional_size
    rows = []
    for index in range(count):
        at = start + index * 40
        raw = data[at:at + 8].split(b"\0", 1)[0]
        if raw and all(0x20 <= value <= 0x7E for value in raw):
            rows.append((raw.decode("ascii"), at))
    return tuple(rows)


def _pe_rva_offset(data: bytes, rva: int) -> int | None:
    header = _pe_header(data)
    if header is None:
        return None
    pe, count, optional_size = header
    optional = pe + 24
    size_of_headers = _u32(data, optional + 60, "<") if optional_size >= 64 else None
    if size_of_headers is not None and rva < size_of_headers and rva < len(data):
        return rva
    section_table = optional + optional_size
    for index in range(count):
        at = section_table + index * 40
        virtual_size = _u32(data, at + 8, "<")
        virtual_address = _u32(data, at + 12, "<")
        raw_size = _u32(data, at + 16, "<")
        raw_offset = _u32(data, at + 20, "<")
        if None in {virtual_size, virtual_address, raw_size, raw_offset}:
            return None
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            delta = rva - virtual_address
            if delta >= raw_size or raw_offset + delta >= len(data):
                return None
            return raw_offset + delta
    return None


def _pe_cli_metadata(data: bytes) -> tuple[int, int, int] | None:
    """Return bounded CLI/metadata offsets from PE data-directory structures."""
    header = _pe_header(data)
    if header is None:
        return None
    pe, _count, optional_size = header
    optional = pe + 24
    magic = _u16(data, optional, "<")
    if magic == 0x10B:
        directory_at, count_at = optional + 96, optional + 92
    elif magic == 0x20B:
        directory_at, count_at = optional + 112, optional + 108
    else:
        return None
    directory_count = _u32(data, count_at, "<")
    cli_entry = directory_at + 14 * 8
    if (directory_count is None or directory_count < 15
            or cli_entry + 8 > optional + optional_size):
        return None
    cli_rva, cli_size = _u32(data, cli_entry, "<"), _u32(data, cli_entry + 4, "<")
    if cli_rva is None or cli_size is None or cli_rva == 0 or cli_size < 0x48:
        return None
    cli_offset = _pe_rva_offset(data, cli_rva)
    if cli_offset is None or cli_offset + 16 > len(data):
        return None
    cli_header_size = _u32(data, cli_offset, "<")
    metadata_rva = _u32(data, cli_offset + 8, "<")
    metadata_size = _u32(data, cli_offset + 12, "<")
    if (cli_header_size is None or cli_header_size < 0x48 or cli_header_size > cli_size
            or cli_offset + cli_header_size > len(data)
            or metadata_rva is None or metadata_size is None or metadata_size < 16):
        return None
    metadata_offset = _pe_rva_offset(data, metadata_rva)
    if (metadata_offset is None or metadata_offset + metadata_size > len(data)
            or data[metadata_offset:metadata_offset + 4] != b"BSJB"):
        return None
    return cli_offset, metadata_offset, metadata_size


def _java_class_sane(data: bytes) -> bool:
    """Validate constant-pool and table bounds without loading JVM bytecode."""
    if len(data) < 24 or data[:4] != b"\xca\xfe\xba\xbe":
        return False
    major, pool_count = _u16(data, 6, ">"), _u16(data, 8, ">")
    if major is None or pool_count is None or not 45 <= major <= 100 or not 2 <= pool_count <= 65535:
        return False
    tags = [0] * pool_count
    at, index = 10, 1
    while index < pool_count:
        if at >= len(data):
            return False
        tag = data[at]
        tags[index] = tag
        at += 1
        if tag == 1:  # CONSTANT_Utf8
            size = _u16(data, at, ">")
            if size is None:
                return False
            at += 2 + size
        elif tag in {3, 4}:  # int/float
            at += 4
        elif tag in {5, 6}:  # long/double occupy two pool slots
            if index + 1 >= pool_count:
                return False
            at += 8
            index += 1
        elif tag in {7, 8, 16, 19, 20}:
            at += 2
        elif tag in {9, 10, 11, 12, 17, 18}:
            at += 4
        elif tag == 15:
            at += 3
        else:
            return False
        if at > len(data):
            return False
        index += 1
    if at + 8 > len(data):
        return False
    this_class = _u16(data, at + 2, ">")
    super_class = _u16(data, at + 4, ">")
    interfaces = _u16(data, at + 6, ">")
    if (this_class is None or not 0 < this_class < pool_count or tags[this_class] != 7
            or super_class is None or super_class >= pool_count
            or super_class and tags[super_class] != 7 or interfaces is None):
        return False
    at += 8
    if at + interfaces * 2 > len(data):
        return False
    for offset in range(interfaces):
        entry = _u16(data, at + offset * 2, ">")
        if entry is None or not 0 < entry < pool_count or tags[entry] != 7:
            return False
    at += interfaces * 2

    def attributes(cursor: int, count: int) -> int | None:
        for _ in range(count):
            if cursor + 6 > len(data):
                return None
            name_index = _u16(data, cursor, ">")
            size = _u32(data, cursor + 2, ">")
            if (name_index is None or not 0 < name_index < pool_count or tags[name_index] != 1
                    or size is None or cursor + 6 + size > len(data)):
                return None
            cursor += 6 + size
        return cursor

    def members(cursor: int) -> int | None:
        count = _u16(data, cursor, ">")
        if count is None:
            return None
        cursor += 2
        for _ in range(count):
            if cursor + 8 > len(data):
                return None
            name_index = _u16(data, cursor + 2, ">")
            descriptor_index = _u16(data, cursor + 4, ">")
            attribute_count = _u16(data, cursor + 6, ">")
            if (name_index is None or descriptor_index is None or attribute_count is None
                    or not 0 < name_index < pool_count or tags[name_index] != 1
                    or not 0 < descriptor_index < pool_count or tags[descriptor_index] != 1):
                return None
            cursor = attributes(cursor + 8, attribute_count)
            if cursor is None:
                return None
        return cursor

    at = members(at)
    if at is None:
        return False
    at = members(at)
    if at is None:
        return False
    class_attributes = _u16(data, at, ">")
    if class_attributes is None:
        return False
    at = attributes(at + 2, class_attributes)
    return at == len(data)


def _parse_metadata(data: bytes) -> BinaryMetadata:
    if data.startswith(b"\0asm") and len(data) >= 8 and data[4:8] == b"\x01\0\0\0":
        return BinaryMetadata("wasm", "wasm32", 32)

    if _java_class_sane(data):
        return BinaryMetadata("java-class", "jvm", None, managed=True)

    if len(data) >= 16 and data[:4] == b"\x7fELF" and data[4] in (1, 2) and data[5] in (1, 2):
        bits = 32 if data[4] == 1 else 64
        endian = "<" if data[5] == 1 else ">"
        header_size = 52 if bits == 32 else 64
        header_size_offset = 40 if bits == 32 else 52
        if (len(data) < header_size or data[6] != 1 or _u32(data, 20, endian) != 1
                or _u16(data, header_size_offset, endian) != header_size):
            return BinaryMetadata("unknown")
        machine = _u16(data, 18, endian)
        arch = {
            3: "x86", 8: "mips", 20: "ppc", 21: "ppc64", 40: "arm",
            62: "amd64", 183: "aarch64", 243: "riscv", 247: "ebpf",
        }.get(machine)
        entry = _u32(data, 24, endian) if bits == 32 else _u64(data, 24, endian)
        return BinaryMetadata("elf", arch, bits, entry)

    pe_header = _pe_header(data)
    if pe_header is not None:
        pe, _sections, optional_size = pe_header
        machine = _u16(data, pe + 4, "<")
        arch = {0x014C: "x86", 0x8664: "amd64", 0x01C0: "arm", 0xAA64: "aarch64"}.get(machine)
        optional = pe + 24
        magic = _u16(data, optional, "<") if optional_size >= 2 else None
        bits = 32 if magic == 0x10B else 64 if magic == 0x20B else None
        entry_rva = _u32(data, optional + 16, "<") if optional_size >= 20 else None
        if magic == 0x10B and optional_size >= 32:
            base = _u32(data, optional + 28, "<")
        elif magic == 0x20B and optional_size >= 32:
            base = _u64(data, optional + 24, "<")
        else:
            base = None
        entry = base + entry_rva if base is not None and entry_rva is not None else entry_rva
        managed = _pe_cli_metadata(data) is not None
        return BinaryMetadata("pe", arch, bits, entry, base, managed)

    # Thin Mach-O only; fat containers deliberately stay architecture-neutral.
    macho = {
        b"\xce\xfa\xed\xfe": ("<", 32), b"\xcf\xfa\xed\xfe": ("<", 64),
        b"\xfe\xed\xfa\xce": (">", 32), b"\xfe\xed\xfa\xcf": (">", 64),
    }.get(data[:4])
    if macho is not None and len(data) >= (28 if macho[1] == 32 else 32):
        endian, bits = macho
        cpu = _u32(data, 4, endian)
        arch = {
            7: "x86", 0x01000007: "amd64", 12: "arm", 0x0100000C: "aarch64",
        }.get(cpu)
        return BinaryMetadata("macho", arch, bits)

    return BinaryMetadata("unknown")


def _marker_offsets(data: bytes, markers: Iterable[bytes]) -> tuple[tuple[str, int], ...]:
    rows = []
    for marker in markers:
        offset = data.find(marker)
        if offset >= 0:
            rows.append((marker.decode("ascii", "backslashreplace"), offset))
    return tuple(rows)


def _lead(name: str, confidence: int, rows: Sequence[tuple[str, int]], *extra: str) -> Lead:
    evidence = tuple(dict.fromkeys([*(item[0] for item in rows), *extra]))
    offsets = tuple(sorted({item[1] for item in rows if item[1] >= 0}))
    return Lead(name, max(0, min(100, confidence)), evidence, offsets)


_RUST_HASHED = re.compile(rb"_?ZN(?:\d+[A-Za-z0-9_$]+){2,}17h[0-9a-f]{16}E")
_RUST_V0 = re.compile(rb"(?<![A-Za-z0-9_])_R[A-Za-z0-9_$.]{12,256}")


def detect_language_leads(data: bytes, metadata: BinaryMetadata | None = None) -> tuple[Lead, ...]:
    """Return high-signal language/runtime leads in a stable priority order."""
    data = _require_bytes(data)
    metadata = metadata or _parse_metadata(data)
    leads: list[Lead] = []

    cli = _pe_cli_metadata(data) if metadata.format == "pe" else None
    if cli is not None:
        cli_offset, metadata_offset, metadata_size = cli
        metadata_blob = data[metadata_offset:metadata_offset + metadata_size]
        dotnet = [
            (name, metadata_offset + offset)
            for name, offset in _marker_offsets(metadata_blob, (b"BSJB", b"#Strings", b"#~"))
        ]
        leads.append(_lead("dotnet", 100, dotnet,
                           f"PE CLI header at file offset {cli_offset:#x}"))

    if metadata.format == "java-class":
        leads.append(Lead("java", 100, ("validated CAFEBABE class header",), (0,)))
    elif data.startswith((b"PK\x03\x04", b"PK\x05\x06")) and b"META-INF/MANIFEST.MF" in data and b".class" in data:
        rows = _marker_offsets(data, (b"META-INF/MANIFEST.MF", b".class"))
        leads.append(_lead("java", 76, rows, "archive-like JVM markers"))

    kotlin = _marker_offsets(data, (
        b"Lkotlin/Metadata;", b"kotlin/Metadata", b".kotlin_module", b"kotlin.Metadata",
        b"Kotlin/Native", b"konan_lldb",
    ))
    kotlin_archive = data.startswith((b"PK\x03\x04", b"PK\x05\x06")) and any(
        item[0] == ".kotlin_module" for item in kotlin
    )
    kotlin_native = metadata.format in {"elf", "pe", "macho"} and {
        "Kotlin/Native", "konan_lldb"
    } <= {item[0] for item in kotlin}
    if kotlin and (metadata.format == "java-class" or kotlin_archive or kotlin_native):
        confidence = 96 if metadata.format == "java-class" else 91 if kotlin_native else 88
        leads.append(_lead("kotlin", confidence, kotlin, "structural Kotlin metadata/runtime marker"))

    go = _marker_offsets(data, (b"Go build ID:", b"runtime.main", b"runtime.morestack", b".gopclntab", b"go.buildid"))
    if len(go) >= 2 and metadata.format in {"elf", "pe", "macho"}:
        leads.append(_lead("go", min(99, 78 + len(go) * 5), go, "multiple Go runtime/build markers"))

    rust_rows = list(_marker_offsets(data, (b"rust_eh_personality", b"core::panicking", b"alloc::", b"rustc_demangle")))
    rust_symbol = _RUST_HASHED.search(data)
    if rust_symbol is not None:
        rust_rows.append((rust_symbol.group()[:96].decode("ascii"), rust_symbol.start()))
    rust_v0 = _RUST_V0.search(data)
    if rust_v0 is not None:
        rust_rows.append((rust_v0.group()[:96].decode("ascii"), rust_v0.start()))
    if (rust_symbol is not None or rust_v0 is not None or len(rust_rows) >= 2) and metadata.format in {"elf", "pe", "macho"}:
        leads.append(_lead("rust", 97 if rust_symbol is not None else 95 if rust_v0 is not None else 86, rust_rows,
                           "Rust symbol/runtime evidence"))

    swift = _marker_offsets(data, (b"__swift5_types", b"__swift5_proto", b"swift_once", b"swift_release", b"_$s"))
    strong_swift = any(item[0].startswith("__swift5_") for item in swift)
    if len(swift) >= 2 and (strong_swift or metadata.format == "macho") and metadata.format in {"elf", "pe", "macho"}:
        leads.append(_lead("swift", min(98, 82 + len(swift) * 3), swift,
                           "Swift reflection/runtime markers"))

    if metadata.format == "wasm":
        leads.append(Lead("wasm", 100, ("validated WebAssembly v1 header",), (0,)))

    if metadata.format == "elf" and metadata.architecture == "ebpf":
        ebpf = _marker_offsets(data, (b"license", b".maps", b"xdp", b"tracepoint"))
        leads.append(_lead("ebpf", 100, ebpf, "ELF e_machine is EM_BPF (247)"))

    order = {name: index for index, name in enumerate(
             ("dotnet", "java", "kotlin", "go", "rust", "swift", "wasm", "ebpf"))}
    return tuple(sorted(leads, key=lambda item: (order[item.name], -item.confidence, item.evidence)))


def detect_protector_leads(data: bytes, metadata: BinaryMetadata | None = None) -> tuple[Lead, ...]:
    """Identify UPX/Themida/VMProtect from paired or structural evidence."""
    data = _require_bytes(data)
    metadata = metadata or _parse_metadata(data)
    if metadata.format not in {"elf", "pe", "macho"}:
        return ()
    sections = _pe_sections(data)
    section_lookup = {name.lower(): offset for name, offset in sections}
    leads: list[Lead] = []

    upx = list(_marker_offsets(data, (b"UPX!", b"UPX0", b"UPX1", b"$Info: This file is packed with the UPX")))
    upx_sections = {name for name in section_lookup if name in {"upx0", "upx1", "upx2"}}
    if {"upx0", "upx1"} <= upx_sections or (any(row[0] == "UPX!" for row in upx) and len(upx) >= 2):
        leads.append(_lead("UPX", 99 if {"upx0", "upx1"} <= upx_sections else 92, upx,
                           "paired UPX sections/markers"))

    if metadata.format == "pe":
        themida_rows = list(_marker_offsets(data, (b"Themida", b"WinLicense", b"Oreans Technologies")))
        themida_sections = [(name, offset) for name, offset in sections
                            if name.lower() in {".themida", ".winlice", ".oreans"}]
        themida_rows.extend(themida_sections)
        if themida_sections or len(themida_rows) >= 2:
            leads.append(_lead("Themida", 98 if themida_sections else 87, themida_rows,
                               "protector section or paired Oreans markers"))

        vmp_rows = list(_marker_offsets(data, (b"VMProtect", b".vmp0", b".vmp1", b".vmp2")))
        vmp_sections = [(name, offset) for name, offset in sections
                        if re.fullmatch(r"\.vmp[0-9]", name.lower())]
        vmp_rows.extend(vmp_sections)
        if vmp_sections or (any(row[0] == "VMProtect" for row in vmp_rows) and len(vmp_rows) >= 2):
            leads.append(_lead("VMProtect", 98 if vmp_sections else 88, vmp_rows,
                               "VMProtect section or paired markers"))

    order = {"UPX": 0, "Themida": 1, "VMProtect": 2}
    return tuple(sorted(leads, key=lambda item: (order[item.name], -item.confidence)))


def analyze_static(data: bytes) -> StaticReport:
    """Analyze one in-memory artifact without invoking a parser runtime."""
    data = _require_bytes(data)
    metadata = _parse_metadata(data)
    return StaticReport(
        scanned_size=len(data),
        metadata=metadata,
        language_leads=detect_language_leads(data, metadata),
        protector_leads=detect_protector_leads(data, metadata),
    )


_LABEL = re.compile(
    r"^\s*(?:(?:0x)?([0-9A-Fa-f]{3,16})\s+)?<([^>]{1,160})>:\s*$|"
    r"^\s*([A-Za-z_.$][\w.$@-]{0,159}):\s*$",
    re.MULTILINE,
)
_INSTRUCTION = re.compile(
    r"^\s*(?:(?:0x)?[0-9A-Fa-f]{3,16}\s*:?)?\s*"
    r"(?:(?:[0-9A-Fa-f]{2}\s+){0,16})"
    r"([A-Za-z][A-Za-z0-9_.]{0,31})(?:\s+(.*?))?\s*$"
)


def _semantic_features(mnemonics: Sequence[str], operands: Sequence[str]) -> tuple[str, ...]:
    features: set[str] = set()
    for mnemonic, operand in zip(mnemonics, operands):
        base = mnemonic.lower().split(".", 1)[0]
        if base.startswith(("add", "adc", "inc")):
            features.add("arithmetic-add")
        if base.startswith(("sub", "sbb", "dec", "neg")):
            features.add("arithmetic-sub")
        if base.startswith(("mul", "imul", "div", "idiv")):
            features.add("arithmetic-muldiv")
        if base.startswith("xor"):
            features.add("bitwise-xor")
        if base.startswith(("and", "or", "not")):
            features.add("bitwise-logic")
        if base.startswith(("shl", "shr", "sar", "sal", "rol", "ror")):
            features.add("shift-rotate")
        if base.startswith(("cmp", "test")):
            features.add("compare")
        if base.startswith("j") or base in {"br", "br_if", "b", "cbz", "cbnz"}:
            features.add("branch")
        if base.startswith("call") or base in {"bl", "blr"}:
            features.add("call")
        if base.startswith(("push", "pop")):
            features.add("stack")
        if base.startswith(("ret", "hlt", "ud2")):
            features.add("return-halt")
        if base.startswith(("mov", "lea", "ldr", "str", "ld", "st")):
            features.add("memory-transfer")
        if base.startswith("jmp") and ("*" in operand or "[" in operand or re.search(r"\b[re]?[abcds][xip]\b", operand)):
            features.add("indirect-dispatch")
    return tuple(sorted(features or {"unknown"}))


def extract_vm_handlers(disassembly: str) -> tuple[VMHandler, ...]:
    """Extract labeled VM-looking blocks from bounded saved disassembly."""
    if not isinstance(disassembly, str):
        raise TypeError("disassembly must be text")
    if len(disassembly) > MAX_DISASSEMBLY_CHARS:
        raise ValueError("disassembly exceeds the 8 MiB cap")
    labels = []
    for label in _LABEL.finditer(disassembly):
        labels.append(label)
        if len(labels) >= MAX_VM_LABELS:
            break
    handlers = []
    for index, label in enumerate(labels):
        name = label.group(2) or label.group(3) or ""
        if not re.search(r"(?i)(?:vm|handler|opcode|op[_-]?(?:0x)?[0-9a-f]+)", name):
            continue
        start = label.end()
        end = labels[index + 1].start() if index + 1 < len(labels) else len(disassembly)
        mnemonics: list[str] = []
        operands: list[str] = []
        for line in disassembly[start:end].splitlines()[:MAX_HANDLER_LINES]:
            match = _INSTRUCTION.match(line)
            if not match:
                continue
            mnemonic = match.group(1).lower()
            # Reject common directive/label words that happen to fit the grammar.
            if mnemonic in {"section", "segment", "align", "db", "dw", "dd", "dq"}:
                continue
            mnemonics.append(mnemonic)
            operands.append((match.group(2) or "").strip())
        address_text = label.group(1)
        address = int(address_text, 16) if address_text else None
        handlers.append(VMHandler(
            name=name,
            address=address,
            instruction_count=len(mnemonics),
            features=_semantic_features(mnemonics, operands),
            opcodes=tuple(mnemonics[:64]),
        ))
        if len(handlers) >= MAX_VM_HANDLERS:
            break
    return tuple(sorted(handlers, key=lambda item: (
        item.address is None, item.address if item.address is not None else 0, item.name
    )))


def _coerce_handler(item: VMHandler | Mapping[str, object]) -> VMHandler:
    if isinstance(item, VMHandler):
        item = {
            "name": item.name, "address": item.address,
            "instruction_count": item.instruction_count,
            "features": item.features, "opcodes": item.opcodes,
        }
    if not isinstance(item, Mapping):
        raise TypeError("handler must be VMHandler or mapping")
    name = item.get("name")
    features = item.get("features")
    address = item.get("address")
    count = item.get("instruction_count", 0)
    opcodes = item.get("opcodes", ())
    if not isinstance(name, str) or not name or len(name) > 160:
        raise ValueError("handler name is invalid")
    if address is not None and (not isinstance(address, int) or isinstance(address, bool)
                                or not 0 <= address < (1 << 64)):
        raise ValueError("handler address is invalid")
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= 1_000_000:
        raise ValueError("handler instruction count is invalid")
    if not isinstance(features, (list, tuple, set, frozenset)) or not features:
        raise ValueError("handler features must be a non-empty sequence")
    if any(not isinstance(value, str) for value in features):
        raise ValueError("handler features must contain text only")
    normalized = tuple(sorted({value for value in features if value}))
    if not normalized or len(normalized) > 128 or any(len(value) > 80 for value in normalized):
        raise ValueError("handler features are invalid")
    if not isinstance(opcodes, (list, tuple)) or len(opcodes) > 64:
        raise ValueError("handler opcodes are invalid")
    if any(not isinstance(value, str) or len(value) > 32 for value in opcodes):
        raise ValueError("handler opcodes must contain bounded text only")
    return VMHandler(name, address, count, normalized, tuple(opcodes))


def cluster_vm_handlers(
    handlers: Sequence[VMHandler | Mapping[str, object]], *, similarity: float = 0.75
) -> tuple[VMCluster, ...]:
    """Cluster handlers using deterministic transitive Jaccard similarity."""
    if not isinstance(handlers, Sequence) or isinstance(handlers, (str, bytes)):
        raise TypeError("handlers must be a sequence")
    if len(handlers) > MAX_VM_HANDLERS:
        raise ValueError("too many VM handlers")
    if not isinstance(similarity, (int, float)) or isinstance(similarity, bool) or not 0.0 <= similarity <= 1.0:
        raise ValueError("similarity must be between zero and one")
    rows = sorted((_coerce_handler(item) for item in handlers), key=lambda item: (
        item.address is None, item.address if item.address is not None else 0, item.name
    ))
    parents = list(range(len(rows)))

    def root(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        lroot, rroot = root(left), root(right)
        if lroot != rroot:
            parents[max(lroot, rroot)] = min(lroot, rroot)

    feature_sets = [set(row.features) for row in rows]
    for left in range(len(rows)):
        for right in range(left + 1, len(rows)):
            union_set = feature_sets[left] | feature_sets[right]
            score = len(feature_sets[left] & feature_sets[right]) / len(union_set) if union_set else 1.0
            if score >= float(similarity):
                union(left, right)

    groups: dict[int, list[int]] = {}
    for index in range(len(rows)):
        groups.setdefault(root(index), []).append(index)
    clusters = []
    for cluster_id, indexes in enumerate(sorted(groups.values(), key=lambda values: values[0]), 1):
        shared = set(rows[indexes[0]].features)
        for index in indexes[1:]:
            shared &= set(rows[index].features)
        representative = min(
            (rows[index] for index in indexes),
            key=lambda item: (-item.instruction_count, item.address is None,
                              item.address if item.address is not None else 0, item.name),
        )
        clusters.append(VMCluster(
            cluster_id=cluster_id,
            members=tuple(rows[index].name for index in indexes),
            shared_features=tuple(sorted(shared)),
            representative=representative.name,
        ))
    return tuple(clusters)


def analyze_vm_obfuscation(disassembly: str, *, similarity: float = 0.75) -> VMObfuscationReport:
    """Rank VM-obfuscation evidence and cluster extracted handler families."""
    handlers = extract_vm_handlers(disassembly)
    lower = disassembly.lower()
    indirect = len(re.findall(r"(?m)^.*\b(?:jmp|br|blr)\s+(?:\*|\[|[re]?[abcds][xip]\b)", lower))
    state_compares = len(re.findall(r"(?m)^.*\b(?:cmp|test)\b", lower))
    indicators = []
    score = 0
    if len(handlers) >= 3:
        indicators.append(f"{len(handlers)} VM/opcode-labeled handler blocks")
        score += min(45, 20 + len(handlers) * 4)
    if indirect:
        indicators.append(f"{indirect} indirect dispatcher branch(es)")
        score += min(30, 12 + indirect * 4)
    if state_compares >= 4:
        indicators.append(f"{state_compares} compare/test operations suggest state dispatch")
        score += min(20, 4 + state_compares * 2)
    semantically_rich = sum(len(set(handler.features) - {"memory-transfer", "return-halt", "stack"}) >= 1
                            for handler in handlers)
    if semantically_rich >= 3:
        indicators.append(f"{semantically_rich} handlers expose distinct semantic operations")
        score += 10
    clusters = cluster_vm_handlers(handlers, similarity=similarity)
    return VMObfuscationReport(min(100, score), tuple(indicators), handlers, clusters)


__all__ = [
    "BinaryMetadata", "Lead", "StaticReport", "VMHandler", "VMCluster",
    "VMObfuscationReport", "analyze_static", "detect_language_leads",
    "detect_protector_leads", "extract_vm_handlers", "cluster_vm_handlers",
    "analyze_vm_obfuscation",
]
