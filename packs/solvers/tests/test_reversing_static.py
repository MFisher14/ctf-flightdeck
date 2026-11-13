"""Deterministic coverage for the r5d static reversing lane."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import reversing_static as static  # noqa: E402


def _elf(machine: int = 62, *markers: bytes) -> bytes:
    data = bytearray(128)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", data, 18, machine)
    struct.pack_into("<I", data, 20, 1)
    struct.pack_into("<Q", data, 24, 0x401000)
    struct.pack_into("<H", data, 52, 64)
    return bytes(data) + b"\0".join(markers)


def _pe(sections: tuple[str, ...] = (), *markers: bytes) -> bytes:
    data = bytearray(0x500)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x86, len(sections))
    struct.pack_into("<H", data, 0x94, 0xF0)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<I", data, 0x98 + 16, 0x1234)
    struct.pack_into("<Q", data, 0x98 + 24, 0x140000000)
    section_table = 0x80 + 24 + 0xF0
    for index, name in enumerate(sections):
        encoded = name.encode("ascii")
        assert len(encoded) <= 8
        data[section_table + index * 40:section_table + index * 40 + len(encoded)] = encoded
    return bytes(data) + b"\0".join(markers)


def _dotnet_pe() -> bytes:
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 0xF0)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 112 + 14 * 8, 0x1100, 0x48)
    section = 0x80 + 24 + 0xF0
    data[section:section + 5] = b".text"
    struct.pack_into("<IIII", data, section + 8, 0x400, 0x1000, 0x400, 0x200)
    cli = 0x300
    struct.pack_into("<I", data, cli, 0x48)
    struct.pack_into("<II", data, cli + 8, 0x1200, 0x80)
    metadata = b"BSJB\0#~\0#Strings\0"
    data[0x400:0x400 + len(metadata)] = metadata
    return bytes(data)


def _lead_names(data: bytes) -> set[str]:
    return {lead.name for lead in static.analyze_static(data).language_leads}


def _java_class(*utf8_values: bytes) -> bytes:
    entries = [b"\x07\x00\x02", b"\x01\x00\x04Demo"]
    for value in utf8_values:
        entries.append(b"\x01" + struct.pack(">H", len(value)) + value)
    header = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 61, len(entries) + 1)
    body = struct.pack(">HHHHHHH", 0x21, 1, 0, 0, 0, 0, 0)
    return header + b"".join(entries) + body


def test_language_leads_cover_managed_native_wasm_and_ebpf():
    dotnet = _dotnet_pe()
    assert _lead_names(dotnet) == {"dotnet"}
    dotnet_report = static.analyze_static(dotnet)
    assert dotnet_report.metadata.managed is True
    assert dotnet_report.metadata.architecture == "amd64"

    java_header = _java_class()
    assert _lead_names(java_header) == {"java"}
    kotlin = _java_class(b"Lkotlin/Metadata;", b".kotlin_module")
    assert _lead_names(kotlin) == {"java", "kotlin"}

    go = _elf(62, b"Go build ID: r5d", b"runtime.main", b".gopclntab")
    assert _lead_names(go) == {"go"}
    rust = _elf(62, b"_ZN4core3ptr13drop_in_place17h0123456789abcdefE", b"rust_eh_personality")
    assert _lead_names(rust) == {"rust"}
    rust_v0 = _elf(62, b"_RNvCs1234567890ab_4demo4main")
    assert _lead_names(rust_v0) == {"rust"}
    swift = _elf(62, b"__swift5_types", b"swift_release", b"_$s4Demo")
    assert _lead_names(swift) == {"swift"}

    assert _lead_names(b"\0asm\x01\0\0\0") == {"wasm"}
    ebpf_report = static.analyze_static(_elf(247, b"license", b".maps", b"xdp"))
    assert {lead.name for lead in ebpf_report.language_leads} == {"ebpf"}
    assert ebpf_report.metadata.architecture == "ebpf"


def test_bare_words_do_not_create_language_or_protector_false_positives():
    report = static.analyze_static(
        b"Documentation mentions Java Kotlin Go Rust Swift .NET UPX Themida VMProtect only."
    )
    assert report.metadata.format == "unknown"
    assert report.language_leads == ()
    assert report.protector_leads == ()

    one_marker = static.analyze_static(_elf(62, b"runtime.main"))
    assert one_marker.language_leads == ()
    fake_kotlin = static.analyze_static(b"Lkotlin/Metadata; and .kotlin_module in documentation")
    assert fake_kotlin.language_leads == ()


def test_truncated_java_and_elf_headers_are_not_structural_leads():
    truncated_java = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 61, 2) + b"\x01\x00\x10short"
    assert static.analyze_static(truncated_java).metadata.format == "unknown"
    truncated_elf64 = b"\x7fELF\x02\x01\x01" + b"\0" * 45
    assert static.analyze_static(truncated_elf64).metadata.format == "unknown"
    bad_ehsize = bytearray(_elf())
    bad_ehsize[52:54] = b"\0\0"
    assert static.analyze_static(bytes(bad_ehsize)).metadata.format == "unknown"
    fake_cli_strings = _pe((), b"BSJB", b"#~", b"#Strings", b"mscoree.dll")
    assert "dotnet" not in _lead_names(fake_cli_strings)
    oversized_cli = bytearray(_dotnet_pe())
    struct.pack_into("<I", oversized_cli, 0x300, 0x100)
    assert "dotnet" not in _lead_names(bytes(oversized_cli))


def test_protector_evidence_uses_sections_or_paired_markers():
    image = _pe(("UPX0", "UPX1", ".themida", ".vmp0"), b"UPX!", b"Themida", b"VMProtect")
    report = static.analyze_static(image)
    assert [lead.name for lead in report.protector_leads] == ["UPX", "Themida", "VMProtect"]
    assert all(lead.confidence >= 98 for lead in report.protector_leads)
    assert any("UPX" in evidence for evidence in report.protector_leads[0].evidence)

    weak = static.analyze_static(_pe((), b"UPX!", b"Themida", b"VMProtect"))
    assert weak.protector_leads == ()
    native_words = static.analyze_static(_elf(
        62, b"Themida", b"WinLicense", b"VMProtect", b".vmp0"
    ))
    assert native_words.protector_leads == ()


VM_TEXT = """
1000 <vm_op_01>:
1000: pop rax
1001: pop rbx
1002: add rax, rbx
1004: push rax
1005: ret
1100 <handler_opcode_02>:
1100: pop rcx
1101: pop rdx
1102: add rcx, rdx
1104: push rcx
1105: ret
1200 <vm_op_03>:
1200: pop rax
1201: pop rbx
1202: xor rax, rbx
1204: push rax
1205: ret
1300 <vm_dispatch>:
1300: cmp eax, 1
1302: cmp eax, 2
1304: cmp eax, 3
1306: cmp eax, 4
1308: jmp rax
"""


def test_vm_extraction_clustering_and_score_are_stable():
    handlers = static.extract_vm_handlers(VM_TEXT)
    assert [item.name for item in handlers] == [
        "vm_op_01", "handler_opcode_02", "vm_op_03", "vm_dispatch"
    ]
    assert "arithmetic-add" in handlers[0].features
    assert "bitwise-xor" in handlers[2].features
    assert "indirect-dispatch" in handlers[3].features

    clusters = static.cluster_vm_handlers(handlers)
    paired = next(cluster for cluster in clusters if "vm_op_01" in cluster.members)
    assert paired.members == ("vm_op_01", "handler_opcode_02")
    assert paired.representative == "vm_op_01"
    report = static.analyze_vm_obfuscation(VM_TEXT)
    assert report.score >= 70
    assert report.to_dict() == static.analyze_vm_obfuscation(VM_TEXT).to_dict()


def test_vm_cluster_mapping_validation_and_caps():
    rows = [
        {"name": "b", "address": 2, "instruction_count": 3,
         "features": ["branch", "compare"], "opcodes": ["cmp", "jne"]},
        {"name": "a", "address": 1, "instruction_count": 4,
         "features": ["compare", "branch"], "opcodes": ["cmp", "je"]},
    ]
    clusters = static.cluster_vm_handlers(rows, similarity=1.0)
    assert clusters[0].members == ("a", "b")
    assert clusters[0].representative == "a"
    with pytest.raises(ValueError, match="similarity"):
        static.cluster_vm_handlers(rows, similarity=1.1)
    with pytest.raises(ValueError, match="features"):
        static.cluster_vm_handlers([{"name": "x", "features": []}])
    with pytest.raises(ValueError, match="text only"):
        static.cluster_vm_handlers([{"name": "x", "features": [object()]}])
    with pytest.raises(ValueError, match="address"):
        static.cluster_vm_handlers([
            static.VMHandler("x", 1 << 64, 1, ("branch",), ("jmp",))
        ])


def test_vm_label_and_handler_caps_are_deterministic(monkeypatch):
    monkeypatch.setattr(static, "MAX_VM_LABELS", 2)
    text = "\n".join(
        f"{0x1000 + index * 0x10:x} <vm_op_{index}>:\n{0x1000 + index * 0x10:x}: ret"
        for index in range(4)
    )
    assert [item.name for item in static.extract_vm_handlers(text)] == ["vm_op_0", "vm_op_1"]
    monkeypatch.setattr(static, "MAX_VM_HANDLERS", 1)
    with pytest.raises(ValueError, match="too many"):
        static.cluster_vm_handlers([
            {"name": "a", "features": ["branch"]},
            {"name": "b", "features": ["branch"]},
        ])


def test_static_input_contract_rejects_mutable_or_oversized_data(monkeypatch):
    with pytest.raises(TypeError, match="bytes"):
        static.analyze_static(bytearray(b"MZ"))  # type: ignore[arg-type]
    monkeypatch.setattr(static, "MAX_ARTIFACT_BYTES", 4)
    with pytest.raises(ValueError, match="cap"):
        static.analyze_static(b"12345")
    with pytest.raises(TypeError, match="text"):
        static.extract_vm_handlers(b"vm:")  # type: ignore[arg-type]
