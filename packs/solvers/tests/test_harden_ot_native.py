"""Independent vector locks and fail-closed fuzz for native OT readers.

Oracles are hand-authored documented layouts, Python's ZIP/UDP encoders, and
``hashlib``.  No expected value is obtained from an engine encoder.

Sources:
* CODESYS symbol XML documentation and published Symbolconfiguration schema.
* Kaspersky ICS CERT, *The secrets of Schneider Electric's UMAS protocol*.
* ESET, *WIN32/INDUSTROYER*, page 13, Figure 20; RFC 768 for UDP.
"""

from __future__ import annotations

import hashlib
import io
import random
import struct
import zipfile

import pytest

import ot_codesys_native as codesys
import ot_schneider_native as schneider
import ot_siprotec_signature as siprotec


CODESYS_SYMBOL = b"""<?xml version="1.0" encoding="utf-8"?>
<Symbolconfiguration xmlns="http://www.3s-software.com/schemas/Symbolconfiguration.xsd"
                     version="3.5">
  <Header><ProjectInfo name="WaterPlant" appname="Application"/></Header>
  <TypeList><TypeSimple name="T_BOOL" size="1" iecname="BOOL"/></TypeList>
  <NodeList>
    <Node name="Application" offset="0">
      <Node name="PLC_PRG" offset="4">
        <Node name="PumpRun" type="T_BOOL" access="ReadWrite" offset="12"/>
      </Node>
    </Node>
  </NodeList>
</Symbolconfiguration>"""

CODESYS_INI = (
    b"\xef\xbb\xbf; supplied fixture\r\n"
    b"[CmpApp]\r\nApplication.1=WaterPlant\r\n"
    b"Application.1=Standby ; literal semicolon\r\n"
    b"[SysFileMap]\r\nFile.1=/plc/app;/plc/app\r\n"
)

SIPROTEC_FIGURE20 = bytes.fromhex(
    "11 49 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28 9e"
)


def _only_declared(call, declared_error, cases):
    """Permit a clean parse or exactly the engine's public error type."""

    for label, candidate in cases:
        try:
            result = call(candidate)
        except declared_error:
            continue
        except Exception as exc:  # pragma: no cover - assertion explains a leak
            pytest.fail(
                f"{label} leaked {type(exc).__name__} instead of "
                f"{declared_error.__name__}: {exc}"
            )
        assert result is None or isinstance(result, dict), label


def _apx_vector(payload: bytes = b"PumpRun\x00") -> bytes:
    """Encode the observed apxutil type-2 layout without engine helpers."""

    file_header = bytearray(32)
    file_header[:4] = b"APX\0"
    file_header[4:6] = (0x0100).to_bytes(2, "little")
    file_header[6] = 2
    file_header[10] = 16
    section_header = struct.pack(
        "<HHHIIH", 2, 0, 0x1234, 0x10203040, len(payload), 0
    )
    rte = struct.pack(
        "<IIIHBB", 0, max(0, len(payload) - 1), 0, 0xBEEF, 0x7A, 0
    )
    return bytes(file_header) + section_header + rte + payload


def _zip_vector(name: str, payload: bytes) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(name, payload)
    return stream.getvalue()


def _umas_download_pdu() -> bytes:
    # Kaspersky documents FC 0x5a, session, UMAS 0x31, then operation data.
    return b"\x5a\x7f\x31\x00\x01\x34\x12\x03\x00ABC"


def _modbus_tcp_adu(pdu: bytes) -> bytes:
    # Modbus/TCP MBAP is network order: transaction, protocol, length, unit.
    return struct.pack("!HHHB", 0xCAFE, 0, 1 + len(pdu), 0x11) + pdu


def _udp_datagram(payload: bytes, *, checksum: int = 0) -> bytes:
    # RFC 768: source, destination, total UDP length, checksum, all network order.
    return struct.pack("!HHHH", 12345, 50000, 8 + len(payload), checksum) + payload


def test_codesys_documented_symbol_and_ini_vectors():
    symbol = codesys.parse_symbol_xml(CODESYS_SYMBOL)
    assert symbol["format"] == "codesys-symbolconfiguration"
    assert symbol["attributes"] == {
        "version": "3.5",
    }
    assert [record["path"] for record in symbol["symbols"]] == [
        "Application",
        "Application.PLC_PRG",
        "Application.PLC_PRG.PumpRun",
    ]
    assert symbol["symbols"][-1]["attributes"] == {
        "name": "PumpRun",
        "type": "T_BOOL",
        "access": "ReadWrite",
        "offset": "12",
    }
    assert symbol["types"][0]["attributes"] == {
        "name": "T_BOOL",
        "size": "1",
        "iecname": "BOOL",
    }

    config = codesys.parse_runtime_config(CODESYS_INI)
    assert config["sections"] == [
        {"name": "CmpApp", "line": 2},
        {"name": "SysFileMap", "line": 5},
    ]
    assert config["entries"] == [
        {"section": "CmpApp", "key": "Application.1", "value": "WaterPlant", "line": 3},
        {
            "section": "CmpApp",
            "key": "Application.1",
            "value": "Standby ; literal semicolon",
            "line": 4,
        },
        {
            "section": "SysFileMap",
            "key": "File.1",
            "value": "/plc/app;/plc/app",
            "line": 6,
        },
    ]


def test_codesys_opaque_hash_and_string_offsets_use_independent_oracles():
    payload = b"\x7fELF\x00Application.PLC_PRG.PumpRun\x00offline-evidence"
    report = codesys.analyze_bytes(payload, name="WaterPlant.app")
    assert report["sha256"] == hashlib.sha256(payload).hexdigest()
    assert report["signature"] == "elf"
    assert report["role_hint"] == "boot-application"
    assert report["symbol_candidates"] == [
        {
            "value": "Application.PLC_PRG.PumpRun",
            "string_offset": 5,
            "encoding": "ascii",
            "evidence": "printable-string-only",
        }
    ]


def test_codesys_public_byte_parsers_fail_closed_on_required_mutations():
    rng = random.Random(0xC0DE_2026)
    damaged_symbol = bytearray(CODESYS_SYMBOL)
    damaged_symbol[CODESYS_SYMBOL.index(b"NodeList") + 1] ^= 0x20
    _only_declared(
        codesys.parse_symbol_xml,
        codesys.CodesysError,
        [
            ("empty", b""),
            ("random", rng.randbytes(97)),
            ("truncated-valid", CODESYS_SYMBOL[:-23]),
            ("bit-flipped", bytes(damaged_symbol)),
            ("oversized", bytes(codesys.MAX_XML + 1)),
        ],
    )
    _only_declared(
        codesys.parse_runtime_config,
        codesys.CodesysError,
        [
            ("empty", b""),
            ("random", rng.randbytes(89)),
            ("truncated-valid", CODESYS_INI[:-7]),
            ("bit-flipped", b"{" + CODESYS_INI[4:]),
            ("oversized", b"A" * (codesys.MAX_XML + 1)),
        ],
    )
    opaque = b"MZ\x00Application.PLC_PRG.PumpRun\x00"
    flipped = bytearray(opaque)
    flipped[0] ^= 1
    _only_declared(
        codesys.analyze_bytes,
        codesys.CodesysError,
        [
            ("empty", b""),
            ("random", rng.randbytes(111)),
            ("truncated-valid", opaque[:-1]),
            ("bit-flipped", bytes(flipped)),
            ("oversized", bytes(codesys.MAX_INPUT + 1)),
        ],
    )


def test_schneider_apx_zip_and_umas_vectors():
    payload = b"PumpRun\x00CSCTF{native_fixture}\x00"
    apx = _apx_vector(payload)
    parsed = schneider.parse_apx(apx)
    assert parsed["header"] == {
        "raw_hex": apx[:32].hex(),
        "version_raw": 0x0100,
        "rte_type": 2,
        "rte_size": 16,
    }
    assert len(parsed["sections"]) == 1
    section = parsed["sections"][0]
    assert section["offset"] == 32
    assert section["number"] == 0x1234
    assert section["memory_offset_raw"] == 0x10203040
    assert section["declared_data_size"] == len(payload)
    assert section["data_offset"] == 64
    assert section["crc_raw"] == 0xBEEF
    assert section["memory_byte_raw"] == 0x7A
    assert section["sha256"] == hashlib.sha256(payload).hexdigest()

    archive = _zip_vector("BinAppli/Station.apx", apx)
    inventory = schneider.parse_archive(archive, name="WaterPlant.sta")
    assert inventory["sha256"] == hashlib.sha256(archive).hexdigest()
    assert inventory["container_hint"] == "sta"
    assert inventory["entries"][0]["kind"] == "apx"
    assert inventory["entries"][0]["decoded"]["sections"][0]["number"] == 0x1234

    pdu = _umas_download_pdu()
    request = schneider.decode_umas(pdu, direction="request")
    assert request["session"] == 0x7F
    assert request["function"] == 0x31
    assert request["operation"] == "download_packet"
    assert request["fields"] == {
        "marker_hex": "0001",
        "block_number": 0x1234,
        "block_size": 3,
        "data_hex": "414243",
    }
    tcp = schneider.decode_umas(
        _modbus_tcp_adu(pdu), direction="request", framing="tcp"
    )
    assert tcp["mbap"] == {
        "transaction_id": 0xCAFE,
        "protocol_id": 0,
        "length": 1 + len(pdu),
        "unit_id": 0x11,
    }
    assert tcp["fields"] == request["fields"]


def test_schneider_public_byte_parsers_fail_closed_on_required_mutations():
    rng = random.Random(0x5A31_2026)
    apx = _apx_vector(b"KNOWN")
    bad_apx = bytearray(apx)
    bad_apx[0] ^= 1
    _only_declared(
        schneider.parse_apx,
        schneider.SchneiderError,
        [
            ("empty", b""),
            ("random", rng.randbytes(71)),
            ("truncated-valid", apx[:-1]),
            ("bit-flipped", bytes(bad_apx)),
            ("oversized", bytes(schneider.MAX_INPUT + 1)),
        ],
    )

    archive = _zip_vector("BinAppli/Station.apx", apx)
    bad_archive = bytearray(archive)
    bad_archive[bad_archive.index(b"APX\0")] ^= 1
    _only_declared(
        schneider.parse_archive,
        schneider.SchneiderError,
        [
            ("empty", b""),
            ("random", rng.randbytes(83)),
            ("truncated-valid", archive[:-1]),
            ("bit-flipped", bytes(bad_archive)),
            ("oversized", bytes(schneider.MAX_INPUT + 1)),
        ],
    )

    pdu = _umas_download_pdu()
    bad_pdu = bytearray(pdu)
    bad_pdu[0] ^= 1
    _only_declared(
        lambda data: schneider.decode_umas(data, direction="request"),
        schneider.SchneiderError,
        [
            ("empty", b""),
            ("random", rng.randbytes(29)),
            ("truncated-valid", pdu[:-1]),
            ("bit-flipped", bytes(bad_pdu)),
            ("oversized", bytes(schneider.MAX_PDU + 1)),
        ],
    )
    adu = _modbus_tcp_adu(pdu)
    _only_declared(
        lambda data: schneider.decode_umas(
            data, direction="request", framing="tcp"
        ),
        schneider.SchneiderError,
        [
            ("truncated-tcp", adu[:-1]),
            ("bit-flipped-length", adu[:5] + bytes([adu[5] ^ 1]) + adu[6:]),
        ],
    )


def test_siprotec_published_payload_and_rfc768_datagram_vector():
    # ESET Figure 20 is exactly 18 bytes: 11 49, fourteen zeroes, 28 9e.
    assert len(SIPROTEC_FIGURE20) == 18
    payload = siprotec.detect_payload(
        SIPROTEC_FIGURE20, destination_port=50000, transport="udp"
    )
    assert payload is not None
    assert payload["rule_id"] == "industroyer_siprotec_cve_2015_5374"
    assert payload["cve"] == "CVE-2015-5374"
    assert payload["evidence"] == "documented_udp_flow"
    assert payload["payload_length"] == 18

    # A nonzero checksum remains unverified without the IP pseudo-header.
    datagram = _udp_datagram(SIPROTEC_FIGURE20, checksum=0xBEEF)
    result = siprotec.detect_udp_datagram(datagram)
    assert result is not None
    assert result["source_port"] == 12345
    assert result["destination_port"] == 50000
    assert result["udp_length"] == 26
    assert result["checksum_verified"] is False


def test_siprotec_public_detectors_fail_closed_on_required_mutations():
    rng = random.Random(0x2015_5374)
    flipped_payload = bytearray(SIPROTEC_FIGURE20)
    flipped_payload[9] ^= 1
    _only_declared(
        siprotec.detect_payload,
        siprotec.SiprotecError,
        [
            ("empty", b""),
            ("random", rng.randbytes(53)),
            ("truncated-valid", SIPROTEC_FIGURE20[:-1]),
            ("bit-flipped", bytes(flipped_payload)),
            ("oversized", bytes(siprotec.MAX_PAYLOAD + 1)),
        ],
    )

    datagram = _udp_datagram(SIPROTEC_FIGURE20)
    flipped_datagram = bytearray(datagram)
    flipped_datagram[5] ^= 1
    _only_declared(
        siprotec.detect_udp_datagram,
        siprotec.SiprotecError,
        [
            ("empty", b""),
            ("random", rng.randbytes(47)),
            ("truncated-valid", datagram[:-1]),
            ("bit-flipped", bytes(flipped_datagram)),
            ("oversized", bytes(siprotec.MAX_DATAGRAM + 1)),
        ],
    )
