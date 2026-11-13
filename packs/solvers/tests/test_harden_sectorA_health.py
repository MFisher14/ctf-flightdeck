"""Independent vector locks and fail-closed fuzz for sector-A health parsers.

The valid artifacts in this file do not come from the engines under test:

* DICOM uses pydicom's bundled ``CT_small.dcm`` and pydicom as the oracle.
* HL7 uses the ADT example published in the hl7apy parsing tutorial.
* FHIR uses RFC 4648 Base64 and the R4 SampledData transform.
* ISHNE is packed from the published 1.0 fixed-header layout and a separately
  implemented CRC-16/IBM-3740 routine.
* SCP-ECG is packed from the published section grammar and checked with the
  independent crccheck implementation of CRC-16/IBM-3740.
"""

from __future__ import annotations

import base64
import json
import random
import struct
from decimal import Decimal
from pathlib import Path

import pydicom
import pytest
from crccheck.crc import Crc16Ibm3740
from hl7apy.parser import parse_message

import health2_dicom as dicom
import health2_fhir as fhir
import health2_hl7 as hl7
import health2_ishne as ishne
import health2_scp as scp


HL7APY_ADT = (
    "MSH|^~\\&|GHH_ADT||||20080115153000||ADT^A01^ADT_A01|0123456789|P|2.5||||AL\r"
    "EVN||20080115153000||AAA|AAA|20080114003000\r"
    "PID|1||566-554-3423^^^GHH^MR||EVERYMAN^ADAM^A|||M|||"
    "2222 HOME STREET^^ANN ARBOR^MI^^USA||555-555-2004~444-333-222|||M\r"
    "NK1|1|NUCLEAR^NELDA^W|SPO|2222 HOME STREET^^ANN ARBOR^MI^^USA\r"
    "PV1|1|I|GHH PATIENT WARD|U||||^SENDER^SAM^^MD|^PUMP^PATRICK^P|CAR||||2|A0|"
    "||||||||||||||||||||||||||||2008\r"
    "IN1|1|HCID-GL^GLOBAL|HCID-23432|HC PAYOR, INC.|"
    "5555 INSURERS CIRCLE^^ANN ARBOR^MI^99999^USA|||||||||||||||||||||||||||||||"
    "|||||||||444-33-3333"
)


def _only_declared(call, label, value, declared_error):
    """Accept a clean result or the one parser-specific exception, nothing else."""
    try:
        call(value)
    except declared_error:
        return
    except BaseException as exc:  # includes accidental SystemExit from library code
        pytest.fail(
            f"{label} leaked {type(exc).__name__}, expected only "
            f"{declared_error.__name__}: {exc}"
        )


def _flip(data: bytes, offset: int) -> bytes:
    changed = bytearray(data)
    changed[offset] ^= 0x80
    return bytes(changed)


def _binary_fuzz(call, valid: bytes, declared_error, *, limit: int, seed: int, flip: int):
    """Exercise the five required malformed-input classes without retaining 64 MiB blobs."""
    rng = random.Random(seed)
    _only_declared(call, "empty", b"", declared_error)
    _only_declared(call, "deterministic random", rng.randbytes(607), declared_error)
    _only_declared(call, "truncated-valid tail", valid[:-1], declared_error)
    _only_declared(call, "truncated-valid midpoint", valid[: len(valid) // 2], declared_error)
    _only_declared(call, "bit-flipped", _flip(valid, flip), declared_error)
    oversized = bytes(limit + 1)
    _only_declared(call, "oversized", oversized, declared_error)


def _dicom_fixture() -> tuple[Path, bytes]:
    path = Path(pydicom.__file__).parent / "data" / "test_files" / "CT_small.dcm"
    assert path.is_file(), "the pydicom wheel must contain its published CT_small fixture"
    return path, path.read_bytes()


def _crc16_reference(data: bytes) -> int:
    """Bitwise CRC-16/IBM-3740, independent of binascii and both ECG engines."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ (0x1021 if crc & 0x8000 else 0)) & 0xFFFF
    return crc


def _ishne_fixture() -> bytes:
    comments = b"published-layout-vector\0"
    # Bytes 10..521 follow Table 3 field order in the ISHNE 1.0 specification.
    header = struct.pack("<4ih", len(comments), 4, 522, 522 + len(comments), 1)
    header += b"Ada".ljust(40, b"\0")
    header += b"Lovelace".ljust(40, b"\0")
    header += b"P001".ljust(20, b"\0")
    header += struct.pack("<2h", 2, 0)
    header += struct.pack(
        "<12h", 10, 12, 1815, 5, 11, 2026, 5, 11, 2026, 12, 30, 45
    )
    header += struct.pack("<h", 2)
    header += struct.pack("<12h", 5, 6, *([-9] * 10))
    header += struct.pack("<12h", 1, 1, *([-9] * 10))
    header += struct.pack("<12h", 1000, 2500, *([-9] * 10))
    header += struct.pack("<h", 0)
    header += b"digital".ljust(40, b"\0")
    header += struct.pack("<h", 500)
    header += b"proprietary".ljust(80, b"\0")
    header += b"copyright".ljust(80, b"\0")
    header += bytes(88)
    assert len(header) == 512
    checked = header + comments
    # Four literal multiplexed frames: I then II in each frame.
    waveform = struct.pack("<8h", 0, 100, -1, -100, 32767, -32768, 7, 9)
    return b"ISHNE1.0" + struct.pack("<H", _crc16_reference(checked)) + checked + waveform


def _scp_section(section_id: int, payload: bytes, protocol: int = 20) -> bytes:
    payload += bytes(len(payload) % 2)
    body = struct.pack(
        "<HIBB6s",
        section_id,
        16 + len(payload),
        20,
        protocol,
        b"SCPECG" if section_id == 0 else bytes(6),
    ) + payload
    return struct.pack("<H", Crc16Ibm3740.calc(body)) + body


def _scp_fixture() -> bytes:
    comment = b"published difference vector\0"
    patient = b"\x02\x06\x00P0001\x00"
    patient += struct.pack("<BH", 30, len(comment)) + comment + b"\xff\x00\x00"
    lead_definitions = b"\x02\x00" + struct.pack("<IIBIIB", 1, 5, 1, 3, 5, 2)
    # For x=(10,12,15,19,24), second differences after the two raw seeds are 1,1,1.
    # For x=(-5,-3,-4), the final second difference is -3.
    encoded = (10, 12, 1, 1, 1, -5, -3, -3)
    rhythm = struct.pack("<HHBBHH8h", 1000, 2000, 2, 0, 10, 6, *encoded)
    sections = {
        1: _scp_section(1, patient),
        3: _scp_section(3, lead_definitions),
        6: _scp_section(6, rhythm),
    }

    next_offset = 6 + 136  # record prefix plus section 0 (16 + 12*10 bytes)
    pointers = struct.pack("<HII", 0, 136, 7)
    for section_id in range(1, 12):
        section = sections.get(section_id)
        if section is None:
            pointers += struct.pack("<HII", section_id, 0, 0)
        else:
            pointers += struct.pack("<HII", section_id, len(section), next_offset + 1)
            next_offset += len(section)
    body = _scp_section(0, pointers)
    body += b"".join(sections[section_id] for section_id in sorted(sections))
    length_and_sections = struct.pack("<I", len(body) + 6) + body
    return struct.pack("<H", Crc16Ibm3740.calc(length_and_sections)) + length_and_sections


def test_dicom_vector_lock_against_pydicom():
    path, raw = _dicom_fixture()
    oracle = pydicom.dcmread(path)
    observed = dicom.inspect_dicom(raw, decode_pixels=True)

    assert observed["transfer_syntax"] == str(oracle.file_meta.TransferSyntaxUID)
    assert observed["pixels"]["rows"] == oracle.Rows
    assert observed["pixels"]["columns"] == oracle.Columns
    assert observed["pixels"]["decoded"].tolist() == oracle.pixel_array.tolist()
    patient = next(item for item in observed["elements"] if item["keyword"] == "PatientName")
    assert patient["value"] == str(oracle.PatientName)

    dictionary_oracle = pydicom.datadict.get_entry(0x00100010)
    assert dicom.lookup_tag(0x00100010) == dict(
        zip(("vr", "vm", "name", "retired", "keyword"), dictionary_oracle)
    )


def test_dicom_fail_closed_fuzz():
    _, valid = _dicom_fixture()
    _binary_fuzz(
        dicom.inspect_dicom,
        valid,
        dicom.Health2DicomError,
        limit=dicom.MAX_BYTES,
        seed=0xD1C0,
        flip=128,
    )
    _only_declared(dicom.lookup_tag, "malformed dictionary tag", object(), dicom.Health2DicomError)


def test_hl7_vector_lock_against_hl7apy():
    oracle = parse_message(HL7APY_ADT, find_groups=False)
    observed = hl7.parse_hl7(HL7APY_ADT)["messages"][0]

    assert observed["message_type"] == oracle.msh.msh_9.to_er7()
    assert observed["control_id"] == oracle.msh.msh_10.value
    assert observed["version"] == oracle.msh.msh_12.value
    assert [item["id"] for item in observed["segments"]] == [
        item.name for item in oracle.children
    ]
    patient = next(item for item in observed["segments"] if item["id"] == "PID")
    assert patient["fields"][4]["raw"] == oracle.pid.pid_5.to_er7()
    oracle_pid_13 = "~".join(
        item.to_er7() for item in oracle.pid.children if item.name == "PID_13"
    )
    assert patient["fields"][12]["raw"] == oracle_pid_13

    definition = hl7.field_definition("PID", 5, "2.5")
    library_entry = __import__("hl7apy").load_library("2.5").FIELDS["PID_5"]
    assert definition == {
        "name": library_entry[3],
        "datatype": library_entry[2],
        "table": library_entry[4],
    }


def test_hl7_fail_closed_fuzz():
    valid = HL7APY_ADT.encode("ascii")
    _binary_fuzz(
        hl7.parse_hl7,
        valid,
        hl7.HL7Error,
        limit=hl7.MAX_BYTES,
        seed=0x117,
        flip=0,
    )
    for value in (("PI", 5), ("PID", 0), (object(), 1), ("PID", 5, object())):
        _only_declared(
            lambda item: hl7.field_definition(*item),
            "malformed dictionary request",
            value,
            hl7.HL7Error,
        )


def test_fhir_vector_lock_rfc4648_and_r4_sampled_data():
    # RFC 4648 section 10 test vector.
    assert fhir.decode_base64("Zm9vYmFy") == b"foobar"

    sampled = {
        "origin": {"value": 2048, "unit": "uV"},
        "period": 10,
        "factor": 1.612,
        "dimensions": 1,
        "data": "2041 2043 2037 2047 2060 2062",
    }
    expected = [
        float(Decimal(value) * Decimal("1.612") + Decimal(2048))
        for value in (2041, 2043, 2037, 2047, 2060, 2062)
    ]
    decoded = fhir.decode_sampled_data(sampled)
    assert [row[0] for row in decoded["rows"]] == pytest.approx(expected)
    assert decoded["period_ms"] == 10

    resource = {
        "resourceType": "Observation",
        "id": "ecg",
        "valueSampledData": sampled,
        "presentedForm": [
            {
                "contentType": "text/plain",
                "data": base64.b64encode(b"foobar").decode("ascii"),
                "size": 6,
            }
        ],
    }
    report = fhir.parse_fhir(json.dumps(resource, separators=(",", ":")).encode("utf-8"))
    assert report["blobs"][0]["data"] == b"foobar"
    assert [row[0] for row in report["sampled_data"][0]["rows"]] == pytest.approx(expected)


def test_fhir_fail_closed_fuzz():
    valid = b'{"resourceType":"Patient","id":"published-vector"}'
    _binary_fuzz(
        fhir.parse_fhir,
        valid,
        fhir.FHIRFormatError,
        limit=fhir.MAX_INPUT,
        seed=0xF417,
        flip=0,
    )

    base64_cases = (
        ("empty", ""),
        ("deterministic random", random.Random(0xB64).randbytes(31)),
        ("truncated-valid", "Zm9vYmF"),
        ("bit-flipped", "Zm9v!mFy"),
    )
    for label, value in base64_cases:
        _only_declared(fhir.decode_base64, label, value, fhir.FHIRFormatError)
    _only_declared(
        fhir.decode_base64,
        "oversized",
        "A" * (fhir.MAX_INPUT + 1),
        fhir.FHIRFormatError,
    )

    valid_sampled = {
        "origin": {"value": 0},
        "period": 1,
        "dimensions": 2,
        "data": "1 2",
    }
    sampled_cases = (
        ("empty", {}),
        ("deterministic random", {"origin": random.Random(0x5A).randbytes(7)}),
        ("truncated-valid", {key: value for key, value in valid_sampled.items() if key != "origin"}),
        ("bit-flipped", {**valid_sampled, "data": "1 !"}),
    )
    for label, value in sampled_cases:
        _only_declared(fhir.decode_sampled_data, label, value, fhir.FHIRFormatError)
    _only_declared(
        fhir.decode_sampled_data,
        "oversized",
        {**valid_sampled, "data": "0" * (fhir.MAX_INPUT + 1)},
        fhir.FHIRFormatError,
    )


def test_ishne_vector_lock_published_layout():
    assert _crc16_reference(b"123456789") == 0x29B1
    observed = ishne.parse_ishne(_ishne_fixture())

    assert observed["format"] == "ISHNE1.0"
    assert observed["metadata"]["first_name"] == "Ada"
    assert observed["metadata"]["last_name"] == "Lovelace"
    assert observed["metadata"]["record_date"] == "2026-11-05"
    assert observed["metadata"]["start_time"] == "12:30:45"
    assert observed["sample_rate_hz"] == 500
    assert observed["samples_per_lead"] == 4
    assert observed["leads"][0]["name"] == "I"
    assert observed["leads"][0]["resolution_nv"] == 1000
    assert observed["leads"][0]["samples"] == [0, -1, 32767, 7]
    assert observed["leads"][1]["name"] == "II"
    assert observed["leads"][1]["resolution_nv"] == 2500
    assert observed["leads"][1]["samples"] == [100, -100, -32768, 9]


def test_ishne_fail_closed_fuzz_and_reader(tmp_path):
    valid = _ishne_fixture()
    _binary_fuzz(
        ishne.parse_ishne,
        valid,
        ishne.IshneError,
        limit=ishne.MAX_FILE,
        seed=0x15A1,
        flip=0,
    )
    path = tmp_path / "valid.ecg"
    path.write_bytes(valid)
    assert ishne.read_ishne(path)["leads"][1]["samples"] == [100, -100, -32768, 9]
    for bad_path in (tmp_path / "missing.ecg", tmp_path):
        _only_declared(ishne.read_ishne, "invalid path", bad_path, ishne.IshneError)


def test_scp_vector_lock_published_second_difference():
    observed = scp.parse_scp(_scp_fixture())

    assert observed["format"] == "SCP-ECG v1/v2 raw16"
    assert observed["resolution_nv"] == 1000
    assert observed["sample_interval_us"] == 2000
    assert observed["sample_rate_hz"] == 500
    assert observed["difference_order"] == 2
    assert observed["leads"][0]["samples"] == [10, 12, 15, 19, 24]
    assert observed["leads"][1]["samples"] == [-5, -3, -4]
    assert observed["patient_fields"][0]["text"] == "P0001"


def test_scp_fail_closed_fuzz_and_reader(tmp_path):
    valid = _scp_fixture()
    _binary_fuzz(
        scp.parse_scp,
        valid,
        scp.ScpError,
        limit=scp.MAX_FILE,
        seed=0x5C9,
        flip=0,
    )
    path = tmp_path / "valid.scp"
    path.write_bytes(valid)
    assert scp.read_scp(path)["leads"][0]["samples"] == [10, 12, 15, 19, 24]
    for bad_path in (tmp_path / "missing.scp", tmp_path):
        _only_declared(scp.read_scp, "invalid path", bad_path, scp.ScpError)
