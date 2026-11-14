"""Deterministic synthetic coverage for every r5f deep ICS payload dissector."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))

import ics_protocols as ics  # noqa: E402


def modbus_tcp(transaction: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", transaction, 0, len(pdu) + 1, unit) + pdu


def dnp3_frame(user: bytes, control: int = 0xC4, destination: int = 1, source: int = 2) -> bytes:
    length = 5 + len(user)
    header = b"\x05\x64" + bytes([length, control]) + struct.pack("<HH", destination, source)
    encoded = header + struct.pack("<H", ics.crc16_dnp3(header))
    for offset in range(0, len(user), 16):
        block = user[offset : offset + 16]
        encoded += block + struct.pack("<H", ics.crc16_dnp3(block))
    return encoded


def s7_tpkt(rosctr: int, parameter: bytes, data: bytes = b"", reference: int = 0x1234) -> bytes:
    header = (
        bytes([0x32, rosctr])
        + b"\x00\x00"
        + struct.pack(">H", reference)
        + struct.pack(">HH", len(parameter), len(data))
    )
    if rosctr in (2, 3):
        header += b"\x00\x00"
    s7 = header + parameter + data
    return b"\x03\x00" + struct.pack(">H", 7 + len(s7)) + b"\x02\xf0\x80" + s7


def bvlc(npdu_apdu: bytes, function: int = 0x0B) -> bytes:
    return b"\x81" + bytes([function]) + struct.pack(">H", 4 + len(npdu_apdu)) + npdu_apdu


def enip(command: int, payload: bytes, session: int = 0x11223344) -> bytes:
    return (
        struct.pack("<HHII", command, len(payload), session, 0)
        + b"CTXBYTES"
        + struct.pack("<I", 0)
        + payload
    )


def iec104_i(asdu: bytes, send: int = 0, receive: int = 0) -> bytes:
    control = struct.pack("<HH", send << 1, receive << 1)
    return b"\x68" + bytes([4 + len(asdu)]) + control + asdu


def test_modbus_tcp_rtu_and_deep_functions() -> None:
    write = modbus_tcp(7, 3, b"\x10\x00\x20\x00\x02\x04\x12\x34\x56\x78")
    report = ics.parse_modbus(write, direction="request")
    assert report["transaction_id"] == 7
    assert report["pdu"]["registers"] == [0x1234, 0x5678]
    assert report["pdu"]["findings"][0]["kind"] == "register-write"

    device_id = modbus_tcp(
        8,
        3,
        b"\x2b\x0e\x01\x01\x00\x00\x02\x00\x06Vendor\x01\x05Model",
    )
    identified = ics.parse_modbus(device_id, direction="response")
    assert [row["value"] for row in identified["pdu"]["objects"]] == ["Vendor", "Model"]

    pdu = b"\x08\x00\x04\x00\x00"
    rtu_body = b"\x01" + pdu
    rtu = rtu_body + struct.pack("<H", ics.crc16_modbus(rtu_body))
    diagnostic = ics.parse_modbus(rtu, transport="rtu", direction="request")
    assert diagnostic["crc_valid"]
    assert diagnostic["pdu"]["subfunction_name"] == "Force Listen Only Mode"
    with pytest.raises(ics.ParseError, match="CRC"):
        ics.parse_modbus(rtu[:-1] + bytes([rtu[-1] ^ 1]), transport="rtu")


def test_modbus_rejects_inner_count_mismatches_and_trailing_bytes() -> None:
    bad_quantity = modbus_tcp(1, 1, b"\x10\x00\x20\x00\x02\x02\x12\x34")
    with pytest.raises(ics.ParseError, match="quantity/byte-count"):
        ics.parse_modbus(bad_quantity, direction="request")
    trailing_registers = modbus_tcp(2, 1, b"\x03\x02\x00\x2aJUNK")
    with pytest.raises(ics.ParseError, match="length mismatch"):
        ics.parse_modbus(trailing_registers, direction="response")
    trailing_bits = modbus_tcp(3, 1, b"\x01\x01\x01JUNK")
    with pytest.raises(ics.ParseError, match="length mismatch"):
        ics.parse_modbus(trailing_bits, direction="response")


def test_dnp3_transport_objects_crc_and_control_finding() -> None:
    crob = b"\x41\x02" + struct.pack("<II", 1000, 250) + b"\x00"
    objects = b"\x0c\x01\x17\x01\x07" + crob
    user = b"\xc5\xc2\x04" + objects
    frame = dnp3_frame(user)
    report = ics.parse_dnp3(frame)
    assert report["transport"]["final"] is True
    assert report["transport"]["first"] is True
    assert report["transport"]["sequence"] == 5
    assert report["application"]["function_name"] == "OPERATE"
    point = report["application"]["objects"][0]["points"][0]
    assert point["index"] == 7
    assert point["on_time_ms"] == 1000
    assert report["findings"][0]["severity"] == "critical"
    assert ics.crc16_dnp3(b"123456789") == 0xEA82
    with pytest.raises(ics.ParseError, match="CRC"):
        ics.parse_dnp3(frame[:-1] + bytes([frame[-1] ^ 1]))


def test_dnp3_packed_binary_and_fragment_api() -> None:
    # Group 1 variation 1 uses one packed bit per requested point.
    objects = b"\x01\x01\x00\x02\x09\x2d"  # qualifier 00, start 2, stop 9, packed 00101101
    parsed = ics.parse_dnp3_application(b"\xc1\x81\x00\x00" + objects)
    points = parsed["application"]["objects"][0]["points"]
    assert [point["index"] for point in points] == list(range(2, 10))
    assert [point["state"] for point in points] == [True, False, True, True, False, True, False, False]

    application = b"\xc1\x01\x3c\x02\x06"
    first = ics.parse_dnp3(dnp3_frame(b"\x40" + application[:2]))
    last = ics.parse_dnp3(dnp3_frame(b"\x81" + application[2:]))
    assert first["fragmented_application"] and last["fragmented_application"]
    assert bytes.fromhex(first["transport"]["fragment"]) + bytes.fromhex(last["transport"]["fragment"]) == application

    read_range = ics.parse_dnp3_application(b"\xc2\x01\x1e\x01\x00\x05\x07")
    requested = read_range["application"]["objects"][0]
    assert requested["group_name"] == "Analog Input"
    assert requested["requested_indices"] == [5, 6, 7]

    start_count = ics.parse_dnp3_application(b"\xc3\x81\x00\x00\x01\x02\x03\x02\x02\x81\x01")
    assert [row["index"] for row in start_count["application"]["objects"][0]["points"]] == [2, 3]

    command = b"\x29\x03\x17\x01\x05" + struct.pack("<fB", 1.5, 2)
    analog = ics.parse_dnp3_application(b"\xc4\x04" + command)
    point = analog["application"]["objects"][0]["points"][0]
    assert point["value"] == pytest.approx(1.5)
    assert point["status"] == 2


def test_s7_write_var_userdata_szl_and_plus() -> None:
    varspec = b"\x12\x0a\x10\x02\x00\x01\x00\x01\x84\x00\x00\x10"
    parameter = b"\x05\x01" + varspec
    data = b"\x00\x04\x00\x08A"
    report = ics.parse_s7comm(s7_tpkt(1, parameter, data))
    assert report["s7"]["variables"][0]["area_name"] == "Data Blocks"
    assert report["s7"]["variables"][0]["byte_address"] == 2
    assert report["s7"]["data_items"][0]["value"] == "41"
    assert report["findings"][0]["kind"] == "s7-write"

    user_parameter = b"\x00\x01\x12\x04\x11\x44\x01\x02"
    element = b"CSCTF{szl}"
    szl_payload = b"\x00\x11\x00\x01" + struct.pack(">HH", len(element), 1) + element
    user_data = b"\xff\x09" + struct.pack(">H", len(szl_payload)) + szl_payload
    userdata_report = ics.parse_s7comm(s7_tpkt(7, user_parameter, user_data))
    user = userdata_report["s7"]["userdata"]
    assert user["function_group_name"] == "CPU"
    assert user["szl_id"] == 0x11
    assert user["szl_elements"][0]["flags"] == ["CSCTF{szl}"]

    plus_payload = b"\x72\x01\x31hello"
    plus = b"\x03\x00" + struct.pack(">H", 7 + len(plus_payload)) + b"\x02\xf0\x80" + plus_payload
    assert ics.parse_s7comm(plus)["variant"] == "s7comm-plus"


def test_s7_exact_lengths_userdata_and_cotp_segmentation() -> None:
    frame = s7_tpkt(1, b"\xf0\x00\x00\x01\x00\x01\x01\xe0")
    with_trailing = frame[:2] + struct.pack(">H", len(frame) + 1) + frame[4:] + b"X"
    with pytest.raises(ics.ParseError, match="exactly match"):
        ics.parse_s7comm(with_trailing)

    parameter = b"\x00\x01\x12\x04\x11\x44\x01\x02"
    truncated_inner = s7_tpkt(7, parameter, b"\xff\x09\x00\x20AB")
    with pytest.raises(ics.ParseError, match="userdata payload"):
        ics.parse_s7comm(truncated_inner)

    not_eot = frame[:6] + b"\x00" + frame[7:]
    segmented = ics.parse_s7comm(not_eot)
    assert segmented["segmented"] is True
    assert bytes.fromhex(segmented["s7_fragment"]) == frame[7:]


def test_bacnet_services_tags_tables_and_control() -> None:
    who_is = bvlc(b"\x01\x00\x10\x08")
    report = ics.parse_bacnet(who_is)
    assert report["bvlc_function_name"] == "Original-Broadcast-NPDU"
    assert report["apdu"]["service_name"] == "who-Is"

    # Confirmed WriteProperty: object-id context 0, property-id context 1, value context 3.
    object_identifier = ((2 << 22) | 9).to_bytes(4, "big")
    tags = b"\x0c" + object_identifier + b"\x19\x55\x3e\x21\x2a\x3f"
    write_property = bvlc(b"\x01\x00" + b"\x00\x05\x01\x0f" + tags, function=0x0A)
    written = ics.parse_bacnet(write_property)
    assert written["apdu"]["service_name"] == "writeProperty"
    assert written["apdu"]["tags"][0]["raw"] == object_identifier.hex()
    assert written["apdu"]["object_identifier"] == {"object_type": 2, "instance": 9}
    assert written["apdu"]["property_name"] == "present-value"
    assert written["findings"][0]["severity"] == "high"

    bdt_body = bytes([10, 0, 0, 1]) + struct.pack(">H", 47808) + bytes([255, 255, 255, 0])
    bdt = b"\x81\x03" + struct.pack(">H", 4 + len(bdt_body)) + bdt_body
    assert ics.parse_bacnet(bdt)["bdt"][0]["address"] == "10.0.0.1:47808"
    ack = ics.parse_bacnet(bvlc(b"\x01\x00\x20\x01\x0c", function=0x0A))
    assert ack["apdu"]["service_name"] == "readProperty"
    secure = b"\x81\x0c\x00\x0cCSCTF{x}"
    assert ics.parse_bacnet(secure)["flags"] == ["CSCTF{x}"]


def test_enip_cpf_cip_paths_nested_services_and_writes() -> None:
    symbol = b"\x91\x03ABC\x00"
    cip = b"\x4d\x03" + symbol + b"\xc4\x00\x01\x00CSCTF{cip}"
    cpf = (
        struct.pack("<IHH", 0, 0, 2)
        + struct.pack("<HH", 0, 0)
        + struct.pack("<HH", 0x00B2, len(cip))
        + cip
    )
    report = ics.parse_enip(enip(0x006F, cpf))
    decoded = report["items"][1]["cip"]
    assert decoded["path"][0] == {"type": "symbol", "value": "ABC"}
    assert decoded["element_count"] == 1
    assert decoded["flags"] == ["CSCTF{cip}"]
    assert report["findings"][0]["kind"] == "cip-control"

    get_identity = b"\x0e\x03\x20\x01\x24\x01\x30\x07"
    routed = ics.parse_cip(get_identity)
    assert [row["type"] for row in routed["path"]] == ["class", "instance", "attribute"]
    assert routed["path"][0]["name"] == "Identity"

    unconnected = (
        b"\x52\x02\x20\x06\x24\x01"
        + b"\x0a\x05"
        + struct.pack("<H", len(get_identity))
        + get_identity
        + b"\x01\x00\x01\x00"
    )
    uc = ics.parse_cip(unconnected)
    assert uc["embedded_request"]["service_name"] == "Get_Attribute_Single"
    assert uc["route_path"][0]["type"] == "port"
    assert uc["route_path"][0]["link"] == "00"

    response_a, response_b = b"\x8e\x00\x00\x00A", b"\x8e\x00\x00\x00B"
    multiple_payload = struct.pack("<HHH", 2, 6, 6 + len(response_a)) + response_a + response_b
    multiple = ics.parse_cip(b"\x8a\x00\x00\x00" + multiple_payload)
    assert [row["data"] for row in multiple["services"]] == ["41", "42"]


def test_cip_recursion_cpf_exactness_address_items_and_implicit_io() -> None:
    nested = b"\x0e\x02\x20\x01\x24\x01"
    for _ in range(ics.MAX_TAG_DEPTH + 2):
        nested = b"\x0a\x02\x20\x02\x24\x01\x01\x00\x04\x00" + nested
    with pytest.raises(ics.ParseError, match="depth"):
        ics.parse_cip(nested)

    trailing_cpf = struct.pack("<IHH", 0, 0, 0) + b"JUNK"
    with pytest.raises(ics.ParseError, match="trailing"):
        ics.parse_enip(enip(0x006F, trailing_cpf))

    cpf = (
        struct.pack("<IHH", 0, 0, 2)
        + struct.pack("<HHII", 0x8002, 8, 0x11223344, 7)
        + struct.pack("<HH", 0x00B1, 2)
        + b"\x09\x00"
    )
    addressed = ics.parse_enip(enip(0x0070, cpf))
    assert addressed["items"][0]["connection_id"] == 0x11223344
    assert addressed["items"][0]["sequence"] == 7

    implicit = ics.parse_enip_io(struct.pack("<II", 0xAABBCCDD, 9) + b"process-data")
    assert implicit["format"] == "raw-sequenced"
    assert implicit["connection_id"] == 0xAABBCCDD
    cpf_io = struct.pack("<H", 1) + struct.pack("<HHII", 0x8002, 8, 3, 4)
    assert ics.parse_enip_io(cpf_io)["items"][0]["sequence"] == 4


def test_iec104_values_commands_sequences_and_timestamps() -> None:
    asdu = (
        bytes([45, 1, 6, 0])
        + struct.pack("<H", 1)
        + (100).to_bytes(3, "little")
        + b"\x81"
    )
    report = ics.parse_iec104(iec104_i(asdu, send=12, receive=9))
    assert report["send_sequence"] == 12
    assert report["asdu"]["objects"][0]["ioa"] == 100
    assert report["asdu"]["objects"][0]["command"] is True
    assert report["asdu"]["objects"][0]["select"] is True
    assert report["findings"][0]["severity"] == "critical"

    cp56 = struct.pack("<H", 12345) + bytes([34, 12, 7, 11, 26])
    clock_asdu = bytes([103, 1, 6, 0]) + struct.pack("<H", 2) + b"\x00\x00\x00" + cp56
    clock = ics.parse_iec104(iec104_i(clock_asdu))
    assert clock["asdu"]["objects"][0]["time"]["year"] == 2026
    assert clock["asdu"]["objects"][0]["time"]["minute"] == 34

    assert ics.parse_iec104(b"\x68\x04\x01\x00\x0a\x00")["format"] == "S"
    assert ics.parse_iec104(b"\x68\x04\x07\x00\x00\x00")["u_function"] == "STARTDT act"


def test_iec104_cp24_semantics_and_exact_apci_asdu_lengths() -> None:
    cp24 = struct.pack("<H", 12_345) + bytes([0x80 | 22])
    asdu = bytes([2, 1, 3, 0]) + struct.pack("<H", 1) + b"\x07\x00\x00" + b"\x81" + cp24
    point = ics.parse_iec104(iec104_i(asdu))["asdu"]["objects"][0]
    assert point["value"] is True and point["quality"] == 0x80
    assert point["time"] == {
        "milliseconds": 12_345,
        "second": 12,
        "minute": 22,
        "invalid": True,
        "substituted": False,
    }
    with pytest.raises(ics.ParseError, match="U-format"):
        ics.parse_iec104(b"\x68\x05\x07\x00\x00\x00X")
    command = bytes([45, 1, 6, 0]) + struct.pack("<H", 1) + b"\x01\x00\x00\x01"
    command_frame = iec104_i(command)
    command_with_trailing = b"\x68" + bytes([command_frame[1] + 1]) + command_frame[2:] + b"X"
    with pytest.raises(ics.ParseError, match="trailing"):
        ics.parse_iec104(command_with_trailing)


def test_dispatch_bounds_errors_and_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    frame = modbus_tcp(1, 1, b"\x03\x00\x00\x00\x01")
    assert ics.detect_protocol(frame) == "modbus"
    assert ics.dissect(frame, direction="request")["pdu"]["quantity"] == 1
    with pytest.raises(ics.ParseError):
        ics.dissect(b"not-a-protocol")
    with pytest.raises(ics.ParseError, match="length mismatch"):
        ics.parse_iec104(b"\x68\x05\x00\x00\x00\x00")

    artifact = tmp_path / "request.bin"
    artifact.write_bytes(frame)
    assert ics.main([str(artifact), "--direction", "request"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output[0]["analysis"]["transaction_id"] == 1


def test_all_payload_parsers_reject_deterministic_malformed_inputs_cleanly() -> None:
    parsers = [
        ics.parse_modbus,
        ics.parse_dnp3,
        ics.parse_s7comm,
        ics.parse_bacnet,
        ics.parse_enip,
        ics.parse_iec104,
    ]
    for parser_index, parser in enumerate(parsers):
        for length in range(65):
            malformed = bytes(((position * 37 + length * 11 + parser_index) & 0xFF) for position in range(length))
            try:
                parser(malformed)
            except (ics.ParseError, ValueError, TypeError):
                pass

