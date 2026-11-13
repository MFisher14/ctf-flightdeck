"""Independent vectors and deterministic malformed-input locks for ics_fieldbus.

Oracle sources (no engine encoder/output is used to create expected values):
* BACnet-stack's NPDU and application-tag encoders, reflecting ASHRAE 135:
  https://github.com/bacnet-stack/bacnet-stack/blob/master/src/bacnet/npdu.c
  https://github.com/bacnet-stack/bacnet-stack/blob/master/src/bacnet/bacdcode.c
* Scapy's independent ENIP and PNIO wire encoders:
  https://scapy.readthedocs.io/en/stable/api/scapy.contrib.enipTCP.html
* Hand-built CIP EPATH/CPF and DCE/RPC fields in specified byte order. Expected
  numbers/strings are fixed before parsing. struct supplies IEEE-754 conversion.

Previously documented bugs now run as ordinary regression assertions.
"""
import inspect
import json
import random
import struct

import pytest
from scapy.all import Ether, IP, UDP, TCP, Raw, wrpcap
from scapy.contrib.enipTCP import ENIPTCP, ENIPRegisterSession
from scapy.contrib.pnio import ProfinetIO
from scapy.contrib.pnio_dcp import ProfinetDCP

import ics_fieldbus as f


FLAG = "CSCTF{fieldbus_vector}"
# Confirmed ReadProperty: max APDU 1476, invoke 42, analog-value:7,
# property present-value (85). Tag bytes are handwritten from the BACnet grammar.
READ_PROPERTY = bytes.fromhex("00052a0c0c008000071955")
# ComplexACK carrying an IEEE-754 REAL of -12.5 in context tag 3.
READ_ACK = bytes.fromhex("302a0c0c0080000719553e44c14800003f")
WHO_IS = bytes.fromhex("100809051928")
CIP_READ = bytes.fromhex("4c0491055370656564000100")
CIP_RESPONSE = bytes.fromhex("cc000000c40078563412")


def _bacnet(apdu, function=0x0A):
    npdu = b"\x01\x00" + apdu
    return bytes((0x81, function)) + struct.pack(">H", len(npdu) + 4) + npdu


def _enip(command, body, session=0x12345678):
    # ENIP v1 header: little endian command/length/session/status, opaque context.
    return struct.pack("<HHII8sI", command, len(body), session, 0, b"context!", 0) + body


def _cpf(cip, connected=False):
    payload = struct.pack("<H", 0x4321) + cip if connected else cip
    tid = 0xB1 if connected else 0xB2
    return struct.pack("<IHHHHHH", 0, 5, 2, 0, 0, tid, len(payload)) + payload


def _rpc_request():
    stub = b"CSCTF{opc_stub}"
    return (bytes.fromhex("0500000310000000")
            + struct.pack("<HHI", 24 + len(stub), 0, 42)
            + struct.pack("<IHH", len(stub), 2, 7) + stub)


def test_bvlc_unicast_forwarding_and_result_vectors():
    wire = _bacnet(WHO_IS)
    got = f.parse_bvlc(wire)
    assert (got["bvlc_type"], got["function_num"], got["length"], got["npdu_offset"]) == (0x81, 10, 12, 4)
    forwarded = bytes.fromhex("8104000e c0000205 bac0 01001008")
    got = f.parse_bvlc(forwarded)
    assert (got["forwarded_from"], got["npdu_offset"]) == ("192.0.2.5:47808", 10)
    got = f.parse_bvlc(bytes.fromhex("810000060030"))
    assert (got["result_code"], got["npdu_offset"]) == (0x30, None)


def test_npdu_routing_fields_at_nonzero_offset():
    # NPDU control 0x2f: DNET/SNET, expecting reply, life-safety priority.
    data = bytes.fromhex("eeee 012f 1234 02 aabb 5678 01 cc 09 1008")
    got = f.parse_npdu(data, 2)
    assert {k: got[k] for k in ("version", "priority", "dnet", "dadr", "snet", "sadr", "hop_count", "apdu_offset")} == {
        "version": 1, "priority": 3, "dnet": 0x1234, "dadr": "aabb",
        "snet": 0x5678, "sadr": "cc", "hop_count": 9, "apdu_offset": 14,
    }
    assert got["expecting_reply"] is True


def test_npdu_vendor_specific_network_header_vector():
    # ASHRAE 135 NPDU: message types >=0x80 add a two-byte big-endian vendor ID.
    got = f.parse_npdu(bytes.fromhex("0180801234"), 0)
    assert (got.get("vendor_id"), got["apdu_offset"]) == (0x1234, 5)


@pytest.mark.parametrize("wire", ["0180", "018080", "01808012"])
def test_npdu_truncated_network_vendor_header(wire):
    with pytest.raises(f._BError):
        f.parse_npdu(bytes.fromhex(wire), 0)


def test_npdu_network_payload_offset_and_standard_message():
    got = f.parse_npdu(bytes.fromhex("eeee0180ff3412aabb"), 2)
    assert (got["vendor_id"], got["apdu_offset"]) == (0x3412, 7)
    got = f.parse_npdu(bytes.fromhex("0180001234"), 0)
    assert got["apdu_offset"] == 3 and "vendor_id" not in got


@pytest.mark.parametrize("wire,app_type,expected", [
    ("00", "Null", None), ("10", "Boolean", False), ("11", "Boolean", True),
    ("220123", "Unsigned", 291), ("32ff80", "Signed", -128),
    ("44c1480000", "Real", -12.5), ("55084029000000000000", "Double", 12.5),
    ("63aabbcc", "OctetString", "aabbcc"), ("9103", "Enumerated", 3),
])
def test_bacnet_application_primitive_vectors(wire, app_type, expected):
    token = f.decode_bacnet_tags(bytes.fromhex(wire))[0]
    assert (token["app_type"], token["value"]) == (app_type, expected)


def test_bacnet_object_identifier_and_extended_character_vector():
    wire = bytes.fromhex("c402003039")
    token = f.decode_bacnet_tags(wire)[0]
    assert token["value"] == {"object_type": "device", "object_type_num": 8, "instance": 12345, "text": "device:12345"}
    # UTF-16BE character string, extended 16-bit length, two encoded codepoints.
    wire = b"\x75\xfe\x00\x05\x04\x00A\x03\xa9"
    token = f.decode_bacnet_tags(wire)[0]
    assert (token["encoding"], token["value"]) == ("utf-16-be", "AΩ")


def test_bacnet_extended_context_tags_and_depth():
    got = f.decode_bacnet_tags(bytes.fromhex("fe203e21073fff20"))
    assert [(t.get("kind"), t["depth"]) for t in got] == [("opening", 0), ("opening", 1), ("primitive", 2), ("closing", 1), ("closing", 0)]
    assert (got[0]["tag_number"], got[-1]["tag_number"], got[2]["value"]) == (32, 32, 7)


@pytest.mark.parametrize("apdu,kind,invoke,service", [
    (READ_PROPERTY, "Confirmed-REQ", 42, "readProperty"),
    (READ_ACK, "ComplexACK", 42, "readProperty"),
    (bytes.fromhex("202a0f"), "SimpleACK", 42, "writeProperty"),
    (bytes.fromhex("502a0c91019120"), "Error-PDU", 42, "readProperty"),
    (bytes.fromhex("600104"), "Reject-PDU", 1, None),
    (bytes.fromhex("710205"), "Abort-PDU", 2, None),
])
def test_apdu_header_vectors(apdu, kind, invoke, service):
    got = f.parse_bacnet_apdu(apdu, 0)
    assert (got["pdu_type"], got["invoke_id"], got.get("service_choice")) == (kind, invoke, service)


def test_apdu_read_property_and_segmented_fields():
    got = f.parse_bacnet_apdu(READ_PROPERTY, 0)
    assert got["service_reading"] == {"object": "analog-value:7", "property": "present-value"}
    got = f.parse_bacnet_apdu(READ_ACK, 0)
    assert got["service_reading"] == {"object": "analog-value:7", "property": "present-value", "value": -12.5}
    got = f.parse_bacnet_apdu(bytes.fromhex("08052a03040c"), 0)
    assert (got["segmented"], got["sequence_number"], got["proposed_window"], got["service_choice_num"]) == (True, 3, 4, 12)


def test_bacnet_report_i_am_who_is_and_string_flag():
    got = f.bacnet_report(_bacnet(WHO_IS, 0x0B))
    assert got["apdu"]["service_reading"]["device_instance_range"] == [5, 40]
    iam = bytes.fromhex("1000c4020001042205c491002163")
    assert f.bacnet_report(_bacnet(iam))["apdu"]["service_reading"] == {"device": "device:260", "max_apdu": 1476, "vendor_id": 99}
    text = b"\0" + FLAG.encode("ascii")
    ack = bytes.fromhex("302a0c0c02000001194d3e") + b"\x75" + bytes([len(text)]) + text + b"\x3f"
    got = f.bacnet_report(_bacnet(ack))
    assert got["apdu"]["service_reading"]["value"] == FLAG
    assert got["flags"] == [FLAG]


def test_cip_logical_symbol_and_response_vectors():
    got = f.parse_cip(bytes.fromhex("0e03200124013007"))
    assert [(p["segment"], p["value"]) for p in got["path"]] == [("class", 1), ("instance", 1), ("attribute", 7)]
    assert got["service_num"] == 14
    got = f.parse_cip(CIP_READ)
    assert (got["service"], got["path"], got["request_data"]) == ("Read_Tag", [{"segment": "symbol", "name": "Speed"}], "0100")
    got = f.parse_cip(CIP_RESPONSE)
    assert (got["direction"], got["general_status_num"], got["response_data"]) == ("response", 0, "c40078563412")
    got = f.parse_cip(bytes.fromhex("8e0005013412"))
    assert (got["general_status_num"], got["additional_status"]) == (5, "3412")


def test_cip_multiple_service_vector():
    one = bytes.fromhex("0e03200124013007")
    two = bytes.fromhex("050220012402")
    table = struct.pack("<HHH", 2, 6, 6 + len(one))
    got = f.parse_cip(bytes.fromhex("0a0220022401") + table + one + two)
    assert [x["service_num"] for x in got["embedded"]] == [14, 5]
    assert got["embedded"][1]["path"][1]["value"] == 2


def test_enip_register_session_against_scapy_encoder():
    # Set length explicitly: the Scapy ENIP layer does not autofill this field.
    packet = ENIPTCP(commandId=0x65, length=4, session=0x12345678) / ENIPRegisterSession(protocolVersion=1, options=2)
    raw = bytes(packet)
    independent = ENIPTCP(raw)
    got = f.parse_enip(raw)
    assert (got["command_num"], got["length"], got["session"]) == (int(independent.commandId), int(independent.length), hex(int(independent.session)))
    assert (got["protocol_version"], got["session_options"]) == (1, 2)


@pytest.mark.parametrize("connected", [False, True])
def test_enip_cpf_keeps_wire_order(connected):
    command = 0x70 if connected else 0x6F
    got = f.parse_enip(_enip(command, _cpf(CIP_RESPONSE, connected)))
    assert (got["command_num"], got["item_count"], got["timeout"]) == (command, 2, 5)
    item = got["items"][1]
    assert item["cip"]["response_data"] == "c40078563412"
    if connected:
        assert item["sequence_count"] == 0x4321


def test_enip_list_identity_vector():
    product = b"CSCTF{identity}"
    sockaddr = struct.pack(">HH4s8s", 2, 44818, bytes([192, 0, 2, 7]), b"\0" * 8)
    identity = (struct.pack("<H", 1) + sockaddr + struct.pack("<HHHBBHI", 123, 12, 7, 3, 8, 4, 0x12345678)
                + bytes([len(product)]) + product + b"\x03")
    got = f.parse_enip(_enip(0x63, struct.pack("<HHH", 1, 0x0C, len(identity)) + identity))
    item = got["items"][0]["identity"]
    assert {k: item[k] for k in ("vendor_id", "device_type", "product_code", "revision", "status", "serial", "socket_addr", "socket_port")} == {
        "vendor_id": 123, "device_type": 12, "product_code": 7, "revision": "3.8", "status": 4,
        "serial": "0x12345678", "socket_addr": "192.0.2.7", "socket_port": 44818}
    assert item["product_name"] == "CSCTF{identity}"


def test_profinet_wrapper_independent_scapy_vector():
    packet = ProfinetIO(frameID=0xFEFE) / ProfinetDCP(service_id=5, service_type=0, xid=0x11223344)
    for got in (f.profinet_report(bytes(packet)), f.profinet_report(pkt=packet)):
        assert got["frame_id_num"] == 0xFEFE
        assert (got["dcp"]["service_id"], got["dcp"]["service_type"], got["dcp"]["xid"]) == ("Identify", "Request", "0x11223344")


def test_opcda_manual_dce_rpc_header_vector():
    got = f.opcda_report(_rpc_request())
    assert (got["version"], got["pdu_type_num"], got["call_id"], got["byte_order"], got["frag_length"]) == ("5.0", 0, "0x2a", "little-endian", 39)
    assert got["flags"] == ["CSCTF{opc_stub}"]


def test_opcda_manual_dce_rpc_request_fields_vector():
    got = f.opcda_report(_rpc_request())
    assert (got.get("op_num"), got.get("context_id"), got.get("alloc_hint")) == (7, 2, 15)


@pytest.mark.parametrize("endian", ["<", ">"])
def test_opcda_request_byte_order_and_packet_object(endian):
    from scapy.contrib.opc_da import OpcDaMessage
    data_repr = b"\x10\0\0\0" if endian == "<" else b"\0\0\0\0"
    wire = (b"\x05\0\0\x03" + data_repr + struct.pack(endian + "HHI", 26, 0, 42)
            + struct.pack(endian + "IHH", 2, 0x1234, 0x5678) + b"AB")
    for got in (f.opcda_report(wire), f.opcda_report(pkt=OpcDaMessage(wire))):
        assert (got.get("alloc_hint"), got.get("context_id"), got.get("op_num")) == (2, 0x1234, 0x5678)


@pytest.mark.parametrize("fragment_length,auth_length,pfc_flags", [
    (16, 0, 3), (23, 0, 3), (40, 0, 3), (24, 0, 0x83), (24, 1, 3),
])
def test_opcda_fallback_respects_fragment_and_auth_bounds(fragment_length, auth_length, pfc_flags):
    # Physical bytes after a short declared fragment cannot supply missing fields;
    # nor can authentication material or a missing optional object UUID.
    wire = (bytes([5, 0, 0, pfc_flags]) + b"\x10\0\0\0"
            + struct.pack("<HHI", fragment_length, auth_length, 42)
            + struct.pack("<IHH", 2, 0x1234, 0x5678) + b"AB")
    got = f.opcda_report(wire)
    assert "error" in got
    assert "op_num" not in got and "context_id" not in got and "alloc_hint" not in got


@pytest.mark.parametrize("wire,protocol", [
    (_bacnet(WHO_IS), "bacnet"), (_enip(0x65, bytes.fromhex("01000000")), "enip"),
    (_rpc_request(), "opcda"), (bytes.fromhex("fefe0500"), "profinet"), (b"", None),
])
def test_protocol_detection_vectors(wire, protocol):
    assert f.detect_protocol(wire) == protocol


def test_pcap_and_file_wrappers_against_scapy_capture(tmp_path):
    path = tmp_path / "known.pcap"
    packets = [Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=47808, dport=47808) / Raw(_bacnet(READ_ACK)),
               Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=12345, dport=44818) / Raw(_enip(0x6F, _cpf(CIP_READ)))]
    for packet in packets:
        packet.time = 1700000000
    wrpcap(str(path), packets)
    for reports in (f.reports_from_pcap(str(path)), f.analyze_file(str(path))["reports"]):
        assert [r["protocol"] for r in reports] == ["bacnet-ip", "ethernet-ip"]
        assert reports[0]["apdu"]["service_reading"]["value"] == -12.5
        assert reports[1]["items"][1]["cip"]["path"][0]["name"] == "Speed"


def test_raw_file_render_and_cli_vectors(tmp_path, capsys):
    path = tmp_path / "known.bin"
    path.write_bytes(_bacnet(READ_ACK))
    result = f.analyze_file(str(path))
    assert result["kind"] == "raw"
    assert result["reports"][0]["apdu"]["service_reading"]["value"] == -12.5
    rendered = f.render(result)
    lines = []
    f.render_report(result["reports"][0], lines)
    for output in (rendered, "\n".join(lines)):
        assert "analog-value:7" in output and "present-value" in output and "-12.5" in output
    assert f.main([str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["reports"][0]["apdu"]["invoke_id"] == 42


# Each malformed case stays individually visible in pytest.
PARSE_CASES = {
    "decode_bacnet_tags": (lambda b: f.decode_bacnet_tags(b), bytes.fromhex("3e44c14800003f")),
    "parse_bvlc": (f.parse_bvlc, _bacnet(READ_ACK)),
    "parse_npdu": (lambda b: f.parse_npdu(b, 0), bytes.fromhex("012f123402aabb567801cc091008")),
    "parse_bacnet_apdu": (lambda b: f.parse_bacnet_apdu(b, 0), READ_ACK),
    "parse_cip": (f.parse_cip, CIP_READ),
    "parse_enip": (f.parse_enip, _enip(0x6F, _cpf(CIP_READ))),
}


def _fuzz_cases():
    rng = random.Random(0x1C52026)
    for name, (_, seed) in PARSE_CASES.items():
        cases = [("empty", b"")]
        cases += [(f"ff-{n}", b"\xff" * n) for n in (1, 2, 3, 4, 8, 16, 32)]
        cases += [(f"zero-{n}", b"\0" * n) for n in (1, 2, 3, 4, 8, 16, 32)]
        cases += [(f"random-{i}", rng.randbytes(i % 33)) for i in range(48)]
        cases += [(f"truncated-{n}", seed[:n]) for n in range(len(seed))]
        for index in range(len(seed)):
            flipped = bytearray(seed)
            flipped[index] ^= 1 << (index % 8)
            cases.append((f"bitflip-{index}", bytes(flipped)))
        if name == "parse_bacnet_apdu":
            cases += [(f"short-kind-{hex(kind)}-{n}", bytes([kind]) + b"\0" * (n - 1))
                      for kind, minimum in ((0, 4), (8, 6), (0x10, 2), (0x20, 3), (0x30, 3), (0x38, 5), (0x50, 3), (0x60, 3), (0x70, 3))
                      for n in range(1, minimum)]
        for label, blob in cases:
            yield pytest.param(name, blob, id=f"{name}-{label}")


@pytest.mark.parametrize("name,blob", list(_fuzz_cases()))
def test_public_parser_fail_closed_fuzz(name, blob):
    try:
        result = PARSE_CASES[name][0](blob)
    except f._BError:
        return
    assert result is None or isinstance(result, (dict, list))


def test_every_public_parse_entrypoint_has_fuzz_adapter():
    entrypoints = {name for name, value in inspect.getmembers(f, inspect.isfunction)
                   if name.startswith("parse_") and value.__module__ == f.__name__}
    assert entrypoints == set(PARSE_CASES) - {"decode_bacnet_tags"}
