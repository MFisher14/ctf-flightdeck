"""Independent vectors and fail-closed mutation tests for OT protocol engines.

Oracles are external to the implementations:

* Beckhoff's published IEC 60870-5-101 FT1.2 Samples 1 and 3.
* ISO 9506/X.690 BER tag-length-value semantics for an MMS Identify request.
* IEC 61850-6 SCL object/reference semantics in a hand-authored model.
* OPC 10000-14 7.2.4 UADP and OPC 10000-6 Annex F NodeSet2 layouts.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable, Iterable
from typing import Any

import pytest

import ot_iec101_serial as iec101
import ot_mms_services as mms
import ot_opcua_pubsub as pubsub
import ot_scl_integrity as scl


# Beckhoff TF6500 documentation, "IEC 60870-5-101 telegram structure",
# published Sample 1 and Sample 3 byte-for-byte.
IEC_FIXED = bytes.fromhex("10 49 0C 00 55 16")
IEC_VARIABLE = bytes.fromhex(
    "68 0B 0B 68 08 0C 00 65 01 0A 0C 00 00 00 05 95 16"
)
IEC_ASDU = bytes.fromhex("65 01 0A 0C 00 00 00 05")


# Hand-encoded X.690 definite-short-form BER:
# [0] Confirmed-Request { INTEGER invokeID=1, [2] Identify NULL }.
MMS_IDENTIFY = bytes.fromhex("A0 05 02 01 01 82 00")
ACSE_RELEASE_REQUEST = bytes.fromhex("62 00")  # APPLICATION 2, constructed.
# Fully-encoded presentation data: one PDV, context 1, single-ASN.1 MMS value.
PRESENTATION_IDENTIFY = bytes.fromhex(
    "61 0E 30 0C 02 01 01 A0 07 A0 05 02 01 01 82 00"
)
TPKT_IDENTIFY = (
    b"\x03\x00"
    + (7 + len(MMS_IDENTIFY)).to_bytes(2, "big")
    + b"\x02\xf0\x80"
    + MMS_IDENTIFY
)


SCL_NS = "http://www.iec.ch/61850/2003/SCL"
SCL_DOCUMENT = f"""<SCL xmlns="{SCL_NS}">
  <Communication><SubNetwork name="station">
    <ConnectedAP iedName="IED1" apName="AP1">
      <GSE ldInst="LD0" cbName="go1"><Address>
        <P type="MAC-Address">01-0C-CD-01-00-01</P>
        <P type="APPID">1001</P><P type="VLAN-ID">001</P>
        <P type="VLAN-PRIORITY">4</P>
      </Address></GSE>
    </ConnectedAP>
  </SubNetwork></Communication>
  <IED name="IED1"><AccessPoint name="AP1"><Server>
    <LDevice inst="LD0" ldName="IED1LD0">
      <LN0 lnClass="LLN0" inst="" lnType="LT0">
        <DataSet name="ds1">
          <FCDA ldInst="LD0" lnClass="LLN0" doName="Beh"
                daName="stVal" fc="ST"/>
        </DataSet>
        <GSEControl name="go1" datSet="ds1" confRev="7" appID="GOID"/>
      </LN0>
    </LDevice>
  </Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LT0" lnClass="LLN0"><DO name="Beh" type="DOT0"/></LNodeType>
    <DOType id="DOT0" cdc="ENS">
      <DA name="stVal" bType="Enum" type="EN0" fc="ST"/>
    </DOType>
    <EnumType id="EN0"><EnumVal ord="1">on</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>""".encode()


# OPC 10000-14 Table 162: valid key-frame, Variant encoding, one field.
# OPC 10000-6 Variant encoding: type id 6 (Int32), little-endian value 42.
DATASET_INT32_42 = bytes.fromhex("01 01 00 06 2A 00 00 00")
# UADPFlags version=1, no PayloadHeader; DataSetReader supplies the one size.
UADP_INT32_42 = b"\x01" + DATASET_INT32_42
NODESET = f"""<UANodeSet xmlns="{pubsub.NODESET_NS}">
  <NamespaceUris><Uri>urn:test</Uri></NamespaceUris>
  <Aliases><Alias Alias="HasComponent">i=47</Alias></Aliases>
  <UAObject NodeId="ns=1;i=1001" BrowseName="1:Pump">
    <DisplayName>Pump</DisplayName>
    <References>
      <Reference ReferenceType="HasComponent">ns=1;i=1002</Reference>
    </References>
  </UAObject>
</UANodeSet>""".encode()


def _ber_tlv(tag: int, body: bytes) -> bytes:
    """Independent definite-length BER writer used only for the GOOSE fixture."""

    if len(body) < 128:
        length = bytes([len(body)])
    else:
        encoded = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + length + body


def _goose_frame() -> bytes:
    """Hand-built IEC 61850-8-1 GOOSE Ethernet/VLAN/APDU fixture."""

    all_data = _ber_tlv(0x83, b"\xff")
    body = b"".join(
        (
            _ber_tlv(0x80, b"IED1LD0/LLN0$GO$go1"),
            _ber_tlv(0x81, b"\x03\xe8"),
            _ber_tlv(0x82, b"IED1LD0/LLN0$ds1"),
            _ber_tlv(0x83, b"GOID"),
            _ber_tlv(0x84, bytes.fromhex("0000000100000000")),
            _ber_tlv(0x85, b"\x01"),
            _ber_tlv(0x86, b"\x00"),
            _ber_tlv(0x87, b"\x00"),
            _ber_tlv(0x88, b"\x07"),
            _ber_tlv(0x89, b"\x00"),
            _ber_tlv(0x8A, b"\x01"),
            _ber_tlv(0xAB, all_data),
        )
    )
    pdu = _ber_tlv(0x61, body)
    app = struct.pack(">4H", 0x1001, len(pdu) + 8, 0, 0) + pdu
    ethernet = bytes.fromhex("010ccd010001001122334455")
    vlan = struct.pack(">3H", 0x8100, (4 << 13) | 1, 0x88B8)
    return ethernet + vlan + app


def _classic_pcap(frame: bytes) -> bytes:
    """Classic little-endian PCAP with one Ethernet packet at t=1.5 s."""

    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 500_000, len(frame), len(frame))
    return header + record + frame


def _hostile_cases(valid: bytes, limit: int) -> Iterable[tuple[str, Any]]:
    """Deterministic empty/random/truncated/bit-flipped/oversized mutations."""

    yield "wrong-type", None
    yield "empty", b""
    for size in (1, 2, 7, 19, 64):
        block = bytearray()
        counter = 0
        while len(block) < size:
            block.extend(hashlib.sha256(f"ot-fuzz-{size}-{counter}".encode()).digest())
            counter += 1
        yield f"random-{size}", bytes(block[:size])
    for cut in sorted({0, 1, len(valid) // 3, len(valid) // 2, len(valid) - 1}):
        if 0 <= cut < len(valid):
            yield f"truncated-{cut}", valid[:cut]
    for position in sorted({0, len(valid) // 2, len(valid) - 1}):
        changed = bytearray(valid)
        changed[position] ^= 1 << (position % 8)
        yield f"bitflip-{position}", bytes(changed)
    yield "oversized", b"\x00" * (limit + 1)


def _assert_only_declared(
    parser: Callable[[Any], Any],
    error: type[BaseException],
    cases: Iterable[tuple[str, Any]],
) -> None:
    for label, value in cases:
        try:
            parser(value)
        except error:
            continue
        except Exception as exc:  # pragma: no cover - assertion reports the leak.
            pytest.fail(
                f"{parser!r} leaked {type(exc).__name__} for {label}: {exc}"
            )


def test_iec101_beckhoff_published_ft12_vectors():
    control = iec101.decode_control(0x49)
    assert control["raw"] == 0x49
    assert control["role"] == "primary"
    assert control["function_code"] == 9
    assert control["function"] == "request_link_status"
    assert control["fcb"] is False
    assert control["fcv"] is False
    assert control["reserved_bits"] == 0

    fixed = iec101.parse_frame(
        IEC_FIXED, address_size=2, cot_size=1, common_address_size=2, ioa_size=2
    )
    assert fixed["format"] == "fixed"
    assert fixed["link_address"] == 12
    assert fixed["checksum"] == 0x55
    assert fixed["control"]["primary"] is True
    assert fixed["control"]["function_code"] == 9
    assert fixed["control"]["function"] == "request_link_status"

    variable = iec101.parse_frame(
        IEC_VARIABLE,
        address_size=2,
        cot_size=1,
        common_address_size=2,
        ioa_size=2,
    )
    assert variable["checksum"] == 0x95
    assert variable["link_address"] == 12
    assert variable["control"]["function_code"] == 8
    assert variable["asdu"]["type_id"] == 101
    assert variable["asdu"]["cause"] == 10
    assert variable["asdu"]["common_address"] == 12
    assert variable["asdu"]["information_objects"] == [
        {"ioa": 0, "raw_hex": "05", "qcc": 5}
    ]

    stream = iec101.parse_stream(
        b"\xe5" + IEC_FIXED + IEC_VARIABLE,
        address_size=2,
        cot_size=1,
        common_address_size=2,
        ioa_size=2,
    )
    assert [row["offset"] for row in stream] == [0, 1, 7]
    assert [row["format"] for row in stream] == ["single", "fixed", "variable"]


def test_iec101_decode_control_invalid_arguments_fail_closed():
    calls = (
        lambda: iec101.decode_control(None),
        lambda: iec101.decode_control(b"I"),
        lambda: iec101.decode_control(True),
        lambda: iec101.decode_control(-1),
        lambda: iec101.decode_control(256),
        lambda: iec101.decode_control(0x49, mode="invalid"),
        lambda: iec101.decode_control(0x49, mode=None),
    )
    for call in calls:
        try:
            call()
        except iec101.IEC101Error:
            continue
        except Exception as exc:  # pragma: no cover
            pytest.fail(f"decode_control leaked {type(exc).__name__}: {exc}")
        pytest.fail("decode_control accepted an invalid argument")


def test_iec101_entrypoints_fail_closed_under_mutation():
    frame_call = lambda value: iec101.parse_frame(  # noqa: E731
        value, address_size=2, cot_size=1, common_address_size=2, ioa_size=2
    )
    stream_call = lambda value: iec101.parse_stream(  # noqa: E731
        value, address_size=2, cot_size=1, common_address_size=2, ioa_size=2
    )
    asdu_call = lambda value: iec101.decode_asdu(  # noqa: E731
        value, cot_size=1, common_address_size=2, ioa_size=2
    )
    _assert_only_declared(
        frame_call, iec101.IEC101Error, _hostile_cases(IEC_FIXED, 261)
    )
    _assert_only_declared(
        stream_call,
        iec101.IEC101Error,
        _hostile_cases(b"\xe5" + IEC_FIXED + IEC_VARIABLE, iec101.MAX_INPUT),
    )
    _assert_only_declared(
        asdu_call, iec101.IEC101Error, _hostile_cases(IEC_ASDU, 254)
    )


def test_mms_hand_encoded_ber_and_tpkt_vectors():
    expected_mms = {
        "protocol": "mms",
        "pdu": "confirmed_request",
        "invoke_id": 1,
        "service": {"number": 2, "name": "identify"},
        "details": {},
    }
    decoded = mms.parse_mms(MMS_IDENTIFY)
    assert decoded == expected_mms

    release = mms.parse_acse(ACSE_RELEASE_REQUEST)
    assert release == {
        "protocol": "acse",
        "pdu": "rlrq",
        "user_information": [],
    }

    presentation = mms.parse_presentation(
        PRESENTATION_IDENTIFY, {1: mms.MMS_SYNTAX}
    )
    assert presentation["pdvs"][0]["context_id"] == 1
    assert presentation["pdvs"][0]["abstract_syntax"] == mms.MMS_SYNTAX
    assert presentation["pdvs"][0]["mms"] == expected_mms

    wrapped = mms.analyze(TPKT_IDENTIFY)
    assert wrapped["wrappers"] == ["tpkt", "cotp_dt"]
    assert {
        key: value for key, value in wrapped.items() if key != "wrappers"
    } == expected_mms


def test_mms_entrypoints_fail_closed_under_mutation():
    calls = (
        (mms.parse_mms, MMS_IDENTIFY),
        (mms.parse_acse, ACSE_RELEASE_REQUEST),
        (
            lambda value: mms.parse_presentation(value, {1: mms.MMS_SYNTAX}),
            PRESENTATION_IDENTIFY,
        ),
        (mms.analyze, TPKT_IDENTIFY),
    )
    for parser, valid in calls:
        _assert_only_declared(
            parser, mms.MMSParseError, _hostile_cases(valid, mms.MAX_INPUT)
        )


def test_scl_documented_semantic_model_and_diff_vector():
    report = scl.analyze_scl(SCL_DOCUMENT)
    assert report["findings"] == []
    canonical = report["canonical"]
    assert canonical["ieds"] == [
        {"key": '["IED1"]', "attributes": {"name": "IED1"}}
    ]
    assert canonical["logical_devices"][0]["domain"] == "IED1LD0"
    assert canonical["datasets"][0]["reference"] == "IED1LD0/LLN0$ds1"
    assert canonical["datasets"][0]["members"] == [
        {
            "prefix": "",
            "lnInst": "",
            "daName": "stVal",
            "ldInst": "LD0",
            "lnClass": "LLN0",
            "doName": "Beh",
            "fc": "ST",
        }
    ]
    control = canonical["controls"][0]
    assert control["reference"] == "IED1LD0/LLN0$GO$go1"
    assert control["conf_revision"] == 7

    changed = SCL_DOCUMENT.replace(b'confRev="7"', b'confRev="8"')
    diff = scl.diff_scl(SCL_DOCUMENT, changed)
    assert diff["equal"] is False
    assert [(row["section"], row["key"]) for row in diff["changes"]] == [
        ("controls", '["IED1","AP1","LD0","LLN0","GSEControl","go1"]')
    ]


def test_scl_hand_built_goose_and_classic_pcap_vectors():
    frame_bytes = _goose_frame()
    correlated = scl.correlate_frames(SCL_DOCUMENT, [frame_bytes])
    assert correlated["findings"] == []
    assert len(correlated["frames"]) == 1
    frame = correlated["frames"][0]
    assert frame["index"] == 0
    assert frame["protocol"] == "iec61850-goose"
    assert frame["findings"] == []
    assert len(frame["matches"]) == 1
    assert frame["mapped_fields"] == [
        {
            "asdu": 0,
            "index": 0,
            "dataset": '["IED1","AP1","LD0","LLN0","ds1"]',
            "member": {
                "prefix": "",
                "lnInst": "",
                "daName": "stVal",
                "ldInst": "LD0",
                "lnClass": "LLN0",
                "doName": "Beh",
                "fc": "ST",
            },
            "value": {
                "type": "boolean",
                "tag": 0x83,
                "raw_length": 1,
                "raw": "ff",
                "value": True,
            },
        }
    ]

    capture = scl.correlate_capture(SCL_DOCUMENT, _classic_pcap(frame_bytes))
    assert capture["findings"] == []
    assert capture["ignored_packets"] == 0
    assert len(capture["frames"]) == 1
    assert capture["frames"][0]["timestamp"] == 1.5
    assert capture["frames"][0]["protocol"] == "iec61850-goose"
    assert capture["frames"][0]["findings"] == []


def test_scl_correlation_entrypoints_fail_closed_under_mutation():
    frame_bytes = _goose_frame()
    capture = _classic_pcap(frame_bytes)
    _assert_only_declared(
        lambda value: scl.correlate_frames(SCL_DOCUMENT, [value]),
        scl.SclError,
        _hostile_cases(frame_bytes, scl.power.MAX_FRAME),
    )
    _assert_only_declared(
        lambda value: scl.correlate_capture(SCL_DOCUMENT, value),
        scl.SclError,
        _hostile_cases(capture, scl.MAX_CAPTURE),
    )


def test_scl_parse_entrypoints_fail_closed_under_mutation():
    cases = tuple(_hostile_cases(SCL_DOCUMENT, scl.MAX_INPUT))
    _assert_only_declared(scl.canonicalize_scl, scl.SclError, iter(cases))
    _assert_only_declared(scl.analyze_scl, scl.SclError, iter(cases))
    for label, value in cases:
        for left, right in ((value, SCL_DOCUMENT), (SCL_DOCUMENT, value)):
            try:
                scl.diff_scl(left, right)
            except scl.SclError:
                continue
            except Exception as exc:  # pragma: no cover
                pytest.fail(
                    f"diff_scl leaked {type(exc).__name__} for {label}: {exc}"
                )


def test_opcua_published_uadp_variant_and_nodeset_semantics():
    expected_fields = [
        {
            "index": 0,
            "value": {
                "type_id": 6,
                "type": "Int32",
                "array": False,
                "value": 42,
            },
        }
    ]
    dataset = pubsub.parse_dataset_message(DATASET_INT32_42)
    assert dataset["field_encoding"] == "Variant"
    assert dataset["message_type"] == "key-frame"
    assert dataset["field_count"] == 1
    assert dataset["fields"] == expected_fields

    network = pubsub.parse_uadp(UADP_INT32_42, dataset_sizes=[8])
    assert network["version"] == 1
    assert network["header_size"] == 1
    assert network["payload_status"] == "decoded"
    assert network["dataset_messages"][0]["fields"] == expected_fields

    nodeset = pubsub.parse_nodeset(NODESET)
    assert nodeset["namespace_uris"] == [pubsub.UA_NS, "urn:test"]
    assert nodeset["aliases"] == {"HasComponent": "i=47"}
    node = nodeset["nodes"][0]
    assert node["node_id"]["text"] == "ns=1;i=1001"
    assert node["browse_name"] == {
        "namespace": 1,
        "name": "Pump",
        "namespace_uri": "urn:test",
    }
    assert node["references"][0]["reference_type"]["identifier"] == 47
    assert node["references"][0]["target_id"] == "ns=1;i=1002"
    assert node["references"][0]["target_scope"] == "external"


def test_opcua_pubsub_entrypoints_fail_closed_under_mutation():
    calls = (
        (pubsub.parse_dataset_message, DATASET_INT32_42),
        (lambda value: pubsub.parse_uadp(value, dataset_sizes=[8]), UADP_INT32_42),
        (pubsub.parse_nodeset, NODESET),
    )
    for parser, valid in calls:
        _assert_only_declared(
            parser, pubsub.ParseError, _hostile_cases(valid, pubsub.MAX_INPUT)
        )
