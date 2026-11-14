"""Independent wire construction, not engine-generated expected results.

Tag/schema oracle: Wireshark epan/dissectors/asn1/{goose,sv}/*.asn and
libiec61850 src/sampled_values/sv_subscriber.c (fixed wire widths).
BER, Ethernet, and sample encoders below are written by hand using struct.
"""
import argparse
import json
import random
import struct

import pytest

import power_iec61850 as power


def tlv(tag, value):
    length = len(value)
    if length < 128:
        size = bytes([length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        size = bytes([128 | len(encoded)]) + encoded
    return bytes([tag]) + size + value


def appid(tag, body, aid):
    pdu = tlv(tag, body)
    return struct.pack(">HHHH", aid, len(pdu) + 8, 0, 0) + pdu


def goose_body(*, values=None, count=2, state=1, seq=0, conf=1, defaults=False):
    if values is None:
        values = tlv(0x83, b"\xff") + tlv(0x8a, b"CSCTF{synthetic_vector}")
    parts = [tlv(0x80, b"IED/LLN0$GO$gcb"), tlv(0x81, b"\x03\xe8"),
             tlv(0x82, b"IED/LLN0$dataset"), tlv(0x83, b"publisher"),
             tlv(0x84, bytes.fromhex("650000008000008a")),
             tlv(0x85, bytes([state])), tlv(0x86, bytes([seq]))]
    if not defaults:
        parts.append(tlv(0x87, b"\x00"))
    parts.append(tlv(0x88, bytes([conf])))
    if not defaults:
        parts.append(tlv(0x89, b"\x00"))
    return b"".join(parts) + tlv(0x8a, bytes([count])) + tlv(0xab, values)


def sv_asdu(samples=b"\x00\x01", *, count=3999, optional=False):
    body = tlv(0x80, b"MU01")
    if optional:
        body += tlv(0x81, b"MU/LLN0$ds")
    body += tlv(0x82, struct.pack(">H", count)) + tlv(0x83, struct.pack(">I", 5))
    if optional:
        body += tlv(0x84, bytes.fromhex("6500000040000021"))
    body += tlv(0x85, b"\x02")
    if optional:
        body += tlv(0x86, struct.pack(">H", 80))
    body += tlv(0x87, samples)
    if optional:
        body += tlv(0x88, b"\x00") + tlv(0x89, b"\x01\x02\x03\x04\x05\x06\x07\x08")
    return tlv(0x30, body)


def sv(*asdus, count=None):
    n = len(asdus) if count is None else count
    return appid(0x60, tlv(0x80, bytes([n])) + tlv(0xa2, b"".join(asdus)), 0x4000)


def ethernet(payload, ethertype=0x88ba, vlan=False):
    macs = bytes.fromhex("010ccd040001001122334455")
    if vlan:
        return macs + struct.pack(">HHHHH", 0x88a8, 101, 0x8100, 0x8003, ethertype) + payload
    return macs + struct.pack(">H", ethertype) + payload


def test_goose_reuses_decoder_and_defaults():
    result = power.parse_goose(appid(0x61, goose_body(defaults=True), 0x1000))
    assert result["appid"] == 0x1000
    assert result["fields"]["time_allowed_to_live"] == 1000
    assert result["fields"]["simulation"] is False
    assert result["fields"]["needs_commissioning"] is False
    assert result["all_data"][0]["value"] is True
    assert result["all_data"][1]["value"] == "CSCTF{synthetic_vector}"
    assert result["timestamp_detail"]["fraction_seconds"] == 0.5
    assert result["timestamp_detail"]["leap_seconds_known"] is True
    assert result["timestamp_detail"]["time_accuracy"] == 10
    json.dumps(result, allow_nan=False)


def test_goose_nested_real_float_integer_values():
    values = tlv(0xa2, tlv(0x85, b"\xff\xfe") + tlv(0x87, b"\x08" + struct.pack(">f", 1.5)))
    result = power.parse_goose(appid(0x61, goose_body(values=values, count=1), 1))
    children = result["all_data"][0]["children"]
    assert children[0]["value"] == -2
    assert children[1]["value"] == 1.5


def test_sv_multiple_asdus_and_optional_fields():
    result = power.parse_sv(sv(sv_asdu(optional=True), sv_asdu(count=4000)))
    assert result["asdu_count"] == 2
    a, b = result["asdus"]
    assert a["sv_id"] == "MU01"
    assert a["sample_count"] == 3999
    assert b["sample_count"] == 4000
    assert a["conf_revision"] == 5
    assert a["reference_time"]["fraction_seconds"] == 0.25
    assert a["reference_time"]["not_synchronized"] is True
    assert a["sample_sync"] == 2
    assert a["sample_rate"] == 80
    assert a["sample_mode"] == 0
    assert a["gmid_hex"] == "0102030405060708"
    assert a["data_hex"] == "0001"
    assert "samples" not in a


def test_sv_9_2le_sign_quality_no_implicit_profile():
    counts = [-2147483648, -1, 0, 1, 2147483647, -2000, 3000, -4000]
    wire = b"".join(struct.pack(">iI", n, i << 3) for i, n in enumerate(counts))
    raw = sv(sv_asdu(wire))
    assert "samples" not in power.parse_sv(raw)["asdus"][0]
    parsed = power.parse_sv(raw, decode_9_2le=True)["asdus"][0]["samples"]
    assert [x["raw_value"] for x in parsed] == counts
    assert [x["quality"] for x in parsed] == [i << 3 for i in range(8)]
    assert [x["channel"] for x in parsed] == ["Ia", "Ib", "Ic", "In", "Va", "Vb", "Vc", "Vn"]


def test_ethernet_vlan_metadata_and_opaque_trailer():
    frame = ethernet(sv(sv_asdu()), vlan=True) + b"\xde\xad\xbe\xef"
    result = power.parse_frame(frame)
    e = result["ethernet"]
    assert e["source"] == "00:11:22:33:44:55"
    assert e["destination"] == "01:0c:cd:04:00:01"
    assert [x["id"] for x in e["vlans"]] == [101, 3]
    assert e["vlans"][1]["priority"] == 4
    assert e["trailer_hex"] == "deadbeef"


@pytest.mark.parametrize("body", [
    b"", goose_body(count=1), goose_body() + tlv(0x8a, b"\x02"),
    goose_body().replace(tlv(0x85, b"\x01"), tlv(0x85, b"\x80")),
    goose_body().replace(tlv(0x87, b"\x00"), tlv(0x87, b"")),
    goose_body(values=tlv(0x84, b"\x07\x7f"), count=1),
    goose_body(values=tlv(0x87, b"\x09" + struct.pack(">f", 1)), count=1),
    goose_body(values=tlv(0xa2, b"\x83\x03\x01"), count=1),
])
def test_goose_rejects_malformed_structures(body):
    with pytest.raises(power.Power61850Error):
        power.parse_goose(appid(0x61, body, 1))


def test_goose_nesting_cap():
    value = tlv(0x83, b"\x00")
    for _ in range(20):
        value = tlv(0xa1, value)
    with pytest.raises(power.Power61850Error):
        power.parse_goose(appid(0x61, goose_body(values=value, count=1), 1))


@pytest.mark.parametrize("wire", [
    sv(sv_asdu(), count=2), sv(),
    sv(tlv(0x30, tlv(0x80, b"MU"))),
    sv(tlv(0x30, sv_asdu()[2:].replace(b"\x82\x02\x0f\x9f", b"\x82\x01\x00"))),
    appid(0x60, tlv(0x80, b"\x01") + tlv(0xa2, tlv(0x31, b"")), 0x4000),
])
def test_sv_rejects_wrong_count_type_missing_field(wire):
    with pytest.raises(power.Power61850Error):
        power.parse_sv(wire)


def test_wrong_profile_and_size():
    with pytest.raises(power.Power61850Error):
        power.parse_sv(sv(sv_asdu()), decode_9_2le=True)
    with pytest.raises(power.Power61850Error):
        power.parse_sv(sv(sv_asdu()) + b"\0")
    with pytest.raises(power.Power61850Error):
        power.parse_frame(ethernet(sv(sv_asdu()), ethertype=0x800))


def test_all_truncations_fail_closed():
    for parser, data in ((power.parse_goose, appid(0x61, goose_body(), 1)),
                         (power.parse_sv, sv(sv_asdu())),
                         (power.parse_frame, ethernet(sv(sv_asdu()), vlan=True))):
        for length in range(len(data)):
            with pytest.raises(power.Power61850Error):
                parser(data[:length])


def test_wrong_types_and_deterministic_corruption_only_declared_errors():
    rng = random.Random(2026)
    for parser in (power.parse_sv, power.parse_goose, power.parse_frame):
        for value in (None, {}, [], 1, "", b"\0" * (power.MAX_FRAME + 1)):
            with pytest.raises(power.Power61850Error):
                parser(value)
        for _ in range(200):
            data = rng.randbytes(rng.randrange(0, 128))
            try:
                parser(data)
            except power.Power61850Error:
                pass


def test_sequence_observations_are_scoped_by_stream():
    def f(**kwargs):
        return ethernet(appid(0x61, goose_body(**kwargs), 1), ethertype=0x88b8)
    frames = [f(), f(seq=1), f(seq=1, values=tlv(0x83, b"\0"), count=1), f(state=0, conf=2)]
    kinds = [o["kind"] for o in power.analyze_frames(frames)["observations"]]
    assert kinds == ["dataset_encoding_changed_without_state_change", "sequence_not_increasing",
                     "configuration_changed", "state_decreased_or_wrapped"]
    assert power.analyze_frames([frames[0], bytes.fromhex("010ccd040002") + frames[0][6:]])["observations"] == []


def test_cli(tmp_path, capsys):
    path = tmp_path / "sv.bin"
    path.write_bytes(sv(sv_asdu()))
    assert power.main([str(path), "--format", "sv"]) == 0
    assert json.loads(capsys.readouterr().out)["protocol"] == "iec61850-sv"
    assert power.main([str(path)]) == 2
    assert power.main([]) == 2
    assert power.main(["--help"]) == 0
    assert power.main([str(path) + ".missing"]) == 2
    path.write_text(sv(sv_asdu()).hex())
    assert power.main([str(path), "--format", "sv", "--hex"]) == 0


def test_cli_noninteger_systemexit(monkeypatch):
    def exit_text(*args, **kwargs):
        raise SystemExit("bad")
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", exit_text)
    assert power.main([]) == 2


def test_memoryview_byte_size_and_strict_options():
    # len(view) is 1; nbytes is 655... and must be checked before allocation.
    view = memoryview(b"x" * (power.MAX_FRAME + 1)).cast("B", [1, power.MAX_FRAME + 1])
    for parser in (power.parse_frame, power.parse_goose, power.parse_sv):
        with pytest.raises(power.Power61850Error):
            parser(view)
    view.release()
    with pytest.raises(power.Power61850Error):
        power.parse_sv(view)
    with pytest.raises(power.Power61850Error):
        power.parse_frame(ethernet(appid(0x61, goose_body(), 1), 0x88b8), decode_9_2le="yes")
    with pytest.raises(power.Power61850Error):
        power.analyze_frames([], decode_9_2le="yes")


def test_sv_ed2_sync_source_ids_and_gmid_width():
    # IEEE PSRC H6 report 053 p.30: Ed2 permits IDs 5..254.
    for identifier in (5, 123, 254):
        asdu = sv_asdu().replace(b"\x85\x01\x02", bytes([0x85, 1, identifier]))
        parsed = power.parse_sv(sv(asdu))["asdus"][0]
        assert parsed["legacy_local_sync_source_id"] == identifier
    for identifier in (3, 4, 255):
        asdu = sv_asdu().replace(b"\x85\x01\x02", bytes([0x85, 1, identifier]))
        with pytest.raises(power.Power61850Error):
            power.parse_sv(sv(asdu))
    body = sv_asdu(optional=True)[2:]
    invalid = tlv(0x30, body.replace(tlv(0x89, bytes(range(1, 9))), tlv(0x89, b"x")))
    with pytest.raises(power.Power61850Error):
        power.parse_sv(sv(invalid))
