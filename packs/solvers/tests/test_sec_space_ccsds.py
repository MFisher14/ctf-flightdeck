"""Independent CCSDS/ECSS bit-layout fixtures and fail-closed checks.

Builders encode the published layouts directly.  CRCs use the independent
stdlib ``binascii.crc_hqx`` implementation, never engine-generated output.
"""

import binascii
import random

import pytest

import sec_space_ccsds as m


def fecf(data):
    return binascii.crc_hqx(data, 0xFFFF).to_bytes(2, "big")


def packet(payload, apid=0x123, kind=0, secondary=0, flags=3, count=42):
    identity = (kind << 12) | (secondary << 11) | apid
    sequence = (flags << 14) | count
    return (identity.to_bytes(2, "big") + sequence.to_bytes(2, "big")
            + (len(payload) - 1).to_bytes(2, "big") + payload)


def tm(payload, secondary=b"", ocf=b"", fhp=0, crc=True):
    first = (0x155 << 4) | (5 << 1) | bool(ocf)
    control = (bool(secondary) << 15) | (2 << 11) | fhp
    body = (first.to_bytes(2, "big") + b"\x07\x09"
            + control.to_bytes(2, "big") + secondary + payload + ocf)
    return body + (fecf(body) if crc else b"")


def tc(payload, bypass=0, control=0, segment=None, crc=True):
    first = (bypass << 13) | (control << 12) | 0x155
    total = 5 + (segment is not None) + len(payload) + (2 if crc else 0)
    body = (first.to_bytes(2, "big")
            + ((12 << 10) | (total - 1)).to_bytes(2, "big") + b"\x44")
    if segment is not None:
        body += bytes(((segment[0] << 6) | segment[1],))
    body += payload
    return body + (fecf(body) if crc else b"")


def uslp(payload, rule=7, pointer=None, insert=b"", ocf=b"", crc=True):
    primary = ((0xC << 28) | (0x1234 << 12) | (1 << 11)
               | (17 << 5) | (6 << 1))
    tfdf = bytes(((rule << 5) | 3,))
    if pointer is not None:
        tfdf += pointer.to_bytes(2, "big")
    tfdf += payload
    control = 0x80 | (bool(ocf) << 3) | 2
    total = 7 + 2 + len(insert) + len(tfdf) + len(ocf) + (2 if crc else 0)
    body = (primary.to_bytes(4, "big") + (total - 1).to_bytes(2, "big")
            + bytes((control,)) + b"\x12\x34" + insert + tfdf + ocf)
    return body + (fecf(body) if crc else b"")


def test_crc_published_check_and_independent_oracle():
    assert m.crc16_fecf(b"123456789") == 0x29B1
    rng = random.Random(1330)
    for length in (0, 1, 15, 255, 4096):
        raw = rng.randbytes(length)
        assert m.crc16_fecf(raw) == binascii.crc_hqx(raw, 0xFFFF)


def test_space_packet_literal_and_exact_stream():
    literal = bytes.fromhex("0923 c02a 0003 deadbeef")
    got = m.parse_space_packet(literal)
    assert (got["apid"], got["direction"], got["sequence_count"]) == (0x123, "tm", 42)
    assert got["secondary_header_present"] and got["sequence_flag_name"] == "unsegmented"
    assert got["packet_data_length"] == 4 and got["data_hex"] == "deadbeef"
    other = packet(b"ABC", apid=9, flags=1, count=7)
    rows = m.parse_space_packet_stream(literal + other)
    assert [row["stream_offset"] for row in rows] == [0, len(literal)]
    assert rows[1]["sequence_flag_name"] == "first_segment"


def test_pus_c_tc_tm_headers_and_packet_delegation():
    tc_data = bytes.fromhex("2d 11 07 beef") + b"PAY"
    got = m.parse_pus_secondary(tc_data, "tc")
    assert (got["acknowledgement_flags"], got["service"], got["subtype"]) == (13, 17, 7)
    assert got["source_id"] == 0xBEEF and got["application_data_hex"] == b"PAY".hex()
    enclosed = packet(tc_data, kind=1, secondary=1)
    assert m.parse_space_packet(enclosed, pus="tc")["pus"]["source_id"] == 0xBEEF

    tm_data = bytes.fromhex("23 05 02 1234 abcd 010203040506") + b"DATA"
    got = m.parse_pus_secondary(tm_data, "tm", time_length=6)
    assert (got["message_type_counter"], got["destination_id"]) == (0x1234, 0xABCD)
    assert got["time_code_hex"] == "010203040506"
    with pytest.raises(m.SecSpaceCCSDSError):
        m.parse_pus_secondary(tc_data, "tc", time_length=1)
    with pytest.raises(m.SecSpaceCCSDSError):
        m.parse_space_packet(packet(b"ABC"), pus_time_length=1)


def test_tm_transfer_frame_secondary_ocf_and_fecf():
    raw = tm(b"HELLO", secondary=bytes.fromhex("02 aabb"),
             ocf=bytes.fromhex("10203040"), fhp=1)
    got = m.parse_tm_frame(raw, has_fecf=True)
    assert (got["spacecraft_id"], got["virtual_channel_id"]) == (0x155, 5)
    assert got["secondary_header"] == {"version": 0, "length": 3, "data_hex": "02aabb"}
    assert got["data_field_hex"] == b"HELLO".hex() and got["ocf_hex"] == "10203040"
    assert got["fecf"] == int.from_bytes(fecf(raw[:-2]), "big")
    idle = m.parse_tm_frame(tm(b"\x55" * 8, fhp=0x7FE, crc=False))
    assert idle["first_header_pointer_kind"] == "idle_data"
    assert idle["segment_length_name"] == "managed_code_2"


def test_tc_transfer_frame_segment_and_control_rules():
    got = m.parse_tc_frame(tc(b"COMMAND", segment=(3, 0x2A)),
                           has_fecf=True, segmented=True)
    assert (got["spacecraft_id"], got["virtual_channel_id"]) == (0x155, 12)
    assert got["frame_sequence_number"] == 0x44
    assert got["segment_header"] == {
        "sequence_flags": 3, "sequence_flag_name": "unsegmented", "map_id": 0x2A,
    }
    assert got["data_field_hex"] == b"COMMAND".hex()
    control = m.parse_tc_frame(tc(b"BC", bypass=1, control=1, crc=False))
    assert control["control_command_flag"] and control["service_type"] == "type-b"
    with pytest.raises(m.SecSpaceCCSDSError):
        m.parse_tc_frame(tc(b"X", control=1, crc=False))


def test_uslp_truncated_full_and_profile_selected_pointer():
    primary = ((0xC << 28) | (0xCAFE << 12) | (4 << 5) | (2 << 1) | 1)
    # Complete/no-segmentation TFDF header followed by expedited user data.
    truncated = primary.to_bytes(4, "big") + b"\xe3OK"
    got = m.parse_uslp_frame(truncated)
    assert got["truncated"] and got["spacecraft_id"] == 0xCAFE
    assert got["tfdf"]["payload_hex"] == b"OK".hex()

    raw = uslp(b"USLP", insert=b"IZ", ocf=bytes.fromhex("01020304"))
    got = m.parse_uslp_frame(raw, has_fecf=True, insert_zone_length=2)
    assert (got["virtual_channel_frame_count"], got["insert_zone_hex"]) == (0x1234, b"IZ".hex())
    assert got["tfdf"]["construction_rule_name"] == "complete_no_segmentation"
    assert got["tfdf"]["payload_hex"] == b"USLP".hex() and got["ocf_hex"] == "01020304"

    pointed = uslp(b"ABC", rule=0, pointer=1, crc=False)
    got = m.parse_uslp_frame(pointed, tfdf_pointer_present=True)
    assert got["tfdf"]["pointer"] == 1
    # The same bytes remain opaque user data unless the caller selects a pointer profile.
    assert m.parse_uslp_frame(pointed)["tfdf"]["pointer"] is None


def test_sdls_managed_header_order_fields_and_no_false_crypto_claim():
    # Normative order is SPI, IV, sequence number, pad-length field.
    header = bytes.fromhex("1234") + bytes(range(12)) + bytes.fromhex("01020304 02")
    secured = header + b"SECRET" + b"\x80\x00" + bytes.fromhex("aa" * 16)
    got = m.parse_sdls_fields(secured, sequence_length=4, iv_length=12,
                              pad_length_field_length=1, mac_length=16)
    assert got["security_parameter_index"] == 0x1234
    assert got["iv_hex"] == bytes(range(12)).hex()
    assert got["sequence_number"] == 0x01020304
    assert got["protected_data_hex"] == b"SECRET".hex()
    assert got["padding_hex"] == "8000" and got["mac_hex"] == "aa" * 16
    assert got["authentication_verified"] is False


def test_sdls_extended_procedures_and_fsr():
    assert m.parse_sdls_ep_pdu(bytes.fromhex("31 0000"))["procedure_identifier"] == 1
    reply = m.parse_sdls_ep_pdu(bytes.fromhex("b1 0010 dead"))
    assert reply["reply"] and reply["data_hex"] == "dead"
    fsr = m.parse_sdls_fsr(bytes.fromhex("cd 1234 7f"))
    assert fsr["control_type"] and fsr["version"] == 4
    assert fsr["alarm"] and fsr["bad_sequence_number"]
    assert not fsr["bad_mac"] and fsr["bad_security_association"]
    assert (fsr["last_spi"], fsr["last_arsn"]) == (0x1234, 0x7F)


def test_every_truncation_and_crc_bit_flip_fail_closed():
    cases = [
        (packet(b"abcdef"), lambda x: m.parse_space_packet(x)),
        (tm(b"abcdef"), lambda x: m.parse_tm_frame(x, has_fecf=True)),
        (tc(b"abcdef"), lambda x: m.parse_tc_frame(x, has_fecf=True)),
        (uslp(b"abcdef"), lambda x: m.parse_uslp_frame(x, has_fecf=True)),
    ]
    for valid, parser in cases:
        for size in range(len(valid)):
            with pytest.raises(m.SecSpaceCCSDSError):
                parser(valid[:size])
    for valid, parser in cases[1:]:
        for bit in range(len(valid) * 8):
            changed = bytearray(valid)
            changed[bit // 8] ^= 1 << (7 - bit % 8)
            with pytest.raises(m.SecSpaceCCSDSError):
                parser(bytes(changed))


def test_random_wrong_oversized_and_released_buffers_never_leak():
    parsers = [
        m.parse_space_packet, m.parse_space_packet_stream,
        lambda x: m.parse_pus_secondary(x, "tc"),
        lambda x: m.parse_tm_frame(x, has_fecf=True),
        lambda x: m.parse_tc_frame(x, has_fecf=True, segmented=True),
        lambda x: m.parse_uslp_frame(x, has_fecf=True),
        lambda x: m.parse_sdls_header(x, sequence_length=4, iv_length=12,
                                      pad_length_field_length=1),
        lambda x: m.parse_sdls_fields(x, sequence_length=4, iv_length=12,
                                      pad_length_field_length=1, mac_length=16),
        m.parse_sdls_ep_pdu, m.parse_sdls_fsr,
    ]
    rng = random.Random(0xCC5D5)
    view = memoryview(b"x")
    view.release()
    values = [None, True, 1, "00", [], {}, object(), b"", b"\x00", view,
              rng.randbytes(m.MAX_INPUT + 1)]
    values += [rng.randbytes(rng.randrange(90)) for _ in range(100)]
    for parser in parsers:
        for value in values:
            try:
                assert isinstance(parser(value), (dict, list))
            except m.SecSpaceCCSDSError:
                pass


def test_cli_guarded_missing_nul_and_oversized(tmp_path, capsys):
    path = tmp_path / "packet.bin"
    path.write_bytes(packet(b"ABC"))
    assert m.main(["packet", str(path)]) == 0
    assert '"apid"' in capsys.readouterr().out
    assert m.main(["crc", str(path)]) == 0
    assert '"crc16_fecf"' in capsys.readouterr().out
    assert m.main(["--help"]) == 0
    assert m.main([]) == 2
    assert m.main(["packet", str(path) + ".missing"]) == 2
    assert m.main(["packet", "\0"]) == 2
    huge = tmp_path / "huge.bin"
    huge.write_bytes(b"x" * (m.MAX_INPUT + 1))
    assert m.main(["crc", str(huge)]) == 2
