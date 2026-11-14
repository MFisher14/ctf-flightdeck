"""Independent vector locks and fail-closed fuzz for defense-sector parsers.

The vectors are hand-packed from the cited public layouts, except NITF whose
minimal file is emitted by the independent NGA Sarpy implementation.  No
engine-under-test output is used to construct an expected value.
"""
from __future__ import annotations

import random
import struct

import pytest
from sarpy.io.general.nitf_elements.nitf_head import NITFHeader

import defense_link16 as link16
import defense_markings as markings
import defense_mil1553 as mil1553
import defense_nitf as nitf
import defense_piv as piv
import defense_stanag as stanag
import defense_usmtf as usmtf


def _closed(call, declared_error):
    """A fuzz case may parse or decline, but may not leak another exception."""
    try:
        call()
    except declared_error as exc:
        assert type(exc) is declared_error
        return
    except Exception as exc:  # pragma: no cover - this is the contract failure
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")


# --- Independent vector locks -------------------------------------------------


def _mil_command(rt: int, transmit: int, subaddress: int, count: int) -> int:
    # MIL-STD-1553B command-word field order: RT(5), T/R(1), SA(5), WC/MC(5).
    return int(f"{rt:05b}{transmit:01b}{subaddress:05b}{count:05b}", 2)


def _mil_status(rt: int, low_bits: int = 0) -> int:
    # Status field order starts with the five-bit RT address, then eleven flags.
    return (rt << 11) | low_bits


def test_mil1553_published_command_status_and_transfer_layout():
    command = _mil_command(5, 0, 7, 2)
    assert command == 0x28E2
    decoded = mil1553.decode_command(command)
    assert (decoded["rt_address"], decoded["transmit"], decoded["subaddress"],
            decoded["word_count"]) == (5, False, 7, 2)
    status = _mil_status(5, (1 << 10) | (1 << 8) | (1 << 3))
    flags = mil1553.decode_status(status)
    assert flags["message_error"] and flags["service_request"] and flags["busy"]
    assert not flags["instrumentation"] and flags["reserved_bits"] == 0
    transfer = mil1553.decode_transfer(
        [command, int.from_bytes(b"AB", "big"), int.from_bytes(b"CD", "big"), _mil_status(5)]
    )
    assert transfer["payload_hex"] == b"ABCD".hex()
    assert transfer["payload_ascii"] == "ABCD"
    assert mil1553.parse_word_text("28e2 4142 4344 2800") == [command, 0x4142, 0x4344, 0x2800]


def _link16_initial(label: int, sublabel: int, mli: int, info: int = 0) -> int:
    # Public Link-16 J-word common header is LSB-first: format2,label5,sublabel3,MLI3.
    fields = ((0, 2), (label, 5), (sublabel, 3), (mli, 3), (info, 57))
    bits = "".join(f"{value:0{width}b}"[::-1] for value, width in fields)
    return int(bits[::-1], 2)


def test_link16_dsto_common_header_and_le9_container():
    word = _link16_initial(3, 2, 1, 0x12345)
    assert word & 0x1FFF == 0x050C
    expected = {
        "kind": "initial", "message": "J3.2", "message_length_indicator": 1,
        "information_bit_offset": 13, "information_bit_count": 57,
        "information_hex": "12345",
    }
    got = link16.decode_word(word)
    for key, value in expected.items():
        assert got[key] == value
    assert link16.decode_words([word])[0]["message"] == "J3.2"
    assert link16.parse_words(word.to_bytes(9, "little"), "le9")[0]["word_hex"] == f"{word:018x}"


def _sarpy_minimal_nitf() -> bytes:
    # Sarpy is an independent NGA NITF implementation, not an engine helper.
    header = NITFHeader(OSTAID="ORACLE", FDT="20261105120000", FTITLE="sector B vector")
    header.FL = header.HL
    return header.to_bytes()


def test_nitf_21_sarpy_oracle_and_documented_tre_framing():
    raw = _sarpy_minimal_nitf()
    assert raw[:9] == b"NITF02.10" and len(raw) == 388
    got = nitf.parse_nitf(raw)
    assert got["fields"]["FHDR"] == "NITF"
    assert got["fields"]["FVER"] == "02.10"
    assert got["fields"]["OSTAID"] == "ORACLE"
    assert got["fields"]["FL"] == got["fields"]["HL"] == 388
    assert got["segments"] == []
    # NITF TRE framing is six-byte tag + five decimal length + opaque value.
    tre = nitf.parse_tres(b"TEST0100004\x00A\xffZ")[0]
    assert tre == {"tag": "TEST01", "offset": 0, "length": 4,
                   "data_hex": "0041ff5a", "data_text": "\x00A\xffZ"}


def _piv_chuid() -> bytes:
    # NIST SP 800-73 CHUID tags/widths: 30/25, 34/16, 35/8, 3E/signature, FE/0.
    return (b"\x30\x19" + bytes(range(25))
            + b"\x34\x10" + bytes(range(16))
            + b"\x35\x08" + b"20301231"
            + b"\x3e\x00\xfe\x00")


def test_piv_sp800_73_chuid_vector():
    got = piv.parse_piv(_piv_chuid())
    assert got["kind"] == "chuid"
    assert got["fasc_n_hex"] == bytes(range(25)).hex()
    assert got["guid"] == "00010203-0405-0607-0809-0a0b0c0d0e0f"
    assert got["expiration"] == "2030-12-31"
    assert got["signature_present"] is got["authenticated"] is False


def test_capco_and_ism_documented_semantics():
    # Public CAPCO aliases: OC=ORCON and NF=NOFORN; REL TO preserves country codes.
    banner = markings.parse_marking("(TS//SI/TK//OC/NF/REL TO USA, GBR)")
    assert banner["classification"] == "TS"
    assert banner["sci_controls"] == ["SI", "TK"]
    assert banner["dissemination_controls"] == ["ORCON", "NOFORN"]
    assert banner["releasable_to"] == ["USA", "GBR"]
    text = markings.parse_text("(S//NF) operational line\n(U) public line\n")
    assert [row["line"] for row in text["records"]] == [1, 2]
    assert text["records"][0]["text"] == "operational line"
    xml = ('<r xmlns:i="urn:us:gov:ic:ism:v2" i:classification="S" '
           'i:ownerProducer="USA GBR" i:releasableTo="USA"><p>text</p></r>')
    record = markings.parse_ism(xml)["records"][0]
    assert record["classification"] == "S" and record["level"] == 2
    assert record["lists"]["ownerProducer"] == ["USA", "GBR"]
    assert record["lists"]["releasableTo"] == ["USA"]


def test_usmtf_published_genadmin_slash_set_template():
    message = (
        "MSGID/GENADMIN/COMMARFORXXX/-/MONTH//\n"
        "SUBJ/SHORT DESCRIPTIVE SUBJ LINE//\n"
        "REF/A/ORDER/COMMAND/DTG (CLASSIFICATION)//\n"
        "REF/B/RFF/CDRXXXCOM/DTG (CLASSIFICATION)//"
    )
    got = usmtf.parse_usmtf(message)
    assert got["message_type"] == "GENADMIN"
    assert [item["name"] for item in got["sets"]] == ["MSGID", "SUBJ", "REF", "REF"]
    assert got["sets"][0]["fields"] == ["GENADMIN", "COMMARFORXXX", "-", "MONTH"]
    assert got["sets"][3]["fields"][0] == "B"


def _stanag_segment(kind: int, body: bytes) -> bytes:
    return struct.pack(">BI", kind, len(body) + 5) + body


def _stanag_packet(segments: bytes) -> bytes:
    # packet-stanag4607.c public layout: version,size,nationality,...,mission/job IDs.
    return struct.pack(">2sI2sB2sHB10sII", b"30", 32 + len(segments), b"US", 5,
                       b"  ", 0, 128, b"EAGLE     ", 42, 9) + segments


def _stanag_mission() -> bytes:
    return struct.pack(">12s12sB10sHBB", b"MISSION A", b"FLIGHT 7", 1,
                       b"CONFIG", 2026, 11, 6)


def test_stanag_4607_and_5066_published_wire_layouts():
    packet = _stanag_packet(_stanag_segment(1, _stanag_mission()))
    got = stanag.parse_4607(packet)["packets"][0]
    assert (got["nationality"], got["platform_id"], got["mission_id"], got["job_id"]) == (
        "US", "EAGLE", 42, 9)
    assert got["segments"][0]["mission"] == {
        "mission_plan": "MISSION A", "flight_plan": "FLIGHT 7", "platform_type": 1,
        "platform_configuration": "CONFIG", "date": "2026-11-06",
    }
    # STANAG 5066 SIS v0: sync 90EB, version 00, size 0001 (type included), type 17.
    keepalive = bytes.fromhex("90eb00000111")
    sis = stanag.parse_5066(keepalive)["records"][0]
    assert sis == {"offset": 0, "length": 6, "pdu_type": 17,
                   "name": "S_KEEP_ALIVE", "body_hex": "", "body_validation": "opaque"}


# --- Fail-closed fuzz: every public parse/decode entrypoint -------------------


def test_mil1553_all_entrypoints_fail_closed_fuzz():
    rng = random.Random(0x1553)
    command = _mil_command(5, 0, 7, 1)
    status = _mil_status(5)
    valid_transfer = [command, 0x4142, status]
    scalar_cases = [b"", None, rng.randbytes(3), command >> 8, command ^ 1, 1 << 20]
    for decoder in (mil1553.decode_command, mil1553.decode_status):
        for value in scalar_cases:
            _closed(lambda decoder=decoder, value=value: decoder(value), mil1553.Defense1553Error)
    transfer_cases = [[], [rng.randrange(65536) for _ in range(7)], valid_transfer[:-1],
                      [command ^ 0x400, 0x4142, status], [0] * 35]
    for value in transfer_cases:
        _closed(lambda value=value: mil1553.decode_transfer(value), mil1553.Defense1553Error)
    text_cases = ["", rng.randbytes(17).decode("latin-1"), "28e2 4142 280",
                  "28e2 G142 2800", "0000 " * 1000]
    for value in text_cases:
        _closed(lambda value=value: mil1553.parse_word_text(value), mil1553.Defense1553Error)


def test_link16_all_entrypoints_fail_closed_fuzz():
    rng = random.Random(0x1616)
    word = _link16_initial(3, 2, 1, 0x12345)
    for value in (b"", None, rng.randbytes(11), word >> 9, word ^ 3, 1 << 70):
        _closed(lambda value=value: link16.decode_word(value), link16.DefenseLink16Error)
    for value in ([], [rng.randrange(1 << 70) for _ in range(5)], [word][:-1],
                  [word ^ 3], [word] * (link16.MAX_WORDS + 1)):
        _closed(lambda value=value: link16.decode_words(value), link16.DefenseLink16Error)
    hex_cases = [b"", rng.randbytes(19), b"050", b"g50c", b"0 " * (link16.MAX_WORDS + 1)]
    for value in hex_cases:
        _closed(lambda value=value: link16.parse_words(value), link16.DefenseLink16Error)
    le9 = word.to_bytes(9, "little")
    for value in (b"", rng.randbytes(18), le9[:-1], le9[:-1] + b"\x80", le9 * (link16.MAX_WORDS + 1)):
        _closed(lambda value=value: link16.parse_words(value, "le9"), link16.DefenseLink16Error)


def test_nitf_all_entrypoints_fail_closed_fuzz(monkeypatch):
    rng = random.Random(0x2500)
    valid_file = _sarpy_minimal_nitf()
    flipped = bytearray(valid_file)
    flipped[4] ^= 1
    for value in (b"", rng.randbytes(127), valid_file[:-1], bytes(flipped)):
        _closed(lambda value=value: nitf.parse_nitf(value), nitf.DefenseNITFError)
    monkeypatch.setattr(nitf, "MAX_BYTES", len(valid_file) - 1)
    _closed(lambda: nitf.parse_nitf(valid_file), nitf.DefenseNITFError)

    valid_tre = b"ABC12300003xyz"
    tre_flipped = bytearray(valid_tre)
    tre_flipped[0] = ord("!")
    for value in (b"", rng.randbytes(23), valid_tre[:-1], bytes(tre_flipped)):
        _closed(lambda value=value: nitf.parse_tres(value), nitf.DefenseNITFError)
    monkeypatch.setattr(nitf, "MAX_HEADER", len(valid_tre) - 1)
    _closed(lambda: nitf.parse_tres(valid_tre), nitf.DefenseNITFError)


def test_piv_parse_entrypoint_fail_closed_fuzz(monkeypatch):
    rng = random.Random(0x8073)
    valid = _piv_chuid()
    flipped = bytearray(valid)
    flipped[0] ^= 0x40
    for value in (b"", rng.randbytes(91), valid[:-1], bytes(flipped)):
        _closed(lambda value=value: piv.parse_piv(value), piv.PIVError)
    monkeypatch.setattr(piv, "MAX_BYTES", len(valid) - 1)
    _closed(lambda: piv.parse_piv(valid), piv.PIVError)


def test_markings_all_parse_entrypoints_fail_closed_fuzz(monkeypatch):
    rng = random.Random(0x5200)
    seeds = {
        markings.parse_marking: "(S//NF)",
        markings.parse_text: "(S//NF) operational line\n",
        markings.parse_ism: ('<r xmlns:i="urn:us:gov:ic:ism" '
                             'i:classification="S" i:ownerProducer="USA"/>'),
    }
    for parser, valid in seeds.items():
        random_text = rng.randbytes(31)
        truncated = valid[:-1]
        bit_flipped = chr(ord(valid[0]) ^ 1) + valid[1:]
        for value in ("", random_text, truncated, bit_flipped):
            _closed(lambda parser=parser, value=value: parser(value), markings.MarkingsError)
    monkeypatch.setattr(markings, "MAX_BYTES", 32)
    for parser in seeds:
        _closed(lambda parser=parser: parser("A" * 33), markings.MarkingsError)


def test_usmtf_parse_entrypoint_fail_closed_fuzz(monkeypatch):
    rng = random.Random(0x6040)
    valid = "MSGID/GENADMIN/ORIGINATOR//SUBJ/EXERCISE//"
    flipped = chr(ord(valid[0]) ^ 1) + valid[1:]
    for value in ("", rng.randbytes(63), valid[:-1], flipped):
        _closed(lambda value=value: usmtf.parse_usmtf(value), usmtf.DefenseUSMTFError)
    monkeypatch.setattr(usmtf, "MAX_BYTES", len(valid) - 1)
    _closed(lambda: usmtf.parse_usmtf(valid), usmtf.DefenseUSMTFError)


def test_stanag_all_parse_entrypoints_fail_closed_fuzz(monkeypatch):
    rng = random.Random(0x4607)
    valid_4607 = _stanag_packet(_stanag_segment(1, _stanag_mission()))
    flipped_4607 = bytearray(valid_4607)
    flipped_4607[0] ^= 1
    for value in (b"", rng.randbytes(97), valid_4607[:-1], bytes(flipped_4607)):
        _closed(lambda value=value: stanag.parse_4607(value), stanag.DefenseStanagError)

    valid_5066 = bytes.fromhex("90eb00000111")
    flipped_5066 = bytearray(valid_5066)
    flipped_5066[0] ^= 1
    for value in (b"", rng.randbytes(29), valid_5066[:-1], bytes(flipped_5066)):
        _closed(lambda value=value: stanag.parse_5066(value), stanag.DefenseStanagError)
    monkeypatch.setattr(stanag, "MAX_BYTES", 4)
    _closed(lambda: stanag.parse_4607(valid_4607), stanag.DefenseStanagError)
    _closed(lambda: stanag.parse_5066(valid_5066), stanag.DefenseStanagError)

