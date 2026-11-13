"""Published OP25/TIA layouts and independent fixtures for passive P25 parsing."""
from __future__ import annotations

import json
import random

import pytest

import sec_lmr_p25 as p25


SYNC1 = 0x5575F5FF77FF
SYNC2 = 0x575D57F7FF

# Published by OP25 p25craft.py; packets were checked against TIA-102.BAAB-B.
NIDS_293 = {
    0x0: 0x29300F3B5DF801C2,
    0x3: 0x29333977728CED6E,
    0x5: 0x293555EF2C653437,
    0x7: 0x2937F88514ABAECC,
    0xA: 0x293ABA93BEC26A2B,
    0xC: 0x293CD60BE02BB372,
    0xF: 0x293FE047CF5F5FDE,
}

PHASE2_DUID = {
    0: 0x00, 1: 0x17, 2: 0x2E, 3: 0x39,
    4: 0x4B, 5: 0x5C, 6: 0x65, 7: 0x72,
    8: 0x8D, 9: 0x9A, 10: 0xA3, 11: 0xB4,
    12: 0xC6, 13: 0xD1, 14: 0xE8, 15: 0xFF,
}


def packed(bits: str) -> bytes:
    assert bits and set(bits) <= {"0", "1"}
    padded = bits + "0" * (-len(bits) % 8)
    return int(padded, 2).to_bytes(len(padded) // 8, "big")


def field(value: int, width: int) -> str:
    assert 0 <= value < (1 << width)
    return f"{value:0{width}b}"


def add_status(logical: str, status: str = "01") -> str:
    """TIA rule: insert one status dibit after every 70 non-status bits."""
    assert len(status) == 2
    chunks = []
    for offset in range(0, len(logical), 70):
        chunk = logical[offset:offset + 70]
        chunks.append(chunk)
        if len(chunk) == 70:
            chunks.append(status)
    return "".join(chunks)


def tdu(nid: int = NIDS_293[3], status: str = "01") -> str:
    logical = field(SYNC1, 48) + field(nid, 64) + "0" * 28
    assert len(logical) == 140
    physical = add_status(logical, status)
    assert len(physical) == 144
    return physical


def phase2_burst(duid: int, *, corrupt_bit: bool = False) -> str:
    dibits = [0] * 180
    prefix = field(SYNC2, 40)
    dibits[:20] = [int(prefix[i:i + 2], 2) for i in range(0, 40, 2)]
    code = PHASE2_DUID[duid] ^ (1 if corrupt_bit else 0)
    symbols = [(code >> shift) & 3 for shift in (6, 4, 2, 0)]
    for offset, symbol in zip((20, 57, 142, 179), symbols):
        dibits[offset] = symbol
    return "".join(f"{symbol:02b}" for symbol in dibits)


def clean(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except p25.SecLmrP25Error:
        return None
    except BaseException as exc:  # pragma: no cover - assertion diagnostic
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")


def test_published_nid_vector_and_status_removal():
    report = p25.parse_phase1_frame(packed(tdu()), 144)
    assert report["sync_hex"] == "5575f5ff77ff"
    assert report["nac"] == 0x293
    assert report["duid"] == 3
    assert report["data_unit"] == "TDU"
    assert report["nid_received_hex"] == "29333977728ced6e"
    assert report["nid_corrected_bits"] == 0
    assert [item["value"] for item in report["status_symbols"]] == [1, 1]
    assert report["structural_bit_length"] == 140


@pytest.mark.parametrize("duid", [0, 3, 5, 7, 10, 15])
def test_all_fixed_phase1_frame_layouts_use_published_nids(duid):
    lengths = {0: 792, 3: 144, 5: 1728, 7: 720, 10: 1728, 15: 432}
    logical_length = lengths[duid] - 2 * (lengths[duid] // 72)
    logical = field(SYNC1, 48) + field(NIDS_293[duid], 64)
    logical += "0" * (logical_length - len(logical))
    raw = add_status(logical, "11")
    assert len(raw) == lengths[duid]
    report = p25.parse_phase1_frame(packed(raw), len(raw))
    assert report["duid"] == duid
    assert report["transmitted_bit_length"] == lengths[duid]
    if duid in (5, 10):
        voices = [item for item in report["regions"] if item["name"].startswith("voice_")]
        fragments = [item for item in report["regions"] if "fragment_" in item["name"]]
        assert len(voices) == 9
        assert all(item["bit_length"] == 144 for item in voices)
        assert len(fragments) == 6


@pytest.mark.parametrize("damage", [1 << 20, 1 << 63])
def test_bch_decoder_corrects_one_supplied_nid_error(damage):
    # Exercise both a parity-region error and an error in the systematic NAC.
    damaged = NIDS_293[3] ^ damage
    report = p25.parse_phase1_frame(packed(tdu(damaged)), 144)
    assert report["nac"] == 0x293 and report["duid"] == 3
    assert report["nid_corrected_bits"] == 1


def test_published_packet_data_nid_with_one_channel_block():
    # A minimum structural fixture here is FS+NID plus one 196-bit packet
    # channel block.  Status insertion is performed independently above.
    logical = field(SYNC1, 48) + field(NIDS_293[0xC], 64) + "0" * 196
    physical = add_status(logical, "10")
    report = p25.parse_phase1_frame(packed(physical), len(physical))
    assert report["nac"] == 0x293
    assert report["duid"] == 0xC and report["data_unit"] == "PDU"
    assert report["regions"][-1]["bit_length"] == 196


def test_corrected_hdu_link_control_and_encryption_sync_fields():
    mi = bytes.fromhex("010203040506070809")
    hdu = mi + bytes((0x01, 0x84)) + bytes.fromhex("12344567")
    assert len(hdu) == 15
    report = p25.parse_hdu_fields(hdu)
    assert report["message_indicator_hex"] == mi.hex()
    assert report["manufacturer_id"] == 1
    assert report["algorithm"]["algid"] == 0x84
    assert report["key_id"] == 0x1234 and report["talkgroup_id"] == 0x4567

    # P=0, SF=0, LCO=0; MFID; service options; reserved; TGID; source.
    lcw = bytes.fromhex("0001c5003456123456")
    lc = p25.parse_link_control(lcw)
    assert lc["protected"] is False and lc["lco"] == 0
    assert lc["service_options"]["protected"] is True
    assert lc["talkgroup_id"] == 0x3456
    assert lc["source_id"] == 0x123456

    ess = mi + b"\x81" + bytes.fromhex("beef")
    sync = p25.parse_encryption_sync(ess)
    assert sync["message_indicator_hex"] == mi.hex()
    assert sync["algorithm"]["algid"] == 0x81
    assert sync["key_id"] == 0xBEEF


@pytest.mark.parametrize(("duid", "name", "voices"), [
    (0, "4V", 4), (6, "2V", 2), (3, "SACCH", 0),
    (4, "LCCH", 0), (9, "FACCH", 0), (12, "SACCH", 0),
    (13, "LCCH", 0), (15, "FACCH", 0),
])
def test_phase2_distributed_duid_and_voice_regions(duid, name, voices):
    report = p25.parse_phase2_burst(packed(phase2_burst(duid)))
    assert report["phase2_sync_match"] is True
    assert report["duid"] == duid and name in report["duid_name"]
    assert report["duid_corrected_hex"] == f"{PHASE2_DUID[duid]:02x}"
    assert report["duid_corrected_bits"] == 0
    assert len(report.get("voice_regions", [])) == voices
    for item in report.get("voice_regions", []):
        assert item["coded_bits"] == 72
        assert item["physical_end_dibit"] - item["physical_start_dibit"] == 36
    if duid in (3, 4, 9):
        assert report["acch_scrambled"] is True
    if duid in (12, 13, 15):
        assert report["acch_scrambled"] is False


def test_phase2_one_bit_duid_correction_and_crypto_context():
    report = p25.parse_phase2_burst(packed(phase2_burst(6, corrupt_bit=True)))
    assert report["duid"] == 6 and report["duid_corrected_bits"] == 1
    expected = {0x80: "clear", 0x81: "DES", 0x84: "AES", 0xAA: "ADP"}
    for algid, label in expected.items():
        assert label.lower() in json.dumps(p25.encryption_context(algid)).lower()
    context_report = p25.technology_context()
    assert context_report["phase1"]["dibit_deviation_khz"] == {
        "01": 1.8, "00": 0.6, "10": -0.6, "11": -1.8,
    }
    context = json.dumps(context_report)
    assert all(term in context for term in ("C4FM", "IMBE", "AMBE", "TDMA"))


def test_fail_closed_random_and_guarded_cli(tmp_path, capsys):
    rng = random.Random(0x2525)
    for size in range(80):
        blob = rng.randbytes(size)
        clean(p25.parse_phase1_frame, blob, size * 8 if size else 0)
        clean(p25.parse_phase2_burst, blob)
    for malformed in (None, bytearray(b"x"), memoryview(b"x"), {}, [], "00"):
        clean(p25.parse_phase1_frame, malformed, 8)
        clean(p25.parse_phase2_burst, malformed)
        clean(p25.parse_hdu_fields, malformed)
        clean(p25.parse_link_control, malformed)
        clean(p25.parse_encryption_sync, malformed)
    clean(p25.encryption_context, True)

    path = tmp_path / "tdu.bin"
    path.write_bytes(packed(tdu()))
    assert p25.main(["phase1", str(path), "--bits", "144"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["nac"] == 0x293 and report["duid"] == 3
    assert p25.main(["--help"]) == 0
    capsys.readouterr()
    assert p25.main([]) == 2

