#!/usr/bin/env python3
"""B-084: offline MIFARE Ultralight C forge-engine tests.

Everything here is synthetic -- the card dumps are built inside the tests, never copied from a real
challenge card -- and offline: no reader, no socket, no challenge binary. The networked validator
probe is tested separately in test_b084_validator_probe.py.
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import rfid_nfc_depth as rfid  # noqa: E402


FACTORY_KEY = rfid.UL_C_FACTORY_KEYS["nxp-default"]


def _crc32_params():
    # Standard CRC-32 (reflected), identical to zlib.crc32.
    return rfid._ecc().CRCParameters(32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, True, True)


def build_plaintext(*, user_type: int, name: bytes, ts: int, uid7: bytes) -> bytes:
    """A 144-byte CHRONOS-style record: magic, version/user_type, name, u64 BE timestamp, CRC32."""
    pt = bytearray(144)
    pt[0:8] = b"CHRONOS1"
    pt[16] = 0x01
    pt[17] = user_type
    pt[20:20 + len(name)] = name
    pt[40:48] = struct.pack(">Q", ts)
    msg = uid7 + bytes(pt[40:48]) + bytes([pt[17]])
    pt[48:52] = struct.pack(">I", zlib.crc32(msg) & 0xFFFFFFFF)
    return bytes(pt)


def _bcc_inline(uid7: bytes) -> tuple[int, int]:
    # ISO 14443-3 cascade-level BCC for a 7-byte UID, written out here (not via rfid.ultralight_bcc)
    # so the fixtures do not depend on the function under test: BCC0 covers the cascade tag 0x88.
    return (0x88 ^ uid7[0] ^ uid7[1] ^ uid7[2], uid7[3] ^ uid7[4] ^ uid7[5] ^ uid7[6])


def build_ulc_dump(*, uid7: bytes, plaintext: bytes, auth0: int = 0x04, auth1: int = 0x00,
                   key: bytes = FACTORY_KEY, counter: int = 0, key_pages: bytes = bytes(16)) -> bytes:
    """Assemble a 192-byte UL-C dump whose user memory holds ``plaintext`` enciphered with ``key``."""
    assert len(uid7) == 7 and len(plaintext) == 144 and len(key_pages) == 16
    raw = bytearray(192)
    bcc0, bcc1 = _bcc_inline(uid7)
    raw[0:3], raw[3] = uid7[0:3], bcc0
    raw[4:8], raw[8] = uid7[3:7], bcc1
    raw[0x03 * 4:0x03 * 4 + 4] = bytes([0x43, 0x55, 0x01, 0x00])  # OTP marker
    raw[0x29 * 4:0x29 * 4 + 2] = counter.to_bytes(2, "little")
    raw[0x2A * 4] = auth0
    raw[0x2B * 4] = auth1
    # key pages read back as zero on a real card; zero by default, set explicitly for a raw image
    raw[0x2C * 4:0x30 * 4] = key_pages
    raw[16:160] = rfid.encrypt_cbc(plaintext, key, algo="3des", iv=bytes(8))
    return bytes(raw)


SAM_UID = bytes([0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
ADMIN_UID = bytes([0x04, 0xC0, 0xFF, 0xEE, 0x13, 0x37, 0xA5])


@pytest.fixture
def sam_card():
    pt = build_plaintext(user_type=0x01, name=b"Sam", ts=0x63BF4D80, uid7=SAM_UID)
    return build_ulc_dump(uid7=SAM_UID, plaintext=pt)


# ---- layout -------------------------------------------------------------------------------------

def test_parse_ultralight_c_layout(sam_card):
    p = rfid.parse_ultralight_c_dump(sam_card)
    assert p["format"] == "ultralight-c"
    assert p["page_count"] == 48 and p["size_bytes"] == 192
    assert p["uid"] == SAM_UID.hex().upper()
    assert p["bcc0_valid"] and p["bcc1_valid"]
    assert p["auth0"] == 0x04 and p["auth_enabled"] is True
    assert p["auth1"] == 0x00 and p["auth1_write_only"] is False
    assert p["key_first_page"] == 0x2C and p["key_pages_zeroed"] is True


def test_bad_bcc_is_reported():
    pt = build_plaintext(user_type=1, name=b"X", ts=1, uid7=SAM_UID)
    raw = bytearray(build_ulc_dump(uid7=SAM_UID, plaintext=pt))
    raw[3] ^= 0xFF  # corrupt BCC0
    p = rfid.parse_ultralight_c_dump(bytes(raw))
    assert p["bcc0_valid"] is False and p["bcc1_valid"] is True


def test_parse_ntag_dump_delegates_to_ultralight_c(sam_card):
    # A 48-page dump handed to the generic NTAG entry routes to the UL-C parser.
    assert rfid.parse_ntag_dump(sam_card)["format"] == "ultralight-c"


def test_parse_rejects_wrong_geometry():
    with pytest.raises(rfid.RFIDParseError):
        rfid.parse_ultralight_c_dump(bytes(188))  # 47 pages
    with pytest.raises(rfid.RFIDParseError):
        rfid.parse_ultralight_c_dump(bytes(190))  # not page aligned


# ---- 3DES / AES CBC -----------------------------------------------------------------------------

def test_cbc_roundtrip_3des(sam_card):
    pt = build_plaintext(user_type=1, name=b"Sam", ts=0x63BF4D80, uid7=SAM_UID)
    ct = rfid.encrypt_cbc(pt, FACTORY_KEY, algo="3des", iv=bytes(8))
    assert ct != pt
    assert rfid.decrypt_cbc(ct, FACTORY_KEY, algo="3des", iv=bytes(8)) == pt
    assert rfid.decrypt_ul_c_data(sam_card, FACTORY_KEY) == pt


def test_cbc_roundtrip_aes():
    key = bytes(range(16))
    pt = bytes(range(32))
    ct = rfid.encrypt_cbc(pt, key, algo="aes", iv=bytes(16))
    assert rfid.decrypt_cbc(ct, key, algo="aes", iv=bytes(16)) == pt


def test_cbc_rejects_bad_inputs():
    with pytest.raises(rfid.RFIDParseError):
        rfid.encrypt_cbc(b"\x00" * 15, FACTORY_KEY, algo="3des")   # not block aligned
    with pytest.raises(rfid.RFIDParseError):
        rfid.encrypt_cbc(b"\x00" * 16, FACTORY_KEY, algo="rot13")  # unknown algo
    with pytest.raises(rfid.RFIDParseError):
        rfid.encrypt_cbc(b"\x00" * 16, FACTORY_KEY, algo="3des", iv=bytes(16))  # wrong IV size
    with pytest.raises(rfid.RFIDParseError):
        rfid.encrypt_cbc(b"\x00" * 16, b"short", algo="3des")      # bad key length


# ---- CRC identification -------------------------------------------------------------------------

def test_identify_crc_finds_crc32(sam_card):
    pt = rfid.decrypt_ul_c_data(sam_card, FACTORY_KEY)
    msg = SAM_UID + bytes(pt[40:48]) + bytes([pt[17]])
    tag = bytes(pt[48:52])
    matches = rfid.identify_crc(msg, tag)
    assert any(m["name"] == "CRC-32" and m["endian"] == "big" for m in matches)


def test_identify_crc_rejects_wrong_message(sam_card):
    pt = rfid.decrypt_ul_c_data(sam_card, FACTORY_KEY)
    tag = bytes(pt[48:52])
    wrong = SAM_UID + bytes(pt[40:48]) + bytes([0x99])  # wrong user_type in the message
    assert not any(m["name"] == "CRC-32" and m["endian"] == "big"
                   for m in rfid.identify_crc(wrong, tag))


def test_find_crc_message_recovers_fields(sam_card):
    pt = rfid.decrypt_ul_c_data(sam_card, FACTORY_KEY)
    tag = bytes(pt[48:52])
    components = [("uid", SAM_UID), ("ts", bytes(pt[40:48])), ("user_type", bytes([pt[17]]))]
    hits = rfid.find_crc_message(components, tag)
    assert any(h["name"] == "CRC-32" and h["components"] == ["uid", "ts", "user_type"]
               for h in hits)


def test_crc32_catalog_entry_equals_zlib():
    # Guards the identity the forge relies on: the catalogued CRC-32 is zlib.crc32.
    data = b"forge-engine-crc-check"
    assert rfid._ecc().crc_value(data, _crc32_params()) == (zlib.crc32(data) & 0xFFFFFFFF)


# ---- forge --------------------------------------------------------------------------------------

def test_set_ultralight_uid_recomputes_bcc(sam_card):
    out = rfid.set_ultralight_uid(sam_card, ADMIN_UID)
    p = rfid.parse_ultralight_c_dump(out)
    assert p["uid"] == ADMIN_UID.hex().upper()
    assert p["bcc0_valid"] and p["bcc1_valid"]
    # hand-computed: 0x88^0x04^0xC0^0xFF = 0xB3, 0xEE^0x13^0x37^0xA5 = 0x6F
    assert out[3] == 0xB3 and out[8] == 0x6F


def test_forge_admin_card_end_to_end(sam_card):
    crc_spec = {"message": [("uid",), ("plain", 40, 48), ("plain", 17, 18)],
                "at": 48, "params": _crc32_params(), "endian": "big"}
    res = rfid.forge_ul_c_card(
        sam_card, FACTORY_KEY, uid=ADMIN_UID, crc=crc_spec,
        data_edits=[(17, b"\x03"), (20, bytes(24)), (20, b"Admin")])
    assert res["uid"] == ADMIN_UID.hex().upper()
    forged = rfid.decrypt_ul_c_data(res["dump"], FACTORY_KEY)
    assert forged[17] == 0x03                       # user_type set to admin
    assert forged[20:25] == b"Admin"
    # CRC recomputed over the NEW uid, timestamp and user_type
    expect = zlib.crc32(ADMIN_UID + bytes(forged[40:48]) + bytes([0x03])) & 0xFFFFFFFF
    assert struct.unpack(">I", forged[48:52])[0] == expect == res["crc"]
    p = rfid.parse_ultralight_c_dump(res["dump"])
    assert p["uid"] == ADMIN_UID.hex().upper() and p["bcc0_valid"] and p["bcc1_valid"]


def test_forge_rejects_out_of_range_edit(sam_card):
    with pytest.raises(rfid.RFIDParseError):
        rfid.forge_ul_c_card(sam_card, FACTORY_KEY, data_edits=[(143, b"\x01\x02")])


def test_factory_key_is_breakme():
    assert rfid.UL_C_FACTORY_KEYS["nxp-default"] == b"BREAKMEIFYOUCAN!"
    assert len(rfid.UL_C_FACTORY_KEYS["nxp-default"]) == 16


# ---- rf.nfc_info UL-C awareness -----------------------------------------------------------------

def test_rf_nfc_info_surfaces_ultralight_c():
    import rf  # noqa: E402  (flat sibling import on the toolkits path)
    lines = ["Filetype: Flipper NFC device", "Version: 4", "Device type: Mifare Ultralight C",
             "UID: 04 11 22 33 44 55 66", "ATQA: 00 44", "SAK: 00"]
    for page in range(48):
        lines.append(f"Page {page}: 00 00 00 00")
    # overwrite the config pages with meaningful values
    lines[6 + 0x2A] = "Page 42: 04 00 00 00"   # AUTH0
    lines[6 + 0x2B] = "Page 43: 00 00 00 00"   # AUTH1
    info = rf.nfc_info("\n".join(lines) + "\n")
    assert info is not None and "ultralight_c" in info
    assert info["ultralight_c"]["auth0"] == 0x04
    assert info["ultralight_c"]["key_pages_present"] is True
    assert info["ultralight_c"]["key_pages_zeroed"] is True


# ---- round-1 verification fixes: fixed known answers and boundaries -----------------------------

def test_ultralight_bcc_known_values():
    # Hand-computed: BCC0 = 0x88 ^ 0x04 ^ 0x11 ^ 0x22 = 0xBF, BCC1 = 0x33 ^ 0x44 ^ 0x55 ^ 0x66 = 0x44.
    assert rfid.ultralight_bcc(SAM_UID) == (0xBF, 0x44)
    assert rfid.ultralight_bcc(ADMIN_UID) == (0xB3, 0x6F)


def test_parse_flags_bcc_without_cascade_tag():
    # A BCC0 computed without the 0x88 cascade tag is wrong and must be reported invalid.
    pt = build_plaintext(user_type=1, name=b"X", ts=1, uid7=SAM_UID)
    raw = bytearray(build_ulc_dump(uid7=SAM_UID, plaintext=pt))
    raw[3] = SAM_UID[0] ^ SAM_UID[1] ^ SAM_UID[2]
    assert rfid.parse_ultralight_c_dump(bytes(raw))["bcc0_valid"] is False


@pytest.mark.parametrize("auth0, enabled", [(0x2F, True), (0x30, False), (0x2E, True), (0xFF, False)])
def test_auth0_window_boundary(auth0, enabled):
    pt = build_plaintext(user_type=1, name=b"X", ts=1, uid7=SAM_UID)
    p = rfid.parse_ultralight_c_dump(build_ulc_dump(uid7=SAM_UID, plaintext=pt, auth0=auth0))
    assert p["auth0"] == auth0 and p["auth_enabled"] is enabled


@pytest.mark.parametrize("auth1, write_only", [(0x01, True), (0x00, False), (0x02, False), (0x03, True)])
def test_auth1_write_only_bit(auth1, write_only):
    pt = build_plaintext(user_type=1, name=b"X", ts=1, uid7=SAM_UID)
    p = rfid.parse_ultralight_c_dump(build_ulc_dump(uid7=SAM_UID, plaintext=pt, auth1=auth1))
    assert p["auth1"] == auth1 and p["auth1_write_only"] is write_only


def test_counter_and_raw_key_pages():
    pt = build_plaintext(user_type=1, name=b"X", ts=1, uid7=SAM_UID)
    keyp = bytes(range(0x10, 0x20))
    p = rfid.parse_ultralight_c_dump(
        build_ulc_dump(uid7=SAM_UID, plaintext=pt, counter=0x1234, key_pages=keyp))
    assert p["counter"] == 0x1234
    assert p["key_pages"] == keyp.hex() and p["key_pages_zeroed"] is False


def test_crc_a_known_answers():
    cat = dict(rfid._crc_catalog())
    params = cat["CRC-16/ISO-IEC-14443-3-A"]
    # Published check value of CRC-16/ISO-IEC-14443-3-A over b"123456789".
    assert rfid._ecc().crc_value(b"123456789", params) == 0xBF05
    # ISO/IEC 14443-3 Annex B example: data 00 00 -> CRC_A bytes sent A0 1E (LSB first).
    matches = rfid.identify_crc(b"\x00\x00", b"\xA0\x1E")
    assert any(m["name"] == "CRC-16/ISO-IEC-14443-3-A" and m["endian"] == "little" for m in matches)
    assert not any(m["name"] == "CRC-16/ISO-IEC-14443-3-A" and m["endian"] == "big" for m in matches)


def test_identify_crc_little_endian_tag(sam_card):
    pt = rfid.decrypt_ul_c_data(sam_card, FACTORY_KEY)
    msg = SAM_UID + bytes(pt[40:48]) + bytes([pt[17]])
    tag_le = struct.pack("<I", zlib.crc32(msg) & 0xFFFFFFFF)
    matches = rfid.identify_crc(msg, tag_le)
    assert [(m["name"], m["endian"]) for m in matches] == [("CRC-32", "little")]


def test_identify_crc_needs_every_sample_to_match():
    m1, m2 = b"record-one", b"record-two"
    t1 = struct.pack(">I", zlib.crc32(m1))
    t2 = struct.pack(">I", zlib.crc32(m2))
    assert any(m["name"] == "CRC-32" for m in rfid.identify_crc_samples([(m1, t1), (m2, t2)]))
    bad = bytes([t2[0] ^ 1]) + t2[1:]
    assert rfid.identify_crc_samples([(m1, t1), (m2, bad)]) == []
    assert rfid.identify_crc(m1, t1, samples=[(m2, bad)]) == []
    with pytest.raises(rfid.RFIDParseError):
        rfid.identify_crc_samples([(m1, t1), (m2, t2[:2])])  # mixed tag widths


def test_find_crc_message_finds_a_later_run(sam_card):
    pt = rfid.decrypt_ul_c_data(sam_card, FACTORY_KEY)
    tag = bytes(pt[48:52])
    components = [("magic", bytes(pt[0:8])), ("uid", SAM_UID), ("ts", bytes(pt[40:48])),
                  ("user_type", bytes([pt[17]]))]
    hits = rfid.find_crc_message(components, tag)
    assert [(h["name"], h["endian"], h["components"]) for h in hits] == \
        [("CRC-32", "big", ["uid", "ts", "user_type"])]


def test_find_crc_records_over_several_handout_records():
    records = []
    for uid, utype, ts in ((SAM_UID, 1, 0x63BF4D80), (ADMIN_UID, 2, 0x11223344)):
        pt = build_plaintext(user_type=utype, name=b"N", ts=ts, uid7=uid)
        comps = [("uid", uid), ("ts", pt[40:48]), ("user_type", pt[17:18])]
        records.append((comps, pt[48:52]))
    hits = rfid.find_crc_records(records)
    assert [(h["name"], h["components"]) for h in hits] == [("CRC-32", ["uid", "ts", "user_type"])]
    # One record whose tag follows a different definition: no run explains every record.
    comps0, tag0 = records[0]
    records.append((comps0, bytes([tag0[0] ^ 0x80]) + tag0[1:]))
    assert rfid.find_crc_records(records) == []
    with pytest.raises(rfid.RFIDParseError):
        rfid.find_crc_records([records[0], ([("other", b"x")], tag0)])


def test_forge_crc_offset_guard(sam_card):
    spec = {"message": [("uid",)], "params": _crc32_params(), "endian": "big"}
    with pytest.raises(rfid.RFIDParseError, match="CRC write offset"):
        rfid.forge_ul_c_card(sam_card, FACTORY_KEY, crc={**spec, "at": 142})
    with pytest.raises(rfid.RFIDParseError, match="CRC write offset"):
        rfid.forge_ul_c_card(sam_card, FACTORY_KEY, crc={**spec, "at": -1})
    # the last in-range offset (140..143 for 4 bytes) is accepted and written
    res = rfid.forge_ul_c_card(sam_card, FACTORY_KEY, crc={**spec, "at": 140})
    assert res["plaintext"][140:144] == struct.pack(">I", zlib.crc32(SAM_UID))


def test_missing_pycryptodome_fails_loudly(monkeypatch):
    monkeypatch.setitem(sys.modules, "Crypto.Cipher", None)
    with pytest.raises(rfid.RFIDCryptoUnavailable, match="pycryptodome"):
        rfid.encrypt_cbc(bytes(16), FACTORY_KEY, algo="3des")
    with pytest.raises(rfid.RFIDCryptoUnavailable):
        rfid.decrypt_cbc(bytes(16), bytes(16), algo="aes")


# ---- rf.nfc_info: UL-C block only on a real UL-C -------------------------------------------------

def _flipper_nfc(device_type: str, pages: dict[int, bytes], total: int, subtype: str | None = None) -> str:
    lines = ["Filetype: Flipper NFC device", "Version: 4", f"Device type: {device_type}",
             "UID: 04 11 22 33 44 55 66", "ATQA: 00 44", "SAK: 00"]
    if subtype:
        lines.append(f"NTAG/Ultralight type: {subtype}")
    for page in range(total):
        lines.append(f"Page {page}: " + " ".join(f"{b:02X}" for b in pages.get(page, bytes(4))))
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize("device_type, subtype, total", [
    ("NTAG215", None, 135), ("NTAG213", None, 45), ("NTAG216", None, 231),
    ("NTAG/Ultralight", "NTAG215", 135), ("Mifare Ultralight EV1 21", None, 41),
])
def test_rf_nfc_info_no_ultralight_c_block_for_ntag(device_type, subtype, total):
    import rf  # noqa: E402
    # On an NTAG21x, pages 0x2A/0x2B are CFG/PWD bytes: they must not be reported as AUTH0/AUTH1.
    pages = {0x2A: bytes([0x11, 0, 0, 0]), 0x2B: bytes([0x22, 0, 0, 0]), 0x2C: b"\xff\xff\xff\xff"}
    info = rf.nfc_info(_flipper_nfc(device_type, pages, total, subtype))
    assert info is not None and info["pages"]
    assert "ultralight_c" not in info


def test_rf_nfc_info_ultralight_c_by_page_count_and_key_pages():
    import rf  # noqa: E402
    pages = {0x2A: bytes([0x30, 0, 0, 0]), 0x2B: bytes([0x01, 0, 0, 0]),
             0x2C: b"BREA", 0x2D: b"KMEI", 0x2E: b"FYOU", 0x2F: b"CAN!"}
    # Generic type line, no subtype: the 48-page geometry identifies an UL-C.
    info = rf.nfc_info(_flipper_nfc("NTAG/Ultralight", pages, 48))
    ulc = info["ultralight_c"]
    assert ulc["auth0"] == 0x30 and ulc["auth1"] == 0x01
    assert ulc["key_pages_present"] is True
    assert ulc["key_pages"] == b"BREAKMEIFYOUCAN!".hex() and ulc["key_pages_zeroed"] is False
    # Same 48 pages but the type names an NTAG model: no UL-C block.
    assert "ultralight_c" not in rf.nfc_info(_flipper_nfc("NTAG/Ultralight", pages, 48, "NTAG213"))
    # Named UL-C with a partial read (key pages missing): block present, key pages unknown.
    partial = rf.nfc_info(_flipper_nfc("Mifare Ultralight C", {0x2A: bytes([0x04, 0, 0, 0])}, 0x2C))
    assert partial["ultralight_c"]["auth0"] == 0x04
    assert partial["ultralight_c"]["key_pages_present"] is False
    assert partial["ultralight_c"]["key_pages_zeroed"] is False


# ---- round-2 verification fixes ------------------------------------------------------------------

def test_package_import_identify_crc_in_clean_interpreter():
    # Imported as ``solvers.toolkits.rfid_nfc_depth`` with only the checkout root on sys.path (no
    # flat toolkits dir), the ecc dependency must still load. A child interpreter is used because this
    # test process already has solvers/toolkits on sys.path, which would hide the bug.
    import subprocess
    code = (
        "import sys, zlib\n"
        f"sys.path[:0] = [{str(REPO)!r}]\n"
        "from solvers.toolkits import rfid_nfc_depth as r\n"
        "tag = (zlib.crc32(b'synthetic') & 0xFFFFFFFF).to_bytes(4, 'big')\n"
        "names = [m['name'] for m in r.identify_crc(b'synthetic', tag)]\n"
        "assert 'CRC-32' in names, names\n"
        "assert r._ecc().__name__ == 'solvers.toolkits.ecc', r._ecc().__name__\n"
        "print('ok')\n")
    proc = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                          timeout=600, cwd=str(REPO.parent))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ok"


def test_ecc_file_loader_registers_module_before_exec():
    # The last-resort loader must register the module before exec: ecc's @dataclass under
    # ``from __future__ import annotations`` resolves its module through sys.modules.
    sys.modules.pop(rfid._ECC_FILE_MODULE_NAME, None)
    try:
        module = rfid._load_ecc_by_file()
        params = module.CRCParameters(32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, True, True)
        assert module.crc_value(b"123456789", params) == 0xCBF43926   # CRC-32 check value
        assert sys.modules[rfid._ECC_FILE_MODULE_NAME] is module
        assert rfid._load_ecc_by_file() is module                    # cached, not re-executed
    finally:
        sys.modules.pop(rfid._ECC_FILE_MODULE_NAME, None)


def test_forge_crc_over_page_and_bytes_refs(sam_card):
    # CRC message = all of dump page 0 (UID0..2 + BCC0 of the NEW uid) + a literal hex string +
    # plaintext[17:18] + literal raw bytes. The tag is hand-computed with zlib.crc32 over bytes
    # assembled here (inline BCC helper), not by the editor.
    literal = "c0ffee"
    crc_spec = {"message": [("page", 0, 0, 4), ("bytes", literal), ("plain", 17, 18),
                            ("bytes", b"\x5a")],
                "at": 48, "params": _crc32_params(), "endian": "little"}
    res = rfid.forge_ul_c_card(sam_card, FACTORY_KEY, uid=ADMIN_UID, crc=crc_spec,
                               data_edits=[(17, b"\x03")])
    page0 = bytes(ADMIN_UID[0:3]) + bytes([_bcc_inline(ADMIN_UID)[0]])
    expect = zlib.crc32(page0 + bytes.fromhex(literal) + b"\x03" + b"\x5a") & 0xFFFFFFFF
    forged = rfid.decrypt_ul_c_data(res["dump"], FACTORY_KEY)
    assert res["crc"] == expect
    assert struct.unpack("<I", forged[48:52])[0] == expect


def test_rf_nfc_info_no_ultralight_c_block_for_large_generic_dump():
    import rf  # noqa: E402
    # A generic type line with no model subtype: only the 48-page geometry means UL-C, so a 135-page
    # (NTAG215-sized) or 49-page dump must not be tagged as one.
    pages = {0x2A: bytes([0x11, 0, 0, 0]), 0x2B: bytes([0x22, 0, 0, 0])}
    for device_type in ("NTAG/Ultralight", "Mifare Ultralight"):
        for total in (135, 49):
            info = rf.nfc_info(_flipper_nfc(device_type, pages, total))
            assert info is not None and len(info["pages"]) == total
            assert "ultralight_c" not in info, (device_type, total)
        assert "ultralight_c" in rf.nfc_info(_flipper_nfc(device_type, pages, 48))
