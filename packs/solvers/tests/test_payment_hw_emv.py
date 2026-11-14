"""EMV Book 3 section 6.5/annex B grammar, independently assembled fixtures.

These are synthetic protocol vectors, not claims of valid issuer-generated MACs.
Source: https://mech.vub.ac.be/teaching/info/mechatronica/finished_projects_2007/
Groep%201/Smartcard_files/EMV%20v4.1%20Book%203.pdf
"""
import random

import pytest

import payment_hw_emv as emv


def reference_tlv(tag, value):
    # Independent BER encoder for synthetic input, never engine output.
    if len(value) < 128:
        length = bytes([len(value)])
    else:
        size = (len(value).bit_length() + 7) // 8
        length = bytes([128 + size]) + len(value).to_bytes(size, "big")
    return bytes.fromhex(tag) + length + value


@pytest.mark.parametrize("cid,kind", [(0, "AAC"), (0x40, "TC"), (0x80, "ARQC"), (0x88, "ARQC")])
def test_format1_and_format2_same_independent_fields(cid, kind):
    # EMV Book3 format1 is CID[1] ATC[2] AC[8] optional IAD[0..32].
    ac = bytes.fromhex("1234567890ABCDEF")
    iad = bytes.fromhex("06010A03A00000")
    positional = reference_tlv("80", bytes([cid]) + b"\x01\x23" + ac + iad)
    tagged = reference_tlv("77", b"".join([
        reference_tlv("9F10", iad), reference_tlv("9F26", ac),
        reference_tlv("9F36", b"\x01\x23"), reference_tlv("9F27", bytes([cid])),
    ]))
    for fixture in (positional, tagged):
        result = emv.parse_cryptogram(fixture)
        assert result["cryptogram_type"] == kind
        assert result["atc"] == 291  # binary, not decimal BCD 123
        assert result["application_cryptogram"] == "1234567890ABCDEF"
        assert result["issuer_application_data"] == "06010A03A00000"
        assert result["cryptogram_verified"] is False


def test_cda_retains_signed_data_without_claiming_ac():
    fields = reference_tlv("9F27", b"\x40") + reference_tlv("9F36", b"\x00\x01")
    fields += reference_tlv("9F4B", bytes(range(128)))
    result = emv.parse_cryptogram(reference_tlv("77", fields))
    assert result["application_cryptogram"] is None
    assert result["signed_dynamic_application_data"] == bytes(range(128)).hex().upper()


def test_empty_iad_and_inherited_emv_padding():
    result = emv.parse_cryptogram("0077179F2701809F360200019F260801020304050607089F1000FF")
    assert result["issuer_application_data"] == ""
    assert result["cryptogram_verified"] is False


@pytest.mark.parametrize("fixture", [
    "800B8000010102030405060708",  # complete, used for strict truncation checks below
    "77149F2701809F360200019F26080102030405060708",
])
def test_cryptogram_all_truncations(fixture):
    data = bytes.fromhex(fixture)
    assert emv.parse_cryptogram(data)["atc"] == 1
    for end in range(len(data)):
        with pytest.raises(emv.PaymentEMVError):
            emv.parse_cryptogram(data[:end])


@pytest.mark.parametrize("data", [
    "800AC0000000000000000000", "800BC000000000000000000000", "7700", "8000",
    "7780", "9F270180", "800B80000101020304050607089F270180",
])
def test_bad_cryptograms(data):
    with pytest.raises(emv.PaymentEMVError):
        emv.parse_cryptogram(data)


def test_duplicate_and_wrong_sized_fields():
    good = reference_tlv("9F27", b"\x80") + reference_tlv("9F36", b"\x00\x01")
    good += reference_tlv("9F26", b"12345678")
    for bad in (good + reference_tlv("9F27", b"\x40"),
                good.replace(b"\x9f\x36\x02\x00\x01", b"\x9f\x36\x01\x01"),
                good + reference_tlv("9F10", b"x" * 33)):
        with pytest.raises(emv.PaymentEMVError):
            emv.parse_cryptogram(reference_tlv("77", bad))


def test_gpo_templates_and_afl():
    # AIP=5800; AFL: SFI1 records1..3 with2 ODA; SFI30 record255 with1.
    afl = bytes([8, 1, 3, 2, 240, 255, 255, 1])
    for fixture in (reference_tlv("80", b"\x58\x00" + afl),
                    reference_tlv("77", reference_tlv("94", afl) + reference_tlv("82", b"\x58\x00"))):
        result = emv.parse_gpo(fixture)
        assert result["aip"] == "5800"
        assert result["afl"] == [
            {"sfi": 1, "first_record": 1, "last_record": 3, "offline_authentication_records": 2},
            {"sfi": 30, "first_record": 255, "last_record": 255, "offline_authentication_records": 1},
        ]
    assert emv.parse_gpo("770482025800")["afl"] is None


@pytest.mark.parametrize("data", ["080102", "00010100", "09010100", "F8010100", "08000100", "08020100", "08010102"])
def test_invalid_afl(data):
    with pytest.raises(emv.PaymentEMVError):
        emv.parse_afl(data)


def test_cdol_exact_mapping_preserves_duplicate_tags():
    # Common CDOL1: amount6, other6, country2, TVR5, currency2, date3,
    # type1, UN4; duplicate UN included to catch lossy dict implementations.
    specs = [("9F02", "000000001234"), ("9F03", "000000000000"),
             ("9F1A", "0840"), ("95", "0000000000"), ("5F2A", "0840"),
             ("9A", "261106"), ("9C", "00"), ("9F37", "DEADBEEF"), ("9F37", "11223344")]
    dol = b"".join(bytes.fromhex(tag) + bytes([len(value) // 2]) for tag, value in specs)
    payload = bytes.fromhex("".join(value for _, value in specs))
    result = emv.map_dol(dol, payload)
    assert [(x["tag"], x["value"]) for x in result] == specs
    assert result[0]["decoded"]["numeric"] == "1234"
    assert result[-1]["offset"] == 29
    for wrong in (payload[:-1], payload + b"\x00"):
        with pytest.raises(emv.PaymentEMVError):
            emv.map_dol(dol, wrong)


def test_dol_lengths_are_not_ber_and_zero_lengths_are_kept():
    result = emv.map_dol("9F37805F2A00", bytes(range(128)))
    assert [r["length"] for r in result] == [128, 0]
    assert result[1]["value"] == ""
    assert emv.map_dol("", b"") == []


@pytest.mark.parametrize("data", ["9F", "9F37", "0000", "FF00", "7701", "9F800100", "9FFF"])
def test_bad_dol(data):
    with pytest.raises(emv.PaymentEMVError):
        emv.parse_dol(data)


def test_arpc_methods_have_different_boundaries():
    data = "0102030405060708ABCD"
    first = emv.parse_issuer_authentication(data, 1)
    second = emv.parse_issuer_authentication(data, 2)
    assert first["arpc"] == "0102030405060708"
    assert first["card_status_update"] is None
    assert second["arpc"] == "01020304"
    assert second["card_status_update"] == "05060708"
    assert first["issuer_additional_data"] == second["issuer_additional_data"] == "ABCD"
    for method in (None, True, [], "1", 0, 3):
        with pytest.raises(emv.PaymentEMVError):
            emv.parse_issuer_authentication(data, method)


@pytest.mark.parametrize("value", [None, 12, [], {}, object(), "QQ", "0", "１２"])
def test_contract_for_wrong_types(value):
    for function in (emv.parse_cryptogram, emv.parse_gpo, emv.parse_afl, emv.parse_dol):
        with pytest.raises(emv.PaymentEMVError):
            function(value)


def test_seeded_malformed_inputs_never_leak_stdlib_exceptions():
    rng = random.Random(7816)
    for _ in range(250):
        data = rng.randbytes(rng.randrange(60))
        for function in (emv.parse_cryptogram, emv.parse_gpo, emv.parse_afl, emv.parse_dol):
            try:
                function(data)
            except emv.PaymentEMVError:
                pass


def test_cli(tmp_path, capsys):
    path = tmp_path / "response.hex"
    path.write_text("800B8000010102030405060708")
    assert emv.main(["cryptogram", str(path), "--hex"]) == 0
    assert '"cryptogram_type": "ARQC"' in capsys.readouterr().out
    assert emv.main(["--help"]) == 0
    assert emv.main([]) == 2
    assert emv.main(["gpo", str(tmp_path / "absent")]) == 2
    path.write_bytes(b"\xff")
    assert emv.main(["gpo", str(path), "--hex"]) == 2
    assert emv.main(["gpo", "\x00"]) == 2


def test_cli_noninteger_systemexit(monkeypatch):
    def stop(*args, **kwargs):
        raise SystemExit("not an integer")
    monkeypatch.setattr(emv.argparse.ArgumentParser, "parse_args", stop)
    assert emv.main([]) == 2
