"""Published AWB vector and independently specified IATA composition cases."""
import json
import pytest
import transport_cargo as cargo


def test_abf_published_modulus_vector():
    # ABF: 1234567 / 7 = 176366 remainder 5. Airline prefix is not checksummed.
    # https://www.abf.gov.au/sdg-subsite/Pages/Check-Digit-Algorithms/Air-Waybill-Number-Validation.aspx
    for prefix in ("000", "020", "999"):
        out = cargo.parse_awb(prefix + "-12345675")
        assert out["checksum_valid"] is True
        assert out["serial"] == "1234567"
        assert out["check_digit"] == 5
    assert cargo.parse_awb("020-12345676")["checksum_valid"] is False
    assert cargo.parse_awb("02000000000")["serial"] == "0000000"
    assert cargo.parse_awb("02000000000")["checksum_valid"] is True


@pytest.mark.parametrize("value,type_code,serial,owner", [
    ("AKE12345LH", "AKE", "12345", "LH"),
    ("PMC1234FX", "PMC", "1234", "FX"),
    ("A2NA1235X", "A2N", "A123", "5X"),
])
def test_iata_uld_composition(value, type_code, serial, owner):
    # IATA: 3-character type + 4/5-character serial + 2-character owner.
    # dnata SOP clarifies alphanumeric serial first position and numeric remainder.
    out = cargo.parse_uld(value)
    assert (out["type_code"], out["serial"], out["owner_code"]) == (type_code, serial, owner)
    assert not out["registry_verified"]


@pytest.mark.parametrize("bad", [None, True, 12345675, {}, [], b"AKE12345LH", "\ud800", "a" * 65])
def test_malformed_type_fails_closed(bad):
    for fn in (cargo.parse_awb, cargo.parse_uld):
        with pytest.raises(cargo.TransportCargoError):
            fn(bad)


@pytest.mark.parametrize("bad", ["AKE123LH", "AKE123456LH", "AKE12A4LH", "1KE12345LH", "ake12345lh", "AKE1234-", "AKE 12345 LH"])
def test_uld_rejects_bad_layout(bad):
    with pytest.raises(cargo.TransportCargoError):
        cargo.parse_uld(bad)


@pytest.mark.parametrize("bad", ["020-1234567", "020--12345675", "０２０12345675", "020/12345675", "020123456755"])
def test_awb_rejects_bad_layout(bad):
    with pytest.raises(cargo.TransportCargoError):
        cargo.parse_awb(bad)


def test_cli(capsys):
    assert cargo.main(["awb", "020-12345675"]) == 0
    assert json.loads(capsys.readouterr().out)["checksum_valid"]
    assert cargo.main(["--help"]) == 0
    assert cargo.main([]) == 2
    assert cargo.main(["uld", "bad"]) == 2
