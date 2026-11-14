"""Verify reuse of existing track readers against a published provider fixture.

Source: Cybersource REST API field reference, paymentInformation.card.trackData:
https://docs.cybersource.com/content/dam/documentation/en/reference/api-fields/api-fields-rest.pdf
No new track parser is needed for this lane.
"""
import financial
import rf


TRACK1 = "%B4111111111111111^SMITH/ JOHN ^2412101976110000868000000?"
TRACK2 = ";4111111111111111=24121019761186800000?"


def test_published_cybersource_tracks_existing_reader():
    first, second = rf.magstripe_text(TRACK1 + TRACK2)
    assert first["raw"] == TRACK1
    assert first["name"] == "SMITH/ JOHN"  # rf deliberately strips name edges
    assert first["discretionary"] == "976110000868000000"
    assert second["discretionary"] == "9761186800000"
    for result in (first, second):
        assert result["pan"] == "4111111111111111"
        assert result["expiry"] == "2412"
        assert result["service_code"] == "101"
        assert result["luhn"] is True


def test_existing_emv_packed_track_rendering():
    # Independently derive the tag57 value from the published ASCII track2.
    digits = TRACK2[1:-1].replace("=", "D")
    if len(digits) % 2:
        digits += "F"
    value = bytes.fromhex(digits)
    tlv = b"\x70" + bytes([len(value) + 2]) + b"\x57" + bytes([len(value)]) + value
    result = financial.parse_emv(tlv)
    decoded = result["tlvs"][0]["children"][0]["decoded"]
    assert decoded["track2"] == TRACK2[1:-1]
    assert decoded["track2_parsed"]["pan"] == "4111111111111111"


def test_existing_bit_reader_with_independent_parity_and_lrc():
    symbols = [ord(c) - 48 for c in TRACK2]
    lrc = 0
    for symbol in symbols:
        lrc ^= symbol
    symbols.append(lrc)
    encoded = ""
    for symbol in symbols:
        data = "".join(str((symbol >> bit) & 1) for bit in range(4))
        encoded += data + str(1 - (data.count("1") % 2))
    result = rf.magstripe_bits(encoded)
    assert any(r["text"] == TRACK2 and r["lrc_ok"] is True for r in result)
