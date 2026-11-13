"""Independent ICD-layout vectors for ``sec_gnss_nav``.

The builders below implement published bit layouts and integrity equations in
test code.  They never call an engine encoder or use engine masks/constants.
"""

import random

import pytest
from crccheck.crc import Crc24LteA

import sec_gnss_nav as m


def bits(value, width):
    return f"{value & ((1 << width) - 1):0{width}b}"


def packed(text):
    padding = (-len(text)) % 8
    return int(text + "0" * padding, 2).to_bytes((len(text) + 7) // 8, "big")


def crc24q_bits(text):
    register = 0
    for character in text:
        feedback = ((register >> 23) & 1) ^ int(character)
        register = (register << 1) & 0xFFFFFF
        if feedback:
            register ^= 0x864CFB
    return register


PARITY_TERMS = (
    ("29", 1, 2, 3, 5, 6, 10, 11, 12, 13, 14, 17, 18, 20, 23),
    ("30", 2, 3, 4, 6, 7, 11, 12, 13, 14, 15, 18, 19, 21, 24),
    ("29", 1, 3, 4, 5, 7, 8, 12, 13, 14, 15, 16, 19, 20, 22),
    ("30", 2, 4, 5, 6, 8, 9, 13, 14, 15, 16, 17, 20, 21, 23),
    ("30", 1, 3, 5, 6, 7, 9, 10, 14, 15, 16, 17, 18, 21, 22, 24),
    ("29", 3, 5, 6, 8, 9, 10, 11, 13, 15, 19, 22, 23, 24),
)


def lnav_parity(source24, previous29=0, previous30=0):
    source = [int(ch) for ch in bits(source24, 24)]
    prior = {"29": previous29, "30": previous30}
    result = ""
    for row in PARITY_TERMS:
        value = prior[row[0]]
        for position in row[1:]:
            value ^= source[position - 1]
        result += str(value)
    return result


def lnav_subframe(data_words):
    # IS-GPS-200 makes word-10 data bits 23/24 non-information-bearing and
    # selects them so the next subframe always starts with D29*=D30*=0.
    for tail in range(4):
        words = list(data_words)
        words[-1] = (words[-1] & ~3) | tail
        previous29 = previous30 = 0
        wire = ""
        for source in words:
            source_text = bits(source, 24)
            parity = lnav_parity(source, previous29, previous30)
            transmitted = "".join(str(int(ch) ^ previous30) for ch in source_text) + parity
            wire += transmitted
            previous29, previous30 = int(transmitted[-2]), int(transmitted[-1])
        if (previous29, previous30) == (0, 0):
            return wire
    raise AssertionError("word-10 non-information bits could not terminate parity state")


def set_word_field(word, low, high, value):
    width = high - low + 1
    shift = 24 - high
    mask = ((1 << width) - 1) << shift
    return (word & ~mask) | ((value & ((1 << width) - 1)) << shift)


def cnav_message(message_type, fields=()):
    body = list(bits(0x8B, 8) + bits(4, 6) + bits(message_type, 6)
                + bits(123, 17) + "0" + "0" * 238)
    for start, end, value in fields:
        body[start:end] = bits(value, end - start)
    text = "".join(body)
    return packed(text + bits(crc24q_bits(text), 24))


def galileo_word_type1():
    # WT, IODnav, toe, M0, e, sqrt(A), reserved.
    return (bits(1, 6) + bits(0x155, 10) + bits(321, 14)
            + bits(-0x1234567, 32) + bits(0x12345678, 32)
            + bits(0x3456789A, 32) + "00")


def galileo_pair(word):
    even = "00" + word[:112] + "000000"
    odd_prefix = "10" + word[112:] + bits(0x123456789A, 40) + bits(0x2AAAAA, 22) + "00"
    checksum_input = even[:114] + odd_prefix
    return even + odd_prefix + bits(crc24q_bits(checksum_input), 24) + bits(0x5A, 8) + "000000"


GLO_SETS = (
    {9, 10, 12, 13, 15, 17, 19, 20, 22, 24, 26, 28, 30, 32, 34, 35, 37, 39, 41, 43, 45, 47, 49, 51, 53, 55, 57, 59, 61, 63, 65, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84},
    {9, 11, 12, 14, 15, 18, 19, 21, 22, 25, 26, 29, 30, 33, 34, 36, 37, 40, 41, 44, 45, 48, 49, 52, 53, 56, 57, 60, 61, 64, 65, 67, 68, 71, 72, 75, 76, 79, 80, 83, 84},
    set(range(10, 13)) | set(range(16, 20)) | set(range(23, 27)) | set(range(31, 35)) | set(range(38, 42)) | set(range(46, 50)) | set(range(54, 58)) | set(range(62, 66)) | set(range(69, 73)) | set(range(77, 81)) | {85},
    set(range(13, 20)) | set(range(27, 35)) | set(range(42, 50)) | set(range(58, 66)) | set(range(73, 81)),
    set(range(20, 35)) | set(range(50, 66)) | set(range(81, 86)),
    set(range(35, 66)), set(range(66, 86)),
)


def glo_put(icd, low, high, value):
    encoded = bits(value, high - low + 1)
    for position, character in zip(range(high, low - 1, -1), encoded):
        icd[position] = int(character)


def glonass_finish(icd):
    for check_bit, positions in enumerate(GLO_SETS, 1):
        icd[check_bit] = sum(icd[position] for position in positions) & 1
    icd[8] = sum(icd[position] for position in range(1, 8)) ^ sum(
        icd[position] for position in range(9, 86))
    icd[8] &= 1
    return "".join(str(icd[position]) for position in range(85, 0, -1))


def glonass_string4():
    icd = {position: 0 for position in range(1, 86)}
    glo_put(icd, 81, 84, 4)
    glo_put(icd, 16, 26, 777)
    glo_put(icd, 11, 15, 19)
    glo_put(icd, 9, 10, 2)
    glo_put(icd, 49, 53, 7)
    glo_put(icd, 30, 33, 5)
    return glonass_finish(icd)


def bch15(message):
    code = message << 4
    remainder = code
    for position in range(14, 3, -1):
        if remainder & (1 << position):
            remainder ^= 0x13 << (position - 4)
    return code | (remainder & 0xF)


def interleave_bch(first, second):
    left, right = bits(first, 15), bits(second, 15)
    return "".join(left[index] + right[index] for index in range(15))


def beidou_frame(frame_id=1, sow=0x34ABC):
    first15 = "11100010010" + "0000"
    first_message = (frame_id << 8) | (sow >> 12)
    word1 = first15 + bits(bch15(first_message), 15)
    lower = sow & 0xFFF
    word2 = interleave_bch(bch15(lower >> 1), bch15((lower & 1) << 10))
    zero = interleave_bch(bch15(0), bch15(0))
    return word1 + word2 + zero * 8


def test_crc24q_published_oracle_and_complete_cnav_vector():
    assert Crc24LteA.calc(b"123456789") == 0xCDE703
    assert m.crc24q(b"123456789") == Crc24LteA.calc(b"123456789")
    # PRN 3, MT10, TOW 0x12345, alert 0, zero payload; 75 hex nibbles.
    published = "8b0ca91a28000000000000000000000000000000000000000000000000000000000008051e5"
    frame = packed(bits(int(published, 16), 300))
    got = m.decode_gps_cnav(frame)
    assert (got["prn"], got["message_type"], got["tow_count"]) == (3, 10, 0x12345)
    assert got["integrity"]["received"] == "8051e5"
    prefix = (bits(0x8B, 8) + bits(7, 6) + bits(10, 6) + bits(77, 17) + "0"
              + bits(0x123, 13) + bits(5, 3) + bits(17, 11)
              + bits(-3, 5) + bits(19, 11))
    body = prefix + "0" * (276 - len(prefix))
    typed = m.decode_gps_cnav(packed(body + bits(crc24q_bits(body), 24)))
    nav = typed["navigation"]
    assert (nav["kind"], nav["week_number"], nav["signal_health"]) == (
        "ephemeris_1", 0x123, 5)
    assert (nav["top_seconds"], nav["ura_ed_index"], nav["toe_seconds"]) == (
        17 * 300, -3, 19 * 300)
    assert nav["delta_a_m"] == nav["a_dot_m_per_second"] == 0


def test_gps_lnav_published_parity_and_ephemeris_fields():
    assert lnav_parity(0x8B0000, 0, 0) == "010010"
    words = [0x8B0000, (12345 << 7) | (2 << 2)] + [0] * 8
    words[2] = set_word_field(words[2], 1, 8, 0x5A)
    words[2] = set_word_field(words[2], 9, 24, 0xFFFF)
    words[3] = set_word_field(words[3], 1, 16, 1)
    words[3] = set_word_field(words[3], 17, 24, 0x12)
    words[4] = 0x345678
    words[5] = set_word_field(words[5], 1, 16, 0xFFFE)
    words[5] = set_word_field(words[5], 17, 24, 0x34)
    words[6] = 0x56789A
    words[7] = set_word_field(words[7], 1, 16, 2)
    words[7] = set_word_field(words[7], 17, 24, 0x56)
    words[8] = 0x789ABC
    words[9] = set_word_field(words[9], 1, 16, 100)
    frame_bits = lnav_subframe(words)
    got = m.decode_gps_lnav(packed(frame_bits))
    assert got["how"]["subframe_id"] == 2 and got["how"]["tow_seconds"] == 12345 * 6
    nav = got["navigation"]
    assert nav["kind"] == "ephemeris_part_1" and nav["iode"] == 0x5A
    assert nav["crs_m"] == -1 * 2.0 ** -5 and nav["toe_seconds"] == 1600
    assert all(row["valid"] for row in got["integrity"]["words"])


def test_gps_lnav_almanac_and_iono_utc_pages():
    almanac = [0x8B0000, (222 << 7) | (5 << 2)] + [0] * 8
    almanac[2] = set_word_field(almanac[2], 1, 2, 1)
    almanac[2] = set_word_field(almanac[2], 3, 8, 12)
    almanac[2] = set_word_field(almanac[2], 9, 24, 100)
    almanac[3] = set_word_field(almanac[3], 1, 8, 7)
    almanac[3] = set_word_field(almanac[3], 9, 24, -3)
    almanac[4] = set_word_field(almanac[4], 1, 16, -4)
    almanac[4] = set_word_field(almanac[4], 17, 24, 5)
    almanac[5] = 0x123456
    almanac[6] = (-7) & 0xFFFFFF
    almanac[7] = 8
    almanac[8] = (-9) & 0xFFFFFF
    almanac[9] = set_word_field(almanac[9], 1, 11, -2)
    almanac[9] = set_word_field(almanac[9], 12, 22, 3)
    nav = m.decode_gps_lnav(packed(lnav_subframe(almanac)))["navigation"]
    assert (nav["kind"], nav["sv_id"], nav["toa_seconds"]) == (
        "almanac", 12, 7 * 4096)
    assert nav["delta_i_semicircles"] == -3 * 2.0 ** -19
    assert nav["af0_seconds"] == -2 * 2.0 ** -20

    utc = [0x8B0000, (333 << 7) | (4 << 2)] + [0] * 8
    utc[2] = set_word_field(utc[2], 1, 2, 1)
    utc[2] = set_word_field(utc[2], 3, 8, 56)
    utc[2] = set_word_field(utc[2], 9, 16, -1)
    utc[2] = set_word_field(utc[2], 17, 24, 2)
    utc[3] = set_word_field(utc[3], 1, 8, -3)
    utc[3] = set_word_field(utc[3], 9, 16, 4)
    utc[3] = set_word_field(utc[3], 17, 24, 5)
    utc[4] = set_word_field(utc[4], 1, 8, -6)
    utc[4] = set_word_field(utc[4], 9, 16, 7)
    utc[4] = set_word_field(utc[4], 17, 24, -8)
    utc[5] = (-9) & 0xFFFFFF
    utc[6] = (-10) & 0xFFFFFF
    utc[7] = set_word_field(utc[7], 1, 8, 0xFE)
    utc[7] = set_word_field(utc[7], 9, 16, 11)
    utc[7] = set_word_field(utc[7], 17, 24, 12)
    utc[8] = set_word_field(utc[8], 1, 8, -18)
    utc[8] = set_word_field(utc[8], 9, 16, 13)
    utc[8] = set_word_field(utc[8], 17, 24, 6)
    utc[9] = set_word_field(utc[9], 1, 8, -17)
    nav = m.decode_gps_lnav(packed(lnav_subframe(utc)))["navigation"]
    assert nav["kind"] == "ionosphere_utc"
    assert (nav["delta_tls"], nav["delta_tlsf"], nav["tot_seconds"]) == (
        -18, -17, 11 * 4096)
    assert nav["alpha"][0] == -1 * 2.0 ** -30


def test_cnav2_separate_subframe_crcs():
    sf2 = bits(0x123, 13) + bits(0x5A, 8) + "0" * (576 - 21)
    sf3 = bits(33, 8) + bits(17, 6) + "0" * 236
    frame = bits(0x101, 9) + sf2 + bits(crc24q_bits(sf2), 24) + sf3 + bits(crc24q_bits(sf3), 24)
    got = m.decode_gps_cnav2(packed(frame))
    assert got["time_of_interval"] == 0x101
    assert (got["week_number"], got["interval_time_of_week"],
            got["sf3_prn"], got["sf3_page_number"]) == (0x123, 0x5A, 33, 17)
    assert got["integrity"]["sf2"]["valid"] and got["integrity"]["sf3"]["valid"]


def test_cnav_ephemeris_clock_almanac_and_utc_types():
    mt11 = m.decode_gps_cnav(cnav_message(11, (
        (38, 49, 7), (49, 82, -9), (82, 115, 11),
        (115, 132, -3), (179, 203, -256),
    )))["navigation"]
    assert mt11["toe_seconds"] == 2100
    assert mt11["omega0_semicircles"] == -9 * 2.0 ** -32
    assert mt11["crs_m"] == -1

    mt30 = m.decode_gps_cnav(cnav_message(30, (
        (38, 49, 8), (49, 54, -2), (60, 71, 9), (71, 97, -4),
        (127, 140, -3), (192, 200, -5), (224, 232, 6), (256, 264, 77),
    )))["navigation"]
    assert (mt30["top_seconds"], mt30["toc_seconds"], mt30["wnop_mod_256"]) == (
        2400, 2700, 77)
    assert mt30["tgd_seconds"] == -3 * 2.0 ** -35
    assert mt30["alpha"][0] == -5 * 2.0 ** -30

    packet = bits(22, 6) + bits(-3, 8) + bits(4, 7) + bits(-5, 7) + "101"
    mt31 = m.decode_gps_cnav(cnav_message(31, (
        (127, 140, 0x345), (140, 148, 12), (148, 179, int(packet, 2)),
    )))["navigation"]
    assert mt31["almanac_week"] == 0x345 and mt31["toa_seconds"] == 12 * 4096
    first = mt31["reduced_almanac"][0]
    assert first["prn"] == 22 and first["delta_a_m"] == -3 * 512
    assert (first["l1_health"], first["l2_health"], first["l5_health"]) == (1, 0, 1)

    mt33 = m.decode_gps_cnav(cnav_message(33, (
        (127, 143, -4), (163, 171, -18), (171, 187, 50),
        (187, 200, 0x456), (200, 213, 0x457), (213, 217, 6), (217, 225, -17),
    )))["navigation"]
    assert mt33["utc_a0_seconds"] == -4 * 2.0 ** -35
    assert (mt33["delta_tls"], mt33["tot_seconds"], mt33["wnot"],
            mt33["day_number"], mt33["delta_tlsf"]) == (-18, 800, 0x456, 6, -17)


def test_galileo_nominal_pair_crc_span_and_word_layout():
    word = galileo_word_type1()
    pair = galileo_pair(word)
    assert len(word) == 128 and len(pair) == 240
    got = m.decode_galileo_inav(packed(pair))
    nav = got["navigation"]
    assert (nav["word_type"], nav["iod_nav"], nav["toe_seconds"]) == (1, 0x155, 321 * 60)
    assert nav["m0_semicircles"] == -0x1234567 * 2.0 ** -31
    direct_report = m.decode_galileo_word(packed(word))
    assert direct_report["integrity"]["checked"] is False
    assert direct_report["navigation"]["eccentricity"] == 0x12345678 * 2.0 ** -33
    changed = list(pair)
    changed[150] = "1" if changed[150] == "0" else "0"
    with pytest.raises(m.SecGNSSNavError):
        m.decode_galileo_inav(packed("".join(changed)))
    bad_tail = list(pair)
    bad_tail[119] = "1"
    with pytest.raises(m.SecGNSSNavError, match="tail"):
        m.decode_galileo_inav(packed("".join(bad_tail)))


def test_galileo_iono_and_utc_word_semantics():
    word5 = (bits(5, 6) + bits(100, 11) + bits(-5, 11) + bits(-7, 14)
             + bits(0x15, 5) + bits(-2, 10) + bits(3, 10)
             + bits(1, 2) + bits(2, 2) + "10" + bits(0xABC, 12)
             + bits(0x54321, 20) + "0" * 23)
    nav5 = m.decode_galileo_word(packed(word5))["navigation"]
    assert nav5["iono_ai0_sfu"] == 25
    assert nav5["iono_ai1_sfu_per_degree"] == -5 * 2.0 ** -8
    assert nav5["iono_ai2_sfu_per_degree2"] == -7 * 2.0 ** -15
    assert (nav5["week_number"], nav5["tow_seconds"]) == (0xABC, 0x54321)
    word6 = (bits(6, 6) + bits(-100, 32) + bits(20, 24) + bits(-18, 8)
             + bits(9, 8) + bits(22, 8) + bits(23, 8) + bits(4, 3)
             + bits(-17, 8) + bits(0x34567, 20) + "000")
    nav6 = m.decode_galileo_word(packed(word6))["navigation"]
    assert nav6["kind"] == "utc_conversion"
    assert (nav6["delta_tls"], nav6["delta_tlsf"], nav6["day_number"]) == (-18, -17, 4)
    word7 = (bits(7, 6) + bits(9, 4) + bits(2, 2) + bits(17, 10)
             + bits(12, 6) + bits(-3, 13) + bits(9, 11) + bits(-10, 16)
             + bits(4, 11) + bits(-5, 16) + bits(6, 11) + bits(-7, 16)
             + "0" * 6)
    nav7 = m.decode_galileo_word(packed(word7))["navigation"]
    assert (nav7["kind"], nav7["iod_a"], nav7["t0a_seconds"]) == (
        "almanac_1", 9, 17 * 600)
    sat = nav7["satellite_1"]
    assert sat["svid"] == 12 and sat["delta_sqrt_a_sqrt_m"] == -3 * 2.0 ** -9
    assert sat["m0_semicircles"] == -7 * 2.0 ** -15


def test_glonass_icd_order_hamming_and_string4_fields():
    frame = glonass_string4()
    assert len(frame) == 85
    got = m.decode_glonass_string(packed(frame))
    assert got["string_number"] == 4 and got["integrity"]["syndrome"] == [0] * 8
    nav = got["navigation"]
    assert (nav["day_number"], nav["slot_number"], nav["satellite_type"]) == (777, 19, 2)
    assert nav["age_days"] == 7 and nav["accuracy_index"] == 5


def test_glonass_time_and_almanac_string_fields():
    string5 = {position: 0 for position in range(1, 86)}
    glo_put(string5, 81, 84, 5)
    glo_put(string5, 70, 80, 1000)
    glo_put(string5, 38, 69, 123)
    glo_put(string5, 32, 36, 17)
    glo_put(string5, 10, 31, 456)
    string5[9] = 1
    nav5 = m.decode_glonass_string(packed(glonass_finish(string5)))["navigation"]
    assert (nav5["kind"], nav5["calendar_day"], nav5["four_year_interval"]) == (
        "system_time", 1000, 17)
    assert nav5["tau_c_seconds"] == 123 * 2.0 ** -31

    string6 = {position: 0 for position in range(1, 86)}
    glo_put(string6, 81, 84, 6)
    string6[80] = 1
    glo_put(string6, 78, 79, 2)
    glo_put(string6, 73, 77, 19)
    glo_put(string6, 63, 72, 7)
    glo_put(string6, 42, 62, 8)
    glo_put(string6, 24, 41, 9)
    glo_put(string6, 9, 23, 10)
    nav6 = m.decode_glonass_string(packed(glonass_finish(string6)))["navigation"]
    assert (nav6["kind"], nav6["almanac_pair"], nav6["slot_number"]) == (
        "almanac_even", 1, 19)
    assert nav6["eccentricity"] == 10 * 2.0 ** -20

    string7 = {position: 0 for position in range(1, 86)}
    glo_put(string7, 81, 84, 7)
    glo_put(string7, 65, 80, 11)
    glo_put(string7, 44, 64, 12)
    glo_put(string7, 22, 43, 13)
    glo_put(string7, 15, 21, 14)
    glo_put(string7, 10, 14, 15)
    string7[9] = 1
    nav7 = m.decode_glonass_string(packed(glonass_finish(string7)))["navigation"]
    assert nav7["kind"] == "almanac_odd" and nav7["frequency_channel_raw"] == 15
    assert nav7["t_lambda_seconds"] == 12 * 2.0 ** -5


def test_beidou_bch_published_anchors_d1_and_bcnav2():
    assert bch15(0x5A3) == 0x5A37 and bch15(0x400) == 0x4009
    assert m.beidou_bch15_valid(0x5A37) and m.beidou_bch15_valid(0x4009)
    assert int(interleave_bch(0x5A37, 0x4009), 2) == 0x32880A6B
    d1 = beidou_frame()
    got = m.decode_beidou_d1(packed(d1))
    assert (got["frame_id"], got["seconds_of_week"]) == (1, 0x34ABC)
    assert all(row["valid"] for row in got["integrity"]["words"])
    bcdata = bits(9, 6) + bits(22, 6) + bits(0x23456, 18) + ("01" * 117)
    bcnav2 = bcdata + bits(crc24q_bits(bcdata), 24)
    got = m.decode_beidou_bcnav2(packed(bcnav2))
    assert (got["prn"], got["message_type"], got["seconds_of_week"]) == (9, 22, 0x23456)


def test_integrity_bit_flips_truncation_and_nonzero_padding():
    cnav_hex = "8b0ca91a28000000000000000000000000000000000000000000000000000000000008051e5"
    cnav = packed(bits(int(cnav_hex, 16), 300))
    lnav = packed(lnav_subframe([0x8B0000, (10 << 7) | (1 << 2)] + [0] * 8))
    galileo = packed(galileo_pair(galileo_word_type1()))
    glonass = packed(glonass_string4())
    beidou = packed(beidou_frame())
    cases = [
        (cnav, m.decode_gps_cnav), (lnav, m.decode_gps_lnav),
        (galileo, m.decode_galileo_inav), (glonass, m.decode_glonass_string),
        (beidou, m.decode_beidou_d1),
    ]
    for valid, parser in cases:
        for size in range(len(valid)):
            with pytest.raises(m.SecGNSSNavError):
                parser(valid[:size])
        changed = bytearray(valid)
        changed[len(changed) // 2] ^= 0x20
        with pytest.raises(m.SecGNSSNavError):
            parser(bytes(changed))
    for valid, parser in ((cnav, m.decode_gps_cnav), (glonass, m.decode_glonass_string)):
        changed = bytearray(valid)
        changed[-1] |= 1
        with pytest.raises(m.SecGNSSNavError, match="padding"):
            parser(bytes(changed))
    sf2, sf3 = "0" * 576, "0" * 250
    cnav2 = packed("0" * 9 + sf2 + bits(crc24q_bits(sf2), 24)
                   + sf3 + bits(crc24q_bits(sf3), 24))
    changed = bytearray(cnav2)
    changed[-1] |= 1
    with pytest.raises(m.SecGNSSNavError, match="padding"):
        m.decode_gps_cnav2(bytes(changed))


def test_fail_closed_types_released_buffers_random_and_oversized():
    parsers = [
        m.decode_gps_lnav, m.decode_gps_cnav, m.decode_gps_cnav2,
        m.decode_galileo_inav, m.decode_galileo_word,
        m.decode_glonass_string, m.decode_beidou_d1, m.decode_beidou_d2,
        m.decode_beidou_bcnav2,
    ]
    view = memoryview(b"x")
    view.release()
    rng = random.Random(0x6E55)
    values = [None, True, 1, 1.5, [], {}, object(), b"", view,
              b"x" * (m.MAX_INPUT + 1)]
    values += [rng.randbytes(rng.randrange(1, 140)) for _ in range(100)]
    for parser in parsers:
        for value in values:
            try:
                result = parser(value)
                assert isinstance(result, dict)
            except m.SecGNSSNavError:
                pass
    for bad in (None, True, -1, 1 << 15, "5a37", [], {}):
        with pytest.raises(m.SecGNSSNavError):
            m.beidou_bch15_valid(bad)
    with pytest.raises(m.SecGNSSNavError):
        m.decode_navigation(b"", "unknown")
    valid = cnav_message(10)
    assert m.decode_navigation(valid, "gps-cnav")["message_type"] == 10
    for value in values[:20]:
        try:
            assert isinstance(m.decode_navigation(value, "gps-cnav"), dict)
        except m.SecGNSSNavError:
            pass
    with pytest.raises(m.SecGNSSNavError):
        m.decode_gps_lnav("0" * 300, packing=True)


def test_cli_guard_help_nul_and_noninteger_systemexit(tmp_path, capsys, monkeypatch):
    cnav_hex = "8b0ca91a28000000000000000000000000000000000000000000000000000000000008051e5"
    path = tmp_path / "cnav.bin"
    path.write_bytes(packed(bits(int(cnav_hex, 16), 300)))
    assert m.main(["gps-cnav", str(path)]) == 0
    assert '"message_type": 10' in capsys.readouterr().out
    assert m.main(["--help"]) == 0
    assert m.main([]) == 2
    assert m.main(["gps-cnav", str(path) + ".missing"]) == 2
    assert m.main(["gps-cnav", "\0"]) == 2
    monkeypatch.setattr(m.argparse.ArgumentParser, "parse_args",
                        lambda self, argv: (_ for _ in ()).throw(SystemExit("not-int")))
    assert m.main([]) == 2
