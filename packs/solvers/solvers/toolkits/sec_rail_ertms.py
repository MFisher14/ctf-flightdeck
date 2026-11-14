#!/usr/bin/env python3
"""Passive ERTMS/ETCS artifact decoder.

The decoder accepts supplied Eurobalise telegrams, ETCS user-data bit fields,
and EuroRadio safety PDUs.  It never opens a socket or creates rail traffic.

References: ERA/UNISIG SUBSET-036 v4.0.0 (Eurobalise air gap), SUBSET-026
v4.0.0 (ETCS language), SUBSET-037-2 v4.0.0 (EuroRadio safety layer), and
SUBSET-085 v3.0.0 (published Eurobalise test vectors).
"""
from __future__ import annotations

import argparse
import functools
import hmac
import json
from pathlib import Path
import sys

try:
    from Crypto.Cipher import DES
except ImportError:  # Import stays usable; MAC entry points fail with our error.
    DES = None


MAX_INPUT = 1024 * 1024


class SecRailERTMSError(ValueError):
    """Malformed, unsupported, or over-limit ERTMS artifact."""


def _closed(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SecRailERTMSError:
            raise
        except Exception as exc:
            raise SecRailERTMSError(
                f"{function.__name__}: {type(exc).__name__}: {exc}"
            ) from None
    return wrapper


def _bytes(value, label="input", maximum=MAX_INPUT):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SecRailERTMSError(f"{label} must be bytes")
    if len(value) > maximum:
        raise SecRailERTMSError(f"{label} exceeds {maximum}-byte limit")
    return bytes(value)


class _Bits:
    def __init__(self, bits):
        if not isinstance(bits, str) or any(c not in "01" for c in bits):
            raise SecRailERTMSError("invalid bit stream")
        self.bits = bits
        self.at = 0

    @property
    def remaining(self):
        return len(self.bits) - self.at

    def take(self, width, name="field"):
        if type(width) is not int or width < 0 or self.at + width > len(self.bits):
            raise SecRailERTMSError(f"truncated {name}")
        chunk = self.bits[self.at:self.at + width]
        self.at += width
        return int(chunk, 2) if chunk else 0

    def text(self, width, name="field"):
        if type(width) is not int or width < 0 or self.at + width > len(self.bits):
            raise SecRailERTMSError(f"truncated {name}")
        chunk = self.bits[self.at:self.at + width]
        self.at += width
        return chunk


def _padded_bits(data, bit_length):
    raw = _bytes(data)
    if type(bit_length) is not int or bit_length <= 0 or bit_length > len(raw) * 8:
        raise SecRailERTMSError("invalid bit length")
    if len(raw) != (bit_length + 7) // 8:
        raise SecRailERTMSError("non-canonical byte container")
    bits = "".join(f"{byte:08b}" for byte in raw)
    if any(bit != "0" for bit in bits[bit_length:]):
        raise SecRailERTMSError("nonzero byte-padding bits")
    return bits[:bit_length]


def _bit_bytes(bits):
    padding = (-len(bits)) % 8
    return int(bits + "0" * padding, 2).to_bytes((len(bits) + 7) // 8, "big")


# SUBSET-036 Annex B.2, in normative ascending order.  The table index is the
# ten-bit source word; the listed octal value is its eleven-bit codeword.
_SUBSTITUTION_OCTAL = """
00101 00102 00103 00104 00105 00106 00107 00110 00111 00112 00113 00114 00115 00116 00117 00120 00121 00122 00123 00124
00125 00126 00127 00130 00131 00132 00133 00134 00135 00141 00142 00143 00144 00145 00146 00147 00150 00151 00152 00153
00154 00155 00156 00157 00160 00161 00162 00163 00164 00165 00166 00167 00170 00171 00172 00173 00174 00175 00176 00201
00206 00211 00214 00216 00217 00220 00222 00223 00224 00225 00226 00231 00233 00244 00245 00246 00253 00257 00260 00261
00272 00273 00274 00275 00276 00301 00303 00315 00317 00320 00321 00332 00334 00341 00342 00343 00344 00346 00352 00353
00357 00360 00374 00376 00401 00403 00404 00405 00406 00407 00410 00411 00412 00413 00416 00417 00420 00424 00425 00426
00427 00432 00433 00442 00443 00445 00456 00457 00460 00461 00464 00465 00470 00471 00472 00474 00475 00476 00501 00502
00503 00504 00505 00506 00507 00516 00517 00520 00521 00522 00523 00524 00525 00530 00531 00532 00533 00534 00535 00544
00545 00546 00547 00550 00551 00552 00553 00554 00555 00556 00557 00560 00561 00562 00563 00571 00573 00576 00601 00602
00604 00605 00610 00611 00612 00613 00614 00615 00616 00617 00620 00621 00622 00623 00624 00625 00626 00627 00630 00634
00635 00644 00645 00646 00647 00650 00651 00652 00653 00654 00655 00656 00657 00660 00661 00662 00663 00666 00667 00672
00674 00675 00676 00701 00712 00713 00716 00717 00720 00721 00722 00723 00730 00731 00732 00733 00734 00735 00742 00743
00744 00745 00746 00747 00750 00751 00752 00753 00754 00755 00756 00757 00760 00761 00764 00765 00766 00767 00772 00773
00776 01001 01004 01005 01016 01017 01020 01021 01022 01023 01024 01025 01030 01031 01032 01033 01034 01035 01043 01044
01045 01046 01047 01054 01057 01060 01061 01062 01075 01076 01101 01102 01103 01110 01114 01115 01116 01117 01120 01121
01122 01123 01124 01125 01126 01127 01130 01131 01132 01133 01142 01143 01144 01145 01146 01147 01151 01152 01153 01154
01155 01156 01157 01160 01164 01166 01167 01176 01201 01214 01217 01220 01221 01222 01223 01224 01225 01226 01227 01230
01231 01232 01233 01243 01244 01245 01253 01254 01255 01256 01257 01260 01261 01272 01273 01274 01275 01276 01301 01302
01303 01305 01306 01307 01317 01320 01321 01332 01334 01335 01342 01343 01344 01345 01350 01351 01352 01353 01355 01356
01357 01360 01361 01364 01365 01370 01371 01372 01373 01374 01376 01401 01403 01406 01407 01414 01415 01416 01417 01420
01424 01425 01431 01433 01434 01435 01443 01445 01456 01457 01460 01462 01474 01475 01476 01501 01502 01503 01504 01505
01516 01517 01520 01524 01532 01533 01544 01546 01550 01551 01552 01553 01554 01557 01560 01561 01562 01563 01566 01567
01576 01601 01603 01604 01605 01606 01607 01610 01611 01612 01613 01614 01615 01616 01617 01620 01621 01622 01623 01624
01625 01626 01630 01631 01632 01633 01635 01643 01644 01645 01650 01651 01652 01653 01654 01655 01656 01657 01660 01661
01672 01674 01675 01676 01701 01720 01744 01745 01746 01747 01750 01751 01752 01753 01754 01755 01756 01757 01760 01761
01762 01763 01764 01765 01766 01767 01770 01771 01772 01773 01774 01775 02002 02003 02004 02005 02006 02007 02010 02011
02012 02013 02014 02015 02016 02017 02020 02021 02022 02023 02024 02025 02026 02027 02030 02031 02032 02033 02057 02076
02101 02102 02103 02105 02116 02117 02120 02121 02122 02123 02124 02125 02126 02127 02132 02133 02134 02142 02144 02145
02146 02147 02151 02152 02153 02154 02155 02156 02157 02160 02161 02162 02163 02164 02165 02166 02167 02170 02171 02172
02173 02174 02176 02201 02210 02211 02214 02215 02216 02217 02220 02223 02224 02225 02226 02227 02231 02233 02244 02245
02253 02257 02260 02261 02272 02273 02274 02275 02276 02301 02302 02303 02315 02317 02320 02321 02332 02334 02342 02343
02344 02346 02352 02353 02357 02360 02361 02362 02363 02370 02371 02374 02376 02401 02403 02404 02405 02406 02407 02412
02413 02416 02417 02420 02421 02422 02424 02425 02426 02427 02432 02433 02434 02435 02442 02443 02445 02456 02457 02460
02470 02471 02472 02474 02475 02476 02501 02502 02503 02504 02505 02516 02517 02520 02521 02522 02523 02524 02532 02533
02534 02544 02545 02546 02547 02550 02551 02552 02553 02554 02555 02556 02557 02560 02563 02576 02601 02610 02611 02613
02617 02620 02621 02622 02623 02624 02625 02626 02630 02631 02632 02633 02634 02635 02644 02645 02646 02647 02650 02651
02652 02653 02654 02655 02656 02657 02660 02661 02662 02663 02667 02674 02675 02676 02701 02702 02715 02716 02717 02720
02723 02730 02731 02732 02733 02734 02742 02743 02744 02745 02746 02747 02752 02753 02754 02755 02756 02757 02760 02761
02772 02773 02776 03001 03004 03005 03010 03011 03012 03013 03016 03017 03020 03021 03022 03023 03024 03025 03026 03027
03030 03031 03032 03033 03034 03035 03042 03043 03044 03045 03046 03047 03054 03055 03056 03057 03060 03061 03064 03065
03076 03101 03102 03103 03105 03110 03111 03114 03115 03116 03117 03120 03121 03122 03123 03124 03125 03126 03127 03130
03131 03132 03133 03142 03143 03147 03150 03151 03152 03153 03154 03155 03156 03157 03160 03161 03162 03163 03164 03165
03166 03167 03172 03173 03175 03176 03201 03204 03206 03214 03215 03216 03217 03220 03221 03222 03223 03224 03225 03226
03227 03230 03231 03232 03233 03242 03243 03244 03245 03246 03247 03252 03253 03254 03255 03256 03257 03260 03261 03270
03271 03272 03273 03274 03275 03276 03301 03302 03303 03305 03306 03307 03312 03313 03316 03317 03320 03321 03332 03334
03335 03344 03345 03350 03351 03352 03353 03357 03360 03361 03364 03365 03366 03367 03370 03371 03372 03373 03374 03376
03401 03403 03417 03420 03424 03425 03431 03433 03434 03435 03436 03443 03445 03456 03457 03460 03462 03474 03476 03501
03502 03503 03504 03505 03516 03517 03520 03524 03531 03532 03533 03544 03546 03551 03552 03553 03554 03555 03557 03560
03561 03563 03566 03571 03576 03601 03602 03603 03604 03605 03606 03607 03610 03611 03612 03613 03614 03615 03616 03617
03620 03621 03622 03623 03624 03625 03626 03627 03630 03631 03632 03633 03634 03635 03636 03642 03643 03644 03645 03646
03647 03650 03651 03652 03653 03654 03655 03656 03657 03660 03661 03662 03663 03664 03665 03666 03667 03670 03671 03672
03673 03674 03675 03676
"""
_SUBSTITUTION = tuple(int(value, 8) for value in _SUBSTITUTION_OCTAL.split())
_INVERSE_SUBSTITUTION = {value: index for index, value in enumerate(_SUBSTITUTION)}
if len(_SUBSTITUTION) != 1024 or len(_INVERSE_SUBSTITUTION) != 1024:
    raise RuntimeError("internal SUBSET-036 substitution table is corrupt")


_CHECK_POLYNOMIALS = {
    1023: (
        (10, 9, 7, 6, 4, 3, 2, 1, 0),
        (75, 73, 72, 71, 67, 62, 61, 60, 57, 56, 55, 52, 51, 49,
         46, 45, 44, 43, 41, 37, 35, 34, 33, 31, 30, 28, 26, 24, 21,
         17, 16, 15, 13, 12, 11, 9, 4, 1, 0),
    ),
    341: (
        (10, 8, 7, 5, 3, 1, 0),
        (75, 72, 71, 70, 69, 68, 66, 65, 64, 63, 60, 55, 54, 49, 47,
         46, 45, 44, 43, 42, 41, 39, 38, 37, 36, 34, 33, 32, 31, 30,
         27, 25, 22, 19, 17, 13, 12, 11, 10, 6, 3, 1, 0),
    ),
}


def _polynomial(exponents):
    value = 0
    for exponent in exponents:
        value |= 1 << exponent
    return value


def _poly_multiply(left, right):
    result = 0
    while right:
        if right & 1:
            result ^= left
        left <<= 1
        right >>= 1
    return result


def _poly_remainder(value, divisor):
    degree = divisor.bit_length() - 1
    while value and value.bit_length() - 1 >= degree:
        value ^= divisor << (value.bit_length() - 1 - degree)
    return value


def _expected_check_bits(prefix, telegram_length):
    f_exp, g_exp = _CHECK_POLYNOMIALS[telegram_length]
    g = _polynomial(g_exp)
    divisor = _poly_multiply(_polynomial(f_exp), g)
    return _poly_remainder(prefix << 85, divisor) ^ g


def _descramble(words, seed):
    state = (2801775573 * seed) & 0xFFFFFFFF
    bits = "".join(f"{word:010b}" for word in words)
    plain = []
    for bit in bits:
        scrambled = int(bit)
        plain.append(str(((state >> 31) & 1) ^ scrambled))
        state = (state << 1) & 0xFFFFFFFF
        if scrambled:
            state ^= 0xEA000001
    values = [int("".join(plain)[at:at + 10], 2)
              for at in range(0, len(plain), 10)]
    values[0] = (values[0] - sum(values[1:])) & 0x3FF
    return "".join(f"{value:010b}" for value in values)


_Q_SCALE = {0: 0.1, 1: 1.0, 2: 10.0, 3: None}


def _take_fields(reader, fields):
    return {name: reader.take(width, name) for name, width in fields}


def _distance(result, field, scale):
    value = result.get(field)
    factor = _Q_SCALE.get(scale)
    key = field.lower()
    if factor is None:
        result[key + "_scale_spare"] = True
    elif value == 0x7FFF:
        result[key + "_special"] = "maximum/special value"
    elif value is not None:
        result[field.lower() + "_metres"] = value * factor


def _decode_packet_body(packet_id, body):
    reader = _Bits(body)
    result = {}
    if packet_id == 2:
        result = _take_fields(reader, (("M_VERSION", 7),))
    elif packet_id == 5:
        result = _take_fields(reader, (("Q_SCALE", 2), ("D_LINK", 15),
            ("Q_NEWCOUNTRY", 1)))
        if result["Q_NEWCOUNTRY"]:
            result["NID_C"] = reader.take(10, "NID_C")
        result.update(_take_fields(reader, (("NID_BG", 14),
            ("Q_LINKORIENTATION", 1), ("Q_LINKREACTION", 2),
            ("Q_LOCACC", 6), ("N_ITER", 5))))
        links = []
        for _ in range(result["N_ITER"]):
            link = _take_fields(reader, (("D_LINK", 15), ("Q_NEWCOUNTRY", 1)))
            if link["Q_NEWCOUNTRY"]:
                link["NID_C"] = reader.take(10, "NID_C")
            link.update(_take_fields(reader, (("NID_BG", 14),
                ("Q_LINKORIENTATION", 1), ("Q_LINKREACTION", 2),
                ("Q_LOCACC", 6))))
            _distance(link, "D_LINK", result["Q_SCALE"])
            links.append(link)
        result["links"] = links
        _distance(result, "D_LINK", result["Q_SCALE"])
    elif packet_id == 21:
        result = _take_fields(reader, (("Q_SCALE", 2), ("D_GRADIENT", 15),
            ("Q_GDIR", 1), ("G_A", 8), ("N_ITER", 5)))
        gradients = []
        for _ in range(result["N_ITER"]):
            gradient = _take_fields(reader, (("D_GRADIENT", 15),
                ("Q_GDIR", 1), ("G_A", 8)))
            _distance(gradient, "D_GRADIENT", result["Q_SCALE"])
            gradients.append(gradient)
        result["gradients"] = gradients
        _distance(result, "D_GRADIENT", result["Q_SCALE"])
    elif packet_id == 31:
        result = _take_fields(reader, (("Q_SCALE", 2), ("D_RBCTR", 15),
            ("NID_C", 10), ("NID_RBC", 14), ("Q_SLEEPSESSION", 1)))
        _distance(result, "D_RBCTR", result["Q_SCALE"])
        result["transport_profile"] = "FRMCS-capable RBC transition"
    elif packet_id in (32, 42):
        result = _take_fields(reader, (("Q_RBC", 1), ("NID_C", 10),
            ("NID_RBC", 14)))
        if packet_id == 42:
            result["NID_RADIO"] = reader.take(64, "NID_RADIO")
        result["Q_SLEEPSESSION"] = reader.take(1, "Q_SLEEPSESSION")
        result["transport_profile"] = (
            "FRMCS session management" if packet_id == 32
            else "legacy radio session management"
        )
    elif packet_id == 44:
        result["NID_XUSER"] = reader.take(9, "NID_XUSER")
        result["XUSER_bits"] = reader.text(reader.remaining)
    else:
        result["raw_bits"] = reader.text(reader.remaining)
    if reader.remaining:
        raise SecRailERTMSError(f"packet {packet_id} has undeclared trailing bits")
    return result


def _parse_packets(bits, start):
    packets = []
    cursor = start
    while cursor < len(bits):
        remainder = bits[cursor:]
        if len(remainder) < 8:
            raise SecRailERTMSError("truncated NID_PACKET")
        packet_id = int(remainder[:8], 2)
        if packet_id == 0:
            if len(remainder) < 14:
                raise SecRailERTMSError("truncated Packet 0")
            packets.append({"NID_PACKET": 0, "name": "virtual_balise_cover_marker",
                            "NID_VBCMK": int(remainder[8:14], 2), "L_PACKET": 14})
            cursor += 14
            continue
        if packet_id == 255:
            packets.append({"NID_PACKET": 255, "name": "end_of_information",
                            "L_PACKET": 8})
            cursor += 8
            fill = bits[cursor:]
            if any(bit != "1" for bit in fill):
                raise SecRailERTMSError("non-one fill after packet 255")
            return packets, cursor, True
        if len(remainder) < 23:
            raise SecRailERTMSError("truncated ETCS packet header")
        q_dir = int(remainder[8:10], 2)
        if q_dir == 3:
            raise SecRailERTMSError("reserved Q_DIR value")
        length = int(remainder[10:23], 2)
        if length < 23 or cursor + length > len(bits):
            raise SecRailERTMSError("invalid L_PACKET")
        body = bits[cursor + 23:cursor + length]
        decoded = {"NID_PACKET": packet_id, "Q_DIR": q_dir,
                   "L_PACKET": length}
        decoded.update(_decode_packet_body(packet_id, body))
        packets.append(decoded)
        cursor += length
    return packets, cursor, False


@_closed
def parse_etcs_user_data(data, bit_length=None):
    """Decode a 210/830-bit Eurobalise user field and bounded ETCS packets."""
    raw = _bytes(data, "ETCS user data", 104)
    if bit_length is None:
        bit_length = {27: 210, 104: 830}.get(len(raw))
    if bit_length not in (210, 830):
        raise SecRailERTMSError("ETCS balise user data must be 210 or 830 bits")
    bits = _padded_bits(raw, bit_length)
    reader = _Bits(bits)
    header = _take_fields(reader, (("Q_UPDOWN", 1), ("M_VERSION", 7),
        ("Q_MEDIA", 1), ("N_PIG", 3), ("N_TOTAL", 3), ("M_DUP", 2),
        ("M_MCOUNT", 8), ("NID_C", 10), ("NID_BG", 14), ("Q_LINK", 1)))
    if header["Q_UPDOWN"] != 1:
        raise SecRailERTMSError("Eurobalise user data must be track-to-train")
    packets, end, terminated = _parse_packets(bits, reader.at)
    return {
        "format": "ETCS Eurobalise user data",
        "bit_length": bit_length,
        "header": header,
        "packets": packets,
        "packet_terminated": terminated,
        "fill_bit_count": bit_length - end,
    }


@_closed
def decode_balise_telegram(data):
    """Validate and decode one 341- or 1023-bit SUBSET-036 telegram.

    Byte containers are 43 or 128 bytes; unused low bits in the final byte must
    be zero.  Invalid BCH/check bits or 11-bit alphabet symbols are rejected.
    """
    raw = _bytes(data, "Eurobalise telegram", 128)
    bit_length = {43: 341, 128: 1023}.get(len(raw))
    if bit_length is None:
        raise SecRailERTMSError("telegram must be a 43- or 128-byte container")
    bits = _padded_bits(raw, bit_length)
    word_count = 21 if bit_length == 341 else 83
    shaped_length = word_count * 11
    shaped = bits[:shaped_length]
    control = int(bits[shaped_length:shaped_length + 3], 2)
    seed = int(bits[shaped_length + 3:shaped_length + 15], 2)
    extra = int(bits[shaped_length + 15:shaped_length + 25], 2)
    check = int(bits[-85:], 2)
    if control != 0b001:
        raise SecRailERTMSError("invalid Eurobalise control bits")
    telegram = int(bits, 2)
    expected = _expected_check_bits(telegram >> 85, bit_length)
    if check != expected:
        raise SecRailERTMSError("Eurobalise check-bit mismatch")
    encoded_words = [int(shaped[at:at + 11], 2)
                     for at in range(0, shaped_length, 11)]
    all_words = [int(bits[at:at + 11], 2) for at in range(0, bit_length, 11)]
    if any(word not in _INVERSE_SUBSTITUTION for word in all_words):
        raise SecRailERTMSError("invalid Eurobalise 11-bit alphabet symbol")
    try:
        words = [_INVERSE_SUBSTITUTION[word] for word in encoded_words]
    except KeyError:
        raise SecRailERTMSError("invalid Eurobalise 11-bit alphabet symbol") from None
    user_bits = _descramble(words, seed)
    user = _bit_bytes(user_bits)
    result = {
        "format": "Eurobalise telegram",
        "telegram_length": bit_length,
        "kind": "short" if bit_length == 341 else "long",
        "control_bits": control,
        "scrambling_bits": seed,
        "extra_shaping_bits": extra,
        "check_bits_valid": True,
        "shaped_words": word_count,
        "alphabet_words_checked": bit_length // 11,
        "user_data_hex": user.hex(),
    }
    # Published channel-code vectors can carry an older ETCS packet dialect.
    # Preserve a valid channel decode while clearly reporting that distinction.
    try:
        result["etcs"] = parse_etcs_user_data(user, len(user_bits))
    except SecRailERTMSError as exc:
        result["etcs_parse_error"] = str(exc)
    return result


_SAPDU_NAMES = {
    0x1: "AU1", 0x2: "AU2", 0x3: "AU3", 0x5: "DT",
    0x8: "DI", 0x9: "AR",
}


def _des_block(block, key, decrypt=False):
    if DES is None:
        raise SecRailERTMSError("PyCryptodome is required for EuroRadio MAC")
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(block) if decrypt else cipher.encrypt(block)


@_closed
def euroradio_mac(message, key):
    """Compute SUBSET-037 modified MAC algorithm 3 over supplied MAC input."""
    data = _bytes(message, "MAC input")
    secret = _bytes(key, "EuroRadio session key", 24)
    if len(secret) != 24:
        raise SecRailERTMSError("EuroRadio MAC key must be exactly 24 bytes")
    if not data:
        raise SecRailERTMSError("EuroRadio MAC input must not be empty")
    data += b"\x00" * (-len(data) % 8)
    state = b"\x00" * 8
    for at in range(0, len(data), 8):
        block = bytes(left ^ right for left, right in zip(state, data[at:at + 8]))
        state = _des_block(block, secret[:8])
    state = _des_block(state, secret[8:16], decrypt=True)
    return _des_block(state, secret[16:24])


def _destination(receiver_id):
    if type(receiver_id) is int and 0 <= receiver_id < (1 << 24):
        return receiver_id.to_bytes(3, "big")
    raw = _bytes(receiver_id, "receiver identity", 3)
    if len(raw) != 3:
        raise SecRailERTMSError("receiver identity must be 24 bits")
    return raw


@_closed
def verify_euroradio_mac(message, transmitted_mac, receiver_id, key):
    """Verify a transmitted MAC using l(DA|m) || DA || m per SUBSET-037."""
    body = _bytes(message, "SaPDU without MAC", 1024)
    tag = _bytes(transmitted_mac, "transmitted MAC", 8)
    if len(tag) != 8:
        raise SecRailERTMSError("EuroRadio MAC must be exactly 8 bytes")
    destination = _destination(receiver_id)
    covered_length = len(destination) + len(body)
    if covered_length > 0xFFFF:
        raise SecRailERTMSError("EuroRadio MAC length does not fit two octets")
    covered = covered_length.to_bytes(2, "big") + destination + body
    expected = euroradio_mac(covered, key)
    return hmac.compare_digest(expected, tag)


@_closed
def parse_euroradio_sapdu(data, receiver_id=None, key=None):
    """Inventory one SUBSET-037/098 Safety PDU and optionally verify its MAC."""
    raw = _bytes(data, "EuroRadio SaPDU", 1032)
    if not raw:
        raise SecRailERTMSError("empty EuroRadio SaPDU")
    header = raw[0]
    entity_type, message_type, direction = header >> 5, (header >> 1) & 0xF, header & 1
    name = _SAPDU_NAMES.get(message_type)
    if name is None:
        raise SecRailERTMSError("reserved EuroRadio message type")
    result = {"format": "EuroRadio SaPDU", "type": name,
              "message_type": message_type, "direction_flag": direction,
              "entity_type": entity_type, "length": len(raw)}
    fixed_direction = {"AU1": 0, "AU2": 1, "AU3": 0, "AR": 1}.get(name)
    if fixed_direction is not None and direction != fixed_direction:
        raise SecRailERTMSError(f"invalid {name} direction flag")
    has_mac = name in ("AU2", "AU3", "AR", "DT")
    expected_lengths = {"AU1": 13, "AU2": 21, "AU3": 9, "AR": 9, "DI": 3}
    if name in expected_lengths and len(raw) != expected_lengths[name]:
        raise SecRailERTMSError(f"invalid {name} SaPDU length")
    if name == "DT" and not 10 <= len(raw) <= 1032:
        raise SecRailERTMSError("DT SaPDU requires 1..1023 user-data octets")
    if name in ("AU3", "AR", "DT", "DI") and entity_type:
        result["reserved_entity_bits_nonzero"] = True
    if name in ("AU1", "AU2"):
        result.update(source_id=int.from_bytes(raw[1:4], "big"),
                      safety_feature=raw[4], random_hex=raw[5:13].hex())
        if result["safety_feature"] != 1:
            result["unsupported_safety_feature"] = True
    elif name == "DT":
        result["user_data_hex"] = raw[1:-8].hex()
    elif name == "DI":
        result.update(reason=raw[1], sub_reason=raw[2])
    if has_mac:
        result["mac_hex"] = raw[-8:].hex()
        if (receiver_id is None) != (key is None):
            raise SecRailERTMSError("receiver identity and key must be supplied together")
        if key is not None:
            result["mac_valid"] = verify_euroradio_mac(
                raw[:-8], raw[-8:], receiver_id, key
            )
    elif receiver_id is not None or key is not None:
        raise SecRailERTMSError(f"{name} does not carry a MAC")
    return result


_RBC_PACKET_TYPES = {1: "AU1", 2: "AU2", 3: "DT", 4: "DI"}


@_closed
def parse_rbc_rbc_frame(data, receiver_id=None, key=None):
    """Inventory the SUBSET-098 RBC-RBC adaptation header and nested SaPDU.

    The header checksum is retained but deliberately not asserted: SUBSET-098's
    CRC-CCITT output ordering needs an Annex-vector oracle before verification.
    """
    raw = _bytes(data, "SUBSET-098 frame", 1042)
    if len(raw) < 10:
        raise SecRailERTMSError("truncated SUBSET-098 adaptation frame")
    declared = int.from_bytes(raw[:2], "big")
    if declared != len(raw) - 2:
        raise SecRailERTMSError("SUBSET-098 packet length mismatch")
    packet_type = raw[7]
    expected_type = _RBC_PACKET_TYPES.get(packet_type)
    if expected_type is None:
        raise SecRailERTMSError("reserved SUBSET-098 packet type")
    if raw[6] not in (0, 1):
        raise SecRailERTMSError("invalid SUBSET-098 normal/redundant flag")
    sapdu = parse_euroradio_sapdu(raw[10:], receiver_id, key)
    if sapdu["type"] != expected_type:
        raise SecRailERTMSError("SUBSET-098 packet type disagrees with SaPDU")
    return {
        "format": "SUBSET-098 RBC-RBC adaptation frame",
        "packet_length": declared,
        "version": raw[2],
        "application": raw[3],
        "transmission_sequence": int.from_bytes(raw[4:6], "big"),
        "redundant": bool(raw[6]),
        "packet_type": packet_type,
        "packet_type_name": expected_type,
        "header_checksum_hex": raw[8:10].hex(),
        "header_checksum_verified": None,
        "sapdu": sapdu,
    }


def _hex_bytes(text, label):
    if not isinstance(text, str) or len(text) % 2:
        raise SecRailERTMSError(f"{label} must be even-length hexadecimal")
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise SecRailERTMSError(f"{label} must be hexadecimal") from None


def _read_bounded(path, maximum):
    try:
        if path.stat().st_size > maximum:
            raise SecRailERTMSError(f"input exceeds {maximum}-byte limit")
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
    except OSError as exc:
        raise SecRailERTMSError(f"cannot read input: {exc}") from None
    if len(data) > maximum:
        raise SecRailERTMSError(f"input exceeds {maximum}-byte limit")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description="Passive ERTMS/ETCS decoder")
    sub = parser.add_subparsers(dest="mode", required=True)
    balise = sub.add_parser("balise", help="decode a 43/128-byte telegram file")
    balise.add_argument("file", type=Path)
    user = sub.add_parser("user", help="decode a 210/830-bit user-data file")
    user.add_argument("file", type=Path)
    user.add_argument("--bits", type=int, choices=(210, 830))
    radio = sub.add_parser("euroradio", help="inventory one SaPDU file")
    radio.add_argument("file", type=Path)
    radio.add_argument("--receiver-id", help="24-bit receiver identity in hex")
    radio.add_argument("--key", help="24-byte session MAC key in hex")
    rbc = sub.add_parser("rbc-rbc", help="inventory one SUBSET-098 frame")
    rbc.add_argument("file", type=Path)
    rbc.add_argument("--receiver-id", help="24-bit receiver identity in hex")
    rbc.add_argument("--key", help="24-byte session MAC key in hex")
    mac = sub.add_parser("mac", help="calculate published algorithm-3 MAC input")
    mac.add_argument("file", type=Path)
    mac.add_argument("--key", required=True, help="24-byte key in hex")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        limits = {"balise": 128, "user": 104, "euroradio": 1032,
                  "rbc-rbc": 1042, "mac": MAX_INPUT}
        data = _read_bounded(args.file, limits[args.mode])
        if args.mode == "balise":
            result = decode_balise_telegram(data)
        elif args.mode == "user":
            result = parse_etcs_user_data(data, args.bits)
        elif args.mode in ("euroradio", "rbc-rbc"):
            receiver = (_hex_bytes(args.receiver_id, "receiver identity")
                        if args.receiver_id is not None else None)
            key = _hex_bytes(args.key, "key") if args.key is not None else None
            result = (parse_euroradio_sapdu(data, receiver, key)
                      if args.mode == "euroradio"
                      else parse_rbc_rbc_frame(data, receiver, key))
        else:
            result = {"mac_hex": euroradio_mac(data, _hex_bytes(args.key, "key")).hex()}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, SecRailERTMSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
