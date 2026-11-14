"""Hand-built field encoder, independent from decoder bit masks.

Field widths/order are from DSTO-TN-1257 / Wireshark public Link16 dissector.
The test encoder assembles least-significant-first strings of individual fields.
"""

import random

import pytest

import defense_link16 as m


def pack(fields):
    bits = "".join(format(value, f"0{width}b")[::-1] for value, width in fields)
    assert len(bits) == 70
    return int(bits[::-1], 2)


def initial(label=3, sublabel=2, mli=1, info=0):
    return pack([(0, 2), (label, 5), (sublabel, 3), (mli, 3), (info, 57)])


def test_initial_layout_reference():
    # J3.2 air-track header, MLI=1 -> literal low header 0x050c.
    assert initial() == 0x050C
    for label in range(32):
        for sublabel in range(8):
            for mli in range(8):
                got = m.decode_word(initial(label, sublabel, mli, 0x123456789ABCD))
                assert got["kind"] == "initial"
                assert got["message"] == f"J{label}.{sublabel}"
                assert got["message_length_indicator"] == mli
                assert got["information_hex"] == "123456789abcd"
                assert got["information_bit_count"] == 57


def test_extension_continuation_context():
    extension = pack([(2, 2), (0xFEDCBA9876, 68)])
    continuation = pack([(1, 2), (7, 5), (0xAABBCCDD, 63)])
    got = m.decode_words([initial(), extension, extension, continuation, initial(2, 0), extension])
    assert [w["message"] for w in got] == ["J3.2"]*4 + ["J2.0"]*2
    assert got[1]["extension_index"] == 0
    assert got[2]["extension_index"] == 1
    assert got[5]["extension_index"] == 0
    assert got[1]["information_hex"] == "fedcba9876"
    assert got[3]["continuation_label"] == 7
    assert got[3]["information_hex"] == "aabbccdd"


def test_both_container_formats():
    value = initial(3, 2, 7, (1 << 56))
    # Fixed nine-byte little-endian container from independent Python integer API.
    binary = value.to_bytes(9, "little")
    assert m.parse_words(binary, "le9")[0]["word_hex"] == f"{value:018x}"
    assert m.parse_words(f"0x{value:x}\n".encode())[0]["word_hex"] == f"{value:018x}"
    assert m.parse_words(binary, "le9")[0] == m.parse_words(f"{value:x}".encode())[0]


@pytest.mark.parametrize("value", [None, True, -1, 1 << 70, 3, 1.2, "0", b"0", [], {}])
def test_bad_word_inputs(value):
    with pytest.raises(m.DefenseLink16Error):
        m.decode_word(value)


@pytest.mark.parametrize("value", [None, True, 1, "0", b"0", [], {}, [1], [2], [0]*4097])
def test_bad_sequence_inputs(value):
    with pytest.raises(m.DefenseLink16Error):
        m.decode_words(value)


@pytest.mark.parametrize("data,packing", [
    (b"", "hex"), (b"-1", "hex"), (b"0x", "hex"), (b"0g", "hex"),
    (b"\xff", "hex"), (b"f"*19, "hex"), (b"0 "*4097, "hex"),
    (b"\0"*8, "le9"), (b"\0"*8+b"\x40", "le9"),
    (b"\0"*8+b"\x80", "le9"), (b"0", "wrong"), (b"0", []),
    (b" "*(m.MAX_FILE+1), "hex"), ("0", "hex"), (None, "hex"),
])
def test_bad_containers(data, packing):
    with pytest.raises(m.DefenseLink16Error):
        m.parse_words(data, packing)


def test_random_malformed_contract():
    rng = random.Random(6016)
    for _ in range(300):
        raw = rng.randbytes(rng.randrange(50))
        for packing in ("hex", "le9"):
            try:
                m.parse_words(raw, packing)
            except m.DefenseLink16Error:
                pass


def test_cli(tmp_path, capsys):
    path = tmp_path / "words.txt"
    path.write_text("050c 02 1d")
    assert m.main([str(path)]) == 0
    assert '"message": "J3.2"' in capsys.readouterr().out
    assert m.main(["--help"]) == 0
    assert m.main([]) == 2
    assert m.main([str(path)+"missing"]) == 2
    assert m.main(["\0"]) == 2
    assert m.main([str(path), "--packing", "nonsense"]) == 2
    path.write_text("03")
    assert m.main([str(path)]) == 2
