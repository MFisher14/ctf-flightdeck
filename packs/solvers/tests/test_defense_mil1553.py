"""MIL-STD-1553B layouts are encoded independently as literal bit strings.

Reference: sections 4.3.3.5.1/.3 and 4.3.3.6 of the published standard;
the encoder here does not call engine code or use its masks/constants.
"""

import random

import pytest

import defense_mil1553 as m


def command(rt, transmit, subaddress, count):
    return int(f"{rt:05b}{transmit:01b}{subaddress:05b}{count:05b}", 2)


def status(rt, flags="00000000000"):
    return int(f"{rt:05b}" + flags, 2)


def test_command_layout_reference():
    # Published field order: RT, T/R, subaddress, word count / mode code.
    assert command(1, 1, 2, 4) == 0x0C44
    got = m.decode_command(0x0C44)
    assert (got["rt_address"], got["transmit"], got["subaddress"], got["word_count"]) == (1, True, 2, 4)
    for rt in range(32):
        for sub in range(32):
            for count in (0, 1, 16, 31):
                got = m.decode_command(command(rt, 0, sub, count))
                assert got["rt_address"] == rt
                assert got["subaddress"] == sub
                assert got["broadcast"] == (rt == 31)
                if sub in (0, 31):
                    assert got["mode_code"] == count
                    assert got["word_count"] is None
                else:
                    assert got["word_count"] == (count or 32)


def test_status_fields_reference():
    # Status bits following RT: ME, instrumentation, SR, reserved3, BCR, busy,
    # subsystem, dynamic bus control acceptance, terminal flag.
    got = m.decode_status(status(19, "10100011111"))
    assert got["rt_address"] == 19
    assert got["message_error"] and got["service_request"]
    assert not got["instrumentation"] and got["reserved_bits"] == 0
    assert all(got[k] for k in ("broadcast_received", "busy", "subsystem_flag",
                               "dynamic_bus_control_acceptance", "terminal_flag"))
    assert m.decode_status(status(0, "01011100000"))["reserved_bits"] == 7


def test_odd_parity():
    for value in (0, 1, 0x8000, 0xFFFF, 0xA55A):
        parity = 1 - (format(value, "016b").count("1") % 2)
        assert m.decode_command(value, parity)["parity_checked"]
        assert m.decode_status(value, parity)["parity_checked"]
        with pytest.raises(m.Defense1553Error):
            m.decode_command(value, 1-parity)


def test_receive_transmit_and_broadcast_payloads():
    raw = b"CSCTF{1553!}"
    words = [int.from_bytes(raw[i:i+2], "big") for i in range(0, len(raw), 2)]
    for transmit in (0, 1):
        frame = [command(5, transmit, 7, len(words))]
        frame += [status(5)] + words if transmit else words + [status(5)]
        got = m.decode_transfer(frame)
        assert got["payload_hex"] == raw.hex()
        assert got["flags"] == ["CSCTF{1553!}"]
    got = m.decode_transfer([command(31, 0, 7, len(words))] + words)
    assert got["status"] is None
    assert got["payload_ascii"] == raw.decode()
    assert m.decode_transfer([command(1, 0, 1, 1), 0x4241, status(1)], "little")["payload_ascii"] == "AB"


def test_count_zero_means_32():
    got = m.decode_transfer([command(1, 0, 1, 0)] + list(range(32)) + [status(1)])
    assert len(got["data_words"]) == 32


def test_modes_and_status_only_busy():
    got = m.decode_transfer([command(3, 1, 0, 18), status(3), 0x0C44])
    assert got["command"]["mode_name"] == "transmit_last_command_word"
    assert got["data_words"] == [0x0C44]
    assert m.decode_transfer([command(31, 1, 0, 1)])["data_words"] == []
    assert m.decode_transfer([command(31, 0, 31, 17), 42])["data_words"] == [42]
    assert m.decode_transfer([command(3, 1, 1, 7), status(3, "00000001000")])["data_words"] == []


@pytest.mark.parametrize("frame", [
    [], [0], [command(1, 1, 1, 1), status(2), 42],
    [command(1, 0, 1, 1), status(1)],
    [command(31, 1, 1, 1), 42],
    [command(31, 1, 0, 2)],
    [command(1, 0, 0, 18), 42, status(1)],
    [command(1, 1, 0, 9), status(1)],
    [command(1, 0, 1, 1), 42, status(1, "01000000000")],
    [command(1, 0, 1, 1), 42, status(1, "00000100000")],
    [command(1, 1, 1, 1), status(1, "00000001000"), 42],
])
def test_bad_transfers(frame):
    with pytest.raises(m.Defense1553Error):
        m.decode_transfer(frame)


@pytest.mark.parametrize("value", [None, True, -1, 65536, 1.2, "0", b"\x00\x00", [], {}])
def test_bad_public_inputs(value):
    for f in (m.decode_command, m.decode_status):
        with pytest.raises(m.Defense1553Error):
            f(value)
    with pytest.raises(m.Defense1553Error):
        m.decode_transfer(value)


def test_bounded_text_and_noise_contract():
    assert m.parse_word_text("0C44 0x0800\n4241") == [0x0C44, 0x0800, 0x4241]
    for text in ("", "12345", "-1", "0x", "x", "0 "*35, " "*4097, None):
        with pytest.raises(m.Defense1553Error):
            m.parse_word_text(text)
    rng = random.Random(1553)
    for _ in range(200):
        frame = [rng.randrange(65536) for _ in range(rng.randrange(1, 35))]
        try:
            m.decode_transfer(frame)
        except m.Defense1553Error:
            pass


def test_cli(tmp_path, capsys):
    path = tmp_path / "words.txt"
    path.write_text("0841 4142 0800")
    assert m.main(["transfer", str(path)]) == 0
    assert '"payload_ascii": "AB"' in capsys.readouterr().out
    assert m.main(["command", "0c44"]) == 0
    assert m.main(["status", "0800"]) == 0
    assert m.main(["--help"]) == 0
    assert m.main([]) == 2
    assert m.main(["command", "zz"]) == 2
    assert m.main(["transfer", str(path)+"missing"]) == 2
    assert m.main(["transfer", "\0"]) == 2
    path.write_bytes(b"\xff")
    assert m.main(["transfer", str(path)]) == 2
