"""Independent ISO7816/EMV grammar vectors, not engine-generated fixtures.

Length rules: Oracle Java Card 3.1 Extended APDU Format (ISO7816-4 summary).
Command/status meanings: EMV Book 3, section 6. Values are synthetic.
"""

import argparse
import json
import random

import pytest

import payment_hw_apdu as apdu


@pytest.mark.parametrize("wire,case,body,lc,le", [
    ("00A40000", "1", "", 0, None),
    ("00B2010C20", "2S", "", 0, 32),
    ("00B2010C00", "2S", "", 0, 256),
    ("00A4040007A0000000031010", "3S", "A0000000031010", 7, None),
    ("80A8000002830000", "4S", "8300", 2, 256),
    ("00C00000000001", "2E", "", 0, 1),
    ("00C00000000000", "2E", "", 0, 65536),
    ("00A40400000007A0000000031010", "3E", "A0000000031010", 7, None),
    ("80AE80000000030102031000", "4E", "010203", 3, 4096),
    ("80AE80000000030102030000", "4E", "010203", 3, 65536),
])
def test_published_length_grammar(wire, case, body, lc, le):
    result = apdu.parse_command(wire)
    assert result["case"] == case
    assert result["lc"] == lc
    assert result["le"] == le
    assert result["data_hex"] == body
    assert result["raw_hex"] == wire


def reference_command(header, body, expected, extended):
    """Independent assembler directly following the ISO length-field table."""
    result = bytearray(header)
    if body:
        if extended:
            result.extend((0, len(body) // 256, len(body) % 256))
        else:
            result.append(len(body))
        result.extend(body)
    if expected is not None:
        if extended:
            if not body:
                result.append(0)
            result.extend(((expected % 65536) // 256, expected % 256))
        else:
            result.append(expected % 256)
    return bytes(result)


@pytest.mark.parametrize("length,le,extended", [
    (0, None, False), (0, 1, False), (0, 255, False), (0, 256, False),
    (1, None, False), (255, 256, False), (255, 255, False),
    (0, 65535, True), (0, 65536, True), (1, 1, True),
    (256, None, True), (65535, None, True), (65535, 65536, True),
])
def test_boundary_sizes_from_independent_encoder(length, le, extended):
    body = bytes(index % 251 for index in range(length))
    raw = reference_command((0x80, 0xAE, 0x80, 0), body, le, extended)
    result = apdu.parse_command(raw)
    assert result["lc"] == length
    assert result["le"] == le
    assert bytes.fromhex(result["data_hex"]) == body
    assert result["requested_cryptogram"] == "ARQC"


@pytest.mark.parametrize("raw", [
    b"", b"\x00", b"\x00\x00\x00", "xyz", "000", "00:00:00:00", "0x00",
    "00A4040007A000", "00A4040001AABBCC", "00A400000000",  # lengths
    "00A4000000000000",  # zero extended Lc followed by data
    "00A40000000001AA00",  # mixed extended Lc and short Le
    "00A40000000001AA000000",  # three-byte Le when Lc already present
    None, 9, True, [], {}, memoryview(b"0000"),
])
def test_malformed_command_contract(raw):
    with pytest.raises(apdu.APDUError):
        apdu.parse_command(raw)


def test_oversized_inputs():
    with pytest.raises(apdu.APDUError):
        apdu.parse_command(b"\0" * (apdu.MAX_COMMAND + 1))
    with pytest.raises(apdu.APDUError):
        apdu.parse_response(b"\0" * (apdu.MAX_RESPONSE + 1))
    with pytest.raises(apdu.APDUError):
        apdu.parse_trace(" " * (apdu.MAX_TRACE + 1))
    with pytest.raises(apdu.APDUError):
        apdu.parse_trace("\n" * (apdu.MAX_TRACE_LINES + 1))


def test_command_semantics_and_class_awareness():
    select = apdu.parse_command("00A404000E325041592E5359532E444446303100")
    assert select["command"] == "SELECT"
    assert select["df_name_ascii"] == "2PAY.SYS.DDF01"
    record = apdu.parse_command("00B2021400")
    assert (record["record_reference"], record["record_mode"], record["sfi"]) == (2, 4, 2)
    assert apdu.parse_command("00B201FC00")["sfi_meaning"] == "reserved"
    assert apdu.parse_command("00B2010400")["sfi_meaning"] == "current EF"
    assert apdu.parse_command("80A8000002830000")["command"] == "GET PROCESSING OPTIONS"
    assert apdu.parse_command("80AE900000")["cda_requested"] is True
    assert apdu.parse_command("80AE400000")["requested_cryptogram"] == "TC"
    assert apdu.parse_command("80AEC00000")["requested_cryptogram"] == "RFU"
    assert apdu.parse_command("0020008008241234FFFFFFFFFF")["verification_reference"] == "plaintext offline PIN"
    for raw in ("80A4040000", "90A4040000", "20A4040000", "00AE800000"):
        assert apdu.parse_command(raw)["command"] == "UNKNOWN"


def test_logical_channels_and_secure_messaging():
    channel = apdu.parse_command("03A4040000")
    assert channel["command"] == "SELECT"
    assert channel["logical_channel"] == 3
    assert channel["secure_messaging"] is False
    secured = apdu.parse_command("6FA4040002000000")
    assert secured["logical_channel"] == 19
    assert secured["secure_messaging"] is True
    assert "df_name_hex" not in secured
    assert apdu.parse_command("10B2010C00")["command_chaining"] is True


@pytest.mark.parametrize("wire,status,key,value", [
    ("9000", "normal processing", "success", True),
    ("6A82", "file or application not found", "success", False),
    ("6100", "response bytes available", "available_bytes", 256),
    ("6110", "response bytes available", "available_bytes", 16),
    ("6C00", "wrong Le; correct short Le indicated", "correct_le", 256),
    ("6C80", "wrong Le; correct short Le indicated", "correct_le", 128),
    ("63C2", "verification failed; retry counter indicated", "retries_remaining", 2),
    ("63C0", "verification failed; retry counter indicated", "retries_remaining", 0),
    ("6983", "authentication method blocked", "success", False),
    ("9123", "unknown status", "success", False),
])
def test_response_status(wire, status, key, value):
    result = apdu.parse_response("DEADBEEF" + wire)
    assert result["sw"] == wire
    assert result["data_hex"] == "DEADBEEF"
    assert result["data_length"] == 4
    assert result["status"] == status
    assert result[key] == value


@pytest.mark.parametrize("raw", [None, False, 2, [], {}, "", "90", "900", "nonsense", b"\x90"])
def test_response_contract(raw):
    with pytest.raises(apdu.APDUError):
        apdu.parse_response(raw)


def test_directional_trace_and_get_response():
    result = apdu.parse_trace("""# SELECT then GET RESPONSE
> 00 A4 04 00 07 A0 00 00 00 03 10 10 00
< 61 10

C: 00 C0 00 00 10
R: 6F0084009000
""")
    assert len(result) == 2
    assert result[0]["command_line"] == 2
    assert result[0]["response_line"] == 3
    assert result[0]["response"]["available_bytes"] == 16
    assert result[1]["command"]["command"] == "GET RESPONSE"
    assert result[1]["response"]["data_hex"] == "6F008400"
    assert result[1]["response"]["success"] is True


@pytest.mark.parametrize("text", [
    None, [], b"> 00A40000\n< 9000", "", "# comment", "9000", "< 9000",
    "> 00A40000", "> 00A40000\n> 00A40000", "> 00A40000\n< 9000\n< 9000",
    "> 00A40000\n< FF", "TX: 00A40000\nRX: 9000", "> 00A40000 # inline comment\n< 9000",
])
def test_trace_contract(text):
    with pytest.raises(apdu.APDUError):
        apdu.parse_trace(text)


def test_deterministic_arbitrary_data_does_not_leak_exceptions():
    rng = random.Random(7816)
    for length in range(128):
        raw = rng.randbytes(length)
        for parser in (apdu.parse_command, apdu.parse_response):
            try:
                result = parser(raw)
            except apdu.APDUError:
                continue
            assert result["raw_hex"] == raw.hex().upper()
            if parser is apdu.parse_command:
                reconstructed = reference_command(
                    (result["cla"], result["ins"], result["p1"], result["p2"]),
                    bytes.fromhex(result["data_hex"]), result["le"], result["extended"])
                assert reconstructed == raw


def test_cli(tmp_path, capsys):
    assert apdu.main(["command", "--hex", "80A8000002830000"]) == 0
    assert json.loads(capsys.readouterr().out)["command"] == "GET PROCESSING OPTIONS"
    path = tmp_path / "trace.txt"
    path.write_text(">00A40000\n<9000\n", encoding="utf-8")
    assert apdu.main(["trace", str(path)]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 1
    path.write_bytes(b"\x00\xA4\x00\x00")
    assert apdu.main(["command", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["case"] == "1"
    assert apdu.main(["trace", str(path)]) == 2
    assert apdu.main(["command", "--hex", "bad"]) == 2
    assert apdu.main(["command", str(tmp_path / "missing")]) == 2
    assert apdu.main(["command", "\0"]) == 2
    assert apdu.main(["command"]) == 2
    assert apdu.main(["command", str(path), "--hex", "00A40000"]) == 2
    assert apdu.main(["trace", "--hex", "00A40000"]) == 2
    assert apdu.main([]) == 2
    assert apdu.main(["--help"]) == 0


def test_cli_noninteger_system_exit_guard(monkeypatch):
    def fail(*args, **kwargs):
        raise SystemExit("not an integer")
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", fail)
    assert apdu.main([]) == 2
