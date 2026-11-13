"""Independent AWS example and psec 1.3.0 crypto/header oracle tests."""

import json
import random

import pytest
from psec import tr31

import payment_hw_tr31 as engine


# Published AWS Payment Cryptography export-key response, not engine output:
# https://docs.aws.amazon.com/payment-cryptography/latest/userguide/keys-export.html
AWS_BLOCK = (
    "D0144K0AB00E0000A24D3ACF3005F30A6E31D533E07F2E1B17A2A003B338B1E79"
    "E5B3AD4FBF7850FACF9A3784489581A543C84816C8D3542AE888CE6D4EDDFD09C39957B131617BC"
)


def oracle_block(monkeypatch, version="B", optional=None):
    # Fix independent library's padding random source, for reproducibility only.
    monkeypatch.setattr(tr31, "_urandom", lambda size: bytes(i % 256 for i in range(size)))
    header = tr31.Header(version, "P0", "T", "E", "01", "N")
    for name, value in (optional or {}).items():
        header.blocks[name] = value
    key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    return tr31.KeyBlock(key, header).wrap(key), key


def test_published_aws_example():
    result = engine.parse_key_block(AWS_BLOCK)
    assert result["header"] == "D0144K0AB00E0000"
    assert result["length"] == 144
    assert result["key_usage"] == "K0"
    assert result["algorithm"] == "A"
    assert result["mode_of_use"] == "B"
    assert result["key_version"] == "00"
    assert result["exportability"] == "E"
    assert result["ciphertext_bytes"] == 48
    assert result["mac"] == "AE888CE6D4EDDFD09C39957B131617BC"
    assert result["mac_bytes"] == 16
    assert result["optional_blocks"] == []
    assert result["authenticated"] is False
    assert engine.parse_key_block(AWS_BLOCK.encode("ascii")) == result


@pytest.mark.parametrize("version,mac_size,block_size", [("A", 4, 8), ("B", 8, 8), ("C", 4, 8), ("D", 16, 16)])
@pytest.mark.parametrize("optional", [None, {"KS": "00604B120F9292800000"}, {"LB": "CTF test label"}, {"LB": "X" * 300}])
def test_independent_psec_envelopes(monkeypatch, version, mac_size, block_size, optional):
    block, key = oracle_block(monkeypatch, version, optional)
    parsed = engine.parse_key_block(block)
    reference = tr31.Header()
    header_length = reference.load(block)
    # Real crypto library must authenticate its reference fixture.
    assert tr31.KeyBlock(key).unwrap(block) == key
    assert parsed["header_length"] == header_length
    assert parsed["header_length"] % block_size == 0
    assert parsed["mac_bytes"] == mac_size
    assert parsed["mac"] == block[-2 * mac_size:]
    assert parsed["ciphertext"] == block[header_length:-2 * mac_size]
    values = {entry["id"]: entry["data"] for entry in parsed["optional_blocks"] if entry["id"] != "PB"}
    assert values == dict(reference.blocks)
    if optional and len(optional.get("LB", "")) > 255:
        assert parsed["optional_blocks"][0]["extended_length"]


def replace_part(block, start, stop, text):
    return block[:start] + text + block[stop:]


@pytest.mark.parametrize("data", [None, 0, [], {}, bytearray(AWS_BLOCK.encode()), b"\xff" * 20,
                                 "", "D" * 10000, AWS_BLOCK + "\n", AWS_BLOCK + "00",
                                 AWS_BLOCK[:-1], AWS_BLOCK[:20] + "\x00" + AWS_BLOCK[21:]])
def test_wrong_types_and_malformed(data):
    with pytest.raises(engine.PaymentHWTR31Error):
        engine.parse_key_block(data)


@pytest.mark.parametrize("start,stop,value", [(0, 1, "E"), (1, 5, "0143"), (1, 5, "0A44"),
                                             (12, 14, "0A"), (14, 16, "01"), (20, 21, "Z"),
                                             (5, 6, "é"), (12, 14, "99")])
def test_corrupt_header_or_hex(start, stop, value):
    with pytest.raises(engine.PaymentHWTR31Error):
        engine.parse_key_block(replace_part(AWS_BLOCK, start, stop, value))


def hand_envelope(optional, count):
    # Deliberately hand-written structural fixture: no cryptographic validity.
    tail = "00" * 16 + "FF" * 8
    size = 16 + len(optional) + len(tail)
    return f"B{size:04d}P0TE00N{count:02d}00" + optional + tail


@pytest.mark.parametrize("optional,count", [
    ("KS03", 1), ("KSFFabcd", 1), ("KS00", 1), ("KS0000aa", 1),
    ("KS0002GGGGaaaaaa", 1), ("KS00020005aaaaaa", 1),
    ("KS0002FFFFaaaaaa", 1), ("KS000FFFFFaaaaaa", 1),
    ("KS04KS04", 2), ("PB04KS04", 2), ("!!08abcd", 1), ("KS05a", 1),
])
def test_malformed_optional_lengths_and_duplicates(optional, count):
    with pytest.raises(engine.PaymentHWTR31Error):
        engine.parse_key_block(hand_envelope(optional, count))


def test_hand_written_empty_unknown_optional_blocks():
    parsed = engine.parse_key_block(hand_envelope("ZZ04PB04", 2))
    assert parsed["optional_blocks"][0]["data"] == ""
    assert parsed["optional_blocks"][0]["id"] == "ZZ"
    assert parsed["authenticated"] is False


def test_tampering_never_implies_authentication(monkeypatch):
    block, key = oracle_block(monkeypatch)
    changed = block[:-1] + ("0" if block[-1] != "0" else "1")
    assert engine.parse_key_block(changed)["authenticated"] is False
    with pytest.raises(tr31.KeyBlockError):
        tr31.KeyBlock(key).unwrap(changed)


def test_declared_error_for_deterministic_mutations():
    random_source = random.Random(7813)
    for _ in range(300):
        chars = list(AWS_BLOCK)
        for _ in range(random_source.randrange(1, 5)):
            chars[random_source.randrange(len(chars))] = chr(random_source.randrange(256))
        try:
            result = engine.parse_key_block("".join(chars))
            assert result["authenticated"] is False
        except engine.PaymentHWTR31Error:
            pass


def test_cli(tmp_path, capsys):
    assert engine.main(["--help"]) == 0
    assert engine.main([]) == 2
    assert engine.main(["--unknown"]) == 2
    assert engine.main([str(tmp_path / "absent")]) == 2
    source = tmp_path / "block.txt"
    source.write_bytes(AWS_BLOCK.encode() + b"\r\n")
    capsys.readouterr()
    assert engine.main([str(source)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["length"] == 144
    assert engine.main(["--block", AWS_BLOCK]) == 0
    assert engine.main([str(source), "--block", AWS_BLOCK]) == 2
    source.write_bytes(b"X" * 20000)
    assert engine.main([str(source)]) == 2


def test_cli_noninteger_systemexit(monkeypatch):
    def exit_with_string(*args, **kwargs):
        raise SystemExit("bad arguments")
    monkeypatch.setattr(engine.argparse.ArgumentParser, "parse_args", exit_with_string)
    assert engine.main([]) == 2
