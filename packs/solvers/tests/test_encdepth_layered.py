"""Non-circular fixtures: stdlib encoders, RFC vectors, literal expected bytes."""
import base64
import bz2
import codecs
import gzip
import json
import lzma
import quopri
import random
import urllib.parse
import zlib

import pytest

import encdepth_layered as e


FLAG = b"CSCTF{L4yers_Keep_Bytes}"


@pytest.mark.parametrize("encoder", [base64.b64encode, base64.urlsafe_b64encode,
                                    base64.b32encode, base64.b32hexencode,
                                    base64.b85encode, base64.a85encode,
                                    bytes.hex])
def test_reference_encoder_layers(encoder):
    encoded = encoder(FLAG)
    hit = e.solve(encoded, max_depth=1)
    assert hit and hit.payload == FLAG


@pytest.mark.parametrize("compress", [gzip.compress, zlib.compress, bz2.compress, lzma.compress])
def test_nested_binary_intermediate(compress):
    # Encoding and compression are deliberately opposite traversal order.
    source = base64.b64encode(compress(FLAG))
    hit = e.solve(source, max_depth=2)
    assert hit and hit.payload == FLAG
    assert hit.chain[0] == "base64"


@pytest.mark.parametrize("compress", [gzip.compress, zlib.compress, bz2.compress, lzma.compress])
def test_compression_then_encoding(compress):
    source = compress(base64.b64encode(FLAG))
    hit = e.solve(source, max_depth=2)
    assert hit and hit.payload == FLAG
    assert hit.chain[-1] == "base64"


def test_unicode_base_existing_library_oracle():
    import base65536
    source = base64.b64encode(base65536.encode(FLAG).encode())
    hit = e.solve(source, max_depth=2)
    assert hit and hit.payload == FLAG
    assert hit.chain == ("base64", "base65536")


def test_deep_mixed_layers_and_peel_provenance():
    source = base64.b64encode(gzip.compress(urllib.parse.quote_from_bytes(FLAG).encode())).hex().encode()
    hit = e.solve(source, max_depth=4)
    assert hit and hit.matches == (FLAG,)
    assert hit.chain == ("base16", "base64", "gzip", "percent")


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32", "utf-8-sig"])
def test_bom_order(encoding):
    encoded = FLAG.decode().encode(encoding)
    assert e.peel(encoded)[0] == (encoding, FLAG)
    assert e.solve(encoded, max_depth=1).payload == FLAG


def test_qp_soft_breaks_before_base64():
    encoded = base64.b64encode(FLAG)
    encoded = encoded[:8] + b"=\r\n" + encoded[8:]
    hit = e.solve(encoded, max_depth=2)
    assert hit and hit.payload == FLAG
    assert hit.chain[-1] == "base64"


def test_transport_whitespace_not_payload_whitespace():
    payload = b"\x00 \tCSCTF{preserve}\n\x00"
    source = b" \n" + base64.b64encode(payload) + b"\r\n"
    assert e.solve(source, max_depth=1).payload == payload


@pytest.mark.parametrize("value", [b"Zh==", b"Zg=", b"Zg===", b"=Zg==", b"Z=g=", b"Zg==\v"])
def test_bad_base64_not_silently_repaired(value):
    assert "base64" not in dict(e.peel(value))


@pytest.mark.parametrize("value", [b"MZ======", b"MY=====", b"MY=======", b"M=Y====="])
def test_bad_base32_not_silently_repaired(value):
    assert "base32" not in dict(e.peel(value))


def test_unpadded_short_rfc_vectors():
    assert dict(e.peel(b"Zg"))["base64"] == b"f"
    assert dict(e.peel(b"MY"))["base32"] == b"f"


def test_raw_incomplete_and_legacy_slug_not_success():
    assert e.solve(FLAG, max_depth=0).payload == FLAG
    for text in (b"CSCTF{unfinished", b"XCSCTF{fake}", b"CSCTF{}",
                 b"the answer is here\nred-green-blue-42", b"CSCTF{bad\nline}"):
        assert e.solve(text, max_depth=1) is None


def test_wrong_case_prefix_follows_the_event_case_rule(monkeypatch):
    # CSCTF's profile is prefix-insensitive (csctf{...} is a CSCTF flag); Pink's is exact.
    assert e.solve(b"csctf{rightcase}", max_depth=1) is not None
    monkeypatch.setenv("CTF_EVENT", "pink")
    assert e.solve(b"pink{wrongcase}", max_depth=1) is None
    assert e.solve(b"PINK{rightcase}", max_depth=1) is not None


def test_literal_crib_whole_exact_case():
    payload = b"prefix [A-Z]+ exact CRIB suffix"
    source = base64.b64encode(payload)
    assert e.solve(source, crib=b"[A-Z]+ exact CRIB", max_depth=1).payload == payload
    assert e.solve(source, crib=b"[A-Z]+ exact crib", max_depth=1) is None
    assert e.solve(source, crib=b"[A-Z]+ exact CRIB more", max_depth=1) is None


def test_wrong_final_crib_never_accepted_because_english():
    source = base64.b64encode(b"This is the answer.\nred-green-blue-42")
    assert e.solve(source, crib=b"this specific full crib", max_depth=2) is None


def test_multiple_flags_are_explicit_ambiguity():
    raw = b"CSCTF{first} CSCTF{second}"
    result = e.search(base64.b64encode(raw), max_depth=1)
    assert result.candidates[0].matches == (b"CSCTF{first}", b"CSCTF{second}")
    assert e.solve(base64.b64encode(raw), max_depth=1) is None


def test_opt_in_reverse_and_rot13_roundtrip():
    source = codecs.encode(FLAG.decode(), "rot13").encode()[::-1]
    assert e.solve(source, max_depth=2) is None
    hit = e.solve(source, transforms=("rot13", "reverse"), max_depth=2)
    assert hit and hit.payload == FLAG


def test_state_and_byte_quota_report():
    source = base64.b64encode(FLAG)
    result = e.search(source, max_states=1)
    assert result.truncated and result.states == 1
    assert e.solve(source, max_states=1) is None
    result = e.search(source, max_total_bytes=len(source))
    assert result.truncated and result.total_bytes == len(source)


def test_signature_peel_priority_under_budget():
    raw = b"".join(b"&#%d;" % c for c in FLAG)
    steps = e.peel(raw)
    assert steps[0] == ("html-entities", FLAG)
    result = e.search(raw, max_depth=1, max_states=2)
    assert result.candidates[0].payload == FLAG


@pytest.mark.parametrize("compress", [gzip.compress, zlib.compress, bz2.compress, lzma.compress])
def test_compressed_overflow_truncation_and_junk(compress):
    bomb = compress(b"A" * 20000)
    assert not any(name in ("gzip", "zlib", "bzip2", "xz") for name, _ in e.peel(bomb, max_bytes=1024))
    encoded = compress(FLAG)
    for bad in (encoded[:-3], encoded + b"trailing-junk"):
        assert not any(name in ("gzip", "zlib", "bzip2", "xz") for name, _ in e.peel(bad))


@pytest.mark.parametrize("kwargs", [{"max_depth": -1}, {"max_states": 0}, {"max_bytes": True},
                                    {"max_total_bytes": "10"}, {"transforms": "reverse"},
                                    {"transforms": [None]}, {"crib": b""}, {"crib": []},
                                    {"crib": "\ud800"}])
def test_fail_closed_options(kwargs):
    with pytest.raises(e.DecodeError):
        e.search(b"abc", **kwargs)


@pytest.mark.parametrize("value", [None, 17, [], {}, "\ud800", memoryview(b"x")])
def test_fail_closed_types(value):
    with pytest.raises(e.DecodeError):
        e.search(value)


def test_random_malformed_inputs_never_leak_exception():
    rng = random.Random(126)
    for _ in range(100):
        data = rng.randbytes(rng.randrange(0, 120))
        try:
            e.search(data, max_depth=1, max_states=20)
        except e.DecodeError:
            pass


def test_guarded_cli(tmp_path, capsys):
    assert e.main(["--help"]) == 0
    assert e.main([]) == 2
    assert e.main(["invalid\x00filename"]) == 2
    assert e.main(["missing", "--max-depth", "oops"]) == 2
    path = tmp_path / "encoded.txt"
    path.write_bytes(base64.b64encode(FLAG))
    capsys.readouterr()
    assert e.main([str(path), "--max-depth", "1"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["candidates"][0]["payload_hex"] == FLAG.hex()
    assert e.main([str(path), "--max-bytes", "-1"]) == 2


def test_base122_whitespace_is_data():
    # Independent bit packing: 'A'=01000001 -> 0100000,1000000 -> SP,@.
    assert dict(e.peel(b" @"))["base122"] == b"A"
    # 0001001,1000000 -> 00010011 => 0x13; TAB is a legal first symbol.
    assert dict(e.peel(b"\t@"))["base122"] == b"\x13"


def test_base122_expensive_branch_capped():
    assert "base122" not in dict(e.peel(b"A" * 8193))


def test_literal_flag_in_invalid_container_is_not_accepted():
    # A stored XZ block exposes literal bytes, but checksum still must validate.
    source = bytearray(lzma.compress(FLAG))
    position = source.index(FLAG)
    source[position + 8] ^= 1
    assert e.solve(bytes(source), max_depth=1) is None
    assert e.solve(b"\x1f\x8b" + FLAG, max_depth=0) is None


def test_default_search_not_starved_by_speculative_branches():
    source = base64.b64encode(gzip.compress(FLAG)).hex().encode()
    result = e.search(source)
    assert not result.truncated
    assert e.solve(source).payload == FLAG
