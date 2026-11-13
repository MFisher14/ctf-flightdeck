"""Independent stdlib encoders and published RFC vectors; no engine encoders."""
import base64
import binascii
import ipaddress
import random

import pytest

import encdepth_transport as codec


def corpus():
    rng = random.Random(2045)
    return [b"", b"CSCTF{transport_edges}", b"\0\0\0\0    ", bytes(range(256))] + [
        bytes(rng.randrange(256) for _ in range(n)) for n in range(1, 61)
    ]


def test_qp_stdlib_encoder():
    for plain in corpus():
        encoded = binascii.b2a_qp(plain, quotetabs=True, istext=False)
        assert codec.decode_qp(encoded) == plain


def test_qp_rfc2045_softbreak_and_transport_space():
    # RFC2045 section 6.7 published sentence, represented with soft breaks.
    wire = b"Now's the time =\r\nfor all folk to come=\r\n to the aid of their country."
    assert codec.decode_qp(wire) == b"Now's the time for all folk to come to the aid of their country."
    assert codec.decode_qp(b"first \t\r\nsecond\t \n") == b"first\r\nsecond\n"
    assert codec.decode_qp(b"a_b=3Dc") == b"a_b=c"
    assert codec.decode_qp(b"=3d", allow_lowercase=True) == b"="


@pytest.mark.parametrize("wire", [b"=", b"=A", b"=GG", b"=3d", b"\xff", b"a\rb", b"a\x00b", b"a" * 77, b"abc= \n=QZ"])
def test_qp_rejects_malformed(wire):
    with pytest.raises(codec.TransportError):
        codec.decode_qp(wire)


def uu_reference(plain, backtick):
    return b"begin 644 ignored.bin\n" + b"".join(
        binascii.b2a_uu(plain[i:i + 45], backtick=backtick) for i in range(0, len(plain), 45)
    ) + (b"`\n" if backtick else b" \n") + b"end\n"


def test_uu_stdlib_encoder_both_zero_aliases():
    for plain in corpus():
        for backtick in (False, True):
            assert codec.decode_uu(uu_reference(plain, backtick)) == plain
            assert codec.decode_uu(uu_reference(plain, backtick).replace(b"\n", b"\r\n")) == plain


def test_uu_base64_variant_independent_encoder():
    for plain in corpus():
        encoded = b"begin-base64 644 unused\n" + base64.encodebytes(plain) + b"====\n"
        assert codec.decode_uu(encoded) == plain


@pytest.mark.parametrize("wire", [
    b"begin 644 x\n#04)#\nend\n",  # missing length-zero record
    b"begin 644 x\n`\nend\njunk\n",
    b"begin 644 x\n!00 !\n`\nend\n",  # nonzero unused sextet bits
    b"begin 644 x\n!0\n`\nend\n",  # a2b_uu would silently pad missing data
    b"begin 644 x\n`\n#04)#\n`\nend\n",
    b"begin-base64 644 x\nZh==\n====\n",  # noncanonical base64 pad bits
    b"begin-base64 644 x\nZg\n====\n",
    b"begin-base64 644 x\nZg==\nend\n",
    b"begin 888 x\n`\nend\n",
])
def test_uu_rejects_incomplete_frames_and_padding(wire):
    with pytest.raises(codec.TransportError):
        codec.decode_uu(wire)


def test_ascii85_stdlib_encoders_dialects():
    for plain in corpus():
        adobe = base64.a85encode(plain, adobe=True, wrapcol=17)
        assert codec.decode_ascii85(adobe) == plain
        assert codec.decode_ascii85(adobe[2:]) == plain  # PDF allows only trailing delimiter
        bare = base64.a85encode(plain, foldspaces=True, wrapcol=23)
        assert codec.decode_ascii85(bare, dialect="btoa-body") == plain
    assert codec.decode_ascii85(b"!!!!!~>") == b"\0" * 4
    assert codec.decode_ascii85(b"y", dialect="btoa-body") == b" " * 4


@pytest.mark.parametrize("wire", [b"!~>", b"<~!!", b"<~uuuuu~>", b"<~!z~>", b"<~y~>", b"<~!!~>junk", b"<~\x0b!!~>", b"< ~!!~>", b"<~!!~ >", b"< ~!!~ >", b"<\x00~!!~>"])
def test_ascii85_malformed(wire):
    with pytest.raises(codec.TransportError):
        codec.decode_ascii85(wire)


def test_rfc1924_published_vector_and_integer_encoder():
    # RFC1924 section 5, not block-wise Python b85 encoding.
    assert codec.decode_rfc1924(b"4)+k&C#VzJ4br>0wv%Yp") == ipaddress.IPv6Address("1080::8:800:200c:417a").packed
    alphabet = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
    rng = random.Random(1924)
    for value in [0, (1 << 128) - 1] + [rng.getrandbits(128) for _ in range(20)]:
        n, out = value, bytearray()
        for _ in range(20):
            n, remainder = divmod(n, 85)
            out.append(alphabet[remainder])
        assert codec.decode_rfc1924(bytes(reversed(out))) == value.to_bytes(16, "big")
    with pytest.raises(codec.TransportError):
        codec.decode_rfc1924(b"~" * 20)


def test_idna_published_and_idna2008_differences():
    # A-label examples from idna docs and the standard sharp-s distinction.
    assert codec.decode_idna(b"XN--BCHER-KVA.example.") == "bücher.example.".encode()
    assert codec.decode_idna(b"xn--fa-hia.de") == "faß.de".encode()
    assert codec.decode_idna(b"example.com") == b"example.com"
    for wire in [b"xn--", b"bad_name.example", b"-bad.example", b"a..b", b"a" * 64 + b".com", b"xn--e28h.com"]:
        with pytest.raises(codec.TransportError):
            codec.decode_idna(wire)


def test_declared_error_contract_and_limits():
    for reader in [codec.decode_qp, codec.decode_uu, codec.decode_ascii85, codec.decode_rfc1924, codec.decode_idna]:
        for value in [None, 3, [], {}, "\ud800", "é", b"x" * (codec.MAX_INPUT + 1)]:
            with pytest.raises(codec.TransportError):
                reader(value)
    with pytest.raises(codec.TransportError):
        codec.decode_qp(b"x", allow_lowercase=1)
    with pytest.raises(codec.TransportError):
        codec.decode_ascii85(b"", dialect=[])


def test_steps_are_marker_gated_and_cli_guarded(tmp_path, capsys):
    assert codec.steps(b"normal prose") == []
    assert codec.steps(b"4)+k&C#VzJ4br>0wv%Yp") == []
    assert codec.steps(b"CSCTF=7Bqp=7D") == [("quoted-printable", b"CSCTF{qp}")]
    assert codec.steps(b"=GG") == []
    assert codec.steps(None) == []
    assert codec.main(["--help"]) == 0
    assert codec.main([]) == 2
    assert codec.main(["nonsense", "x"]) == 2
    assert codec.main(["qp", str(tmp_path / "missing")]) == 1
    capsys.readouterr()


def test_cli_invalid_path_contract():
    import encdepth_transport
    assert encdepth_transport.main(["qp", "invalid\x00filename"]) == 1
