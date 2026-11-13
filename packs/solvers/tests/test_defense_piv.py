"""Independent SP800-73 field fixtures and cryptography-generated certificates."""
from datetime import datetime, timezone
import gzip
import random

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from defense_piv import MAX_BYTES, PIVError, main, parse_piv


def tlv(tag, value):
    """Handwritten ISO7816 definite-length writer, independent of parser."""
    tagbytes = tag.to_bytes((tag.bit_length() + 7) // 8, "big")
    size = len(value)
    length = bytes([size]) if size < 128 else b"\x82" + size.to_bytes(2, "big")
    return tagbytes + length + value


def chuid(*, date=b"20300228", signature=b"", extra=b""):
    # NIST SP800-73pt1-5 Table10 field widths and tag values.
    return (b"\x30\x19" + bytes(range(25)) + b"\x34\x10" + bytes(range(16))
            + b"\x35\x08" + date + tlv(0x3E, signature) + b"\xFE\x00" + extra)


@pytest.fixture(scope="module")
def certificate():
    # Fixed Ed25519 seed and timestamps produce a deterministic, real X509 DER.
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CSCTF offline oracle")])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(123456)
            .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
            .sign(key, algorithm=None).public_bytes(serialization.Encoding.DER))


def cert_object(cert, compressed=False):
    data = gzip.compress(cert, mtime=0) if compressed else cert
    return tlv(0x53, tlv(0x70, data) + tlv(0x71, bytes([compressed])) + b"\xfe\x00")


def test_chuid_nist_field_layout():
    report = parse_piv(chuid(extra=b"\x36\x10" + bytes(reversed(range(16)))))
    assert report["guid"] == "00010203-0405-0607-0809-0a0b0c0d0e0f"
    assert report["cardholder_uuid"] == "0f0e0d0c-0b0a-0908-0706-050403020100"
    assert report["expiration"] == "2030-02-28"
    assert report["fasc_n_hex"] == bytes(range(25)).hex()
    assert report["signature_present"] is False
    assert report["signature_verified"] is report["authenticated"] is False


def test_wrapped_apdu_and_unknown_element():
    raw = tlv(0x53, chuid(signature=b"opaque CMS", extra=tlv(0x7F21, b"future"))) + b"\x90\x00"
    report = parse_piv(raw, apdu=True)
    assert report["wrapped"] and report["signature_present"]
    assert report["fields"][-1] == {"tag": "7F21", "length": 6, "hex": b"future".hex()}
    with pytest.raises(PIVError):
        parse_piv(raw)


@pytest.mark.parametrize("compressed", [False, True])
def test_real_certificate_envelope(certificate, compressed):
    report = parse_piv(cert_object(certificate, compressed))
    assert report["compressed"] is compressed
    assert bytes.fromhex(report["certificate_der_hex"]) == certificate
    assert report["certificate_bytes"] == len(certificate)
    assert report["authenticated"] is False


def test_every_truncation(certificate):
    for raw in (tlv(0x53, chuid()), cert_object(certificate), cert_object(certificate, True)):
        for n in range(len(raw)):
            with pytest.raises(PIVError):
                parse_piv(raw[:n])


@pytest.mark.parametrize("raw", [b"", b"\x53\x80\x00\x00", b"\x53\x84\xff\xff\xff\xff",
                                    b"\x7f", b"\x7f\x80\x00\x00", b"\x53\x01\x00",
                                    b"\xff\x00", b"\x00\x00", b"\x53\x00"])
def test_malformed_lengths_and_tags(raw):
    with pytest.raises(PIVError):
        parse_piv(raw)


@pytest.mark.parametrize("value", [None, True, 99, [], {}, "text", memoryview(b"x"), b"x" * (MAX_BYTES + 1)])
def test_bad_types_and_size(value):
    with pytest.raises(PIVError):
        parse_piv(value)


@pytest.mark.parametrize("date", [b"20230229", b"00000229", b"20301301", b"20300230", b"2030010x", b"\xff" * 8])
def test_bad_dates(date):
    with pytest.raises(PIVError):
        parse_piv(chuid(date=date))


def test_missing_duplicate_wrong_fields():
    for raw in (chuid()[:-2], chuid(extra=b"\x35\x08" + b"20300101"),
                chuid().replace(b"\x34\x10", b"\x34\x0f", 1),
                chuid(extra=b"\x70\x00"), chuid().replace(b"\xfe\x00", b"\xfe\x01x"),
                chuid(signature=b"x" * 2817)):
        with pytest.raises(PIVError):
            parse_piv(raw)


def test_cert_rejects_bad_content(certificate):
    for payload, info in ((b"garbage", b"\x00"), (certificate + b"x", b"\x00"),
                          (certificate, b"\x02"), (certificate, b""),
                          (gzip.compress(certificate)[:-1], b"\x01"),
                          (gzip.compress(certificate) + gzip.compress(certificate), b"\x01"),
                          (gzip.compress(b"x" * (MAX_BYTES + 1)), b"\x01")):
        with pytest.raises(PIVError):
            parse_piv(tlv(0x70, payload) + tlv(0x71, info) + b"\xfe\x00")


def test_bad_options():
    for kw in ({"kind": []}, {"kind": "other"}, {"apdu": 1}, {"apdu": True}, {"kind": "certificate"}):
        with pytest.raises(PIVError):
            parse_piv(chuid(), **kw)


def test_deterministic_garbage_contract():
    rng = random.Random(731)
    for size in range(512):
        raw = rng.randbytes(size)
        try:
            parse_piv(raw)
        except PIVError:
            pass


def test_cli(tmp_path, certificate, capsys):
    source, output = tmp_path / "piv.bin", tmp_path / "cert.der"
    source.write_bytes(cert_object(certificate, True))
    assert main([str(source), "--certificate-out", str(output)]) == 0
    assert output.read_bytes() == certificate
    assert main([str(source), "--certificate-out", str(output)]) == 2
    assert main([]) == 2
    assert main(["--help"]) == 0
    assert main([str(tmp_path / "missing")]) == 2
    assert main(["bad\x00path"]) == 2
    assert main([str(source), "--certificate-out", "bad\x00path"]) == 2
