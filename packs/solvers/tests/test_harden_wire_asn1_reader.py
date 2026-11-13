"""Independent cryptography/asn1crypto DER, SSH and RFC4880 packet vectors.

https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
https://www.rfc-editor.org/rfc/rfc4880#section-12.2
"""
import base64
from datetime import datetime, timezone
import hashlib
import random
import struct

from asn1crypto import core
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
import pytest

import asn1_reader as engine


def certificate():
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CSCTF test')])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(0x12345678).not_valid_before(datetime(2020, 1, 2, tzinfo=timezone.utc))
            .not_valid_after(datetime(2030, 3, 4, tzinfo=timezone.utc)).sign(key, None))


def test_real_certificate_der_pem_and_pure_fallback(monkeypatch):
    cert = certificate()
    der = cert.public_bytes(serialization.Encoding.DER)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    assert engine.pem_blocks(pem) == [('CERTIFICATE', der)]
    for available in (True, False):
        monkeypatch.setattr(engine, '_HAVE_CRYPTO', available)
        for data in (der, pem):
            out = engine.classify(data)['facts']
            assert out['serial'] == 0x12345678
            assert out['subject_cn'] == out['issuer_cn'] == 'CSCTF test'
            assert out['not_before'] == datetime(2020, 1, 2, tzinfo=timezone.utc)
            assert out['not_after'] == datetime(2030, 3, 4, tzinfo=timezone.utc)
            assert out['fingerprint_sha256'] == hashlib.sha256(der).hexdigest()


def test_openssh_real_public_key_and_hash():
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32))).public_key()
    text = key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    blob = base64.b64decode(text.split()[1])
    out = engine.ssh_pubkey(text + ' fixture')
    assert out['ssh_type'] == 'ssh-ed25519'
    assert out['ssh_bits'] == 256
    assert out['ssh_comment'] == 'fixture'
    assert out['ssh_fingerprint_sha256'] == 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def pgp():
    # v4, creation1, RSA, MPI modulus16bits and exponent17bits.
    body = bytes.fromhex('04 00000001 01 0010 ca01 0011 010001')
    return b'\xc6' + bytes([len(body)]) + body, body


def test_openpgp_fingerprint_exact_prefix_and_byte_order():
    raw, body = pgp()
    expected = hashlib.sha1(b'\x99' + len(body).to_bytes(2, 'big') + body).hexdigest()
    out = engine.pgp_key(raw)
    assert out['pgp_fingerprint'] == expected
    assert out['pgp_keyid'] == expected[-16:]
    assert out['pgp_created'] == datetime(1970, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
    assert out['pgp_algo'] == 'rsa'


@pytest.mark.parametrize('year', [1950, 1968, 1969, 1999, 2000, 2049])
def test_rfc5280_utc_time_century_boundary(year):
    raw = core.UTCTime(datetime(year, 1, 2, 3, 4, 5, tzinfo=timezone.utc)).contents
    assert engine._der_time(raw, 0, len(raw)) == datetime(year, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


@pytest.mark.parametrize('oid', ['1.2.840.113549.1.1.1', '2.5.4.3', '0.9.2342.19200300.100.1.25'])
def test_asn1crypto_object_identifier(oid):
    raw = core.ObjectIdentifier(oid).contents
    assert engine._der_oid(raw, 0, len(raw)) == oid


@pytest.mark.parametrize('oid', ['2.999.3', '2.48.1'])
def test_multibyte_first_oid_subidentifier(oid):
    raw = core.ObjectIdentifier(oid).contents
    assert engine._der_oid(raw, 0, len(raw)) == oid


def test_truncated_ssh_key_does_not_claim_256_bits():
    raw = struct.pack('>I', 11) + b'ssh-ed25519'
    assert engine.ssh_pubkey('ssh-ed25519 ' + base64.b64encode(raw).decode()) is None


def call_closed(function, *args):
    try:
        return function(*args)
    except engine._DerError:
        return None


@pytest.mark.parametrize('entry', [engine.pgp_key, engine.classify])
def test_old_pgp_header_missing_length(entry):
    call_closed(entry, b'\x98')


def test_oversized_v4_pgp_body():
    body = b'\x04\0\0\0\x01\x01' + bytes(65536)
    call_closed(engine.pgp_key, b'\xc6\xff' + len(body).to_bytes(4, 'big') + body)


def test_empty_pem_certificate_sequence():
    call_closed(engine.classify, b'-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----')


@pytest.mark.parametrize('entry', [engine.pem_blocks, engine.pgp_key, engine.classify])
def test_random_truncated_mutated_bytes(entry, monkeypatch):
    rng = random.Random(0xa511)
    der = certificate().public_bytes(serialization.Encoding.DER)
    inputs = [b'', b'\xff' * 512] + [rng.randbytes(n) for n in (2, 3, 4, 15, 100, 1024)]
    for valid in (der, pgp()[0]):
        inputs += [valid[:n] for n in (1, 2, 5, len(valid)-1)]
        for _ in range(20):
            altered = bytearray(valid)
            altered[rng.randrange(len(valid))] ^= 1 << rng.randrange(8)
            inputs.append(bytes(altered))
    for raw in inputs:
        call_closed(entry, raw)
    monkeypatch.setattr(engine, 'MAX_FILE', 16)
    assert engine.classify(der) is None
