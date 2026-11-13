"""Known-answer tests for the EBICS decrypt-with-key helper (B-161).

Fixtures are built here from the E002 recipe with an AES implementation
separate from the module's (pycryptodome): zlib-compress, pad (ANSI X9.23 /
PKCS#7), AES-128-CBC with a zero IV, base64 into OrderData; the transaction key
is RSA PKCS#1 v1.5 encrypted to a freshly generated receiver key, and the H004
``EncryptionPubKeyDigest`` is computed here from its spelled-out definition.
"""

from __future__ import annotations

import base64
import hashlib
import json
import zlib

import pytest
from Crypto.Cipher import AES, DES3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import sec_bank_ebics_decrypt as D


H004 = "urn:org:ebics:H004"
H005 = "urn:org:ebics:H005"
TX_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
ORDER = (b'<?xml version="1.0" encoding="UTF-8"?>\n<Document xmlns="urn:iso:std:iso:20022:tech:xsd:'
         b'camt.053.001.08"><BkToCstmrStmt><GrpHdr><MsgId>CSCTF{ebics_order_plain}</MsgId></GrpHdr>'
         b'<Ustrd>' + b"x" * 300 + b'</Ustrd></BkToCstmrStmt></Document>')


def x923(data: bytes) -> bytes:
    count = 16 - len(data) % 16
    return data + bytes(count - 1) + bytes((count,))


def pkcs7(data: bytes) -> bytes:
    count = 16 - len(data) % 16
    return data + bytes((count,)) * count


def encrypt(plain: bytes, key: bytes = TX_KEY, pad=x923, compress: bool = True) -> bytes:
    body = zlib.compress(plain) if compress else plain
    return AES.new(key, AES.MODE_CBC, iv=bytes(16)).encrypt(pad(body))


@pytest.fixture(scope="module")
def receiver():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


@pytest.fixture(scope="module")
def other():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def h004_digest(key) -> str:
    numbers = key.public_key().public_numbers()
    exponent = format(numbers.e, "x").lstrip("0")
    modulus = format(numbers.n, "x").lstrip("0")
    return base64.b64encode(hashlib.sha256(f"{exponent} {modulus}".encode()).digest()).decode()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def response_init(wrapped: bytes, segment: bytes, digest: str, *, last: str = "false", tid: str = "AB12",
                  version: str = "E002") -> bytes:
    return f'''<ebicsResponse xmlns="{H004}" Version="H004" Revision="1">
  <header authenticate="true">
    <static><TransactionID>{tid}</TransactionID><NumSegments>2</NumSegments></static>
    <mutable><TransactionPhase>Initialisation</TransactionPhase>
      <SegmentNumber lastSegment="{last}">1</SegmentNumber>
      <ReturnCode>000000</ReturnCode><ReportText>[EBICS_OK] OK</ReportText></mutable>
  </header>
  <body>
    <DataTransfer>
      <DataEncryptionInfo authenticate="true">
        <EncryptionPubKeyDigest Version="{version}" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256">{digest}</EncryptionPubKeyDigest>
        <TransactionKey>{b64(wrapped)}</TransactionKey>
      </DataEncryptionInfo>
      <OrderData>{b64(segment)}</OrderData>
    </DataTransfer>
    <ReturnCode authenticate="true">000000</ReturnCode>
  </body>
</ebicsResponse>'''.encode()


def response_transfer(segment: bytes, number: int, *, last: str = "true", tid: str = "AB12") -> bytes:
    return f'''<ebicsResponse xmlns="{H004}" Version="H004" Revision="1">
  <header authenticate="true">
    <static><TransactionID>{tid}</TransactionID></static>
    <mutable><TransactionPhase>Transfer</TransactionPhase>
      <SegmentNumber lastSegment="{last}">{number}</SegmentNumber></mutable>
  </header>
  <body><DataTransfer><OrderData>{b64(segment)}</OrderData></DataTransfer>
    <ReturnCode authenticate="true">000000</ReturnCode></body>
</ebicsResponse>'''.encode()


def two_segment_download(receiver):
    ciphertext = encrypt(ORDER)
    cut = (len(ciphertext) // 32) * 16  # split on a block boundary
    wrapped = receiver.public_key().encrypt(TX_KEY, padding.PKCS1v15())
    init = response_init(wrapped, ciphertext[:cut], h004_digest(receiver))
    transfer = response_transfer(ciphertext[cut:], 2)
    return init, transfer


# ------------------------------------------------------------------ payload primitive

def test_payload_known_answer_x923_and_pkcs7():
    for pad in (x923, pkcs7):
        assert D.decrypt_payload(encrypt(ORDER, pad=pad), TX_KEY)["plaintext"] == ORDER
    body = b"0123456789"  # 10 bytes: six padding bytes, so the schemes differ
    assert D.decrypt_payload(encrypt(body, compress=False), TX_KEY, inflate=False)["padding"] == "ansi-x9.23"
    assert D.decrypt_payload(encrypt(body, pad=pkcs7, compress=False), TX_KEY,
                             inflate=False)["padding"] == "pkcs7"
    iso = AES.new(TX_KEY, AES.MODE_CBC, iv=bytes(16)).encrypt(body + b"\x11\x22\x33\x44\x55\x06")
    assert D.decrypt_payload(iso, TX_KEY, inflate=False) == {
        "plaintext": body, "padding": "iso-10126", "compressed_bytes": 10, "cipher": "aes-128-cbc",
        "key_verified": False}


def test_payload_without_inflate_returns_compressed_body():
    result = D.decrypt_payload(encrypt(b"raw order", compress=False), TX_KEY, inflate=False)
    assert result["plaintext"] == b"raw order"
    with pytest.raises(D.EbicsDecryptError, match="not zlib"):
        D.decrypt_payload(encrypt(b"raw order", compress=False), TX_KEY)


def test_payload_wrong_key_and_bad_lengths_fail_by_name():
    with pytest.raises(D.EbicsDecryptError, match="padding|zlib"):
        D.decrypt_payload(encrypt(ORDER), bytes(16))
    with pytest.raises(D.EbicsDecryptError, match="multiple of 16"):
        D.decrypt_payload(encrypt(ORDER)[:-1], TX_KEY)
    with pytest.raises(D.EbicsDecryptError, match="16 bytes"):
        D.decrypt_payload(encrypt(ORDER), TX_KEY[:8])


def test_payload_truncated_stream_and_trailing_data_detected():
    full = zlib.compress(ORDER)
    truncated = AES.new(TX_KEY, AES.MODE_CBC, iv=bytes(16)).encrypt(x923(full[:-6]))
    with pytest.raises(D.EbicsDecryptError, match="truncated"):
        D.decrypt_payload(truncated, TX_KEY)
    trailing = AES.new(TX_KEY, AES.MODE_CBC, iv=bytes(16)).encrypt(x923(full + b"junk"))
    with pytest.raises(D.EbicsDecryptError, match="follow the zlib stream"):
        D.decrypt_payload(trailing, TX_KEY)


def test_payload_inflate_cap():
    bomb = encrypt(b"\x00" * 200_000)
    with pytest.raises(D.EbicsDecryptError, match="cap"):
        D.decrypt_payload(bomb, TX_KEY, max_plaintext=1000)


# ------------------------------------------------------------------ E001 (two-key 3DES)

DES_KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")  # K1 K2, two-key triple DES


def x923_8(data: bytes) -> bytes:
    count = 8 - len(data) % 8
    return data + bytes(count - 1) + bytes((count,))


def encrypt_e001(plain: bytes, key: bytes = DES_KEY) -> bytes:
    return DES3.new(key, DES3.MODE_CBC, iv=bytes(8)).encrypt(x923_8(zlib.compress(plain)))


def test_payload_e001_known_answer():
    ciphertext = encrypt_e001(ORDER)
    for name in ("3des-cbc", "E001", "e001"):
        result = D.decrypt_payload(ciphertext, DES_KEY, cipher=name)
        assert result["plaintext"] == ORDER
        assert result["cipher"] == "3des-cbc"
    # an 8-byte block cipher: lengths that are 8 mod 16 are whole E001 ciphertexts
    short = DES3.new(DES_KEY, DES3.MODE_CBC, iv=bytes(8)).encrypt(x923_8(b"abc"))
    assert len(short) == 8
    assert D.decrypt_payload(short, DES_KEY, cipher="E001", inflate=False)["plaintext"] == b"abc"
    with pytest.raises(D.EbicsDecryptError, match="multiple of 16"):
        D.decrypt_payload(short, DES_KEY, inflate=False)
    with pytest.raises(D.EbicsDecryptError, match="padding|zlib"):
        D.decrypt_payload(ciphertext, DES_KEY)  # E002 (AES) on E001 data
    with pytest.raises(D.EbicsDecryptError, match="unknown EBICS cipher"):
        D.decrypt_payload(ciphertext, DES_KEY, cipher="E009")


def test_e001_envelope_cipher_follows_declared_version(receiver):
    wrapped = receiver.public_key().encrypt(DES_KEY, padding.PKCS1v15())
    doc = response_init(wrapped, encrypt_e001(ORDER), h004_digest(receiver), last="true", version="E001")
    result = D.decrypt_envelopes([doc], private_key=pem(receiver))
    assert result["order_plaintext"] == ORDER
    assert result["report"]["cipher"] == "3des-cbc"
    assert result["report"]["cipher_source"] == "declared E001"
    with pytest.raises(D.EbicsDecryptError, match="padding|zlib"):
        D.decrypt_envelopes([doc], private_key=pem(receiver), cipher="E002")
    odd = response_init(wrapped, encrypt_e001(ORDER), h004_digest(receiver), last="true", version="E007")
    with pytest.raises(D.EbicsDecryptError, match="not E001/E002"):
        D.decrypt_envelopes([odd], private_key=pem(receiver))
    assert D.decrypt_envelopes([odd], private_key=pem(receiver), cipher="E001")["order_plaintext"] == ORDER


def test_cipher_assumed_e002_is_reported(receiver):
    _, transfer = two_segment_download(receiver)
    doc = response_transfer(encrypt(ORDER), 1)
    report = D.decrypt_envelopes([doc], transaction_key=TX_KEY)["report"]
    assert report["cipher"] == "aes-128-cbc"
    assert report["cipher_source"].startswith("assumed E002")
    init, _ = two_segment_download(receiver)
    assert D.decrypt_envelopes([init, transfer], transaction_key=TX_KEY)["report"]["cipher_source"] == (
        "declared E002")


# ------------------------------------------------------------------ envelopes

def test_rsa_unwrap_and_segment_order(receiver):
    init, transfer = two_segment_download(receiver)
    result = D.decrypt_envelopes([transfer, init], private_key=pem(receiver))
    report = result["report"]
    assert result["order_plaintext"] == ORDER
    assert report["segments"] == [1, 2]
    assert report["key_source"] == "rsa-unwrapped"
    assert report["transaction_key_hex"] == TX_KEY.hex()
    assert report["pubkey_digest_matches_h004"] is True
    assert report["protocol_version"] == "H004"
    assert report["transaction_id"] == "AB12"
    assert report["order_data"]["kind"] == "xml"
    assert report["order_data"]["xml_root"] == "Document"
    assert report["order_data"]["flags"] == ["CSCTF{ebics_order_plain}"]
    assert report["order_data"]["sha256"] == hashlib.sha256(ORDER).hexdigest()
    json.dumps(report)


def test_h004_digest_definition(receiver, other):
    assert D.public_key_digest_h004(receiver.public_key()) == h004_digest(receiver)
    assert D.public_key_digest_h004(other.public_key()) != h004_digest(receiver)


def test_digest_mismatch_reported_not_hidden(receiver, other):
    ciphertext = encrypt(ORDER)
    wrapped = receiver.public_key().encrypt(TX_KEY, padding.PKCS1v15())
    doc = response_init(wrapped, ciphertext, h004_digest(other), last="true")
    report = D.decrypt_envelopes([doc], private_key=pem(receiver))["report"]
    assert report["pubkey_digest_matches_h004"] is False
    assert report["segments"] == [1]


def test_wrong_private_key_fails_by_name(receiver, other):
    init, transfer = two_segment_download(receiver)
    with pytest.raises(D.EbicsDecryptError, match="wrong private key"):
        D.decrypt_envelopes([init, transfer], private_key=pem(other))


def test_supplied_transaction_key_skips_rsa(receiver):
    init, transfer = two_segment_download(receiver)
    result = D.decrypt_envelopes([init, transfer], transaction_key=TX_KEY)
    assert result["order_plaintext"] == ORDER
    assert result["report"]["key_source"] == "supplied-transaction-key"
    with pytest.raises(D.EbicsDecryptError):
        D.decrypt_envelopes([init, transfer], transaction_key=bytes(range(1, 17)))


def test_key_arguments_exactly_one(receiver):
    init, transfer = two_segment_download(receiver)
    with pytest.raises(D.EbicsDecryptError, match="exactly one"):
        D.decrypt_envelopes([init, transfer])
    with pytest.raises(D.EbicsDecryptError, match="exactly one"):
        D.decrypt_envelopes([init, transfer], private_key=pem(receiver), transaction_key=TX_KEY)


def test_missing_last_segment_duplicate_and_gap_detected(receiver):
    init, transfer = two_segment_download(receiver)
    with pytest.raises(D.EbicsDecryptError, match="lastSegment"):
        D.decrypt_envelopes([init], private_key=pem(receiver))
    with pytest.raises(D.EbicsDecryptError, match="duplicate SegmentNumber"):
        D.decrypt_envelopes([init, transfer, transfer], private_key=pem(receiver))
    seg3 = response_transfer(b"\x00" * 16, 3)
    with pytest.raises(D.EbicsDecryptError, match="not contiguous"):
        D.decrypt_envelopes([init, seg3], private_key=pem(receiver))
    other_tx = response_transfer(b"\x00" * 16, 2, tid="ZZ99")
    with pytest.raises(D.EbicsDecryptError, match="different transactions"):
        D.decrypt_envelopes([init, other_tx], private_key=pem(receiver))


def test_transfer_only_needs_transaction_key(receiver):
    _, transfer = two_segment_download(receiver)
    with pytest.raises(D.EbicsDecryptError, match="TransactionKey"):
        D.decrypt_envelopes([transfer], private_key=pem(receiver))


def test_h005_upload_signature_data_and_order(receiver):
    """Upload: the init request carries the key and the ES; the transfer request the order."""
    es = (b'<UserSignatureData xmlns="http://www.ebics.org/S002"><OrderSignatureData>'
          b'<SignatureVersion>A006</SignatureVersion><PartnerID>P1</PartnerID><UserID>U1</UserID>'
          b'</OrderSignatureData></UserSignatureData>')
    order = b"pain.001 upload CSCTF{ebics_upload}"
    wrapped = receiver.public_key().encrypt(TX_KEY, padding.PKCS1v15())
    init = f'''<ebicsRequest xmlns="{H005}" Version="H005" Revision="1">
  <header authenticate="true"><static><HostID>BANK</HostID><PartnerID>P1</PartnerID><UserID>U1</UserID>
    <OrderDetails><AdminOrderType>BTU</AdminOrderType></OrderDetails>
    <SecurityMedium>0000</SecurityMedium><NumSegments>1</NumSegments></static>
    <mutable><TransactionPhase>Initialisation</TransactionPhase></mutable></header>
  <body><DataTransfer>
    <DataEncryptionInfo authenticate="true">
      <EncryptionPubKeyDigest Version="E002" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256">{h004_digest(receiver)}</EncryptionPubKeyDigest>
      <TransactionKey>{b64(wrapped)}</TransactionKey></DataEncryptionInfo>
    <SignatureData authenticate="true">{b64(encrypt(es))}</SignatureData>
  </DataTransfer></body>
</ebicsRequest>'''.encode()
    transfer = f'''<ebicsRequest xmlns="{H005}" Version="H005" Revision="1">
  <header authenticate="true"><static><HostID>BANK</HostID><TransactionID>TX5</TransactionID></static>
    <mutable><TransactionPhase>Transfer</TransactionPhase>
      <SegmentNumber lastSegment="true">1</SegmentNumber></mutable></header>
  <body><DataTransfer><OrderData>{b64(encrypt(order))}</OrderData></DataTransfer></body>
</ebicsRequest>'''.encode()
    result = D.decrypt_envelopes([init, transfer], private_key=pem(receiver))
    assert result["order_plaintext"] == order
    assert result["signature_plaintext"] == es
    assert result["report"]["signature_data"]["xml_root"] == "UserSignatureData"
    assert result["report"]["order_data"]["kind"] == "text"
    assert result["report"]["order_data"]["flags"] == ["CSCTF{ebics_upload}"]
    assert result["report"]["protocol_version"] == "H005"
    # H005 digests the bank certificate, so the H004 key digest is not compared (no false verdict)
    assert result["report"]["pubkey_digest_matches_h004"] is None
    assert "X.509 certificate" in result["report"]["pubkey_digest_check"]


def test_digest_check_states_why_when_not_compared(receiver):
    init, transfer = two_segment_download(receiver)
    report = D.decrypt_envelopes([init, transfer], transaction_key=TX_KEY)["report"]
    assert report["pubkey_digest_matches_h004"] is None
    assert "transaction key supplied" in report["pubkey_digest_check"]
    report = D.decrypt_envelopes([init, transfer], private_key=pem(receiver))["report"]
    assert report["pubkey_digest_check"] == "H004 public-key digest compared"


def test_private_key_forms(receiver, other):
    init, transfer = two_segment_download(receiver)
    der = receiver.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    assert D.decrypt_envelopes([init, transfer], private_key=der)["order_plaintext"] == ORDER
    locked = receiver.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.BestAvailableEncryption(b"pass-phrase"))
    result = D.decrypt_envelopes([init, transfer], private_key=locked, key_password=b"pass-phrase")
    assert result["order_plaintext"] == ORDER
    with pytest.raises(D.EbicsDecryptError, match="neither PEM nor DER"):
        D.decrypt_envelopes([init, transfer], private_key=locked, key_password=b"wrong")
    with pytest.raises(D.EbicsDecryptError, match="neither PEM nor DER"):
        D.decrypt_envelopes([init, transfer], private_key=b"not a key")
    from cryptography.hazmat.primitives.asymmetric import ec

    ec_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    with pytest.raises(D.EbicsDecryptError, match="needs RSA"):
        D.decrypt_envelopes([init, transfer], private_key=ec_key)


def test_modulus_size_mismatch_named(receiver):
    big = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    init, transfer = two_segment_download(receiver)
    with pytest.raises(D.EbicsDecryptError, match="not the receiver's encryption key"):
        D.decrypt_envelopes([init, transfer], private_key=pem(big))


def test_unwrapped_key_length_checked(receiver):
    wrapped = receiver.public_key().encrypt(TX_KEY + b"\x00", padding.PKCS1v15())
    with pytest.raises(D.EbicsDecryptError, match="17 bytes, expected 16"):
        D.unwrap_transaction_key(wrapped, pem(receiver))


def test_segment_numbering_errors(receiver):
    ciphertext = encrypt(ORDER)
    unnumbered = f'''<ebicsResponse xmlns="{H004}" Version="H004" Revision="1">
  <header authenticate="true"><static><TransactionID>AB12</TransactionID></static>
    <mutable><TransactionPhase>Transfer</TransactionPhase></mutable></header>
  <body><DataTransfer><OrderData>{b64(ciphertext)}</OrderData></DataTransfer></body>
</ebicsResponse>'''.encode()
    assert D.decrypt_envelopes([unnumbered], transaction_key=TX_KEY)["report"]["segments"] == [None]
    with pytest.raises(D.EbicsDecryptError, match="without SegmentNumber"):
        D.decrypt_envelopes([unnumbered, unnumbered], transaction_key=TX_KEY)
    with pytest.raises(D.EbicsDecryptError, match="some do not"):
        D.decrypt_envelopes([unnumbered, response_transfer(ciphertext, 1)], transaction_key=TX_KEY)
    with pytest.raises(D.EbicsDecryptError, match="no OrderData"):
        D.decrypt_envelopes([unnumbered.replace(b"<OrderData>", b"<X>").replace(b"</OrderData>", b"</X>")],
                            transaction_key=TX_KEY)


def test_describe_kinds():
    assert D.decrypt_payload(encrypt(b"PK\x03\x04rest"), TX_KEY)["plaintext"].startswith(b"PK")
    assert D._describe(b"PK\x03\x04rest")["kind"] == "zip"
    assert D._describe(b"\xff\xfe\x00binary")["kind"] == "binary"
    assert D._describe(b"plain text")["kind"] == "text"
    broken = D._describe(b"<unclosed")
    assert broken["kind"] == "xml" and "xml_error" in broken


def test_non_ebics_document_rejected():
    with pytest.raises(D.EbicsDecryptError, match="not a supported EBICS envelope"):
        D.decrypt_envelopes([b"<notEbics/>"], transaction_key=TX_KEY)


# ------------------------------------------------------------------ CLI

def test_cli_envelope_and_raw(tmp_path, receiver, other, capsys):
    init, transfer = two_segment_download(receiver)
    (tmp_path / "1.xml").write_bytes(init)
    (tmp_path / "2.xml").write_bytes(transfer)
    (tmp_path / "key.pem").write_bytes(pem(receiver))
    (tmp_path / "other.pem").write_bytes(pem(other))
    out = tmp_path / "order.xml"
    code = D.main(["envelope", str(tmp_path / "2.xml"), str(tmp_path / "1.xml"),
                   "--private-key", str(tmp_path / "key.pem"), "--out", str(out)])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert out.read_bytes() == ORDER
    assert report["written"]["order_data"] == str(out)

    assert D.main(["envelope", str(tmp_path / "1.xml"), str(tmp_path / "2.xml"),
                   "--private-key", str(tmp_path / "other.pem")]) == 2
    assert "wrong private key" in capsys.readouterr().err

    blob = tmp_path / "order.b64"
    blob.write_text(b64(encrypt(ORDER)) + "\n")
    raw_out = tmp_path / "raw.bin"
    assert D.main(["raw", str(blob), "--transaction-key", TX_KEY.hex(), "--out", str(raw_out)]) == 0
    assert raw_out.read_bytes() == ORDER
    assert json.loads(capsys.readouterr().out)["order_data"]["flags"] == ["CSCTF{ebics_order_plain}"]

    des_blob = tmp_path / "e001.b64"
    des_blob.write_text(b64(encrypt_e001(ORDER)))
    assert D.main(["raw", str(des_blob), "--transaction-key", DES_KEY.hex(), "--cipher", "E001"]) == 0
    assert json.loads(capsys.readouterr().out)["cipher"] == "3des-cbc"
    assert D.main(["raw", str(des_blob), "--transaction-key", DES_KEY.hex()]) == 2
    capsys.readouterr()
    assert D.main(["envelope", str(tmp_path / "1.xml"), str(tmp_path / "2.xml"),
                   "--private-key", str(tmp_path / "key.pem"), "--cipher", "E001"]) == 2
    err = capsys.readouterr().err
    assert "padding" in err or "zlib" in err


def test_no_inflate_reports_the_key_as_unverified(receiver):
    # inflated: the zlib stream is the key check, so the key counts as verified
    assert D.decrypt_payload(encrypt(ORDER), TX_KEY)["key_verified"] is True
    # without inflation a wrong key whose last block decrypts to a valid length byte returns
    # garbage: search the 256 wrong keys 00..ff with one byte varied for one that passes padding
    ciphertext = encrypt(ORDER)
    for byte in range(256):
        wrong = bytes((byte,)) + bytes(15)
        try:
            result = D.decrypt_payload(ciphertext, wrong, inflate=False)
        except D.EbicsDecryptError:
            continue
        assert result["plaintext"] != zlib.compress(ORDER)
        assert result["key_verified"] is False
        break
    else:
        pytest.fail("no wrong key passed the padding-length check; widen the search")
    init, transfer = two_segment_download(receiver)
    report = D.decrypt_envelopes([init, transfer], private_key=pem(receiver), inflate=False)["report"]
    assert report["key_verified"] is False and report["key_check"] == D.KEY_CHECK_NONE
    report = D.decrypt_envelopes([init, transfer], private_key=pem(receiver))["report"]
    assert report["key_verified"] is True and report["key_check"] == D.KEY_CHECK_ZLIB


def test_cli_no_inflate_warns_key_not_verified(tmp_path, capsys):
    blob = tmp_path / "order.b64"
    blob.write_text(b64(encrypt(b"raw order", compress=False)))
    assert D.main(["raw", str(blob), "--transaction-key", TX_KEY.hex(), "--no-inflate"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["key_verified"] is False
    assert "warning: key not verified" in captured.err
    blob.write_text(b64(encrypt(ORDER)))
    assert D.main(["raw", str(blob), "--transaction-key", TX_KEY.hex()]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["key_verified"] is True
    assert "warning" not in captured.err
