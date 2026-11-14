#!/usr/bin/env python3
"""Decrypt EBICS order data with a supplied key (E002 AES, E001 3DES), offline.

``sec_bank_ebics`` reports EBICS structure and stops at the opaque payloads.
This helper takes the key a challenge hands over and turns those payloads into
plaintext:

* the **transaction key** (``DataEncryptionInfo/TransactionKey``) is a 16-byte
  symmetric key wrapped with RSA PKCS#1 v1.5 under the *receiver's* encryption
  key.  Supply the receiver's RSA private key (PEM or DER) to unwrap it, or
  supply the 16-byte transaction key itself (hex) when the challenge gives it.
  For H004 the key is checked against ``EncryptionPubKeyDigest`` and the result
  reported (a mismatch is reported, not fatal: the unwrap decides);
* ``OrderData`` segments (base64, ordered by ``SegmentNumber``) are concatenated,
  then CBC decrypted with a zero IV: AES-128 for E002 (H004/H005), two-key
  triple DES for E001 (H003; envelopes are read through ``sec_bank_ebics``, which
  parses H004/H005, so H003 E001 material goes through the ``raw`` command).
  The cipher follows ``EncryptionPubKeyDigest/@Version`` unless one is passed,
  and the report says which and why.  The padding
  (ANSI X9.23 / ISO 10126: last byte = pad length) is removed; the result is
  zlib-inflated;
* ``SignatureData`` (the user's ES, ``UserSignatureData`` XML) is decrypted the
  same way with the same transaction key.

Nothing is transmitted, signed or verified against a bank: a decrypted payload
is evidence, not proof of authorization.  Every failure raises
:class:`EbicsDecryptError` with a named reason (wrong key, bad padding, not
zlib, missing segment, ...); there is no best-effort fallback.

EBICS order data carries no MAC: the zlib stream is the wrong-key check.  With
``inflate=False`` (``--no-inflate``) only the padding length byte is checked,
which about one wrong key in sixteen passes, so the result says
``key_verified: false`` and the CLI warns on stderr; treat that plaintext as
unconfirmed until it reads as order data.

CLI::

    tools/ctfpy toolkits.sec_bank_ebics_decrypt envelope SEG1.xml [SEG2.xml ...] \\
        (--private-key key.pem [--key-password-file F] | --transaction-key HEX) \\
        [--cipher e002|e001] [--out plain.bin] [--signature-out es.xml] [--no-inflate]
    tools/ctfpy toolkits.sec_bank_ebics_decrypt raw ORDERDATA.b64 --transaction-key HEX [--cipher e001] [--out F]
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
import sys
import zlib
from typing import Any, Iterable

try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

try:
    import sec_bank_ebics as _reader
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parent))
    import sec_bank_ebics as _reader


MAX_SEGMENTS = 4096
MAX_CIPHERTEXT = 64 * 1024 * 1024
MAX_PLAINTEXT = 256 * 1024 * 1024
KEY_CHECK_ZLIB = "zlib stream inflated cleanly (the only wrong-key check: order data has no MAC)"
KEY_CHECK_NONE = ("key not verified: without inflation only the padding length byte is checked,"
                  " which a wrong key passes about 1 time in 16")
AES_BLOCK = 16
DES_BLOCK = 8
TRANSACTION_KEY_BYTES = 16
# EncryptionPubKeyDigest/@Version -> order-data cipher (EBICS spec, encryption versions)
CIPHERS = {"E002": "aes-128-cbc", "E001": "3des-cbc"}

__all__ = [
    "EbicsDecryptError",
    "unwrap_transaction_key",
    "decrypt_payload",
    "decrypt_envelopes",
    "public_key_digest_h004",
    "main",
]


class EbicsDecryptError(ValueError):
    """The supplied key or EBICS material does not decrypt; the message names why."""


# --------------------------------------------------------------------------- primitives

def _load_private_key(key: Any, password: bytes | None):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    if isinstance(key, rsa.RSAPrivateKey):
        return key
    if not isinstance(key, (bytes, bytearray)) or not key:
        raise EbicsDecryptError("private key must be PEM/DER bytes or an RSA private key object")
    raw = bytes(key)
    errors = []
    loaders = (serialization.load_pem_private_key, serialization.load_der_private_key)
    for loader in loaders:
        try:
            loaded = loader(raw, password=password)
        except (ValueError, TypeError) as exc:
            errors.append(f"{loader.__name__}: {exc}")
            continue
        if not isinstance(loaded, rsa.RSAPrivateKey):
            raise EbicsDecryptError(
                f"private key is {type(loaded).__name__}, EBICS E001/E002 needs RSA"
            )
        return loaded
    raise EbicsDecryptError("private key is neither PEM nor DER RSA: " + "; ".join(errors))


def public_key_digest_h004(public_key) -> str:
    """H004 key digest: SHA-256 of ``<exponent hex> <modulus hex>`` (lower case,
    no leading zeros), base64 - the value an ``EncryptionPubKeyDigest`` carries."""

    numbers = public_key.public_numbers()
    text = f"{numbers.e:x} {numbers.n:x}".encode("ascii")
    return base64.b64encode(hashlib.sha256(text).digest()).decode("ascii")


def unwrap_transaction_key(wrapped: bytes, private_key: Any, *, password: bytes | None = None) -> bytes:
    """RSA PKCS#1 v1.5 decrypt of an EBICS ``TransactionKey`` into the AES-128 key."""

    from cryptography.hazmat.primitives.asymmetric import padding

    rsa_key = _load_private_key(private_key, password)
    size = (rsa_key.key_size + 7) // 8
    if len(wrapped) != size:
        raise EbicsDecryptError(
            f"TransactionKey is {len(wrapped)} bytes but the RSA modulus is {size} bytes:"
            " this is not the receiver's encryption key"
        )
    try:
        key = rsa_key.decrypt(bytes(wrapped), padding.PKCS1v15())
    except ValueError as exc:
        raise EbicsDecryptError(
            "TransactionKey does not decrypt under this RSA key (PKCS#1 v1.5 padding check"
            " failed): wrong private key"
        ) from exc
    # OpenSSL 3.2+ answers a bad PKCS#1 v1.5 block with a random "implicit rejection" plaintext
    # instead of an error, so the length check below (and the padding/zlib checks after it) are
    # what catch a wrong key there
    if len(key) != TRANSACTION_KEY_BYTES:
        raise EbicsDecryptError(
            f"unwrapped transaction key is {len(key)} bytes, expected {TRANSACTION_KEY_BYTES}"
            " (AES-128): wrong private key or not an E001/E002 transaction key"
        )
    return key


def _unpad(data: bytes, block: int = AES_BLOCK) -> tuple[bytes, str]:
    if not data:
        raise EbicsDecryptError("empty decryption result")
    count = data[-1]
    if not 1 <= count <= block or count > len(data):
        raise EbicsDecryptError(
            f"invalid padding length byte {count}: wrong transaction key or not EBICS order data"
        )
    pad = data[-count:]
    if count == 1:
        scheme = "one-byte (pkcs7 = x9.23 = iso-10126)"
    elif all(byte == count for byte in pad):
        scheme = "pkcs7"
    elif all(byte == 0 for byte in pad[:-1]):
        scheme = "ansi-x9.23"
    else:
        scheme = "iso-10126"
    return data[:-count], scheme


def _inflate(data: bytes, limit: int) -> bytes:
    inflater = zlib.decompressobj()
    try:
        out = inflater.decompress(data, limit + 1)
    except zlib.error as exc:
        raise EbicsDecryptError(
            f"decrypted data is not zlib-compressed ({exc}): wrong key, or pass inflate=False"
        ) from exc
    if len(out) > limit or inflater.unconsumed_tail:
        raise EbicsDecryptError(f"inflated order data exceeds the {limit}-byte cap")
    if not inflater.eof:
        raise EbicsDecryptError("zlib stream is truncated: a segment is missing")
    if inflater.unused_data:
        raise EbicsDecryptError(
            f"{len(inflater.unused_data)} bytes follow the zlib stream: extra or misordered segment"
        )
    return out


def _cipher_name(cipher: str) -> str:
    name = str(cipher).strip()
    by_version = CIPHERS.get(name.upper())
    if by_version:
        return by_version
    if name.lower() in CIPHERS.values():
        return name.lower()
    raise EbicsDecryptError(
        f"unknown EBICS cipher {cipher!r}: use E002 / aes-128-cbc or E001 / 3des-cbc"
    )


def decrypt_payload(
    ciphertext: bytes,
    transaction_key: bytes,
    *,
    inflate: bool = True,
    max_plaintext: int = MAX_PLAINTEXT,
    cipher: str = "aes-128-cbc",
) -> dict[str, Any]:
    """CBC (zero IV) decrypt, unpad and (optionally) inflate one payload.

    ``cipher`` is ``aes-128-cbc`` (E002, default) or ``3des-cbc`` (E001, two-key
    triple DES); the version names ``E002``/``E001`` are accepted too.
    Returns ``{"plaintext": bytes, "padding": scheme, "compressed_bytes": n, "cipher": name,
    "key_verified": bool}``.  ``key_verified`` is true only when the zlib stream inflated
    cleanly; without inflation a wrong key can pass the padding check and return garbage.
    """

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    name = _cipher_name(cipher)
    key = bytes(transaction_key)
    if len(key) != TRANSACTION_KEY_BYTES:
        raise EbicsDecryptError(
            f"transaction key must be {TRANSACTION_KEY_BYTES} bytes, got {len(key)}"
        )
    data = bytes(ciphertext)
    if not data:
        raise EbicsDecryptError("empty ciphertext")
    if len(data) > MAX_CIPHERTEXT:
        raise EbicsDecryptError(f"ciphertext exceeds the {MAX_CIPHERTEXT}-byte cap")
    if name == "3des-cbc":
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

        # a 16-byte E001 key is two-key 3DES (K1 K2 K1); spelled out as 24 bytes, which is the same
        # cipher and the form `cryptography` keeps supporting
        block, algorithm = DES_BLOCK, TripleDES(key + key[:8])
    else:
        block, algorithm = AES_BLOCK, algorithms.AES(key)
    if len(data) % block:
        raise EbicsDecryptError(
            f"ciphertext length {len(data)} is not a multiple of {block}: a segment is missing or"
            " truncated"
        )
    decryptor = Cipher(algorithm, modes.CBC(bytes(block))).decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    compressed, scheme = _unpad(padded, block)
    plaintext = _inflate(compressed, max_plaintext) if inflate else compressed
    return {"plaintext": plaintext, "padding": scheme, "compressed_bytes": len(compressed),
            "cipher": name, "key_verified": bool(inflate)}


# --------------------------------------------------------------------------- envelopes

def _b64(node: Any, label: str) -> bytes:
    compact = "".join((node.text or "").split())
    if not compact:
        raise EbicsDecryptError(f"empty {label}")
    try:
        return base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise EbicsDecryptError(f"invalid base64 in {label}") from exc


def _envelope(data: bytes, index: int) -> dict[str, Any]:
    try:
        report = _reader.parse_ebics(data)
        root = _reader._xml(data)
    except _reader.SecBankEbicsError as exc:
        raise EbicsDecryptError(f"document {index}: not a supported EBICS envelope: {exc}") from exc
    namespace = report["namespace"]
    body = _reader._one(root, "body", namespace=namespace, required=True)
    transfer = _reader._one(body, "DataTransfer", namespace=namespace)
    row: dict[str, Any] = {
        "index": index,
        "root": report["root"],
        "protocol_version": report["protocol_version"],
        "transaction_id": report["header"]["transaction_id"],
        "transaction_phase": report["header"]["transaction_phase"],
        "segment_number": report["header"]["segment_number"],
        "last_segment": report["header"]["last_segment"],
        "order_type": (report.get("order") or {}).get("order_type")
        or (report.get("order") or {}).get("admin_order_type"),
        "transaction_key": None,
        "encryption_pubkey_digest": None,
        "signature_data": None,
        "order_data": None,
    }
    if transfer is None:
        return row
    info = _reader._one(transfer, "DataEncryptionInfo", namespace=namespace)
    if info is not None:
        wrapped = _reader._one(info, "TransactionKey", namespace=namespace)
        if wrapped is not None:
            row["transaction_key"] = _b64(wrapped, "TransactionKey")
        digest = _reader._one(info, "EncryptionPubKeyDigest", namespace=namespace)
        if digest is not None:
            row["encryption_pubkey_digest"] = {
                "value": "".join((digest.text or "").split()),
                "version": digest.get("Version"),
                "algorithm": digest.get("Algorithm"),
            }
    signature = _reader._one(transfer, "SignatureData", namespace=namespace)
    if signature is not None:
        row["signature_data"] = _b64(signature, "SignatureData")
    order = _reader._one(transfer, "OrderData", namespace=namespace)
    if order is not None:
        row["order_data"] = _b64(order, "OrderData")
    return row


def _order_segments(rows: list[dict[str, Any]]) -> list[tuple[int | None, bytes]]:
    carrying = [row for row in rows if row["order_data"] is not None]
    if not carrying:
        raise EbicsDecryptError("no OrderData in the supplied documents")
    ids = {row["transaction_id"] for row in carrying if row["transaction_id"]}
    if len(ids) > 1:
        raise EbicsDecryptError(f"documents belong to different transactions: {sorted(ids)}")
    numbered = [row for row in carrying if row["segment_number"] is not None]
    if numbered and len(numbered) != len(carrying):
        raise EbicsDecryptError("some OrderData segments have a SegmentNumber and some do not")
    if not numbered:
        if len(carrying) > 1:
            raise EbicsDecryptError(
                "several OrderData segments without SegmentNumber: their order is unknown"
            )
        return [(None, carrying[0]["order_data"])]
    try:
        keyed = sorted(((int(row["segment_number"]), row) for row in carrying), key=lambda item: item[0])
    except ValueError as exc:
        raise EbicsDecryptError("SegmentNumber is not an integer") from exc
    numbers = [number for number, _ in keyed]
    if len(set(numbers)) != len(numbers):
        raise EbicsDecryptError(f"duplicate SegmentNumber in {numbers}")
    if numbers != list(range(1, len(numbers) + 1)):
        raise EbicsDecryptError(f"OrderData segments are not contiguous from 1: got {numbers}")
    last = keyed[-1][1]["last_segment"]
    if last is not None and last.strip().lower() != "true":
        raise EbicsDecryptError(
            f"segment {numbers[-1]} is not marked lastSegment=true: later segments are missing"
        )
    return [(number, row["order_data"]) for number, row in keyed]


def _single(rows: list[dict[str, Any]], field: str) -> Any:
    values = [row[field] for row in rows if row[field] is not None]
    if not values:
        return None
    if any(value != values[0] for value in values[1:]):
        raise EbicsDecryptError(f"documents carry different {field} values")
    return values[0]


def _describe(plaintext: bytes) -> dict[str, Any]:
    kind = "binary"
    detail: dict[str, Any] = {}
    stripped = plaintext.lstrip(b"\xef\xbb\xbf \t\r\n")
    if plaintext.startswith(b"PK\x03\x04"):
        kind = "zip"
    elif stripped.startswith(b"<"):
        kind = "xml"
        try:
            from lxml import etree

            root = _reader._xml(plaintext)
            detail["xml_root"] = etree.QName(root).localname
            detail["xml_namespace"] = etree.QName(root).namespace
        except Exception as exc:  # noqa: BLE001 - reported, not hidden
            detail["xml_error"] = f"{type(exc).__name__}: {exc}"[:240]
    else:
        try:
            plaintext.decode("utf-8")
            kind = "text"
        except UnicodeDecodeError:
            kind = "binary"
    try:
        flags = flagfmt.find_flags(plaintext)
        flag_error = None
    except Exception as exc:  # noqa: BLE001 - no active event: say so instead of guessing
        flags, flag_error = [], f"{type(exc).__name__}: {exc}"[:240]
    result = {
        "kind": kind,
        "bytes": len(plaintext),
        "sha256": hashlib.sha256(plaintext).hexdigest(),
        "flags": flags,
        **detail,
    }
    if flag_error:
        result["flag_scan_error"] = flag_error
    return result


def decrypt_envelopes(
    documents: Iterable[bytes],
    *,
    private_key: Any = None,
    key_password: bytes | None = None,
    transaction_key: bytes | None = None,
    inflate: bool = True,
    cipher: str | None = None,
) -> dict[str, Any]:
    """Decrypt the OrderData (and SignatureData) of one EBICS transaction.

    ``documents`` are the transaction's EBICS XML documents (initialisation plus
    transfer phases) in any order.  Exactly one of ``private_key`` (the
    receiver's RSA encryption key, PEM/DER) or ``transaction_key`` (16 raw
    bytes) is required.  ``cipher`` (``E002``/``E001`` or a cipher name) overrides
    the one ``EncryptionPubKeyDigest/@Version`` declares; with neither, E002
    (AES-128, the H004/H005 version) is used and the report says it was assumed.
    Returns a JSON-safe report plus ``order_plaintext`` and
    ``signature_plaintext`` bytes (``None`` when absent).
    """

    if (private_key is None) == (transaction_key is None):
        raise EbicsDecryptError("supply exactly one of private_key or transaction_key")
    docs = list(documents)
    if not docs:
        raise EbicsDecryptError("no EBICS documents supplied")
    if len(docs) > MAX_SEGMENTS:
        raise EbicsDecryptError(f"more than {MAX_SEGMENTS} documents")
    rows = [_envelope(bytes(doc), index) for index, doc in enumerate(docs)]
    wrapped = _single(rows, "transaction_key")
    digest = _single(rows, "encryption_pubkey_digest")
    key_source = "supplied-transaction-key"
    digest_match = None
    digest_check = "no EncryptionPubKeyDigest in the documents"
    protocol = _single(rows, "protocol_version")
    if transaction_key is None:
        if wrapped is None:
            raise EbicsDecryptError(
                "no DataEncryptionInfo/TransactionKey in the documents: include the"
                " initialisation-phase document, or supply the transaction key"
            )
        rsa_key = _load_private_key(private_key, key_password)
        if digest is not None and digest["value"]:
            if protocol == "H004":
                digest_match = public_key_digest_h004(rsa_key.public_key()) == digest["value"]
                digest_check = "H004 public-key digest compared"
            else:
                # H005 (EBICS 3.0) digests the bank's X.509 certificate, which the envelope does not
                # carry: comparing the H004 key digest would report a false mismatch
                digest_check = f"not checked: {protocol} digests the X.509 certificate, not the key"
        key = unwrap_transaction_key(wrapped, rsa_key)
        key_source = "rsa-unwrapped"
    else:
        key = bytes(transaction_key)
        digest_check = "not checked: transaction key supplied, no RSA key to compare"
    declared = (digest or {}).get("version")
    if cipher is not None:
        cipher_name, cipher_source = _cipher_name(cipher), "supplied"
    elif declared:
        if declared.strip().upper() not in CIPHERS:
            raise EbicsDecryptError(
                f"EncryptionPubKeyDigest Version {declared!r} is not E001/E002: pass cipher="
            )
        cipher_name, cipher_source = CIPHERS[declared.strip().upper()], f"declared {declared.strip()}"
    else:
        cipher_name, cipher_source = CIPHERS["E002"], "assumed E002 (no EncryptionPubKeyDigest Version)"
    segments = _order_segments(rows)
    ciphertext = b"".join(chunk for _, chunk in segments)
    order = decrypt_payload(ciphertext, key, inflate=inflate, cipher=cipher_name)
    signature = None
    signature_bytes = _single(rows, "signature_data")
    if signature_bytes is not None:
        signature = decrypt_payload(signature_bytes, key, inflate=inflate, cipher=cipher_name)
    report = {
        "type": "ebics-decrypt",
        "protocol_version": protocol,
        "transaction_id": _single(rows, "transaction_id"),
        "order_type": _single(rows, "order_type"),
        "key_source": key_source,
        "cipher": cipher_name,
        "cipher_source": cipher_source,
        "transaction_key_hex": key.hex(),
        "encryption_pubkey_digest": digest,
        "pubkey_digest_matches_h004": digest_match,
        "pubkey_digest_check": digest_check,
        "segments": [number for number, _ in segments],
        "ciphertext_bytes": len(ciphertext),
        "padding": order["padding"],
        "inflated": inflate,
        "key_verified": order["key_verified"],
        "key_check": KEY_CHECK_ZLIB if inflate else KEY_CHECK_NONE,
        "order_data": _describe(order["plaintext"]),
        "signature_data": None
        if signature is None
        else {"padding": signature["padding"], **_describe(signature["plaintext"])},
        "authenticity": "not established: EBICS order data carries no MAC; signatures are"
        " not verified here",
    }
    return {
        "report": report,
        "order_plaintext": order["plaintext"],
        "signature_plaintext": None if signature is None else signature["plaintext"],
    }


# --------------------------------------------------------------------------- CLI

def _hex_key(text: str) -> bytes:
    compact = "".join(text.split())
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise EbicsDecryptError("transaction key is not hex") from exc


def _read(path: str, cap: int = _reader.MAX_BYTES) -> bytes:
    with Path(path).open("rb") as stream:
        data = stream.read(cap + 1)
    if len(data) > cap:
        raise EbicsDecryptError(f"{path} exceeds the {cap}-byte cap")
    return data


def _write(path: str | None, data: bytes | None) -> str | None:
    if path is None or data is None:
        return None
    Path(path).write_bytes(data)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    env = sub.add_parser("envelope", help="decrypt EBICS XML documents of one transaction")
    env.add_argument("documents", nargs="+")
    group = env.add_mutually_exclusive_group(required=True)
    group.add_argument("--private-key", help="receiver's RSA encryption key (PEM/DER)")
    group.add_argument("--transaction-key", help="AES-128 transaction key, hex")
    env.add_argument("--key-password-file", help="file holding the private key passphrase")
    env.add_argument("--out", help="write the order-data plaintext here")
    env.add_argument("--signature-out", help="write the decrypted SignatureData here")
    env.add_argument("--no-inflate", action="store_true", help="skip the zlib step")
    env.add_argument("--cipher", help="E002 (AES-128) or E001 (3DES); default: the envelope's declared version")
    raw = sub.add_parser("raw", help="decrypt one base64 OrderData blob")
    raw.add_argument("blob", help="file with the base64 OrderData text (or raw bytes with --binary)")
    raw.add_argument("--transaction-key", required=True)
    raw.add_argument("--binary", action="store_true", help="the file is raw ciphertext, not base64")
    raw.add_argument("--out")
    raw.add_argument("--no-inflate", action="store_true")
    raw.add_argument("--cipher", default="E002", help="E002 (AES-128, default) or E001 (3DES)")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.command == "envelope":
            password = None
            if args.key_password_file:
                password = _read(args.key_password_file, 4096).rstrip(b"\r\n")
            result = decrypt_envelopes(
                [_read(path) for path in args.documents],
                private_key=_read(args.private_key, 1 << 20) if args.private_key else None,
                key_password=password,
                transaction_key=_hex_key(args.transaction_key) if args.transaction_key else None,
                inflate=not args.no_inflate,
                cipher=args.cipher,
            )
            report = dict(result["report"])
            report["written"] = {
                "order_data": _write(args.out, result["order_plaintext"]),
                "signature_data": _write(args.signature_out, result["signature_plaintext"]),
            }
        else:
            blob = _read(args.blob, MAX_CIPHERTEXT * 2)
            if not args.binary:
                try:
                    blob = base64.b64decode(b"".join(blob.split()), validate=True)
                except (ValueError, binascii.Error) as exc:
                    raise EbicsDecryptError("blob is not base64 (use --binary for raw bytes)") from exc
            decrypted = decrypt_payload(blob, _hex_key(args.transaction_key),
                                        inflate=not args.no_inflate, cipher=args.cipher)
            report = {
                "type": "ebics-decrypt-raw",
                "cipher": decrypted["cipher"],
                "padding": decrypted["padding"],
                "inflated": not args.no_inflate,
                "key_verified": decrypted["key_verified"],
                "key_check": KEY_CHECK_NONE if args.no_inflate else KEY_CHECK_ZLIB,
                "order_data": _describe(decrypted["plaintext"]),
                "written": {"order_data": _write(args.out, decrypted["plaintext"])},
            }
        if not report["key_verified"]:
            print(f"sec_bank_ebics_decrypt: warning: {KEY_CHECK_NONE}", file=sys.stderr)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (EbicsDecryptError, OSError) as exc:
        print(f"sec_bank_ebics_decrypt: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
