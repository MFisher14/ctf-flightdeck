#!/usr/bin/env python3
"""Decrypt KNX Secure traffic with a supplied key or ETS keyring, offline.

``sec_bas_knx`` decodes the KNX wire and stops at the protected bytes.  This
helper applies the key a challenge hands over:

* **ETS keyring** (``*.knxkeys``): the keyring password gives
  ``PBKDF2-HMAC-SHA256(password, "1.keyring.ets.knx.org", 65536, 16)``; every
  ``Key``/``ToolKey`` attribute is AES-128-CBC under it with
  ``IV = SHA-256(Created)[:16]``; password attributes carry 8 random bytes and
  a length-byte padding.  The keyring ``Signature`` is checked, so a wrong
  password fails loudly instead of yielding garbage keys.
* **KNX Data Secure** (cEMI ``SecureService`` APCI 0x3F1, S-A_Data): the
  KNX CCM variant: CBC-MAC over ``B0 = SeqNr|Src|Dst|00|A000EEEE|TPCI+03|F1|00|len``
  and the SCF, CTR from ``SeqNr|Src|Dst|00000000 0100``; the 4-byte MAC takes the
  first keystream bytes.  Authentication-only frames are MAC-checked and their
  APDU (already clear) is returned.
* **KNX IP Secure** ``SECURE_WRAPPER``: AES-CCM with the backbone key (routing,
  session 0) or the tunnelling session key; ``SESSION_RESPONSE`` and
  ``SESSION_AUTHENTICATE`` MACs can be checked with the device authentication
  code / user password.  The session key is ``SHA-256(X25519 shared)[:16]`` when
  a private key and the peer public key are supplied.

* **KNX IoT OSCORE** (CoAP, RFC 8613, AES-CCM-16-64-128): the Master Secret,
  Master Salt and ID Context give the sender keys and Common IV by HKDF-SHA256;
  a request is opened with the key of the ``kid`` it names, a response with the
  responder's key and the request's kid/Partial IV in the external AAD.  The
  unprotected CoAP message is rebuilt and decoded through ``sec_bas_knx``.

Every MAC or AEAD tag is verified before a plaintext is reported; a wrong key
raises :class:`KNXSecureError` naming the failed check.

CLI::

    tools/ctfpy toolkits.sec_bas_knx_secure keyring FILE.knxkeys --password-file P
    tools/ctfpy toolkits.sec_bas_knx_secure data-secure FRAME [--hex] (--key HEX | --keyring F --password-file P) [--dpt 9]
    tools/ctfpy toolkits.sec_bas_knx_secure wrapper FRAME [--hex] (--key HEX | --keyring F --password-file P
        | --private-key HEX --peer-public HEX) [--data-secure-keyring]
    tools/ctfpy toolkits.sec_bas_knx_secure oscore FRAME [--hex] --master-secret HEX [--master-salt HEX]
        [--id-context HEX] [--responder-id HEX [--request-kid HEX --request-piv HEX]]

With ``oscore --hex`` a response line is paired with the earlier request line that has the
same CoAP token, so ``--request-kid``/``--request-piv`` are needed only for a lone response.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping

try:
    import sec_bas_knx as _wire
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parent))
    import sec_bas_knx as _wire


KEYRING_SALT = b"1.keyring.ets.knx.org"
DEVICE_AUTH_SALT = b"device-authentication-code.1.secure.ip.knx.org"
USER_PASSWORD_SALT = b"user-password.1.secure.ip.knx.org"
KDF_ITERATIONS = 65536
KEYRING_NAMESPACE_PREFIX = "http://knx.org/xml/keyring/"
MAX_KEYRING = 16 * 1024 * 1024
COUNTER_0_HANDSHAKE = bytes(14) + b"\xff\x00"
_APCI_SECURE = 0x3F1
_SESSION_RESPONSE_HEADER = bytes.fromhex("061009520038")
_SESSION_AUTHENTICATE_HEADER = bytes.fromhex("061009530018")
KEYRING_SIGNATURE_BYTES = 16  # ETS stores the first 16 bytes of the SHA-256 signature digest
OSCORE_ALG_AES_CCM_16_64_128 = 10  # COSE algorithm id
OSCORE_NONCE_BYTES = 13
OSCORE_TAG_BYTES = 8

__all__ = [
    "KNXSecureError",
    "keyring_password_hash",
    "derive_device_authentication_code",
    "derive_user_password_key",
    "load_keyring",
    "keyring_keys",
    "cbc_mac",
    "decrypt_data_secure",
    "decrypt_secure_wrapper",
    "session_key_from_x25519",
    "verify_session_response",
    "verify_session_authenticate",
    "derive_oscore_context",
    "oscore_nonce",
    "oscore_aad",
    "decrypt_oscore",
    "main",
]


class KNXSecureError(ValueError):
    """The supplied key or KNX Secure material does not decrypt or verify."""


# --------------------------------------------------------------------------- primitives

def _aes(key: bytes):
    from cryptography.hazmat.primitives.ciphers import algorithms

    if len(key) != 16:
        raise KNXSecureError(f"KNX Secure keys are AES-128 (16 bytes), got {len(key)}")
    return algorithms.AES(bytes(key))


def cbc_mac(key: bytes, additional_data: bytes, payload: bytes = b"", block_0: bytes = bytes(16)) -> bytes:
    """KNX CBC-MAC: ``B0 | len(AD) (2) | AD | payload`` zero-padded as one stream, IV 0."""

    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    if len(block_0) != 16:
        raise KNXSecureError("block 0 must be 16 bytes")
    stream = block_0 + len(additional_data).to_bytes(2, "big") + additional_data + payload
    stream += bytes(-len(stream) % 16)
    encryptor = Cipher(_aes(key), modes.CBC(bytes(16))).encryptor()
    return (encryptor.update(stream) + encryptor.finalize())[-16:]


def _ctr(key: bytes, counter_0: bytes, mac: bytes, payload: bytes = b"") -> tuple[bytes, bytes]:
    """CTR keystream from ``counter_0``: first over the MAC, then (continuing) the payload."""

    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    cipher = Cipher(_aes(key), modes.CTR(counter_0)).encryptor()
    mac_out = cipher.update(mac)
    return cipher.update(payload) + cipher.finalize(), mac_out


def keyring_password_hash(password: str | bytes) -> bytes:
    raw = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    return hashlib.pbkdf2_hmac("sha256", raw, KEYRING_SALT, KDF_ITERATIONS, 16)


def derive_device_authentication_code(password: str | bytes) -> bytes:
    raw = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    return hashlib.pbkdf2_hmac("sha256", raw, DEVICE_AUTH_SALT, KDF_ITERATIONS, 16)


def derive_user_password_key(password: str | bytes) -> bytes:
    raw = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    return hashlib.pbkdf2_hmac("sha256", raw, USER_PASSWORD_SALT, KDF_ITERATIONS, 16)


# --------------------------------------------------------------------------- keyring

def _keyring_xml(data: bytes):
    from lxml import etree

    if not isinstance(data, (bytes, bytearray)) or not data:
        raise KNXSecureError("keyring must be nonempty bytes")
    if len(data) > MAX_KEYRING:
        raise KNXSecureError(f"keyring exceeds the {MAX_KEYRING}-byte cap")
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True,
                             huge_tree=False, recover=False)
    try:
        root = etree.fromstring(bytes(data), parser)
    except etree.XMLSyntaxError as exc:
        raise KNXSecureError(f"keyring is not well-formed XML: {exc}") from exc
    if root.getroottree().docinfo.doctype:
        raise KNXSecureError("keyring DOCTYPE is forbidden")
    qname = etree.QName(root)
    if qname.localname != "Keyring" or not (qname.namespace or "").startswith(KEYRING_NAMESPACE_PREFIX):
        raise KNXSecureError(
            f"root is {{{qname.namespace}}}{qname.localname}, not an ETS keyring"
            f" ({KEYRING_NAMESPACE_PREFIX}*)"
        )
    return root


def _signature_digest(root, password_hash: bytes) -> bytes:
    """ETS keyring signature: SHA-256 over a length-prefixed walk of the document."""

    from lxml import etree

    digest = hashlib.sha256()

    def append(text: str) -> None:
        raw = text.encode("utf-8")
        if len(raw) > 255:
            raise KNXSecureError("keyring attribute too long for the signature encoding")
        digest.update(bytes((len(raw),)) + raw)

    for event, node in etree.iterwalk(root, events=("start", "end")):
        if not isinstance(node.tag, str):
            continue
        if event == "start":
            digest.update(b"\x01")
            append(etree.QName(node).localname)
            for name, value in sorted(node.attrib.items()):
                if name in ("Signature", "xmlns"):
                    continue
                append(name)
                append(value)
        else:
            digest.update(b"\x02")
    append(base64.b64encode(password_hash).decode("ascii"))
    return digest.digest()


def _b64(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise KNXSecureError(f"keyring {label} is not base64") from exc


def _cbc_decrypt(key: bytes, iv: bytes, data: bytes, label: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    if not data or len(data) % 16:
        raise KNXSecureError(f"keyring {label} is {len(data)} bytes, not whole AES blocks")
    decryptor = Cipher(_aes(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _decrypt_key(value: str, pw_hash: bytes, iv: bytes, label: str) -> str:
    plain = _cbc_decrypt(pw_hash, iv, _b64(value, label), label)
    if len(plain) != 16:
        raise KNXSecureError(f"keyring {label} decrypts to {len(plain)} bytes, expected 16")
    return plain.hex()


def _decrypt_password(value: str, pw_hash: bytes, iv: bytes, label: str) -> str:
    plain = _cbc_decrypt(pw_hash, iv, _b64(value, label), label)
    count = plain[-1]
    if not 1 <= count <= 16 or 8 + count > len(plain) or any(b != count for b in plain[-count:]):
        raise KNXSecureError(f"keyring {label} has invalid padding: wrong keyring password")
    try:
        return plain[8:-count].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise KNXSecureError(f"keyring {label} is not UTF-8: wrong keyring password") from exc


def _group_address_text(raw: int) -> str:
    return f"{(raw >> 11) & 31}/{(raw >> 8) & 7}/{raw & 255}"


def _parse_group(text: str) -> int:
    text = str(text).strip()
    if text.isdigit():
        value = int(text)
    else:
        parts = text.split("/")
        try:
            numbers = [int(part) for part in parts]
        except ValueError as exc:
            raise KNXSecureError(f"bad group address {text!r}") from exc
        if len(numbers) == 3 and numbers[0] < 32 and numbers[1] < 8 and numbers[2] < 256:
            value = (numbers[0] << 11) | (numbers[1] << 8) | numbers[2]
        elif len(numbers) == 2 and numbers[0] < 32 and numbers[1] < 2048:
            value = (numbers[0] << 11) | numbers[1]
        else:
            raise KNXSecureError(f"bad group address {text!r}")
    if not 0 <= value <= 0xFFFF:
        raise KNXSecureError(f"group address {text!r} out of range")
    return value


def load_keyring(data: bytes, password: str | bytes, *, verify_signature: bool = True) -> dict[str, Any]:
    """Decrypt every key and password in an ETS ``.knxkeys`` keyring.

    Returns ``backbone``, ``group_keys`` ({"a/b/c": hex}), ``devices`` and
    ``interfaces`` with decrypted material.  ``verify_signature`` (default)
    rejects a wrong password or an edited keyring before anything is decrypted.
    """

    root = _keyring_xml(data)
    pw_hash = keyring_password_hash(password)
    created = root.get("Created")
    if not created:
        raise KNXSecureError("keyring has no Created attribute (the IV source)")
    signature = root.get("Signature")
    signature_ok = None
    if verify_signature:
        if not signature:
            raise KNXSecureError("keyring has no Signature; pass verify_signature=False to skip")
        expected = _b64(signature, "Signature")
        if len(expected) != KEYRING_SIGNATURE_BYTES:
            raise KNXSecureError(
                f"keyring Signature is {len(expected)} bytes, expected {KEYRING_SIGNATURE_BYTES}")
        signature_ok = _signature_digest(root, pw_hash)[:KEYRING_SIGNATURE_BYTES] == expected
        if not signature_ok:
            raise KNXSecureError("keyring Signature does not match: wrong password or edited keyring")
    iv = hashlib.sha256(created.encode("utf-8")).digest()[:16]

    from lxml import etree

    def local(node) -> str:
        return etree.QName(node).localname

    result: dict[str, Any] = {
        "project": root.get("Project"),
        "created": created,
        "created_by": root.get("CreatedBy"),
        "signature_verified": signature_ok,
        "backbone": None,
        "group_keys": {},
        "devices": {},
        "interfaces": [],
    }
    for node in root.iter():
        if not isinstance(node.tag, str):
            continue
        name = local(node)
        if name == "Backbone":
            result["backbone"] = {
                "multicast_address": node.get("MulticastAddress"),
                "latency": node.get("Latency"),
                "key": _decrypt_key(node.get("Key"), pw_hash, iv, "Backbone/Key")
                if node.get("Key") else None,
            }
        elif name == "Group" and local(node.getparent()) == "GroupAddresses":
            address = _parse_group(node.get("Address", ""))
            if node.get("Key"):
                result["group_keys"][_group_address_text(address)] = _decrypt_key(
                    node.get("Key"), pw_hash, iv, f"Group {address}/Key")
        elif name == "Device":
            ia = node.get("IndividualAddress") or ""
            row: dict[str, Any] = {"sequence_number": node.get("SequenceNumber")}
            if node.get("ToolKey"):
                row["tool_key"] = _decrypt_key(node.get("ToolKey"), pw_hash, iv, f"Device {ia}/ToolKey")
            for attr, label in (("ManagementPassword", "management_password"),
                                ("Authentication", "authentication_code_password")):
                if node.get(attr):
                    row[label] = _decrypt_password(node.get(attr), pw_hash, iv, f"Device {ia}/{attr}")
            result["devices"][ia] = row
        elif name == "Interface":
            row = {
                "individual_address": node.get("IndividualAddress"),
                "type": node.get("Type"),
                "host": node.get("Host"),
                "user_id": node.get("UserID"),
                "groups": {
                    _group_address_text(_parse_group(child.get("Address", ""))): (child.get("Senders") or "").split()
                    for child in node if isinstance(child.tag, str) and local(child) == "Group"
                },
            }
            for attr, label in (("Password", "password"), ("Authentication", "authentication_password")):
                if node.get(attr):
                    row[label] = _decrypt_password(node.get(attr), pw_hash, iv,
                                                   f"Interface {row['individual_address']}/{attr}")
            if "password" in row:
                row["user_password_key"] = derive_user_password_key(row["password"]).hex()
            result["interfaces"].append(row)
    return result


def keyring_keys(keyring: Mapping[str, Any]) -> dict[str, str]:
    """One Data Secure key mapping from a decrypted keyring: group keys by ``a/b/c`` and
    device tool keys by individual address, as :func:`decrypt_data_secure` takes them."""

    keys = dict(keyring.get("group_keys") or {})
    for address, row in (keyring.get("devices") or {}).items():
        if row.get("tool_key"):
            keys[address] = row["tool_key"]
    return keys


# --------------------------------------------------------------------------- Data Secure

def _key_bytes(value: Any, label: str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, str):
        try:
            raw = bytes.fromhex("".join(value.split()))
        except ValueError as exc:
            raise KNXSecureError(f"{label} is not hex") from exc
    else:
        raise KNXSecureError(f"{label} must be bytes or hex text")
    if len(raw) != 16:
        raise KNXSecureError(f"{label} must be 16 bytes (AES-128), got {len(raw)}")
    return raw


def _split_cemi(frame: bytes) -> tuple[bytes, bytes | None]:
    """Return (cEMI, KNXnet/IP prefix or None) for a cEMI or a tunnelling/routing frame."""

    if len(frame) >= 6 and frame[:2] == b"\x06\x10":
        parsed = _wire.parse_knxnetip(frame)
        service = parsed["service_type"]
        if service == 0x0420:
            return frame[10:], frame[:10]
        if service in (0x0530, 0x0533):
            return frame[6:], frame[:6]
        raise KNXSecureError(f"KNXnet/IP service {parsed['service']} carries no cEMI")
    return frame, None


def _select_key(keys: Any, parsed: dict[str, Any]) -> tuple[bytes, str]:
    if isinstance(keys, (bytes, bytearray, str)):
        return _key_bytes(keys, "Data Secure key"), "supplied"
    if not isinstance(keys, Mapping):
        raise KNXSecureError("keys must be one 16-byte key or a mapping of address -> key")
    destination = parsed["destination"]
    if parsed["control2"]["destination_type"] == "group":
        name = destination["three_level"]
        for candidate in (name, destination["raw"], str(destination["raw"])):
            if candidate in keys:
                return _key_bytes(keys[candidate], f"key for {name}"), name
        raise KNXSecureError(f"no key for group address {name} in the supplied keys")
    # point-to-point traffic is secured with the managed device's tool key: the device is the
    # destination of a tool's request and the source of its response
    for name in (destination["individual"], parsed["source"]["individual"]):
        if name in keys:
            return _key_bytes(keys[name], f"key for {name}"), name
    raise KNXSecureError(
        f"no tool key for individual address {destination['individual']} or"
        f" {parsed['source']['individual']} in the supplied keys"
    )


def decrypt_data_secure(frame: bytes, keys: Any, *, dpt: str | None = None) -> dict[str, Any]:
    """Verify and decrypt one KNX Data Secure S-A_Data frame (cEMI or KNXnet/IP-wrapped).

    ``keys`` is one 16-byte key (bytes or hex) or a mapping such as
    ``keyring_keys(load_keyring(...))`` (group keys by ``a/b/c``, tool keys by ``a.b.c``).  Returns the plain APDU, the rebuilt plain
    cEMI and its ``sec_bas_knx`` decoding.
    """

    raw = bytes(frame)
    cemi, prefix = _split_cemi(raw)
    try:
        parsed = _wire.parse_cemi(cemi)
    except _wire.SecBasKNXError as exc:
        raise KNXSecureError(f"not a decodable cEMI frame: {exc}") from exc
    secure = parsed.get("data_secure")
    if secure is None:
        raise KNXSecureError("frame is not a Data Secure APDU (APCI 0x3F1)")
    if secure["service"] != "S-A_Data":
        raise KNXSecureError(f"{secure['service']} is a sync handshake, not protected data")
    key, key_id = _select_key(keys, parsed)
    control = 2 + cemi[1]
    ctrl2 = cemi[control + 1]
    address_fields = cemi[control + 2: control + 6]
    tpdu = cemi[control + 7:]
    scf = tpdu[2:3]
    sequence = tpdu[3:9]
    protected = tpdu[9:-4]
    mac = tpdu[-4:]

    def block_0(length: int) -> bytes:
        return sequence + address_fields + bytes(
            (0, ctrl2 & 0x8F, (tpdu[0] & 0xFC) | (_APCI_SECURE >> 8), _APCI_SECURE & 0xFF, 0, length)
        )

    if secure["algorithm"] == "aes-ccm-authentication":
        expected = cbc_mac(key, scf + protected, b"", block_0(0))[:4]
        if expected != mac:
            raise KNXSecureError("Data Secure MAC verification failed (authentication-only): wrong key")
        plain = protected
        mode = "authenticated"
    else:
        counter_0 = sequence + address_fields + b"\x00\x00\x00\x00\x01\x00"
        plain, mac_clear = _ctr(key, counter_0, mac, protected)
        expected = cbc_mac(key, scf, plain, block_0(len(plain)))[:4]
        if expected != mac_clear:
            raise KNXSecureError("Data Secure MAC verification failed: wrong key or tampered frame")
        mode = "authenticated-decrypted"
    if len(plain) < 2:
        raise KNXSecureError("decrypted APDU is shorter than two octets")
    plain_tpdu = bytes(((tpdu[0] & 0xFC) | (plain[0] & 0x03),)) + plain[1:]
    plain_cemi = cemi[: control + 6] + bytes((len(plain_tpdu) - 1,)) + plain_tpdu
    try:
        decoded = _wire.parse_cemi(plain_cemi, dpt=dpt)
    except _wire.SecBasKNXError as exc:
        raise KNXSecureError(f"MAC verified but the plain APDU does not decode: {exc}") from exc
    return {
        "type": "knx-data-secure-decrypt",
        "mode": mode,
        "key_id": key_id,
        "sequence_number": int.from_bytes(sequence, "big"),
        "source": parsed["source"]["individual"],
        "destination": parsed["destination"],
        "mac_verified": True,
        "plain_apdu_hex": plain.hex(),
        "plain_cemi_hex": plain_cemi.hex(),
        "decoded": decoded,
        "knxnetip_prefix_hex": None if prefix is None else prefix.hex(),
    }


# --------------------------------------------------------------------------- IP Secure

def decrypt_secure_wrapper(frame: bytes, key: Any) -> dict[str, Any]:
    """Verify and decrypt one KNXnet/IP ``SECURE_WRAPPER`` (backbone or session key)."""

    raw = bytes(frame)
    try:
        parsed = _wire.parse_knxnetip(raw)
    except _wire.SecBasKNXError as exc:
        raise KNXSecureError(f"not a KNXnet/IP frame: {exc}") from exc
    if parsed["service_type"] != 0x0950:
        raise KNXSecureError(f"frame is {parsed['service']}, not SECURE_WRAPPER")
    aes_key = _key_bytes(key, "IP Secure key")
    header, body = raw[:6], raw[6:]
    session_id = body[0:2]
    nonce = body[2:16]  # sequence information (6) | serial number (6) | message tag (2)
    encrypted, mac = body[16:-16], body[-16:]
    inner, mac_clear = _ctr(aes_key, nonce + b"\xff\x00", mac, encrypted)
    expected = cbc_mac(aes_key, header + session_id, inner, nonce + len(inner).to_bytes(2, "big"))
    if expected != mac_clear:
        raise KNXSecureError("SECURE_WRAPPER MAC verification failed: wrong backbone/session key")
    try:
        decoded = _wire.parse_knxnetip(inner)
    except _wire.SecBasKNXError as exc:
        raise KNXSecureError(f"MAC verified but the inner frame does not decode: {exc}") from exc
    session = int.from_bytes(session_id, "big")
    return {
        "type": "knx-ip-secure-decrypt",
        "session_id": session,
        "mode": "secure-routing-multicast" if session == 0 else "secure-session-unicast",
        "sequence_information": int.from_bytes(nonce[:6], "big"),
        "serial_number_hex": nonce[6:12].hex(),
        "message_tag": int.from_bytes(nonce[12:14], "big"),
        "mac_verified": True,
        "inner_hex": inner.hex(),
        "inner": decoded,
    }


def session_key_from_x25519(private_key: Any, peer_public: Any) -> bytes:
    """Tunnelling session key: ``SHA-256(X25519(private, peer_public))[:16]``."""

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

    private = _raw32(private_key, "X25519 private key")
    public = _raw32(peer_public, "X25519 peer public key")
    shared = X25519PrivateKey.from_private_bytes(private).exchange(
        X25519PublicKey.from_public_bytes(public))
    return hashlib.sha256(shared).digest()[:16]


def _raw32(value: Any, label: str) -> bytes:
    if isinstance(value, str):
        try:
            value = bytes.fromhex("".join(value.split()))
        except ValueError as exc:
            raise KNXSecureError(f"{label} is not hex") from exc
    if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
        raise KNXSecureError(f"{label} must be 32 bytes")
    return bytes(value)


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def verify_session_response(frame: bytes, client_public: Any, device_authentication_code: Any) -> dict[str, Any]:
    """Check a ``SESSION_RESPONSE`` MAC with the device authentication code."""

    raw = bytes(frame)
    if raw[:6] != _SESSION_RESPONSE_HEADER or len(raw) != 56:
        raise KNXSecureError("not a 56-byte SESSION_RESPONSE frame")
    key = _key_bytes(device_authentication_code, "device authentication code")
    session_id, server_public, mac = raw[6:8], raw[8:40], raw[40:56]
    _, mac_clear = _ctr(key, COUNTER_0_HANDSHAKE, mac)
    expected = cbc_mac(key, raw[:6] + session_id + _xor(_raw32(client_public, "client public key"), server_public))
    return {"session_id": int.from_bytes(session_id, "big"), "server_public_hex": server_public.hex(),
            "mac_valid": expected == mac_clear}


def verify_session_authenticate(inner: bytes, client_public: Any, server_public: Any,
                                user_password_key: Any) -> dict[str, Any]:
    """Check a (decrypted) ``SESSION_AUTHENTICATE`` MAC with a user password key."""

    raw = bytes(inner)
    if raw[:6] != _SESSION_AUTHENTICATE_HEADER or len(raw) != 24:
        raise KNXSecureError("not a 24-byte SESSION_AUTHENTICATE frame")
    key = _key_bytes(user_password_key, "user password key")
    reserved_user, mac = raw[6:8], raw[8:24]
    _, mac_clear = _ctr(key, COUNTER_0_HANDSHAKE, mac)
    expected = cbc_mac(key, raw[:6] + reserved_user + _xor(_raw32(client_public, "client public key"),
                                                           _raw32(server_public, "server public key")))
    return {"user_id": raw[7], "mac_valid": expected == mac_clear}


# --------------------------------------------------------------------------- KNX IoT OSCORE

def _oscore_bytes(value: Any, label: str, *, limit: int) -> bytes:
    if value is None:
        return b""
    if isinstance(value, str):
        try:
            value = bytes.fromhex("".join(value.split()))
        except ValueError as exc:
            raise KNXSecureError(f"{label} is not hex") from exc
    if not isinstance(value, (bytes, bytearray)):
        raise KNXSecureError(f"{label} must be bytes or hex text")
    if len(value) > limit:
        raise KNXSecureError(f"{label} is {len(value)} bytes, more than {limit}")
    return bytes(value)


def _oscore_info(identifier: bytes, id_context: bytes | None, kind: str, length: int) -> bytes:
    import cbor2

    return cbor2.dumps([identifier, id_context, OSCORE_ALG_AES_CCM_16_64_128, kind, length])


def _oscore_hkdf(master_secret: bytes, master_salt: bytes, info: bytes, length: int) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    # RFC 8613 3.2.1: HKDF-SHA256, salt = Master Salt (the empty salt is HKDF's all-zero salt)
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=master_salt or None,
                info=info).derive(master_secret)


def derive_oscore_context(master_secret: Any, *, sender_id: Any, recipient_id: Any,
                          master_salt: Any = b"", id_context: Any = None) -> dict[str, bytes | None]:
    """RFC 8613 3.2 security context for AES-CCM-16-64-128 (the KNX IoT AEAD).

    Returns ``sender_key``, ``recipient_key`` and ``common_iv``.  A key depends only on its
    owner's ID, so the client's sender key is the server's recipient key.
    """

    secret = _oscore_bytes(master_secret, "OSCORE Master Secret", limit=256)
    if not secret:
        raise KNXSecureError("OSCORE Master Secret is empty")
    salt = _oscore_bytes(master_salt, "OSCORE Master Salt", limit=256)
    sender = _oscore_bytes(sender_id, "OSCORE Sender ID", limit=OSCORE_NONCE_BYTES - 6)
    recipient = _oscore_bytes(recipient_id, "OSCORE Recipient ID", limit=OSCORE_NONCE_BYTES - 6)
    context = None if id_context is None else _oscore_bytes(id_context, "OSCORE ID Context", limit=256)
    return {
        "sender_id": sender,
        "recipient_id": recipient,
        "id_context": context,
        "sender_key": _oscore_hkdf(secret, salt, _oscore_info(sender, context, "Key", 16), 16),
        "recipient_key": _oscore_hkdf(secret, salt, _oscore_info(recipient, context, "Key", 16), 16),
        "common_iv": _oscore_hkdf(secret, salt, _oscore_info(b"", context, "IV", OSCORE_NONCE_BYTES),
                                  OSCORE_NONCE_BYTES),
    }


def oscore_nonce(common_iv: bytes, id_piv: bytes, partial_iv: bytes) -> bytes:
    """RFC 8613 5.2: ``(len(ID_PIV) | ID_PIV padded to 7 | PIV padded to 5) XOR Common IV``."""

    if len(common_iv) != OSCORE_NONCE_BYTES:
        raise KNXSecureError(f"OSCORE Common IV must be {OSCORE_NONCE_BYTES} bytes")
    if len(id_piv) > OSCORE_NONCE_BYTES - 6 or len(partial_iv) > 5:
        raise KNXSecureError("OSCORE ID_PIV is longer than 7 bytes or Partial IV longer than 5")
    block = (bytes((len(id_piv),)) + id_piv.rjust(OSCORE_NONCE_BYTES - 6, b"\x00")
             + partial_iv.rjust(5, b"\x00"))
    return _xor(block, common_iv)


def oscore_aad(request_kid: bytes, request_piv: bytes) -> bytes:
    """RFC 8613 5.4 Enc_structure with the external AAD (no Class I options)."""

    import cbor2

    external = cbor2.dumps([1, [OSCORE_ALG_AES_CCM_16_64_128], request_kid, request_piv, b""])
    return cbor2.dumps(["Encrypt0", b"", external])


def _coap_option_bytes(options: list[tuple[int, bytes]]) -> bytes:
    def nibble(value: int) -> tuple[int, bytes]:
        if value < 13:
            return value, b""
        if value < 269:
            return 13, bytes((value - 13,))
        if value < 65805:
            return 14, (value - 269).to_bytes(2, "big")
        raise KNXSecureError("CoAP option delta or length too large")

    out, previous = bytearray(), 0
    for number, value in options:
        if number < previous:
            raise KNXSecureError(f"CoAP options out of order: option {number} after {previous}")
        delta, delta_ext = nibble(number - previous)
        length, length_ext = nibble(len(value))
        out += bytes(((delta << 4) | length,)) + delta_ext + length_ext + value
        previous = number
    return bytes(out)


def _coap_options(parsed: Mapping[str, Any]) -> list[tuple[int, bytes]]:
    return [(int(row["number"]), bytes.fromhex(row["value_hex"])) for row in parsed["options"]]


def decrypt_oscore(message: bytes, master_secret: Any, *, master_salt: Any = b"", id_context: Any = None,
                   responder_id: Any = None, request_kid: Any = None,
                   request_piv: Any = None) -> dict[str, Any]:
    """Verify and decrypt one OSCORE-protected CoAP message (RFC 8613, KNX IoT).

    A request names its sender in the OSCORE option ``kid`` and carries a Partial IV; its key is
    derived from that kid.  A response is protected with the responder's key, so ``responder_id``
    (the server's Sender ID) and the request's ``request_kid`` / ``request_piv`` are required; the
    response nonce uses its own Partial IV when it carries one, else the request's.  The AEAD tag
    is checked before anything is reported, and the unprotected CoAP message is rebuilt (outer
    header, Class U options and the decrypted inner code, Class E options and payload) and decoded
    with ``sec_bas_knx``.
    """

    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    raw = bytes(message)
    try:
        parsed = _wire.parse_coap(raw, decode_plaintext_cbor=False)
    except _wire.SecBasKNXError as exc:
        raise KNXSecureError(f"not a CoAP message: {exc}") from exc
    option = parsed.get("oscore")
    if option is None:
        raise KNXSecureError("CoAP message carries no OSCORE option")
    ciphertext = bytes.fromhex(parsed["payload_hex"])
    if len(ciphertext) <= OSCORE_TAG_BYTES:
        raise KNXSecureError("OSCORE payload is shorter than the 8-byte tag plus a code byte")
    option_piv = bytes.fromhex(option["partial_iv_hex"])
    option_kid = None if option["kid_hex"] is None else bytes.fromhex(option["kid_hex"])
    option_context = None if option["kid_context_hex"] is None else bytes.fromhex(option["kid_context_hex"])
    context = None if id_context is None else _oscore_bytes(id_context, "OSCORE ID Context", limit=256)
    if option_context is not None:
        if context is not None and context != option_context:
            raise KNXSecureError("supplied ID Context differs from the kid context in the OSCORE option")
        context = option_context
    is_request = parsed["code"] >> 5 == 0
    if is_request:
        if option_kid is None:
            raise KNXSecureError("OSCORE request has no kid: the sender's key cannot be chosen")
        if not option_piv:
            raise KNXSecureError("OSCORE request has no Partial IV")
        if responder_id is not None or request_kid is not None or request_piv is not None:
            raise KNXSecureError("responder_id/request_kid/request_piv apply to responses only")
        sender, aad_kid, aad_piv = option_kid, option_kid, option_piv
        id_piv, piv = option_kid, option_piv
    else:
        if responder_id is None or request_kid is None or request_piv is None:
            raise KNXSecureError("an OSCORE response needs responder_id, request_kid and request_piv")
        sender = _oscore_bytes(responder_id, "responder ID", limit=OSCORE_NONCE_BYTES - 6)
        aad_kid = _oscore_bytes(request_kid, "request kid", limit=OSCORE_NONCE_BYTES - 6)
        aad_piv = _oscore_bytes(request_piv, "request Partial IV", limit=5)
        if not aad_piv:
            raise KNXSecureError("request Partial IV is empty")
        id_piv, piv = (sender, option_piv) if option_piv else (aad_kid, aad_piv)
    keys = derive_oscore_context(master_secret, sender_id=sender, recipient_id=b"",
                                 master_salt=master_salt, id_context=context)
    nonce = oscore_nonce(keys["common_iv"], id_piv, piv)
    aad = oscore_aad(aad_kid, aad_piv)
    try:
        plaintext = AESCCM(keys["sender_key"], tag_length=OSCORE_TAG_BYTES).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise KNXSecureError(
            "OSCORE AEAD tag verification failed: wrong Master Secret/Salt/ID Context, wrong"
            " sender ID, wrong request kid/Partial IV, or a tampered message") from exc
    if not plaintext:
        raise KNXSecureError("OSCORE plaintext is empty: no inner code")
    try:
        inner = _wire.parse_coap(bytes((0x40, plaintext[0], 0, 0)) + plaintext[1:], decode_plaintext_cbor=False)
    except _wire.SecBasKNXError as exc:
        raise KNXSecureError(f"OSCORE tag verified but the inner message does not decode: {exc}") from exc
    inner_options = _coap_options(inner)
    inner_numbers = {number for number, _ in inner_options}
    outer_options = [(number, value) for number, value in _coap_options(parsed)
                     if number != 9 and number not in inner_numbers]
    merged = sorted(outer_options + inner_options, key=lambda row: row[0])
    token_end = 4 + (raw[0] & 15)
    inner_payload = bytes.fromhex(inner["payload_hex"])
    unprotected = (bytes((raw[0], plaintext[0])) + raw[2:token_end] + _coap_option_bytes(merged)
                   + ((b"\xff" + inner_payload) if inner_payload else b""))
    try:
        decoded = _wire.parse_coap(unprotected)
    except _wire.SecBasKNXError as exc:
        raise KNXSecureError(f"OSCORE tag verified but the rebuilt message does not decode: {exc}") from exc
    return {
        "type": "knx-iot-oscore-decrypt",
        "direction": "request" if is_request else "response",
        "sender_id_hex": sender.hex(),
        "id_context_hex": None if context is None else context.hex(),
        "partial_iv_hex": piv.hex(),
        "nonce_hex": nonce.hex(),
        "aad_hex": aad.hex(),
        "tag_verified": True,
        "plaintext_hex": plaintext.hex(),
        "inner_code_text": f"{plaintext[0] >> 5}.{plaintext[0] & 31:02d}",
        "unprotected_hex": unprotected.hex(),
        "decoded": decoded,
        "request_kid_hex": aad_kid.hex(),
        "request_piv_hex": aad_piv.hex(),
    }


# --------------------------------------------------------------------------- CLI

def _read_frames(path: str, hexadecimal: bool) -> list[bytes]:
    with Path(path).open("rb") as handle:
        raw = handle.read(_wire.MAX_INPUT + 1)
    if len(raw) > _wire.MAX_INPUT:
        raise KNXSecureError(f"{path} exceeds {_wire.MAX_INPUT} bytes")
    if not hexadecimal:
        return [raw]
    frames = []
    for number, line in enumerate(raw.decode("ascii", "strict").splitlines(), 1):
        compact = "".join(line.split("#", 1)[0].split())
        if not compact:
            continue
        try:
            frames.append(bytes.fromhex(compact))
        except ValueError as exc:
            raise KNXSecureError(f"{path}:{number}: not hex") from exc
    if not frames:
        raise KNXSecureError(f"{path}: no hex frames")
    return frames


def _password(path: str) -> str:
    return Path(path).read_text(encoding="utf-8").rstrip("\r\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    ring = sub.add_parser("keyring", help="decrypt an ETS .knxkeys keyring")
    ring.add_argument("file")
    ring.add_argument("--password-file", required=True)
    ring.add_argument("--no-verify-signature", action="store_true")
    for name in ("data-secure", "wrapper"):
        cmd = sub.add_parser(name)
        cmd.add_argument("file", help="raw frame, or one hex frame per line with --hex")
        cmd.add_argument("--hex", action="store_true")
        cmd.add_argument("--key", help="AES-128 key, hex")
        cmd.add_argument("--keyring")
        cmd.add_argument("--password-file")
        cmd.add_argument("--dpt")
        if name == "wrapper":
            cmd.add_argument("--private-key", help="X25519 private key, hex (derive the session key)")
            cmd.add_argument("--peer-public", help="peer X25519 public key, hex")
            cmd.add_argument("--data-secure-keyring", action="store_true",
                             help="also decrypt Data Secure APDUs inside with the keyring's group keys")
    osc = sub.add_parser("oscore", help="decrypt KNX IoT OSCORE (RFC 8613) CoAP messages")
    osc.add_argument("file", help="raw CoAP datagram, or one hex datagram per line with --hex")
    osc.add_argument("--hex", action="store_true")
    osc.add_argument("--master-secret", required=True, help="OSCORE Master Secret, hex")
    osc.add_argument("--master-salt", default="", help="OSCORE Master Salt, hex (default empty)")
    osc.add_argument("--id-context", help="OSCORE ID Context, hex (else the option's kid context)")
    osc.add_argument("--responder-id", help="the server's Sender ID, hex (needed for responses)")
    osc.add_argument("--request-kid", help="kid of the request a lone response answers, hex")
    osc.add_argument("--request-piv", help="Partial IV of that request, hex")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.command == "keyring":
            data = Path(args.file).read_bytes()
            report: Any = load_keyring(data, _password(args.password_file),
                                       verify_signature=not args.no_verify_signature)
        elif args.command == "oscore":
            rows = []
            requests: dict[str, tuple[str, str]] = {}  # token -> (kid, Partial IV) of a decrypted request
            for frame in _read_frames(args.file, args.hex):
                token = frame[4:4 + (frame[0] & 15)].hex() if frame else ""
                if len(frame) >= 4 and frame[1] >> 5:  # code class 2..5: a response
                    kid, piv = args.request_kid, args.request_piv
                    if kid is None and piv is None and token in requests:
                        kid, piv = requests[token]
                    if args.responder_id is None:
                        raise KNXSecureError("an OSCORE response needs --responder-id")
                    if kid is None or piv is None:
                        raise KNXSecureError(
                            f"no request with token {token or '(empty)'} before this response: pass"
                            " --request-kid and --request-piv")
                    row = decrypt_oscore(frame, args.master_secret, master_salt=args.master_salt,
                                         id_context=args.id_context, responder_id=args.responder_id,
                                         request_kid=kid, request_piv=piv)
                else:
                    row = decrypt_oscore(frame, args.master_secret, master_salt=args.master_salt,
                                         id_context=args.id_context)
                    requests[token] = (row["request_kid_hex"], row["request_piv_hex"])
                rows.append(row)
            report = rows[0] if len(rows) == 1 else rows
        else:
            keyring = None
            if args.keyring:
                if not args.password_file:
                    raise KNXSecureError("--keyring needs --password-file")
                keyring = load_keyring(Path(args.keyring).read_bytes(), _password(args.password_file))
            frames = _read_frames(args.file, args.hex)
            rows = []
            if args.command == "data-secure":
                keys: Any = args.key if args.key else (keyring_keys(keyring) if keyring else None)
                if keys is None:
                    raise KNXSecureError("data-secure needs --key or --keyring")
                for frame in frames:
                    rows.append(decrypt_data_secure(frame, keys, dpt=args.dpt))
            else:
                if args.private_key or args.peer_public:
                    if not (args.private_key and args.peer_public):
                        raise KNXSecureError("--private-key and --peer-public go together")
                    key: Any = session_key_from_x25519(args.private_key, args.peer_public)
                elif args.key:
                    key = args.key
                elif keyring and keyring["backbone"] and keyring["backbone"]["key"]:
                    key = keyring["backbone"]["key"]
                else:
                    raise KNXSecureError("wrapper needs --key, a keyring with a backbone key, or"
                                         " --private-key/--peer-public")
                for frame in frames:
                    row = decrypt_secure_wrapper(frame, key)
                    inner_cemi = row["inner"].get("cemi") or {}
                    if args.data_secure_keyring and "data_secure" in inner_cemi:
                        if keyring is None:
                            raise KNXSecureError("--data-secure-keyring needs --keyring")
                        row["data_secure"] = decrypt_data_secure(
                            bytes.fromhex(row["inner_hex"]), keyring_keys(keyring), dpt=args.dpt)
                    rows.append(row)
            report = rows[0] if len(rows) == 1 else rows
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (KNXSecureError, OSError, UnicodeDecodeError) as exc:
        print(f"sec_bas_knx_secure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
