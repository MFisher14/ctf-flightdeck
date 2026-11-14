#!/usr/bin/env python3
"""Toolkit asn1_reader: a lane-agnostic ASN.1/DER + X.509 / PKCS / PEM / SSH / PGP reader
(gap-analysis ticket C2, docs/retro/ctf-solver-gap-analysis.md; built 2026-10-23). Offline, static.

ASN.1/DER parsing lived only welded to PE Authenticode; there was no reader for a bare
certificate / key / CSR / CRL / SSH public key / PGP packet delivery. This answers the
CONTAINER/STRUCTURE facts of such an artifact and nothing else:

  pem      -----BEGIN X-----/-----END X----- blocks: the label and the DER bytes inside
  x509     a certificate: subject/issuer (full DN and the common name), serial, notBefore/
           notAfter, signature algorithm, public-key algorithm and size, the SHA-1 and SHA-256
           fingerprints (a digest of the exact DER bytes)
  key      an RSA/EC public or private key: algorithm, size, the RSA modulus/exponent, the curve
  ssh      an OpenSSH public key line: the key type, the SHA256 and MD5 fingerprints, the bit
           length, the comment
  pgp      OpenPGP public-key packets: the v4 fingerprint (SHA-1 of the hashed key body), the
           key id (its last 8 bytes), the public-key algorithm, the creation time, a User ID

HARD RULES (AGENTS.md "New categories", "Uncertain answers"):
  - RECON ONLY. Nothing is a key that is USED, a signature that is verified, or a secret that is
    submitted. A private key's own secret parameters (the private exponent, the primes) are never
    an answer. A flag is None.
  - NEVER-GUESS. A fingerprint and a serial are a deterministic read of exact bytes, so they are
    plain-ELIGIBLE: offered as labels.pick(key, options) of their renderings (hex, colon-hex,
    upper), which tools/verify.py probes on the untimed base and the ledger answers plain once a
    rendering is judged. A selection among several equal fields (which SAN, the spelling of a DN),
    an author-chosen algorithm name and every time are unsure. A truncated or ambiguous parse, and
    anything unproven, is None.
  - Bounded: at most MAX_ITEMS TLV nodes and MAX_DEPTH deep; `cryptography`/`asn1crypto` are used
    when present in the .venv and a bounded pure-Python DER walk otherwise; every reader is
    fail-closed (a parse that raises yields no fact).

Keys: `asn1_reader.<field>/<shape>` (solvers/common/labels.py TOOLKIT_PREFIXES knows the prefix).
"""
import base64
import binascii
import hashlib
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if __name__ == "__main__" and sys.path and Path(sys.path[0] or ".").resolve() == HERE:
    sys.path.pop(0)             # a sibling toolkit must never shadow a standard module
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
import labels    # noqa: E402
import triage    # noqa: E402

KEY = "asn1_reader"
ARROW = triage.ARROW
UTC = timezone.utc
MAX_FILE = 64 * 1024 * 1024
MAX_DEPTH = 40
MAX_ITEMS = 100000
MAX_SCAN = 8 * 1024 * 1024

try:                            # used when present in the .venv; a pure DER walk otherwise
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes as _hashes       # noqa: F401 (API probe)
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, ec as _ec
    _HAVE_CRYPTO = True
except Exception:               # noqa: BLE001 - a missing library is a fall-back, never an error
    _HAVE_CRYPTO = False

SSH_TYPES = ("ssh-rsa", "ssh-dss", "ssh-ed25519", "ssh-ed448",
             "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
             "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
# Signature / public-key algorithm OIDs -> an author-style name (unsure).
_SIG_OIDS = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption", "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption", "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss", "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
    "1.2.840.10045.4.3.3": "ecdsaWithSHA384", "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
    "1.3.101.112": "ed25519", "1.3.101.113": "ed448"}
_PK_OIDS = {"1.2.840.113549.1.1.1": "rsa", "1.2.840.10045.2.1": "ec", "1.3.101.112": "ed25519",
            "1.3.101.113": "ed448", "1.2.840.10040.4.1": "dsa"}


# ---------------------------------------------------------------------------- bounded DER walk

class _DerError(ValueError):
    pass


def _der_len(data: bytes, i: int):
    """(length, header_len) of the length field that starts at `i` (after the tag byte)."""
    if i >= len(data):
        raise _DerError("length past end")
    b = data[i]
    if b < 0x80:
        return b, 1
    n = b & 0x7F
    if n == 0 or n > 4 or i + 1 + n > len(data):       # indefinite / absurd length: not clean DER
        raise _DerError("bad length")
    return int.from_bytes(data[i + 1:i + 1 + n], "big"), 1 + n


def _der_items(data: bytes, start: int, end: int, _budget=None):
    """[(tag, content_start, content_end)] of the TLVs in data[start:end], bounded."""
    if _budget is None:
        _budget = [MAX_ITEMS]
    out, i = [], start
    while i < end:
        if _budget[0] <= 0:
            raise _DerError("too many items")
        _budget[0] -= 1
        tag = data[i]
        length, hl = _der_len(data, i + 1)
        cs = i + 1 + hl
        ce = cs + length
        if ce > end:
            raise _DerError("item past end")
        out.append((tag, cs, ce))
        i = ce
    return out


def _der_oid(data: bytes, cs: int, ce: int) -> str:
    """The dotted OID of an OBJECT IDENTIFIER body data[cs:ce]."""
    body = data[cs:ce]
    if not body:
        raise _DerError("empty oid")
    # Each subidentifier is base-128 (big bit continues). The FIRST subidentifier
    # encodes the two leading arcs combined as X*40+Y, and it may itself be multibyte.
    subs, val = [], 0
    for byte in body:
        val = (val << 7) | (byte & 0x7F)
        if not byte & 0x80:
            subs.append(val)
            val = 0
    if not subs:
        raise _DerError("truncated oid")
    first = subs[0]
    if first < 40:
        parts = ["0", str(first)]
    elif first < 80:
        parts = ["1", str(first - 40)]
    else:
        parts = ["2", str(first - 80)]
    parts += [str(s) for s in subs[1:]]
    return ".".join(parts)


def _der_time(data: bytes, cs: int, ce: int):
    """A UTCTime / GeneralizedTime body as an aware UTC datetime, or None."""
    s = data[cs:ce].decode("ascii", "replace")
    # UTCTime (2-digit year): X.509/RFC 5280 S4.1.2.5.1 mandates the pivot at 50
    # (YY>=50 => 19YY, YY<50 => 20YY) — NOT strptime's fixed POSIX pivot at 69.
    try:
        dt = datetime.strptime(s[:13] + ("Z" if not s[:13].endswith("Z") else ""), "%y%m%d%H%M%SZ")
        yy = int(s[:2])
        return dt.replace(year=(1900 + yy if yy >= 50 else 2000 + yy), tzinfo=UTC)
    except ValueError:
        pass
    # GeneralizedTime (4-digit year): unambiguous.
    try:
        return datetime.strptime(s[:15] + ("Z" if not s[:15].endswith("Z") else ""), "%Y%m%d%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        pass
    try:
        return datetime.strptime(s, "%Y%m%d%H%M%S%z").astimezone(UTC)
    except ValueError:
        return None


def _rdn_cn(data: bytes, name_cs: int, name_ce: int):
    """The commonName (OID 2.5.4.3) value of a Name (a SEQUENCE OF RDN), or None."""
    try:
        for _, rcs, rce in _der_items(data, name_cs, name_ce):        # RelativeDistinguishedName SET
            for _, acs, ace in _der_items(data, rcs, rce):            # AttributeTypeAndValue SEQUENCE
                items = _der_items(data, acs, ace)
                if len(items) >= 2 and items[0][0] == 0x06 and _der_oid(data, items[0][1], items[0][2]) == "2.5.4.3":
                    vcs, vce = items[1][1], items[1][2]
                    return data[vcs:vce].decode("utf-8", "replace").strip()
    except _DerError:
        return None
    return None


# ---------------------------------------------------------------------------- what a blob is

def _looks_der_seq(data: bytes) -> bool:
    if len(data) < 4 or data[0] != 0x30:
        return False
    try:
        length, hl = _der_len(data, 1)
    except _DerError:
        return False
    return 1 + hl + length == len(data) and length > 0


def pem_blocks(data: bytes) -> list:
    """[(label, der_bytes)] of every PEM block, label upper-cased without BEGIN/END."""
    out = []
    try:
        text = data.decode("ascii", "replace")
    except Exception:  # noqa: BLE001
        return out
    for m in re.finditer(r"-----BEGIN ([A-Za-z0-9 .+-]+)-----\s*(.*?)-----END \1-----", text, re.S):
        label = m.group(1).strip().upper()
        b64 = re.sub(r"\s+", "", m.group(2))
        b64 = re.sub(r"^.*?:[^\n]*\n", "", b64)              # drop a Proc-Type/DEK-Info header line
        try:
            der = base64.b64decode(b64, validate=False)
        except (binascii.Error, ValueError):
            continue
        if der:
            out.append((label, der))
    return out


def _cert_from_der(der: bytes) -> dict:
    """Facts of an X.509 certificate DER. Fingerprints are computed from the exact bytes, so they
    stand whether or not `cryptography` is present; everything else is best-effort and fail-closed."""
    facts = {"shape": "x509",
             "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
             "fingerprint_sha1": hashlib.sha1(der).hexdigest(),
             "fingerprint_md5": hashlib.md5(der).hexdigest()}
    if _HAVE_CRYPTO:
        try:
            cert = _x509.load_der_x509_certificate(der)
            facts["serial"] = cert.serial_number
            facts["subject"] = cert.subject.rfc4514_string()
            facts["issuer"] = cert.issuer.rfc4514_string()
            cn = cert.subject.get_attributes_for_oid(_x509.oid.NameOID.COMMON_NAME)
            icn = cert.issuer.get_attributes_for_oid(_x509.oid.NameOID.COMMON_NAME)
            facts["subject_cn"] = cn[0].value if cn else None
            facts["issuer_cn"] = icn[0].value if icn else None
            nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
            na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
            facts["not_before"] = nb if nb.tzinfo else nb.replace(tzinfo=UTC)
            facts["not_after"] = na if na.tzinfo else na.replace(tzinfo=UTC)
            facts["sig_alg"] = getattr(cert.signature_algorithm_oid, "_name", None) or cert.signature_algorithm_oid.dotted_string
            facts["version"] = cert.version.name
            pk = cert.public_key()
            if isinstance(pk, _rsa.RSAPublicKey):
                facts["pubkey_algo"], facts["key_size"] = "rsa", pk.key_size
                facts["modulus"] = pk.public_numbers().n
                facts["public_exponent"] = pk.public_numbers().e
            elif isinstance(pk, _ec.EllipticCurvePublicKey):
                facts["pubkey_algo"], facts["key_size"], facts["curve"] = "ec", pk.key_size, pk.curve.name
            else:
                facts["pubkey_algo"] = type(pk).__name__.replace("PublicKey", "").lower() or None
            return facts
        except Exception:  # noqa: BLE001 - fall back to the bounded pure walk below
            pass
    # Pure-Python fall-back: serial, validity, the algorithm OIDs, the common names.
    try:
        top = _der_items(der, 0, len(der))
        if len(top) != 1 or top[0][0] != 0x30:
            return facts
        tbs_items = _der_items(der, top[0][1], top[0][2])
        if not tbs_items:
            return facts
        tbs = tbs_items[0]
        if tbs[0] != 0x30:
            return facts
        inner = _der_items(der, tbs[1], tbs[2])
        idx = 0
        if inner and inner[0][0] == 0xA0:                 # [0] EXPLICIT version
            idx = 1
        if idx < len(inner) and inner[idx][0] == 0x02:
            facts["serial"] = int.from_bytes(der[inner[idx][1]:inner[idx][2]], "big")
        # signature AlgorithmIdentifier is inner[idx+1]; subject is inner[idx+3]; validity inner[idx+4]... layout:
        # serial, sigAlg, issuer, validity, subject, subjectPKInfo
        try:
            sig = inner[idx + 1]
            soid = _der_items(der, sig[1], sig[2])
            if soid and soid[0][0] == 0x06:
                facts["sig_alg"] = _SIG_OIDS.get(_der_oid(der, soid[0][1], soid[0][2]))
            issuer, validity, subject = inner[idx + 2], inner[idx + 3], inner[idx + 4]
            facts["issuer_cn"] = _rdn_cn(der, issuer[1], issuer[2])
            facts["subject_cn"] = _rdn_cn(der, subject[1], subject[2])
            vitems = _der_items(der, validity[1], validity[2])
            if len(vitems) >= 2:
                facts["not_before"] = _der_time(der, vitems[0][1], vitems[0][2])
                facts["not_after"] = _der_time(der, vitems[1][1], vitems[1][2])
            spki = inner[idx + 5]
            ai = _der_items(der, spki[1], spki[2])
            aoid = _der_items(der, ai[0][1], ai[0][2]) if ai and ai[0][0] == 0x30 else []
            if aoid and aoid[0][0] == 0x06:
                facts["pubkey_algo"] = _PK_OIDS.get(_der_oid(der, aoid[0][1], aoid[0][2]))
        except (_DerError, IndexError):
            pass
    except _DerError:
        pass
    return facts


def _key_from_der(der: bytes, private: bool) -> dict:
    """Facts of an RSA/EC key DER (PKCS#1/PKCS#8/SPKI), fail-closed. Private secrets are not kept."""
    facts = {"shape": "key"}
    if not _HAVE_CRYPTO:
        return facts
    try:
        k = (_ser.load_der_private_key(der, password=None) if private
             else _ser.load_der_public_key(der))
        pk = k.public_key() if private else k
        if isinstance(pk, _rsa.RSAPublicKey):
            facts.update(pubkey_algo="rsa", key_size=pk.key_size,
                         modulus=pk.public_numbers().n, public_exponent=pk.public_numbers().e)
        elif isinstance(pk, _ec.EllipticCurvePublicKey):
            facts.update(pubkey_algo="ec", key_size=pk.key_size, curve=pk.curve.name)
        else:
            facts["pubkey_algo"] = type(pk).__name__.replace("PublicKey", "").lower() or None
    except Exception:  # noqa: BLE001
        return {"shape": "key"}
    return facts


# ---------------------------------------------------------------------------- SSH public keys

def ssh_pubkey(text: str):
    """Facts of the first OpenSSH public-key line in `text`, or None. The SHA256/MD5 fingerprints
    are computed from the exact key blob, as `ssh-keygen -l` prints them."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in SSH_TYPES:
            try:
                blob = base64.b64decode(parts[1], validate=True)
            except (binascii.Error, ValueError):
                continue
            fields = _ssh_strings(blob)
            if not fields or fields[0].decode("ascii", "replace") != parts[0]:
                continue
            if len(fields) < 2 or not fields[1]:     # a bare type with no public-key field is not a key
                continue
            facts = {"shape": "ssh", "ssh_type": parts[0],
                     "ssh_fingerprint_sha256": "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("="),
                     "ssh_fingerprint_md5": "MD5:" + ":".join(f"{b:02x}" for b in hashlib.md5(blob).digest())}
            if len(parts) >= 3:
                facts["ssh_comment"] = " ".join(parts[2:])
            if parts[0] == "ssh-rsa" and len(fields) >= 3:     # e, n -> modulus bit length
                n = int.from_bytes(fields[2].lstrip(b"\x00"), "big")
                facts["ssh_bits"] = n.bit_length()
            elif parts[0] == "ssh-ed25519":
                facts["ssh_bits"] = 256
            elif parts[0].startswith("ecdsa-sha2-nistp"):
                facts["ssh_bits"] = int(parts[0].rsplit("nistp", 1)[-1])
            return facts
    return None


def _ssh_strings(blob: bytes) -> list:
    """The length-prefixed fields of an SSH wire blob (bounded)."""
    out, i = [], 0
    while i + 4 <= len(blob) and len(out) < 64:
        n = struct.unpack_from(">I", blob, i)[0]
        i += 4
        if n > len(blob) - i:
            break
        out.append(blob[i:i + n])
        i += n
    return out


# ---------------------------------------------------------------------------- OpenPGP packets

_PGP_PK_ALGO = {1: "rsa", 2: "rsa_encrypt", 3: "rsa_sign", 16: "elgamal", 17: "dsa", 18: "ecdh",
                19: "ecdsa", 22: "eddsa", 25: "x25519", 27: "ed25519"}


def pgp_key(data: bytes):
    """Facts of the first OpenPGP public-key packet, or None. The v4 fingerprint is the SHA-1 of
    0x99 || len || the key packet body (RFC 4880), a deterministic read of exact bytes."""
    facts = None
    userid = None
    i, guard = 0, 0
    while i < len(data) and guard < 4096:
        guard += 1
        b = data[i]
        if not (b & 0x80):
            break
        if b & 0x40:                            # new-format header
            tag = b & 0x3F
            i += 1
            if i >= len(data):
                break
            l0 = data[i]
            if l0 < 192:
                length, i = l0, i + 1
            elif l0 < 224:
                if i + 2 > len(data):
                    break
                length = ((l0 - 192) << 8) + data[i + 1] + 192
                i += 2
            elif l0 == 255:
                if i + 5 > len(data):
                    break
                length = struct.unpack_from(">I", data, i + 1)[0]
                i += 5
            else:                               # partial body length: not read
                break
        else:                                   # old-format header
            tag = (b >> 2) & 0x0F
            lt = b & 0x03
            i += 1
            try:
                if lt == 0:
                    length = data[i]; i += 1
                elif lt == 1:
                    length = struct.unpack_from(">H", data, i)[0]; i += 2
                elif lt == 2:
                    length = struct.unpack_from(">I", data, i)[0]; i += 4
                else:
                    break
            except (struct.error, IndexError):
                break
        cs, ce = i, i + length
        if ce > len(data):
            break
        body = data[cs:ce]
        if tag in (6, 14) and facts is None and body and body[0] == 4 and 6 <= len(body) <= 0xFFFF:   # v4 public key / subkey
            fpr = hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).hexdigest()
            created = struct.unpack_from(">I", body, 1)[0]
            facts = {"shape": "pgp", "pgp_fingerprint": fpr, "pgp_keyid": fpr[-16:],
                     "pgp_algo": _PGP_PK_ALGO.get(body[5]),
                     "pgp_created": datetime.fromtimestamp(created, UTC) if 0 < created < (1 << 32) else None}
        elif tag == 13 and userid is None:      # User ID packet
            userid = body.decode("utf-8", "replace")
        i = ce
    if facts is not None and userid:
        facts["pgp_userid"] = userid
    return facts


# ---------------------------------------------------------------------------- one report per file

def classify(data: bytes, name: str = "") -> dict:
    """{kind, facts, label?} for a file this toolkit reads, else None. kind in pem/x509/key/ssh/pgp."""
    if not isinstance(data, (bytes, bytearray)) or not data or len(data) > MAX_FILE:
        return None
    data = bytes(data)
    head = data[:MAX_SCAN]
    # PEM first (the label tells us what the DER is).
    for label, der in pem_blocks(head):
        if "CERTIFICATE" in label and "REQUEST" not in label and "REVOCATION" not in label and "CRL" not in label:
            f = _cert_from_der(der); f["pem_label"] = label
            return {"kind": "x509", "facts": f}
        if ("PRIVATE KEY" in label or "PUBLIC KEY" in label) and "PGP" not in label:
            f = _key_from_der(der, private="PRIVATE" in label); f["pem_label"] = label
            return {"kind": "key", "facts": f}
        if "PGP" in label:
            try:
                blob = _dearmor_pgp(head)
            except Exception:  # noqa: BLE001
                blob = None
            f = (pgp_key(blob) if blob else None) or {"shape": "pgp"}
            f["pem_label"] = label
            return {"kind": "pgp", "facts": f}
        if der and der[0] == 0x30:              # CSR, CRL, PKCS7, ... : the fingerprint of the DER is still a fact
            return {"kind": "pem", "facts": {"shape": "der", "pem_label": label,
                                             "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
                                             "fingerprint_sha1": hashlib.sha1(der).hexdigest()}}
    # Raw DER certificate.
    if _looks_der_seq(head) and len(head) == len(data):
        if _is_der_certificate(data):
            return {"kind": "x509", "facts": _cert_from_der(data)}
    # OpenSSH public key.
    try:
        sf = ssh_pubkey(head.decode("ascii", "replace"))
    except Exception:  # noqa: BLE001
        sf = None
    if sf:
        return {"kind": "ssh", "facts": sf}
    # Binary OpenPGP.
    if data[:1] and (data[0] & 0x80) and (data[0] & 0x40 or ((data[0] >> 2) & 0x0F) in (6, 14)):
        f = pgp_key(data)
        if f:
            return {"kind": "pgp", "facts": f}
    return None


def _is_der_certificate(der: bytes) -> bool:
    """True only when the DER parses as the Certificate shape (SEQ{ SEQ tbs, SEQ sigAlg, BITSTRING })."""
    try:
        top = _der_items(der, 0, len(der))
        if len(top) != 1 or top[0][0] != 0x30:
            return False
        items = _der_items(der, top[0][1], top[0][2])
        return len(items) == 3 and items[0][0] == 0x30 and items[1][0] == 0x30 and items[2][0] == 0x03
    except _DerError:
        return False


def _dearmor_pgp(data: bytes):
    """The binary packets of an ASCII-armored PGP block, or None."""
    text = data.decode("ascii", "replace")
    m = re.search(r"-----BEGIN PGP [A-Z ]+-----\s*(.*?)-----END PGP", text, re.S)
    if not m:
        return None
    body = m.group(1)
    body = re.sub(r"^[A-Za-z][\w-]*:[^\n]*\n", "", body)        # armor headers
    body = re.sub(r"\n=.{4}\s*$", "", body.strip())            # the CRC-24 checksum line
    try:
        return base64.b64decode(re.sub(r"\s+", "", body), validate=False)
    except (binascii.Error, ValueError):
        return None


def reports(files) -> list:
    out = []
    try:
        for name, data in triage.unique_files(files or {}):
            try:
                rep = classify(data, name)
            except Exception:  # noqa: BLE001 - one unreadable file does not cost the others
                rep = None
            if rep is not None:
                out.append((name, rep))
    except Exception:  # noqa: BLE001
        return []
    return out


# ---------------------------------------------------------------------------- signals

_WORDS = re.compile(
    r"certificate|\bx\.?509\b|\bder\b|\bpem\b|\bpkcs\b|subject|issuer|serial|fingerprint|thumbprint|"
    r"not ?before|not ?after|valid(?:ity| from| to)|signature algorithm|public key|modulus|\brsa\b|"
    r"\becc?\b|elliptic|\bssh\b|openssh|\bpgp\b|gpg|openpgp|key ?id|common name|\bcn\b|\bsan\b|"
    r"distinguished name|\bdn\b|curve|csr|\bcrl\b|authenticode|keypair|private key", re.I)


def signals(questions, files) -> float:
    """0..1: a certificate/key/PGP/SSH blob validates in the bytes, plus PKI vocabulary. 0.0 when
    nothing validates, so it never competes on a 64-byte blob or an unrelated delivery."""
    try:
        kinds = {r["kind"] for _n, r in reports(files or {})}
    except Exception:  # noqa: BLE001
        kinds = set()
    if not kinds:
        return 0.0
    score = 0.5
    hits = set()
    for q in questions or []:
        f = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        text = " ".join(str(x or "") for x in (q.get("question"), q.get("answer_id") or q.get("id"), f.get("syntax")))
        hits |= {m.group().lower() for m in _WORDS.finditer(text)}
    score += min(0.4, 0.1 * len(hits))
    return round(min(1.0, score), 2)


# ---------------------------------------------------------------------------- answers (never-guess)

def _hex_options(value, field):
    """Rendering options of a byte-exact hash/fingerprint already stored as a hex (or SHA256:/MD5:) string."""
    v = str(value)
    body = v.split(":", 1)[1] if v[:7] in ("SHA256:", "SHA512:") or v[:4] == "MD5:" else v
    opts = [("raw", v)]
    if re.fullmatch(r"[0-9a-fA-F]+", body):
        low = body.lower()
        opts = [("lower", low), ("upper", low.upper()),
                ("colon_lower", ":".join(low[i:i + 2] for i in range(0, len(low), 2))),
                ("colon_upper", ":".join(low[i:i + 2] for i in range(0, len(low), 2)).upper())]
        if v != low:
            opts.insert(0, ("raw", v))
    return opts


def _serial_options(n):
    hx = format(n, "x")
    if len(hx) % 2:
        hx = "0" + hx
    return [("decimal", str(n)), ("hex", hx), ("hex_0x", "0x" + hx),
            ("colon_hex", ":".join(hx[i:i + 2] for i in range(0, len(hx), 2)))]


def _time_options(t: datetime):
    u = t.astimezone(UTC)
    return [("iso_z", u.strftime("%Y-%m-%dT%H:%M:%SZ")), ("iso_space", u.strftime("%Y-%m-%d %H:%M:%S")),
            ("iso_offset", u.strftime("%Y-%m-%dT%H:%M:%S+00:00")), ("date", u.strftime("%Y-%m-%d")),
            ("epoch", str(int(u.timestamp()))), ("space_utc", u.strftime("%Y-%m-%d %H:%M:%S UTC"))]


def _int_options(n):
    hx = format(n, "x")
    if len(hx) % 2:
        hx = "0" + hx
    return [("decimal", str(n)), ("hex", hx), ("hex_0x", "0x" + hx)]


def _pick(field, shape, options):
    opts, seen = [], set()
    for name, value in options:
        value = str(value)
        if value and (name, value) not in seen:
            seen.add((name, value))
            opts.append((name, value))
    if not opts:
        return None
    try:
        return labels.pick(f"{KEY}.{field}/{shape}", opts)
    except ValueError:
        return None


def _file_for(q, reps):
    member = q.get("member") or (str(q.get("artifact") or "").split(ARROW)[-1] if q.get("artifact") else "")
    base = Path(str(member)).name if member else ""
    if base:
        hit = [r for r in reps if Path(r[0]).name == base or r[0].split(ARROW)[-1] == member or r[0] == member]
        if len(hit) == 1:
            return hit[0][1]
        if hit:
            return None
    return reps[0][1] if len(reps) == 1 else None


def _answer_one(q, rep) -> object:
    text = str(q.get("question") or "")
    aid = str(q.get("answer_id") or q.get("id") or q.get("qid") or "")
    t = (text + " " + aid).lower()
    facts = rep["facts"]
    shape = facts.get("shape") or rep["kind"]

    def has(*words):
        return any(w in t for w in words)

    def fact(name):
        return facts.get(name)

    if has("flag"):
        return None
    # Fingerprints / thumbprints (a digest of exact bytes) - plain-eligible as a rendering pick.
    if has("fingerprint", "thumbprint", "hash of the cert", "hash of the key", "cert hash"):
        if has("sha256", "sha-256", "sha_256") and fact("fingerprint_sha256"):
            return _pick("fingerprint_sha256", shape, _hex_options(fact("fingerprint_sha256"), "fp"))
        if has("sha1", "sha-1", "sha_1") and fact("fingerprint_sha1"):
            return _pick("fingerprint_sha1", shape, _hex_options(fact("fingerprint_sha1"), "fp"))
        if has("md5") and fact("fingerprint_md5"):
            return _pick("fingerprint_md5", shape, _hex_options(fact("fingerprint_md5"), "fp"))
        if shape == "ssh" and fact("ssh_fingerprint_sha256"):
            return _pick("ssh_fingerprint", shape, _hex_options(fact("ssh_fingerprint_sha256"), "fp"))
        if shape == "pgp" and fact("pgp_fingerprint"):
            return _pick("pgp_fingerprint", shape, _hex_options(fact("pgp_fingerprint"), "fp"))
        # No qualifier: offer sha256 first, never plain across the ambiguity of "the fingerprint".
        for name in ("fingerprint_sha256", "ssh_fingerprint_sha256", "pgp_fingerprint"):
            if fact(name):
                return _pick(name.replace("_sha256", ""), shape, _hex_options(fact(name), "fp"))
        return None
    if shape == "pgp" and has("key id", "keyid", "key-id") and fact("pgp_keyid"):
        return _pick("pgp_keyid", shape, _hex_options(fact("pgp_keyid"), "kid"))
    if has("serial") and fact("serial") is not None:
        return _pick("serial", shape, _serial_options(fact("serial")))
    if has("not before", "valid from", "issued on", "issued at", "notbefore") and fact("not_before"):
        return _pick("not_before", shape, _time_options(fact("not_before")))
    if has("not after", "valid to", "valid until", "expire", "expiry", "expiration", "notafter") and fact("not_after"):
        return _pick("not_after", shape, _time_options(fact("not_after")))
    if has("common name", "\bcn\b") or re.search(r"(?<![a-z])cn(?![a-z])", t):
        if has("issuer") and fact("issuer_cn"):
            return _pick("issuer_cn", shape, [("raw", fact("issuer_cn"))])
        if fact("subject_cn"):
            return _pick("subject_cn", shape, [("raw", fact("subject_cn"))])
    if has("issuer") and (fact("issuer") or fact("issuer_cn")):
        return _pick("issuer", shape, [("rfc4514", fact("issuer"))] if fact("issuer") else [("cn", fact("issuer_cn"))])
    if has("subject") and (fact("subject") or fact("subject_cn")):
        return _pick("subject", shape, [("rfc4514", fact("subject"))] if fact("subject") else [("cn", fact("subject_cn"))])
    if has("signature algorithm", "signature_algorithm", "sig alg", "sigalg", "signed with", "signature scheme") and fact("sig_alg"):
        return _pick("sig_alg", shape, [("raw", fact("sig_alg")), ("lower", str(fact("sig_alg")).lower())])
    if has("modulus") and fact("modulus") is not None:
        return _pick("modulus", shape, _int_options(fact("modulus")))
    if has("exponent") and fact("public_exponent") is not None:
        return _pick("public_exponent", shape, _int_options(fact("public_exponent")))
    if has("curve") and fact("curve"):
        return _pick("curve", shape, [("raw", fact("curve")), ("lower", str(fact("curve")).lower())])
    if has("key size", "key_size", "key length", "keylength", "bits", "modulus size", "how many bits"):
        if shape == "ssh" and fact("ssh_bits") is not None:
            return _pick("key_size", shape, [("decimal", fact("ssh_bits"))])
        if fact("key_size") is not None:
            return _pick("key_size", shape, [("decimal", fact("key_size"))])
    if has("public key algorithm", "public-key algorithm", "key algorithm", "key type", "algorithm of the key", "pubkey"):
        if shape == "ssh" and fact("ssh_type"):
            return _pick("ssh_type", shape, [("raw", fact("ssh_type"))])
        if shape == "pgp" and fact("pgp_algo"):
            return _pick("pgp_algo", shape, [("raw", fact("pgp_algo"))])
        if fact("pubkey_algo"):
            return _pick("pubkey_algo", shape, [("raw", fact("pubkey_algo")), ("upper", str(fact("pubkey_algo")).upper())])
    if shape == "ssh" and has("comment") and fact("ssh_comment"):
        return _pick("ssh_comment", shape, [("raw", fact("ssh_comment"))])
    if shape == "ssh" and has("key type", "type of key", "algorithm") and fact("ssh_type"):
        return _pick("ssh_type", shape, [("raw", fact("ssh_type"))])
    if shape == "pgp" and (has("user id", "userid", "uid", "owner") ) and fact("pgp_userid"):
        return _pick("pgp_userid", shape, [("raw", fact("pgp_userid"))])
    if shape == "pgp" and has("created", "creation", "generated") and fact("pgp_created"):
        return _pick("pgp_created", shape, _time_options(fact("pgp_created")))
    if has("version") and fact("version"):
        return _pick("version", shape, [("raw", fact("version")), ("lower", str(fact("version")).lower())])
    if has("pem", "label", "type of block", "block type") and fact("pem_label"):
        return _pick("pem_label", shape, [("raw", fact("pem_label"))])
    return None


def solve_set(questions, files, ctx) -> dict:
    reps = reports(files)
    out = {}
    for q in questions or []:
        qid = q.get("qid") or q.get("id") or q.get("answer_id")
        if qid is None:
            continue
        rep = _file_for(q, reps)
        try:
            out[qid] = None if rep is None else _answer_one(q, rep)
        except Exception:  # noqa: BLE001 - a fact that cannot be read is no answer
            out[qid] = None
    if isinstance(ctx, dict) and isinstance(ctx.get("partial"), dict):
        ctx["partial"].update({k: v for k, v in out.items() if v is not None})
    return out


# ---------------------------------------------------------------------------- CLI (offline triage)

def _jsonable(facts: dict) -> dict:
    out = {}
    for k, v in facts.items():
        if isinstance(v, datetime):
            out[k] = v.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        elif isinstance(v, int) and k in ("modulus", "serial") and v.bit_length() > 80:
            out[k] = {"decimal_digits": len(str(v)), "hex": format(v, "x")}
        else:
            out[k] = v
    return out


def main(argv) -> int:
    as_json = "--json" in argv
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: asn1_reader.py <file>... [--json]   (RECON ONLY; private secrets and flags are None)",
              file=sys.stderr)
        return 2
    out = []
    for p in paths:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"asn1_reader.py: {p}: {e}", file=sys.stderr)
            continue
        rep = classify(data, p)
        out.append({"file": p, "kind": rep["kind"] if rep else None,
                    "facts": _jsonable(rep["facts"]) if rep else None, "bytes": len(data)})
    if as_json:
        print(json.dumps(out, indent=1))
        return 0
    for row in out:
        if not row["kind"]:
            print(f"- {row['file']}: no ASN.1/X.509/key/SSH/PGP structure recognised ({row['bytes']} bytes)")
            continue
        print(f"# {row['file']}  [{row['kind']}]")
        for k, v in row["facts"].items():
            print(f"    {k} = {v}")
        print("  deterministic facts (fingerprints, serial) are plain-eligible via labels.pick; "
              "a private key's secret parameters and the flag are None.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
