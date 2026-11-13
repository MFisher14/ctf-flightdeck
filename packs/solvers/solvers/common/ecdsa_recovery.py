#!/usr/bin/env python3
"""Schema/DER-tolerant ECDSA ``(r, s, z)`` reader in front of ``ecc_faults`` recovery (B-027).

The recovery arithmetic for ECDSA nonce faults already lives, fail-closed and ``d*G``-verified, in
``solvers/common/ecc_faults.py`` (``recover_ecdsa_reused_nonce``, ``recover_ecdsa_known_nonce``,
``recover_ecdsa_nonce_delta``).  What was missing, and what this module adds, is everything in *front*
of those functions:

* a tolerant reader that turns a JSON signature export (``r||s`` under any ``*_rs``/``*signature*``
  name, message under ``*_b64``/``*_hex``/``message``) into ``(r, s, z)`` records and the public key;
* a minimal, standards-only DER walker that pulls the SEC1 public point out of a SubjectPublicKeyInfo
  and every ``(message, r, s)`` from the ``ECDSA-Sig-Value`` sequences in a signed-order bundle;
* a canonical-message rebuilder that reconstructs the exact signed bytes of an audit-log record from a
  **declared** field layout (the signer's framing is data the operator supplies, never guessed here),
  so signature-bearing logs become ``(r, s, z)`` records;
* ``recover_ecdsa_linear_nonce``: key recovery when the nonces are related by a low-degree polynomial
  in the record index (``k_i = c0 + c1*i + ...``, the arithmetic-progression / stride fault), solved as
  a linear system modulo the group order and then **self-verified by ``d*G == Q`` and re-verification
  of every signature** before a scalar is returned.

Everything is offline standard-library arithmetic and emits a scalar only after it reproduces the
supplied public key.  ``solve()`` is the engine entry: it reads the challenge's JSON/DER artifacts,
recovers the private scalar, and emits it (plus candidate downstream parameters such as
``IKM = I2OSP(d, 32)``) as a candidate for the operator to format or feed to a KDF/AEAD open.  A live
signing/authorize service and the exact log framing are documented gaps, not silent fallbacks.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

# Flat import: the engine sys.path (conftest / ctf.engines boot) puts solvers/common on it.
from ecc_faults import (  # noqa: E402
    CURVES,
    SECP256K1,
    SECP256R1,
    WeierstrassCurve,
    ec_mul,
    ecdsa_verify,
    recover_ecdsa_known_nonce,
    recover_ecdsa_nonce_delta,
    recover_ecdsa_reused_nonce,
)

_HASHES = {"sha256": hashlib.sha256, "sha-256": hashlib.sha256, "sha1": hashlib.sha1,
           "sha-1": hashlib.sha1, "sha384": hashlib.sha384, "sha-384": hashlib.sha384,
           "sha512": hashlib.sha512, "sha-512": hashlib.sha512}


class EcdsaReadError(ValueError):
    """An artifact could not be read into signature records (named reason, never a silent fallback)."""


def resolve_curve(curve: str | WeierstrassCurve | None) -> Optional[WeierstrassCurve]:
    """Accept a ``WeierstrassCurve``, a known curve name, or ``None`` (unknown)."""
    if isinstance(curve, WeierstrassCurve):
        return curve
    if isinstance(curve, str):
        return CURVES.get(curve.strip().lower())
    return None


def hash_z(message: bytes, curve: WeierstrassCurve, hash_name: str = "sha256") -> int:
    """ECDSA ``z``: the big-endian integer of ``H(message)`` reduced modulo the group order."""
    fn = _HASHES.get(hash_name.strip().lower())
    if fn is None:
        raise EcdsaReadError(f"unsupported hash {hash_name!r}; known: {', '.join(sorted(_HASHES))}")
    return int.from_bytes(fn(message).digest(), "big") % curve.n


# ---------------------------------------------------------------------------
# Signature records


@dataclass(frozen=True)
class SigRecord:
    """One ECDSA signature ready for recovery: ``r``, ``s`` and the message hash ``z``."""

    r: int
    s: int
    z: int
    message: Optional[bytes] = None
    index: Optional[int] = None     # sequence index, for index-related nonces
    label: Optional[str] = None

    @property
    def rsz(self) -> tuple[int, int, int]:
        return self.r, self.s, self.z


def _as_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            if re.fullmatch(r"[0-9]+", text):
                return int(text)
            return int(text, 16)
        except ValueError:
            return None
    return None


def _decode_field(name: str, value: Any) -> Optional[bytes]:
    """Decode a message field by the convention its name declares (``*_b64`` / ``*_hex``)."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if not isinstance(value, str):
        return None
    low = name.lower()
    text = value.strip()
    try:
        if low.endswith("_b64") or low.endswith("_base64") or "b64" in low:
            return base64.b64decode(text, validate=True)
        if low.endswith("_hex") or "hex" in low:
            return bytes.fromhex(text)
    except (binascii.Error, ValueError) as exc:
        raise EcdsaReadError(f"field {name!r} is not valid {('base64' if 'b64' in low else 'hex')}: {exc}")
    # Last resort: a plain textual message is signed as its UTF-8 bytes.
    return text.encode("utf-8")


_RS_NAME = re.compile(r"(^|_)(rs|sig|signature)(_|$)|signature", re.IGNORECASE)
_MSG_NAME = re.compile(r"(^|_)(msg|message)(_|$)|message", re.IGNORECASE)


def _split_rs(value: Any, curve: WeierstrassCurve) -> Optional[tuple[int, int]]:
    """Split a concatenated ``r||s`` hex/bytes field into two equal halves."""
    raw: Optional[bytes] = None
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]+", value.strip()) and len(value.strip()) % 2 == 0:
        try:
            raw = bytes.fromhex(value.strip())
        except ValueError:
            raw = None
    if raw is None or len(raw) < 2 or len(raw) % 2:
        return None
    half = len(raw) // 2
    r = int.from_bytes(raw[:half], "big")
    s = int.from_bytes(raw[half:], "big")
    if 0 < r < curve.n and 0 < s < curve.n:
        return r, s
    return None


def _record_from_mapping(item: dict, curve: WeierstrassCurve, hash_name: str,
                         index: Optional[int]) -> Optional[SigRecord]:
    r = s = None
    # Explicit r / s fields win.
    if "r" in item and "s" in item:
        r, s = _as_int(item["r"]), _as_int(item["s"])
    if r is None or s is None:
        for key, value in item.items():
            if _RS_NAME.search(key):
                split = _split_rs(value, curve)
                if split:
                    r, s = split
                    break
    if r is None or s is None or not (0 < r < curve.n and 0 < s < curve.n):
        return None
    # Message / z.
    z = None
    message = None
    for key, value in item.items():
        if key in ("r", "s") or _RS_NAME.search(key):
            continue
        if _MSG_NAME.search(key) or key.lower().endswith(("_b64", "_hex", "_base64")):
            message = _decode_field(key, value)
            if message is not None:
                break
    if message is not None:
        z = hash_z(message, curve, hash_name)
    elif "z" in item:
        z = _as_int(item["z"])
        if z is not None:
            z %= curve.n
    if z is None:
        return None
    seq = _as_int(item.get("seq")) if "seq" in item else index
    return SigRecord(r=r, s=s, z=z, message=message, index=seq,
                     label=str(item.get("record_id") or item.get("id") or "") or None)


def _public_point(obj: Any, curve: WeierstrassCurve) -> Optional[tuple[int, int]]:
    """Find an ``(x, y)`` public point in a decoded-JSON object."""
    if isinstance(obj, dict):
        for key in ("public_key", "pubkey", "public", "Q", "spki"):
            if key in obj:
                found = _public_point(obj[key], curve)
                if found:
                    return found
        if "x" in obj and "y" in obj:
            x, y = _as_int(obj["x"]), _as_int(obj["y"])
            if x is not None and y is not None:
                return x, y
    if isinstance(obj, (list, tuple)) and len(obj) == 2:
        x, y = _as_int(obj[0]), _as_int(obj[1])
        if x is not None and y is not None:
            return x, y
    if isinstance(obj, str):
        text = obj.strip()
        if re.fullmatch(r"(?:0x)?04[0-9a-fA-F]+", text) and len(text.replace("0x", "")) == 130:
            raw = bytes.fromhex(text.replace("0x", ""))
            return int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:65], "big")
    return None


def json_declared_curve(obj: Any) -> Optional[str]:
    """The canonical name of the curve a ``signature_format`` block declares, or None if absent/unknown."""
    fmt = obj.get("signature_format") if isinstance(obj, dict) else None
    if not isinstance(fmt, dict):
        return None
    cv = resolve_curve(fmt.get("curve"))
    return cv.name if cv is not None else None


def read_json_records(obj: Any, *, curve: str | WeierstrassCurve | None = None,
                      hash_name: str | None = None) -> tuple[list[SigRecord], Optional[tuple[int, int]]]:
    """Tolerantly read ``(records, public_point)`` from a decoded JSON signature export.

    Curve and hash come from a ``signature_format`` block when present, else from the ``curve`` keyword.
    """
    fmt = obj.get("signature_format") if isinstance(obj, dict) else None
    if curve is None and isinstance(fmt, dict):
        curve = fmt.get("curve")
    cv = resolve_curve(curve) or SECP256K1
    if hash_name is None:
        hash_name = (fmt.get("hash") if isinstance(fmt, dict) else None) or "sha256"
    # Find the record list: the first list of dicts that yields at least one record.
    candidates: list[list] = []
    if isinstance(obj, list):
        candidates.append(obj)
    elif isinstance(obj, dict):
        for value in obj.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                candidates.append(value)
    records: list[SigRecord] = []
    for lst in candidates:
        acc: list[SigRecord] = []
        for i, item in enumerate(lst):
            if isinstance(item, dict):
                rec = _record_from_mapping(item, cv, hash_name, i)
                if rec:
                    acc.append(rec)
        if len(acc) > len(records):
            records = acc
    return records, _public_point(obj, cv)


# ---------------------------------------------------------------------------
# Minimal DER reader (standard ASN.1 DER; no third-party dependency)


@dataclass(frozen=True)
class DerNode:
    tag: int
    value: bytes
    children: tuple["DerNode", ...]

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)


def parse_der(data: bytes, *, _depth: int = 0) -> list[DerNode]:
    """Parse concatenated DER TLVs into a node tree.  Fail-closed on malformed length/bounds."""
    if _depth > 40:
        raise EcdsaReadError("DER nesting too deep")
    nodes: list[DerNode] = []
    i, end = 0, len(data)
    while i < end:
        tag = data[i]
        i += 1
        if i >= end:
            raise EcdsaReadError("truncated DER: missing length")
        length = data[i]
        i += 1
        if length & 0x80:
            nbytes = length & 0x7F
            if nbytes == 0 or i + nbytes > end:
                raise EcdsaReadError("truncated or indefinite DER length")
            length = int.from_bytes(data[i:i + nbytes], "big")
            i += nbytes
        if i + length > end:
            raise EcdsaReadError("DER length runs past the buffer")
        value = data[i:i + length]
        i += length
        children: tuple[DerNode, ...] = ()
        if tag & 0x20:          # constructed
            children = tuple(parse_der(value, _depth=_depth + 1))
        nodes.append(DerNode(tag=tag, value=value, children=children))
    return nodes


def _iter_nodes(nodes: Iterable[DerNode]) -> Iterable[DerNode]:
    for node in nodes:
        yield node
        if node.children:
            yield from _iter_nodes(node.children)


_TAG_INT = 0x02
_TAG_BITSTRING = 0x03
_TAG_OCTET = 0x04
_TAG_SEQ = 0x30


def _sec1_point(encoded: bytes) -> Optional[tuple[int, int]]:
    if len(encoded) == 65 and encoded[0] == 0x04:
        return int.from_bytes(encoded[1:33], "big"), int.from_bytes(encoded[33:65], "big")
    return None


def der_public_point(nodes: Sequence[DerNode]) -> Optional[tuple[int, int]]:
    """The uncompressed SEC1 public point from a SubjectPublicKeyInfo BIT STRING."""
    for node in _iter_nodes(nodes):
        if node.tag == _TAG_BITSTRING and node.value and node.value[0] == 0:
            point = _sec1_point(node.value[1:])
            if point:
                return point
    return None


_TAG_OID = 0x06
# namedCurve OIDs (RFC 5480 / SEC 2), DER-encoded OBJECT IDENTIFIER bodies.
_CURVE_OIDS = {
    bytes.fromhex("2b8104000a"): "secp256k1",          # 1.3.132.0.10
    bytes.fromhex("2a8648ce3d030107"): "secp256r1",    # 1.2.840.10045.3.1.7 (prime256v1)
}


def der_declared_curve(nodes: Sequence[DerNode]) -> Optional[str]:
    """The curve a SubjectPublicKeyInfo's namedCurve OID declares, or None if no known OID is present."""
    for node in _iter_nodes(nodes):
        if node.tag == _TAG_OID and node.value in _CURVE_OIDS:
            return _CURVE_OIDS[node.value]
    return None


def read_der_records(data: bytes, *, curve: str | WeierstrassCurve | None = None,
                     hash_name: str = "sha256") -> tuple[list[SigRecord], Optional[tuple[int, int]]]:
    """Read ``(records, public_point)`` from a signed-order DER bundle.

    An ``ECDSA-Sig-Value`` is a SEQUENCE of exactly two INTEGERs; its enclosing SEQUENCE (a signed
    order) also carries the OCTET STRING message and, optionally, an INTEGER sequence number.
    The curve is the ``curve`` keyword, else the SPKI namedCurve OID, else secp256k1.
    """
    nodes = parse_der(data)
    cv = resolve_curve(curve) or resolve_curve(der_declared_curve(nodes)) or SECP256K1
    point = der_public_point(nodes)
    records: list[SigRecord] = []
    order_index = 0
    for order in _iter_nodes(nodes):
        if order.tag != _TAG_SEQ or not order.children:
            continue
        # Find a two-INTEGER child SEQUENCE (the signature) inside this order.
        sig = None
        for child in order.children:
            if (child.tag == _TAG_SEQ and len(child.children) == 2
                    and all(c.tag == _TAG_INT for c in child.children)):
                sig = child
                break
        if sig is None:
            continue
        message = next((c.value for c in order.children if c.tag == _TAG_OCTET), None)
        if message is None:
            continue
        seq_node = next((c for c in order.children
                         if c.tag == _TAG_INT and c is not sig), None)
        r = int.from_bytes(sig.children[0].value, "big")
        s = int.from_bytes(sig.children[1].value, "big")
        if not (0 < r < cv.n and 0 < s < cv.n):
            continue
        seq = int.from_bytes(seq_node.value, "big") if seq_node is not None else order_index
        records.append(SigRecord(r=r, s=s, z=hash_z(message, cv, hash_name),
                                 message=message, index=seq, label=f"order{seq}"))
        order_index += 1
    return records, point


# ---------------------------------------------------------------------------
# Canonical-message rebuild for signed logs (declared layout, never guessed)
#
# A layout is a sequence of field descriptors the operator declares from the protocol spec:
#   ("const", b"SP00KY-LOG-v1")          literal bytes
#   ("uint", "timestamp_ms", 8)          big-endian fixed-width integer from the record
#   ("lenpstr", "username", 1)           uint8 length prefix + the field's bytes (big-endian prefix)
#   ("bytes", "event")                   the field's raw bytes with no prefix
# Field values are looked up in each record mapping; str values become UTF-8 bytes.

LayoutField = tuple


def _field_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise EcdsaReadError(f"cannot serialize field value of type {type(value).__name__}")


def build_canonical_message(record: dict, layout: Sequence[LayoutField]) -> bytes:
    """Rebuild the exact signed bytes of one record from a declared canonical layout."""
    out = bytearray()
    for field in layout:
        kind = field[0]
        if kind == "const":
            out += _field_bytes(field[1])
        elif kind == "uint":
            _, name, width = field
            out += int(record[name]).to_bytes(width, "big")
        elif kind in ("lenpstr", "bytes"):
            name = field[1]
            payload = _field_bytes(record[name])
            if kind == "lenpstr":
                width = field[2]
                out += len(payload).to_bytes(width, "big")
            out += payload
        else:
            raise EcdsaReadError(f"unknown layout field kind {kind!r}")
    return bytes(out)


def read_log_records(records: Sequence[dict], layout: Sequence[LayoutField], *,
                     curve: str | WeierstrassCurve | None = None,
                     hash_name: str = "sha256") -> list[SigRecord]:
    """Turn signature-bearing log records into ``SigRecord``s via a declared canonical layout.

    Each record supplies the layout fields plus ``r`` and ``s`` (ints or hex).
    """
    cv = resolve_curve(curve) or SECP256K1
    out: list[SigRecord] = []
    for i, record in enumerate(records):
        r, s = _as_int(record.get("r")), _as_int(record.get("s"))
        if r is None or s is None or not (0 < r < cv.n and 0 < s < cv.n):
            continue
        message = build_canonical_message(record, layout)
        out.append(SigRecord(r=r, s=s, z=hash_z(message, cv, hash_name),
                             message=message, index=i,
                             label=str(record.get("user") or record.get("username") or "") or None))
    return out


# ---------------------------------------------------------------------------
# Recovery


def _solve_linear_mod(matrix: list[list[int]], vector: list[int], n: int) -> Optional[list[int]]:
    """Solve ``matrix * x == vector`` (mod prime ``n``) by Gauss-Jordan.  None if underdetermined."""
    rows = len(matrix)
    cols = len(matrix[0]) if matrix else 0
    aug = [[x % n for x in row] + [vector[r] % n] for r, row in enumerate(matrix)]
    pivot_row = 0
    pivot_cols: list[int] = []
    for col in range(cols):
        sel = next((r for r in range(pivot_row, rows) if aug[r][col] % n), None)
        if sel is None:
            continue
        aug[pivot_row], aug[sel] = aug[sel], aug[pivot_row]
        inv = pow(aug[pivot_row][col], -1, n)
        aug[pivot_row] = [(x * inv) % n for x in aug[pivot_row]]
        for r in range(rows):
            if r != pivot_row and aug[r][col] % n:
                factor = aug[r][col]
                aug[r] = [(a - factor * b) % n for a, b in zip(aug[r], aug[pivot_row])]
        pivot_cols.append(col)
        pivot_row += 1
        if pivot_row == rows:
            break
    if len(pivot_cols) < cols:
        return None     # underdetermined: not enough independent equations
    solution = [0] * cols
    for idx, col in enumerate(pivot_cols):
        solution[col] = aug[idx][cols] % n
    return solution


def _verify_scalar(private: int, public_key: Any, records: Sequence[SigRecord],
                   curve: WeierstrassCurve) -> bool:
    if not (isinstance(private, int) and 0 < private < curve.n):
        return False
    if ec_mul(private, None, curve) != tuple(public_key):
        return False
    return all(ecdsa_verify(rec.rsz, public_key, curve) for rec in records)


def recover_reused_nonce(records: Sequence[SigRecord], public_key: Any,
                         curve: str | WeierstrassCurve = "secp256k1") -> Optional[int]:
    """Scan for two records sharing ``r`` and recover ``d`` (delegates to ``ecc_faults``)."""
    cv = resolve_curve(curve)
    if cv is None:
        return None
    by_r: dict[int, SigRecord] = {}
    for rec in records:
        prior = by_r.get(rec.r)
        if prior is not None and prior.rsz != rec.rsz:
            found = recover_ecdsa_reused_nonce(prior.rsz, rec.rsz, public_key, cv)
            if found is not None:
                return found
        by_r.setdefault(rec.r, rec)
    return None


def recover_ecdsa_linear_nonce(records: Sequence[SigRecord], public_key: Any, *,
                               degree: int = 1,
                               curve: str | WeierstrassCurve = "secp256k1") -> Optional[int]:
    """Recover ``d`` when ``k_i`` is a degree-``degree`` polynomial in the record index ``i``.

    Models ``k_i = c0 + c1*i + ... + c_degree*i^degree`` with unknown coefficients (the stopped-sampler
    / arithmetic-progression nonce fault at ``degree == 1``).  Each signature gives
    ``s_i*k_i - r_i*d = z_i``, linear in the unknowns ``(c0..c_degree, d)``; solving ``degree+2``
    of them pins every unknown.  A scalar is returned only after ``d*G == Q`` and every supplied
    signature re-verifies.  Both the signer's raw ``s`` and a uniform low-S flip are tried.
    """
    cv = resolve_curve(curve)
    if cv is None or degree < 0:
        return None
    ordered = [rec for rec in records if rec.index is not None]
    ordered.sort(key=lambda rec: rec.index)
    unknowns = degree + 2
    if len(ordered) < unknowns:
        return None
    n = cv.n
    for flip in (False, True):
        subset = ordered[:unknowns]
        matrix: list[list[int]] = []
        vector: list[int] = []
        for rec in subset:
            s = (-rec.s) % n if flip else rec.s % n
            row = [(s * pow(rec.index, j, n)) % n for j in range(degree + 1)]
            row.append((-rec.r) % n)
            matrix.append(row)
            vector.append(rec.z % n)
        solution = _solve_linear_mod(matrix, vector, n)
        if solution is None:
            continue
        private = solution[-1]
        if _verify_scalar(private, public_key, ordered, cv):
            return private
    return None


@dataclass(frozen=True)
class Recovery:
    private: int
    method: str
    curve: str
    records: int


def recover_known_nonce(records: Sequence[SigRecord], nonce: int, public_key: Any,
                        curve: str | WeierstrassCurve = "secp256k1") -> Optional[int]:
    """Recover ``d`` from a leaked nonce ``k`` used by one of ``records`` (delegates to ``ecc_faults``).

    The first record whose ``r`` matches ``k*G`` (or ``-k*G``) yields ``d``; it is returned only if
    every supplied signature also re-verifies under ``d*G == Q``.
    """
    cv = resolve_curve(curve)
    if cv is None:
        return None
    for rec in records:
        found = recover_ecdsa_known_nonce(rec.rsz, nonce, public_key, cv)
        if found is not None and _verify_scalar(found, public_key, records, cv):
            return found
    return None


def recover_nonce_delta(records: Sequence[SigRecord], delta: int, public_key: Any,
                        curve: str | WeierstrassCurve = "secp256k1") -> Optional[int]:
    """Recover ``d`` when consecutive records (by index) satisfy ``k_{i+1} = k_i + delta``.

    Works from just two signatures (the linear solve needs three), because the delta is supplied.
    Delegates to ``ecc_faults.recover_ecdsa_nonce_delta``; every record must re-verify.
    """
    cv = resolve_curve(curve)
    if cv is None:
        return None
    ordered = sorted((rec for rec in records if rec.index is not None), key=lambda rec: rec.index)
    for left, right in zip(ordered, ordered[1:]):
        steps = right.index - left.index
        if steps <= 0:
            continue
        found = recover_ecdsa_nonce_delta(left.rsz, right.rsz, delta * steps, public_key, cv)
        if found is not None and _verify_scalar(found, public_key, records, cv):
            return found
    return None


def recover(records: Sequence[SigRecord], public_key: Any, *,
            curve: str | WeierstrassCurve = "secp256k1",
            max_degree: int = 3, known_nonce: int | None = None,
            nonce_delta: int | None = None) -> Optional[Recovery]:
    """Try repeated-nonce, a supplied known nonce, a supplied nonce delta, then index-linear nonce up
    to ``max_degree``.  Self-verified throughout."""
    cv = resolve_curve(curve)
    if cv is None:
        raise EcdsaReadError(f"unknown curve {curve!r}; known: {', '.join(sorted(CURVES))}")
    if public_key is None:
        raise EcdsaReadError("no public key: recovery is fail-closed and needs Q to verify d*G")
    reused = recover_reused_nonce(records, public_key, cv)
    if reused is not None:
        return Recovery(reused, "reused-nonce", cv.name, len(records))
    if known_nonce is not None:
        found = recover_known_nonce(records, known_nonce, public_key, cv)
        if found is not None:
            return Recovery(found, "known-nonce", cv.name, len(records))
    if nonce_delta is not None:
        found = recover_nonce_delta(records, nonce_delta, public_key, cv)
        if found is not None:
            return Recovery(found, "nonce-delta", cv.name, len(records))
    for degree in range(1, max_degree + 1):
        found = recover_ecdsa_linear_nonce(records, public_key, degree=degree, curve=cv)
        if found is not None:
            return Recovery(found, f"linear-nonce-degree-{degree}", cv.name, len(records))
    return None


# ---------------------------------------------------------------------------
# ECDSA signing (for challenge-response clients; see signing_protocol.py)


def ecdsa_sign(private: int, message: bytes, *, curve: str | WeierstrassCurve = "secp256r1",
               hash_name: str = "sha256", k: int | None = None,
               low_s: bool = True) -> tuple[int, int]:
    """Deterministic (RFC 6979) ECDSA signature of ``message``; ``k`` may be pinned for testing."""
    cv = resolve_curve(curve)
    if cv is None:
        raise EcdsaReadError(f"unknown curve {curve!r}")
    z = hash_z(message, cv, hash_name)
    n = cv.n
    while True:
        nonce = k if k is not None else _rfc6979_k(private, z, n, hash_name)
        point = ec_mul(nonce, None, cv)
        if point is None:
            if k is not None:
                raise EcdsaReadError("supplied k gives the point at infinity")
            z = (z + 1) % n
            continue
        r = point[0] % n
        if r == 0:
            if k is not None:
                raise EcdsaReadError("supplied k gives r == 0")
            z = (z + 1) % n
            continue
        s = (pow(nonce, -1, n) * (z + r * private)) % n
        if s == 0:
            if k is not None:
                raise EcdsaReadError("supplied k gives s == 0")
            z = (z + 1) % n
            continue
        if low_s and s > n // 2:
            s = n - s
        return r, s


def _rfc6979_k(private: int, z: int, n: int, hash_name: str) -> int:
    fn = _HASHES.get(hash_name.strip().lower(), hashlib.sha256)
    hlen = fn().digest_size
    qlen = n.bit_length()
    rlen = (qlen + 7) // 8

    def bits2int(data: bytes) -> int:
        value = int.from_bytes(data, "big")
        extra = len(data) * 8 - qlen
        return value >> extra if extra > 0 else value

    def int2octets(value: int) -> bytes:
        return value.to_bytes(rlen, "big")

    def bits2octets(data: bytes) -> bytes:
        return int2octets(bits2int(data) % n)

    import hmac

    x = private.to_bytes(rlen, "big")
    h1 = bits2octets(z.to_bytes((z.bit_length() + 7) // 8 or 1, "big"))
    v = b"\x01" * hlen
    key = b"\x00" * hlen
    key = hmac.new(key, v + b"\x00" + x + h1, fn).digest()
    v = hmac.new(key, v, fn).digest()
    key = hmac.new(key, v + b"\x01" + x + h1, fn).digest()
    v = hmac.new(key, v, fn).digest()
    while True:
        t = b""
        while len(t) < rlen:
            v = hmac.new(key, v, fn).digest()
            t += v
        candidate = bits2int(t)
        if 1 <= candidate < n:
            return candidate
        key = hmac.new(key, v + b"\x00", fn).digest()
        v = hmac.new(key, v, fn).digest()


# ---------------------------------------------------------------------------
# Engine entry


Artifact = tuple[str, list[SigRecord], Optional[tuple[int, int]], Optional[str]]


def _load_artifacts(challenge_dir: Path) -> list[Artifact]:
    """``(relative path, records, public point, declared curve name or None)`` per readable artifact."""
    out: list[Artifact] = []
    files_dir = challenge_dir / "files"
    roots = [files_dir] if files_dir.is_dir() else [challenge_dir]
    for root in roots:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
                continue
            suffix = path.suffix.lower()
            try:
                if suffix == ".json":
                    obj = json.loads(path.read_text(encoding="utf-8", errors="strict"))
                    records, point = read_json_records(obj)
                    if records:
                        out.append((str(path.relative_to(challenge_dir)), records, point,
                                    json_declared_curve(obj)))
                elif suffix in (".der", ".bin", ".crt", ".cer"):
                    data = path.read_bytes()
                    records, point = read_der_records(data)
                    if records:
                        out.append((str(path.relative_to(challenge_dir)), records, point,
                                    der_declared_curve(parse_der(data))))
            except (EcdsaReadError, ValueError, OSError):
                continue
    return out


def solve(challenge_dir, profile, **opts):
    """Contract entry: read JSON/DER signature exports, recover the ECDSA private scalar.

    Options: ``curve`` (name), ``max_degree`` (default 3), ``known_nonce`` / ``nonce_delta`` (int or
    hex string: a leaked nonce, or the step between consecutive nonces). The first attempt uses the
    ``curve`` option, else the curve the artifact declares (JSON ``signature_format.curve``, DER SPKI
    namedCurve OID), else secp256k1; with no ``curve`` option the other known curve is tried after.
    Logs need a declared layout and are handled by ``read_log_records`` from a driver, not
    auto-discovered here (documented gap).
    """
    from ctf.result import Cost, Evidence, SolverResult

    challenge_dir = Path(challenge_dir)
    engine_id = "common.ecdsa_recovery"
    curve_opt = opts.get("curve")
    if curve_opt is not None and resolve_curve(curve_opt) is None:
        return SolverResult(status="blocked", engine=engine_id,
                            notes=f"unknown curve option {curve_opt!r}; known: {', '.join(sorted(CURVES))}")
    max_degree = int(opts.get("max_degree", 3))
    nonce_kwargs: dict[str, int] = {}
    for key in ("known_nonce", "nonce_delta"):
        if opts.get(key) is not None:
            value = _as_int(opts[key])
            if value is None:
                return SolverResult(status="blocked", engine=engine_id,
                                    notes=f"option {key}={opts[key]!r} is not an integer (decimal or hex)")
            nonce_kwargs[key] = value

    artifacts = _load_artifacts(challenge_dir)
    if not artifacts:
        return SolverResult(status="none", engine=engine_id,
                            notes="no JSON or DER signature export with readable (r,s) records found")

    for rel, records, point, declared in artifacts:
        if point is None:
            continue
        if curve_opt is not None:
            first, source = resolve_curve(curve_opt).name, "option"
        elif declared is not None:
            first, source = declared, "declared by the artifact"
        else:
            first, source = SECP256K1.name, "default"
        if first != (declared or SECP256K1.name):
            # The artifact was read under its declared curve (or the secp256k1 default); re-read it
            # so z is reduced modulo the order of the curve actually being tried.
            records, point = _reread(challenge_dir, rel, first)
        rec = None
        if records and point is not None:
            try:
                rec = recover(records, point, curve=first, max_degree=max_degree, **nonce_kwargs)
            except EcdsaReadError:
                rec = None
        # If the first curve is a guess or a wrong declaration, try the other known 256-bit curve.
        if rec is None and curve_opt is None:
            for name in (SECP256R1.name, SECP256K1.name):
                if name == first:
                    continue
                recs2, pt2 = _reread(challenge_dir, rel, name)
                if recs2 and pt2 is not None:
                    try:
                        rec = recover(recs2, pt2, curve=name, max_degree=max_degree, **nonce_kwargs)
                    except EcdsaReadError:
                        rec = None
                    if rec is not None:
                        records, point, source = recs2, pt2, f"fallback after {first} failed"
                        break
        if rec is None:
            continue
        hex_d = f"{rec.private:064x}"
        ikm = rec.private.to_bytes((max(rec.private.bit_length(), 1) + 7) // 8, "big")
        evidence = [
            Evidence("match", f"recovered scalar d via {rec.method} on {rec.records} records; "
                              f"d*G equals the supplied public key", path=rel),
        ]
        notes = (f"d = {hex_d} ({rec.curve}, {rec.method}; curve source: {source}). "
                 f"Downstream candidates: scalar as 64-hex, I2OSP(d,32)="
                 f"{rec.private.to_bytes(32, 'big').hex() if rec.private < (1 << 256) else ikm.hex()}. "
                 "If the flag is the scalar, submit the 64-hex body; if a sealed blob accompanies it, "
                 "derive the key from the IKM per the challenge's note.")
        flags = _candidate_flags(hex_d, profile)
        status = "candidate" if flags else "unsure"
        return SolverResult(status=status, flags=tuple(flags), evidence=tuple(evidence),
                            engine=engine_id, notes=notes, cost=Cost())

    return SolverResult(status="none", engine=engine_id,
                        notes="read signature records but no reused/linear-nonce recovery verified "
                              "against the public key (needs another nonce relation, lattice bias "
                              "attack, or the live service)")


def _reread(challenge_dir: Path, rel: str, curve_name: str):
    path = challenge_dir / rel
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            obj = json.loads(path.read_text(encoding="utf-8"))
            return read_json_records(obj, curve=curve_name)
        return read_der_records(path.read_bytes(), curve=curve_name)
    except (EcdsaReadError, ValueError, OSError):
        return [], None


def _candidate_flags(hex_d: str, profile) -> list[str]:
    """When the event flag body admits a 64-hex token, offer ``PREFIX{<64hex>}`` as a candidate."""
    try:
        from ctf import flagfmt
        shape = flagfmt.for_profile(profile)
        prefixes = getattr(getattr(profile, "flag", None), "prefixes", None) or []
    except Exception:
        return []
    out: list[str] = []
    for prefix in prefixes:
        candidate = f"{prefix}{{{hex_d}}}"
        try:
            if shape.is_flag(candidate):
                out.append(candidate)
        except Exception:
            continue
    return out


def _main(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="ECDSA nonce-fault scalar recovery (B-027)")
    parser.add_argument("path", help="a JSON signature export or a DER signed-order bundle")
    parser.add_argument("--curve", default=None)
    parser.add_argument("--max-degree", type=int, default=3)
    args = parser.parse_args(argv)

    data_path = Path(args.path)
    raw = data_path.read_bytes()
    if data_path.suffix.lower() == ".json":
        obj = json.loads(raw.decode("utf-8"))
        records, point = read_json_records(obj, curve=args.curve)
        declared = json_declared_curve(obj)
    else:
        records, point = read_der_records(raw, curve=args.curve)
        declared = der_declared_curve(parse_der(raw))
    if point is None:
        print("no public key found in the artifact; recovery is fail-closed", flush=True)
        return 1
    rec = recover(records, point, curve=args.curve or declared or "secp256k1",
                  max_degree=args.max_degree)
    if rec is None:
        print(f"read {len(records)} records; no verified recovery", flush=True)
        return 1
    print(f"d = {rec.private:064x}  ({rec.method}, {rec.curve}, {rec.records} records)", flush=True)
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(_main(sys.argv[1:]))
