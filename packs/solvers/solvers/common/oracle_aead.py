"""Verified offline oracle, AEAD-misuse, and white-box helpers.

This r5c module is intentionally transport-free.  Oracle attacks receive bounded
callbacks and never open a socket.  More importantly, candidate generation is
kept separate from emission: a plaintext/key/forgery is returned only after it
reproduces the original public equation, every captured authenticator, or an
independent caller-supplied verification callback.  Multiple surviving
candidates are an ambiguity and return ``None``.

The expensive state machines and finite-field arithmetic are the repository's
already-tested :mod:`crypto_oracles` and :mod:`crypto_depth` implementations.
This module adds the strict evidence gates that are desirable before an answer
can leave the crypto lane.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Sequence

try:
    from . import crypto_depth as _depth
    from . import crypto_oracles as _oracles
    from . import modern_crypto as _modern
except ImportError:  # repository's standalone common-module convention
    import crypto_depth as _depth
    import crypto_oracles as _oracles
    from _shadowed import common_module
    _modern = common_module("modern_crypto")  # solvers/toolkits/modern_crypto.py wins a flat import


MAX_RECORDS = 64
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_SECRET_LENGTH_CANDIDATES = 4096
MAX_WHITEBOX_TRACES = 4096
MAX_WHITEBOX_KEYS = 65536


__all__ = [
    "NonceReuseFinding",
    "recover_rsa_parity_plaintext",
    "recover_bleichenbacher_plaintext",
    "recover_manger_plaintext",
    "recover_manger_oaep_plaintext",
    "recover_cbc_padding_plaintext",
    "forge_prefix_mac_length_extension",
    "forge_cbc_mac_variable_iv",
    "forge_cbc_mac_length_extension",
    "detect_nonce_reuse",
    "recover_gcm_nonce_reuse_key",
    "forge_gcm_nonce_reuse_tag",
    "recover_chacha20_poly1305_one_time_key",
    "forge_chacha20_poly1305_nonce_reuse_tag",
    "aes_sbox",
    "recover_whitebox_xor_sbox",
    "recover_whitebox_trace_key",
]


def _bool_result(callback: Callable, *args) -> bool:
    """Require an actual bool/0/1 rather than accepting arbitrary truthiness."""
    if not callable(callback):
        return False
    try:
        answer = callback(*args)
    except Exception:
        return False
    return isinstance(answer, bool) and answer or isinstance(answer, int) and answer == 1


def _bounded_bytes(value, name: str, *, exact: Optional[int] = None) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    if len(value) > MAX_TOTAL_BYTES:
        raise ValueError(f"{name} exceeds the byte cap")
    out = bytes(value)
    if exact is not None and len(out) != exact:
        raise ValueError(f"{name} must be exactly {exact} bytes")
    return out


def _bounded_items(values, limit: int):
    """Materialise at most ``limit`` items, including from infinite iterators."""
    try:
        iterator = iter(values)
    except TypeError:
        return None
    out = []
    for index, value in enumerate(iterator):
        if index >= limit:
            return None
        out.append(value)
    return out


def _tamper_tag(tag: bytes) -> Optional[bytes]:
    return bytes([tag[0] ^ 1]) + tag[1:] if tag else None


def _ciphertext_int(ciphertext: int | bytes, n: int) -> Optional[int]:
    if isinstance(ciphertext, bytes):
        value = int.from_bytes(ciphertext, "big")
    elif isinstance(ciphertext, int) and not isinstance(ciphertext, bool):
        value = ciphertext
    else:
        return None
    return value if isinstance(n, int) and 0 <= value < n else None


# -- RSA adaptive oracles ----------------------------------------------------

def recover_rsa_parity_plaintext(
    ciphertext: int | bytes,
    n: int,
    e: int,
    oracle: Callable[[object], bool],
    *,
    odd_is_true: bool = True,
    oracle_input: str = "bytes",
    max_queries: Optional[int] = None,
    verify: Optional[Callable[[int], bool]] = None,
) -> Optional[int]:
    """Recover one RSA plaintext through an LSB oracle, then prove it publicly.

    ``pow(m,e,n)==ciphertext`` is always required.  ``verify`` may impose an
    additional problem-specific format check; a rejection or malformed oracle
    answer declines instead of leaking an exception into an answer pipeline.
    """
    original = _ciphertext_int(ciphertext, n)
    if original is None or not isinstance(e, int) or e < 2:
        return None
    try:
        candidate = _oracles.rsa_parity_oracle_recover(
            ciphertext, n, e, oracle, odd_is_true=odd_is_true,
            oracle_input=oracle_input, max_queries=max_queries,
        )
    except Exception:
        return None
    if candidate is None or pow(candidate, e, n) != original:
        return None
    if verify is not None and not _bool_result(verify, candidate):
        return None
    return candidate


def recover_bleichenbacher_plaintext(
    ciphertext: int | bytes,
    n: int,
    e: int,
    oracle: Callable[[object], bool],
    *,
    oracle_input: str = "bytes",
    max_queries: int = 2_000_000,
    verify: Optional[Callable[[bytes], bool]] = None,
) -> Optional[bytes]:
    """Recover and strictly decode PKCS#1-v1.5 encryption-oracle plaintext."""
    original = _ciphertext_int(ciphertext, n)
    if original is None or not isinstance(e, int) or e < 2:
        return None
    try:
        encoded = _oracles.bleichenbacher_pkcs1_v1_5_recover(
            ciphertext, n, e, oracle, oracle_input=oracle_input,
            max_queries=max_queries,
        )
    except Exception:
        return None
    if encoded is None or pow(int.from_bytes(encoded, "big"), e, n) != original:
        return None
    plaintext = _oracles.decode_pkcs1_v1_5(encoded)
    if plaintext is None:
        return None
    if verify is not None and not _bool_result(verify, plaintext):
        return None
    return plaintext


def recover_manger_plaintext(
    ciphertext: int | bytes,
    n: int,
    e: int,
    oracle: Callable[[object], bool],
    *,
    oracle_input: str = "bytes",
    max_queries: int = 100_000,
    decoder: Optional[Callable[[bytes], Optional[bytes]]] = None,
    verify: Optional[Callable[[bytes], bool]] = None,
) -> Optional[bytes]:
    """Recover a Manger threshold-oracle block and verify its chosen structure.

    A decoder is mandatory: returning an unstructured RSA integer would be
    weaker evidence than the original problem.  The decoder must deterministically
    return bytes or ``None``.  :func:`recover_manger_oaep_plaintext` supplies the
    strict OAEP decoder.
    """
    original = _ciphertext_int(ciphertext, n)
    if original is None or not callable(decoder) or not isinstance(e, int) or e < 2:
        return None
    try:
        value = _oracles.manger_leading_zero_recover(
            ciphertext, n, e, oracle, oracle_input=oracle_input,
            max_queries=max_queries,
        )
    except Exception:
        return None
    if value is None or pow(value, e, n) != original:
        return None
    size = (n.bit_length() + 7) // 8
    try:
        plaintext = decoder(value.to_bytes(size, "big"))
    except Exception:
        return None
    if not isinstance(plaintext, bytes):
        return None
    if verify is not None and not _bool_result(verify, plaintext):
        return None
    return plaintext


def recover_manger_oaep_plaintext(
    ciphertext: int | bytes,
    n: int,
    e: int,
    oracle: Callable[[object], bool],
    *,
    label: bytes = b"",
    hash_name: str = "sha1",
    oracle_input: str = "bytes",
    max_queries: int = 100_000,
    verify: Optional[Callable[[bytes], bool]] = None,
) -> Optional[bytes]:
    """Manger recovery with strict OAEP label-hash and delimiter validation."""
    if not isinstance(label, bytes):
        return None
    return recover_manger_plaintext(
        ciphertext, n, e, oracle, oracle_input=oracle_input,
        max_queries=max_queries,
        decoder=lambda block: _oracles.oaep_decode(
            block, label=label, hash_name=hash_name
        ),
        verify=verify,
    )


# -- padding and MAC oracles -------------------------------------------------

def recover_cbc_padding_plaintext(
    ciphertext: bytes,
    oracle: Callable[[bytes], bool],
    verify: Callable[[bytes], bool],
    *,
    iv: Optional[bytes] = None,
    block_size: int = 16,
    strip_padding: bool = True,
    max_queries: int = 1_000_000,
) -> Optional[bytes]:
    """CBC padding-oracle recovery gated by an independent plaintext check."""
    try:
        candidate = _oracles.cbc_padding_oracle_decrypt(
            ciphertext, oracle, iv=iv, block_size=block_size,
            strip_padding=strip_padding, max_queries=max_queries,
        )
    except Exception:
        return None
    return candidate if _bool_result(verify, candidate) else None


def forge_prefix_mac_length_extension(
    algorithm: str,
    original_digest: bytes | str,
    original_message: bytes,
    append: bytes,
    secret_lengths: Iterable[int],
    verify: Callable[[bytes, bytes], bool],
) -> Optional[tuple[bytes, bytes, int]]:
    """Find the unique verifier-accepted Merkle--Damgard prefix-MAC forgery.

    This is an oracle helper, not a guess emitter: every proposed secret length
    is locally constructed, but the result is returned only when exactly one is
    accepted by ``verify(message, digest_bytes)``.
    """
    try:
        message = _bounded_bytes(original_message, "original_message")
        extra = _bounded_bytes(append, "append")
        lengths = _bounded_items(secret_lengths, MAX_SECRET_LENGTH_CANDIDATES)
    except (TypeError, ValueError):
        return None
    if not lengths or len(message) + len(extra) > MAX_TOTAL_BYTES:
        return None
    if any(isinstance(x, bool) or not isinstance(x, int) or x < 0 for x in lengths):
        return None
    try:
        supplied_digest = (bytes.fromhex(original_digest.strip())
                           if isinstance(original_digest, str)
                           else bytes(original_digest))
    except (TypeError, ValueError):
        return None
    negative_control = _tamper_tag(supplied_digest)
    if (negative_control is None
            or not _bool_result(verify, message, supplied_digest)
            or _bool_result(verify, message, negative_control)):
        return None
    accepted: set[tuple[bytes, bytes, int]] = set()
    for secret_length in sorted(set(lengths)):
        try:
            forged_message, digest_hex = _modern.length_extension(
                algorithm, original_digest, message, extra, secret_length
            )
            digest = bytes.fromhex(digest_hex)
        except (TypeError, ValueError):
            return None
        if _bool_result(verify, forged_message, digest):
            accepted.add((forged_message, digest, secret_length))
    return next(iter(accepted)) if len(accepted) == 1 else None


def forge_cbc_mac_variable_iv(
    original_message: bytes,
    original_iv: bytes,
    original_tag: bytes,
    target_message: bytes,
    verify: Callable[[bytes, bytes, bytes], bool],
    *,
    block_size: int = 16,
) -> Optional[tuple[bytes, bytes]]:
    """Forge CBC-MAC when the IV is attacker-controlled.

    The messages must differ only in their first block; changing the IV by the
    same XOR delta makes the block-cipher input (and therefore the full chain)
    identical.  Acceptance is still required before ``(forged_iv, tag)`` is
    emitted.
    """
    try:
        old = _bounded_bytes(original_message, "original_message")
        new = _bounded_bytes(target_message, "target_message")
        iv = _bounded_bytes(original_iv, "original_iv", exact=block_size)
        tag = _bounded_bytes(original_tag, "original_tag", exact=block_size)
    except (TypeError, ValueError):
        return None
    if block_size < 2 or len(old) < block_size or len(old) != len(new):
        return None
    if len(old) % block_size or old[block_size:] != new[block_size:]:
        return None
    negative_control = _tamper_tag(tag)
    if (negative_control is None
            or not _bool_result(verify, old, iv, tag)
            or _bool_result(verify, old, iv, negative_control)):
        return None
    forged_iv = bytes(a ^ b ^ c for a, b, c in zip(iv, old[:block_size], new[:block_size]))
    return (forged_iv, tag) if _bool_result(verify, new, forged_iv, tag) else None


def forge_cbc_mac_length_extension(
    original_message: bytes,
    original_tag: bytes,
    extension: bytes,
    extension_tag: bytes,
    verify: Callable[[bytes, bytes], bool],
    *,
    block_size: int = 16,
) -> Optional[tuple[bytes, bytes]]:
    """Forge raw, zero-IV CBC-MAC from MAC(M) and MAC(extension).

    All inputs are block aligned and unpadded.  The bridge block is
    ``extension[0] XOR MAC(M)``; the remainder follows unchanged, making the
    forged chain end at ``MAC(extension)``.  A verifier must accept it.
    """
    try:
        message = _bounded_bytes(original_message, "original_message")
        tag = _bounded_bytes(original_tag, "original_tag", exact=block_size)
        extra = _bounded_bytes(extension, "extension")
        extra_tag = _bounded_bytes(extension_tag, "extension_tag", exact=block_size)
    except (TypeError, ValueError):
        return None
    if block_size < 2 or not message or not extra:
        return None
    if len(message) % block_size or len(extra) % block_size:
        return None
    if len(message) + len(extra) > MAX_TOTAL_BYTES:
        return None
    negative_control = _tamper_tag(tag)
    if (negative_control is None
            or not _bool_result(verify, message, tag)
            or not _bool_result(verify, extra, extra_tag)
            or _bool_result(verify, message, negative_control)):
        return None
    bridge = bytes(a ^ b for a, b in zip(extra[:block_size], tag))
    forged = message + bridge + extra[block_size:]
    return (forged, extra_tag) if _bool_result(verify, forged, extra_tag) else None


# -- AEAD nonce reuse --------------------------------------------------------

@dataclass(frozen=True)
class NonceReuseFinding:
    algorithm: str
    key_id: str
    nonce: bytes
    record_indices: tuple[int, ...]


def detect_nonce_reuse(records: Iterable[dict]) -> Optional[tuple[NonceReuseFinding, ...]]:
    """Inventory exact nonce reuse without conflating unknown/different keys.

    Every record must carry an explicit nonempty ``algorithm``, ``key_id``, and
    byte-string ``nonce``.  Missing key identity is ambiguous and declines.
    """
    try:
        items = _bounded_items(records, MAX_RECORDS)
    except Exception:
        return None
    if not items:
        return None
    groups: dict[tuple[str, str, bytes], list[int]] = {}
    total = 0
    for index, record in enumerate(items):
        if not isinstance(record, dict):
            return None
        algorithm, key_id, nonce = record.get("algorithm"), record.get("key_id"), record.get("nonce")
        if not isinstance(algorithm, str) or not algorithm.strip():
            return None
        if not isinstance(key_id, str) or not key_id.strip():
            return None
        try:
            nonce_b = _bounded_bytes(nonce, "nonce")
        except (TypeError, ValueError):
            return None
        if not nonce_b:
            return None
        total += len(nonce_b)
        if total > MAX_TOTAL_BYTES:
            return None
        groups.setdefault((algorithm.strip().lower(), key_id, nonce_b), []).append(index)
    findings = [
        NonceReuseFinding(algorithm, key_id, nonce, tuple(indices))
        for (algorithm, key_id, nonce), indices in groups.items() if len(indices) >= 2
    ]
    return tuple(sorted(findings, key=lambda f: (f.algorithm, f.key_id, f.nonce)))


def _normalise_aead_observations(observations) -> Optional[list[tuple[bytes, bytes, bytes]]]:
    try:
        items = _bounded_items(observations, MAX_RECORDS)
    except Exception:
        return None
    if items is None or not 2 <= len(items):
        return None
    out = []
    total = 0
    for item in items:
        try:
            aad, ciphertext, tag = item
            aad = _bounded_bytes(aad, "aad")
            ciphertext = _bounded_bytes(ciphertext, "ciphertext")
            tag = _bounded_bytes(tag, "tag", exact=16)
        except (TypeError, ValueError):
            return None
        total += len(aad) + len(ciphertext) + len(tag)
        if total > MAX_TOTAL_BYTES:
            return None
        out.append((aad, ciphertext, tag))
    return out


def recover_gcm_nonce_reuse_key(observations) -> Optional[tuple[int, int]]:
    """Return unique ``(GHASH H, E_K(J0))`` only after every tag reproduces."""
    triples = _normalise_aead_observations(observations)
    if triples is None:
        return None
    try:
        candidates = set(_depth.gcm_recover_subkey(triples))
    except (TypeError, ValueError, ArithmeticError):
        return None
    proven = {
        (h, mask) for h, mask in candidates
        if all(_depth.gcm_tag(h, mask, aad, ciphertext) == tag
               for aad, ciphertext, tag in triples)
    }
    return next(iter(proven)) if len(proven) == 1 else None


def forge_gcm_nonce_reuse_tag(
    observations,
    target_aad: bytes,
    target_ciphertext: bytes,
    verify: Callable[[bytes, bytes, bytes], bool],
) -> Optional[bytes]:
    """Forge a GCM tag from unique recovered state and require acceptance."""
    triples = _normalise_aead_observations(observations)
    if triples is None:
        return None
    state = recover_gcm_nonce_reuse_key(triples)
    if state is None:
        return None
    try:
        aad = _bounded_bytes(target_aad, "target_aad")
        ciphertext = _bounded_bytes(target_ciphertext, "target_ciphertext")
        tag = _depth.gcm_forge_tag(state[0], state[1], aad, ciphertext)
    except (TypeError, ValueError, ArithmeticError):
        return None
    control = _tamper_tag(triples[0][2])
    if (control is None
            or not _bool_result(verify, *triples[0])
            or _bool_result(verify, triples[0][0], triples[0][1], control)):
        return None
    return tag if _bool_result(verify, aad, ciphertext, tag) else None


def recover_chacha20_poly1305_one_time_key(
    observations, *, max_carry: int = 4, max_degree: int = 2
) -> Optional[tuple[int, int]]:
    """Return a unique Poly1305 ``(r,s)`` reproducing every captured tag."""
    triples = _normalise_aead_observations(observations)
    if triples is None:
        return None
    try:
        candidates = set(_depth.recover_chacha20_poly1305_nonce_reuse(
            triples, max_carry=max_carry, max_degree=max_degree
        ))
    except (TypeError, ValueError, ArithmeticError):
        return None
    proven = {
        (r, s) for r, s in candidates
        if all(_depth.chacha20_poly1305_forge_tag(r, s, aad, ciphertext) == tag
               for aad, ciphertext, tag in triples)
    }
    return next(iter(proven)) if len(proven) == 1 else None


def forge_chacha20_poly1305_nonce_reuse_tag(
    observations,
    target_aad: bytes,
    target_ciphertext: bytes,
    verify: Callable[[bytes, bytes, bytes], bool],
    *,
    max_carry: int = 4,
    max_degree: int = 2,
) -> Optional[bytes]:
    """Forge a Poly1305 tag from unique recovered state and require acceptance."""
    triples = _normalise_aead_observations(observations)
    if triples is None:
        return None
    state = recover_chacha20_poly1305_one_time_key(
        triples, max_carry=max_carry, max_degree=max_degree
    )
    if state is None:
        return None
    try:
        aad = _bounded_bytes(target_aad, "target_aad")
        ciphertext = _bounded_bytes(target_ciphertext, "target_ciphertext")
        tag = _depth.chacha20_poly1305_forge_tag(state[0], state[1], aad, ciphertext)
    except (TypeError, ValueError, ArithmeticError):
        return None
    control = _tamper_tag(triples[0][2])
    if (control is None
            or not _bool_result(verify, *triples[0])
            or _bool_result(verify, triples[0][0], triples[0][1], control)):
        return None
    return tag if _bool_result(verify, aad, ciphertext, tag) else None


# -- exact white-box analyses ------------------------------------------------

def _aes_gf_mul(a: int, b: int) -> int:
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return out


def aes_sbox(value: int) -> int:
    """Algorithmic AES S-box, useful as an independently inspectable model."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 256:
        raise ValueError("AES S-box input must be a byte")
    if value == 0:
        inverse = 0
    else:
        inverse = 1
        exponent = 254
        base = value
        while exponent:
            if exponent & 1:
                inverse = _aes_gf_mul(inverse, base)
            base = _aes_gf_mul(base, base)
            exponent >>= 1
    result = inverse
    for shift in (1, 2, 3, 4):
        result ^= ((inverse << shift) | (inverse >> (8 - shift))) & 0xFF
    return result ^ 0x63


def recover_whitebox_xor_sbox(
    table: Sequence[int],
    *,
    sbox: Optional[Sequence[int]] = None,
    known_pairs: Iterable[tuple[int, int]] = (),
) -> Optional[tuple[int, int]]:
    """Recover a unique ``(input_key_xor, output_mask)`` from a 256-byte table.

    The exact model is ``table[x] == sbox[x XOR key] XOR mask``.  Every one of
    the 256 entries and every supplied known I/O pair is rechecked.  Symmetric
    tables with multiple explanations decline.
    """
    try:
        observed_items = _bounded_items(table, 256)
        model_items = (list(aes_sbox(x) for x in range(256)) if sbox is None
                       else _bounded_items(sbox, 256))
        pair_items = _bounded_items(known_pairs, MAX_WHITEBOX_TRACES)
    except Exception:
        return None
    if observed_items is None or model_items is None or pair_items is None:
        return None
    if len(observed_items) != 256 or len(model_items) != 256:
        return None
    if (any(isinstance(x, bool) or not isinstance(x, int) for x in observed_items + model_items)
            or any(not isinstance(pair, (tuple, list)) or len(pair) != 2
                   or any(isinstance(x, bool) or not isinstance(x, int) for x in pair)
                   for pair in pair_items)):
        return None
    observed, model = tuple(observed_items), tuple(model_items)
    pairs = tuple((pair[0], pair[1]) for pair in pair_items)
    if any(not 0 <= x < 256 for x in observed + model):
        return None
    if any(not (0 <= x < 256 and 0 <= y < 256) for x, y in pairs):
        return None
    candidates = set()
    for key in range(256):
        mask = observed[0] ^ model[key]
        if all(observed[x] == (model[x ^ key] ^ mask) for x in range(256)):
            if all(observed[x] == y for x, y in pairs):
                candidates.add((key, mask))
    return next(iter(candidates)) if len(candidates) == 1 else None


def recover_whitebox_trace_key(
    traces: Iterable[tuple[int, int]],
    model: Callable[[int, int], int],
    *,
    key_candidates: Iterable[int] = range(256),
) -> Optional[int]:
    """Exact, bounded key recovery from noiseless white-box leakage traces.

    ``model(input_value, candidate_key)`` must reproduce the observed integer
    leakage.  All traces must agree and exactly one candidate must survive.
    No statistical ranking is silently converted into a key.
    """
    if not callable(model):
        return None
    try:
        trace_items = _bounded_items(traces, MAX_WHITEBOX_TRACES)
        candidate_items = _bounded_items(key_candidates, MAX_WHITEBOX_KEYS)
    except Exception:
        return None
    if trace_items is None or candidate_items is None:
        return None
    if (any(not isinstance(pair, (tuple, list)) or len(pair) != 2
            or any(isinstance(x, bool) or not isinstance(x, int) for x in pair)
            for pair in trace_items)
            or any(isinstance(key, bool) or not isinstance(key, int)
                   for key in candidate_items)):
        return None
    observations = tuple((pair[0], pair[1]) for pair in trace_items)
    candidates = tuple(candidate_items)
    if not observations:
        return None
    if not candidates or len(set(candidates)) != len(candidates):
        return None
    proven = set()
    for key in candidates:
        try:
            if all(model(value, key) == leakage for value, leakage in observations):
                proven.add(key)
        except Exception:
            return None
    return next(iter(proven)) if len(proven) == 1 else None
