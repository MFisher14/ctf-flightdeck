"""B-059 round-1 fixes: S+kL ceiling, canonicalising an observed S+kL
signature, ref10 top-bits model, caller-error validation, and the web half
(dual-key payload carrying canonical vs malleable signatures)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "common"))
sys.path.insert(0, str(ROOT / "solvers" / "web"))

import ecc_faults as ecc  # noqa: E402
import parser_differential as P  # noqa: E402

L = ecc.ED25519_L


def _scalar_from_seed(seed: bytes) -> int:
    expanded = bytearray(hashlib.sha512(seed).digest()[:32])
    expanded[0] &= 248
    expanded[31] &= 63
    expanded[31] |= 64
    return int.from_bytes(expanded, "little") % L


def _sign(private: int, public: bytes, nonce: int, message: bytes) -> bytes:
    encoded_r = ecc.ed25519_public_from_scalar(nonce)
    assert encoded_r is not None
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % L
    return encoded_r + ((nonce + challenge * private) % L).to_bytes(32, "little")


def _with_s(signature: bytes, scalar_s: int) -> bytes:
    return signature[:32] + scalar_s.to_bytes(32, "little")


@pytest.fixture(scope="module")
def signed():
    seed = bytes(range(3, 35))
    private = _scalar_from_seed(seed)
    public = ecc.ed25519_public_from_scalar(private)
    assert public is not None
    message = b"landfall grant G-0001"
    signature = _sign(private, public, 0xC0FFEE1234, message)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    library_public = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    library_public.verify(signature, message)  # canonical base, library-proven
    return signature, message, public, library_public


def _library_rejects(library_public, signature: bytes, message: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        library_public.verify(signature, message)
    except InvalidSignature:
        return True
    return False


# --- 2**256 ceiling -----------------------------------------------------------


def test_count_beyond_encoding_ceiling_stops_at_last_fitting_k(signed):
    signature, message, public, _lib = signed
    base_s = int.from_bytes(signature[32:], "little")
    variants = ecc.ed25519_malleable_signatures(signature, count=20)
    expected_max_k = (ecc.ED25519_S_ENCODING_BOUND - 1 - base_s) // L
    assert expected_max_k == 15  # this fixture's S is below 2**256 - 1 - 15L
    assert len(variants) == expected_max_k < 20
    assert [v.k for v in variants] == list(range(1, expected_max_k + 1))
    last = variants[-1]
    assert last.scalar_s < 2**256
    assert last.scalar_s + L >= 2**256  # the next k would not fit 32 bytes
    assert len(last.signature) == 64
    assert int.from_bytes(last.signature[32:], "little") == last.scalar_s
    # Even the highest variant is still a valid lax signature.
    assert ecc.ed25519_verify_lax(last.signature, message, public)
    # A larger count cannot go past the ceiling.
    assert ecc.ed25519_malleable_signatures(signature, count=100) == variants


def test_ceiling_is_fourteen_when_s_is_near_l(signed):
    """The largest k is (2**256 - 1 - S) // L: 15 or 14, never 16.

    Crafted S values (no verification needed for the count): the switch from
    15 to 14 sits exactly at S = 2**256 - 1 - 15L, which is below L.
    """
    signature = signed[0]
    threshold = ecc.ED25519_S_ENCODING_BOUND - 1 - 15 * L
    assert 0 < threshold < L
    at_threshold = ecc.ed25519_malleable_signatures(_with_s(signature, threshold), count=100)
    assert [v.k for v in at_threshold] == list(range(1, 16))
    for near_l in (threshold + 1, L - 1):
        variants = ecc.ed25519_malleable_signatures(_with_s(signature, near_l), count=100)
        assert [v.k for v in variants] == list(range(1, 15))
        assert variants[-1].scalar_s < 2**256 <= variants[-1].scalar_s + L
    # S = 0 is the smallest S and still gives 15, not 16.
    assert len(ecc.ed25519_malleable_signatures(_with_s(signature, 0), count=100)) == 15
    # canonicalize=True skips the observed k, so one fewer: 13 for S near L.
    observed = _with_s(signature, (L - 1) + 3 * L)
    skipped = ecc.ed25519_malleable_signatures(observed, count=100, canonicalize=True)
    assert [v.k for v in skipped] == [1, 2] + list(range(4, 15))


# --- canonicalising an observed S+kL signature ---------------------------------


def test_canonicalize_helper_reports_observed_k(signed):
    signature, _message, _public, _lib = signed
    base_s = int.from_bytes(signature[32:], "little")
    assert ecc.ed25519_canonicalize_signature(signature) == (signature, 0)
    for k in (1, 2, 5):
        observed = _with_s(signature, base_s + k * L)
        assert ecc.ed25519_canonicalize_signature(observed) == (signature, k)
    # Malformed input (wrong length, non-canonical R) gives None.
    assert ecc.ed25519_canonicalize_signature(signature[:63]) is None
    bad_r = (2**255 - 19 + 1).to_bytes(32, "little")  # y >= p: non-canonical R
    assert ecc.ed25519_canonicalize_signature(bad_r + signature[32:]) is None


def test_observed_noncanonical_signature_yields_unseen_variants(signed):
    signature, message, public, lib = signed
    base_s = int.from_bytes(signature[32:], "little")
    observed = _with_s(signature, base_s + L)  # what the audit ledger showed

    # Default: refused (the input is already S+kL) ...
    assert ecc.ed25519_malleable_signatures(observed) == []
    # ... canonicalize=True reduces it and skips the observed k=1.
    variants = ecc.ed25519_malleable_signatures(
        observed, count=2, canonicalize=True, public_key=public, message=message
    )
    assert [v.k for v in variants] == [2, 3]
    for v in variants:
        assert v.signature != observed and v.signature != signature
        assert v.scalar_s == base_s + v.k * L
        assert ecc.ed25519_verify_lax(v.signature, message, public)
        assert not ecc.ed25519_verify(v.signature, message, public)
        assert _library_rejects(lib, v.signature, message)

    # Observed k=2 skips 2 and fills from 1 and 3.
    observed2 = _with_s(signature, base_s + 2 * L)
    assert [v.k for v in ecc.ed25519_malleable_signatures(observed2, count=2, canonicalize=True)] == [1, 3]
    # A canonical input with canonicalize=True behaves like the default.
    assert ecc.ed25519_malleable_signatures(signature, count=2, canonicalize=True) == (
        ecc.ed25519_malleable_signatures(signature, count=2)
    )
    # The proof check runs on the reduced form: a wrong message still fails closed.
    assert (
        ecc.ed25519_malleable_signatures(
            observed, canonicalize=True, public_key=public, message=b"other"
        )
        == []
    )
    # Bad R is refused under canonicalize too.
    bad_r = (2**255 - 19 + 1).to_bytes(32, "little")
    assert ecc.ed25519_malleable_signatures(bad_r + observed[32:], canonicalize=True) == []


# --- ref10 / libsodium-compat top-bits model ----------------------------------


def test_ref10_top_bits_mode_accepts_only_s_plus_l(signed):
    signature, message, public, _lib = signed
    base_s = int.from_bytes(signature[32:], "little")
    assert base_s + L < 2**253  # this fixture's S+L clears the ref10 bound
    v1, v2 = ecc.ed25519_malleable_signatures(signature, count=2)
    assert v1.ref10_compatible is True
    assert v2.ref10_compatible is False  # 2L > 2**253 always
    assert ecc.ed25519_verify_lax(signature, message, public, ref10_top_bits=True)
    assert ecc.ed25519_verify_lax(v1.signature, message, public, ref10_top_bits=True)
    assert not ecc.ed25519_verify_lax(v2.signature, message, public, ref10_top_bits=True)
    # The default lax model has no top-bits check and accepts S+2L.
    assert ecc.ed25519_verify_lax(v2.signature, message, public)


def test_ref10_compatible_boundary_is_two_to_the_253():
    below = ecc.Ed25519MalleableSignature(k=1, scalar_s=2**253 - 1, signature=b"")
    at = ecc.Ed25519MalleableSignature(k=1, scalar_s=2**253, signature=b"")
    assert below.ref10_compatible is True
    assert at.ref10_compatible is False
    assert ecc.ED25519_REF10_S_BOUND == 2**253


def test_verify_lax_ref10_rejects_top_bits_before_the_equation(signed, monkeypatch):
    """S in [2**253, 2L) is refused by the sig[63] & 224 gate itself.

    No natural S+L lands in that window (S would need to be within ~2**125 of
    L), so the gate is shown by crafted scalars and by whether the challenge
    hash (the first step of the group equation) is ever reached.
    """
    signature, message, public, _lib = signed
    calls = []
    real_challenge = ecc._ed_challenge

    def recording_challenge(*args):
        calls.append(args)
        return real_challenge(*args)

    monkeypatch.setattr(ecc, "_ed_challenge", recording_challenge)
    assert 2**253 < 2 * L
    for top in (2**253, 2**253 + 1, 2 * L - 1):
        calls.clear()
        crafted = _with_s(signature, top)
        assert ecc.ed25519_verify_lax(crafted, message, public, ref10_top_bits=True) is False
        assert calls == [], f"S={top:#x} reached the group equation"
        # Without the gate the same input does reach the equation.
        assert ecc.ed25519_verify_lax(crafted, message, public) is False
        assert len(calls) == 1
    # Just below the bound passes the gate and is decided by the equation.
    calls.clear()
    assert ecc.ed25519_verify_lax(_with_s(signature, 2**253 - 1), message, public, ref10_top_bits=True) is False
    assert len(calls) == 1


# --- caller errors raise, not silently degrade ---------------------------------


def test_half_given_proof_pair_raises(signed):
    signature, message, public, _lib = signed
    with pytest.raises(ValueError, match="together"):
        ecc.ed25519_malleable_signatures(signature, public_key=b"x" * 32)
    with pytest.raises(ValueError, match="together"):
        ecc.ed25519_malleable_signatures(signature, message=message)
    # Both given (valid) and both omitted are fine.
    assert len(ecc.ed25519_malleable_signatures(signature, public_key=public, message=message)) == 2
    assert len(ecc.ed25519_malleable_signatures(signature)) == 2


@pytest.mark.parametrize("bad", [0, -1, True, False, 1.5, "2", None])
def test_bad_count_raises(signed, bad):
    signature = signed[0]
    with pytest.raises(ValueError, match="count"):
        ecc.ed25519_malleable_signatures(signature, count=bad)


def test_count_one_emits_exactly_s_plus_l(signed):
    signature = signed[0]
    (only,) = ecc.ed25519_malleable_signatures(signature, count=1)
    assert only.k == 1


# --- web half: dual-key body carrying canonical vs malleable signatures --------


def test_dual_key_payload_routes_canonical_and_malleable_signatures(signed):
    """Compose B-021's case_variant_body with the S+kL generator (offline).

    Landfall shape: a case-insensitive gateway that strictly verifies the
    capitalised ``Sig`` and an exact-key downstream that laxly verifies ``sig``.
    The body must carry two distinct signatures under case-variant keys, each
    valid for exactly its reader's verifier.
    """

    signature, message, public, _lib = signed
    canonical, observed_k = ecc.ed25519_canonicalize_signature(signature)
    assert observed_k == 0
    malleable = ecc.ed25519_malleable_signatures(
        signature, count=2, public_key=public, message=message
    )[-1]
    body = P.case_variant_body(
        {"operation": "dispatch", "sig": malleable.signature.hex()},
        {"operation": "cancel", "sig": canonical.hex()},
        shadow_case="title",
    )
    findings = P.detect_duplicate_case_keys(body)
    assert {tuple(f["keys"]) for f in findings} == {("operation", "Operation"), ("sig", "Sig")}
    assert all(f["kind"] == "case-variant" for f in findings)

    # Exact-key downstream reads the lowercase keys.
    exact = json.loads(body)
    downstream_sig = bytes.fromhex(exact["sig"])
    assert exact["operation"] == "dispatch"
    assert downstream_sig == malleable.signature
    assert ecc.ed25519_verify_lax(downstream_sig, message, public)
    assert not ecc.ed25519_verify(downstream_sig, message, public)

    # Case-insensitive last-wins gateway resolves to the capitalised (shadow) keys.
    folded: dict[str, str] = {}
    for key, value in json.loads(body, object_pairs_hook=list):
        folded[key.casefold()] = value
    gateway_sig = bytes.fromhex(folded["sig"])
    assert folded["operation"] == "cancel"
    assert gateway_sig == canonical != downstream_sig
    assert ecc.ed25519_verify(gateway_sig, message, public)
