"""The ECDSA recovery engine (B-027) routes on signature nonce reuse, not on AEAD nonce reuse.

Merging B-027 into the master first gave it a bare "nonce reuse" keyword at priority 64: every
"ChaCha20-Poly1305 nonce reuse" or "GCM nonce reuse" brief then fronted ecdsa_recovery ahead of
crypto_depth, the engine that actually forges those. These pin the narrowed keywords both ways."""
from __future__ import annotations

import pytest

from ctf import triage

ECDSA = "solvers/common/ecdsa_recovery.py"
AEAD = "solvers/common/crypto_depth.py"


@pytest.mark.parametrize("brief", [
    "ChaCha20-Poly1305 nonce reuse",
    "AES-GCM nonce reuse lets you forge a tag",
    "XChaCha nonce reuse on the session cipher",
])
def test_an_aead_nonce_reuse_brief_does_not_suggest_the_ecdsa_engine(brief):
    assert ECDSA not in triage.suggest("crypto", brief)["engines"]


def test_poly1305_nonce_reuse_fronts_crypto_depth():
    assert triage.suggest("crypto", "Poly1305 nonce reuse")["engines"][0] == AEAD


@pytest.mark.parametrize("brief", [
    "signature nonce reuse in the signing service",
    "the DSA nonce reuse leaks the key",
    "two signatures share a reused nonce",
    "ECDSA with nonce reuse",
])
def test_a_signature_nonce_reuse_brief_fronts_the_ecdsa_engine(brief):
    assert triage.suggest("crypto", brief)["engines"][0] == ECDSA
