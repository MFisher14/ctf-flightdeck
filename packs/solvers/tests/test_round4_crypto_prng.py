"""Round-4 exact-proof fixtures for deeper crypto and PRNG recovery."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

from Crypto.Cipher import AES, ChaCha20_Poly1305


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
import crypto_depth as cd  # noqa: E402
import ecc_weak as ecc  # noqa: E402
import lattice_tools as lattice  # noqa: E402
import modern_crypto as mc  # noqa: E402
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import prng_recovery as prng_cli  # noqa: E402


def _chacha(key, nonce, aad, plaintext):
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(aad)
    return cipher.encrypt_and_digest(plaintext)


def test_general_degree_poly1305_nonce_reuse_recovers_quintic_key():
    key = bytes(reversed(range(32)))
    nonce = bytes(range(12, 24))
    aad = b"same-aad"
    observations = []
    for plaintext in (b"A" * 64, b"B" * 64):
        ciphertext, tag = _chacha(key, nonce, aad, plaintext)
        observations.append((aad, ciphertext, tag))

    # Compatibility mode still declines; the general finite-field factorizer
    # finds and verifies the degree-five equation.
    assert cd.recover_chacha20_poly1305_nonce_reuse(observations) == []
    candidates = cd.recover_chacha20_poly1305_nonce_reuse(observations, max_degree=8)
    assert len(candidates) == 1
    r, s = candidates[0]
    assert all(cd.chacha20_poly1305_forge_tag(r, s, a, c) == tag
               for a, c, tag in observations)


def test_gcm_two_pair_recovery_needs_no_presupplied_h_and_contains_true_key(tmp_path, capsys):
    key = bytes(range(16))
    nonce = bytes(range(12))
    pairs = []
    for aad, plaintext in ((b"a", b"first body"), (b"different", b"second body longer")):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        pairs.append((aad, ciphertext, tag))
    true_h = int.from_bytes(AES.new(key, AES.MODE_ECB).encrypt(bytes(16)), "big")
    candidates = cd.gcm_recover_subkey(pairs)
    matching = [(h, mask) for h, mask in candidates if h == true_h]
    assert len(matching) == 1
    h, mask = matching[0]
    assert all(cd.gcm_tag(h, mask, aad, ciphertext) == tag
               for aad, ciphertext, tag in pairs)

    fixture = tmp_path / "gcm-reuse.json"
    fixture.write_text(json.dumps({"observations": [
        {"aad": aad.hex(), "ciphertext": ciphertext.hex(), "tag": tag.hex()}
        for aad, ciphertext, tag in pairs
    ]}))
    assert cd.main(["gcm-recover", str(fixture), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert true_h.to_bytes(16, "big").hex() in {
        candidate["h"] for candidate in report["candidates"]
    }


def test_supplied_polynomial_small_root_supports_five_variables():
    target = (1, 2, 3, 4, 5)
    polynomial = {(0, 0, 0, 0, 0): sum(value * value for value in target)}
    for index, value in enumerate(target):
        square = tuple(2 if position == index else 0 for position in range(5))
        linear = tuple(1 if position == index else 0 for position in range(5))
        polynomial[square] = 1
        polynomial[linear] = -2 * value
    result = lattice.small_roots_detailed(
        polynomial, 1_000_003,
        [[value - 1, value + 1] for value in target],
        m=1, t=0,
    )
    assert result.roots == (target,)
    assert result.methods == ("bounded-enumeration",)


def test_mov_pairing_embedding_degree_three_with_checked_extension_field():
    # E/F_11: y^2=x^3+x+1, #E=14. P has order 7 and ord_7(11)=3.
    p, a, b, order = 11, 1, 1, 7
    point = (3, 3)
    public = ecc.ec_mul(5, point, p, a)
    modulus = [1, 0, 4, 1]  # x^3+4x^2+1, irreducible over F_11
    auxiliary = ((2, 1, 0), (7, 6, 4))
    assert ecc.embedding_degree(p, order, 12) == 3
    result = ecc.mov_frey_ruck_recover(
        p, a, b, point, public, order, embedding=3,
        auxiliary=auxiliary, extension_modulus=modulus,
    )
    assert result["scalar"] == 5
    assert result["embedding_degree"] == 3
    assert result["verified"] is True
    assert ecc.mov_frey_ruck_recover(
        p, a, b, point, public, order, embedding=3,
        auxiliary=auxiliary, extension_modulus=[1, 0, 0, 1],
    ) is None


def test_truncated_java_and_xorshift_recovery_round_trip():
    state = 0x123456789ABC & mc.JAVA_RANDOM_MASK
    java = []
    for _ in range(8):
        state = (state * mc.JAVA_RANDOM_MULTIPLIER + mc.JAVA_RANDOM_ADDEND) & mc.JAVA_RANDOM_MASK
        java.append(state >> 28)
    result = mc.java_random_truncated_recover(java[:-1], 20)
    assert result["next"] == java[-1]
    assert result["verified"] is True

    operations = (("L", 13), ("R", 17), ("L", 5))
    state = 0xDEADBEEF
    xorshift = []
    for _ in range(8):
        xorshift.append(state >> 16)
        state = mc._xorshift_step(state, 32, operations)
    result = mc.xorshift_truncated_recover(xorshift[:-1], 32, operations, 16)
    assert result["next"] == xorshift[-1]
    assert result["state"] == 0xDEADBEEF


def test_xoshiro_and_unknown_lcg_parameters_are_uniquely_proved():
    state = (1, 2, 3, 4)
    outputs = []
    for _ in range(7):
        outputs.append(mc._xoshiro256ss_output(state))
        state = mc._xoshiro256_step(state)
    result = mc.xoshiro256ss_truncated_recover(outputs[:-1], 64)
    assert result["next"] == outputs[-1]
    assert tuple(result["state"]) == (1, 2, 3, 4)

    width, output_bits = 16, 12
    mask, multiplier, increment, state = (1 << width) - 1, 25173, 13849, 0xABCD
    values = []
    for _ in range(18):
        values.append(state >> (width - output_bits))
        state = (multiplier * state + increment) & mask
    result = mc.lcg_power2_truncated_recover(
        values[:-1], output_bits, state_bits=[15, 16, 17],
        require_odd_multiplier=True, require_odd_increment=True,
    )
    assert result["next"] == values[-1]
    assert result["modulus"] == 1 << width
    assert result["multiplier"] == multiplier
    assert result["increment"] == increment


def test_new_prng_cli_and_seeded_mutation_boundaries(tmp_path, capsys):
    state = 0x13579BDF2468 & mc.JAVA_RANDOM_MASK
    values = []
    for _ in range(7):
        state = (state * mc.JAVA_RANDOM_MULTIPLIER + mc.JAVA_RANDOM_ADDEND) & mc.JAVA_RANDOM_MASK
        values.append(state >> 28)
    fixture = tmp_path / "java-truncated.json"
    fixture.write_text(json.dumps({"outputs": values[:-1], "bits": 20}))
    assert prng_cli.main(["java-truncated", str(fixture), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["candidate"]["next"] == values[-1]

    random_source = random.Random(0xC5C7F004)
    for _ in range(100):
        malformed = [random_source.getrandbits(random_source.randrange(0, 80))
                     for _ in range(random_source.randrange(0, 12))]
        # Public parsers/recoverers decline malformed or underdetermined evidence;
        # no arithmetic/recursion traceback may escape.
        mc.java_random_truncated_recover(malformed, random_source.randrange(1, 33), timeout_ms=5)
        mc.xorshift_truncated_recover(malformed, 32, (("L", 13), ("R", 17), ("L", 5)), 8)
        cd._prime_poly_roots([random_source.randrange(cd.POLY1305_P) for _ in range(4)], 3)

