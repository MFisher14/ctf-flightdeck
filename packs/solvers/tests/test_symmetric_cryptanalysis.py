"""Deterministic replay, ambiguity, callback, and cap tests for r5c symmetric analysis."""

from __future__ import annotations

import importlib
import itertools
import sys
from pathlib import Path

from Crypto.Cipher import AES, DES


COMMON = Path(__file__).resolve().parents[1] / "solvers" / "common"
sys.path.insert(0, str(COMMON))

import symmetric_cryptanalysis as sym  # noqa: E402


def _aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def _aes_ecb_decrypt(key: bytes, block: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).decrypt(block)


def test_differential_harness_filters_then_replays_original_aes_pairs():
    keys = [bytes([index]) * 16 for index in range(6)]
    secret = keys[3]
    delta = bytes.fromhex("80000000000000000000000000000001")
    pairs = []
    for value in (bytes(16), bytes(range(16)), bytes(reversed(range(16)))):
        paired = bytes(a ^ b for a, b in zip(value, delta))
        pairs.append((value, paired, _aes_ecb_encrypt(secret, value),
                      _aes_ecb_encrypt(secret, paired)))

    def last_round_filter(key, p0, p1, c0, c1):
        return bytes(a ^ b for a, b in zip(_aes_ecb_decrypt(key, c0),
                                           _aes_ecb_decrypt(key, c1))) == delta

    assert sym.recover_differential_key(
        pairs, keys, _aes_ecb_encrypt, expected_input_xor=delta,
        differential_test=last_round_filter,
    ) == secret
    assert sym.recover_differential_key(
        pairs, keys, _aes_ecb_encrypt, expected_input_xor=bytes(16)
    ) is None
    assert sym.recover_differential_key(
        [(b"a", b"b", b"x", b"x")], [1, 2],
        lambda _key, _plain: b"x",
    ) is None  # both keys replay: ambiguous


def test_linear_harness_bias_ranks_but_exact_replay_emits_key():
    sbox = (6, 4, 12, 5, 0, 7, 2, 14, 1, 15, 3, 13, 8, 10, 9, 11)
    inverse = [0] * 16
    for source, destination in enumerate(sbox):
        inverse[destination] = source
    secret = 7

    def encrypt(key, plaintext):
        return bytes([sbox[plaintext[0] ^ key]])

    samples = [(bytes([value]), encrypt(secret, bytes([value]))) for value in range(16)]

    def approximation(key, plaintext, ciphertext):
        return (inverse[ciphertext[0]] ^ plaintext[0] ^ key).bit_count() & 1

    assert sym.recover_linear_key(
        samples, range(16), encrypt, approximation, min_abs_bias=8
    ) == secret
    assert sym.recover_linear_key(
        [(b"a", b"x"), (b"b", b"x")], [1, 2],
        lambda _key, _plain: b"x", lambda *_args: 0,
    ) is None


def test_mitm_double_aes_finds_unique_pair_and_xor_cipher_declines():
    first_keys = [index.to_bytes(16, "big") for index in range(8)]
    second_keys = [(0x100 + index).to_bytes(16, "big") for index in range(8)]
    expected = (first_keys[3], second_keys[5])
    pairs = []
    for plaintext in (bytes(16), bytes(range(16)), bytes(reversed(range(16)))):
        middle = _aes_ecb_encrypt(expected[0], plaintext)
        pairs.append((plaintext, _aes_ecb_encrypt(expected[1], middle)))
    assert sym.meet_in_middle_double_encryption(
        pairs, first_keys, second_keys, _aes_ecb_encrypt,
        _aes_ecb_encrypt, _aes_ecb_decrypt,
    ) == expected

    xor = lambda key, block: bytes(value ^ key for value in block)
    ambiguous = [(b"\x10", b"\x13")]
    assert sym.meet_in_middle_double_encryption(
        ambiguous, range(4), range(4), xor, xor, xor
    ) is None


def test_mitm_double_des_style_candidate_spaces_cross_check_pycryptodome():
    def key(index):
        # Change data bits, not only DES parity bits.
        return bytes(((index * 18 + offset * 2) & 0xFE) for offset in range(8))

    first_keys = [key(index) for index in range(1, 7)]
    second_keys = [key(index) for index in range(9, 15)]
    expected = (first_keys[2], second_keys[4])
    encrypt = lambda candidate, block: DES.new(candidate, DES.MODE_ECB).encrypt(block)
    decrypt = lambda candidate, block: DES.new(candidate, DES.MODE_ECB).decrypt(block)
    pairs = []
    for plaintext in (bytes(8), b"DES MITM", bytes(range(8))):
        pairs.append((plaintext, encrypt(expected[1], encrypt(expected[0], plaintext))))
    assert sym.meet_in_middle_double_encryption(
        pairs, first_keys, second_keys, encrypt, encrypt, decrypt
    ) == expected


def test_slide_pair_and_related_key_transcripts_require_full_replay():
    secret, rounds = 9, 3

    def round_function(key, block):
        return bytes([(block[0] + key) & 0xFF])

    def full(key, block):
        value = block
        for _ in range(rounds):
            value = round_function(key, value)
        return value

    p0 = b"\x20"
    p1 = round_function(secret, p0)
    transcripts = [(p0, full(secret, p0)), (p1, full(secret, p1)),
                   (b"\x55", full(secret, b"\x55"))]
    assert sym.recover_slide_key(transcripts, range(16), round_function, full) == secret
    assert sym.recover_slide_key(
        [(b"a", b"x"), (b"b", b"x")], [1, 2],
        lambda _key, value: value, lambda _key, _value: b"x",
    ) is None

    master = 11
    derive = lambda key, relation: key ^ relation
    encrypt = lambda key, plaintext: bytes([plaintext[0] ^ key])
    related = [(relation, bytes([value]), encrypt(derive(master, relation), bytes([value])))
               for relation, value in ((0, 0x20), (3, 0x44), (7, 0xA1))]
    assert sym.recover_related_key(related, range(16), derive, encrypt) == master
    assert sym.recover_related_key(
        [(0, b"a", b"a")], [1, 2], lambda _master, _relation: 0,
        lambda _key, plaintext: plaintext,
    ) is None


def test_feistel_structure_round_trip_key_recovery_and_ambiguity():
    secret, rounds = 23, 5

    def round_function(key, index, right):
        mask = (key + 17 * index) & 0xFF
        return bytes(value ^ mask for value in right)

    plaintexts = (bytes.fromhex("00112233"), bytes.fromhex("deadbeef"), bytes.fromhex("a5a55a5a"))
    pairs = [(plaintext, sym.feistel_encrypt(plaintext, secret, rounds, round_function))
             for plaintext in plaintexts]
    assert all(sym.feistel_decrypt(ciphertext, secret, rounds, round_function) == plaintext
               for plaintext, ciphertext in pairs)
    assert sym.recover_feistel_key(pairs, range(32), rounds, round_function) == secret
    assert sym.recover_feistel_structure(
        pairs, secret, range(2, 8),
        lambda key, candidate_rounds, plaintext: sym.feistel_encrypt(
            plaintext, key, candidate_rounds, round_function
        ),
    ) == rounds
    assert sym.recover_feistel_structure(
        [(b"ab", b"ab")], secret, [2, 3],
        lambda _key, _configuration, plaintext: plaintext,
    ) is None
    assert sym.recover_feistel_key(
        [(b"ab", b"ab")], [1, 2], 2,
        lambda _key, _round, right: bytes(len(right)),
    ) is None


def test_spn_structure_inverse_unique_key_and_equivalent_key_decline():
    sbox = (12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2)
    permutation = tuple(reversed(range(8)))
    secret, rounds = 0x5A, 3
    pairs = [(value, sym.spn_encrypt(value, secret, rounds, sbox, permutation, width=8))
             for value in (0x00, 0x12, 0xA5, 0xFF)]
    assert all(sym.spn_decrypt(ciphertext, secret, rounds, sbox, permutation, width=8) == plaintext
               for plaintext, ciphertext in pairs)
    assert sym.recover_spn_key(
        pairs, range(256), rounds, sbox, permutation, width=8
    ) == secret
    assert sym.recover_spn_structure(
        [(plaintext.to_bytes(1, "big"), ciphertext.to_bytes(1, "big"))
         for plaintext, ciphertext in pairs],
        secret, range(1, 6),
        lambda key, candidate_rounds, plaintext: bytes([
            sym.spn_encrypt(plaintext[0], key, candidate_rounds, sbox, permutation, width=8)
        ]),
    ) == rounds
    assert sym.recover_spn_structure(
        [(b"a", b"x")], secret, [1, 2],
        lambda _key, _configuration, _plaintext: b"x",
    ) is None
    identity_box, identity_perm = tuple(range(16)), tuple(range(4))
    ambiguous = [(3, sym.spn_encrypt(3, 0, 1, identity_box, identity_perm, width=4))]
    assert sym.recover_spn_key(
        ambiguous, [0, 15], 1, identity_box, identity_perm, width=4
    ) is None


def test_ecb_pattern_detection_and_verified_cut_paste():
    key = bytes(range(16))
    blocks = (b"account=alice!!!", b"role=user.......", b"role=admin......")
    plaintext = b"".join((blocks[0], blocks[1], blocks[0], blocks[2]))
    ciphertext = AES.new(key, AES.MODE_ECB).encrypt(plaintext)
    report = sym.detect_ecb_patterns(ciphertext)
    assert report is not None and report.block_count == 4
    assert any(indices == (0, 2) for _block, indices in report.repeated_blocks)

    source = AES.new(key, AES.MODE_ECB).encrypt(b"".join(blocks))
    target = b"".join((blocks[0], blocks[2], blocks[1]))

    def verify(candidate):
        return AES.new(key, AES.MODE_ECB).decrypt(candidate) == target

    forged = sym.forge_ecb_cut_and_paste(source, [0, 2, 1], verify)
    assert forged is not None and verify(forged)
    assert sym.forge_ecb_cut_and_paste(source, [0, 2, 1], lambda _value: True) is None

    def broken_verify(candidate):
        if verify(candidate):
            return True
        raise RuntimeError("negative-control failure")

    assert sym.forge_ecb_cut_and_paste(source, [0, 2, 1], broken_verify) is None


def test_cbc_bitflip_iv_reuse_iv_recovery_and_iv_equals_key():
    key, iv = bytes(range(16)), bytes(range(32, 48))
    plaintext = b"user=guest;xxxx!" + b"payload-block-02"
    assert len(plaintext) == 32
    ciphertext = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(plaintext)
    expected = b"user=admin;xxxx!" + plaintext[16:]

    def verify_flip(candidate_iv, candidate_ciphertext):
        return AES.new(key, AES.MODE_CBC, iv=candidate_iv).decrypt(candidate_ciphertext) == expected

    forged = sym.forge_cbc_bitflip(
        iv, ciphertext, 5, b"guest", b"admin", verify_flip
    )
    assert forged is not None and verify_flip(*forged)
    assert sym.forge_cbc_bitflip(
        iv, ciphertext, 5, b"guest", b"admin", lambda *_args: True
    ) is None

    def broken_flip(candidate_iv, candidate_ciphertext):
        if verify_flip(candidate_iv, candidate_ciphertext):
            return True
        raise RuntimeError("negative-control failure")

    assert sym.forge_cbc_bitflip(
        iv, ciphertext, 5, b"guest", b"admin", broken_flip
    ) is None

    findings = sym.detect_cbc_iv_reuse([
        (iv, ciphertext), (bytes(16), ciphertext), (iv, ciphertext[::-1])
    ])
    assert findings == (sym.IVReuseFinding(iv, (0, 2)),)

    first_plaintext, first_ciphertext = plaintext[:16], ciphertext[:16]
    recovered_iv = sym.recover_cbc_iv(
        first_plaintext, first_ciphertext,
        lambda block: AES.new(key, AES.MODE_ECB).decrypt(block),
        lambda block: AES.new(key, AES.MODE_ECB).encrypt(block),
        lambda candidate: candidate == iv,
    )
    assert recovered_iv == iv
    assert sym.recover_cbc_iv(
        first_plaintext, first_ciphertext,
        lambda block: AES.new(key, AES.MODE_ECB).decrypt(block),
        lambda block: AES.new(key, AES.MODE_ECB).encrypt(block),
        lambda _candidate: True,
    ) is None
    assert sym.recover_cbc_iv(
        first_plaintext, first_ciphertext,
        lambda block: AES.new(key, AES.MODE_ECB).decrypt(block),
        lambda block: AES.new(key, AES.MODE_ECB).encrypt(block),
        lambda candidate: True if candidate == iv else _raises(),
    ) is None

    c1 = AES.new(key, AES.MODE_ECB).encrypt(b"chosen-c1-block!")
    crafted = c1 + bytes(16) + c1
    leaked = AES.new(key, AES.MODE_CBC, iv=key).decrypt(crafted)
    assert sym.recover_cbc_iv_equals_key(
        crafted, leaked, lambda candidate: candidate == key
    ) == key
    assert sym.recover_cbc_iv_equals_key(crafted, leaked, lambda _candidate: True) is None


def test_ctr_ofb_and_cfb_reuse_recover_only_verified_plaintext():
    key = bytes(reversed(range(16)))
    known = b"known stream plaintext material!!"
    target_plaintext = b"secret target text"

    nonce = b"nonce123"
    known_ctr = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(known)
    target_ctr = AES.new(key, AES.MODE_CTR, nonce=nonce).encrypt(target_plaintext)
    assert sym.recover_ctr_ofb_reuse_plaintext(
        known, known_ctr, target_ctr,
        lambda value: value == target_plaintext, mode="ctr",
    ) == target_plaintext

    iv = bytes(range(16))
    known_ofb = AES.new(key, AES.MODE_OFB, iv=iv).encrypt(known)
    target_ofb = AES.new(key, AES.MODE_OFB, iv=iv).encrypt(target_plaintext)
    assert sym.recover_ctr_ofb_reuse_plaintext(
        known, known_ofb, target_ofb,
        lambda value: value == target_plaintext, mode="ofb",
    ) == target_plaintext
    assert sym.recover_ctr_ofb_reuse_plaintext(
        known, known_ofb, target_ofb, lambda _value: True, mode="ofb"
    ) is None
    assert sym.recover_ctr_ofb_reuse_plaintext(
        known, known_ofb, target_ofb,
        lambda value: True if value == target_plaintext else _raises(), mode="ofb"
    ) is None

    known_segment, target_segment = b"known-cfb-block!", b"secret-cfb-data!"
    known_cfb = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).encrypt(known_segment)
    target_cfb = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).encrypt(target_segment)
    assert sym.recover_cfb_reused_segment(
        known_segment, known_cfb, target_cfb, iv, iv,
        lambda value: value == target_segment,
    ) == target_segment
    assert sym.recover_cfb_reused_segment(
        known_segment, known_cfb, target_cfb, iv, bytes(16),
        lambda _value: True,
    ) is None
    assert sym.recover_cfb_reused_segment(
        known_segment, known_cfb, target_cfb, iv, iv,
        lambda _value: True,
    ) is None
    assert sym.recover_cfb_reused_segment(
        known_segment, known_cfb, target_cfb, iv, iv,
        lambda value: True if value == target_segment else _raises(),
    ) is None
    assert sym.recover_cfb_reused_segment(
        known + b"extra", known_ctr[:len(known) + 5], target_ctr,
        iv, iv, lambda _value: True,
    ) is None


def test_supplied_sample_distinguisher_reports_bias_without_guessing_key():
    samples = [bytes([0, index & 0xFF]) for index in range(128)]
    report = sym.distinguish_stream_samples(
        samples, lambda value: value[0] == 0,
        expected_probability=1 / 256, z_threshold=3,
    )
    assert report is not None and report.hits == 128 and report.distinguished
    balanced = sym.distinguish_stream_samples(
        [bytes([index & 1]) for index in range(100)],
        lambda value: value[0] == 0, expected_probability=0.5, z_threshold=3,
    )
    assert balanced is not None and not balanced.distinguished
    assert sym.distinguish_stream_samples(samples, lambda _value: "yes") is None


def _raises(*_args):
    raise RuntimeError("synthetic callback failure")


def test_iterator_callback_input_and_work_guards_decline():
    def failing_iterator():
        yield (b"a", b"b", b"x", b"y")
        raise RuntimeError("iteration failed")

    assert sym.recover_differential_key(
        failing_iterator(), [1], lambda _key, plain: plain
    ) is None
    assert sym.recover_differential_key(
        [(b"a", b"b", b"x", b"y")], itertools.count(),
        lambda _key, plain: plain,
    ) is None
    assert sym.recover_linear_key(
        [(b"a", b"a"), (b"b", b"b")], [1],
        lambda _key, plain: plain, _raises,
    ) is None
    assert sym.meet_in_middle_double_encryption(
        [(b"a", b"a")], [1], [2], _raises,
        lambda _key, block: block, lambda _key, block: block,
    ) is None
    assert sym.recover_related_key(
        [(0, b"a", b"a")], [1], _raises, lambda _key, block: block
    ) is None
    assert sym.recover_feistel_key(
        [(b"ab", b"ab")], [1], 2, _raises
    ) is None
    assert sym.detect_ecb_patterns(b"short", block_size=16) is None
    assert sym.distinguish_stream_samples([b"a", b"b"], _raises) is None
    assert sym.recover_differential_key(
        [(b"a", b"b", b"x", b"y")], [1],
        lambda _key, plain: plain,
        max_work=sym.MAX_TOTAL_WORK + 1,
    ) is None
    # A callback failure on even a losing candidate invalidates the harness.
    assert sym.recover_differential_key(
        [(b"a", b"b", b"a", b"b")], [1, 2],
        lambda key, plain: (_raises() if key == 1 else plain),
    ) is None
    assert sym.recover_feistel_structure(
        [(b"ab", b"ab")], 1, [2], _raises
    ) is None
    assert sym.recover_feistel_structure(
        [(b"ab", b"ab")], b"K" * (sym.MAX_KEY_BYTES + 1), [2],
        lambda _key, _configuration, plaintext: plaintext,
    ) is None
    assert sym.recover_differential_key(
        [(b"a", b"b", b"a", b"b")], [b"x" * (sym.MAX_KEY_BYTES + 1)],
        lambda _key, plain: plain,
    ) is None
    assert sym.recover_differential_key(
        [(b"a", b"b", b"a", b"b")], [1 << sym.MAX_KEY_INT_BITS],
        lambda _key, plain: plain,
    ) is None
    assert sym.detect_cbc_iv_reuse([(b"short", b"not-a-multiple")]) is None
    assert sym.detect_cbc_iv_reuse([(bytes(16), bytes(16)), (bytes(8), bytes(16))]) is None


def test_package_import_smoke():
    packaged = importlib.import_module("solvers.common.symmetric_cryptanalysis")
    assert packaged.spn_encrypt(1, 2, 1, tuple(range(16)), tuple(range(4)), width=4) == \
        sym.spn_encrypt(1, 2, 1, tuple(range(16)), tuple(range(4)), width=4)
