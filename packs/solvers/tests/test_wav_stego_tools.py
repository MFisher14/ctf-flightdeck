"""B-130: the named WAV-stego tool catalog + offline password sweep, and the budget overthink cap.

The WAV fixtures are built here, synthetically, with plain Python (no external tool is run, no real
challenge file is used). Two embedders are reimplemented INDEPENDENTLY from the published algorithms
so a mutation in the module's reader is caught: `_embed_pwlsb` re-derives the password-seeded
placement from scratch (it never calls the module's index_stream), and `_embed_wavsteg` writes the
sequential N-LSB layout from scratch. Acceptance is always proved by the reader's own self-check
(magic+CRC, or validate_container), never by the embedder.
"""
from __future__ import annotations

import hashlib
import struct
import sys
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "common"))
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

import audio_stego                 # noqa: E402
import wav_stego_tools as wt       # noqa: E402

from ctf import budget, ledger     # noqa: E402
from ctf.event import Budget       # noqa: E402


# --------------------------------------------------------------------------- fixtures

def cover_wav(n=30000, ch=2, bits=16, seed=7) -> bytes:
    """A noise-like PCM WAV with enough samples to hide a short payload (no external tool)."""
    import random
    rnd = random.Random(seed)
    lo, hi = -(1 << (bits - 1)) // 4, (1 << (bits - 1)) // 4
    if bits == 8:
        lo, hi = 32, 224
    chans = [[rnd.randint(lo, hi) for _ in range(n)] for _ in range(ch)]
    return audio_stego.build_wav(8000, bits, chans)


def len_crc_container(payload: bytes) -> bytes:
    """A validate_container-eligible blob: [len u32 LE][crc32 u32 LE][payload]."""
    return struct.pack("<II", len(payload), zlib.crc32(payload) & 0xFFFFFFFF) + payload


def _independent_index_stream(password, num_samples):
    """A from-scratch reimplementation of the documented pwlsb placement (NOT wt.index_stream), so
    the module's reader is tested against an independently produced carrier."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    n = int(num_samples)
    seen = set()
    key = hashlib.sha256(b"wav-stego-pwlsb\x00" + bytes(password)).digest()
    i = 0
    while len(seen) < n:
        idx = int.from_bytes(hashlib.sha256(key + i.to_bytes(8, "big")).digest()[:8], "big") % n
        i += 1
        if idx not in seen:
            seen.add(idx)
            yield idx


def _embed_pwlsb(cover: bytes, payload: bytes, password) -> bytes:
    """Write the pwlsb record (magic+len+crc+payload) into the cover's sample LSBs at the
    password-seeded positions, reimplemented here from the documented format."""
    info, chans = audio_stego.wav_channels(cover)
    nch, n = len(chans), min(len(c) for c in chans)
    record = wt.PWLSB_MAGIC + struct.pack("<II", len(payload), zlib.crc32(payload) & 0xFFFFFFFF) + payload
    bits = [(b >> (7 - k)) & 1 for b in record for k in range(8)]
    stream = _independent_index_stream(password, n * nch)
    for bit in bits:
        pos = next(stream)
        f, c = divmod(pos, nch)
        chans[c][f] = (chans[c][f] & ~1) | bit
    return audio_stego.build_wav(info["rate"], info["bits"], chans)


def _embed_two_plane_ambiguous(payload_a: bytes, len_b: int):
    """Build ONE carrier whose N=1 LSB plane is a valid len+crc container (payload_a) and whose N=4
    plane is a DIFFERENT valid len+payload+crc container, so recover_wavsteg sees two distinct
    self-validated payloads. Reimplemented here from the documented layouts (it never calls the
    module), returning (wav, payload_a, payload_b). The two planes share bit0, so payload_b is read
    back from the finished carrier rather than chosen; payload_a with a length whose low byte is 0
    (len == 256) keeps the N=4 length field's forced bits clear."""
    rec_a = struct.pack("<II", len(payload_a), zlib.crc32(payload_a) & 0xFFFFFFFF) + payload_a
    a_bits = [(b >> (7 - k)) & 1 for b in rec_a for k in range(8)]
    n_a = len(a_bits)                                   # samples whose bit0 is pinned by container A
    rec_b_len = 4 + len_b + 4
    total = max(n_a, 2 * rec_b_len) + 64
    samples = [1000 + (i % 5) for i in range(total)]
    for i in range(total):
        samples[i] &= ~0b1111                           # clear the low 4 bits we drive
    for i in range(n_a):                                # N=1 plane: bit0 = container A bits
        samples[i] |= a_bits[i]

    def n4_bit(pos):                                     # stream pos -> (sample, sample-bit index)
        return pos // 4, 3 - (pos % 4)                  # N=4 reads b3,b2,b1,b0 per sample, MSB-first

    def put_byte(byte_i, value, free_only):
        for r in range(8):
            s, which = n4_bit(byte_i * 8 + r)
            want = (value >> (7 - r)) & 1
            if free_only and which == 0:
                continue                                # bit0 is the shared/forced plane; leave it
            samples[s] = (samples[s] & ~(1 << which)) | (want << which)

    length_field = struct.pack("<I", len_b)             # forced bits (b0) are 0 here by construction
    for k in range(4):
        put_byte(k, length_field[k], free_only=True)
    for k in range(4, 4 + len_b):                        # payload: clear free bits, keep b0 as-is
        put_byte(k, 0, free_only=True)

    def n4_read_byte(k):
        v = 0
        for r in range(8):
            s, which = n4_bit(k * 8 + r)
            v = (v << 1) | ((samples[s] >> which) & 1)
        return v

    payload_b = bytes(n4_read_byte(k) for k in range(4, 4 + len_b))
    crc_field = struct.pack("<I", zlib.crc32(payload_b) & 0xFFFFFFFF)
    for j in range(4):                                  # crc field sits past container A -> fully free
        k = 4 + len_b + j
        for r in range(8):
            s, which = n4_bit(k * 8 + r)
            assert s >= n_a, "crc field must lie beyond container A's bit0 region"
            want = (crc_field[j] >> (7 - r)) & 1
            samples[s] = (samples[s] & ~(1 << which)) | (want << which)
    return audio_stego.build_wav(8000, 16, [samples]), payload_a, payload_b


def _embed_wavsteg(cover: bytes, blob: bytes, num_lsb: int) -> bytes:
    """Write `blob` sequentially into the low `num_lsb` bits of each sample, MSB-first (the published
    stego-lsb WavSteg layout), reimplemented here."""
    info, chans = audio_stego.wav_channels(cover)
    nch, n = len(chans), min(len(c) for c in chans)
    bits = [(b >> (7 - k)) & 1 for b in blob for k in range(8)]
    idx = 0
    for f in range(n):
        for c in range(nch):
            if idx >= len(bits):
                return audio_stego.build_wav(info["rate"], info["bits"], chans)
            chunk = 0
            for _ in range(num_lsb):
                chunk = (chunk << 1) | (bits[idx] if idx < len(bits) else 0)
                idx += 1
            chans[c][f] = (chans[c][f] & ~((1 << num_lsb) - 1)) | chunk
    return audio_stego.build_wav(info["rate"], info["bits"], chans)


# --------------------------------------------------------------------------- pwlsb + sweep

def test_pwlsb_recovers_payload_under_correct_password():
    payload = b"PINK{pwlsb_recovered}"
    stego = _embed_pwlsb(cover_wav(), payload, "whitenoise")
    r = wt.recover_pwlsb(stego, ["nope", "secret", "whitenoise"])
    assert r.plain == payload
    assert r.validated and r.tool == "pwlsb"
    assert r.password == "whitenoise"
    # the self-check is real: the recovered bytes carry the embedded CRC-32.
    assert zlib.crc32(r.plain) & 0xFFFFFFFF == zlib.crc32(payload) & 0xFFFFFFFF


def test_pwlsb_wrong_password_never_yields_a_payload():
    """The never-wrong core: a wordlist that lacks the real passphrase must find nothing (a wrong
    position stream cannot produce the 4-byte magic + matching CRC-32)."""
    stego = _embed_pwlsb(cover_wav(), b"PINK{secret}", "whitenoise")
    r = wt.recover_pwlsb(stego, ["password", "secret", "stego", "flag", "noise"])
    assert r.plain is None and not r


def test_pwlsb_on_a_clean_cover_finds_nothing():
    r = wt.recover_pwlsb(cover_wav(seed=99), wt.load_wordlist())
    assert r.plain is None


def test_offline_sweep_uses_the_committed_wordlist():
    """A carrier whose passphrase is a committed word is opened by the sweep with no question words."""
    payload = b"PINK{found_by_committed_list}"
    stego = _embed_pwlsb(cover_wav(), payload, "whitenoise")   # 'whitenoise' is in the committed list
    r = wt.offline_sweep(stego)
    assert r.plain == payload and r.tool == "pwlsb"


def test_offline_sweep_adds_question_words():
    payload = b"PINK{question_word}"
    stego = _embed_pwlsb(cover_wav(), payload, "zork42-not-in-list")
    assert wt.offline_sweep(stego).plain is None               # not in the committed list
    r = wt.offline_sweep(stego, question_words=("zork42-not-in-list",))
    assert r.plain == payload


def test_build_pwlsb_wav_round_trips_and_matches_independent_embedder():
    """build_pwlsb_wav (the public embedder) must lay the documented record so recover_pwlsb opens
    it, and must agree BYTE-FOR-BYTE with the suite's independent embedder -- proving it implements
    the format, not just a round-trip against its own reader. A mutation in build_pwlsb_wav (e.g. the
    collapsed LSB write) breaks the CRC and/or the byte-equality, so one of these assertions fails."""
    cover, payload, pw = cover_wav(), b"PINK{build_pwlsb_wav}", "whitenoise"
    built = wt.build_pwlsb_wav(cover, payload, pw)
    assert built == _embed_pwlsb(cover, payload, pw)    # same bytes as the independent embedder
    r = wt.recover_pwlsb(built, [pw])
    assert r.plain == payload and r.validated
    # pwlsb_record is the exact header+payload the reader parses.
    rec = wt.pwlsb_record(payload)
    assert rec[:4] == wt.PWLSB_MAGIC
    assert struct.unpack_from("<II", rec, 4) == (len(payload), zlib.crc32(payload) & 0xFFFFFFFF)
    assert rec[12:] == payload


def test_index_stream_is_deterministic_and_distinct():
    a = list(x for _, x in zip(range(200), wt.index_stream("k", 5000)))
    b = list(x for _, x in zip(range(200), wt.index_stream("k", 5000)))
    assert a == b                                              # deterministic
    assert len(set(a)) == len(a)                               # distinct indices
    assert all(0 <= i < 5000 for i in a)
    assert list(x for _, x in zip(range(200), wt.index_stream("other", 5000))) != a   # key-dependent


# --------------------------------------------------------------------------- WavSteg (sequential LSB)

@pytest.mark.parametrize("num_lsb", [1, 2, 3, 4])
def test_wavsteg_recovers_self_validating_container(num_lsb):
    payload = b"PINK{wavsteg}"
    stego = _embed_wavsteg(cover_wav(n=60000), len_crc_container(payload), num_lsb)
    r = wt.recover_wavsteg(stego)
    assert r.plain == payload and r.validated and r.tool == "wavsteg"
    assert f"N={num_lsb}" in r.method


def test_wavsteg_clean_cover_has_no_plain():
    r = wt.recover_wavsteg(cover_wav(seed=321))
    assert r.plain is None


def test_wavsteg_rejects_non_container_bytes():
    """Random printable LSBs that are not a self-validating container never become plain."""
    stego = _embed_wavsteg(cover_wav(), b"just some text, not a container at all, no crc here!!", 1)
    assert wt.recover_wavsteg(stego).plain is None


def test_wavsteg_two_distinct_validated_payloads_are_ambiguous():
    """Two DIFFERENT self-validating containers on two N planes (A on N=1, B on N=4) must yield NO
    plain: recover_wavsteg refuses to pick one and flags the ambiguity. This pins the `len(plains)
    == 1` guard -- weakening it to `>= 1` (return the first of several) makes this test fail."""
    stego, payload_a, payload_b = _embed_two_plane_ambiguous(b"a" * 256, 1100)
    assert payload_a != payload_b                       # the two planes carry distinct payloads
    r = wt.recover_wavsteg(stego)
    assert r.plain is None                              # ambiguous -> never-wrong rule forbids a plain
    assert any("ambiguous" in n and "distinct" in n for n in r.notes)


# --------------------------------------------------------------------------- catalog / fingerprint

def test_catalog_names_the_tools_and_marks_the_unreproduced_ones():
    keys = {e.key for e in wt.catalog()}
    assert {"wavsteg", "pwlsb", "stools4", "invisible_secrets", "xiao", "openpuff"} <= keys
    for e in wt.catalog():
        if not e.reproduced:
            assert e.human_step, f"{e.key} is not reproduced but has no human step"
    # the pure-Python readers carry a self-check; the proprietary tools we only fingerprint do not.
    for key in ("wavsteg", "pwlsb"):
        assert next(e for e in wt.catalog() if e.key == key).self_check
    for key in ("stools4", "invisible_secrets", "xiao", "openpuff"):
        assert not next(e for e in wt.catalog() if e.key == key).self_check
    stools = next(e for e in wt.catalog() if e.key == "stools4")
    assert "Windows" in stools.human_step and not stools.reproduced


def test_fingerprint_of_a_wav_runs_reproduced_and_lists_human_steps():
    fp = wt.fingerprint(cover_wav())
    assert fp["carrier"] == "wav"
    assert fp["run_now"] == ["wavsteg", "pwlsb"]
    human_keys = {k for k, _ in fp["human"]}
    assert {"stools4", "invisible_secrets", "xiao", "openpuff"} <= human_keys


def test_fingerprint_of_a_non_wav_declines():
    fp = wt.fingerprint(b"not a wav at all")
    assert fp["carrier"] is None and fp["run_now"] == []


def test_mask_does_not_leak_the_password():
    assert wt.mask("whitenoise") == "<10 chars, starts w>"
    assert "whitenoise" not in wt.mask("whitenoise")


# --------------------------------------------------------------------------- the wordlist

def test_load_wordlist_has_words_dedups_and_adds_extra():
    words = wt.load_wordlist()
    assert "whitenoise" in words and "password" in words
    assert len(words) == len(set(words))                       # de-duped
    with_extra = wt.load_wordlist(extra=("password", "zz-unique-extra"))
    assert "zz-unique-extra" in with_extra
    assert with_extra.count("password") == 1                   # an extra already present is not doubled


def test_load_wordlist_missing_fails_loudly(monkeypatch, tmp_path):
    monkeypatch.setattr(wt, "WORDLIST", tmp_path / "does-not-exist.txt")
    with pytest.raises(FileNotFoundError):
        wt.load_wordlist()


# --------------------------------------------------------------------------- budget overthink cap

def test_cap_usd_overthink_clamps_low_point_high_solve():
    b = Budget(per_point=0.5, floor=25.0, ceiling=250.0,
               overthink_usd=15.0, overthink_max_points=50.0, overthink_min_solves=25)
    # Pink 29: 50 pts, 71 solves -> clamp to the overthink cap.
    assert budget.cap_usd(b, 50, solves=71) == 15.0
    # the clamp only lowers: a 50-pt row's normal cap is 25, overthink makes it 15.
    assert budget.cap_usd(b, 50) == 25.0                       # solves unknown -> no clamp
    assert budget.cap_usd(b, 50, solves=5) == 25.0             # few solves -> no clamp
    assert budget.cap_usd(b, 500, solves=100) == 250.0         # high points -> no clamp
    # right at the thresholds (<= points, >= solves) the clamp fires.
    assert budget.cap_usd(b, 50, solves=25) == 15.0


def test_cap_usd_without_overthink_fields_is_unchanged():
    b = Budget()
    assert budget.cap_usd(b, 50, solves=1000) == 25.0          # no overthink config -> never clamps
    assert budget.overthink_cap(b, 50, 1000) is None


def test_ledger_meter_overthink_cap_from_a_fake_board(tmp_path):
    """A fake scoreboard adapter supplies solve counts; the meter clamps the cap and gates at it."""
    b = Budget(per_point=0.5, floor=25.0, ceiling=250.0,
               overthink_usd=15.0, overthink_max_points=50.0, overthink_min_solves=25)

    class FakeBoard:
        def __init__(self, counts):
            self.counts = counts

        def solves(self, cid):
            return self.counts.get(cid)

    board = FakeBoard({"29": 71, "7": 3})
    m = budget.LedgerMeter(b, workdir=tmp_path, solves=board.solves)
    m.register("29", points=50)       # low point, high solve (fake board says 71)
    m.register("7", points=50)        # low point, few solves (3)

    assert m.status("29").cap_usd == 15.0
    assert m.status("7").cap_usd == 25.0              # not high-solve -> normal cap
    assert m.solves("29") == 71

    # the gate bites at the clamped cap: $15 of spend on 29 raises BudgetExceeded.
    m.add_spend("29", 14.0, 1000)
    with pytest.raises(budget.BudgetExceeded):
        m.add_spend("29", 2.0, 1000)


def test_register_records_solves_without_an_adapter(tmp_path):
    b = Budget(per_point=0.5, floor=25.0, ceiling=250.0,
               overthink_usd=15.0, overthink_max_points=50.0, overthink_min_solves=25)
    m = budget.LedgerMeter(b, workdir=tmp_path)
    m.register("29", points=50, solves=71)
    # the solve count persists through the ledger (a fresh meter reads it back).
    m2 = budget.LedgerMeter(b, workdir=tmp_path)
    assert m2.solves("29") == 71
    assert m2.status("29").cap_usd == 15.0
    rows = [r for r in ledger.read(tmp_path) if r.get("event") == "budget_challenge"]
    assert any(r.get("solves") == 71 for r in rows)


def test_register_rejects_a_bad_solve_count(tmp_path):
    m = budget.LedgerMeter(Budget(), workdir=tmp_path)
    with pytest.raises(ValueError):
        m.register("29", solves=-1)
    with pytest.raises(ValueError):
        m.register("29", solves=True)         # bool is not an int here


# --------------------------------------------------------------------------- profile parsing

def test_profile_requires_all_three_overthink_fields():
    from ctf import event
    base = {
        "slug": "ov", "name": "overthink test",
        "dates": {"start": __import__("datetime").date(2026, 1, 1),
                  "end": __import__("datetime").date(2026, 12, 31)},
        "platform": {"kind": "manual"},
        "flag": {"prefixes": ["OV"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
    }
    # only one of the three set -> rejected
    bad = dict(base, budget={"overthink_usd": 15.0})
    with pytest.raises(event.EventError):
        event.parse(bad, src="test")
    # all three set -> accepted
    good = dict(base, budget={"overthink_usd": 15.0, "overthink_max_points": 50.0,
                              "overthink_min_solves": 25})
    prof = event.parse(good, src="test")
    assert prof.budget.overthink_usd == 15.0 and prof.budget.overthink_min_solves == 25


def test_profile_rejects_fractional_min_solves():
    from ctf import event
    bad = {
        "slug": "ov", "name": "x",
        "dates": {"start": __import__("datetime").date(2026, 1, 1),
                  "end": __import__("datetime").date(2026, 12, 31)},
        "platform": {"kind": "manual"}, "flag": {"prefixes": ["OV"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed"},
        "budget": {"overthink_usd": 15.0, "overthink_max_points": 50.0, "overthink_min_solves": 2.5},
    }
    with pytest.raises(event.EventError):
        event.parse(bad, src="test")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
