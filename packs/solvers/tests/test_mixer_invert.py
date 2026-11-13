"""B-024 mixer-inversion at intake: the op model, the three known mixers, the recovery, the engine.

Every fixture is synthetic (a byte blob with the ELF magic, the mixer immediates and a target table
built here); no challenge binary is read or run.  The ground-lock values come from the public solve
note (fmix64 targets -> the 24-byte code ``HALCYON_1B5FC6D72036689A``).
"""
import os
import random

import pytest

import mixer_invert as M
from ctf import event

FMIX64, FMIX32, SPLIT = M.KNOWN


def _profile():
    return event.load("csctf")


# --------------------------------------------------------------------------- op model / inverses
@pytest.mark.parametrize("mx", M.KNOWN, ids=[m.name for m in M.KNOWN])
def test_forward_analytic_and_z3_agree_on_random_inputs(mx):
    rnd = random.Random(1234 + mx.width)
    for _ in range(64):
        x = rnd.getrandbits(mx.width)
        y = M.forward(mx.ops, x, mx.width)
        assert M.invert_analytic(mx.ops, y, mx.width) == x        # bijection: exact pre-image
        sols = M.invert(mx.ops, y, mx.width)
        assert x in sols
        for v in sols:                                            # every z3 answer is a real pre-image
            assert M.forward(mx.ops, v, mx.width) == y


def test_generic_custom_chain_round_trips():
    ops = (("xor", 0xdeadbeef), ("mul", 0x100000001b3), ("rotl", 13),
           ("xorshr", 29), ("add", 0x9e3779b97f4a7c15), ("xorshl", 17))
    rnd = random.Random(7)
    for _ in range(64):
        x = rnd.getrandbits(64)
        y = M.forward(ops, x, 64)
        assert M.invert_analytic(ops, y, 64) == x
        assert x in M.invert(ops, y, 64)


def test_even_multiplier_is_not_invertible_analytically():
    ops = (("mul", 0x1234567800000000 | 2),)      # even multiplier: not a bijection mod 2^64
    y = M.forward(ops, 0x41, 64)
    # even multiplier loses the low bit: analytic returns None rather than a wrong pre-image.
    assert M.invert_analytic(ops, y, 64) is None


def test_forward_rejects_unknown_op_and_bad_width():
    with pytest.raises(M.MixerError):
        M.forward((("nope", 1),), 0, 64)
    with pytest.raises(M.MixerError):
        M.forward((), 0, 65)


# --------------------------------------------------------------------------- signatures
def test_identify_matches_fmix64_by_its_constants_only_when_both_present():
    assert M.identify({0xff51afd7ed558ccd, 0xc4ceb9fe1a85ec53, 33}) == [FMIX64]
    assert M.identify({0xff51afd7ed558ccd}) == []          # one constant is not enough


def test_constants_in_text_reads_hex_and_long_decimals():
    cs = M.constants_in_text("x *= 0xff51afd7ed558ccd; y = 18397679294719823051; z=5;")
    assert 0xff51afd7ed558ccd in cs
    assert 18397679294719823051 in cs
    assert 5 not in cs                                     # short decimals are ignored


def test_mixers_in_bytes_finds_little_endian_immediates():
    blob = (b"\x90\x90" + (0xff51afd7ed558ccd).to_bytes(8, "little")
            + b"...." + (0xc4ceb9fe1a85ec53).to_bytes(8, "little"))
    assert M.mixers_in_bytes(blob) == [FMIX64]
    assert M.mixers_in_bytes(b"\x00" * 64) == []


# --------------------------------------------------------------------------- recovery
GROUND_LOCK_CODE = b"HALCYON_1B5FC6D72036689A"
GROUND_LOCK_TARGETS = [0x8bfd351846ffb86b, 0x3ff3fd892aa7e3b2, 0xf61e79e7e639e0d2]


def test_known_ground_lock_targets_invert_to_the_published_code():
    qs = [M.invert(FMIX64.ops, t, 64)[0] for t in GROUND_LOCK_TARGETS]
    assert b"".join(q.to_bytes(8, "little") for q in qs) == GROUND_LOCK_CODE


def test_recover_from_targets_keeps_order_and_groups_printable_runs():
    recs = M.recover_from_targets(GROUND_LOCK_TARGETS, FMIX64, "pseudocode")
    assert len(recs) == 1 and recs[0].code == GROUND_LOCK_CODE
    assert M.forward_run_ok(FMIX64, recs[0].code, recs[0].targets)


def test_recover_keytable_pulls_the_code_from_a_target_table_in_bytes():
    blob = b"\x01\x02\x03nonprint\xff"
    blob += b"".join(t.to_bytes(8, "little") for t in GROUND_LOCK_TARGETS)
    blob += b"\x00\xfftail"
    recs = M.recover_keytable(blob, FMIX64)
    assert any(r.code == GROUND_LOCK_CODE for r in recs)


def test_recover_keytable_recovers_a_two_qword_table_at_the_min_run_boundary():
    # Exactly two qwords (16 printable bytes): the `len(run_bytes) >= min_run` boundary with the
    # default min_run=2. The ground-lock fixture has three qwords, so a `>=`->`>` mutation (which
    # would silently skip any 2-qword keygen table) survives all other tests; this one kills it.
    code = b"OPEN_THE_LOCK_42"                               # 16 bytes, all printable
    assert len(code) == 16
    targets = [M.forward(FMIX64.ops, int.from_bytes(code[i:i + 8], "little"), 64) for i in (0, 8)]
    # Zero qwords on both sides: fmix64's pre-image of 0 is 0 (bytes all 0x00), which is non-printable,
    # so the printable run is exactly the two target qwords -- the min_run=2 boundary.
    blob = b"\x00" * 8 + b"".join(t.to_bytes(8, "little") for t in targets) + b"\x00" * 8
    recs = M.recover_keytable(blob, FMIX64)
    assert any(r.code == code for r in recs)
    assert M.forward_run_ok(FMIX64, code, targets)


def test_forward_run_ok_rejects_a_tampered_code():
    assert not M.forward_run_ok(FMIX64, b"XALCYON_", [GROUND_LOCK_TARGETS[0]])


# --------------------------------------------------------------------------- engine
def _ground_lock_elf(tmp_path, with_pseudocode=False):
    cdir = tmp_path / "9084-ground-lock"
    (cdir / "files").mkdir(parents=True)
    blob = b"\x7fELF" + b"\x00" * 60
    blob += (0xff51afd7ed558ccd).to_bytes(8, "little") + b"\x90" * 8
    blob += (0xc4ceb9fe1a85ec53).to_bytes(8, "little") + b"\x90" * 8
    blob += b"SEP\x01\x02\x03\xff"
    blob += b"".join(t.to_bytes(8, "little") for t in GROUND_LOCK_TARGETS)
    blob += b"\x00\xfftrailer-bytes"
    (cdir / "files" / "fcunlock").write_bytes(blob)
    if with_pseudocode:
        pc = cdir / "recon" / "decompile" / "fcunlock"
        pc.mkdir(parents=True)
        (pc / "main.c").write_text(
            "x ^= x>>33; x *= 0xff51afd7ed558ccd; x ^= x>>33; x *= 0xc4ceb9fe1a85ec53; x ^= x>>33;\n"
            "if (a==0x8bfd351846ffb86b && b==0x3ff3fd892aa7e3b2 && c==0xf61e79e7e639e0d2) win();\n")
    return cdir


def test_solve_recovers_the_flag_from_raw_immediates(tmp_path):
    cdir = _ground_lock_elf(tmp_path)
    r = M.solve(cdir, _profile())
    assert r.status == "candidate"
    assert "CSCTF{HALCYON_1B5FC6D72036689A}" in r.flags
    assert r.evidence and r.evidence[0].kind == "match"


def test_solve_recovers_the_flag_from_decompiled_pseudocode(tmp_path):
    cdir = _ground_lock_elf(tmp_path, with_pseudocode=True)
    r = M.solve(cdir, _profile())
    assert r.status == "candidate"
    assert "CSCTF{HALCYON_1B5FC6D72036689A}" in r.flags


def test_solve_writes_recovered_codes_for_exec_grep(tmp_path):
    cdir = _ground_lock_elf(tmp_path)
    M.solve(cdir, _profile())
    rec = (cdir / "recon" / "mixer" / "recovered.txt").read_text().splitlines()
    assert "HALCYON_1B5FC6D72036689A" in rec


def test_solve_is_none_without_a_known_mixer(tmp_path):
    cdir = tmp_path / "c"
    (cdir / "files").mkdir(parents=True)
    (cdir / "files" / "plain").write_bytes(b"\x7fELF" + b"\x00" * 200)
    r = M.solve(cdir, _profile())
    assert r.status == "none" and not r.flags


def test_solve_is_unsure_when_the_code_cannot_form_a_flag(tmp_path):
    # A pre-image containing '}' is printable but cannot wrap into a valid flag (body is [^}\n]); the
    # engine reports it `unsure` with the recovered bytes, never a false `candidate`.
    code = b"ab}cdefg"
    target = M.forward(FMIX64.ops, int.from_bytes(code, "little"), 64)
    cdir = tmp_path / "c"
    pc = cdir / "recon" / "decompile" / "x"
    pc.mkdir(parents=True)
    (pc / "main.c").write_text(
        f"x *= 0xff51afd7ed558ccd; x *= 0xc4ceb9fe1a85ec53; if (h == {hex(target)}) ok();\n")
    (cdir / "x.elf").write_bytes(b"\x7fELF" + b"\x00" * 60)
    r = M.solve(cdir, _profile())
    assert r.status == "unsure"
    assert not r.flags
    assert any("ab}cdefg" in e.detail for e in r.evidence)


def test_solve_blocks_naming_z3_when_inversion_needs_it_and_it_is_missing(tmp_path, monkeypatch):
    def _no_z3(*a, **k):
        raise M.Z3Unavailable("z3-solver is not installed (pip install z3-solver==5.1.0.0)")
    # Pseudocode-only signature (no raw immediate table), so recovery depends on z3.
    monkeypatch.setattr(M, "invert", _no_z3)
    cdir = tmp_path / "c"
    pc = cdir / "recon" / "decompile" / "x"
    pc.mkdir(parents=True)
    (pc / "main.c").write_text(
        "x *= 0xff51afd7ed558ccd; x *= 0xc4ceb9fe1a85ec53;\n"
        "if (a==0x8bfd351846ffb86b && b==0x3ff3fd892aa7e3b2) win();\n")
    r = M.solve(cdir, _profile())
    assert r.status == "blocked"
    assert "z3" in r.notes
