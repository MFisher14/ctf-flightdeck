"""The fastlane decode guards of intake (B-012, ctf/intake/decode.py).

The crib decoder's loose steps (single-byte xor, rot13, ...) find flag shapes in a few KB of base64
noise by chance. These tests pin the judge that keeps such readings out of `solved`, the merge that
turns an unconfirmed decode into a `candidate`, and the lock that keeps concurrent intakes from reading
each other's decoder state. Every input is synthetic; nothing runs a challenge binary or the network.
"""
from __future__ import annotations

import base64
import random
import threading
import types

import pytest

from ctf import event
from ctf import intake as I
from ctf.intake import decode as D
from ctf.result import SolverResult

CSCTF = event.load("csctf")
STRICT = frozenset({"b64", "hex", "b32"})      # a stand-in strict-step set for the judge's unit tests


# ================================================================ body_is_printable / judge

def test_body_is_printable():
    assert D.body_is_printable("CSCTF{plain_body 1!}")
    assert not D.body_is_printable("CTF{ab\x07cd}")
    assert not D.body_is_printable("CTF{ab\x7fcd}")
    assert not D.body_is_printable("CTF{café}")


def test_control_character_body_is_noise_even_after_a_strict_decode():
    v, why = D.judge("CTF{@\x07xgr}", ("b64",), "CTF{@\x07xgr}", STRICT)
    assert v == D.NOISE and "control" in why


def test_strict_step_confirms_without_a_reading():
    assert D.judge("CSCTF{deep}", ("reverse", "b64"), None, STRICT)[0] == D.FLAG


def test_rot13_alone_is_a_loose_step_not_a_representation_decode():
    # rot13 is a STRICT decoder inside crib_decode, but it is a classical shift; the real strict set
    # computed from the decoder must leave it out.
    from ctf import fastlane
    if fastlane._crib is None:
        pytest.fail("crib_decode is not importable: the fastlane decoder is missing")
    strict = D._strict_steps(fastlane._crib)
    assert "b64" in strict and "hex" in strict
    assert "rot13" not in strict and "xor37" not in strict
    v, _ = D.judge("CTF{r~}", ("rot13", "xor36"), "q]3^" * 150 + "CTF{r~}", strict)
    assert v == D.UNCONFIRMED


def test_loose_chain_with_the_flag_as_the_whole_reading_is_a_flag():
    assert D.judge("CSCTF{xor_alone}", ("xor42",), "CSCTF{xor_alone}\n", STRICT)[0] == D.FLAG


def test_loose_chain_with_prose_around_the_flag_is_a_flag():
    reading = "Well done, agent. The flag is CSCTF{xor_in_prose} and nothing else, so go and submit it."
    assert D.judge("CSCTF{xor_in_prose}", ("xor42",), reading, STRICT)[0] == D.FLAG


def test_loose_chain_without_a_reading_is_unconfirmed():
    v, why = D.judge("CSCTF{abc}", ("xor11",), None, STRICT)
    assert v == D.UNCONFIRMED and "no reading" in why


def test_loose_chain_in_a_reading_with_control_characters_is_unconfirmed():
    reading = "fTYMOg\x01nYFpUyf[\x05|" * 10 + "CSCTF{printable}" + "\x7fV\x03_}" * 10
    v, why = D.judge("CSCTF{printable}", ("rot13", "xor37"), reading, STRICT)
    assert v == D.UNCONFIRMED and "not clean text" in why


def test_loose_chain_in_symbol_noise_is_unconfirmed():
    noise = "9xwJ&F9!}t^!YUZ!F&SwBaXq]ke*Yg__c'FyE@h{pX#e&qvJpa~_f`" * 4
    v, why = D.judge("CTF{U`k}", ("rot13", "xor12"), noise + "CTF{U`k}" + noise, STRICT)
    assert v == D.UNCONFIRMED and "does not read as text" in why


def test_flag_share_threshold():
    # The flag is just over / just under half of a reading whose rest is symbol noise.
    flag = "CSCTF{" + "a" * 14 + "}"                  # 21 chars
    over = flag + "#" * 20                           # 21 / 41 >= 0.5
    under = flag + "#" * 22                          # 21 / 43 <  0.5
    assert D.judge(flag, ("xor01",), over, STRICT)[0] == D.FLAG
    assert D.judge(flag, ("xor01",), under, STRICT)[0] == D.UNCONFIRMED


def test_wordy_threshold():
    flag = "CSCTF{f}"
    # rest: 100 chars, letters only except k symbols; letters share stays >= 0.6 throughout.
    ok = "a" * 96 + "#" * 4                          # 96% plain
    bad = "a" * 94 + "#" * 6                         # 94% plain
    assert D.judge(flag, ("xor01",), ok + flag, STRICT)[0] == D.FLAG
    assert D.judge(flag, ("xor01",), bad + flag, STRICT)[0] == D.UNCONFIRMED


def test_letters_threshold():
    flag = "CSCTF{f}"
    ok = "a" * 61 + "1" * 39                          # 61% letters, all plain
    bad = "a" * 59 + "1" * 41                         # 59% letters
    assert D.judge(flag, ("xor01",), ok + flag, STRICT)[0] == D.FLAG
    assert D.judge(flag, ("xor01",), bad + flag, STRICT)[0] == D.UNCONFIRMED


# ================================================================ the merge in intake

def _rep(*hits, sweep_flags=()):
    rep = I.Report("9", None, SolverResult("none", engine="intake", challenge_id="9"))
    for f in sweep_flags:
        rep.flags[f] = ["sweep plain in a.txt"]
    rep.fastlane = list(hits)
    return rep


def _hit(flag, verdict, chain=("xor11",), source="a.txt"):
    return D.Hit(flag, chain, source, None, verdict, f"why-{verdict}")


def _finish(rep):
    I._merge(rep, CSCTF, "")
    return I._result(rep, rep.challenge_id)


def test_merge_noise_hit_is_excluded_and_not_a_flag():
    rep = _rep(_hit("CTF{@\x07x}", D.NOISE))
    res = _finish(rep)
    assert res.status == "none" and rep.flags == {}
    assert rep.excluded == {"CTF{@\\x07x}": "why-noise"}


def test_merge_unconfirmed_hit_alone_makes_a_candidate_not_solved():
    rep = _rep(_hit("CSCTF{weak}", D.UNCONFIRMED))
    res = _finish(rep)
    assert res.status == "candidate" and list(res.flags) == ["CSCTF{weak}"]
    assert rep.unconfirmed == {"CSCTF{weak}": "why-unconfirmed"}


def test_merge_unconfirmed_hit_confirmed_by_the_sweep_stays_solved():
    rep = _rep(_hit("CSCTF{both}", D.UNCONFIRMED), sweep_flags=["CSCTF{both}"])
    res = _finish(rep)
    assert res.status == "solved" and rep.unconfirmed == {}


def test_merge_unconfirmed_hit_confirmed_by_a_confirmed_decode_is_solved_in_any_order():
    f = "CSCTF{real_one}"
    for hits in ((_hit(f, D.UNCONFIRMED), _hit(f, D.FLAG, ("b64",), "b.txt")),
                 (_hit(f, D.FLAG, ("b64",), "b.txt"), _hit(f, D.UNCONFIRMED))):
        rep = _rep(*hits)
        res = _finish(rep)
        assert res.status == "solved" and rep.unconfirmed == {}, hits


def test_merge_two_confirmed_decodes_with_different_values_are_a_candidate():
    rep = _rep(_hit("CSCTF{one}", D.FLAG, ("b64",), "a.txt"), _hit("CSCTF{two}", D.FLAG, ("b64",), "b.txt"))
    res = _finish(rep)
    assert res.status == "candidate" and sorted(res.flags) == ["CSCTF{one}", "CSCTF{two}"]


# ================================================================ decode_hits: every blob, under the lock

class _FakeCrib:
    """Stands in for crib_decode: a module-global LAST written by each solve, and a solve lock."""
    STRICT = ()

    def __init__(self):
        self._SOLVE_LOCK = threading.RLock()
        self.LAST = {}


def _fake_fastlane(crib, crib_flag, files=(), blobs=()):
    return types.SimpleNamespace(
        _crib=crib, _crib_flag=crib_flag,
        _first_flag=lambda text: text if text.startswith("CSCTF{") else None,
        _read_small_files=lambda d: list(files),
        _encoded_blobs_from_desc=lambda desc: list(blobs))


def test_decode_hits_reads_every_file_and_every_brief_blob():
    crib = _FakeCrib()

    def crib_flag(data):
        flag = data.decode()
        crib.LAST["flags"] = [(flag, ("b64",), flag)]
        return flag, "b64"

    fl = _fake_fastlane(crib, crib_flag, files=[("a.txt", b"CSCTF{a}"), ("b.txt", b"CSCTF{b}")],
                        blobs=[b"CSCTF{c}"])
    hits = D.decode_hits({"description": "x"}, None, fastlane=fl)
    assert [(h.flag, h.source) for h in hits] == [("CSCTF{a}", "a.txt"), ("CSCTF{b}", "b.txt"),
                                                  ("CSCTF{c}", "description")]
    assert hits[0].reading == "CSCTF{a}" and hits[0].chain == ("b64",)


def test_decode_one_takes_the_reading_of_the_simplest_chain_for_the_flag():
    crib = _FakeCrib()

    def crib_flag(data):
        crib.LAST["flags"] = [("CSCTF{s}", ("b64",), "CSCTF{s}"),
                              ("CSCTF{s}", ("swapcase", "xor01", "b64"), "garbage CSCTF{s} garbage"),
                              ("CSCTF{other}", (), "CSCTF{other}")]
        return "CSCTF{s}", "b64"

    fl = _fake_fastlane(crib, crib_flag)
    assert D._decode_one(fl, b"x") == ("CSCTF{s}", ("b64",), "CSCTF{s}")


def test_decode_hits_without_a_decoder_raises_a_named_error():
    fl = _fake_fastlane(None, None)
    with pytest.raises(RuntimeError, match="crib_decode"):
        D.decode_hits({}, None, fastlane=fl)


def test_decode_one_reads_last_under_the_solve_lock():
    # Thread A's solve writes LAST, then waits for thread B to start its own solve. Under the lock B
    # cannot start until A has read its LAST; without it, B overwrites LAST and A reads B's reading.
    crib = _FakeCrib()
    b_started = threading.Event()

    def crib_flag(data):
        flag = data.decode()
        crib.LAST["flags"] = [(flag, ("xor01",), flag)]
        if flag == "CSCTF{b}":
            b_started.set()
        if flag == "CSCTF{a}":
            b_started.wait(0.5)
        return flag, "xor01"

    fl = _fake_fastlane(crib, crib_flag)
    out = {}

    def run(data):
        out[data] = D._decode_one(fl, data)

    ta = threading.Thread(target=run, args=(b"CSCTF{a}",))
    ta.start()
    while not crib.LAST:
        pass
    tb = threading.Thread(target=run, args=(b"CSCTF{b}",))
    tb.start()
    ta.join(5)
    tb.join(5)
    assert out[b"CSCTF{a}"] == ("CSCTF{a}", ("xor01",), "CSCTF{a}")
    assert out[b"CSCTF{b}"] == ("CSCTF{b}", ("xor01",), "CSCTF{b}")


# ================================================================ real decoder, real noise (regressions)

class _Adapter:
    kind = "fake"

    def __init__(self, files):
        self.files = files

    def get_challenge(self, cid):
        from ctf.platform.base import Challenge
        return Challenge(id=cid, name="Noise", category="crypto", points=100, description="")

    def download_files(self, cid, dest):
        for rel, data in self.files.items():
            (dest / rel).write_bytes(data)


def _b64_noise(seed: int, index: int) -> bytes:
    """The index-th 2250-byte random blob of random.Random(seed), base64-encoded: a found reproduction
    of the crib decoder reading a flag shape out of noise."""
    rnd = random.Random(seed)
    for _ in range(index + 1):
        raw = rnd.randbytes(2250)
    return base64.b64encode(raw)


def _opts():
    return I.Options(net_guard="hook", engines=False, record=False)


def _intake(tmp_path, monkeypatch, files):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    from ctf import fastlane
    if fastlane._crib is None:
        pytest.fail("crib_decode is not importable: the fastlane decoder is missing")
    return I.intake_one("77", CSCTF, adapter=_Adapter(files), workdir=tmp_path / "wd", options=_opts())


def test_base64_noise_that_xor_decodes_to_a_control_character_body_is_never_solved(tmp_path, monkeypatch):
    rep = _intake(tmp_path, monkeypatch, {"cipher.txt": _b64_noise(2, 11)})
    noise = [h for h in rep.fastlane if h.verdict == D.NOISE]
    assert noise, ("precondition: the decoder no longer reads a flag shape from this noise blob; "
                   f"pick a new reproduction ({rep.fastlane})")
    assert rep.status == "none" and rep.flags == {}
    assert any("control" in w for w in rep.excluded.values())
    assert any("fastlane:" in n and "control" in n for n in rep.notes)


def test_base64_noise_with_a_printable_body_from_a_loose_chain_is_only_a_candidate(tmp_path, monkeypatch):
    rep = _intake(tmp_path, monkeypatch, {"cipher.txt": _b64_noise(3, 106)})
    weak = [h for h in rep.fastlane if h.verdict == D.UNCONFIRMED]
    assert weak, ("precondition: the decoder no longer reads a printable flag shape from this noise "
                  f"blob; pick a new reproduction ({rep.fastlane})")
    assert rep.status == "candidate"
    assert set(rep.unconfirmed) == set(rep.result.flags)


def test_a_real_single_byte_xor_flag_is_still_solved(tmp_path, monkeypatch):
    flag = "CSCTF{xor_alone}"
    rep = _intake(tmp_path, monkeypatch, {"x.bin": bytes(b ^ 0x42 for b in flag.encode())})
    assert rep.status == "solved" and list(rep.flags) == [flag]
    assert any("fastlane decode" in w for w in rep.flags[flag])


def test_two_files_with_different_decoded_flags_make_a_candidate(tmp_path, monkeypatch):
    a, b = "CSCTF{first_file}", "CSCTF{second_file}"
    enc = lambda f: base64.b64encode(f.encode()).decode()[::-1].encode()   # noqa: E731
    rep = _intake(tmp_path, monkeypatch, {"a.txt": enc(a), "b.txt": enc(b)})
    assert rep.status == "candidate" and sorted(rep.result.flags) == [a, b]
