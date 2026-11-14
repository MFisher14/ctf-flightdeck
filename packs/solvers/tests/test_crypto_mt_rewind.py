"""B-063: MT19937 backwards in solvers/common/modern_crypto.py (inverse twist, rewind, run detector,
seed boundary).

Ground truth never comes from the code under test. CPython's own generator (`random.Random`) gives
outputs, and its `getstate()` gives the raw state words and the freshly seeded state. `RefMT` is the
reference mt19937ar generator written out here, anchored on the two outputs the C++ standard fixes for
`std::mt19937` (seed 5489: first output 3499211612, 10000th 4123659995). Everything is synthetic.
"""
from __future__ import annotations

import hashlib
import random

import pytest

from _shadowed import common_module

mc = common_module("modern_crypto")

M = 0xFFFFFFFF
TOP = 0x80000000


class RefMT:
    """mt19937ar as published (init_genrand seeding)."""

    def __init__(self, seed: int):
        self.mt = [seed & M]
        for i in range(1, 624):
            self.mt.append((1812433253 * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + i) & M)
        self.seeded = list(self.mt)
        self.mti = 624

    def word(self) -> int:
        """The next raw state word."""
        if self.mti >= 624:
            mt = self.mt
            for kk in range(624):
                y = (mt[kk] & 0x80000000) | (mt[(kk + 1) % 624] & 0x7FFFFFFF)
                mt[kk] = mt[(kk + 397) % 624] ^ (y >> 1) ^ (0x9908B0DF if y & 1 else 0)
            self.mti = 0
        self.mti += 1
        return self.mt[self.mti - 1]

    def u32(self) -> int:
        y = self.word()
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        return (y ^ (y >> 18)) & M


def py_stream(seed, generations: int):
    """(freshly seeded state, outputs, raw state words) of a CPython generator over whole twists."""
    r = random.Random(seed)
    seeded = list(r.getstate()[1][:624])
    outputs, words = [], []
    for _ in range(generations):
        outputs += [r.getrandbits(32) for _ in range(624)]
        words += list(r.getstate()[1][:624])
    return seeded, outputs, words


SEEDED, OUT, X = py_stream(20261107, 7)          # 4368 outputs and the state words behind them


def test_reference_generator_matches_the_standard_vectors():
    g = RefMT(5489)
    values = [g.u32() for _ in range(10000)]
    assert values[0] == 3499211612 and values[9999] == 4123659995


def test_temper_and_untemper_agree_with_cpython():
    assert [mc.mt_temper(v) for v in X[:1000]] == OUT[:1000]
    assert [mc.mt_untemper(v) for v in OUT[:1000]] == X[:1000]


# ---- inverse twist ---------------------------------------------------------------------------------

def test_untwist_gives_the_generation_before():
    assert mc.mt_untwist(X[624:1248]) == X[:624]
    assert mc.mt_untwist(X[1248:1872]) == X[624:1248]
    assert mc._mt_twist(mc.mt_untwist(X[1248:1872])) == X[1248:1872]


def test_untwist_reaches_the_seeded_state_except_the_bits_the_twist_never_reads():
    before = mc.mt_untwist(X[:624])
    assert before[1:] == SEEDED[1:]
    assert before[0] & TOP == SEEDED[0] & TOP
    assert mc._mt_twist(before) == X[:624]


def test_untwist_refuses_what_no_twist_produces():
    assert mc.mt_untwist(SEEDED) is None                     # a seeded state is not a twist output
    for index in (0, 396, 623):
        broken = list(X[624:1248])
        broken[index] ^= 1
        assert mc.mt_untwist(broken) is None, index
    assert mc.mt_untwist(X[624:1247]) is None                # 623 words
    assert mc.mt_untwist(X[624:1249]) is None                # 625 words
    assert mc.mt_untwist([float(v) for v in X[624:1248]]) is None
    assert mc.mt_untwist([True] + X[625:1248]) is None
    assert mc.mt_untwist([1 << 32] + X[625:1248]) is None
    assert mc.mt_untwist([-1] + X[625:1248]) is None
    assert mc.mt_untwist(None) is None


# ---- rewind ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("start, given, count", [
    (624, 624, 624),          # a whole generation back from a generation boundary
    (1000, 700, 1000),        # mid-generation, back over two boundaries to the first output
    (2000, 624, 1),           # the single output before
    (1300, 1248, 37),
])
def test_rewind_returns_the_outputs_that_came_before(start, given, count):
    got = mc.mt_rewind(OUT[start:start + given], count)
    assert got == (OUT[start - count:start], given - 624)


def test_rewind_reads_and_returns_raw_state_words_when_told():
    assert mc.mt_rewind(X[900:1600], 300, tempered=False) == (X[600:900], 76)
    assert mc.mt_rewind(X[900:1600], 300) is None            # state words are not outputs
    assert mc.mt_rewind(OUT[900:1600], 300, tempered=False) is None


def test_rewind_with_no_further_output_reports_zero_verified():
    previous, verified = mc.mt_rewind(OUT[1000:1624], 5)
    assert previous == OUT[995:1000] and verified == 0


def test_rewind_refuses_words_that_do_not_follow_the_recurrence():
    # 76 further outputs: their steps read words 0-76 and 397-472, and the self-check reads 0, 396, 623
    for index in (0, 1, 50, 76, 396, 397, 472, 623, 624, 699):
        broken = list(OUT[1000:1700])
        broken[index] ^= 1 << 7
        assert mc.mt_rewind(broken, 10) is None, index
    # 624 further outputs read every word
    for index in (77, 300, 473, 622, 1000, 1247):
        broken = list(OUT[1000:2248])
        broken[index] ^= 1 << 7
        assert mc.mt_rewind(broken, 10) is None, index
    # the self-check is what protects a bare 624-word window
    for index in (0, 396, 623):
        broken = list(X[1000:1624])
        broken[index] ^= 1
        assert mc.mt_rewind(broken, 10, tempered=False) is None, index
    # the top bit of a word is read by the step 624 later
    broken = list(X[1000:1700])
    broken[3] ^= TOP
    assert mc.mt_rewind(broken, 10, tempered=False) is None
    # a foreign word after the stream
    assert mc.mt_rewind(OUT[1000:1700] + [OUT[1700] ^ 1], 10) is None


def test_rewind_bounds():
    window = OUT[1000:1700]
    assert mc.mt_rewind(window[:623], 1) is None
    assert mc.mt_rewind(window, 0) is None
    assert mc.mt_rewind(window, -1) is None
    assert mc.mt_rewind(window, True) is None
    assert mc.mt_rewind(window, 1.0) is None
    assert mc.mt_rewind(window, mc.MAX_MT_REWIND + 1) is None
    assert mc.mt_rewind(window + ["x"], 1) is None
    assert mc.mt_rewind(window + [1 << 32], 1) is None
    assert mc.MAX_PRNG_WORDS == 4096                         # the input cap it shares with mt_clone
    assert mc.mt_rewind(OUT[100:100 + 4096], 1) == ([OUT[99]], 4096 - 624)
    assert mc.mt_rewind(OUT[100:100 + 4097], 1) is None      # a real stream, one word over the cap
    assert mc.mt_rewind(OUT[2000:2700], 2000)[0] == OUT[:2000]
    assert len(mc.mt_rewind(OUT[2000:2700], mc.MAX_MT_REWIND)[0]) == 65536


def test_extend_gives_the_words_on_both_sides():
    before, after = mc.mt_extend(X[1000:1624], before=1000, after=2000)
    assert before == X[:1000] and after == X[1624:3624]
    assert mc.mt_extend(X[1000:1624]) == ([], [])
    assert mc.mt_extend(X[1000:1624], after=1) == ([], [X[1624]])
    assert mc.mt_extend(X[1000:1624], before=1) == ([X[999]], [])
    # back through the seeding: the seeded words, then what the recurrence implies before them
    before, _ = mc.mt_extend(X[:624], before=624)
    assert before[1:] == SEEDED[1:]


def test_extend_bounds():
    window = X[1000:1624]
    broken = list(window)
    broken[0] ^= 1
    assert mc.mt_extend(broken, before=1) is None
    assert mc.mt_extend(window[:623], before=1) is None
    assert mc.mt_extend(X[1000:1625], before=1) is None
    assert mc.mt_extend(window, before=-1) is None
    assert mc.mt_extend(window, after=-1) is None
    assert mc.mt_extend(window, before=True) is None
    assert mc.mt_extend(window, before=mc.MAX_MT_REWIND + 1) is None
    assert mc.mt_extend(window, after=mc.MAX_MT_REWIND + 1) is None


# ---- run detector ----------------------------------------------------------------------------------

JUNK = [int.from_bytes(hashlib.sha256(b"not mt %d" % i).digest()[:4], "big") for i in range(200)]


def test_runs_finds_a_stream_that_is_the_whole_list():
    assert mc.mt_runs(OUT[:1248]) == [{"mode": "outputs", "start": 0, "length": 1248, "verified": 624}]
    assert mc.mt_runs(X[700:1500]) == [{"mode": "state", "start": 0, "length": 800, "verified": 176}]


def test_runs_finds_a_stream_between_foreign_words():
    words = JUNK[:50] + OUT[300:1600] + JUNK[50:57]
    assert mc.mt_runs(words) == [{"mode": "outputs", "start": 50, "length": 1300, "verified": 676}]


@pytest.mark.parametrize("same_top_bit", [True, False])
def test_a_foreign_word_in_front_is_never_taken_into_the_run(same_top_bit):
    # The step that made the run's 625th word read one bit (the top one) of the word in front of the
    # run. A foreign word there passes that step when its top bit happens to be right: only the
    # self-check keeps it out.
    true_before = X[299]
    foreign = (true_before ^ 0x1234567) if same_top_bit else (true_before ^ TOP ^ 0x1234567)
    assert (foreign & TOP == true_before & TOP) is same_top_bit
    assert mc.mt_runs([foreign] + X[300:1100], modes=("state",)) == [
        {"mode": "state", "start": 1, "length": 800, "verified": 176}]
    words = [mc.mt_temper(foreign)] + OUT[300:1100]
    assert mc.mt_runs(words, modes=("outputs",)) == [
        {"mode": "outputs", "start": 1, "length": 800, "verified": 176}]


def test_a_bare_window_is_reported_unverified():
    assert mc.mt_runs(OUT[1000:1624]) == [{"mode": "outputs", "start": 0, "length": 624, "verified": 0}]
    words = JUNK[:10] + OUT[1000:1624] + JUNK[10:30]
    assert mc.mt_runs(words) == [{"mode": "outputs", "start": 10, "length": 624, "verified": 0}]


def test_one_further_word_makes_a_run_verified():
    assert mc.mt_runs(JUNK[:3] + OUT[1000:1625] + JUNK[3:6]) == [
        {"mode": "outputs", "start": 3, "length": 625, "verified": 1}]


def test_two_streams_in_one_list_are_two_runs():
    second = random.Random(7)
    other = [second.getrandbits(32) for _ in range(700)]
    assert mc.mt_runs(OUT[:650] + other) == [
        {"mode": "outputs", "start": 0, "length": 650, "verified": 26},
        {"mode": "outputs", "start": 650, "length": 700, "verified": 76}]
    # runs come in list order, whether or not they are verified
    assert mc.mt_runs(OUT[1000:1624] + JUNK[:2] + other + X[:624]) == [
        {"mode": "outputs", "start": 0, "length": 624, "verified": 0},
        {"mode": "outputs", "start": 626, "length": 700, "verified": 76},
        {"mode": "state", "start": 1326, "length": 624, "verified": 0}]


def test_runs_modes_are_separate_readings():
    assert mc.mt_runs(OUT[:700], modes=("state",)) == []
    assert mc.mt_runs(X[:700], modes=("outputs",)) == []
    assert mc.mt_runs(X[:700], modes=("state", "state")) == [
        {"mode": "state", "start": 0, "length": 700, "verified": 76}]
    assert mc.mt_runs(OUT[:700], modes=("sideways",)) is None
    assert mc.mt_runs(OUT[:700], modes=()) is None
    assert mc.mt_runs(OUT[:700], modes=None) is None


def test_runs_finds_nothing_in_words_that_are_not_a_stream():
    assert mc.mt_runs(OUT[:623]) == []
    assert mc.mt_runs([]) == []
    assert mc.mt_runs(JUNK * 8) == []
    for index in (0, 396, 623):                    # the three words a bare window's self-check reads
        broken = list(OUT[:624])
        broken[index] ^= 4
        assert mc.mt_runs(broken) == [], index


def test_a_damaged_word_ends_a_run_at_the_first_step_that_reads_it():
    # A run is a stretch in which every step that can be checked holds. Word 500 of 1000 is read by
    # the steps that make words 727, 1123 and 1124 and by the self-check of the window at 104: so one
    # stretch ends at 727, the other starts at 105, and each holds the damaged word where none of its
    # own steps reads it. Fewer than 624 verified words never cover every given word.
    broken = list(OUT[:1000])
    broken[500] ^= 4
    assert mc.mt_runs(broken) == [{"mode": "outputs", "start": 0, "length": 727, "verified": 103},
                                  {"mode": "outputs", "start": 105, "length": 895, "verified": 271}]
    # 624 verified words read every word of the run: a damaged word cannot sit inside such a run
    broken = list(OUT[:3000])
    broken[1500] ^= 4
    full = [r for r in mc.mt_runs(broken) if r["verified"] >= 624]
    assert full == [{"mode": "outputs", "start": 0, "length": 1500, "verified": 876},
                    {"mode": "outputs", "start": 1501, "length": 1499, "verified": 875}]


def test_small_and_structured_numbers_are_never_runs():
    # Zeros are the generator's fixed point and satisfy every check; a counter satisfies the 31-bit
    # self-check by accident (at index 718 of range(2000)). Neither looks like random words.
    assert mc.mt_runs([0] * 2000) == []
    assert mc.mt_runs(list(range(2000))) == []
    assert mc._mt_window_ok(list(range(718, 718 + 624)))          # the accident the balance test removes
    assert mc.mt_runs([v & 0xFFFF for v in OUT[:1300]]) == []
    assert mc.mt_runs([TOP] * 700) == []


def _passing_window(words):
    """624 words made to pass the 31-bit self-check by fixing three of them (x[0]'s low bit and
    x[623]), keeping every word's top bit and width as it was."""
    x = list(words)
    x[0] &= ~1
    x[623] = x[396] ^ ((x[0] & 0x7FFFFFFF) >> 1)
    assert mc._mt_window_ok(x)
    return x


def test_a_window_that_passes_the_self_check_must_still_look_random():
    real = _passing_window(JUNK * 4)                             # 800 hash words: balanced in every bit
    assert mc.mt_runs(real[:624], modes=("state",)) == [{"mode": "state", "start": 0, "length": 624, "verified": 0}]
    top_set = _passing_window([v | TOP for v in JUNK * 4])       # bit 31 in every word
    assert mc.mt_runs(top_set[:624], modes=("state",)) == []
    half_width = _passing_window([v & 0xFFFF for v in JUNK * 4])  # bits 16-31 in no word
    assert mc.mt_runs(half_width[:624], modes=("state",)) == []
    low_clear = _passing_window([v & ~0x10 for v in JUNK * 4])    # one low bit in (almost) no word
    assert mc.mt_runs(low_clear[:624], modes=("state",)) == []


def test_runs_bounds(monkeypatch):
    assert mc.mt_runs(OUT[:700] + [1 << 32]) is None
    assert mc.mt_runs(OUT[:700] + [-1]) is None
    assert mc.mt_runs(OUT[:700] + [1.5]) is None
    assert mc.mt_runs(OUT[:700] + [True]) is None
    assert mc.mt_runs(5) is None
    monkeypatch.setattr(mc, "MAX_MT_SCAN_WORDS", 700)
    assert mc.mt_runs(OUT[:700]) == [{"mode": "outputs", "start": 0, "length": 700, "verified": 76}]
    assert mc.mt_runs(OUT[:701]) is None


# ---- seed boundary ---------------------------------------------------------------------------------

@pytest.mark.parametrize("seed", [0, 1, 1234, 0xFFFFFFFF, 1 << 32, (1 << 64) + 5, (1 << 2000) + 987654321])
def test_seed_of_a_cpython_integer_seed(seed):
    state = list(random.Random(seed).getstate()[1][:624])
    got = mc.mt_seed_from_state(state)
    assert got["kind"] == "init_by_array" and got["python_seed"] == seed
    assert got["key"] == [seed >> 32 * i & M for i in range(max(1, (seed.bit_length() + 31) // 32))]
    assert "python_seed_bytes" not in got


@pytest.mark.parametrize("seed", ["hello world", b"\x01\x02key\xff", "", "a much longer passphrase " * 5])
def test_seed_of_a_cpython_text_or_bytes_seed(seed):
    state = list(random.Random(seed).getstate()[1][:624])
    got = mc.mt_seed_from_state(state)
    raw = seed.encode() if isinstance(seed, str) else seed
    assert got["python_seed_bytes"] == raw.hex()
    assert list(random.Random(got["python_seed"]).getstate()[1][:624]) == state


def test_seed_reported_is_the_shortest_key_that_gives_the_state():
    # key[j] + j is what the seeding adds: [5, 4] adds 5 every time, exactly like [5]
    twin = (4 << 32) | 5
    state = list(random.Random(twin).getstate()[1][:624])
    assert state == list(random.Random(5).getstate()[1][:624])
    assert mc.mt_seed_from_state(state)["python_seed"] == 5


def test_seed_key_length_bound():
    seed = (1 << 32 * 64) + 3                        # a 65-word key
    state = list(random.Random(seed).getstate()[1][:624])
    assert mc.mt_seed_from_state(state) is None
    assert mc.mt_seed_from_state(state, max_key_words=65)["python_seed"] == seed
    assert mc.mt_seed_from_state(state, max_key_words=64) is None
    assert mc.mt_seed_from_state(state, max_key_words=0) is None
    assert mc.mt_seed_from_state(state, max_key_words=mc.MAX_MT_SEED_KEY_WORDS + 1) is None
    assert mc.mt_seed_from_state(state, max_key_words=True) is None
    longest = (1 << 32 * 309) + 3                    # 310 words: the most the inversion can prove
    state = list(random.Random(longest).getstate()[1][:624])
    assert mc.mt_seed_from_state(state, max_key_words=310)["python_seed"] == longest


@pytest.mark.parametrize("seed", [0, 1, 5489, TOP, 0xFFFFFFFF, 20261107])
def test_seed_of_an_init_genrand_state(seed):
    assert mc.mt_seed_from_state(RefMT(seed).seeded) == {"kind": "init_genrand", "seed": seed}


@pytest.mark.needs_tool("py:numpy")
def test_seed_of_a_numpy_randomstate():
    import numpy as np
    rs = np.random.RandomState(4242)
    assert mc.mt_seed_from_state([int(v) for v in rs.get_state()[1]]) == {"kind": "init_genrand", "seed": 4242}


def test_seed_compares_only_the_top_bit_of_word_zero():
    for state in (SEEDED, RefMT(5489).seeded, RefMT(TOP | 77).seeded):
        want = mc.mt_seed_from_state(state)
        assert want is not None
        low = list(state)
        low[0] ^= 0x7654321
        assert mc.mt_seed_from_state(low) == want
        top = list(state)
        top[0] ^= TOP
        assert mc.mt_seed_from_state(top) is None


def test_seed_is_none_for_states_that_were_not_just_seeded():
    assert mc.mt_seed_from_state(X[:624]) is None                         # one twist later
    assert mc.mt_seed_from_state(JUNK[:200] * 3 + JUNK[:24]) is None
    for index in (1, 2, 3, 300, 623):
        for state in (SEEDED, RefMT(5489).seeded):
            broken = list(state)
            broken[index] ^= 1
            assert mc.mt_seed_from_state(broken) is None, index
    assert mc.mt_seed_from_state(SEEDED[:623]) is None
    assert mc.mt_seed_from_state(SEEDED + [1]) is None
    assert mc.mt_seed_from_state(SEEDED[:623] + [1 << 32]) is None
    assert mc.mt_seed_from_state("x") is None


@pytest.mark.parametrize("k", [0, 1, 100, 623, 624, 625, 2000])
def test_seed_search_counts_the_outputs_before_the_window(k):
    assert mc.mt_seed_search(X[k:k + 624]) == {
        "outputs_before": k, "kind": "init_by_array", "key": [20261107], "python_seed": 20261107}


def test_seed_search_on_an_init_genrand_stream():
    g = RefMT(5489)
    words = [g.word() for _ in range(1500)]
    assert mc.mt_seed_search(words[777:777 + 624]) == {"outputs_before": 777, "kind": "init_genrand", "seed": 5489}


def test_seed_search_range_and_bounds():
    window = X[1000:1624]
    assert mc.mt_seed_search(window, max_outputs=1000)["outputs_before"] == 1000
    assert mc.mt_seed_search(window, max_outputs=999) is None
    assert mc.mt_seed_search(X[:624], max_outputs=0)["outputs_before"] == 0
    assert mc.mt_seed_search(window, max_outputs=-1) is None
    assert mc.mt_seed_search(window, max_outputs=True) is None
    assert mc.mt_seed_search(window, max_outputs=mc.MAX_MT_REWIND - 623) is None
    assert mc.mt_seed_search(window, max_key_words=0) is None
    assert mc.mt_seed_search(window, max_key_words=mc.MAX_MT_SEED_KEY_WORDS + 1) is None
    broken = list(window)
    broken[0] ^= 1
    assert mc.mt_seed_search(broken) is None
    assert mc.mt_seed_search(window[:623]) is None
    wide = list(random.Random((1 << 32 * 64) + 3).getstate()[1][:624])
    after = mc._mt_twist(wide)
    assert mc.mt_seed_search(after) is None                               # a 65-word key: out of default reach
    assert mc.mt_seed_search(after, max_key_words=65)["outputs_before"] == 0


def test_seed_search_reports_the_nearest_boundary_when_two_are_in_reach(monkeypatch):
    # A real stream has one seeding in reach (the words before it are extrapolation), so two boundaries
    # are planted by standing in for the per-offset seed test; the search itself runs unchanged.
    window, reach = X[2000:2624], 20                         # the real seeding (2000 back) is out of reach
    planted = {3: {"kind": "init_genrand", "seed": 3}, 9: {"kind": "init_genrand", "seed": 9}}
    real = mc._mt_seed_at
    asked = []

    def seed_at(x, at, max_key_words):
        k = reach - at                                       # the window starts at reach + 624 in x
        asked.append(k)
        return planted[k] if k in planted else real(x, at, max_key_words)

    monkeypatch.setattr(mc, "_mt_seed_at", seed_at)
    assert mc.mt_seed_search(window, max_outputs=reach) == {"outputs_before": 3, "kind": "init_genrand", "seed": 3}
    assert asked == [0, 1, 2, 3]                             # nearest first, and it stops at the first found
    del planted[3]
    assert mc.mt_seed_search(window, max_outputs=reach)["outputs_before"] == 9
    planted.clear()
    assert mc.mt_seed_search(window, max_outputs=reach) is None


def test_seed_search_default_reach_is_the_documented_one():
    assert mc.MT_SEED_SEARCH == 4096 and mc.MT_SEED_KEY_WORDS == 64
    _, _, words = py_stream(31337, 8)
    assert mc.mt_seed_search(words[4096:4096 + 624])["outputs_before"] == 4096
    assert mc.mt_seed_search(words[4097:4097 + 624]) is None
