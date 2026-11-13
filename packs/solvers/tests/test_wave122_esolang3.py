#!/usr/bin/env python3
"""Permanent battery for the wave 122 Warmups esolang build (2026-10-24): ><> (Fish) and LOLCODE.

  .venv/bin/python -m pytest tests/test_wave122_esolang3.py   (or `python tests/test_wave122_esolang3.py`)

  interp    each interpreter's own encoder round-trips through its reader (the straight-line Fish
            encoder, the LOOPING Fish encoder that exercises 2D geometry / string mode / l / ? / ! /
            grid wrap, and both LOLCODE encoders); Fish arithmetic and numeric (`n`) output; the
            mirror geometry; LOLCODE SUM / SMOOSH / variables / BTW+OBTW comments / string escapes;
            strict refusals (Fish: i input, x random, g / p codebox reflection, [ stack-of-stacks,
            underflow, divide-by-zero, a non-integral `n` rendering, an unmodelled executed char, and
            a non-halting program; LOLCODE: GIMMEH, a loop, a conditional, a NUMBAR float, QUOSHUNT,
            printing a NOOB, a missing HAI / KTHXBYE, an unknown escape, assigning an undeclared var)
            all yield None; determinism (the same bytes twice); the three bounds of the Fish VM (the
            cycle guard, the step cap, the time backstop), each proven by a step count, not a time.
  wired     esolang3.py is imported by crib_decode.py with the esolang guard pattern: ESL3 is live,
            its names are strict, _step_fn resolves them, and a Fish / LOLCODE program that prints the
            sentence is answered PLAIN and right through the real solve_blob (3 fresh slugs each, the
            looping Fish encoder among them, and a slug whose trailing digits come from Fish `n`),
            including under an outer base64 layer.
  wrong     decoys (a Fish / LOLCODE program that prints something other than the sentence) and noise
            (random bytes under each language's structure) never give a wrong plain slug; a reader
            whose output breaks the 87-char crib prefix returns NOTHING, never a truncated slug.
  regress   plain / hex / base64 / base32 / rot13 of the sentence still read right and their chains
            name no esolang3 step; _which on a base64 payload is a cheap no-op (no interpreter runs).
  saved     no saved Warmups payload (whole blob or numbered record) is read by any esolang3 reader
            (not run unless $CTF_REAL_CHALLENGES names the saved attempts).
"""
import base64
import codecs
import glob
import json
import os
import random
import sys
import types
from pathlib import Path

import pytest

from ctf import paths

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parent.parent
for _p in (REPO / "solvers" / "common", REPO / "solvers" / "warmups"):
    sys.path.insert(0, str(_p))

import crib_decode as C  # noqa: E402
import esolang3 as E  # noqa: E402

sys.path.insert(0, str(REPO / "tests"))
import sh09_clocks as K  # noqa: E402  (cpu_clock + thread_seconds: load-independent budgets and bounds, SH-08/SH-09)

SENT = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
rnd = random.Random(122)
def check(ok, name, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ((" :: " + str(detail)) if detail and not ok else ""))
    assert ok, name + ((" :: " + str(detail)) if detail else "")


def slug():
    a = ["brave", "crisp", "nimble", "dainty", "quick", "jolly"]
    b = ["blanket", "compass", "canyon", "quill", "zephyr", "castle"]
    c = ["clover", "coral", "birch", "laurel", "pine", "fjord"]
    return "%s-%s-%s-%02d" % (rnd.choice(a), rnd.choice(b), rnd.choice(c), rnd.randint(10, 99))


def solve(blob, budget=None):
    kw = {} if budget is None else {"budget": budget}
    got = C.solve_blob(blob if isinstance(blob, bytes) else blob.encode(), day=25, **kw)
    return (got[0] if got else None), (got[1] if got else None)

# The wired reads are correctness checks (a dialect program is answered PLAIN and right), not timing
# checks: solve_blob's budget is wall-clock, and under a loaded full-suite run (xdist workers beside other
# jobs) the default budget occasionally ran out before the dialect step and the read came back None
# (R-01; the same reasoning as tests/test_warmups_day16.py). The regress test still bounds the common path.
# The raised budget was not enough: the readers' own caps are wall clock too (esolang3.READER_TIME, 20 ms a
# call, and TOTAL_CAP, 50 ms a blob), and a full-suite run cut the looping Fish read with them, so another
# reader answered and the chain named no `fish` (SH-12; the same defect SH-09 fixed for esolang and
# esolang2). So the wired reads run on the CPU clock (sh09_clocks.cpu_clock): every budget and cap keeps its
# production number, counted in seconds of this process's work, which waiting for a core does not spend.
# The looping Fish read, the longest, takes about 4 ms of CPU against the 20 ms cap.
WIRED_BUDGET = 5.0


def solve_wired(blob):
    with K.cpu_clock():
        return solve(blob, budget=WIRED_BUDGET)


def plain_ok(ans, truth):
    if ans == truth:
        return True
    return isinstance(ans, str) and ans.startswith("??") and (json.dumps(truth) in ans or truth in ans)


def wrong_plain(ans, truth):
    return isinstance(ans, str) and not ans.startswith("??") and ans != truth


# A padded Fish program: 20 no-op spaces so the >=16-byte MIN_PROG gate passes and the pointer reaches
# `body` (spaces are no-ops the pointer walks over), so a refusal here is the interpreter's, not the gate's.
def fish(body):
    return (" " * 20 + body).encode("latin-1")


# A straight-line Fish program that prints `prefix` with `o` and then the integer `number` with `n`,
# so the test exercises the numeric-output path end to end (used by the mixed wired case).
def fish_num_tail(prefix, number):
    rev = prefix[::-1]
    digits = "".join(d + "n" for d in str(number))
    return ("'" + rev + "'" + "o" * len(prefix) + digits + ";").encode("latin-1")


# How the Fish VM stopped on `prog`, and the steps it ran. Steps are counted, not timed, with an injected step
# clock (rule 16, SH-08 method): with TICK = 1 the VM looks at its clock once on every step it runs, so the
# clock reads are the steps, and the clock's time IS the step number (the k-th look reads k). The VM has three
# bounds, and each can be made the one that ends a run:
#   the cycle guard    on by default; guard=False turns it off (no state is ever snapshot), which stands in
#                      for a loop whose state never repeats
#   the step cap       STEPS is cut to `cap`, so a loop the guard does not end stops there, not at 2M steps
#   the time backstop  off by default (the deadline is never reached); deadline=k is passed after step k
# Only esolang3's own view of `time` is replaced, and only for the call. A VM that no bound ends would hang
# the test, so the clock itself fails the test once the VM has run twice the step cap.
def fish_steps(prog, cap=1000, guard=True, deadline=float("inf")):
    reads = []

    def look():
        reads.append(1)
        assert len(reads) <= 2 * cap, "the Fish VM ran %d steps: past its step cap (%d) and every bound" % (len(reads), cap)
        return len(reads)

    step_clock = types.SimpleNamespace(perf_counter=look)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(E, "time", step_clock)
        mp.setattr(E, "TICK", 1)
        mp.setattr(E, "STEPS", cap)
        if not guard:
            mp.setattr(E, "FISH_CYCLE_STACK", -1)
        try:
            E._fish_run(E._text(prog), deadline)
            how = "returned"            # the VM loop must end by _Halt or _Refuse, never by falling out
        except E._Halt as h:
            how = ("halt", h.args[0])
        except E._Refuse:
            how = "refuse"
    return how, len(reads)


# ---- interp --------------------------------------------------------------------------------------
@pytest.fixture
def standalone_readers():
    """Run the readers standalone (no blob deadline). crib_decode's search leaves its last blob
    deadline in formats_more.DEADLINE (and esolang3.DEADLINE) after it returns, so a test of the
    same xdist worker that searched earlier would otherwise cap these round-trips at a past time
    and the Fish reader would give up at once (order-dependent failure, batch 9)."""
    import formats_more as FM
    held = (E.DEADLINE[0], FM.DEADLINE[0])
    E.DEADLINE[0] = FM.DEADLINE[0] = None
    yield
    E.DEADLINE[0], FM.DEADLINE[0] = held


# test_interp checks what the interpreters print and refuse, not how fast this machine runs them. But every
# d_fish / d_lolcode call carries esolang3's own time backstop: READER_TIME, 20 ms of WALL clock by default,
# looked at every TICK (4096) steps. The looping Fish round-trip runs about 12,900 steps (4 ms of CPU), so
# it looks at the clock three times; under full-suite load a process that waited for a core before one of
# those looks was past the 20 ms, the reader gave None, and "fish looping encoder round-trip" failed. That
# is every test_interp failure the merge queue recorded (SH-12). So the test gives the interpreters an
# explicit budget on the CPU clock (rule 16): inside sh09_clocks.cpu_clock() the backstop counts this
# process's CPU time, which waiting for a core does not spend, and READER_TIME is INTERP_READER_TIME, far
# above any program here and still finite. Nothing in the test waits, so nothing can hang on the CPU clock.
# That the backstop still fires, and on which step, is proven in the test with a step clock (fish_steps).
INTERP_READER_TIME = 5.0     # seconds of this process's CPU time one reader call may take in test_interp


@pytest.fixture
def interp_budget():
    with K.cpu_clock(), pytest.MonkeyPatch.context() as mp:
        mp.setattr(E, "READER_TIME", INTERP_READER_TIME)
        yield


@pytest.mark.usefixtures("standalone_readers", "interp_budget")
def test_interp():
    # the budget is in force (a test that lost the fixture would go back to the 20 ms wall backstop)
    check(E.time.perf_counter is E.time.process_time and E.READER_TIME == INTERP_READER_TIME,
          "interp: the readers run on the explicit CPU-clock budget")

    for name, enc in E.ENCODERS.items():
        data = (SENT + slug()).encode()
        check(E.BY_NAME[name](enc(data)) == data, "interp: %s encode/decode round-trip" % name)

    # the LOOPING Fish encoder (2D geometry, string mode, l, ?, !, v, >, grid wrap) round-trips too
    data = (SENT + slug()).encode()
    check(E.d_fish(E.fish_encode_loop(data)) == data, "interp: fish looping encoder round-trip (2D/trampoline)")

    # both LOLCODE encoders: no-newline (== data) and default trailing newline (== data + b"\n")
    data = (SENT + slug()).encode()
    check(E.d_lolcode(E.lolcode_encode(data)) == data, "interp: lolcode encoder (VISIBLE ... !) round-trip")
    check(E.d_lolcode(E.lolcode_encode_nl(data)) == data + b"\n", "interp: lolcode encoder (trailing newline) round-trip")

    # Fish arithmetic, numeric output and char output.
    check(E.d_fish(fish("42*n;")) == b"8", "interp: fish arithmetic 4*2 printed with n")
    check(E.d_fish(fish("62,n;")) == b"3", "interp: fish integral float 6/2 printed with n as 3")
    check(E.d_fish(fish("'A'o;")) == b"A", "interp: fish char output o of a string-mode byte")

    # Fish mirror geometry (the pure reflection function).
    check(E._fish_mirror("/", 1, 0) == (0, -1), "interp: fish mirror / turns right-moving IP up")
    check(E._fish_mirror("\\", 1, 0) == (0, 1), "interp: fish mirror \\ turns right-moving IP down")
    check(E._fish_mirror("|", 1, 0) == (-1, 0), "interp: fish mirror | flips horizontal direction")
    check(E._fish_mirror("_", 0, 1) == (0, -1), "interp: fish mirror _ flips vertical direction")
    check(E._fish_mirror("#", 1, 0) == (-1, 0), "interp: fish mirror # reverses direction")

    # Fish strict refusals (each instruction is reached; the program clears MIN_PROG).
    check(E.d_fish(fish("i;")) is None, "interp: fish input i -> None")
    check(E.d_fish(fish("x;")) is None, "interp: fish random direction x -> None")
    check(E.d_fish(fish("00g;")) is None, "interp: fish codebox read g -> None")
    check(E.d_fish(fish("000p;")) is None, "interp: fish codebox write p -> None")
    check(E.d_fish(fish("1[;")) is None, "interp: fish stack-of-stacks [ -> None")
    check(E.d_fish(fish("+;")) is None, "interp: fish stack underflow -> None")
    check(E.d_fish(fish("10,n;")) is None, "interp: fish divide-by-zero -> None")
    check(E.d_fish(fish("10%n;")) is None, "interp: fish mod-by-zero -> None")
    check(E.d_fish(fish("72,n;")) is None, "interp: fish non-integral n (7/2) is author-ambiguous -> None")
    check(E.d_fish(fish("Z;")) is None, "interp: fish unmodelled executed char -> None")

    # Fish non-halting: '>' then spaces, no ';' ever reached; the deterministic VM revisits a full machine
    # state, so the interpreter's cycle guard refuses it -> None (the time backstop and the 2M step cap are
    # the fallbacks). Detection must stay bounded, but a bound on wall time (the old
    # `time.perf_counter() - t0 < 1.0`) also counts the time the process waits for a core (SH-12). So the
    # bound is on this thread's CPU time (SH-08/SH-09 method, tests/sh08_drivers.py). The cycle guard makes
    # the real cost microseconds; 1.0 s of CPU is a loose, load-independent ceiling that still fails if
    # detection ever fell through to the test's 5 s backstop. The exact bounds are the step counts below.
    r, cpu = K.thread_seconds(E.d_fish, b">               ")  # 16 bytes
    check(r is None and cpu < 1.0, "interp: fish non-halting loop -> None (bounded, CPU time)", round(cpu, 6))

    # ... and it is the CYCLE GUARD that refuses it, at the first repeated state. The None above cannot tell
    # that: the step cap and the time backstop also end in None, only later (and the 1.0 s ceiling is far
    # above either). So count the VM's steps: the 16-cell row gives 16 distinct states, one per cell, and the
    # 17th step is back at cell 0 in the first state -> refused there, by an exception (not by leaving the
    # loop, which d_fish would also read as None). A VM without the guard runs to the step cap instead.
    check(fish_steps(b">               ") == ("refuse", 17),
          "interp: fish non-halting loop is refused by the cycle guard on the first repeated state (step 17)",
          fish_steps(b">               "))
    # the step counter itself: a halting program stops by _Halt with its output after exactly its own steps
    # (20 pad cells, then ' A ' o ;), so the guard and the cut step cap do not touch a program that halts.
    check(fish_steps(fish("'A'o;")) == (("halt", b"A"), 25),
          "interp: fish halting program halts with its output after its 25 steps", fish_steps(fish("'A'o;")))

    # The two fallbacks, on the same loop with the cycle guard off (as for a loop whose state never repeats).
    # The step cap allows exactly STEPS steps: the VM runs steps 1..cap and refuses step cap + 1 before it
    # runs. Two caps, so the count is shown to follow the cap.
    for cap in (1000, 37):
        got = fish_steps(b">               ", cap=cap, guard=False)
        check(got == ("refuse", cap), "interp: fish step cap %d refuses a loop after exactly %d steps" % (cap, cap), got)
    # The time backstop refuses once the clock is PAST the deadline: with the deadline at step-time 50 the VM
    # runs steps 1..50 (time 50 is not past it) and is refused on step 51, far below the step cap of 1000.
    # This is the backstop interp_budget moves to the CPU clock: it still ends a loop the guard does not.
    got = fish_steps(b">               ", guard=False, deadline=50)
    check(got == ("refuse", 51), "interp: fish time backstop refuses a loop on the first step past the deadline", got)
    # ... and a reader call sets that deadline READER_TIME after its start (standalone: no blob deadline).
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(E, "time", types.SimpleNamespace(perf_counter=lambda: 100.0))
        mp.setattr(E, "READER_TIME", 7.0)
        check(E._deadline() == 107.0, "interp: a reader's deadline is READER_TIME after its start", E._deadline())

    # LOLCODE positive: SUM, SMOOSH, variables, BTW and OBTW..TLDR comments, string escapes.
    prog = (b"HAI 1.2\n"
            b"BTW a comment line\n"
            b"I HAS A x ITZ 40\n"
            b"I HAS A y ITZ SUM OF x AN 2\n"
            b'VISIBLE SMOOSH "val=" AN y MKAY\n'
            b"OBTW\nblock comment\nTLDR\n"
            b'VISIBLE "end"!\n'
            b"KTHXBYE\n")
    check(E.d_lolcode(prog) == b"val=42\nend", "interp: lolcode SUM/SMOOSH/vars/comments")
    check(E.d_lolcode(b'HAI 1.2\nVISIBLE "a:)b:>c::d"!\nKTHXBYE\n') == b"a\nb\tc:d",
          "interp: lolcode string escapes :) :> ::")
    check(E.d_lolcode(b'HAI 1.2\nVISIBLE ":(48)ello"!\nKTHXBYE\n') == b"Hello",
          "interp: lolcode hex escape :(HHHH)")

    # LOLCODE strict refusals.
    check(E.d_lolcode(b"HAI 1.2\nGIMMEH xvar\nVISIBLE xvar\nKTHXBYE\n") is None, "interp: lolcode GIMMEH input -> None")
    check(E.d_lolcode(b"HAI 1.2\nIM IN YR loopy\nVISIBLE 1\nIM OUTTA YR loopy\nKTHXBYE\n") is None,
          "interp: lolcode loop (IM IN YR) -> None")
    check(E.d_lolcode(b"HAI 1.2\nO RLY?\nKTHXBYE\n") is None, "interp: lolcode conditional (O RLY?) -> None")
    check(E.d_lolcode(b"HAI 1.2\nVISIBLE 3.14\nKTHXBYE\n") is None, "interp: lolcode NUMBAR float -> None")
    check(E.d_lolcode(b"HAI 1.2\nVISIBLE QUOSHUNT OF 7 AN 2\nKTHXBYE\n") is None,
          "interp: lolcode QUOSHUNT (author-rounded) -> None")
    check(E.d_lolcode(b"HAI 1.2\nI HAS A noobvar\nVISIBLE noobvar\nKTHXBYE\n") is None,
          "interp: lolcode printing a NOOB -> None")
    check(E.d_lolcode(b'HAI 1.2\nVISIBLE "hi there friend"\n') is None, "interp: lolcode missing KTHXBYE -> None")
    check(E.d_lolcode(b'VISIBLE "hi there friend"\nKTHXBYE\n') is None, "interp: lolcode missing HAI -> None")
    check(E.d_lolcode(b'HAI 1.2\nVISIBLE ":z and more text"\nKTHXBYE\n') is None,
          "interp: lolcode unknown escape -> None")
    check(E.d_lolcode(b"HAI 1.2\nundeclaredv R 5\nKTHXBYE\n") is None,
          "interp: lolcode assign to an undeclared var -> None")

    # Determinism: the same program gives the same bytes twice.
    data = (SENT + slug()).encode()
    fp = E.fish_encode(data)
    lp = E.lolcode_encode(data)
    check(E.d_fish(fp) == E.d_fish(fp) == data, "interp: fish is deterministic")
    check(E.d_lolcode(lp) == E.d_lolcode(lp) == data, "interp: lolcode is deterministic")


# ---- wired ---------------------------------------------------------------------------------------
def test_wired():
    check(C.ESL3 is E and set(E.NAMES) <= C._STRICT_NAMES, "wired: ESL3 live and strict")
    check(all(C._step_fn(n) is not None for n in E.NAMES), "wired: _step_fn resolves esolang3 names")
    for name, enc in E.ENCODERS.items():
        res = []
        for _ in range(3):
            s = slug()
            ans, chain = solve_wired(enc((SENT + s).encode()))
            flat = [x for c in (chain or ()) for x in (c if isinstance(c, (list, tuple)) else [c])]
            res.append((ans == s, name in flat, chain))
        check(all(a and named for a, named, _ in res), "wired: %s plain, right and chain-named" % name, res)

    # the looping Fish encoder through the real solve_blob
    s = slug()
    ans, chain = solve_wired(E.fish_encode_loop((SENT + s).encode()))
    flat = [x for c in (chain or ()) for x in (c if isinstance(c, (list, tuple)) else [c])]
    check(ans == s and "fish" in flat, "wired: looping fish program solved plain and right", (ans, chain))

    # a slug whose trailing digits are printed by Fish `n` (the numeric-output path, end to end)
    for _ in range(3):
        s = slug()
        head, _, num = s.rpartition("-")
        ans, chain = solve_wired(fish_num_tail(SENT + head + "-", int(num)))
        check(ans == s, "wired: fish n-digit tail solved plain and right", (s, ans, chain))

    # layered: base64 of a LOLCODE program read through both layers.
    s = slug()
    ans, chain = solve_wired(base64.b64encode(E.lolcode_encode((SENT + s).encode())))
    flat = [x for c in (chain or ()) for x in (c if isinstance(c, (list, tuple)) else [c])]
    check(ans == s and "lolcode" in flat and "b64" in flat, "wired: base64(lolcode) read through both layers", (ans, chain))


# ---- wrong ---------------------------------------------------------------------------------------
def test_wrong():
    bad = 0
    for _ in range(12):
        s = slug()
        decoys = [
            E.fish_encode(("totally wrong text %d" % rnd.randint(0, 9999)).encode()),
            E.lolcode_encode(("another wrong string %d" % rnd.randint(0, 9999)).encode()),
            # a LOLCODE program whose structure is valid but whose output is not the sentence
            (b'HAI 1.2\nVISIBLE "unrelated banner %d here padding"!\nKTHXBYE\n' % rnd.randint(0, 255)),
            # random noise under each gate's structure
            (b"';" + bytes(rnd.randrange(32, 127) for _ in range(60)) + b"o;"),
            bytes(rnd.randrange(256) for _ in range(120)),
        ]
        for blob in decoys:
            ans, _ = solve(blob)
            bad += wrong_plain(ans, s)
    check(bad == 0, "wrong: no wrong plain answer on decoys / noise", bad)

    # a reader whose output breaks the 87-char crib prefix returns NOTHING (never a truncated slug)
    truncated = E.fish_encode(b"Nice work decoding this warmup! WRONG continuation and slug-like-99")
    check(E.read(truncated) == [], "wrong: output that breaks the crib prefix is read by nothing")


# ---- regress -------------------------------------------------------------------------------------
def test_regress():
    for label, fn in (("plain", lambda b: b), ("hex", lambda b: b.hex().encode()), ("b64", base64.b64encode),
                      ("b32", base64.b32encode), ("rot13", lambda b: codecs.encode(b.decode(), "rot13").encode())):
        s = slug()
        # The read runs on the CPU clock, so solve_blob's default budget and every reader cap count this
        # process's work, and its cost is this thread's CPU seconds: neither grows while the process waits
        # for a core (SH-12; both bounds here were `time.perf_counter` wall bounds). A read takes 5 to 30 ms
        # of CPU, so 3.0 s holds at any load.
        with K.cpu_clock():
            (ans, chain), cpu = K.thread_seconds(solve, fn((SENT + s).encode()))
        flat = [x for c in (chain or ()) for x in (c if isinstance(c, (list, tuple)) else [c])]
        named = [x for x in flat if x in E.NAMES]
        check(plain_ok(ans, s) and not named and cpu < 3.0, "regress: %s" % label, (ans, chain, round(cpu, 3)))

    pay = base64.b64encode((SENT + slug()).encode())

    def which_2000():
        for _ in range(2000):
            E._which(pay)

    # the per-call cost in this thread's CPU time: about 1 us against the 50 us bound (a VM run is milliseconds)
    _, cpu = K.thread_seconds(which_2000)
    per = cpu / 2000
    check(E._which(pay) == () and E.steps(pay) == [] and per < 5e-5,
          "regress: _which on a base64 payload is a cheap no-op (%.1f us)" % (per * 1e6), per)


# ---- saved ---------------------------------------------------------------------------------------
def saved_warmups_files():
    """Every saved Warmups artifact file under $CTF_REAL_CHALLENGES (the saved Huntress attempts, read only);
    the test does not run when that is unset or holds fewer than 50 files. Resolved through
    ctf.paths.saved_challenges_root(): set to a missing folder, it raises FileNotFoundError (the test fails)."""
    root = paths.saved_challenges_root()
    if root is None:
        pytest.skip("not run: CTF_REAL_CHALLENGES is not set (the saved past-event attempts)")
    files = sorted(f for f in glob.glob(str(root / "day-*" / "warmups*" / "**" / "artifact" / "**" / "*"),
                                        recursive=True) if os.path.isfile(f))
    if len(files) < 50:
        pytest.skip(f"fewer than 50 saved Warmups artifact files under {root} ({len(files)})")
    return files


def test_saved():
    files = saved_warmups_files()
    whole = recs = 0
    read_by = []
    for f in files:
        try:
            raw = open(f, "rb").read()
        except OSError:
            continue
        whole += 1
        if E.steps(raw):
            read_by.append((f, "whole"))
        try:
            parts = C.numbered(raw)
        except Exception:
            parts = None
        for i, rec in enumerate(parts or ()):
            rb = rec if isinstance(rec, (bytes, bytearray)) else str(rec).encode()
            recs += 1
            if E.steps(rb):
                read_by.append((f, "record %d" % i))
    check(not read_by, "saved: no saved Warmups payload is read by any esolang3 reader (%d whole + %d records)"
          % (whole, recs), read_by[:10])


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
