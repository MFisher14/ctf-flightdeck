#!/usr/bin/env python3
"""Offline test of the extra PRNG predictors in solvers/common/modern_crypto.py (the `lib`) and their
wiring into solvers/toolkits/modern_crypto.py: xorshift32/64/128 whole-state and window prediction,
PCG32 (XSH-RR 64/32) state recovery, and truncated-LCG top-bits recovery.

  .venv/bin/python tests/test_prng_predictors.py

The never-wrong boundary this proves:
  * A "next output" is returned ONLY when the reconstruction reproduces EVERY given output exactly
    (a roundtrip proof). A value is PLAIN (like the existing mt19937/lcg prediction) because it is a
    byte-proven fact, not an author-chosen label; where the ANSWER FORM (decimal vs hex) is not fixed
    by the question, it is an unsure pick over forms, never a wrong guess at the form.
  * No reconstruction, two admissible reconstructions that disagree, a sequence that is not that
    generator, too few outputs, a sum-output xorshift128+ (not bounded-recoverable), an unknown PCG
    stream, or a question that asks for anything but the single next output (the seed, the state, the
    previous value, the next N, or a value computed from the next output) all yield None.
  * The interval enumerator and floor_sum used for the truncated recoveries are validated against
    brute force, and the recovery is validated to produce NO false positive on random sequences.
No network and no token (a dead Game Master URL makes that certain).
"""
import importlib.util
import os
import random
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_prng_predictors_"))
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "common"))

spec = importlib.util.spec_from_file_location("tk_modern_crypto", REPO / "solvers" / "toolkits" / "modern_crypto.py")
tk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tk)
mc = tk.lib
import labels                                                   # noqa: E402

FAILED = []
M32 = (1 << 32) - 1
M64 = (1 << 64) - 1


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


def q(question, aid="answer", kind="integer", pattern=None):
    fmt = {"kind": kind}
    if pattern:
        fmt["pattern"] = pattern
    return {"id": aid, "qid": aid, "answer_id": aid, "question": question, "answer_format": fmt}


def solve(question, files):
    return tk.solve_set([question], files, {})[question["qid"]]


def ints_file(xs):
    return {"outputs.txt": ("\n".join(str(v) for v in xs) + "\n").encode()}


# ---- reference generators -------------------------------------------------------------------------

def gen_xorshift32(seed, n):
    x = seed & M32
    out = []
    for _ in range(n):
        x ^= (x << 13) & M32
        x ^= x >> 17
        x ^= (x << 5) & M32
        x &= M32
        out.append(x)
    return out


def gen_xorshift64(seed, n):
    x = seed & M64
    out = []
    for _ in range(n):
        x ^= (x << 13) & M64
        x ^= x >> 7
        x ^= (x << 17) & M64
        x &= M64
        out.append(x)
    return out


def gen_xorshift128(x, y, z, w, n):
    out = []
    for _ in range(n):
        t = (x ^ ((x << 11) & M32)) & M32
        x, y, z = y, z, w
        w = ((w ^ (w >> 19)) ^ (t ^ (t >> 8))) & M32
        out.append(w)
    return out


PCG_MULT = 6364136223846793005


def gen_pcg32(state, inc, n):
    out = []
    s = state & M64
    for _ in range(n):
        old = s
        s = (old * PCG_MULT + inc) & M64
        xorshifted = (((old >> 18) ^ old) >> 27) & M32
        rot = old >> 59
        out.append(((xorshifted >> (rot & 31)) | (xorshifted << ((-rot) & 31))) & M32)
    return out


def gen_trunc_lcg(seed, a, c, m, shift, n):
    out = []
    s = seed % m
    for _ in range(n):
        out.append(s >> shift)
        s = (a * s + c) % m
    return out


def gen_xorshift128plus(s0, s1, n):
    """Vigna xorshift128+ (sum output): NOT bounded-recoverable from outputs, must be declined."""
    out = []
    for _ in range(n):
        x = s1
        y = s0
        s0 = y
        x ^= (x << 23) & M64
        s1 = (x ^ y ^ (x >> 17) ^ (y >> 26)) & M64
        out.append((s1 + y) & M64)
    return out


# ---- the interval enumerator / floor_sum against brute force --------------------------------------

def test_floor_sum_and_interval():
    rnd = random.Random(12345)
    ok = True
    for _ in range(3000):
        n = rnd.randint(0, 40)
        m = rnd.randint(1, 60)
        a = rnd.randint(-80, 80)
        b = rnd.randint(-80, 80)
        if mc._floor_sum(n, m, a, b) != sum((a * i + b) // m for i in range(n)):
            ok = False
            break
    check("floor_sum matches brute force (3000 random)", ok)

    ok = True
    for _ in range(4000):
        n = rnd.randint(1, 50)
        m = rnd.randint(2, 80)
        a = rnd.randint(0, 200)
        lo = rnd.randint(0, m)
        hi = rnd.randint(lo, m)
        bf = [x for x in range(n) if lo <= (a * x) % m < hi]
        if mc._enum_mod_interval(a, m, lo, hi, n) != bf:
            ok = False
            break
    check("interval enumerator matches brute force (4000 random)", ok)
    check("interval enumerator caps and declines (returns None over the cap)",
          mc._enum_mod_interval(1, 1000, 0, 1000, 1000, cap=10) is None)


# ---- xorshift ------------------------------------------------------------------------------------

def test_xorshift32():
    outs = gen_xorshift32(0xDEADBEEF, 9)
    got = mc.xorshift_predict(outs)
    check("lib: xorshift32 next is derived and roundtrip-verified", got and got[0] == gen_xorshift32(0xDEADBEEF, 10)[9]
          and got[1] == 32 and got[3] >= 2, got)
    v = solve(q("Predict the next output of the xorshift32 generator."), ints_file(outs))
    check("tk: xorshift32 next-output is PLAIN (integer kind) and correct",
          v == str(gen_xorshift32(0xDEADBEEF, 10)[9]), v)


def test_xorshift64():
    outs = gen_xorshift64(0x1234567890ABCDEF, 9)
    nxt = gen_xorshift64(0x1234567890ABCDEF, 10)[9]
    got = mc.xorshift_predict(outs)
    check("lib: xorshift64 next derived and verified", got and got[0] == nxt and got[1] == 64, got)
    v = solve(q("What is the next value produced by the xorshift generator?"), ints_file(outs))
    check("tk: xorshift64 next-output PLAIN and correct", v == str(nxt), v)


def test_xorshift128():
    outs = gen_xorshift128(123456789, 362436069, 521288629, 88675123, 12)
    nxt = gen_xorshift128(123456789, 362436069, 521288629, 88675123, 13)[12]
    got = mc.xorshift_predict(outs)
    check("lib: xorshift128 (window) next derived and verified", got and got[0] == nxt and got[1] == 128, got)
    v = solve(q("Predict the next xorshift128 output."), ints_file(outs))
    check("tk: xorshift128 next-output PLAIN and correct", v == str(nxt), v)
    # window needs >= 6 outputs (4 to seed + >= 2 to verify)
    check("lib: xorshift128 with only 5 outputs is declined", mc.xorshift_predict(outs[:5]) is None
          or mc.xorshift_predict(outs[:5])[1] != 128, mc.xorshift_predict(outs[:5]))


def test_xorshift_randomized():
    rnd = random.Random(2024)
    ok32 = ok64 = True
    for _ in range(40):
        seed = rnd.getrandbits(32) or 1
        outs = gen_xorshift32(seed, 10)
        got = mc.xorshift_predict(outs[:9])
        if not got or got[0] != outs[9]:
            ok32 = False
            break
    for _ in range(40):
        seed = rnd.getrandbits(64) or 1
        outs = gen_xorshift64(seed, 10)
        got = mc.xorshift_predict(outs[:9])
        if not got or got[0] != outs[9]:
            ok64 = False
            break
    check("lib: xorshift32 randomized (40 seeds)", ok32)
    check("lib: xorshift64 randomized (40 seeds)", ok64)


def test_xorshift_declines():
    rnd = random.Random(7)
    fp = sum(1 for _ in range(200) if mc.xorshift_predict([rnd.getrandbits(32) for _ in range(9)]) is not None)
    check("lib: xorshift no false positive on 200 random sequences", fp == 0, f"fp={fp}")
    check("lib: xorshift too few outputs (2) declined", mc.xorshift_predict([1, 2]) is None)
    # xorshift128+ (sum output) cannot be bounded-recovered -> None
    plus = gen_xorshift128plus(rnd.getrandbits(64) or 1, rnd.getrandbits(64) or 1, 12)
    check("lib: xorshift128+ (sum output) is declined (None)", mc.xorshift_predict(plus) is None)
    v = solve(q("Predict the next xorshift128+ output."), ints_file(plus))
    check("tk: xorshift128+ yields None (never a wrong guess)", v is None, v)


# ---- PCG32 ---------------------------------------------------------------------------------------

def test_pcg32_default_inc():
    rnd = random.Random(3)
    ok = True
    for _ in range(25):
        st = rnd.getrandbits(64)
        outs = gen_pcg32(st, mc.PCG32_DEFAULT_INC, 7)
        got = mc.pcg32_predict(outs[:6])
        if not got or got[0] != outs[6]:
            ok = False
            break
    check("lib: PCG32 default-increment recovery predicts next (25 random)", ok)
    outs = gen_pcg32(0xCAFEBABEDEADBEEF, mc.PCG32_DEFAULT_INC, 7)
    v = solve(q("Predict the next output of the PCG32 generator."), ints_file(outs[:6]))
    check("tk: PCG32 next-output PLAIN and correct (default stream)", v == str(outs[6]), v)


def test_pcg32_stated_inc():
    rnd = random.Random(5)
    inc = rnd.getrandbits(64) | 1
    outs = gen_pcg32(0x0123456789ABCDEF, inc, 7)
    got = mc.pcg32_predict(outs[:6], incs=[inc])
    check("lib: PCG32 with a stated non-default stream", got and got[0] == outs[6], got)
    files = ints_file(outs[:6])
    files["params.txt"] = (f"increment = {inc}\n").encode()
    v = solve(q("Predict the next PCG output."), files)
    check("tk: PCG32 reads a stated increment and predicts correctly", v == str(outs[6]), v)


def test_pcg32_declines():
    rnd = random.Random(11)
    fp = sum(1 for _ in range(120) if mc.pcg32_predict([rnd.getrandbits(32) for _ in range(6)]) is not None)
    check("lib: PCG32 no false positive on 120 random sequences", fp == 0, f"fp={fp}")
    # a PCG sequence under the WRONG stream -> None
    inc = rnd.getrandbits(64) | 1
    outs = gen_pcg32(rnd.getrandbits(64), inc, 6)
    check("lib: PCG32 with an unknown stream (default tried) -> None", mc.pcg32_predict(outs) is None)
    check("lib: PCG32 too few outputs (3) declined", mc.pcg32_predict([1, 2, 3]) is None)


# ---- truncated LCG -------------------------------------------------------------------------------

def test_truncated_lcg():
    a, c, m, shift = 25214903917, 11, 1 << 48, 16          # drop 16 low bits
    outs = gen_trunc_lcg(0xABCDEF123456 & (m - 1), a, c, m, shift, 6)
    got = mc.lcg_truncated_predict(outs[:5], a, c, m, shift)
    check("lib: truncated LCG (shift 16) next derived and verified", got and got[0] == outs[5], got)
    files = ints_file(outs[:5])
    files["params.txt"] = (f"a = {a}\nc = {c}\nm = {m}\nshift = {shift}\n").encode()
    v = solve(q("Predict the next output of the truncated linear congruential generator (LCG)."), files)
    check("tk: truncated LCG reads a/c/m/shift and predicts PLAIN", v == str(outs[5]), v)
    # a large shift uses the interval enumerator
    a2, c2, m2, shift2 = 6364136223846793005, 1442695040888963407, 1 << 60, 28
    rnd = random.Random(9)
    ok = True
    for _ in range(10):
        outs2 = gen_trunc_lcg(rnd.getrandbits(60), a2, c2, m2, shift2, 6)
        got = mc.lcg_truncated_predict(outs2[:5], a2, c2, m2, shift2)
        if not got or got[0] != outs2[5]:
            ok = False
            break
    check("lib: truncated LCG (shift 28, interval path) predicts next (10 random)", ok)
    # a narrow-output generator (out_bits = 21-9 = 12) is still answerable with ENOUGH outputs:
    # the coincidence bound needs (len-2)*out_bits >= 64, i.e. at least 8 outputs here.
    a3, c3, m3, shift3 = 1103515245, 12345, 1 << 20, 9
    rnd3 = random.Random(17)
    ok3 = True
    for _ in range(10):
        outs3 = gen_trunc_lcg(rnd3.getrandbits(20), a3, c3, m3, shift3, 9)
        got = mc.lcg_truncated_predict(outs3[:8], a3, c3, m3, shift3)   # 8 outputs: (8-2)*12 = 72 >= 64
        if not got or got[0] != outs3[8]:
            ok3 = False
            break
    check("lib: truncated LCG (out_bits 12, 8 outputs) predicts next plain (10 random)", ok3)


def test_truncated_lcg_declines():
    a, c, m, shift = 25214903917, 11, 1 << 48, 16
    outs = gen_trunc_lcg(0x111122223333, a, c, m, shift, 6)
    # without a stated shift the toolkit must NOT guess (it is not a full LCG, so lcg_recover is None too)
    files = ints_file(outs[:5])
    files["params.txt"] = (f"a = {a}\nc = {c}\nm = {m}\n").encode()
    v = solve(q("Predict the next output of the LCG."), files)
    check("tk: truncated LCG with NO stated shift is declined (None, never guessed)", v is None, v)
    # false positive guard: random outputs with plausible params -> None
    rnd = random.Random(31)
    fp = sum(1 for _ in range(60)
             if mc.lcg_truncated_predict([rnd.getrandbits(32) for _ in range(5)], a, c, m, shift) is not None)
    check("lib: truncated LCG no false positive on 60 random sequences", fp == 0, f"fp={fp}")
    # SMALL-OUTPUT-WIDTH REGIME (the coincidence-bound fix): m = 2^16, shift 10 -> out_bits = 7, so a
    # 3-4 output roundtrip (<= 14 independent bits) is NOT a proof and MUST be declined, never returned
    # plain. Before the bound a wrong candidate could survive by coincidence and be answered as a fact.
    sm_a, sm_c, sm_m, sm_shift = 22251, 13413, 1 << 16, 10
    rnd2 = random.Random(2026)
    for nout in (3, 4):
        fp_sm = sum(1 for _ in range(500)
                    if mc.lcg_truncated_predict([rnd2.getrandbits(6) for _ in range(nout)],
                                                sm_a, sm_c, sm_m, sm_shift) is not None)
        check(f"lib: truncated LCG no false positive at small output width ({nout} outputs, m=2^16 shift=10)",
              fp_sm == 0, f"fp={fp_sm}")
    # even genuine small-width data with too few outputs declines rather than guesses
    gsm = gen_trunc_lcg(12345 & (sm_m - 1), sm_a, sm_c, sm_m, sm_shift, 4)
    check("lib: genuine small-width LCG with only 4 outputs is declined (bound, not a guess)",
          mc.lcg_truncated_predict(gsm, sm_a, sm_c, sm_m, sm_shift) is None,
          mc.lcg_truncated_predict(gsm, sm_a, sm_c, sm_m, sm_shift))
    # the exact audit repro: true shift 10 but the delivery STATES shift 11 (a decoy), outputs
    # [10,21,14,20]. On the unfixed code this returned '15' PLAIN (genuine next is 25); it must be None.
    r_a, r_c, r_m, r_outs = 22251, 13413, 1 << 16, [10, 21, 14, 20]
    check("lib: audit repro (wrong-stated shift 11, 4 outputs) -> None, not a wrong plain value",
          mc.lcg_truncated_predict(r_outs, r_a, r_c, r_m, 11) is None,
          mc.lcg_truncated_predict(r_outs, r_a, r_c, r_m, 11))
    rfiles = ints_file(r_outs)
    rfiles["params.txt"] = (f"a = {r_a}\nc = {r_c}\nm = {r_m}\nshift = 11\n").encode()
    rv = solve(q("Predict the next output of the truncated linear congruential generator (LCG)."), rfiles)
    check("tk: audit repro through solve_set returns None (not the wrong plain '15')", rv is None, rv)


# ---- question gating (never answer anything but the single next output) ---------------------------

def test_question_gating():
    outs = gen_xorshift32(0xABCD1234, 9)
    # a question that asks for the seed / state / previous value -> None
    check("gate: asking for the seed is None",
          solve(q("What was the seed of the xorshift32 generator?"), ints_file(outs)) is None)
    check("gate: asking for the internal state is None",
          solve(q("What is the internal state of the xorshift generator?"), ints_file(outs)) is None)
    check("gate: asking for the previous output is None",
          solve(q("What was the previous xorshift output before the list?"), ints_file(outs)) is None)
    check("gate: asking for the next THREE outputs is None",
          solve(q("Predict the next three xorshift outputs."), ints_file(outs)) is None)
    # a value computed FROM the next output -> None (_DERIVED)
    check("gate: asking the SUM of the digits of the next output is None",
          solve(q("What is the sum of the digits of the next xorshift output?"), ints_file(outs)) is None)
    check("gate: asking the next output MOD something is None",
          solve(q("What is the next xorshift output mod 256?"), ints_file(outs)) is None)
    # more than one integer list present -> None (cannot tell which is the stream)
    two = ints_file(outs)
    two["second.txt"] = ("\n".join(str(v) for v in gen_xorshift32(1, 9)) + "\n").encode()
    check("gate: two integer lists -> None", solve(q("Predict the next xorshift output."), two) is None)
    # structured kinds -> None
    check("gate: ordered_tokens kind -> None",
          solve(q("Predict the next xorshift output.", kind="ordered_tokens"), ints_file(outs)) is None)


def test_answer_form():
    outs = gen_xorshift32(0x55AA55AA, 9)
    nxt = gen_xorshift32(0x55AA55AA, 10)[9]
    # integer kind -> plain decimal
    v = solve(q("Predict the next xorshift output.", kind="integer"), ints_file(outs))
    check("form: integer kind gives a plain decimal string", v == str(nxt), v)
    # exact_text with no form words -> an unsure pick over forms (never a wrong guess at dec vs hex)
    v2 = solve(q("Predict the next xorshift output.", kind="exact_text"), ints_file(outs))
    u = labels.parse(v2)
    check("form: no stated form -> unsure pick over decimal/hex (not a bare plain guess)",
          u is not None and any(val == str(nxt) for _, val in u.options), v2)
    # a hex request -> hex forms only, still a proven value
    v3 = solve(q("Give the next xorshift output in hexadecimal.", kind="exact_text"), ints_file(outs))
    u3 = labels.parse(v3)
    check("form: hex request yields hex forms of the proven value",
          (u3 is not None and any(val == f"{nxt:x}" for _, val in u3.options)) or v3 == f"{nxt:x}", v3)


def main():
    try:
        for fn in (test_floor_sum_and_interval, test_xorshift32, test_xorshift64, test_xorshift128,
                   test_xorshift_randomized, test_xorshift_declines, test_pcg32_default_inc,
                   test_pcg32_stated_inc, test_pcg32_declines, test_truncated_lcg,
                   test_truncated_lcg_declines, test_question_gating, test_answer_form):
            fn()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
