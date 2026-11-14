#!/usr/bin/env python3
"""Offline test of the keyless repeating-key XOR break in solvers/toolkits/modern_crypto.py
(reference-technique build list, row 2). No crib, no stated key: the key length is found by
block Hamming distance (bounded 2..40), each column solved as a single-byte XOR by English
fitness, the candidate keys ranked by the plaintext's fitness.

  .venv/bin/python tests/test_modern_crypto_xor.py

The never-wrong boundary this proves: a recovered key or plaintext is a GUESS ranked by fitness,
so solve_set offers it ONLY as a labels.candidates value (unsure, probed untimed/no-deadline) and
NEVER plain -- even when the fitness is overwhelming and even when the recovered text matches the
question's own specific pattern. Its candidate key is SCOPED to the ciphertext (a per-ciphertext
discriminator), so a hypothesis name the judge accepts on one variant's ciphertext becomes plain
only for THAT ciphertext (within-attempt probing and the gate's base replay) and can never promote
a DIFFERENT variant's recovered-but-unproven guess to a bare plain answer -- the adversarial hole
test_scoped_key_no_cross_variant_plain reproduces and fixes.
Also: deterministic, bounded key length, exactly-one-ciphertext, declines when a key is stated or
XOR is not named. No network and no token (a dead Game Master URL makes that certain).
"""
import importlib.util
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_modern_crypto_xor_"))
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")  # the labels ledger writes HERE, never the repo
os.environ["CTF_PLATFORM_URL"] = "http://127.0.0.1:9/"       # nothing here makes a request; this makes sure
os.environ.pop("CTF_TOKEN", None)
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "common"))

spec = importlib.util.spec_from_file_location("tk_modern_crypto", REPO / "solvers" / "toolkits" / "modern_crypto.py")
tk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tk)
mc = tk.lib
import pytest     # noqa: E402
import labels                                                   # noqa: E402

FAILED = []


def judge_backed() -> bool:
    """True when the loaded labels module replays judge acceptance: labels.judge_ledger() is on
    (the event's judge answers per name). Off, or a labels module without it (the neutral shim),
    means an accepted name is never replayed as a plain answer, so the judge tests cannot pass."""
    ledger = getattr(labels, "judge_ledger", None)
    return callable(ledger) and ledger()


# Judge-acceptance tests (an accepted name replays as plain): marked `judge` and skipped, with the
# reason shown, unless a judge-backed labels module is loaded. They used to be dropped from main().
JUDGE = (pytest.mark.judge, pytest.mark.skipif(
    not judge_backed(), reason="judge-acceptance replay needs a judge-backed labels module "
                               "(labels.judge_ledger() is off or absent)"))


def judge(fn):
    for mark in reversed(JUDGE):
        fn = mark(fn)
    return fn


def run_judge(fn):
    """main()'s call of a judge test: run it, or print why it is skipped (never a silent pass)."""
    if judge_backed():
        fn()
    else:
        print(f"skip {fn.__name__}: {JUDGE[1].kwargs['reason']}")


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)


def q(question, aid="answer", kind="exact_text", pattern=None):
    fmt = {"kind": kind}
    if pattern:
        fmt["pattern"] = pattern
    return {"id": aid, "qid": aid, "answer_id": aid, "question": question, "answer_format": fmt}


def solve(question, files):
    return tk.solve_set([question], files, {})[question["qid"]]


def options(v):
    """The (name, value) options of an unsure/candidate answer, or None if it is not one."""
    u = labels.parse(v)
    return u.options if u is not None else None


# An English plaintext long enough that every candidate key length (up to 40) has many samples per
# column, so the true key -- and no spurious multiple of it -- is the top-ranked break.
PLAIN = ((b"The quick brown fox jumps over the lazy dog near the river bank at dawn. "
          b"We should meet at the old bridge before the guards change their watch. ") * 18
         + b"Here is the secret flag: flag{repeating_xor_break_no_crib} do not share it. " * 4)
KEY = b"SPARTA"
CT = mc.xor(PLAIN, KEY)


def test_breaker():
    ranked = tk.break_repeating_xor(CT)
    check("breaker: returns a ranked, non-empty candidate list", bool(ranked), ranked[:1])
    top = ranked[0]
    check("breaker: the top candidate is the true key (minimal period) and plaintext",
          top[1] == KEY and top[2] == PLAIN, (top[1], top[2][:40]))
    check("breaker: ranked by fitness, best first", all(ranked[i][3] >= ranked[i + 1][3] for i in range(len(ranked) - 1)))
    check("breaker: deterministic", tk.break_repeating_xor(CT) == ranked)
    check("breaker: every recovered key length is within the 2..40 bound",
          all(2 <= k <= tk.XOR_KEYLEN_MAX for k, _, _, _ in ranked), [k for k, _, _, _ in ranked])
    # a tighter bound is never exceeded, even when the true key (6) is longer than hi
    r_tight = tk.break_repeating_xor(CT, hi=4)
    check("breaker: a tighter hi is respected (no key longer than hi)",
          r_tight and all(k <= 4 for k, _, _, _ in r_tight), [k for k, _, _, _ in r_tight])
    check("breaker: a ciphertext shorter than the floor is declined", tk.break_repeating_xor(b"short") == [])
    check("min_period: a repeated key reduces, a non-period key does not",
          tk._min_period(b"ABAB") == b"AB" and tk._min_period(b"ABC") == b"ABC" and tk._min_period(KEY * 3) == KEY)


def test_never_plain_key():
    ask = q("What is the repeating-key XOR key used?", "xor-key")
    v = solve(ask, {"cipher.bin": CT})
    check("xor_key: a keyless break is an unsure candidate, never plain", labels.is_candidate(v), v)
    opts = options(v)
    check("xor_key: the candidate key ends in the candidate mark and the true key is its top option",
          opts is not None and opts[0] == ("keylen_6", "SPARTA"), opts)
    check("xor_key: it is NOT a bare plain string", not (isinstance(v, str) and not v.startswith("??")), v)
    v_hex = solve(q("Give the repeating XOR key in hex.", "xor-key-hex"), {"cipher.bin": CT})
    oh = options(v_hex)
    check("xor_key: a hex request yields the key as hex, still a candidate",
          labels.is_candidate(v_hex) and oh and oh[0] == ("keylen_6", KEY.hex()), oh)


def test_never_plain_plaintext():
    ask = q("Decrypt the repeating-key XOR message and give the plaintext.", "pt")
    v = solve(ask, {"cipher.bin": CT})
    check("plaintext: a keyless break is an unsure candidate, never plain", labels.is_candidate(v), v)
    opts = options(v)
    check("plaintext: the recovered plaintext is the candidate's top option",
          opts is not None and opts[0][1] == PLAIN.decode().strip(), opts[0] if opts else None)
    check("plaintext: deterministic across calls", solve(ask, {"cipher.bin": CT}) == v)
    # the never-wrong heart: even a question whose SPECIFIC pattern the recovered text matches stays
    # unsure (a keyless break is a guess; a guess is never promoted to plain by matching a pattern)
    vp = solve(q("Decrypt the repeating XOR message.", "pt2", pattern=r"^.*flag\{[a-z_]+\}.*$"), {"cipher.bin": CT})
    check("plaintext: a recovered text that matches a specific pattern is STILL unsure, never plain",
          labels.is_candidate(vp), vp)


def test_declines():
    # a stated key: solve_sym proves that, so the keyless path stands down (no competing answer)
    stated = {"params.txt": b"key = SPARTA\n", "cipher.bin": CT}
    check("decline: xor_key with a stated key is None (the keyless break does not fire)",
          solve(q("What is the repeating-key XOR key?", "k2"), stated) is None)
    check("decline: solve_repeating_xor returns [] when a key is stated",
          tk.solve_repeating_xor(tk.Material(stated)) == [])
    # XOR not named anywhere: the plaintext path never offers a keyless XOR guess
    check("decline: a plaintext question that never names XOR gives no candidate",
          solve(q("Decrypt the message and give the plaintext.", "p3"), {"cipher.bin": CT}) is None)
    # two ciphertexts: ambiguous which to break, so nothing is offered
    two = {"a.bin": CT, "b.bin": mc.xor(PLAIN, b"ATHENS")}
    check("decline: two candidate ciphertexts are ambiguous (solve_repeating_xor [])",
          tk.solve_repeating_xor(tk.Material(two)) == [])
    check("decline: xor_key is None with two ciphertexts",
          solve(q("What is the repeating XOR key?", "k4"), two) is None)


@judge
def test_scoped_key_no_cross_variant_plain():
    """The never-wrong heart (the adversarial HOLE, reproduced and fixed): the recovered key is a
    fitness GUESS, so its candidate key is scoped to its own ciphertext. A hypothesis name the judge
    accepts on ONE ciphertext (a clean untimed base) can therefore NEVER promote a DIFFERENT variant's
    recovered-but-unproven guess to a bare PLAIN answer. True key 'secret': the base's keylen_6 break
    is 'secret' (correct, accepted); the next variant's keylen_6 break is a corrupted 'Secret' (wrong)
    that the pre-fix code returned PLAIN once 'keylen_6' was accepted."""
    true_key = b"secret"
    base_ct = mc.xor(b"we will leave the city at dawn and travel north along the coastal road ", true_key)
    next_ct = mc.xor(b"the meeting is at noon tomorrow by the river near the old stone bridge ", true_key)
    base_u = labels.parse(solve(q("What is the repeating XOR key?", "x1"), {"c.bin": base_ct}))
    next_u = labels.parse(solve(q("What is the repeating XOR key?", "x2"), {"c.bin": next_ct}))
    check("scope: each variant carries its own per-ciphertext candidate key",
          base_u is not None and next_u is not None and base_u.key != next_u.key,
          (base_u.key if base_u else None, next_u.key if next_u else None))
    check("scope: a keyless-xor candidate key is scoped (not the bare field key)",
          base_u.key.startswith("modern_crypto.xor_key/repeating_keyless.")
          and base_u.key != "modern_crypto.xor_key/repeating_keyless#candidates"
          and re.fullmatch(r"modern_crypto\.xor_key/repeating_keyless\.[0-9a-f]{64}#candidates", base_u.key),
          base_u.key)
    check("scope: the next variant also offers a keylen_6 hypothesis (the promotion path is reachable)",
          "keylen_6" in dict(next_u.options), next_u.options)
    # the untimed base probes and the judge accepts 'keylen_6' for the BASE ciphertext's own key
    labels.learn(base_u.key, "keylen_6", "accepted", scope="key")
    base_after = solve(q("What is the repeating XOR key?", "x3"), {"c.bin": base_ct})
    check("scope: the base's OWN ciphertext answers plain once its key is accepted (the gate's replay)",
          base_after == "secret", base_after)
    nxt = solve(q("What is the repeating XOR key?", "x4"), {"c.bin": next_ct})
    check("never-wrong: the next variant's keyless break stays unsure, never a bare plain",
          labels.is_candidate(nxt) and not (isinstance(nxt, str) and not nxt.startswith("??")), nxt)
    check("never-wrong: the next variant is not the corrupted plain 'Secret'", nxt != "Secret", nxt)


@judge
def test_accept_boundary():
    """The boundary is judge-acceptance of THIS ciphertext's own hypothesis. The candidate key is
    scoped to the ciphertext, so before acceptance the answer is unsure, accepting the name under the
    OLD unscoped key does NOT promote it, and only once the judge accepts the hypothesis name for THIS
    ciphertext does labels.candidates return its plain value (within-attempt probing / the gate)."""
    before = solve(q("What is the repeating XOR key?", "k5"), {"cipher.bin": CT})
    u = labels.parse(before)
    check("boundary: unsure before any accepted name", labels.is_candidate(before), before)
    check("boundary: the candidate key is scoped to this ciphertext, not the bare field key",
          u is not None and u.key.startswith("modern_crypto.xor_key/repeating_keyless.")
          and u.key != "modern_crypto.xor_key/repeating_keyless#candidates"
          and re.fullmatch(r"modern_crypto\.xor_key/repeating_keyless\.[0-9a-f]{64}#candidates", u.key),
          u.key if u else None)
    # accepting the OLD unscoped key (what the pre-fix code recorded) must NOT promote this ciphertext
    labels.learn("modern_crypto.xor_key/repeating_keyless#candidates", "keylen_6", "accepted", scope="key")
    still = solve(q("What is the repeating XOR key?", "k5b"), {"cipher.bin": CT})
    check("boundary: accepting the unscoped key does not promote a scoped-key ciphertext to plain",
          labels.is_candidate(still), still)
    # accepting THIS ciphertext's own scoped key returns its plain value
    labels.learn(u.key, "keylen_6", "accepted", scope="key")
    after = solve(q("What is the repeating XOR key?", "k6"), {"cipher.bin": CT})
    check("boundary: plain only after the judge accepts the hypothesis name for THIS ciphertext", after == "SPARTA", after)


def main():
    try:
        for fn in (test_breaker, test_never_plain_key, test_never_plain_plaintext, test_declines):
            fn()
        for fn in (test_scoped_key_no_cross_variant_plain, test_accept_boundary):
            run_judge(fn)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
