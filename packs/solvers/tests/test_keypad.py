#!/usr/bin/env python3
"""Offline tests of solvers/toolkits/keypad.py -- DTMF-from-tone-list and T9/multitap decode.

  .venv/bin/python tests/test_keypad.py

Pure standard library (no Pillow, no audio). Covers the 2024 Stegano "Call me" archetype: a list of
DTMF tone pairs -> digits, and multitap key presses -> letters. Also exercises the never-wrong edges:
an off-band tone list fails loudly (None), and a mixed-digit multitap run is rejected.
"""
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import keypad as kp       # noqa: E402

FAILED = []


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:300]}]"))
    if not ok:
        FAILED.append(label)


# ---- DTMF -----------------------------------------------------------------------------------------
def test_dtmf_single_keys():
    check("dtmf: 697+1209 -> '1'", kp.dtmf_key(697, 1209) == "1", kp.dtmf_key(697, 1209))
    check("dtmf: 770+1336 -> '5'", kp.dtmf_key(770, 1336) == "5", kp.dtmf_key(770, 1336))
    check("dtmf: 852+1477 -> '9'", kp.dtmf_key(852, 1477) == "9", kp.dtmf_key(852, 1477))
    check("dtmf: 941+1336 -> '0'", kp.dtmf_key(941, 1336) == "0", kp.dtmf_key(941, 1336))
    check("dtmf: 697+1633 -> 'A'", kp.dtmf_key(697, 1633) == "A", kp.dtmf_key(697, 1633))


def test_dtmf_sequence():
    # frequencies for "911" (9=852/1477, 1=697/1209, 1=697/1209)
    pairs = [(852, 1477), (697, 1209), (697, 1209)]
    check("dtmf: tone list -> '911'", kp.dtmf_from_frequencies(pairs) == "911", kp.dtmf_from_frequencies(pairs))


def test_dtmf_tolerance_and_swap():
    check("dtmf: slightly-off tones still snap (700/1210 -> '1')", kp.dtmf_key(700, 1210) == "1", kp.dtmf_key(700, 1210))
    check("dtmf: a swapped (high, low) pair is accepted (1336/770 -> '5')", kp.dtmf_key(1336, 770) == "5", kp.dtmf_key(1336, 770))


def test_dtmf_rejects_off_band():
    check("dtmf: an off-band tone -> None", kp.dtmf_key(1000, 1209) is None, kp.dtmf_key(1000, 1209))
    check("dtmf: any bad pair fails the whole list (loud, not silent)",
          kp.dtmf_from_frequencies([(697, 1209), (1000, 2000)]) is None)
    check("dtmf: malformed pair -> None", kp.dtmf_from_frequencies([(697,)]) is None)


# ---- multitap ------------------------------------------------------------------------------------
def test_multitap_hello():
    check("multitap: '44 33 555 555 666' -> 'HELLO'", kp.multitap_decode("44 33 555 555 666") == "HELLO",
          kp.multitap_decode("44 33 555 555 666"))
    check("multitap: dash separators work too", kp.multitap_decode("44-33-555-555-666") == "HELLO",
          kp.multitap_decode("44-33-555-555-666"))
    check("multitap: a list of runs works", kp.multitap_decode(["44", "33", "555", "555", "666"]) == "HELLO",
          kp.multitap_decode(["44", "33", "555", "555", "666"]))


def test_multitap_wrap_and_literals():
    check("multitap: '7777' wraps to 'S'", kp.multitap_decode("7777") == "S", kp.multitap_decode("7777"))
    check("multitap: '77777' wraps back to 'P'", kp.multitap_decode("77777") == "P", kp.multitap_decode("77777"))
    check("multitap: '0' is a space", kp.multitap_decode("8 0 8") == "T T", kp.multitap_decode("8 0 8"))


def test_multitap_rejects_mixed_run():
    check("multitap: a run mixing digits -> None", kp.multitap_decode("4433") is None, kp.multitap_decode("4433"))
    check("multitap: a '*' run (no letters) -> None", kp.multitap_decode("* 44") is None, kp.multitap_decode("* 44"))


def test_keypad_letters():
    check("keypad_letters('5') == 'JKL'", kp.keypad_letters("5") == "JKL", kp.keypad_letters("5"))
    check("keypad_letters('7') == 'PQRS'", kp.keypad_letters(7) == "PQRS", kp.keypad_letters(7))


def main():
    tests = [test_dtmf_single_keys, test_dtmf_sequence, test_dtmf_tolerance_and_swap,
             test_dtmf_rejects_off_band, test_multitap_hello, test_multitap_wrap_and_literals,
             test_multitap_rejects_mixed_run, test_keypad_letters]
    for t in tests:
        try:
            t()
        except Exception as e:
            import traceback
            check(f"{t.__name__} ran", False, f"{type(e).__name__}: {e} | {traceback.format_exc()[-400:]}")
    print("ok" if not FAILED else f"FAILED {len(FAILED)}: " + "; ".join(FAILED[:10]))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
